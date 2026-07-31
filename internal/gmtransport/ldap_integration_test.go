package gmtransport_test

import (
	"context"
	"net"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/gmtransport"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPBindAndSearchOverTLCP(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedTLCPDirectory(t, store)

	serverConfig, clientConfig := testTLCPConfigs(t)
	transport, err := gmtransport.NewTLCP(serverConfig)
	if err != nil {
		t.Fatalf("NewTLCP(): %v", err)
	}
	address, stop := startTLCPDirectoryServer(t, store, transport, true)
	defer stop()

	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("DialTimeout(): %v", err)
	}
	secured := handshakeTLCPClient(t, raw, clientConfig)
	assertLDAPOverTLCP(t, secured)
}

func TestLDAPStartTLSUpgradeToTLCP(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedTLCPDirectory(t, store)

	serverConfig, clientConfig := testTLCPConfigs(t)
	transport, err := gmtransport.NewTLCP(serverConfig)
	if err != nil {
		t.Fatalf("NewTLCP(): %v", err)
	}
	address, stop := startTLCPDirectoryServer(t, store, transport, false)
	defer stop()

	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("DialTimeout(): %v", err)
	}
	request := ber.NewSequence("LDAPMessage")
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		1,
		"messageID",
	))
	operation := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationExtendedRequest,
		nil,
		"StartTLS",
	)
	operation.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"1.3.6.1.4.1.1466.20037",
		"requestName",
	))
	request.AppendChild(operation)
	if err := ldapwire.Write(raw, request.Bytes()); err != nil {
		t.Fatalf("write StartTLS request: %v", err)
	}
	response, err := ber.ReadPacket(raw)
	if err != nil {
		t.Fatalf("read StartTLS response: %v", err)
	}
	if len(response.Children) < 2 ||
		len(response.Children[1].Children) < 1 {
		t.Fatalf("malformed StartTLS response: %#v", response)
	}
	resultCode, err := ber.ParseInt64(
		response.Children[1].Children[0].Data.Bytes(),
	)
	if err != nil || resultCode != 0 {
		t.Fatalf("StartTLS result code = %d, %v", resultCode, err)
	}

	secured := handshakeTLCPClient(t, raw, clientConfig)
	assertLDAPOverTLCP(t, secured)
}

func handshakeTLCPClient(
	t *testing.T,
	raw net.Conn,
	config *tlcp.Config,
) *tlcp.Conn {
	t.Helper()

	secured := tlcp.Client(raw, config)
	handshakeContext, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()
	if err := secured.HandshakeContext(handshakeContext); err != nil {
		t.Fatalf("TLCP HandshakeContext(): %v", err)
	}
	wantCipherSuite := uint16(tlcp.ECC_SM4_GCM_SM3)
	if len(config.CipherSuites) > 0 {
		wantCipherSuite = config.CipherSuites[0]
	}
	if state := secured.ConnectionState(); state.CipherSuite != wantCipherSuite {
		t.Fatalf(
			"TLCP cipher suite = %#x, want %#x",
			state.CipherSuite,
			wantCipherSuite,
		)
	}
	return secured
}

func assertLDAPOverTLCP(t *testing.T, secured net.Conn) {
	t.Helper()

	client := ldap.NewConn(secured, true)
	client.Start()
	defer client.Close()
	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedSASLMechanisms"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		rootDSE.Entries[0].GetAttributeValue("supportedSASLMechanisms") != "EXTERNAL" {
		t.Fatalf("TLCP SASL Root DSE = %#v, %v", rootDSE, err)
	}
	if err := client.ExternalBind(); err != nil {
		t.Fatalf("TLCP ExternalBind(): %v", err)
	}
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:cn=ldap-go TLCP client" {
		t.Fatalf("TLCP WhoAmI() = %#v, %v", identity, err)
	}
	if err := client.Bind("uid=alice,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("TLCP LDAP Bind(): %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "alice" {
		t.Fatalf("TLCP LDAP Search() = %#v, %v", result, err)
	}
}

func seedTLCPDirectory(t *testing.T, store storage.Store) {
	t.Helper()

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{
				DN: "dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: byteValues("domain")},
					{Description: "dc", Values: byteValues("example")},
				},
			},
			{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: byteValues("inetOrgPerson")},
					{Description: "uid", Values: byteValues("alice")},
					{Description: "cn", Values: byteValues("Alice")},
					{Description: "sn", Values: byteValues("Alice")},
					{Description: "userPassword", Values: byteValues("secret")},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: byteValues("{1}mdb")},
					{Description: "olcSuffix", Values: byteValues("dc=example,dc=com")},
					{
						Description: "olcAccess",
						Values: byteValues(
							"{0}to attrs=userPassword by anonymous auth by * none",
							"{1}to * by * read",
						),
					},
				},
			},
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed directory: %v", err)
	}
}

func startTLCPDirectoryServer(
	t *testing.T,
	store storage.Store,
	transport server.SecureTransport,
	implicit bool,
) (string, func()) {
	t.Helper()

	instance, err := server.New(server.Config{
		Store:           store,
		SecureTransport: transport,
		ImplicitTLS:     implicit,
	})
	if err != nil {
		t.Fatalf("server.New(): %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- instance.Serve(ctx, listener)
	}()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
		if err := <-serveDone; err != nil {
			t.Errorf("Serve(): %v", err)
		}
	}
}

func byteValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = []byte(value)
	}
	return result
}
