package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

func TestSASLSCRAMPlusRFC5802FixedVector(t *testing.T) {
	t.Parallel()

	binding := scram.ChannelBinding{
		Type: scram.ChannelBindingTLSServerEndpoint,
		Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	client, err := scram.SHA256.NewClient("user", "pencil", "authzid")
	if err != nil {
		t.Fatalf("create fixed-vector client: %v", err)
	}
	client.WithNonceGenerator(func() string { return "clientNONCE" })
	credentials, err := client.GetStoredCredentialsWithError(scram.KeyFactors{
		Salt:  "salt1234",
		Iters: 4096,
	})
	if err != nil {
		t.Fatalf("derive fixed-vector credentials: %v", err)
	}
	server, err := scram.SHA256.NewServer(func(username string) (scram.StoredCredentials, error) {
		if username != "user" {
			return scram.StoredCredentials{}, errSASLSCRAMCredentialsUnavailable
		}
		return credentials, nil
	})
	if err != nil {
		t.Fatalf("create fixed-vector server: %v", err)
	}
	server.WithNonceGenerator(func() string { return "serverNONCE" })
	clientConversation := client.NewConversationWithChannelBinding(binding)
	serverConversation := server.NewConversationWithChannelBindingRequired(binding)

	clientFirst, err := clientConversation.Step("")
	if err != nil {
		t.Fatalf("client-first: %v", err)
	}
	const wantClientFirst = "p=tls-server-end-point,a=authzid,n=user,r=clientNONCE"
	if clientFirst != wantClientFirst {
		t.Fatalf("client-first = %q, want %q", clientFirst, wantClientFirst)
	}
	serverFirst, err := serverConversation.Step(clientFirst)
	if err != nil {
		t.Fatalf("server-first: %v", err)
	}
	const wantServerFirst = "r=clientNONCEserverNONCE,s=c2FsdDEyMzQ=,i=4096"
	if serverFirst != wantServerFirst {
		t.Fatalf("server-first = %q, want %q", serverFirst, wantServerFirst)
	}
	clientFinal, err := clientConversation.Step(serverFirst)
	if err != nil {
		t.Fatalf("client-final: %v", err)
	}
	const wantClientFinal = "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCxhPWF1dGh6aWQsAQIDBAUGBwgJCgsMDQ4PEA==,r=clientNONCEserverNONCE,p=bD0YHYVRwx+xWKhepT5F6U49nZTF54EzIfg3Jk9QtZE="
	if clientFinal != wantClientFinal {
		t.Fatalf("client-final = %q, want %q", clientFinal, wantClientFinal)
	}
	serverFinal, err := serverConversation.Step(clientFinal)
	if err != nil {
		t.Fatalf("server-final: %v", err)
	}
	const wantServerFinal = "v=OJpY5IV0FNe60RO1GrhIn0Cfs3s24Cv8FE+3Ffs0njQ="
	if serverFinal != wantServerFinal {
		t.Fatalf("server-final = %q, want %q", serverFinal, wantServerFinal)
	}
	if response, err := clientConversation.Step(serverFinal); err != nil ||
		response != "" || !clientConversation.Valid() || !serverConversation.Valid() {
		t.Fatalf(
			"fixed-vector completion response=%q clientValid=%t serverValid=%t err=%v",
			response,
			clientConversation.Valid(),
			serverConversation.Valid(),
			err,
		)
	}
}

func TestSASLSCRAMPlusRootDSERequiresTLS(t *testing.T) {
	t.Parallel()

	store, address, tlsConfig, stop := startSASLSCRAMPlusTestServer(
		t,
		"SCRAM-SHA-256-PLUS",
	)
	defer func() {
		stop()
		_ = store.Close()
	}()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial Root DSE probe: %v", err)
	}
	defer client.Close()
	mechanisms := searchSASLMechanisms(t, client)
	for _, mechanism := range mechanisms {
		if strings.HasSuffix(mechanism, "-PLUS") {
			t.Fatalf("cleartext Root DSE advertised %q", mechanism)
		}
	}
	if err := client.StartTLS(tlsConfig.Clone()); err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	mechanisms = searchSASLMechanisms(t, client)
	for _, mechanism := range []string{
		"SCRAM-SHA-1-PLUS",
		"SCRAM-SHA-256-PLUS",
		"SCRAM-SHA-512-PLUS",
	} {
		if !containsString(mechanisms, mechanism) {
			t.Errorf("TLS Root DSE omitted %q: %v", mechanism, mechanisms)
		}
	}
}

func TestSASLSCRAMPlusRejectsCleartextDowngradeAndWrongBinding(t *testing.T) {
	t.Parallel()

	t.Run("cleartext explicit PLUS", func(t *testing.T) {
		store, address, _, stop := startSASLSCRAMPlusTestServer(
			t,
			"SCRAM-SHA-256-PLUS",
		)
		defer func() {
			stop()
			_ = store.Close()
		}()
		connection, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatalf("dial cleartext server: %v", err)
		}
		defer connection.Close()
		transport := newSASLSCRAMPlusTransport(connection)
		result, err := sendSyncConsumerSASLBind(
			transport,
			"SCRAM-SHA-256-PLUS",
			[]byte("p=tls-server-end-point,,n=alice,r=cleartextNonce"),
			true,
		)
		if err != nil || result.code != ldap.LDAPResultAuthMethodNotSupported {
			t.Fatalf("cleartext PLUS result = %#v, %v", result, err)
		}
	})

	t.Run("y downgrade", func(t *testing.T) {
		transport, _, closeFixture := dialSASLSCRAMPlusTLS(t, "SCRAM-SHA-256-PLUS")
		defer closeFixture()
		result, err := sendSyncConsumerSASLBind(
			transport,
			"SCRAM-SHA-256-PLUS",
			[]byte("y,,n=alice,r=downgradeNonce"),
			true,
		)
		if err != nil || result.code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("downgrade result = %#v, %v", result, err)
		}
	})

	t.Run("unsupported cbind type", func(t *testing.T) {
		transport, _, closeFixture := dialSASLSCRAMPlusTLS(t, "SCRAM-SHA-256-PLUS")
		defer closeFixture()
		result, err := sendSyncConsumerSASLBind(
			transport,
			"SCRAM-SHA-256-PLUS",
			[]byte("p=tls-unique,,n=alice,r=unsupportedBindingNonce"),
			true,
		)
		if err != nil || result.code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("unsupported-binding result = %#v, %v", result, err)
		}
	})

	t.Run("wrong cbind", func(t *testing.T) {
		transport, binding, closeFixture := dialSASLSCRAMPlusTLS(
			t,
			"SCRAM-SHA-256-PLUS",
		)
		defer closeFixture()
		conversation := newSASLSCRAMPlusClient(
			t,
			scram.SHA256,
			binding,
			"wrongBindingNonce",
		)
		clientFirst, err := conversation.Step("")
		if err != nil {
			t.Fatalf("client-first: %v", err)
		}
		first, err := sendSyncConsumerSASLBind(
			transport,
			"SCRAM-SHA-256-PLUS",
			[]byte(clientFirst),
			true,
		)
		if err != nil || first.code != ldap.LDAPResultSaslBindInProgress {
			t.Fatalf("server-first = %#v, %v", first, err)
		}
		clientFinal, err := conversation.Step(string(first.saslCredentials))
		if err != nil {
			t.Fatalf("client-final: %v", err)
		}
		fields := strings.Split(clientFinal, ",")
		fields[0] = "c=" + base64.StdEncoding.EncodeToString(
			append([]byte("p=tls-server-end-point,,"), []byte("wrong-binding")...),
		)
		result, err := sendSyncConsumerSASLBind(
			transport,
			"SCRAM-SHA-256-PLUS",
			[]byte(strings.Join(fields, ",")),
			true,
		)
		if err != nil || result.code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("wrong-binding result = %#v, %v", result, err)
		}
	})
}

func TestSASLSCRAMPlusRejectsReplayedClientFinal(t *testing.T) {
	t.Parallel()

	transport, binding, closeFixture := dialSASLSCRAMPlusTLS(
		t,
		"SCRAM-SHA-256-PLUS",
	)
	defer closeFixture()
	conversation := newSASLSCRAMPlusClient(
		t,
		scram.SHA256,
		binding,
		"replayClientNonce",
	)
	clientFirst, err := conversation.Step("")
	if err != nil {
		t.Fatalf("client-first: %v", err)
	}
	first, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256-PLUS",
		[]byte(clientFirst),
		true,
	)
	if err != nil || first.code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("server-first = %#v, %v", first, err)
	}
	clientFinal, err := conversation.Step(string(first.saslCredentials))
	if err != nil {
		t.Fatalf("client-final: %v", err)
	}
	final, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256-PLUS",
		[]byte(clientFinal),
		true,
	)
	if err != nil || final.code != ldap.LDAPResultSuccess {
		t.Fatalf("server-final = %#v, %v", final, err)
	}
	if _, err := conversation.Step(string(final.saslCredentials)); err != nil ||
		!conversation.Valid() {
		t.Fatalf("verify server proof: valid=%t err=%v", conversation.Valid(), err)
	}

	second, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256-PLUS",
		[]byte(clientFirst),
		true,
	)
	if err != nil || second.code != ldap.LDAPResultSaslBindInProgress ||
		bytes.Equal(second.saslCredentials, first.saslCredentials) {
		t.Fatalf("second server-first = %#v, %v", second, err)
	}
	replayed, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256-PLUS",
		[]byte(clientFinal),
		true,
	)
	if err != nil || replayed.code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("replayed client-final = %#v, %v", replayed, err)
	}
}

func TestSASLSCRAMSessionClearsSecrets(t *testing.T) {
	t.Parallel()

	binding := []byte("binding-secret")
	storedKey := []byte("stored-key-secret")
	serverKey := []byte("server-key-secret")
	secrets := &saslSCRAMSecrets{
		binding:     binding,
		storedKey:   storedKey,
		serverKey:   serverKey,
		initialized: true,
	}
	session := &serverSASLSession{scramSecrets: secrets}
	clearSASLSCRAMSession(session)
	for name, value := range map[string][]byte{
		"binding":    binding,
		"stored key": storedKey,
		"server key": serverKey,
	} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Errorf("%s was not cleared: %x", name, value)
		}
	}
	if session.scramSecrets != nil || session.scramConversation != nil {
		t.Fatalf("SCRAM session retained secrets: %#v", session)
	}
}

func TestSASLSCRAMPlusRejectsTLCPStyleTransportWithoutStandardBinding(t *testing.T) {
	t.Parallel()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	connection := saslSCRAMTLCPStyleConnection{Conn: local}
	if saslSCRAMPlusAvailable(connection) {
		t.Fatal("TLCP-style secure transport exposed a standard TLS SCRAM binding")
	}
}

type saslSCRAMTLCPStyleConnection struct {
	net.Conn
}

func (saslSCRAMTLCPStyleConnection) SecurityStrengthFactor() uint32 {
	return 128
}

func TestOpenLDAPCyrusSASLSCRAMTLSChannelBinding(t *testing.T) {
	if os.Getenv("LDAP_GO_TEST_OPENLDAP_SCRAM_PLUS") != "1" {
		t.Skip("set LDAP_GO_TEST_OPENLDAP_SCRAM_PLUS=1 to run native OpenLDAP/Cyrus channel-binding interoperability")
	}

	pluginViewer := findSASLPluginViewer(t)
	pluginOutput, err := exec.Command(pluginViewer, "-c").CombinedOutput()
	if err != nil {
		t.Fatalf("inspect Cyrus SASL client plugins: %v\n%s", err, pluginOutput)
	}
	if !strings.Contains(string(pluginOutput), "CHANNEL_BINDING") {
		t.Skip("Cyrus SASL client plugins are installed without CHANNEL_BINDING")
	}
	ldapwhoami, err := exec.LookPath("ldapwhoami")
	if err != nil {
		t.Skip("OpenLDAP ldapwhoami is not installed")
	}

	pluginRoot := filepath.Dir(filepath.Dir(pluginViewer))
	for _, mechanism := range []string{
		"SCRAM-SHA-1",
		"SCRAM-SHA-256",
		"SCRAM-SHA-512",
	} {
		mechanism := mechanism
		t.Run(mechanism, func(t *testing.T) {
			if !strings.Contains(string(pluginOutput), "SASL mechanism: "+mechanism) {
				t.Skipf("Cyrus SASL client plugin %s is not installed", mechanism)
			}
			store := storage.NewMemory()
			seedDirectory(t, store)
			seedSASLSCRAMConfiguration(t, store, mechanism)
			authority := newGlobalTLSTestAuthority(t)
			certificate := issueSASLSCRAMPlusNativeCertificate(t, authority)
			address, stop := startServer(t, store, Config{TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS12,
			}})
			defer func() {
				stop()
				_ = store.Close()
			}()
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatalf("split LDAP address: %v", err)
			}
			caPath := filepath.Join(t.TempDir(), "scram-plus-ca.pem")
			caPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: authority.certificateDER,
			})
			if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
				t.Fatalf("write native SCRAM-PLUS CA: %v", err)
			}
			command := exec.Command(
				ldapwhoami,
				"-H", "ldap://localhost:"+port,
				"-N",
				"-ZZ",
				"-o", "tls_cacert="+caPath,
				"-o", "sasl_cbinding=tls-endpoint",
				"-Y", mechanism,
				"-U", "alice",
				"-w", "secret",
			)
			command.Env = append(os.Environ(),
				"SASL_PATH="+filepath.Join(pluginRoot, "lib", "sasl2"),
			)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("native ldapwhoami %s channel binding: %v\n%s", mechanism, err, output)
			}
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			if len(lines) == 0 ||
				lines[len(lines)-1] != "dn:uid=alice,ou=people,dc=example,dc=com" {
				t.Fatalf("native ldapwhoami output = %q", output)
			}
		})
	}
}

func findSASLPluginViewer(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		"pluginviewer",
		"/opt/homebrew/opt/cyrus-sasl/sbin/pluginviewer",
		"/usr/local/opt/cyrus-sasl/sbin/pluginviewer",
	} {
		path, err := exec.LookPath(candidate)
		if err == nil {
			return path
		}
	}
	t.Skip("Cyrus SASL pluginviewer is not installed")
	return ""
}

func issueSASLSCRAMPlusNativeCertificate(
	t *testing.T,
	authority globalTLSTestAuthority,
) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate native SCRAM-PLUS TLS key: %v", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("resolve native SCRAM-PLUS TLS hostname: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", hostname},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		authority.certificate,
		&privateKey.PublicKey,
		authority.privateKey,
	)
	if err != nil {
		t.Fatalf("create native SCRAM-PLUS TLS certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certificateDER, authority.certificateDER},
		PrivateKey:  privateKey,
	}
}

func startSASLSCRAMPlusTestServer(
	t *testing.T,
	mechanism string,
) (storage.Store, string, *tls.Config, func()) {
	t.Helper()
	store := storage.NewMemory()
	seedDirectory(t, store)
	seedSASLSCRAMConfiguration(t, store, mechanism)
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "localhost", true)
	address, stop := startServer(t, store, Config{TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{certificate.tlsCertificate},
		MinVersion:   tls.VersionTLS12,
	}})
	roots := x509.NewCertPool()
	roots.AddCert(authority.certificate)
	return store, address, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}, stop
}

func dialSASLSCRAMPlusTLS(
	t *testing.T,
	mechanism string,
) (*syncConsumerTransport, scram.ChannelBinding, func()) {
	t.Helper()
	store, address, tlsConfig, stop := startSASLSCRAMPlusTestServer(t, mechanism)
	raw, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		stop()
		_ = store.Close()
		t.Fatalf("dial SCRAM-PLUS server: %v", err)
	}
	transport := newSASLSCRAMPlusTransport(raw)
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 1,
		Request: ldapwire.ExtendedRequest{
			Name: syncConsumerStartTLSOID,
		},
	})
	if err != nil {
		t.Fatalf("encode StartTLS: %v", err)
	}
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("decode StartTLS fixture packet: %v", err)
	}
	result, err := transport.exchangeLDAPResult(
		1,
		packet,
		ldap.ApplicationExtendedResponse,
	)
	if err != nil || result.code != ldap.LDAPResultSuccess {
		t.Fatalf("StartTLS result = %#v, %v", result, err)
	}
	secured := tls.Client(raw, tlsConfig.Clone())
	if err := secured.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	transport.replaceConnection(secured)
	transport.secure = true
	transport.messageID = 1
	state := secured.ConnectionState()
	binding, err := scram.NewTLSServerEndpointBinding(&state)
	if err != nil {
		t.Fatalf("TLS channel binding: %v", err)
	}
	closeFixture := func() {
		_ = transport.close()
		stop()
		_ = store.Close()
	}
	return transport, binding, closeFixture
}

func newSASLSCRAMPlusTransport(connection net.Conn) *syncConsumerTransport {
	return &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
}

func newSASLSCRAMPlusClient(
	t *testing.T,
	generator scram.HashGeneratorFcn,
	binding scram.ChannelBinding,
	nonce string,
) *scram.ClientConversation {
	t.Helper()
	client, err := generator.NewClient("alice", "secret", "u:alice")
	if err != nil {
		t.Fatalf("create SCRAM-PLUS client: %v", err)
	}
	client.WithNonceGenerator(func() string { return nonce })
	return client.NewConversationWithChannelBinding(binding)
}

func searchSASLMechanisms(t *testing.T, client *ldap.Conn) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
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
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("search Root DSE = %#v, %v", result, err)
	}
	return result.Entries[0].GetAttributeValues("supportedSASLMechanisms")
}
