package gmtransport_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/gmtransport"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncreplConsumerOverMutualTLCP(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedTLCPSyncProvider(t, providerStore)

	serverConfig, clientConfig := testTLCPConfigs(t)
	serverConfig.CipherSuites = []uint16{tlcp.ECDHE_SM4_GCM_SM3}
	clientConfig.CipherSuites = []uint16{tlcp.ECDHE_SM4_GCM_SM3}
	transport, err := gmtransport.NewTLCP(serverConfig)
	if err != nil {
		t.Fatalf("NewTLCP(): %v", err)
	}
	providerAddress, stopProvider := startTLCPDirectoryServer(
		t,
		providerStore,
		transport,
		true,
	)
	defer stopProvider()
	_, providerPort, err := net.SplitHostPort(providerAddress)
	if err != nil {
		t.Fatalf("split TLCP provider address: %v", err)
	}
	providerName := net.JoinHostPort("localhost", providerPort)
	certificateFile,
		keyFile,
		encryptionCertificateFile,
		encryptionKeyFile,
		caFile := writeTLCPClientCredentials(
		t,
		serverConfig,
		clientConfig,
	)

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedTLCPSyncConsumer(
		t,
		consumerStore,
		providerName,
		certificateFile,
		keyFile,
		encryptionCertificateFile,
		encryptionKeyFile,
		caFile,
	)
	consumerAddress, stopConsumer := startPlainTLCPConsumer(
		t,
		consumerStore,
	)
	defer stopConsumer()
	consumer := dialPlainTLCPConsumer(t, consumerAddress)
	defer consumer.Close()
	waitForTLCPConsumerAttribute(
		t,
		consumer,
		"uid=alice,dc=example,dc=com",
		"cn",
		"Alice",
	)

	raw, err := net.DialTimeout("tcp", providerAddress, time.Second)
	if err != nil {
		t.Fatalf("dial TLCP provider for modify: %v", err)
	}
	secured := handshakeTLCPClient(t, raw, clientConfig)
	provider := ldap.NewConn(secured, true)
	provider.Start()
	defer provider.Close()
	if err := provider.ExternalBind(); err != nil {
		t.Fatalf("TLCP provider ExternalBind(): %v", err)
	}
	modify := ldap.NewModifyRequest("uid=alice,dc=example,dc=com", nil)
	modify.Replace("cn", []string{"Alice TLCP Delta"})
	if err := provider.Modify(modify); err != nil {
		t.Fatalf("modify TLCP provider: %v", err)
	}
	waitForTLCPConsumerAttribute(
		t,
		consumer,
		"uid=alice,dc=example,dc=com",
		"cn",
		"Alice TLCP Delta",
	)
}

func seedTLCPSyncProvider(t *testing.T, store storage.Store) {
	t.Helper()
	seedTLCPDirectory(t, store)
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("parse TLCP provider suffix: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		var entries []directory.Entry
		if err := writer.ForEach(func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if suffix.Equal(dn) || suffix.AncestorOf(dn) {
				entries = append(entries, entry)
			}
			return nil
		}); err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].DN < entries[j].DN
		})
		var contextCSN string
		for index := range entries {
			csn := fmt.Sprintf(
				"20260730030101.%06dZ#000000#000#000000",
				index+1,
			)
			identifier := fmt.Sprintf(
				"00000000-0000-4000-8000-%012x",
				index+1,
			)
			entries[index].ReplaceValues(
				"entryUUID",
				byteValues(identifier),
			)
			entries[index].ReplaceValues("entryCSN", byteValues(csn))
			contextCSN = csn
		}
		for index := range entries {
			if entries[index].DN == "dc=example,dc=com" {
				entries[index].ReplaceValues(
					"contextCSN",
					byteValues(contextCSN),
				)
			}
			if err := writer.Put(entries[index], true); err != nil {
				return err
			}
		}
		databaseDN, err := directory.ParseDN(
			"olcDatabase={1}mdb,cn=config",
		)
		if err != nil {
			return err
		}
		database, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		database.ReplaceValues(
			"olcAccess",
			byteValues("{0}to * by * write"),
		)
		if err := writer.Put(database, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcOverlay",
				Values:      byteValues("{0}syncprov"),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed TLCP sync provider: %v", err)
	}
}

func seedTLCPSyncConsumer(
	t *testing.T,
	store storage.Store,
	providerAddress,
	certificateFile,
	keyFile,
	encryptionCertificateFile,
	encryptionKeyFile,
	caFile string,
) {
	t.Helper()
	value := `{0}rid=001 provider=ldap+tlcp://` + providerAddress +
		` bindmethod=sasl saslmech=EXTERNAL` +
		` searchbase="dc=example,dc=com"` +
		` filter="(objectClass=*)" scope=sub attrs="*,+"` +
		` tls_reqcert=demand tls_reqsan=demand` +
		` tls_cacert="` + caFile + `"` +
		` tls_cert="` + certificateFile + `"` +
		` tls_key="` + keyFile + `"` +
		` tlcp_enc_cert="` + encryptionCertificateFile + `"` +
		` tlcp_enc_key="` + encryptionKeyFile + `"` +
		` tls_cipher_suite=ECDHE_SM4_GCM_SM3` +
		` type=refreshAndPersist retry="1 +"`
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: byteValues("{1}mdb")},
			{
				Description: "olcSuffix",
				Values:      byteValues("dc=example,dc=com"),
			},
			{
				Description: "olcSyncrepl",
				Values:      byteValues(value),
			},
			{
				Description: "olcUpdateRef",
				Values:      byteValues("ldap+tlcp://" + providerAddress),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed TLCP sync consumer: %v", err)
	}
}

func writeTLCPClientCredentials(
	t *testing.T,
	serverConfig,
	clientConfig *tlcp.Config,
) (string, string, string, string, string) {
	t.Helper()
	if len(clientConfig.Certificates) != 2 {
		t.Fatalf(
			"TLCP client certificates = %d",
			len(clientConfig.Certificates),
		)
	}
	if len(serverConfig.Certificates) < 1 ||
		len(serverConfig.Certificates[0].Certificate) < 2 {
		t.Fatal("TLCP server signing certificate has no CA chain")
	}
	root := t.TempDir()
	writePair := func(
		certificate tlcp.Certificate,
		name string,
	) (string, string) {
		t.Helper()
		privateKey, ok := certificate.PrivateKey.(*sm2.PrivateKey)
		if !ok {
			t.Fatalf(
				"TLCP client %s private key type = %T",
				name,
				certificate.PrivateKey,
			)
		}
		privateKeyDER, err := smx509.MarshalSM2PrivateKey(privateKey)
		if err != nil {
			t.Fatalf("marshal TLCP client %s private key: %v", name, err)
		}
		certificateFile := filepath.Join(root, "client-"+name+".crt")
		keyFile := filepath.Join(root, "client-"+name+".key")
		if err := os.WriteFile(
			certificateFile,
			pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certificate.Certificate[0],
			}),
			0o600,
		); err != nil {
			t.Fatalf("write TLCP client %s certificate: %v", name, err)
		}
		if err := os.WriteFile(
			keyFile,
			pem.EncodeToMemory(&pem.Block{
				Type:  "SM2 PRIVATE KEY",
				Bytes: privateKeyDER,
			}),
			0o600,
		); err != nil {
			t.Fatalf("write TLCP client %s key: %v", name, err)
		}
		return certificateFile, keyFile
	}
	certificateFile, keyFile := writePair(
		clientConfig.Certificates[0],
		"sign",
	)
	encryptionCertificateFile, encryptionKeyFile := writePair(
		clientConfig.Certificates[1],
		"enc",
	)
	caFile := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverConfig.Certificates[0].Certificate[1],
	}), 0o600); err != nil {
		t.Fatalf("write TLCP CA certificate: %v", err)
	}
	return certificateFile,
		keyFile,
		encryptionCertificateFile,
		encryptionKeyFile,
		caFile
}

func startPlainTLCPConsumer(
	t *testing.T,
	store storage.Store,
) (string, func()) {
	t.Helper()
	instance, err := server.New(server.Config{
		Store:        store,
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	if err != nil {
		t.Fatalf("new TLCP sync consumer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TLCP sync consumer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve TLCP sync consumer: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("TLCP sync consumer did not stop")
		}
	}
}

func dialPlainTLCPConsumer(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	connection, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial TLCP sync consumer: %v", err)
	}
	if err := connection.Bind(
		"cn=admin,dc=example,dc=com",
		"secret",
	); err != nil {
		connection.Close()
		t.Fatalf("bind TLCP sync consumer: %v", err)
	}
	return connection
}

func waitForTLCPConsumerAttribute(
	t *testing.T,
	connection *ldap.Conn,
	dn,
	description,
	want string,
) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var (
		last    string
		lastErr error
	)
	for time.Now().Before(deadline) {
		result, err := connection.Search(ldap.NewSearchRequest(
			dn,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			"(objectClass=*)",
			[]string{description},
			nil,
		))
		lastErr = err
		if err == nil && len(result.Entries) == 1 {
			last = result.Entries[0].GetAttributeValue(description)
			if last == want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf(
		"TLCP consumer %s %s = %q, want %q (last error %v)",
		dn,
		description,
		last,
		want,
		lastErr,
	)
}
