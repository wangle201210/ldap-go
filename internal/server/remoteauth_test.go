package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadRemoteAuthRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	pinValue := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	configuration, err := loadRemoteAuthRuntimeConfiguration(directory.Entry{
		DN: "olcOverlay={0}remoteauth,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcRemoteAuthDNAttribute", Values: stringValues("seeAlso")},
			{Description: "olcRemoteAuthDomainAttribute", Values: stringValues("description")},
			{Description: "olcRemoteAuthDefaultDomain", Values: stringValues("default")},
			{Description: "olcRemoteAuthDefaultRealm", Values: stringValues("ldap.example.test")},
			{
				Description: "olcRemoteAuthMapping",
				Values: stringValues(
					"{0}EXAMPLE ldap://one.example.test",
					"{1}example ldap://ignored-duplicate.example.test",
				),
			},
			{Description: "olcRemoteAuthStore", Values: stringValues("TRUE")},
			{Description: "olcRemoteAuthRetryCount", Values: stringValues("4")},
			{
				Description: "olcRemoteAuthTLS",
				Values: stringValues(
					"starttls=critical tls_reqcert=demand tls_reqsan=try tls_crlcheck=peer",
				),
			},
			{
				Description: "olcRemoteAuthTLSPeerkeyHash",
				Values:      stringValues("LDAP.EXAMPLE.TEST sha256:" + pinValue),
			},
		},
	})
	if err != nil {
		t.Fatalf("loadRemoteAuthRuntimeConfiguration(): %v", err)
	}
	if configuration.dnAttribute != "seeAlso" ||
		configuration.domainAttribute != "description" ||
		configuration.defaultDomain != "default" ||
		configuration.defaultRealm != "ldap.example.test" ||
		configuration.mappings["example"] != "ldap://one.example.test" ||
		!configuration.storeOnSuccess || configuration.retryCount != 4 ||
		configuration.connection.startTLS != syncConsumerStartTLSCritical ||
		configuration.connection.tls.requireCert != "demand" ||
		len(configuration.pins) != 1 {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestLoadRemoteAuthRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	validURI := directory.Attribute{
		Description: "olcRemoteAuthMapping",
		Values:      stringValues("example ldap://127.0.0.1"),
	}
	tests := []struct {
		name       string
		attributes []directory.Attribute
		omitTLS    bool
	}{
		{
			name:    "missing TLS",
			omitTLS: true,
			attributes: []directory.Attribute{
				validURI,
			},
		},
		{
			name: "empty TLS",
			attributes: []directory.Attribute{
				validURI,
				{Description: "olcRemoteAuthTLS", Values: stringValues(" ")},
			},
		},
		{
			name: "mapping arity",
			attributes: []directory.Attribute{{
				Description: "olcRemoteAuthMapping",
				Values:      stringValues("example"),
			}},
		},
		{
			name: "negative retries",
			attributes: []directory.Attribute{
				validURI,
				{Description: "olcRemoteAuthRetryCount", Values: stringValues("-1")},
			},
		},
		{
			name: "invalid store",
			attributes: []directory.Attribute{
				validURI,
				{Description: "olcRemoteAuthStore", Values: stringValues("sometimes")},
			},
		},
		{
			name: "invalid TLS",
			attributes: []directory.Attribute{
				validURI,
				{Description: "olcRemoteAuthTLS", Values: stringValues("starttls=required")},
			},
		},
		{
			name: "invalid pin hash",
			attributes: []directory.Attribute{
				validURI,
				{
					Description: "olcRemoteAuthTLSPeerkeyHash",
					Values:      stringValues("ldap.example.test md5:AAAA"),
				},
			},
		},
		{
			name: "duplicate pin host",
			attributes: []directory.Attribute{
				validURI,
				{
					Description: "olcRemoteAuthTLSPeerkeyHash",
					Values: stringValues(
						"ldap.example.test sha256:"+base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)),
						"LDAP.EXAMPLE.TEST sha256:"+base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)),
					),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			attributes := append([]directory.Attribute(nil), test.attributes...)
			if !test.omitTLS {
				hasTLS := false
				for _, attribute := range attributes {
					if strings.EqualFold(attribute.Description, "olcRemoteAuthTLS") {
						hasTLS = true
						break
					}
				}
				if !hasTLS {
					attributes = append(attributes, directory.Attribute{
						Description: "olcRemoteAuthTLS",
						Values:      stringValues("starttls=no"),
					})
				}
			}
			_, err := loadRemoteAuthRuntimeConfiguration(directory.Entry{
				DN:         "olcOverlay=remoteauth,olcDatabase=mdb,cn=config",
				Attributes: attributes,
			})
			if err == nil {
				t.Fatal("invalid remoteauth configuration was accepted")
			}
		})
	}
}

func TestValidateRemoteAuthSchema(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	valid := &remoteAuthRuntimeConfiguration{
		dnAttribute:     "seeAlso",
		domainAttribute: "description",
	}
	if err := validateRemoteAuthSchema(registry, valid); err != nil {
		t.Fatalf("validateRemoteAuthSchema(valid): %v", err)
	}
	invalid := *valid
	invalid.dnAttribute = "undefinedRemoteDN"
	if err := validateRemoteAuthSchema(registry, &invalid); err == nil {
		t.Fatal("undefined remote DN attribute was accepted")
	}
}

func TestLDAPClientRemoteAuthDelegatesAndStoresPassword(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	providerRunning := true
	t.Cleanup(func() {
		if providerRunning {
			stopProvider()
		}
	})

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedDirectory(t, consumerStore)
	seedRemoteAuthConfiguration(t, consumerStore, providerAddress, true)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	userDN := "uid=alice,ou=people,dc=example,dc=com"
	if err := client.Bind(userDN, "wrong"); err == nil {
		t.Fatal("remoteauth accepted an invalid remote password")
	} else {
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	}
	if err := client.Bind(userDN, "secret"); err != nil {
		t.Fatalf("remoteauth Bind(): %v", err)
	}

	storedEntry := readStoredEntry(t, consumerStore, userDN)
	passwords := storedEntry.Values("userPassword")
	if len(passwords) != 1 || !strings.HasPrefix(string(passwords[0]), "{SSHA}") ||
		!auth.VerifyPassword(passwords[0], []byte("secret")) {
		t.Fatalf("stored remoteauth password = %q", passwords)
	}

	stopProvider()
	providerRunning = false
	if err := client.Bind(userDN, "secret"); err != nil {
		t.Fatalf("stored local password Bind() after provider stop: %v", err)
	}
}

func TestLDAPClientRemoteAuthUsesLocalPasswordAndReportsUnavailable(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedDirectory(t, consumerStore)
	seedRemoteAuthConfiguration(t, consumerStore, providerAddress, false)
	seedRemoteAuthLocalUser(t, consumerStore)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=local,ou=people,dc=example,dc=com", "local-secret"); err != nil {
		t.Fatalf("local password Bind(): %v", err)
	}

	stopProvider()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err == nil {
		t.Fatal("remoteauth succeeded while provider was stopped")
	} else {
		assertLDAPResultCode(t, err, ldap.LDAPResultOperationsError)
	}
}

func TestRemoteAuthRealmProvidersFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "realm.txt")
	if err := os.WriteFile(
		path,
		[]byte("ldap-one.example.test comment\nldaps://ldap-two.example.test\n\n"),
		0o600,
	); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	providers, err := remoteAuthRealmProviders("file://" + path)
	if err != nil {
		t.Fatalf("remoteAuthRealmProviders(): %v", err)
	}
	want := []string{
		"ldap://ldap-one.example.test",
		"ldaps://ldap-two.example.test",
	}
	if len(providers) != len(want) {
		t.Fatalf("providers = %#v", providers)
	}
	for index := range want {
		if providers[index] != want[index] {
			t.Fatalf("providers = %#v, want %#v", providers, want)
		}
	}
	if _, err := remoteAuthRealmProviders("file:///does/not/exist"); err == nil {
		t.Fatal("missing realm file was accepted")
	}
}

func TestRemoteAuthRealmSelection(t *testing.T) {
	t.Parallel()

	configuration := remoteAuthRuntimeConfiguration{
		mappings:     map[string]string{"emea": "ldap://emea.example.test"},
		defaultRealm: "ldap://default.example.test",
	}
	for _, domain := range []string{"EMEA", "emea\\alice", "EMEA:alice"} {
		if got := remoteAuthRealm(configuration, domain); got != "ldap://emea.example.test" {
			t.Errorf("remoteAuthRealm(%q) = %q", domain, got)
		}
	}
	if got := remoteAuthRealm(configuration, "unknown"); got != configuration.defaultRealm {
		t.Fatalf("default realm = %q", got)
	}
}

func TestValidateRemoteAuthTLSPeerRequiresTLSForPins(t *testing.T) {
	t.Parallel()

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	transport := &syncConsumerTransport{connection: left, context: context.Background()}
	err := validateRemoteAuthTLSPeer(
		transport,
		"ldap.example.test",
		map[string]remoteAuthTLSPin{
			"ldap.example.test": {hash: "sha256", value: make([]byte, sha256.Size)},
		},
	)
	if err == nil {
		t.Fatal("TLS pin was accepted on a cleartext connection")
	}
}

func TestLDAPClientRemoteAuthStartTLSPeerPins(t *testing.T) {
	providerTLS := testServerTLSConfig(t)
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(
		t,
		providerStore,
		Config{TLSConfig: providerTLS},
	)
	defer stopProvider()
	certificatePath := writePBindTestCertificate(
		t,
		providerTLS.Certificates[0].Certificate[0],
	)
	certificate, err := x509.ParseCertificate(
		providerTLS.Certificates[0].Certificate[0],
	)
	if err != nil {
		t.Fatalf("ParseCertificate(): %v", err)
	}
	sha256Digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	sm3Digest := sm3.Sum(certificate.RawSubjectPublicKeyInfo)
	_, port, err := net.SplitHostPort(providerAddress)
	if err != nil {
		t.Fatalf("SplitHostPort(): %v", err)
	}
	providerURI := "ldap://localhost:" + port
	tlsValue := "starttls=critical tls_cacert=" + certificatePath +
		" tls_reqcert=demand tls_reqsan=demand"

	tests := []struct {
		name    string
		pin     string
		wantErr bool
	}{
		{
			name: "SHA-256",
			pin: "localhost sha256:" +
				base64.StdEncoding.EncodeToString(sha256Digest[:]),
		},
		{
			name: "SM3",
			pin: "localhost sm3:" +
				base64.StdEncoding.EncodeToString(sm3Digest[:]),
		},
		{
			name: "wrong digest",
			pin: "localhost sha256:" +
				base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)),
			wantErr: true,
		},
		{
			name: "missing host",
			pin: "other.example.test sha256:" +
				base64.StdEncoding.EncodeToString(sha256Digest[:]),
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			consumerStore := storage.NewMemory()
			defer consumerStore.Close()
			seedDirectory(t, consumerStore)
			seedRemoteAuthConfiguration(
				t,
				consumerStore,
				providerAddress,
				false,
			)
			setRemoteAuthTLS(
				t,
				consumerStore,
				providerURI,
				tlsValue,
				[]string{test.pin},
			)
			consumerAddress, stopConsumer := startServer(
				t,
				consumerStore,
				Config{},
			)
			defer stopConsumer()

			client, err := ldap.DialURL("ldap://" + consumerAddress)
			if err != nil {
				t.Fatalf("DialURL(): %v", err)
			}
			defer client.Close()
			err = client.Bind(
				"uid=alice,ou=people,dc=example,dc=com",
				"secret",
			)
			if !test.wantErr && err != nil {
				t.Fatalf("remoteauth StartTLS bind: %v", err)
			}
			if test.wantErr {
				if err == nil {
					t.Fatal("remoteauth accepted an invalid TLS peer pin")
				}
				assertLDAPResultCode(t, err, ldap.LDAPResultOperationsError)
			}
		})
	}
}

func seedRemoteAuthConfiguration(
	t *testing.T,
	store storage.Store,
	providerAddress string,
	storeOnSuccess bool,
) {
	t.Helper()
	dn, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", nil)
		entry.ReplaceValues("seeAlso", stringValues(dn.String()))
		entry.ReplaceValues("description", stringValues("EXAMPLE:alice"))
		if err := writer.Put(entry, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}remoteauth,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}remoteauth")},
				{Description: "olcRemoteAuthDNAttribute", Values: stringValues("seeAlso")},
				{Description: "olcRemoteAuthDomainAttribute", Values: stringValues("description")},
				{
					Description: "olcRemoteAuthMapping",
					Values:      stringValues("example ldap://" + providerAddress),
				},
				{Description: "olcRemoteAuthStore", Values: stringValues(strings.ToUpper(strconvBool(storeOnSuccess)))},
				{Description: "olcRemoteAuthRetryCount", Values: stringValues("0")},
				{Description: "olcRemoteAuthTLS", Values: stringValues("starttls=no")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed remoteauth configuration: %v", err)
	}
}

func seedRemoteAuthLocalUser(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "uid=local,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("local")},
				{Description: "cn", Values: stringValues("Local User")},
				{Description: "sn", Values: stringValues("User")},
				{Description: "userPassword", Values: stringValues("local-secret")},
				{Description: "seeAlso", Values: stringValues("uid=missing,ou=people,dc=example,dc=com")},
				{Description: "description", Values: stringValues("EXAMPLE")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed local remoteauth user: %v", err)
	}
}

func setRemoteAuthTLS(
	t *testing.T,
	store storage.Store,
	providerURI,
	tlsValue string,
	pins []string,
) {
	t.Helper()
	dn, err := directory.ParseDN(
		"olcOverlay={0}remoteauth,olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"olcRemoteAuthMapping",
			stringValues("example "+providerURI),
		)
		entry.ReplaceValues("olcRemoteAuthTLS", stringValues(tlsValue))
		entry.ReplaceValues("olcRemoteAuthTLSPeerkeyHash", stringValues(pins...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure remoteauth TLS: %v", err)
	}
}

func strconvBool(value bool) string {
	if value {
		return "TRUE"
	}
	return "FALSE"
}
