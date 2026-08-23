package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestGlobalTLSConfigurationLoadsInlineDER(t *testing.T) {
	material := newGlobalTLSTestAuthority(t)
	serverCertificate := material.issue(t, "inline-server", true)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificate;binary":    {serverCertificate.certificateDER},
		"olcTLSCertificateKey;binary": {serverCertificate.privateKeyDER},
		"olcTLSCACertificate;binary":  {material.certificateDER},
		"olcTLSVerifyClient":          {[]byte("demand")},
		"olcTLSProtocolMin":           {[]byte("3.3")},
		"olcTLSCipherSuite": {
			[]byte("ECDHE-ECDSA-AES128-GCM-SHA256"),
		},
	})

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	instance.closeSQLBackends()
	transport, ok := instance.runtime.Load().secureTransport.(standardTLSTransport)
	if !ok {
		t.Fatalf("runtime TLS transport = %T", instance.runtime.Load().secureTransport)
	}
	configuration := transport.config
	if len(configuration.Certificates) != 1 ||
		configuration.Certificates[0].Leaf.Subject.CommonName != "inline-server" {
		t.Fatalf("TLS certificates = %#v", configuration.Certificates)
	}
	if configuration.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", configuration.ClientAuth)
	}
	if configuration.ClientCAs == nil ||
		len(configuration.ClientCAs.Subjects()) != 1 {
		t.Fatal("inline DER CA was not loaded")
	}
	if configuration.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", configuration.MinVersion)
	}
	if len(configuration.CipherSuites) != 1 ||
		configuration.CipherSuites[0] != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("CipherSuites = %#v", configuration.CipherSuites)
	}
}

func TestGlobalTLSCRLCheckNoneIsAnInertImportDefault(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCRLCheck": {[]byte("none")},
	})
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer instance.closeSQLBackends()
	if instance.runtime.Load().secureTransport != nil {
		t.Fatal("olcTLSCRLCheck=none enabled TLS without certificate material")
	}
}

func TestGlobalTLSCRLPoliciesFromOpenLDAPConfigurationImport(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	now := time.Now().UTC()
	crl := createGlobalTLSTestCRL(
		t,
		authority,
		authority.privateKey,
		1,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
	)
	crlPath := filepath.Join(t.TempDir(), "clients.crl")
	if err := os.WriteFile(crlPath, crl.pem, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
	for _, test := range []struct {
		policy  string
		crlFile string
	}{
		{policy: "none"},
		{policy: "peer", crlFile: crlPath},
	} {
		t.Run(test.policy, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			ldif := fmt.Sprintf(
				"dn: cn=config\nobjectClass: olcGlobal\ncn: config\nolcTLSCRLCheck: %s\n",
				test.policy,
			)
			if test.crlFile != "" {
				ldif += "olcTLSCRLFile: " + test.crlFile + "\n"
			}
			if _, err := migration.ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(ldif),
				migration.ImportOptions{
					Database:             "0",
					Replace:              true,
					SkipSchemaValidation: true,
				},
			); err != nil {
				t.Fatalf("ImportLDIF(OpenLDAP cn=config): %v\n%s", err, ldif)
			}
			instance, err := New(Config{Store: store})
			if err != nil {
				t.Fatalf("New(imported cn=config): %v", err)
			}
			defer instance.closeSQLBackends()
			if instance.runtime.Load().secureTransport != nil {
				t.Fatalf("imported olcTLSCRLCheck=%s enabled TLS without server material", test.policy)
			}
			if err := store.View(context.Background(), func(reader storage.Reader) error {
				entry, err := reader.GetIn(configurationStoragePartition, configurationSuffix)
				if err != nil {
					return err
				}
				attributes, err := parseGlobalTLSAttributes(entry)
				if err != nil {
					return err
				}
				if attributes.crlCheck != test.policy || attributes.crlFile != test.crlFile {
					return fmt.Errorf(
						"imported CRL attributes = %q, %q; want %q, %q",
						attributes.crlCheck,
						attributes.crlFile,
						test.policy,
						test.crlFile,
					)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGlobalTLSCRLConfigurationParsesPEMAndDERWithoutServerMaterial(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	now := time.Now().UTC()
	crl := createGlobalTLSTestCRL(
		t,
		authority,
		authority.privateKey,
		1,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
	)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "PEM", data: crl.pem},
		{name: "DER", data: crl.der},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clients.crl")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatalf("write CRL: %v", err)
			}
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedGlobalTLSAttributes(t, store, map[string][][]byte{
				"olcTLSCRLCheck": {[]byte("peer")},
				"olcTLSCRLFile":  {[]byte(path)},
			})
			instance, err := New(Config{Store: store})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			defer instance.closeSQLBackends()
			if instance.runtime.Load().secureTransport != nil {
				t.Fatal("CRL-only configuration enabled TLS")
			}
		})
	}
	for _, data := range [][]byte{
		append([]byte("not PEM\n"), crl.pem...),
		append(append([]byte(nil), crl.pem...), []byte("not PEM")...),
	} {
		if _, err := parseGlobalTLSCRLs(data); err == nil {
			t.Fatal("CRL parser accepted non-PEM bytes around a PEM CRL")
		}
	}
}

func TestGlobalTLSCRLLazyConfigurationRejectsInvalidSyntax(t *testing.T) {
	for _, test := range []struct {
		name        string
		policy      string
		fileData    []byte
		want        string
		includeFile bool
	}{
		{name: "policy", policy: "sometimes", want: "expected none, peer, or all"},
		{
			name:        "malformed file",
			policy:      "peer",
			fileData:    []byte("not a CRL"),
			want:        "parse DER CRL",
			includeFile: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			attributes := map[string][][]byte{
				"olcTLSCRLCheck": {[]byte(test.policy)},
			}
			if test.includeFile {
				path := filepath.Join(t.TempDir(), "clients.crl")
				if err := os.WriteFile(path, test.fileData, 0o600); err != nil {
					t.Fatalf("write malformed CRL: %v", err)
				}
				attributes["olcTLSCRLFile"] = [][]byte{[]byte(path)}
			}
			seedGlobalTLSAttributes(t, store, attributes)
			_, err := New(Config{Store: store})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGlobalTLSCRLVerificationMatchesPeerAndAllSemantics(t *testing.T) {
	now := time.Now().UTC()
	root := newGlobalTLSTestAuthority(t)
	intermediate := root.issueAuthority(t, "ldap-go intermediate CA")
	client := intermediate.issue(t, "chain-client", false)
	leafCRL := createGlobalTLSTestCRL(
		t,
		intermediate,
		intermediate.privateKey,
		1,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
	)
	issuerCRL := createGlobalTLSTestCRL(
		t,
		root,
		root.privateKey,
		1,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
	)
	chain := []*x509.Certificate{
		client.certificate,
		intermediate.certificate,
		root.certificate,
	}
	if err := verifyGlobalTLSCRLs(chain, []*x509.RevocationList{leafCRL.crl}, "peer", now); err != nil {
		t.Fatalf("peer CRL check: %v", err)
	}
	if err := verifyGlobalTLSCRLs(chain, []*x509.RevocationList{leafCRL.crl}, "all", now); err == nil {
		t.Fatal("all CRL check accepted a chain without the intermediate issuer CRL")
	}
	if err := verifyGlobalTLSCRLs(
		chain,
		[]*x509.RevocationList{leafCRL.crl, issuerCRL.crl},
		"all",
		now,
	); err != nil {
		t.Fatalf("all CRL check: %v", err)
	}

	revoked := createGlobalTLSTestCRL(
		t,
		intermediate,
		intermediate.privateKey,
		2,
		now,
		now.Add(time.Hour),
		[]x509.RevocationListEntry{{
			SerialNumber:   client.certificate.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
		}},
	)
	if err := verifyGlobalTLSCRLs(chain, []*x509.RevocationList{leafCRL.crl, revoked.crl}, "peer", now); err == nil {
		t.Fatal("newer CRL did not revoke the client certificate")
	}
	removed := createGlobalTLSTestCRL(
		t,
		intermediate,
		intermediate.privateKey,
		3,
		now.Add(time.Minute),
		now.Add(time.Hour),
		[]x509.RevocationListEntry{{
			SerialNumber:   client.certificate.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
			ReasonCode:     8,
		}},
	)
	if err := verifyGlobalTLSCRLs(chain, []*x509.RevocationList{revoked.crl, removed.crl}, "peer", now.Add(time.Minute)); err != nil {
		t.Fatalf("removeFromCRL entry rejected client certificate: %v", err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(wrong CRL signer): %v", err)
	}
	badSignature := createGlobalTLSTestCRL(
		t,
		intermediate,
		wrongKey,
		4,
		now,
		now.Add(time.Hour),
		nil,
	)
	if err := verifyGlobalTLSCRLs(chain, []*x509.RevocationList{badSignature.crl}, "peer", now); err == nil {
		t.Fatal("CRL with an invalid issuer signature was accepted")
	}
	for _, crl := range []globalTLSTestCRL{
		createGlobalTLSTestCRL(t, intermediate, intermediate.privateKey, 5, now.Add(time.Minute), now.Add(time.Hour), nil),
		createGlobalTLSTestCRL(t, intermediate, intermediate.privateKey, 6, now.Add(-time.Hour), now.Add(-time.Minute), nil),
	} {
		if err := verifyGlobalTLSCRLs(chain, []*x509.RevocationList{crl.crl}, "peer", now); err == nil {
			t.Fatal("CRL outside its ThisUpdate/NextUpdate window was accepted")
		}
	}
}

func TestGlobalTLSCRLCheckRequiresCurrentCRLWhenTLSIsEnabled(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	serverCertificate := authority.issue(t, "crl-required-server", true)
	now := time.Now().UTC()
	expired := createGlobalTLSTestCRL(
		t,
		authority,
		authority.privateKey,
		1,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
		nil,
	)
	expiredPath := filepath.Join(t.TempDir(), "expired.crl")
	if err := os.WriteFile(expiredPath, expired.pem, 0o600); err != nil {
		t.Fatalf("write expired CRL: %v", err)
	}
	for _, test := range []struct {
		name    string
		crlFile string
	}{
		{name: "missing"},
		{name: "expired", crlFile: expiredPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			attributes := map[string][][]byte{
				"olcTLSCertificate;binary":    {serverCertificate.certificateDER},
				"olcTLSCertificateKey;binary": {serverCertificate.privateKeyDER},
				"olcTLSCRLCheck":              {[]byte("peer")},
			}
			if test.crlFile != "" {
				attributes["olcTLSCRLFile"] = [][]byte{[]byte(test.crlFile)}
			}
			seedGlobalTLSAttributes(t, store, attributes)
			_, err := New(Config{Store: store})
			if err == nil || !strings.Contains(err.Error(), "current olcTLSCRLFile CRL") {
				t.Fatalf("New() error = %v, want current CRL requirement", err)
			}
		})
	}
}

func TestGlobalTLSConfigurationRejectsInexactCipherSelectors(t *testing.T) {
	for _, value := range []string{
		"DEFAULT",
		"HIGH:!aNULL",
		"ALL",
		"@SECLEVEL=2",
		"TLS_AES_128_GCM_SHA256",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := parseGlobalTLSCipherSuites(value); err == nil {
				t.Fatalf("parseGlobalTLSCipherSuites(%q) succeeded", value)
			}
		})
	}
}

func TestGlobalTLSConfigurationVerifyClientMapping(t *testing.T) {
	tests := []struct {
		value string
		want  tls.ClientAuthType
	}{
		{value: "never", want: tls.NoClientCert},
		{value: "allow", want: tls.RequestClientCert},
		{value: "try", want: tls.VerifyClientCertIfGiven},
		{value: "demand", want: tls.RequireAndVerifyClientCert},
		{value: "hard", want: tls.RequireAndVerifyClientCert},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := parseGlobalTLSVerifyClient(test.value)
			if err != nil || got != test.want {
				t.Fatalf("parseGlobalTLSVerifyClient() = %v, %v; want %v", got, err, test.want)
			}
		})
	}
	if _, err := parseGlobalTLSVerifyClient("sometimes"); err == nil {
		t.Fatal("invalid verify-client policy was accepted")
	}
}

func TestGlobalTLSConfigurationProtocolMinMapping(t *testing.T) {
	tests := map[string]uint16{
		"3.1": tls.VersionTLS10,
		"3.2": tls.VersionTLS11,
		"3.3": tls.VersionTLS12,
		"3.4": tls.VersionTLS13,
	}
	for value, want := range tests {
		got, err := parseGlobalTLSProtocolMin(value)
		if err != nil || got != want {
			t.Errorf("parseGlobalTLSProtocolMin(%q) = %x, %v; want %x", value, got, err, want)
		}
	}
	if _, err := parseGlobalTLSProtocolMin("TLS1.2"); err == nil {
		t.Fatal("non-OpenLDAP protocol syntax was accepted")
	}
}

func TestGlobalTLSConfigurationRejectsExplicitTransportConflict(t *testing.T) {
	material := newGlobalTLSTestAuthority(t)
	serverCertificate := material.issue(t, "configured-server", true)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificate;binary":    {serverCertificate.certificateDER},
		"olcTLSCertificateKey;binary": {serverCertificate.privateKeyDER},
	})

	for _, config := range []Config{
		{Store: store, TLSConfig: testServerTLSConfig(t)},
		{Store: store, SecureTransport: waitingSecureTransport{}},
	} {
		_, err := New(config)
		if err == nil || !strings.Contains(err.Error(), "explicit Config TLS transport") {
			t.Fatalf("New() error = %v, want explicit transport conflict", err)
		}
	}

	emptyStore := storage.NewMemory()
	t.Cleanup(func() { _ = emptyStore.Close() })
	_, err := ValidateConfiguration(context.Background(), Config{
		Store:           emptyStore,
		TLSConfig:       testServerTLSConfig(t),
		SecureTransport: waitingSecureTransport{},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("ValidateConfiguration() error = %v, want mutual exclusion", err)
	}
}

func TestGlobalTLSConfigurationRejectsInvalidCertificateMaterial(t *testing.T) {
	material := newGlobalTLSTestAuthority(t)
	first := material.issue(t, "first", true)
	second := material.issue(t, "second", true)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificate;binary":    {first.certificateDER},
		"olcTLSCertificateKey;binary": {second.privateKeyDER},
	})

	_, err := New(Config{Store: store})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "private key") {
		t.Fatalf("New() error = %v, want key-pair mismatch", err)
	}
}

func TestGlobalTLSConfigurationRequiresCompleteMaterial(t *testing.T) {
	material := newGlobalTLSTestAuthority(t)
	certificate := material.issue(t, "complete-material", true)
	tests := []struct {
		name       string
		attributes map[string][][]byte
		want       string
	}{
		{
			name: "certificate only",
			attributes: map[string][][]byte{
				"olcTLSCertificate;binary": {certificate.certificateDER},
			},
			want: "olcTLSCertificateKey",
		},
		{
			name: "key only",
			attributes: map[string][][]byte{
				"olcTLSCertificateKey;binary": {certificate.privateKeyDER},
			},
			want: "olcTLSCertificate",
		},
		{
			name: "missing certificate file",
			attributes: map[string][][]byte{
				"olcTLSCertificateFile":       {[]byte("/missing/ldap-go/server.pem")},
				"olcTLSCertificateKey;binary": {certificate.privateKeyDER},
			},
			want: "olcTLSCertificateFile",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedGlobalTLSAttributes(t, store, test.attributes)
			_, err := New(Config{Store: store})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New() error = %v, want directive %s", err, test.want)
			}
		})
	}
}

func TestOnlineConfigurationRejectsInvalidGlobalTLSCRLPolicyAndRollsBack(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	request := ldap.NewModifyRequest("cn=config", nil)
	request.Replace("olcTLSCRLCheck", []string{"sometimes"})
	err = client.Modify(request)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Fatalf("online Modify error = %v, want constraintViolation", err)
	}

	assertGlobalTLSAttributeAbsent(t, store, "olcTLSCRLCheck")
}

func TestOpenLDAPGlobalTLSConfigurationRebuildsContextSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	source, err := os.ReadFile(filepath.Join(sourceRoot, "servers", "slapd", "bconfig.c"))
	if err != nil {
		t.Fatalf("read OpenLDAP bconfig.c: %v", err)
	}
	text := string(source)
	for _, anchor := range []string{
		"config_tls_cleanup(ConfigArgs *c)",
		"ldap_pvt_tls_ctx_free( slap_tls_ctx );",
		"LDAP_OPT_X_TLS_NEWCTX",
		"config_tls_option(ConfigArgs *c)",
		"config_tls_config(ConfigArgs *c)",
		"config_push_cleanup( c, config_tls_cleanup );",
	} {
		if !strings.Contains(text, anchor) {
			t.Errorf("OpenLDAP TLS configuration source missing %q", anchor)
		}
	}
	for _, attribute := range recognizedGlobalTLSDirectives {
		if !strings.Contains(text, "NAME '"+attribute+"'") {
			t.Errorf("OpenLDAP TLS configuration source missing %s", attribute)
		}
	}
	openSSLSource, err := os.ReadFile(filepath.Join(
		sourceRoot,
		"libraries",
		"libldap",
		"tls_o.c",
	))
	if err != nil {
		t.Fatalf("read OpenLDAP tls_o.c: %v", err)
	}
	for _, anchor := range []string{
		"LDAP_OPT_X_TLS_CRL_PEER",
		"X509_V_FLAG_CRL_CHECK",
		"LDAP_OPT_X_TLS_CRL_ALL",
		"X509_V_FLAG_CRL_CHECK_ALL",
	} {
		if !strings.Contains(string(openSSLSource), anchor) {
			t.Errorf("OpenLDAP TLS CRL source missing %q", anchor)
		}
	}
}

type globalTLSTestCertificate struct {
	certificateDER []byte
	privateKeyDER  []byte
	certificatePEM []byte
	privateKeyPEM  []byte
	tlsCertificate tls.Certificate
	certificate    *x509.Certificate
}

type globalTLSTestCRL struct {
	der []byte
	pem []byte
	crl *x509.RevocationList
}

type globalTLSTestAuthority struct {
	certificateDER []byte
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
}

func newGlobalTLSTestAuthority(t *testing.T) globalTLSTestAuthority {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA): %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "ldap-go test CA"},
		SubjectKeyId: []byte("ldap-go test root CA"),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate(CA): %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}
	return globalTLSTestAuthority{
		certificateDER: der,
		certificate:    certificate,
		privateKey:     privateKey,
	}
}

func (authority globalTLSTestAuthority) issueAuthority(
	t *testing.T,
	commonName string,
) globalTLSTestAuthority {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", commonName, err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		SubjectKeyId:          []byte(commonName),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		authority.certificate,
		&privateKey.PublicKey,
		authority.privateKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", commonName, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", commonName, err)
	}
	return globalTLSTestAuthority{
		certificateDER: der,
		certificate:    certificate,
		privateKey:     privateKey,
	}
}

func (authority globalTLSTestAuthority) issue(
	t *testing.T,
	commonName string,
	server bool,
) globalTLSTestCertificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", commonName, err)
	}
	now := time.Now()
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		authority.certificate,
		&privateKey.PublicKey,
		authority.privateKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", commonName, err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey(%s): %v", commonName, err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	tlsCertificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair(%s): %v", commonName, err)
	}
	return globalTLSTestCertificate{
		certificateDER: certificateDER,
		privateKeyDER:  privateKeyDER,
		certificatePEM: certificatePEM,
		privateKeyPEM:  privateKeyPEM,
		tlsCertificate: tlsCertificate,
		certificate:    mustParseGlobalTLSTestCertificate(t, certificateDER),
	}
}

func mustParseGlobalTLSTestCertificate(
	t *testing.T,
	der []byte,
) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(): %v", err)
	}
	return certificate
}

func createGlobalTLSTestCRL(
	t *testing.T,
	issuer globalTLSTestAuthority,
	signer *ecdsa.PrivateKey,
	number int64,
	thisUpdate,
	nextUpdate time.Time,
	revoked []x509.RevocationListEntry,
) globalTLSTestCRL {
	t.Helper()
	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:                    big.NewInt(number),
			ThisUpdate:                thisUpdate,
			NextUpdate:                nextUpdate,
			RevokedCertificateEntries: revoked,
		},
		issuer.certificate,
		signer,
	)
	if err != nil {
		t.Fatalf("CreateRevocationList(): %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList(): %v", err)
	}
	return globalTLSTestCRL{
		der: der,
		pem: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}),
		crl: crl,
	}
}

func seedGlobalTLSAttributes(
	t *testing.T,
	store storage.Store,
	attributes map[string][][]byte,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if errors.Is(err, storage.ErrEntryNotFound) {
			entry = directory.Entry{
				DN: "cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcGlobal")},
					{Description: "cn", Values: stringValues("config")},
				},
			}
		} else if err != nil {
			return err
		}
		for description, values := range attributes {
			entry.ReplaceValues(description, values)
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed global TLS attributes: %v", err)
	}
}

func assertGlobalTLSAttributeAbsent(
	t *testing.T,
	store storage.Store,
	description string,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		if globalTLSAttributePresent(entry, description) {
			return errors.New("rejected TLS directive was committed to cn=config")
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}
