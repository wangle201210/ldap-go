package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseSyncConsumerCipherSuites(t *testing.T) {
	t.Parallel()

	suites, err := parseSyncConsumerCipherSuites(
		"ECDHE-RSA-AES128-GCM-SHA256:" +
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	)
	if err != nil {
		t.Fatalf("parse cipher suites: %v", err)
	}
	for _, identifier := range []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	} {
		if !slices.Contains(suites, identifier) {
			t.Fatalf("cipher suites %x do not contain %#x", suites, identifier)
		}
	}

	suites, err = parseSyncConsumerCipherSuites(
		"DEFAULT:!ECDHE-RSA-AES128-GCM-SHA256",
	)
	if err != nil {
		t.Fatalf("parse cipher exclusion: %v", err)
	}
	if slices.Contains(
		suites,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	) {
		t.Fatalf("excluded cipher remains in %x", suites)
	}
	if _, err := parseSyncConsumerCipherSuites(
		"TLS_AES_128_GCM_SHA256",
	); err == nil {
		t.Fatal("configurable TLS 1.3 cipher suite was accepted")
	}
	suites, err = parseSyncConsumerCipherSuites(
		"ECDHE-RSA-AES128-GCM-SHA256:" +
			"+TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	)
	if err != nil {
		t.Fatalf("parse absent cipher reorder: %v", err)
	}
	if len(suites) != 1 ||
		suites[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("cipher reorder added an absent suite: %x", suites)
	}
}

func TestParseSyncConsumerCurvePreferences(t *testing.T) {
	t.Parallel()

	curves, err := parseSyncConsumerCurvePreferences(
		"X25519:prime256v1:secp384r1",
	)
	if err != nil {
		t.Fatalf("parse curve preferences: %v", err)
	}
	if !slices.Equal(curves, []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}) {
		t.Fatalf("curve preferences = %#v", curves)
	}
	if _, err := parseSyncConsumerCurvePreferences("SM2"); err == nil {
		t.Fatal("SM2 was accepted as a standard TLS curve")
	}
}

func TestParseSyncConsumerTLCPCipherSuites(t *testing.T) {
	t.Parallel()

	suites, err := parseSyncConsumerTLCPCipherSuites(
		"ECC_SM4_GCM_SM3:ECDHE-SM4-CBC-SM3",
	)
	if err != nil {
		t.Fatalf("parse TLCP cipher suites: %v", err)
	}
	if len(suites) != 2 {
		t.Fatalf("TLCP cipher suites = %#v", suites)
	}
	if _, err := parseSyncConsumerTLCPCipherSuites(
		"ECDHE-RSA-AES128-GCM-SHA256",
	); err == nil {
		t.Fatal("standard TLS cipher suite was accepted for TLCP")
	}
	suites, err = parseSyncConsumerTLCPCipherSuites(
		"ECC_SM4_GCM_SM3:+ECDHE_SM4_CBC_SM3",
	)
	if err != nil {
		t.Fatalf("parse absent TLCP cipher reorder: %v", err)
	}
	if len(suites) != 1 {
		t.Fatalf("TLCP cipher reorder added an absent suite: %#v", suites)
	}
	if syncConsumerTLCPCipherSuitesRequireClientEncryption(
		[]uint16{suites[0]},
	) {
		t.Fatal("TLCP ECC suite unexpectedly requires a client encryption certificate")
	}
	if !syncConsumerTLCPCipherSuitesRequireClientEncryption(
		[]uint16{tlcp.ECDHE_SM4_CBC_SM3},
	) {
		t.Fatal("TLCP ECDHE suite did not require a client encryption certificate")
	}
	suites, err = parseSyncConsumerTLCPCipherSuites(
		"!ECDHE_SM4_CBC_SM3:ALL",
	)
	if err != nil {
		t.Fatalf("parse permanent TLCP cipher exclusion: %v", err)
	}
	if slices.Contains(suites, tlcp.ECDHE_SM4_CBC_SM3) {
		t.Fatalf("permanently excluded TLCP suite was restored: %#v", suites)
	}
}

func TestParseSyncConsumerTLCPProvider(t *testing.T) {
	t.Parallel()

	providers, err := parseSyncConsumerProviders(
		"ldap+tlcp://provider.example:1636",
	)
	if err != nil {
		t.Fatalf("parse TLCP provider: %v", err)
	}
	if !slices.Equal(
		providers,
		[]string{"ldap+tlcp://provider.example:1636"},
	) {
		t.Fatalf("TLCP providers = %q", providers)
	}
}

func TestBuildSyncConsumerTLCPConfigCertificateRequirements(t *testing.T) {
	t.Parallel()

	provider, err := url.Parse("ldap+tlcp://provider.example:1636")
	if err != nil {
		t.Fatalf("parse TLCP provider: %v", err)
	}
	defaultConfig, err := buildSyncConsumerTLCPConfig(
		syncConsumerConfig{},
		provider,
	)
	if err != nil {
		t.Fatalf("build default TLCP config: %v", err)
	}
	if syncConsumerTLCPCipherSuitesRequireClientEncryption(
		defaultConfig.CipherSuites,
	) {
		t.Fatalf(
			"default TLCP config without dual client certificates offers ECDHE: %#v",
			defaultConfig.CipherSuites,
		)
	}
	_, err = buildSyncConsumerTLCPConfig(syncConsumerConfig{
		tls: syncConsumerTLSConfig{
			cipherSuite: "ECDHE_SM4_GCM_SM3",
		},
	}, provider)
	if err == nil || !strings.Contains(err.Error(), "signing and encryption") {
		t.Fatalf("ECDHE without dual client certificates error = %v", err)
	}

	standardProvider, err := url.Parse("ldaps://provider.example")
	if err != nil {
		t.Fatalf("parse LDAPS provider: %v", err)
	}
	_, err = buildSyncConsumerTLSConfig(syncConsumerConfig{
		tls: syncConsumerTLSConfig{
			tlcpEncryptionCertificate: "/tmp/client-enc.crt",
			tlcpEncryptionKey:         "/tmp/client-enc.key",
		},
	}, standardProvider)
	if err == nil || !strings.Contains(err.Error(), "ldap+tlcp") {
		t.Fatalf("TLCP client pair on standard TLS error = %v", err)
	}
}

func TestLoadSyncConsumerTLSMaterialExplicitCAIsExclusive(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	key := generateECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(850),
		Subject:               pkix.Name{CommonName: "exclusive syncrepl CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der := createCertificate(
		t,
		template,
		template,
		&key.PublicKey,
		key,
	)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}), 0o600); err != nil {
		t.Fatalf("write explicit CA: %v", err)
	}
	material, err := loadSyncConsumerTLSMaterial(syncConsumerTLSConfig{
		caCertificate: path,
	})
	if err != nil {
		t.Fatalf("load explicit CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse explicit CA: %v", err)
	}
	expectedRoots := x509.NewCertPool()
	expectedRoots.AddCert(certificate)
	if !material.roots.Equal(expectedRoots) {
		t.Fatal("explicit CA pool does not contain exactly the configured authority")
	}
}

func TestSyncConsumerTLSHostnamePolicies(t *testing.T) {
	t.Parallel()

	commonNameOnly := &x509.Certificate{
		Subject: pkix.Name{CommonName: "ldap.example.com"},
	}
	for _, policy := range []string{"never", "allow", "try"} {
		if err := verifySyncConsumerTLSHostname(
			commonNameOnly,
			"ldap.example.com",
			policy,
		); err != nil {
			t.Fatalf("%s rejected matching common name: %v", policy, err)
		}
	}
	if err := verifySyncConsumerTLSHostname(
		commonNameOnly,
		"ldap.example.com",
		"demand",
	); err == nil {
		t.Fatal("demand accepted a certificate without subjectAltName")
	}

	mismatchedSAN := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "ldap.example.com"},
		DNSNames: []string{"other.example.com"},
		Extensions: []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 17},
		}},
	}
	if err := verifySyncConsumerTLSHostname(
		mismatchedSAN,
		"ldap.example.com",
		"allow",
	); err != nil {
		t.Fatalf("allow did not fall back to common name: %v", err)
	}
	for _, policy := range []string{"try", "demand", "hard"} {
		if err := verifySyncConsumerTLSHostname(
			mismatchedSAN,
			"ldap.example.com",
			policy,
		); err == nil {
			t.Fatalf("%s accepted a mismatched subjectAltName", policy)
		}
	}

	wildcard := &x509.Certificate{
		Subject: pkix.Name{CommonName: "*.example.com"},
	}
	if err := verifySyncConsumerTLSHostname(
		wildcard,
		"ldap.example.com",
		"never",
	); err != nil {
		t.Fatalf("wildcard common name: %v", err)
	}
	if err := verifySyncConsumerTLSHostname(
		wildcard,
		"deep.ldap.example.com",
		"never",
	); err == nil {
		t.Fatal("wildcard common name matched more than one label")
	}
}

func TestSyncConsumerTLSCRLVerification(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	caKey := generateECDSAKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(900),
		Subject:               pkix.Name{CommonName: "syncrepl CRL CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER := createCertificate(
		t,
		caTemplate,
		caTemplate,
		&caKey.PublicKey,
		caKey,
	)
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CRL CA: %v", err)
	}
	leafKey := generateECDSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(901),
		Subject:      pkix.Name{CommonName: "ldap.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER := createCertificate(
		t,
		leafTemplate,
		caCertificate,
		&leafKey.PublicKey,
		caKey,
	)
	leafCertificate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse CRL leaf: %v", err)
	}

	validCRL := createSyncConsumerTestCRL(
		t,
		caCertificate,
		caKey,
		now,
		nil,
	)
	if err := verifySyncConsumerTLSCRLs(
		[]*x509.Certificate{leafCertificate, caCertificate},
		[]*x509.RevocationList{validCRL},
		"peer",
		now,
	); err != nil {
		t.Fatalf("valid CRL rejected certificate: %v", err)
	}
	revokedCRL := createSyncConsumerTestCRL(
		t,
		caCertificate,
		caKey,
		now,
		[]x509.RevocationListEntry{{
			SerialNumber:   leafCertificate.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
		}},
	)
	if err := verifySyncConsumerTLSCRLs(
		[]*x509.Certificate{leafCertificate, caCertificate},
		[]*x509.RevocationList{revokedCRL},
		"peer",
		now,
	); err == nil {
		t.Fatal("revoked TLS certificate was accepted")
	}
}

func TestConfigureSyncConsumerDialerMapsSocketPolicies(t *testing.T) {
	t.Parallel()

	dialer := &net.Dialer{}
	config := syncConsumerConfig{
		keepalive: syncConsumerKeepalive{
			idle:     240,
			probes:   10,
			interval: 30,
			set:      true,
		},
		tcpUserTimeout: 5 * time.Second,
	}
	if err := configureSyncConsumerDialer(dialer, config); err != nil {
		t.Fatalf("configure dialer: %v", err)
	}
	if !dialer.KeepAliveConfig.Enable ||
		dialer.KeepAliveConfig.Idle != 240*time.Second ||
		dialer.KeepAliveConfig.Interval != 30*time.Second ||
		dialer.KeepAliveConfig.Count != 10 {
		t.Fatalf("keepalive config = %#v", dialer.KeepAliveConfig)
	}
	if dialer.Control == nil {
		t.Fatal("tcp-user-timeout did not install socket control")
	}
}

func TestSyncreplConsumerNoncriticalStartTLSFallsBack(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedSpecialSyncConsumerDatabase(
		t,
		consumerStore,
		providerAddress,
		`filter="(objectClass=*)" type=refreshAndPersist starttls=yes`,
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)
}

func TestSyncreplConsumerCriticalStartTLSStops(t *testing.T) {
	t.Parallel()

	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumer, _, _ := newSyncConsumerUnitServer(t)
	suffix := mustSyncConsumerDN(t, "dc=example,dc=com")
	config, err := parseSyncConsumerConfig(
		`rid=1 provider=ldap://`+providerAddress+
			` bindmethod=simple binddn="`+syncTestRootDN+
			`" credentials="`+syncTestRootPassword+
			`" searchbase="dc=example,dc=com"`+
			` type=refreshOnly starttls=critical`,
		"critical-starttls",
		[]directory.DN{suffix},
	)
	if err != nil {
		t.Fatalf("parse critical StartTLS consumer: %v", err)
	}
	err = consumer.runSyncConsumerCycle(
		context.Background(),
		config,
		config.providerURLs[0],
	)
	if err == nil || !strings.Contains(err.Error(), "start TLS") {
		t.Fatalf("critical StartTLS error = %v", err)
	}
}

func createSyncConsumerTestCRL(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey crypto.Signer,
	now time.Time,
	revoked []x509.RevocationListEntry,
) *x509.RevocationList {
	t.Helper()
	raw, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:                    big.NewInt(1),
			ThisUpdate:                now.Add(-time.Minute),
			NextUpdate:                now.Add(time.Hour),
			RevokedCertificateEntries: revoked,
		},
		issuer,
		issuerKey,
	)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	return crl
}
