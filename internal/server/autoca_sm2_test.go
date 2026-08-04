package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var autoCASM2TestNow = time.Date(2026, 8, 3, 9, 10, 11, 987654321, time.FixedZone("CST", 8*60*60))

func TestAutoCASM2SelfSignedCA(t *testing.T) {
	pair := mustGenerateAutoCASM2CA(t)
	certificate := mustParseAutoCASM2Certificate(t, pair.CertificateDER)
	privateKey := mustParseAutoCASM2PrivateKey(t, pair.PrivateKeyDER)

	if certificate.SignatureAlgorithm != smx509.SM2WithSM3 {
		t.Fatalf("signature algorithm = %v, want SM2WithSM3", certificate.SignatureAlgorithm)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatalf("verify SM2 CA self-signature: %v", err)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		t.Fatalf("CA constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
	}
	wantUsage := smx509.KeyUsageDigitalSignature | smx509.KeyUsageCRLSign | smx509.KeyUsageCertSign
	if certificate.KeyUsage != wantUsage {
		t.Fatalf("CA key usage = %v, want %v", certificate.KeyUsage, wantUsage)
	}
	assertAutoCASM2PublicKeyMatch(t, certificate.PublicKey, privateKey.Public())
	if certificate.Subject.CommonName != "Directory SM2 CA" ||
		len(certificate.Subject.OrganizationalUnit) != 1 ||
		certificate.Subject.OrganizationalUnit[0] != "Security" {
		t.Fatalf("CA subject = %v", certificate.Subject)
	}
	if !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
		t.Fatalf("CA subject %v differs from issuer %v", certificate.Subject, certificate.Issuer)
	}
	if !certificate.NotBefore.Equal(autoCASM2TestNow.UTC().Truncate(time.Second)) ||
		!certificate.NotAfter.Equal(autoCASM2TestNow.UTC().Truncate(time.Second).AddDate(0, 0, 3652)) {
		t.Fatalf("CA validity = %s to %s", certificate.NotBefore, certificate.NotAfter)
	}
	if certificate.SerialNumber.Sign() <= 0 || certificate.SerialNumber.BitLen() != 64 {
		t.Fatalf("CA serial = %s (%d bits), want positive 64-bit", certificate.SerialNumber, certificate.SerialNumber.BitLen())
	}
	if len(certificate.SubjectKeyId) == 0 || !bytes.Equal(certificate.SubjectKeyId, certificate.AuthorityKeyId) {
		t.Fatal("CA subject and authority key identifiers are missing or differ")
	}
	wantKeyID, err := autoCASM2SubjectKeyID(certificate.PublicKey)
	if err != nil {
		t.Fatalf("derive CA key identifier: %v", err)
	}
	if !bytes.Equal(certificate.SubjectKeyId, wantKeyID) {
		t.Fatal("CA subject key identifier differs from the AutoCA profile")
	}
}

func TestAutoCASM2UserCertificate(t *testing.T) {
	caPair := mustGenerateAutoCASM2CA(t)
	caCertificate := mustParseAutoCASM2Certificate(t, caPair.CertificateDER)
	pair, err := generateAutoCASM2UserCertificate(caPair, autoCAUserCertificateConfig{
		DN:      "uid=alice+cn=Alice Smith,ou=People,dc=example,dc=com",
		Mail:    "alice@example.com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow.Add(5 * time.Minute),
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate SM2 user certificate: %v", err)
	}
	certificate := mustParseAutoCASM2Certificate(t, pair.CertificateDER)
	privateKey := mustParseAutoCASM2PrivateKey(t, pair.PrivateKeyDER)

	if certificate.SignatureAlgorithm != smx509.SM2WithSM3 {
		t.Fatalf("signature algorithm = %v, want SM2WithSM3", certificate.SignatureAlgorithm)
	}
	if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("verify SM2 user certificate: %v", err)
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid {
		t.Fatalf("user constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
	}
	assertAutoCASM2PublicKeyMatch(t, certificate.PublicKey, privateKey.Public())
	if certificate.Subject.CommonName != "Alice Smith" ||
		len(certificate.Subject.OrganizationalUnit) != 1 ||
		certificate.Subject.OrganizationalUnit[0] != "People" {
		t.Fatalf("user subject = %v", certificate.Subject)
	}
	if certificate.Issuer.CommonName != caCertificate.Subject.CommonName {
		t.Fatalf("user issuer = %v, want %v", certificate.Issuer, caCertificate.Subject)
	}
	if len(certificate.EmailAddresses) != 1 || certificate.EmailAddresses[0] != "alice@example.com" {
		t.Fatalf("user RFC822 SAN = %v", certificate.EmailAddresses)
	}
	wantExtKeyUsage := []smx509.ExtKeyUsage{
		smx509.ExtKeyUsageClientAuth,
		smx509.ExtKeyUsageEmailProtection,
		smx509.ExtKeyUsageCodeSigning,
	}
	if !equalAutoCASM2ExtKeyUsages(certificate.ExtKeyUsage, wantExtKeyUsage) {
		t.Fatalf("user extended key usage = %v, want %v", certificate.ExtKeyUsage, wantExtKeyUsage)
	}
	wantUsage := smx509.KeyUsageDigitalSignature |
		smx509.KeyUsageContentCommitment |
		smx509.KeyUsageKeyEncipherment
	if certificate.KeyUsage != wantUsage {
		t.Fatalf("user key usage = %v, want %v", certificate.KeyUsage, wantUsage)
	}
	if !bytes.Equal(certificate.AuthorityKeyId, caCertificate.SubjectKeyId) {
		t.Fatal("user authority key identifier does not match CA subject key identifier")
	}

	// Standard crypto/x509 support is intentionally not a compatibility gate;
	// this national-crypto extension is validated with smx509.
	_, _ = x509.ParseCertificate(pair.CertificateDER)
}

func TestAutoCASM2UserCertificateWithoutMail(t *testing.T) {
	pair, err := generateAutoCASM2UserCertificate(mustGenerateAutoCASM2CA(t), autoCAUserCertificateConfig{
		DN:      "uid=nomail,ou=People,dc=example,dc=com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate SM2 user certificate without mail: %v", err)
	}
	certificate := mustParseAutoCASM2Certificate(t, pair.CertificateDER)
	if len(certificate.EmailAddresses) != 0 {
		t.Fatalf("user RFC822 SAN = %v, want none", certificate.EmailAddresses)
	}
	if hasAutoCACryptoExtension(certificate.Extensions, asn1.ObjectIdentifier{2, 5, 29, 17}) {
		t.Fatal("SM2 user certificate without mail contains a subjectAltName extension")
	}
}

func TestAutoCASM2ServerCertificate(t *testing.T) {
	caPair := mustGenerateAutoCASM2CA(t)
	caCertificate := mustParseAutoCASM2Certificate(t, caPair.CertificateDER)
	for name, ipHostNumber := range map[string]string{
		"IPv4": "192.0.2.26",
		"IPv6": "2001:db8::26",
	} {
		t.Run(name, func(t *testing.T) {
			pair, err := generateAutoCASM2ServerCertificate(caPair, autoCAServerCertificateConfig{
				DN:           "cn=ldap26,ou=Servers,dc=example,dc=com",
				IPHostNumber: ipHostNumber,
				KeyBits:      autoCASM2KeyBits,
				Days:         825,
				Now:          autoCASM2TestNow.Add(10 * time.Minute),
				Random:       rand.Reader,
			})
			if err != nil {
				t.Fatalf("generate SM2 server certificate: %v", err)
			}
			certificate := mustParseAutoCASM2Certificate(t, pair.CertificateDER)
			privateKey := mustParseAutoCASM2PrivateKey(t, pair.PrivateKeyDER)
			if certificate.SignatureAlgorithm != smx509.SM2WithSM3 {
				t.Fatalf("signature algorithm = %v, want SM2WithSM3", certificate.SignatureAlgorithm)
			}
			if certificate.IsCA || !certificate.BasicConstraintsValid {
				t.Fatalf("server constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
			}
			if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
				t.Fatalf("verify SM2 server certificate signature: %v", err)
			}
			assertAutoCASM2PublicKeyMatch(t, certificate.PublicKey, privateKey.Public())
			if certificate.Subject.CommonName != "ldap26" {
				t.Fatalf("server subject = %v", certificate.Subject)
			}
			wantUsage := smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyEncipherment
			if certificate.KeyUsage != wantUsage {
				t.Fatalf("server key usage = %v, want %v", certificate.KeyUsage, wantUsage)
			}
			wantExtKeyUsage := []smx509.ExtKeyUsage{
				smx509.ExtKeyUsageServerAuth,
				smx509.ExtKeyUsageClientAuth,
			}
			if !equalAutoCASM2ExtKeyUsages(certificate.ExtKeyUsage, wantExtKeyUsage) {
				t.Fatalf("server extended key usage = %v, want %v", certificate.ExtKeyUsage, wantExtKeyUsage)
			}
			if len(certificate.IPAddresses) != 1 || certificate.IPAddresses[0].String() != ipHostNumber {
				t.Fatalf("server IP SAN = %v, want %s", certificate.IPAddresses, ipHostNumber)
			}
			if len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 {
				t.Fatalf("unexpected server SANs: DNS=%v email=%v", certificate.DNSNames, certificate.EmailAddresses)
			}
			if !bytes.Equal(certificate.AuthorityKeyId, caCertificate.SubjectKeyId) {
				t.Fatal("server authority key identifier does not match CA subject key identifier")
			}
		})
	}
}

func TestAutoCASM2ServerCertificateWithoutIPSAN(t *testing.T) {
	pair, err := generateAutoCASM2ServerCertificate(mustGenerateAutoCASM2CA(t), autoCAServerCertificateConfig{
		DN:      "cn=ldap-no-ip,ou=Servers,dc=example,dc=com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate SM2 server certificate without IP: %v", err)
	}
	certificate := mustParseAutoCASM2Certificate(t, pair.CertificateDER)
	if len(certificate.IPAddresses) != 0 {
		t.Fatalf("server IP SAN = %v, want none", certificate.IPAddresses)
	}
	if hasAutoCACryptoExtension(certificate.Extensions, asn1.ObjectIdentifier{2, 5, 29, 17}) {
		t.Fatal("SM2 server certificate without IP contains a subjectAltName extension")
	}
}

func TestAutoCASM2RejectsInvalidCAAndKey(t *testing.T) {
	caPair := mustGenerateAutoCASM2CA(t)
	validUser := autoCAUserCertificateConfig{
		DN:      "uid=alice,ou=People,dc=example,dc=com",
		Mail:    "alice@example.com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	}

	badCertificate := caPair
	badCertificate.CertificateDER = []byte("not a certificate")
	if _, err := generateAutoCASM2UserCertificate(badCertificate, validUser); err == nil {
		t.Fatal("accepted an invalid issuer certificate")
	}
	badKey := caPair
	badKey.PrivateKeyDER = []byte("not a key")
	if _, err := generateAutoCASM2UserCertificate(badKey, validUser); err == nil {
		t.Fatal("accepted an invalid issuer private key")
	}
	otherCA := mustGenerateAutoCASM2CA(t)
	mismatched := caPair
	mismatched.PrivateKeyDER = otherCA.PrivateKeyDER
	if _, err := generateAutoCASM2UserCertificate(mismatched, validUser); err == nil {
		t.Fatal("accepted a mismatched issuer private key")
	}
	if _, err := generateAutoCASM2ServerCertificate(mismatched, autoCAServerCertificateConfig{
		DN:      "cn=ldap,ou=Servers,dc=example,dc=com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	}); err == nil {
		t.Fatal("server issuance accepted a mismatched issuer private key")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate wrong RSA key: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal wrong RSA key: %v", err)
	}
	wrongAlgorithm := caPair
	wrongAlgorithm.PrivateKeyDER = rsaDER
	if _, err := generateAutoCASM2UserCertificate(wrongAlgorithm, validUser); err == nil {
		t.Fatal("accepted a non-SM2 issuer private key")
	}

	nonCAKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate non-CA key: %v", err)
	}
	nonCATemplate := &smx509.Certificate{
		SerialNumber:          caPairSerial(t),
		Subject:               mustAutoCASM2Subject(t, "cn=Not CA,dc=example,dc=com"),
		NotBefore:             autoCASM2TestNow,
		NotAfter:              autoCASM2TestNow.Add(time.Hour),
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              smx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	nonCADER, err := smx509.CreateCertificate(rand.Reader, nonCATemplate, nonCATemplate, nonCAKey.Public(), nonCAKey)
	if err != nil {
		t.Fatalf("create non-CA certificate: %v", err)
	}
	nonCAKeyDER, err := smx509.MarshalPKCS8PrivateKey(nonCAKey)
	if err != nil {
		t.Fatalf("marshal non-CA key: %v", err)
	}
	if _, err := generateAutoCASM2UserCertificate(autoCACertificatePair{
		CertificateDER: nonCADER,
		PrivateKeyDER:  nonCAKeyDER,
	}, validUser); err == nil {
		t.Fatal("accepted a non-CA issuer certificate")
	}
}

func TestAutoCASM2RejectsInvalidConfiguration(t *testing.T) {
	validCA := autoCACertificateConfig{
		DN:      "cn=Directory SM2 CA,dc=example,dc=com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	}
	for name, mutate := range map[string]func(*autoCACertificateConfig){
		"wrong key size": func(config *autoCACertificateConfig) { config.KeyBits = 384 },
		"bad DN":         func(config *autoCACertificateConfig) { config.DN = "uid=bad," },
		"zero days":      func(config *autoCACertificateConfig) { config.Days = 0 },
		"nil random":     func(config *autoCACertificateConfig) { config.Random = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := validCA
			mutate(&config)
			if _, err := generateAutoCASM2SelfSignedCA(config); err == nil {
				t.Fatal("generateAutoCASM2SelfSignedCA() error = nil")
			}
		})
	}

	validUser := autoCAUserCertificateConfig{
		DN:      "uid=alice,dc=example,dc=com",
		Mail:    "alice@example.com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	}
	for name, mutate := range map[string]func(*autoCAUserCertificateConfig){
		"wrong key size": func(config *autoCAUserCertificateConfig) { config.KeyBits = 384 },
		"bad DN":         func(config *autoCAUserCertificateConfig) { config.DN = "uid=bad," },
		"bad mail":       func(config *autoCAUserCertificateConfig) { config.Mail = "bad mail" },
		"zero days":      func(config *autoCAUserCertificateConfig) { config.Days = 0 },
		"nil random":     func(config *autoCAUserCertificateConfig) { config.Random = nil },
	} {
		t.Run("user "+name, func(t *testing.T) {
			config := validUser
			mutate(&config)
			if _, err := generateAutoCASM2UserCertificate(mustGenerateAutoCASM2CA(t), config); err == nil {
				t.Fatal("generateAutoCASM2UserCertificate() error = nil")
			}
		})
	}

	validServer := autoCAServerCertificateConfig{
		DN:           "cn=ldap,ou=Servers,dc=example,dc=com",
		IPHostNumber: "192.0.2.10",
		KeyBits:      autoCASM2KeyBits,
		Days:         30,
		Now:          autoCASM2TestNow,
		Random:       rand.Reader,
	}
	for name, mutate := range map[string]func(*autoCAServerCertificateConfig){
		"wrong key size": func(config *autoCAServerCertificateConfig) { config.KeyBits = 384 },
		"bad DN":         func(config *autoCAServerCertificateConfig) { config.DN = "cn=ldap," },
		"hostname SAN":   func(config *autoCAServerCertificateConfig) { config.IPHostNumber = "ldap.example.com" },
		"CIDR SAN":       func(config *autoCAServerCertificateConfig) { config.IPHostNumber = "2001:db8::1/64" },
		"spaced SAN":     func(config *autoCAServerCertificateConfig) { config.IPHostNumber = "192.0.2.10 " },
		"zero days":      func(config *autoCAServerCertificateConfig) { config.Days = 0 },
		"nil random":     func(config *autoCAServerCertificateConfig) { config.Random = nil },
	} {
		t.Run("server "+name, func(t *testing.T) {
			config := validServer
			mutate(&config)
			if _, err := generateAutoCASM2ServerCertificate(mustGenerateAutoCASM2CA(t), config); err == nil {
				t.Fatal("generateAutoCASM2ServerCertificate() error = nil")
			}
		})
	}
}

func TestAutoCASM2ClonesInputsAndOutputs(t *testing.T) {
	caPair := mustGenerateAutoCASM2CA(t)
	certificateInput := bytes.Clone(caPair.CertificateDER)
	keyInput := bytes.Clone(caPair.PrivateKeyDER)
	pair, err := generateAutoCASM2UserCertificate(caPair, autoCAUserCertificateConfig{
		DN:      "uid=clone,dc=example,dc=com",
		Mail:    "clone@example.com",
		KeyBits: autoCASM2KeyBits,
		Days:    30,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate cloned SM2 pair: %v", err)
	}
	if !bytes.Equal(caPair.CertificateDER, certificateInput) || !bytes.Equal(caPair.PrivateKeyDER, keyInput) {
		t.Fatal("issuance mutated CA input buffers")
	}
	originalKeyByte := pair.PrivateKeyDER[0]
	pair.CertificateDER[0] ^= 0xff
	if pair.PrivateKeyDER[0] != originalKeyByte {
		t.Fatal("certificate and key outputs share mutable storage")
	}
	if !bytes.Equal(caPair.CertificateDER, certificateInput) || !bytes.Equal(caPair.PrivateKeyDER, keyInput) {
		t.Fatal("mutating output changed CA input buffers")
	}
}

func TestAutoCASM2ConcurrentIssuance(t *testing.T) {
	caPair := mustGenerateAutoCASM2CA(t)
	caCertificate := mustParseAutoCASM2Certificate(t, caPair.CertificateDER)
	const workers = 8
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, workers)
	certificates := make(chan []byte, workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			pair, err := generateAutoCASM2UserCertificate(caPair, autoCAUserCertificateConfig{
				DN:      fmt.Sprintf("uid=worker%d,dc=example,dc=com", worker),
				Mail:    fmt.Sprintf("worker%d@example.com", worker),
				KeyBits: autoCASM2KeyBits,
				Days:    30,
				Now:     autoCASM2TestNow,
				Random:  rand.Reader,
			})
			if err != nil {
				errorsByWorker <- err
				return
			}
			certificate, err := smx509.ParseCertificate(pair.CertificateDER)
			if err == nil {
				err = certificate.CheckSignatureFrom(caCertificate)
			}
			if err != nil {
				errorsByWorker <- err
				return
			}
			certificates <- pair.CertificateDER
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	close(certificates)
	for err := range errorsByWorker {
		t.Errorf("concurrent SM2 issuance: %v", err)
	}
	seen := make(map[string]struct{}, workers)
	for certificate := range certificates {
		seen[string(certificate)] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("unique concurrent certificates = %d, want %d", len(seen), workers)
	}
}

func TestAutoCASM2ConcurrentServerIssuance(t *testing.T) {
	caPair := mustGenerateAutoCASM2CA(t)
	caCertificate := mustParseAutoCASM2Certificate(t, caPair.CertificateDER)
	const workers = 8
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, workers)
	certificates := make(chan []byte, workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			pair, err := generateAutoCASM2ServerCertificate(caPair, autoCAServerCertificateConfig{
				DN:           fmt.Sprintf("cn=server%d,ou=Servers,dc=example,dc=com", worker),
				IPHostNumber: fmt.Sprintf("192.0.2.%d", worker+1),
				KeyBits:      autoCASM2KeyBits,
				Days:         30,
				Now:          autoCASM2TestNow,
				Random:       rand.Reader,
			})
			if err != nil {
				errorsByWorker <- err
				return
			}
			certificate, err := smx509.ParseCertificate(pair.CertificateDER)
			if err != nil {
				errorsByWorker <- err
				return
			}
			privateKeyValue, err := smx509.ParsePKCS8PrivateKey(pair.PrivateKeyDER)
			if err != nil {
				errorsByWorker <- err
				return
			}
			privateKey, ok := privateKeyValue.(*sm2.PrivateKey)
			if !ok {
				errorsByWorker <- fmt.Errorf("concurrent SM2 server key type = %T", privateKeyValue)
				return
			}
			if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
				errorsByWorker <- err
				return
			}
			match, err := autoCASM2PublicKeysEqual(certificate.PublicKey, privateKey.Public())
			if err != nil || !match {
				if err == nil {
					err = fmt.Errorf("concurrent SM2 server certificate and key differ")
				}
				errorsByWorker <- err
				return
			}
			certificates <- pair.CertificateDER
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	close(certificates)
	for err := range errorsByWorker {
		t.Errorf("concurrent SM2 server issuance: %v", err)
	}
	seen := make(map[string]struct{}, workers)
	for certificate := range certificates {
		seen[string(certificate)] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("unique concurrent SM2 server certificates = %d, want %d", len(seen), workers)
	}
}

func mustGenerateAutoCASM2CA(t *testing.T) autoCACertificatePair {
	t.Helper()
	pair, err := generateAutoCASM2SelfSignedCA(autoCACertificateConfig{
		DN:      "cn=Directory SM2 CA,ou=Security,dc=example,dc=com",
		KeyBits: autoCASM2KeyBits,
		Days:    3652,
		Now:     autoCASM2TestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate test SM2 CA: %v", err)
	}
	return pair
}

func mustParseAutoCASM2Certificate(t *testing.T, der []byte) *smx509.Certificate {
	t.Helper()
	certificate, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse SM2 certificate: %v", err)
	}
	return certificate
}

func mustParseAutoCASM2PrivateKey(t *testing.T, der []byte) *sm2.PrivateKey {
	t.Helper()
	key, err := smx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("parse SM2 PKCS#8 private key: %v", err)
	}
	privateKey, ok := key.(*sm2.PrivateKey)
	if !ok {
		t.Fatalf("PKCS#8 key type = %T, want *sm2.PrivateKey", key)
	}
	return privateKey
}

func assertAutoCASM2PublicKeyMatch(t *testing.T, left, right any) {
	t.Helper()
	equal, err := autoCASM2PublicKeysEqual(left, right)
	if err != nil {
		t.Fatalf("compare SM2 public keys: %v", err)
	}
	if !equal {
		t.Fatal("certificate public key does not match private key")
	}
}

func equalAutoCASM2ExtKeyUsages(left, right []smx509.ExtKeyUsage) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func mustAutoCASM2Subject(t *testing.T, dn string) pkix.Name {
	t.Helper()
	subject, _, err := autoCAX509Subject(dn)
	if err != nil {
		t.Fatalf("parse SM2 test subject: %v", err)
	}
	return subject
}

func caPairSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := autoCARandomSerial(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 test serial: %v", err)
	}
	return serial
}
