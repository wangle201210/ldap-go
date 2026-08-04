package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

var autoCACryptoTestNow = time.Date(2026, 8, 3, 9, 10, 11, 987654321, time.FixedZone("CST", 8*60*60))

func TestAutoCACryptoSelfSignedCA(t *testing.T) {
	pair := mustGenerateAutoCACryptoCA(t)
	certificate := mustParseAutoCACryptoCertificate(t, pair.CertificateDER)
	privateKey := mustParseAutoCACryptoRSAKey(t, pair.PrivateKeyDER)

	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		t.Fatalf("CA constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
	}
	wantUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	if certificate.KeyUsage != wantUsage {
		t.Fatalf("CA key usage = %v, want %v", certificate.KeyUsage, wantUsage)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatalf("verify CA self-signature: %v", err)
	}
	assertAutoCACryptoPublicKeyMatch(t, certificate.PublicKey, privateKey.Public())
	assertAutoCACryptoValidity(t, certificate, autoCACryptoTestNow, 3652)
	assertAutoCACryptoSubject(t, certificate, map[string][]string{
		"2.5.4.3":                         {"Directory CA"},
		"0.9.2342.19200300.100.1.25":      {"com", "example"},
		"0.9.2342.19200300.100.1.1":       nil,
		"0.9.2342.19200300.100.1.25.9999": nil,
	})
	if certificate.SerialNumber.Sign() <= 0 || certificate.SerialNumber.BitLen() != 64 {
		t.Fatalf("CA serial = %s (%d bits), want positive 64-bit", certificate.SerialNumber, certificate.SerialNumber.BitLen())
	}
	if len(certificate.SubjectKeyId) == 0 ||
		!bytes.Equal(certificate.SubjectKeyId, certificate.AuthorityKeyId) {
		t.Fatal("CA subject and authority key identifiers are missing or differ")
	}
	wantKeyID, err := autoCASubjectKeyID(certificate.PublicKey)
	if err != nil {
		t.Fatalf("derive CA subject key identifier: %v", err)
	}
	if !bytes.Equal(certificate.SubjectKeyId, wantKeyID) {
		t.Fatal("CA subject key identifier does not use the OpenLDAP hash profile")
	}
}

func TestAutoCACryptoUserCertificate(t *testing.T) {
	caPair := mustGenerateAutoCACryptoCA(t)
	caCertificate := mustParseAutoCACryptoCertificate(t, caPair.CertificateDER)
	pair, err := generateAutoCAUserCertificate(caPair, autoCAUserCertificateConfig{
		DN:      "uid=alice+cn=Alice Smith,ou=People,dc=example,dc=com",
		Mail:    "alice@example.com",
		KeyBits: 1024,
		Days:    30,
		Now:     autoCACryptoTestNow.Add(5 * time.Minute),
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate user certificate: %v", err)
	}
	certificate := mustParseAutoCACryptoCertificate(t, pair.CertificateDER)
	privateKey := mustParseAutoCACryptoRSAKey(t, pair.PrivateKeyDER)

	if certificate.IsCA || !certificate.BasicConstraintsValid {
		t.Fatalf("user constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
	}
	if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("verify user certificate signature: %v", err)
	}
	assertAutoCACryptoPublicKeyMatch(t, certificate.PublicKey, privateKey.Public())
	assertAutoCACryptoValidity(t, certificate, autoCACryptoTestNow.Add(5*time.Minute), 30)
	assertAutoCACryptoSubject(t, certificate, map[string][]string{
		"2.5.4.3":                    {"Alice Smith"},
		"2.5.4.11":                   {"People"},
		"0.9.2342.19200300.100.1.1":  {"alice"},
		"0.9.2342.19200300.100.1.25": {"com", "example"},
	})
	if len(certificate.EmailAddresses) != 1 || certificate.EmailAddresses[0] != "alice@example.com" {
		t.Fatalf("user RFC822 SAN = %v, want alice@example.com", certificate.EmailAddresses)
	}
	wantExtKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageCodeSigning,
	}
	if !equalAutoCACryptoExtKeyUsages(certificate.ExtKeyUsage, wantExtKeyUsage) {
		t.Fatalf("user extended key usage = %v, want %v", certificate.ExtKeyUsage, wantExtKeyUsage)
	}
	wantUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment
	if certificate.KeyUsage != wantUsage {
		t.Fatalf("user key usage = %v, want %v", certificate.KeyUsage, wantUsage)
	}
	if !bytes.Equal(certificate.AuthorityKeyId, caCertificate.SubjectKeyId) {
		t.Fatal("user authority key identifier does not match CA subject key identifier")
	}
	if certificate.SerialNumber.Sign() <= 0 || certificate.SerialNumber.BitLen() != 64 {
		t.Fatalf("user serial = %s (%d bits), want positive 64-bit", certificate.SerialNumber, certificate.SerialNumber.BitLen())
	}
}

func TestAutoCACryptoUserCertificateWithoutMail(t *testing.T) {
	pair, err := generateAutoCAUserCertificate(mustGenerateAutoCACryptoCA(t), autoCAUserCertificateConfig{
		DN:      "uid=nomail,ou=people,dc=example,dc=com",
		KeyBits: 1024,
		Days:    30,
		Now:     autoCACryptoTestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate user certificate without mail: %v", err)
	}
	certificate := mustParseAutoCACryptoCertificate(t, pair.CertificateDER)
	if len(certificate.EmailAddresses) != 0 {
		t.Fatalf("user RFC822 SAN = %v, want none", certificate.EmailAddresses)
	}
	if hasAutoCACryptoExtension(certificate.Extensions, asn1.ObjectIdentifier{2, 5, 29, 17}) {
		t.Fatal("user certificate without mail contains a subjectAltName extension")
	}
}

func TestAutoCACryptoServerCertificate(t *testing.T) {
	caPair := mustGenerateAutoCACryptoCA(t)
	caCertificate := mustParseAutoCACryptoCertificate(t, caPair.CertificateDER)
	for name, ipHostNumber := range map[string]string{
		"IPv4": "192.0.2.25",
		"IPv6": "2001:db8::25",
	} {
		t.Run(name, func(t *testing.T) {
			pair, err := generateAutoCAServerCertificate(caPair, autoCAServerCertificateConfig{
				DN:           "cn=ldap25,ou=servers,dc=example,dc=com",
				IPHostNumber: ipHostNumber,
				KeyBits:      1024,
				Days:         825,
				Now:          autoCACryptoTestNow.Add(10 * time.Minute),
				Random:       rand.Reader,
			})
			if err != nil {
				t.Fatalf("generate server certificate: %v", err)
			}
			certificate := mustParseAutoCACryptoCertificate(t, pair.CertificateDER)
			privateKey := mustParseAutoCACryptoRSAKey(t, pair.PrivateKeyDER)
			if certificate.IsCA || !certificate.BasicConstraintsValid {
				t.Fatalf("server constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
			}
			if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
				t.Fatalf("verify server certificate signature: %v", err)
			}
			assertAutoCACryptoPublicKeyMatch(t, certificate.PublicKey, privateKey.Public())
			assertAutoCACryptoValidity(t, certificate, autoCACryptoTestNow.Add(10*time.Minute), 825)
			if certificate.Subject.CommonName != "ldap25" {
				t.Fatalf("server subject = %v", certificate.Subject)
			}
			wantUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
			if certificate.KeyUsage != wantUsage {
				t.Fatalf("server key usage = %v, want %v", certificate.KeyUsage, wantUsage)
			}
			wantExtKeyUsage := []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}
			if !equalAutoCACryptoExtKeyUsages(certificate.ExtKeyUsage, wantExtKeyUsage) {
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

func TestAutoCACryptoServerCertificateWithoutIPSAN(t *testing.T) {
	pair, err := generateAutoCAServerCertificate(mustGenerateAutoCACryptoCA(t), autoCAServerCertificateConfig{
		DN:      "cn=ldap-no-ip,ou=servers,dc=example,dc=com",
		KeyBits: 1024,
		Days:    30,
		Now:     autoCACryptoTestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate server certificate without IP: %v", err)
	}
	certificate := mustParseAutoCACryptoCertificate(t, pair.CertificateDER)
	if len(certificate.IPAddresses) != 0 {
		t.Fatalf("server IP SAN = %v, want none", certificate.IPAddresses)
	}
	if hasAutoCACryptoExtension(certificate.Extensions, asn1.ObjectIdentifier{2, 5, 29, 17}) {
		t.Fatal("server certificate without IP contains a subjectAltName extension")
	}
}

func TestAutoCACryptoRejectsInvalidInputs(t *testing.T) {
	validCA := autoCACertificateConfig{
		DN:      "dc=example,dc=com",
		KeyBits: 1024,
		Days:    30,
		Now:     autoCACryptoTestNow,
		Random:  rand.Reader,
	}
	for name, mutate := range map[string]func(*autoCACertificateConfig){
		"empty DN":       func(config *autoCACertificateConfig) { config.DN = "" },
		"malformed DN":   func(config *autoCACertificateConfig) { config.DN = "uid=bad," },
		"unknown DN OID": func(config *autoCACertificateConfig) { config.DN = "unknown=value,dc=example" },
		"empty DN value": func(config *autoCACertificateConfig) { config.DN = "uid=,dc=example" },
		"small key":      func(config *autoCACertificateConfig) { config.KeyBits = autoCAMinRSAKeyBits - 1 },
		"large key":      func(config *autoCACertificateConfig) { config.KeyBits = autoCAMaxRSAKeyBits + 1 },
		"zero days":      func(config *autoCACertificateConfig) { config.Days = 0 },
		"negative days":  func(config *autoCACertificateConfig) { config.Days = -1 },
		"zero time":      func(config *autoCACertificateConfig) { config.Now = time.Time{} },
		"nil random":     func(config *autoCACertificateConfig) { config.Random = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := validCA
			mutate(&config)
			if _, err := generateAutoCASelfSignedCA(config); err == nil {
				t.Fatal("generateAutoCASelfSignedCA() error = nil")
			}
		})
	}

	caPair := mustGenerateAutoCACryptoCA(t)
	validUser := autoCAUserCertificateConfig{
		DN:      "uid=alice,ou=people,dc=example,dc=com",
		Mail:    "alice@example.com",
		KeyBits: 1024,
		Days:    30,
		Now:     autoCACryptoTestNow,
		Random:  rand.Reader,
	}
	for name, mutate := range map[string]func(*autoCAUserCertificateConfig){
		"malformed DN": func(config *autoCAUserCertificateConfig) { config.DN = "uid=alice," },
		"bad mail":     func(config *autoCAUserCertificateConfig) { config.Mail = "Alice <alice@example.com>" },
		"small key":    func(config *autoCAUserCertificateConfig) { config.KeyBits = 512 },
		"zero days":    func(config *autoCAUserCertificateConfig) { config.Days = 0 },
		"nil random":   func(config *autoCAUserCertificateConfig) { config.Random = nil },
	} {
		t.Run("user "+name, func(t *testing.T) {
			config := validUser
			mutate(&config)
			if _, err := generateAutoCAUserCertificate(caPair, config); err == nil {
				t.Fatal("generateAutoCAUserCertificate() error = nil")
			}
		})
	}

	badCA := caPair
	badCA.PrivateKeyDER = []byte("not a key")
	if _, err := generateAutoCAUserCertificate(badCA, validUser); err == nil {
		t.Fatal("generateAutoCAUserCertificate() accepted invalid issuer key")
	}
	otherCA := mustGenerateAutoCACryptoCA(t)
	badCA = caPair
	badCA.PrivateKeyDER = otherCA.PrivateKeyDER
	if _, err := generateAutoCAUserCertificate(badCA, validUser); err == nil {
		t.Fatal("generateAutoCAUserCertificate() accepted mismatched issuer key")
	}
	if _, err := generateAutoCASelfSignedCAWithProvider(validCA, nil); err == nil {
		t.Fatal("generateAutoCASelfSignedCAWithProvider() accepted nil provider")
	}

	validServer := autoCAServerCertificateConfig{
		DN:           "cn=ldap,ou=servers,dc=example,dc=com",
		IPHostNumber: "192.0.2.10",
		KeyBits:      1024,
		Days:         30,
		Now:          autoCACryptoTestNow,
		Random:       rand.Reader,
	}
	for name, mutate := range map[string]func(*autoCAServerCertificateConfig){
		"malformed DN": func(config *autoCAServerCertificateConfig) { config.DN = "cn=ldap," },
		"hostname SAN": func(config *autoCAServerCertificateConfig) { config.IPHostNumber = "ldap.example.com" },
		"CIDR SAN":     func(config *autoCAServerCertificateConfig) { config.IPHostNumber = "192.0.2.10/24" },
		"spaced SAN":   func(config *autoCAServerCertificateConfig) { config.IPHostNumber = " 192.0.2.10" },
		"small key":    func(config *autoCAServerCertificateConfig) { config.KeyBits = 512 },
		"zero days":    func(config *autoCAServerCertificateConfig) { config.Days = 0 },
		"nil random":   func(config *autoCAServerCertificateConfig) { config.Random = nil },
	} {
		t.Run("server "+name, func(t *testing.T) {
			config := validServer
			mutate(&config)
			if _, err := generateAutoCAServerCertificate(caPair, config); err == nil {
				t.Fatal("generateAutoCAServerCertificate() error = nil")
			}
		})
	}
	if _, err := generateAutoCAServerCertificateWithProvider(caPair, validServer, nil); err == nil {
		t.Fatal("generateAutoCAServerCertificateWithProvider() accepted nil provider")
	}
	badServerCA := caPair
	badServerCA.PrivateKeyDER = otherCA.PrivateKeyDER
	if _, err := generateAutoCAServerCertificate(badServerCA, validServer); err == nil {
		t.Fatal("generateAutoCAServerCertificate() accepted mismatched issuer key")
	}
}

func TestAutoCACryptoClonesInputsAndOutputs(t *testing.T) {
	caPair := mustGenerateAutoCACryptoCA(t)
	certificateInput := bytes.Clone(caPair.CertificateDER)
	keyInput := bytes.Clone(caPair.PrivateKeyDER)
	userPair, err := generateAutoCAUserCertificate(caPair, autoCAUserCertificateConfig{
		DN:      "uid=clone,ou=people,dc=example,dc=com",
		Mail:    "clone@example.com",
		KeyBits: 1024,
		Days:    30,
		Now:     autoCACryptoTestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate cloned user pair: %v", err)
	}
	if !bytes.Equal(caPair.CertificateDER, certificateInput) || !bytes.Equal(caPair.PrivateKeyDER, keyInput) {
		t.Fatal("user issuance mutated CA input buffers")
	}
	if len(userPair.CertificateDER) == 0 || len(userPair.PrivateKeyDER) == 0 {
		t.Fatal("user issuance returned an empty DER buffer")
	}
	originalKeyByte := userPair.PrivateKeyDER[0]
	userPair.CertificateDER[0] ^= 0xff
	if userPair.PrivateKeyDER[0] != originalKeyByte {
		t.Fatal("certificate and private-key outputs share mutable storage")
	}
	if !bytes.Equal(caPair.CertificateDER, certificateInput) || !bytes.Equal(caPair.PrivateKeyDER, keyInput) {
		t.Fatal("mutating user output changed CA input buffers")
	}
}

func TestAutoCACryptoConcurrentIssuance(t *testing.T) {
	caPair := mustGenerateAutoCACryptoCA(t)
	caCertificate := mustParseAutoCACryptoCertificate(t, caPair.CertificateDER)
	const workers = 4
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, workers)
	certificates := make(chan []byte, workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			pair, err := generateAutoCAUserCertificate(caPair, autoCAUserCertificateConfig{
				DN:      "uid=worker" + string(rune('0'+worker)) + ",ou=people,dc=example,dc=com",
				Mail:    "worker" + string(rune('0'+worker)) + "@example.com",
				KeyBits: 1024,
				Days:    30,
				Now:     autoCACryptoTestNow,
				Random:  rand.Reader,
			})
			if err != nil {
				errorsByWorker <- err
				return
			}
			certificate, err := x509.ParseCertificate(pair.CertificateDER)
			if err != nil {
				errorsByWorker <- err
				return
			}
			if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
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
		t.Errorf("concurrent issuance: %v", err)
	}
	seen := make(map[string]struct{}, workers)
	for certificate := range certificates {
		seen[string(certificate)] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("unique concurrent certificates = %d, want %d", len(seen), workers)
	}
}

func TestAutoCACryptoConcurrentServerIssuance(t *testing.T) {
	caPair := mustGenerateAutoCACryptoCA(t)
	caCertificate := mustParseAutoCACryptoCertificate(t, caPair.CertificateDER)
	const workers = 4
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, workers)
	certificates := make(chan []byte, workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			pair, err := generateAutoCAServerCertificate(caPair, autoCAServerCertificateConfig{
				DN:           "cn=server" + string(rune('0'+worker)) + ",ou=servers,dc=example,dc=com",
				IPHostNumber: "192.0.2." + string(rune('1'+worker)),
				KeyBits:      1024,
				Days:         30,
				Now:          autoCACryptoTestNow,
				Random:       rand.Reader,
			})
			if err != nil {
				errorsByWorker <- err
				return
			}
			certificate, err := x509.ParseCertificate(pair.CertificateDER)
			if err != nil {
				errorsByWorker <- err
				return
			}
			privateKeyValue, err := x509.ParsePKCS8PrivateKey(pair.PrivateKeyDER)
			if err != nil {
				errorsByWorker <- err
				return
			}
			privateKey, ok := privateKeyValue.(*rsa.PrivateKey)
			if !ok {
				errorsByWorker <- errors.New("concurrent server key is not RSA")
				return
			}
			if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
				errorsByWorker <- err
				return
			}
			match, err := autoCAPublicKeysEqual(certificate.PublicKey, privateKey.Public())
			if err != nil || !match {
				if err == nil {
					err = errors.New("concurrent server certificate and key differ")
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
		t.Errorf("concurrent server issuance: %v", err)
	}
	seen := make(map[string]struct{}, workers)
	for certificate := range certificates {
		seen[string(certificate)] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("unique concurrent server certificates = %d, want %d", len(seen), workers)
	}
}

func TestAutoCACryptoRandomFailure(t *testing.T) {
	_, err := generateAutoCASelfSignedCA(autoCACertificateConfig{
		DN:      "dc=example,dc=com",
		KeyBits: 1024,
		Days:    30,
		Now:     autoCACryptoTestNow,
		Random:  failingAutoCACryptoReader{},
	})
	if err == nil {
		t.Fatal("generateAutoCASelfSignedCA() accepted a failed random source")
	}
}

type failingAutoCACryptoReader struct{}

func (failingAutoCACryptoReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func mustGenerateAutoCACryptoCA(t *testing.T) autoCACertificatePair {
	t.Helper()
	pair, err := generateAutoCASelfSignedCA(autoCACertificateConfig{
		DN:      "cn=Directory CA,dc=example,dc=com",
		KeyBits: 1024,
		Days:    3652,
		Now:     autoCACryptoTestNow,
		Random:  rand.Reader,
	})
	if err != nil {
		t.Fatalf("generate test CA: %v", err)
	}
	return pair
}

func mustParseAutoCACryptoCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

func mustParseAutoCACryptoRSAKey(t *testing.T, der []byte) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("parse PKCS#8 private key: %v", err)
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("PKCS#8 private key type = %T, want *rsa.PrivateKey", privateKey)
	}
	return rsaKey
}

func assertAutoCACryptoPublicKeyMatch(t *testing.T, left, right crypto.PublicKey) {
	t.Helper()
	equal, err := autoCAPublicKeysEqual(left, right)
	if err != nil {
		t.Fatalf("compare public keys: %v", err)
	}
	if !equal {
		t.Fatal("certificate and private-key public keys differ")
	}
}

func assertAutoCACryptoValidity(
	t *testing.T,
	certificate *x509.Certificate,
	now time.Time,
	days int,
) {
	t.Helper()
	wantNotBefore := now.UTC().Truncate(time.Second)
	wantNotAfter := wantNotBefore.AddDate(0, 0, days)
	if !certificate.NotBefore.Equal(wantNotBefore) || !certificate.NotAfter.Equal(wantNotAfter) {
		t.Fatalf(
			"certificate validity = %s..%s, want %s..%s",
			certificate.NotBefore,
			certificate.NotAfter,
			wantNotBefore,
			wantNotAfter,
		)
	}
}

func assertAutoCACryptoSubject(
	t *testing.T,
	certificate *x509.Certificate,
	want map[string][]string,
) {
	t.Helper()
	got := make(map[string][]string)
	for _, name := range certificate.Subject.Names {
		value, ok := name.Value.(string)
		if !ok {
			t.Fatalf("subject value for %s has type %T", name.Type, name.Value)
		}
		got[name.Type.String()] = append(got[name.Type.String()], value)
	}
	for oid, values := range want {
		if !equalAutoCACryptoStrings(got[oid], values) {
			t.Fatalf("subject values for %s = %v, want %v", oid, got[oid], values)
		}
	}
}

func equalAutoCACryptoStrings(left, right []string) bool {
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

func equalAutoCACryptoExtKeyUsages(left, right []x509.ExtKeyUsage) bool {
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

func hasAutoCACryptoExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, extension := range extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func TestAutoCACryptoNumericOID(t *testing.T) {
	oid, err := autoCADNAttributeOID("1.2.840.113549.1.9.1")
	if err != nil {
		t.Fatalf("parse numeric OID: %v", err)
	}
	if !oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}) {
		t.Fatalf("numeric OID = %s", oid)
	}
	for _, raw := range []string{"", "1", "3.1", "1.40", "1..2", "1.two.3"} {
		if _, err := parseAutoCANumericOID(raw); err == nil {
			t.Errorf("parseAutoCANumericOID(%q) error = nil", raw)
		}
	}
}

func TestAutoCACryptoProviderTypeBoundary(t *testing.T) {
	provider := autoCARSAKeyProvider{}
	if _, err := provider.marshalPKCS8(fakeAutoCACryptoSigner{}); err == nil {
		t.Fatal("RSA provider accepted a non-RSA signer")
	}
}

type fakeAutoCACryptoSigner struct{}

func (fakeAutoCACryptoSigner) Public() crypto.PublicKey { return nil }

func (fakeAutoCACryptoSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not implemented")
}
