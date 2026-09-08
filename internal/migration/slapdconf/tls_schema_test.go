package slapdconf

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSFilesAndPolicy(t *testing.T) {
	base := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(base, "server certificate.pem")
	keyPath := filepath.Join(base, "server key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("TLSCertificateFile %q\nTLSCertificateKeyFile %q\nTLSCACertificateFile %q\n", certificatePath, keyPath, certificatePath)
	path := configFile(t, config+"TLSProtocolMin 3.3\nTLSVerifyClient demand\n")
	document, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := values(t, document, "cn=config", "olcTLSCertificateFile")[0]; got != certificatePath {
		t.Fatalf("certificate path = %q", got)
	}
	for _, directive := range []string{"TLSProtocolMin 99.9", "TLSVerifyClient invalid", "TLSCipherSuite unsupported-cipher", "TLSECName bogus-curve"} {
		path := configFile(t, config+directive+"\n")
		if _, err := ConvertFile(path, ParseOptions{}); err == nil || !strings.Contains(err.Error(), path+":4:") {
			t.Fatalf("%s error = %v", directive, err)
		}
	}
}

func TestIncludedSchemaAndFailureLocation(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "slapd.conf")
	child := filepath.Join(base, "child.schema")
	text := "objectidentifier testOID 1.3.6.1.4.1.55555\ninclude child.schema\nobjectclass ( testOID:2 NAME 'testClass' SUP top AUXILIARY MAY testAttr )\ndatabase mdb\nsuffix dc=example\ndirectory /unused\nindex testAttr eq\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("attributetype ( testOID:1 NAME 'testAttr'\n  DESC 'schema with spaces' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := ConvertFile(path, ParseOptions{IncludeBaseDir: base})
	if err != nil {
		t.Fatal(err)
	}
	var schemaDNs []string
	for _, entry := range document.Entries {
		if strings.HasPrefix(entry.DN, "cn={") {
			schemaDNs = append(schemaDNs, entry.DN)
		}
	}
	if len(schemaDNs) != 3 || !strings.Contains(schemaDNs[1], "child") || !strings.Contains(schemaDNs[2], "slapd") {
		t.Fatalf("schema ordering = %v", schemaDNs)
	}
	if err := os.WriteFile(child, []byte("# source location\nunknown-schema-behavior something\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ConvertFile(path, ParseOptions{IncludeBaseDir: base}); err == nil || !strings.Contains(err.Error(), child+":2:") {
		t.Fatalf("source error = %v", err)
	}
}
