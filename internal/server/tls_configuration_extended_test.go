package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/pkcs8"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestGlobalTLSCACertificatePathLoadsDirectoryAndDeduplicates(t *testing.T) {
	firstAuthority := newGlobalTLSTestAuthority(t)
	secondAuthority := newGlobalTLSTestAuthority(t)
	rogueAuthority := firstAuthority.issueAuthority(t, "rogue hash-dir CA")
	serverCertificate := firstAuthority.issue(t, "ca-directory-server", true)
	firstDirectory := t.TempDir()
	writeGlobalTLSCAHashCertificate(t, firstDirectory, firstAuthority.certificateDER, 0)
	writeGlobalTLSCACertificate(t, firstDirectory, "rogue.pem", rogueAuthority.certificateDER)
	writeGlobalTLSCACertificate(
		t,
		firstDirectory,
		globalTLSWrongCAHashName(t, rogueAuthority.certificateDER, 0),
		rogueAuthority.certificateDER,
	)
	secondPath := writeGlobalTLSCACertificate(
		t,
		firstDirectory,
		"registered.pem",
		secondAuthority.certificateDER,
	)
	if err := os.WriteFile(filepath.Join(firstDirectory, "README"), []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("write ignored CA directory file: %v", err)
	}
	if runtime.GOOS != "windows" {
		name := globalTLSCAHashName(t, secondAuthority.certificateDER, 1)
		if err := os.Symlink(filepath.Base(secondPath), filepath.Join(firstDirectory, name)); err != nil {
			t.Fatalf("create in-directory CA symlink: %v", err)
		}
	} else {
		writeGlobalTLSCAHashCertificate(t, firstDirectory, secondAuthority.certificateDER, 1)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificate;binary":    {serverCertificate.certificateDER},
		"olcTLSCertificateKey;binary": {serverCertificate.privateKeyDER},
		"olcTLSCACertificate;binary":  {firstAuthority.certificateDER},
		"olcTLSCACertificatePath":     {[]byte(firstDirectory)},
		"olcTLSVerifyClient":          {[]byte("demand")},
	})

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer instance.closeSQLBackends()
	transport, ok := instance.runtime.Load().secureTransport.(standardTLSTransport)
	if !ok {
		t.Fatalf("runtime TLS transport = %T", instance.runtime.Load().secureTransport)
	}
	if got := len(transport.config.ClientCAs.Subjects()); got != 2 {
		t.Fatalf("hash-dir CA subjects = %d, want 2; rogue.pem must be ignored", got)
	}
}

func TestGlobalTLSCAHashMatchesOpenSSLAndRejectsWrongPrefix(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t).issueAuthority(t, "OpenSSL hash boundary CA")
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	directory := t.TempDir()
	certificatePath := writeGlobalTLSCACertificate(
		t,
		directory,
		"authority.pem",
		authority.certificateDER,
	)
	command := exec.Command(openssl, "x509", "-subject_hash", "-noout", "-in", certificatePath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -subject_hash: %v: %s", err, output)
	}
	want := strings.TrimSpace(string(output))
	got, err := globalTLSOpenSSLSubjectHash(authority.certificate)
	if err != nil || got != want {
		t.Fatalf("OpenSSL subject hash = %q, Go = %q, %v", want, got, err)
	}

	writeGlobalTLSCACertificate(
		t,
		directory,
		globalTLSWrongCAHashName(t, authority.certificateDER, 0),
		authority.certificateDER,
	)
	certificates, err := loadGlobalTLSCAPath(directory)
	if err != nil {
		t.Fatalf("loadGlobalTLSCAPath(wrong hash): %v", err)
	}
	if len(certificates) != 0 {
		t.Fatalf("wrong hash-dir prefix loaded %d trust anchors", len(certificates))
	}

	writeGlobalTLSCAHashCertificate(t, directory, authority.certificateDER, 0)
	certificates, err = loadGlobalTLSCAPath(directory)
	if err != nil || len(certificates) != 1 {
		t.Fatalf("correct hash-dir prefix loaded %d anchors, %v", len(certificates), err)
	}
}

func TestGlobalTLSCACertificatePathSupportsSemicolonSeparatedDirectories(t *testing.T) {
	firstAuthority := newGlobalTLSTestAuthority(t)
	secondAuthority := newGlobalTLSTestAuthority(t)
	firstDirectory := t.TempDir()
	secondDirectory := t.TempDir()
	writeGlobalTLSCAHashCertificate(t, firstDirectory, firstAuthority.certificateDER, 0)
	writeGlobalTLSCAHashCertificate(t, secondDirectory, secondAuthority.certificateDER, 3)

	certificates, err := loadGlobalTLSCAPath(firstDirectory + ";" + secondDirectory)
	if err != nil {
		t.Fatalf("loadGlobalTLSCAPath(multiple): %v", err)
	}
	if got := len(certificates); got != 2 {
		t.Fatalf("multi-directory certificates = %d, want 2", got)
	}
}

func TestGlobalTLSCACertificatePathRejectsUnsafeAndInvalidPaths(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	outside := t.TempDir()
	outsideCertificate := writeGlobalTLSCACertificate(
		t,
		outside,
		"outside.pem",
		authority.certificateDER,
	)
	for _, test := range []struct {
		name     string
		pathList func(*testing.T) string
		want     string
	}{
		{
			name: "regular file instead of directory",
			pathList: func(*testing.T) string {
				return outsideCertificate
			},
			want: "directory",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildGlobalTLSCAPool(nil, test.pathList(t))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), test.want) {
				t.Fatalf("buildGlobalTLSCAPool() error = %v, want %q", err, test.want)
			}
		})
	}

	if runtime.GOOS == "windows" {
		t.Skip("CA directory symlink confinement is Unix-only in this test")
	}
	directory := t.TempDir()
	if err := os.Symlink(outsideCertificate, filepath.Join(directory, "01234567.0")); err != nil {
		t.Fatalf("create escaping CA symlink: %v", err)
	}
	_, err := buildGlobalTLSCAPool(nil, directory)
	if err == nil || !strings.Contains(err.Error(), "01234567.0") {
		t.Fatalf("escaping CA symlink error = %v, want confinement diagnostic", err)
	}
}

func TestGlobalTLSCACertificatePathResourceLimits(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: authority.certificateDER,
	})
	limits := func() globalTLSCAPathLimits {
		return globalTLSCAPathLimits{
			maximumDirectories:  4,
			maximumFiles:        4,
			maximumBytes:        int64(len(certificatePEM) * 4),
			maximumCertificates: 4,
		}
	}

	t.Run("directories", func(t *testing.T) {
		first := t.TempDir()
		second := t.TempDir()
		writeGlobalTLSCAHashCertificate(t, first, authority.certificateDER, 0)
		writeGlobalTLSCAHashCertificate(t, second, authority.certificateDER, 0)
		configured := first + ";" + second
		exact := limits()
		exact.maximumDirectories = 2
		if _, err := loadGlobalTLSCAPathWithLimits(configured, exact); err != nil {
			t.Fatalf("exact directory limit: %v", err)
		}
		below := exact
		below.maximumDirectories = 1
		if _, err := loadGlobalTLSCAPathWithLimits(configured, below); err == nil ||
			!strings.Contains(err.Error(), "directory limit") {
			t.Fatalf("directory limit error = %v", err)
		}
	})

	t.Run("files", func(t *testing.T) {
		directory := t.TempDir()
		writeGlobalTLSCAHashCertificate(t, directory, authority.certificateDER, 0)
		writeGlobalTLSCACertificate(t, directory, "rogue.pem", authority.certificateDER)
		exact := limits()
		exact.maximumFiles = 2
		if _, err := loadGlobalTLSCAPathWithLimits(directory, exact); err != nil {
			t.Fatalf("exact file limit: %v", err)
		}
		below := exact
		below.maximumFiles = 1
		if _, err := loadGlobalTLSCAPathWithLimits(directory, below); err == nil ||
			!strings.Contains(err.Error(), "file limit") {
			t.Fatalf("file limit error = %v", err)
		}
	})

	t.Run("total bytes", func(t *testing.T) {
		directory := t.TempDir()
		writeGlobalTLSCAHashCertificate(t, directory, authority.certificateDER, 0)
		exact := limits()
		exact.maximumBytes = int64(len(certificatePEM))
		if _, err := loadGlobalTLSCAPathWithLimits(directory, exact); err != nil {
			t.Fatalf("exact byte limit: %v", err)
		}
		below := exact
		below.maximumBytes--
		if _, err := loadGlobalTLSCAPathWithLimits(directory, below); err == nil ||
			!strings.Contains(err.Error(), "byte total limit") {
			t.Fatalf("byte limit error = %v", err)
		}
	})

	t.Run("certificates", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, globalTLSCAHashName(t, authority.certificateDER, 0))
		if err := os.WriteFile(path, append(append([]byte(nil), certificatePEM...), certificatePEM...), 0o644); err != nil {
			t.Fatalf("write certificate bundle: %v", err)
		}
		exact := limits()
		exact.maximumCertificates = 2
		if _, err := loadGlobalTLSCAPathWithLimits(directory, exact); err != nil {
			t.Fatalf("exact certificate limit: %v", err)
		}
		below := exact
		below.maximumCertificates = 1
		if _, err := loadGlobalTLSCAPathWithLimits(directory, below); err == nil ||
			!strings.Contains(err.Error(), "certificate limit") {
			t.Fatalf("certificate limit error = %v", err)
		}
	})
}

func TestGlobalTLSTraditionalEncryptedPEMPrivateKey(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "encrypted-key-server", true)
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "server.pem")
	if err := os.WriteFile(certificatePath, certificate.certificatePEM, 0o644); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	password := []byte("correct horse battery staple")
	keyPath := writeGlobalTLSEncryptedPrivateKey(t, directory, "server.key", certificate, password)
	passwordPath := filepath.Join(directory, "key-password")
	if err := os.WriteFile(passwordPath, append(append([]byte(nil), password...), '\n'), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(keyPath)},
	})
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(encrypted key): %v", err)
	}
	instance.closeSQLBackends()

	if err := os.WriteFile(passwordPath, []byte("wrong password\n"), 0o600); err != nil {
		t.Fatalf("rewrite password file: %v", err)
	}
	_, err = ValidateConfiguration(context.Background(), Config{Store: store})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "password") {
		t.Fatalf("wrong password validation error = %v", err)
	}
}

func TestGlobalTLSPKCS8EncryptedPrivateKey(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "pkcs8-encrypted-key-server", true)
	directory := t.TempDir()
	password := []byte("pkcs8-correct-horse-battery-staple")
	keyPath := writeGlobalTLSPKCS8EncryptedPrivateKey(
		t,
		directory,
		"server-pkcs8.key",
		certificate,
		password,
	)
	passwordPath := filepath.Join(directory, "pkcs8-password")
	if err := os.WriteFile(passwordPath, append(append([]byte(nil), password...), '\n'), 0o600); err != nil {
		t.Fatalf("write PKCS#8 password: %v", err)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)

	normalized, err := normalizeGlobalTLSPrivateKey(mustReadGlobalTLSFile(t, keyPath))
	if err != nil {
		t.Fatalf("normalize PKCS#8 encrypted private key: %v", err)
	}
	defer clearGlobalTLSSecret(normalized)
	if _, err := tls.X509KeyPair(certificate.certificatePEM, normalized); err != nil {
		t.Fatalf("X509KeyPair(PKCS#8 encrypted private key): %v", err)
	}

	if err := os.WriteFile(passwordPath, []byte("wrong-password"), 0o600); err != nil {
		t.Fatalf("replace PKCS#8 password: %v", err)
	}
	if _, err := normalizeGlobalTLSPrivateKey(mustReadGlobalTLSFile(t, keyPath)); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "password") {
		t.Fatalf("wrong PKCS#8 password error = %v", err)
	}
}

func TestGlobalTLSPKCS8EncryptedPrivateKeyOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is unavailable")
	}
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "openssl-pkcs8-server", true)
	directory := t.TempDir()
	_, plainKeyPath := writeGlobalTLSTestFiles(t, directory, "openssl-server", certificate)
	passwordPath := filepath.Join(directory, "openssl-password")
	if err := os.WriteFile(passwordPath, []byte("openssl-pkcs8-password\n"), 0o600); err != nil {
		t.Fatalf("write OpenSSL password: %v", err)
	}
	encryptedKeyPath := filepath.Join(directory, "openssl-server-encrypted.key")
	command := exec.Command(
		openssl,
		"pkcs8",
		"-topk8",
		"-in", plainKeyPath,
		"-out", encryptedKeyPath,
		"-passout", "file:"+passwordPath,
		"-v2", "aes-256-cbc",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("openssl pkcs8: %v: %s", err, output)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)
	normalized, err := normalizeGlobalTLSPrivateKey(mustReadGlobalTLSFile(t, encryptedKeyPath))
	if err != nil {
		t.Fatalf("normalize OpenSSL PKCS#8 key: %v", err)
	}
	defer clearGlobalTLSSecret(normalized)
	if _, err := tls.X509KeyPair(certificate.certificatePEM, normalized); err != nil {
		t.Fatalf("X509KeyPair(OpenSSL PKCS#8 key): %v", err)
	}
}

func TestGlobalTLSPKCS8EncryptedPrivateKeyResourceLimits(t *testing.T) {
	validPBKDF2 := globalTLSPBKDF2Parameters{
		Salt:           []byte("bounded-salt"),
		IterationCount: 4096,
		KeyLength:      32,
	}
	if err := validateGlobalTLSPBES2Parameters(
		marshalGlobalTLSTestPBES2Parameters(t, globalTLSPBKDF2OID, validPBKDF2),
	); err != nil {
		t.Fatalf("valid PBKDF2 parameters: %v", err)
	}

	for name, parameters := range map[string]globalTLSPBKDF2Parameters{
		"iterations": {
			Salt:           []byte("salt"),
			IterationCount: globalTLSPKCS8MaximumIterations + 1,
		},
		"salt": {
			Salt:           make([]byte, globalTLSPKCS8MaximumSaltSize+1),
			IterationCount: 1,
		},
		"key length": {
			Salt:           []byte("salt"),
			IterationCount: 1,
			KeyLength:      globalTLSPKCS8MaximumDerivedKeySize + 1,
		},
	} {
		t.Run("PBKDF2 "+name, func(t *testing.T) {
			if err := validateGlobalTLSPBES2Parameters(
				marshalGlobalTLSTestPBES2Parameters(t, globalTLSPBKDF2OID, parameters),
			); err == nil {
				t.Fatal("unbounded PBKDF2 parameters were accepted")
			}
		})
	}

	for name, parameters := range map[string]globalTLSScryptParameters{
		"memory": {
			Salt:                     []byte("salt"),
			CostParameter:            1 << 20,
			BlockSize:                8,
			ParallelizationParameter: 1,
		},
		"work": {
			Salt:                     []byte("salt"),
			CostParameter:            1 << 18,
			BlockSize:                1,
			ParallelizationParameter: 512,
		},
		"invalid cost": {
			Salt:                     []byte("salt"),
			CostParameter:            3,
			BlockSize:                1,
			ParallelizationParameter: 1,
		},
	} {
		t.Run("scrypt "+name, func(t *testing.T) {
			if err := validateGlobalTLSPBES2Parameters(
				marshalGlobalTLSTestPBES2Parameters(t, globalTLSScryptOID, parameters),
			); err == nil {
				t.Fatal("unbounded scrypt parameters were accepted")
			}
		})
	}

	if _, err := normalizeGlobalTLSPrivateKey(
		make([]byte, globalTLSMaximumFileSize+1),
	); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized inline private key error = %v", err)
	}
}

func TestGlobalTLSPKCS8EncryptedKeyOnlineReloadRollback(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "pkcs8-reload-server", true)
	directory := t.TempDir()
	certificatePath, plainKeyPath := writeGlobalTLSTestFiles(
		t,
		directory,
		"pkcs8-reload-server",
		certificate,
	)
	password := []byte("pkcs8-reload-password")
	encryptedKeyPath := writeGlobalTLSPKCS8EncryptedPrivateKey(
		t,
		directory,
		"pkcs8-reload-server-encrypted.key",
		certificate,
		password,
	)
	passwordPath := filepath.Join(directory, "pkcs8-reload-password")
	if err := os.WriteFile(passwordPath, password, 0o600); err != nil {
		t.Fatalf("write reload password: %v", err)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(plainKeyPath)},
		"olcTLSECName":             {[]byte("P-256:P-384")},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	admin := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP256})
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Replace("olcTLSCertificateKeyFile", []string{encryptedKeyPath})
	if err := admin.Modify(enable); err != nil {
		t.Fatalf("enable PKCS#8 encrypted key: %v", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSCertificateKeyFile", encryptedKeyPath)
	client := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP384})
	client.Close()

	if err := os.WriteFile(passwordPath, []byte("incorrect"), 0o600); err != nil {
		t.Fatalf("replace reload password: %v", err)
	}
	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcTLSECName", []string{"X25519"})
	err := admin.Modify(invalid)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) ||
		ldapError.ResultCode != ldap.LDAPResultConstraintViolation ||
		!strings.Contains(strings.ToLower(err.Error()), "password") {
		t.Fatalf("wrong PKCS#8 password reload error = %v", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSECName", "P-256:P-384")
	client = dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP256})
	client.Close()
}

func TestGlobalTLSEncryptedKeyAndCAPathOnlineReloadRollback(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "encrypted-key-reload-server", true)
	directory := t.TempDir()
	certificatePath, plainKeyPath := writeGlobalTLSTestFiles(
		t,
		directory,
		"server",
		certificate,
	)
	password := []byte("reload-password")
	encryptedKeyPath := writeGlobalTLSEncryptedPrivateKey(
		t,
		directory,
		"server-encrypted.key",
		certificate,
		password,
	)
	passwordPath := filepath.Join(directory, "reload-password")
	if err := os.WriteFile(passwordPath, password, 0o600); err != nil {
		t.Fatalf("write reload password: %v", err)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)
	caDirectory := t.TempDir()
	writeGlobalTLSCAHashCertificate(t, caDirectory, authority.certificateDER, 0)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(plainKeyPath)},
		"olcTLSECName":             {[]byte("P-256")},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	admin := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP256})
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Replace("olcTLSCertificateKeyFile", []string{encryptedKeyPath})
	enable.Replace("olcTLSCACertificatePath", []string{caDirectory})
	if err := admin.Modify(enable); err != nil {
		t.Fatalf("enable encrypted key and CA path: %v", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSCertificateKeyFile", encryptedKeyPath)
	assertGlobalTLSStoredFile(t, store, "olcTLSCACertificatePath", caDirectory)

	if err := os.WriteFile(passwordPath, []byte("incorrect"), 0o600); err != nil {
		t.Fatalf("replace password with incorrect value: %v", err)
	}
	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcTLSECName", []string{"P-384"})
	err := admin.Modify(invalid)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != ldap.LDAPResultConstraintViolation ||
		!strings.Contains(strings.ToLower(err.Error()), "password") {
		t.Fatalf("wrong-password reload error = %v, want password constraintViolation", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSECName", "P-256")
	client := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP256})
	client.Close()
}

func TestGlobalTLSPrivateKeyPasswordFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private file permissions are unavailable on Windows")
	}
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "private-permissions-server", true)
	directory := t.TempDir()
	password := []byte("private-password")
	keyPath := writeGlobalTLSEncryptedPrivateKey(t, directory, "server.key", certificate, password)
	passwordPath := filepath.Join(directory, "password")
	if err := os.WriteFile(passwordPath, password, 0o600); err != nil {
		t.Fatalf("write password: %v", err)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)

	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	if _, err := globalTLSPrivateKeyData(nil, keyPath); err != nil {
		t.Fatalf("OpenLDAP-compatible group-readable key: %v", err)
	}
	if err := os.Chmod(passwordPath, 0o644); err != nil {
		t.Fatalf("chmod password: %v", err)
	}
	if _, err := normalizeGlobalTLSPrivateKey(mustReadGlobalTLSFile(t, keyPath)); err == nil ||
		!strings.Contains(err.Error(), "permissions") {
		t.Fatalf("world-readable password error = %v", err)
	}
	if err := os.Chmod(passwordPath, 0o600); err != nil {
		t.Fatalf("restore password mode: %v", err)
	}
	symlink := filepath.Join(directory, "password-link")
	if err := os.Symlink(passwordPath, symlink); err != nil {
		t.Fatalf("symlink password: %v", err)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, symlink)
	if _, err := normalizeGlobalTLSPrivateKey(mustReadGlobalTLSFile(t, keyPath)); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "symbolic link") {
		t.Fatalf("password symlink error = %v", err)
	}
}

func TestGlobalTLSPrivateKeyPasswordFileReadLimit(t *testing.T) {
	directory := t.TempDir()
	passwordPath := filepath.Join(directory, "password")
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)
	if err := os.WriteFile(passwordPath, []byte(strings.Repeat("x", globalTLSMaximumPassword)), 0o600); err != nil {
		t.Fatalf("write exact-limit password: %v", err)
	}
	password, err := loadGlobalTLSPrivateKeyPassword()
	if err != nil {
		t.Fatalf("load exact-limit password: %v", err)
	}
	clearGlobalTLSSecret(password)
	if err := os.WriteFile(passwordPath, []byte(strings.Repeat("x", globalTLSMaximumPassword+1)), 0o600); err != nil {
		t.Fatalf("write oversized password: %v", err)
	}
	if _, err := loadGlobalTLSPrivateKeyPassword(); err == nil ||
		!strings.Contains(err.Error(), "4096-byte limit") {
		t.Fatalf("oversized password error = %v", err)
	}
}

func TestGlobalTLSECNameMappingsAndExplicitRejections(t *testing.T) {
	t.Setenv("GODEBUG", "tlsmlkem=1,tlssecpmlkem=1")
	accepted := map[string]tls.CurveID{
		"X25519":             tls.X25519,
		"P-256":              tls.CurveP256,
		"prime256v1":         tls.CurveP256,
		"secp256r1":          tls.CurveP256,
		"P-384":              tls.CurveP384,
		"secp384r1":          tls.CurveP384,
		"P-521":              tls.CurveP521,
		"secp521r1":          tls.CurveP521,
		"X25519MLKEM768":     tls.X25519MLKEM768,
		"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
		"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
	}
	for value, want := range accepted {
		got, err := parseGlobalTLSECName(value)
		if (want == tls.SecP256r1MLKEM768 ||
			want == tls.SecP384r1MLKEM1024) &&
			version.Compare(runtime.Version(), "go1.26") < 0 {
			if err == nil || !strings.Contains(err.Error(), "go1.26") {
				t.Errorf("parseGlobalTLSECName(%q) on %s = %#v, %v; want version rejection", value, runtime.Version(), got, err)
			}
			continue
		}
		if err != nil || len(got) != 1 || got[0] != want {
			t.Errorf("parseGlobalTLSECName(%q) = %#v, %v; want %v", value, got, err, want)
		}
	}
	wantList := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.X25519MLKEM768,
	}
	gotList, err := parseGlobalTLSECName(
		"X25519:P-256:secp384r1:P-256:X25519MLKEM768",
	)
	if err != nil || fmt.Sprint(gotList) != fmt.Sprint(wantList) {
		t.Errorf("multi-group list = %#v, %v; want %#v", gotList, err, wantList)
	}
	for _, value := range []string{
		"", "X25519:", ":P-256", "P-256,,P-384", "P-256,P-384", "?X25519", "*X25519",
		"DEFAULT", "X448", "ffdhe2048", "brainpoolP256r1tls13",
	} {
		if _, err := parseGlobalTLSECName(value); err == nil {
			t.Errorf("parseGlobalTLSECName(%q) accepted an inexact OpenSSL selector", value)
		}
	}
	t.Setenv("GODEBUG", "tlsmlkem=0,tlssecpmlkem=1")
	if _, err := parseGlobalTLSECName("X25519MLKEM768"); err == nil ||
		!strings.Contains(err.Error(), "tlsmlkem=0") {
		t.Errorf("tlsmlkem=0 rejection = %v", err)
	}
	t.Setenv("GODEBUG", "tlsmlkem=1,tlssecpmlkem=0")
	if _, err := parseGlobalTLSECName("SecP256r1MLKEM768"); err == nil ||
		!strings.Contains(err.Error(), "tlssecpmlkem=0") {
		t.Errorf("tlssecpmlkem=0 rejection = %v", err)
	}
}

func TestGlobalTLSECNameOnlineReloadAndRollback(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "curve-reload-server", true)
	directory := t.TempDir()
	certificatePath, keyPath := writeGlobalTLSTestFiles(t, directory, "server", certificate)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(keyPath)},
		"olcTLSECName":             {[]byte("P-256:P-384")},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()

	admin := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP256})
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	rotate := ldap.NewModifyRequest("cn=config", nil)
	rotate.Replace("olcTLSECName", []string{"X25519:P-521"})
	if err := admin.Modify(rotate); err != nil {
		t.Fatalf("rotate curve list: %v", err)
	}
	assertGlobalTLSCurveRejected(t, address, tls.CurveP256)
	x25519 := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.X25519})
	x25519.Close()
	p521 := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP521})
	p521.Close()

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcTLSECName", []string{"X25519:X448"})
	err := admin.Modify(invalid)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Fatalf("invalid curve reload error = %v, want constraintViolation", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSECName", "X25519:P-521")
	x25519 = dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.X25519})
	x25519.Close()
}

func TestGlobalTLSECNameAllRuntimeSupportedGroupsHandshake(t *testing.T) {
	t.Setenv("GODEBUG", "tlsmlkem=1,tlssecpmlkem=1")
	groups := []struct {
		name    string
		curve   tls.CurveID
		minimum string
	}{
		{name: "P-256", curve: tls.CurveP256},
		{name: "P-384", curve: tls.CurveP384},
		{name: "P-521", curve: tls.CurveP521},
		{name: "X25519", curve: tls.X25519},
		{name: "X25519MLKEM768", curve: tls.X25519MLKEM768, minimum: "go1.24"},
		{name: "SecP256r1MLKEM768", curve: tls.SecP256r1MLKEM768, minimum: "go1.26"},
		{name: "SecP384r1MLKEM1024", curve: tls.SecP384r1MLKEM1024, minimum: "go1.26"},
	}
	enabledNames := make([]string, 0, len(groups))
	enabledGroups := make([]tls.CurveID, 0, len(groups))
	for _, group := range groups {
		if group.minimum != "" && version.Compare(runtime.Version(), group.minimum) < 0 {
			continue
		}
		enabledNames = append(enabledNames, group.name)
		enabledGroups = append(enabledGroups, group.curve)
	}

	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "all-go-groups-server", true)
	certificatePath, keyPath := writeGlobalTLSTestFiles(t, t.TempDir(), "server", certificate)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(keyPath)},
		"olcTLSECName":             {[]byte(strings.Join(enabledNames, ":"))},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	for index, group := range enabledGroups {
		client, err := dialGlobalTLSClientWithCurves(address, []tls.CurveID{group})
		if err == nil {
			client.Close()
		}
		if err != nil {
			t.Errorf(
				"TLS handshake with configured group %s (%d) failed: %v",
				enabledNames[index],
				group,
				err,
			)
		}
	}
}

func TestGlobalTLSConcurrentCurveReloadAndHandshake(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "curve-race-server", true)
	certificatePath, keyPath := writeGlobalTLSTestFiles(t, t.TempDir(), "server", certificate)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(keyPath)},
		"olcTLSECName":             {[]byte("P-256:P-384")},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	admin := dialGlobalTLSTestClientWithCurves(
		t,
		address,
		[]tls.CurveID{tls.CurveP256, tls.CurveP384},
	)
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 4)
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 12; iteration++ {
				client, err := dialGlobalTLSClientWithCurves(
					address,
					[]tls.CurveID{tls.CurveP256, tls.CurveP384},
				)
				if err != nil {
					errorsChannel <- err
					return
				}
				client.Close()
			}
		}()
	}
	close(start)
	for iteration := 0; iteration < 12; iteration++ {
		curve := "P-256:P-384"
		if iteration%2 != 0 {
			curve = "P-384:P-256"
		}
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcTLSECName", []string{curve})
		if err := admin.Modify(request); err != nil {
			t.Fatalf("reload %s: %v", curve, err)
		}
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent TLS handshake: %v", err)
	}
}

func TestGlobalTLSConcurrentPKCS8EncryptedKeyReloadAndHandshake(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "pkcs8-race-server", true)
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "pkcs8-race-server.pem")
	if err := os.WriteFile(certificatePath, certificate.certificatePEM, 0o644); err != nil {
		t.Fatalf("write race certificate: %v", err)
	}
	password := []byte("pkcs8-race-password")
	firstKeyPath := writeGlobalTLSPKCS8EncryptedPrivateKey(
		t,
		directory,
		"pkcs8-race-first.key",
		certificate,
		password,
	)
	secondKeyPath := writeGlobalTLSPKCS8EncryptedPrivateKey(
		t,
		directory,
		"pkcs8-race-second.key",
		certificate,
		password,
	)
	passwordPath := filepath.Join(directory, "pkcs8-race-password")
	if err := os.WriteFile(passwordPath, password, 0o600); err != nil {
		t.Fatalf("write race password: %v", err)
	}
	t.Setenv(globalTLSPrivateKeyPasswordFileEnvironment, passwordPath)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(firstKeyPath)},
		"olcTLSECName":             {[]byte("P-256:P-384")},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	admin := dialGlobalTLSTestClientWithCurves(
		t,
		address,
		[]tls.CurveID{tls.CurveP256, tls.CurveP384},
	)
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 4)
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 8; iteration++ {
				client, err := dialGlobalTLSClientWithCurves(
					address,
					[]tls.CurveID{tls.CurveP256, tls.CurveP384},
				)
				if err != nil {
					errorsChannel <- err
					return
				}
				client.Close()
			}
		}()
	}
	close(start)
	for iteration := 0; iteration < 8; iteration++ {
		path := firstKeyPath
		if iteration%2 != 0 {
			path = secondKeyPath
		}
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcTLSCertificateKeyFile", []string{path})
		if err := admin.Modify(request); err != nil {
			t.Fatalf("reload PKCS#8 encrypted key %q: %v", path, err)
		}
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent TLS handshake during PKCS#8 reload: %v", err)
	}
}

func TestGlobalTLSConcurrentCAPathReloadAndHandshake(t *testing.T) {
	firstAuthority := newGlobalTLSTestAuthority(t)
	secondAuthority := newGlobalTLSTestAuthority(t)
	certificate := firstAuthority.issue(t, "ca-path-race-server", true)
	certificatePath, keyPath := writeGlobalTLSTestFiles(t, t.TempDir(), "server", certificate)
	firstDirectory := t.TempDir()
	secondDirectory := t.TempDir()
	writeGlobalTLSCAHashCertificate(t, firstDirectory, firstAuthority.certificateDER, 0)
	writeGlobalTLSCAHashCertificate(t, secondDirectory, secondAuthority.certificateDER, 0)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(keyPath)},
		"olcTLSCACertificatePath":  {[]byte(firstDirectory)},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	admin := dialGlobalTLSTestClientWithCurves(
		t,
		address,
		[]tls.CurveID{tls.CurveP256, tls.CurveP384},
	)
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 4)
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 12; iteration++ {
				client, err := dialGlobalTLSClientWithCurves(
					address,
					[]tls.CurveID{tls.CurveP256, tls.CurveP384},
				)
				if err != nil {
					errorsChannel <- err
					return
				}
				client.Close()
			}
		}()
	}
	close(start)
	for iteration := 0; iteration < 12; iteration++ {
		path := firstDirectory
		if iteration%2 != 0 {
			path = firstDirectory + ";" + secondDirectory
		}
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcTLSCACertificatePath", []string{path})
		if err := admin.Modify(request); err != nil {
			t.Fatalf("reload CA path %q: %v", path, err)
		}
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent TLS handshake: %v", err)
	}
}

func writeGlobalTLSCACertificate(
	t *testing.T,
	directory,
	name string,
	der []byte,
) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}), 0o644); err != nil {
		t.Fatalf("write CA certificate: %v", err)
	}
	return path
}

func writeGlobalTLSCAHashCertificate(
	t *testing.T,
	directory string,
	der []byte,
	index int,
) string {
	t.Helper()
	return writeGlobalTLSCACertificate(
		t,
		directory,
		globalTLSCAHashName(t, der, index),
		der,
	)
}

func globalTLSCAHashName(t *testing.T, der []byte, index int) string {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(CA hash name): %v", err)
	}
	hash, err := globalTLSOpenSSLSubjectHash(certificate)
	if err != nil {
		t.Fatalf("globalTLSOpenSSLSubjectHash(): %v", err)
	}
	return fmt.Sprintf("%s.%d", hash, index)
}

func globalTLSWrongCAHashName(t *testing.T, der []byte, index int) string {
	t.Helper()
	correct := globalTLSCAHashName(t, der, index)[:8]
	wrong := "00000000"
	if correct == wrong {
		wrong = "ffffffff"
	}
	return fmt.Sprintf("%s.%d", wrong, index)
}

func writeGlobalTLSEncryptedPrivateKey(
	t *testing.T,
	directory,
	name string,
	certificate globalTLSTestCertificate,
	password []byte,
) string {
	t.Helper()
	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"PRIVATE KEY",
		certificate.privateKeyDER,
		password,
		x509.PEMCipherAES256,
	)
	if err != nil {
		t.Fatalf("EncryptPEMBlock(): %v", err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write encrypted private key: %v", err)
	}
	return path
}

func writeGlobalTLSPKCS8EncryptedPrivateKey(
	t *testing.T,
	directory,
	name string,
	certificate globalTLSTestCertificate,
	password []byte,
) string {
	t.Helper()
	privateKey, err := x509.ParsePKCS8PrivateKey(certificate.privateKeyDER)
	if err != nil {
		t.Fatalf("parse test PKCS#8 private key: %v", err)
	}
	der, err := pkcs8.MarshalPrivateKey(
		privateKey,
		password,
		pkcs.NewPBESEncrypter(
			pkcs.AES256CBC,
			pkcs.NewPBKDF2Opts(pkcs.SHA256, 16, 4096),
		),
	)
	if err != nil {
		t.Fatalf("marshal PKCS#8 encrypted private key: %v", err)
	}
	defer clearGlobalTLSSecret(der)
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: der,
	}), 0o600); err != nil {
		t.Fatalf("write PKCS#8 encrypted private key: %v", err)
	}
	return path
}

func marshalGlobalTLSTestPBES2Parameters(
	t *testing.T,
	kdfOID asn1.ObjectIdentifier,
	kdfParameters any,
) []byte {
	t.Helper()
	kdfDER, err := asn1.Marshal(kdfParameters)
	if err != nil {
		t.Fatalf("marshal test KDF parameters: %v", err)
	}
	parametersDER, err := asn1.Marshal(pkcs.PBES2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{
			Algorithm:  kdfOID,
			Parameters: asn1.RawValue{FullBytes: kdfDER},
		},
		EncryptionScheme: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42},
		},
	})
	if err != nil {
		t.Fatalf("marshal test PBES2 parameters: %v", err)
	}
	return parametersDER
}

func mustReadGlobalTLSFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func dialGlobalTLSTestClientWithCurves(
	t *testing.T,
	address string,
	curves []tls.CurveID,
) *ldap.Conn {
	t.Helper()
	client, err := dialGlobalTLSClientWithCurves(address, curves)
	if err != nil {
		t.Fatalf("dial TLS with curves %v: %v", curves, err)
	}
	return client
}

func dialGlobalTLSClientWithCurves(address string, curves []tls.CurveID) (*ldap.Conn, error) {
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		return nil, err
	}
	err = client.StartTLS(&tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   curves,
	})
	if err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func assertGlobalTLSCurveRejected(t *testing.T, address string, curve tls.CurveID) {
	t.Helper()
	client, err := dialGlobalTLSClientWithCurves(address, []tls.CurveID{curve})
	if err == nil {
		client.Close()
		t.Fatalf("TLS server accepted disabled curve %v", curve)
	}
	if !strings.Contains(strings.ToLower(fmt.Sprint(err)), "handshake") &&
		!strings.Contains(strings.ToLower(fmt.Sprint(err)), "curve") {
		t.Logf("disabled curve handshake diagnostic: %v", err)
	}
}
