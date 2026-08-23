package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestGlobalTLSCACertificatePathLoadsDirectoryAndDeduplicates(t *testing.T) {
	firstAuthority := newGlobalTLSTestAuthority(t)
	secondAuthority := newGlobalTLSTestAuthority(t)
	rogueAuthority := newGlobalTLSTestAuthority(t)
	serverCertificate := firstAuthority.issue(t, "ca-directory-server", true)
	firstDirectory := t.TempDir()
	writeGlobalTLSCACertificate(t, firstDirectory, "01234567.0", firstAuthority.certificateDER)
	writeGlobalTLSCACertificate(t, firstDirectory, "rogue.pem", rogueAuthority.certificateDER)
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
		if err := os.Symlink(filepath.Base(secondPath), filepath.Join(firstDirectory, "89ABCDEF.1")); err != nil {
			t.Fatalf("create in-directory CA symlink: %v", err)
		}
	} else {
		writeGlobalTLSCACertificate(t, firstDirectory, "89ABCDEF.1", secondAuthority.certificateDER)
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

func TestGlobalTLSCACertificatePathSupportsSemicolonSeparatedDirectories(t *testing.T) {
	firstAuthority := newGlobalTLSTestAuthority(t)
	secondAuthority := newGlobalTLSTestAuthority(t)
	firstDirectory := t.TempDir()
	secondDirectory := t.TempDir()
	writeGlobalTLSCACertificate(t, firstDirectory, "01234567.0", firstAuthority.certificateDER)
	writeGlobalTLSCACertificate(t, secondDirectory, "89abcdef.3", secondAuthority.certificateDER)

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
		writeGlobalTLSCACertificate(t, first, "01234567.0", authority.certificateDER)
		writeGlobalTLSCACertificate(t, second, "89abcdef.0", authority.certificateDER)
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
		writeGlobalTLSCACertificate(t, directory, "01234567.0", authority.certificateDER)
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
		writeGlobalTLSCACertificate(t, directory, "01234567.0", authority.certificateDER)
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
		path := filepath.Join(directory, "01234567.0")
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
	writeGlobalTLSCACertificate(t, caDirectory, "01234567.0", authority.certificateDER)

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
	accepted := map[string]tls.CurveID{
		"X25519":     tls.X25519,
		"P-256":      tls.CurveP256,
		"prime256v1": tls.CurveP256,
		"secp256r1":  tls.CurveP256,
		"P-384":      tls.CurveP384,
		"secp384r1":  tls.CurveP384,
		"P-521":      tls.CurveP521,
		"secp521r1":  tls.CurveP521,
	}
	for value, want := range accepted {
		got, err := parseGlobalTLSECName(value)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Errorf("parseGlobalTLSECName(%q) = %#v, %v; want %v", value, got, err, want)
		}
	}
	for _, value := range []string{
		"", "X25519:P-256", "P-256,P-384", "?X25519", "*X25519",
		"DEFAULT", "X448", "ffdhe2048", "brainpoolP256r1tls13",
	} {
		if _, err := parseGlobalTLSECName(value); err == nil {
			t.Errorf("parseGlobalTLSECName(%q) accepted an inexact OpenSSL selector", value)
		}
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
		"olcTLSECName":             {[]byte("P-256")},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()

	admin := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP256})
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	rotate := ldap.NewModifyRequest("cn=config", nil)
	rotate.Replace("olcTLSECName", []string{"P-384"})
	if err := admin.Modify(rotate); err != nil {
		t.Fatalf("rotate curve: %v", err)
	}
	assertGlobalTLSCurveRejected(t, address, tls.CurveP256)
	p384 := dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP384})
	p384.Close()

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcTLSECName", []string{"X25519:P-384"})
	err := admin.Modify(invalid)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Fatalf("invalid curve reload error = %v, want constraintViolation", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSECName", "P-384")
	p384 = dialGlobalTLSTestClientWithCurves(t, address, []tls.CurveID{tls.CurveP384})
	p384.Close()
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
		"olcTLSECName":             {[]byte("P-256")},
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
		curve := "P-256"
		if iteration%2 != 0 {
			curve = "P-384"
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

func TestGlobalTLSConcurrentCAPathReloadAndHandshake(t *testing.T) {
	firstAuthority := newGlobalTLSTestAuthority(t)
	secondAuthority := newGlobalTLSTestAuthority(t)
	certificate := firstAuthority.issue(t, "ca-path-race-server", true)
	certificatePath, keyPath := writeGlobalTLSTestFiles(t, t.TempDir(), "server", certificate)
	firstDirectory := t.TempDir()
	secondDirectory := t.TempDir()
	writeGlobalTLSCACertificate(t, firstDirectory, "01234567.0", firstAuthority.certificateDER)
	writeGlobalTLSCACertificate(t, secondDirectory, "89abcdef.0", secondAuthority.certificateDER)

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
