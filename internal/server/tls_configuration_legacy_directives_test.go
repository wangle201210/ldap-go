package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const globalTLSTestDHParametersPEM = `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
`

func TestGlobalTLSRandFileModernCompatibility(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "rand-file-server", true)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	missing := filepath.Join(t.TempDir(), "intentionally-missing-random-seed")
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificate;binary":    {certificate.certificateDER},
		"olcTLSCertificateKey;binary": {certificate.privateKeyDER},
		"olcTLSRandFile":              {[]byte(missing)},
	})
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New() with inert olcTLSRandFile: %v", err)
	}
	defer instance.closeSQLBackends()
	if instance.runtime.Load().secureTransport == nil {
		t.Fatal("olcTLSRandFile prevented otherwise valid TLS configuration")
	}

	for name, values := range map[string][][]byte{
		"empty":    {[]byte(" \t\n")},
		"NUL":      {[]byte("seed\x00file")},
		"multiple": {[]byte("one"), []byte("two")},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := storage.NewMemory()
			t.Cleanup(func() { _ = candidate.Close() })
			seedGlobalTLSAttributes(t, candidate, map[string][][]byte{
				"olcTLSRandFile": values,
			})
			if _, err := ValidateConfiguration(
				context.Background(),
				Config{Store: candidate},
			); err == nil {
				t.Fatal("invalid olcTLSRandFile value was accepted")
			}
		})
	}
}

func TestGlobalTLSDHParamFileCompatibilityMatrix(t *testing.T) {
	dhPath := writeGlobalTLSTestDHParameters(
		t,
		t.TempDir(),
		"ffdhe2048.pem",
		[]byte(globalTLSTestDHParametersPEM),
	)
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "dh-matrix-server", true)
	for _, test := range []struct {
		name     string
		protocol string
		cipher   string
		material bool
		wantErr  string
	}{
		{
			name:     "TLS 1.3 only",
			protocol: "3.4",
			material: true,
		},
		{
			name:     "TLS 1.2 exact non-DHE suite",
			protocol: "3.3",
			cipher:   "ECDHE-ECDSA-AES128-GCM-SHA256",
			material: true,
		},
		{
			name:     "TLS 1.2 OpenSSL default may use DHE",
			protocol: "3.3",
			material: true,
			wantErr:  "finite-field DHE",
		},
		{
			name:     "directive without active TLS material",
			protocol: "3.3",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			attributes := map[string][][]byte{
				"olcTLSDHParamFile": {[]byte(dhPath)},
				"olcTLSProtocolMin": {[]byte(test.protocol)},
			}
			if test.cipher != "" {
				attributes["olcTLSCipherSuite"] = [][]byte{[]byte(test.cipher)}
			}
			if test.material {
				attributes["olcTLSCertificate;binary"] = [][]byte{certificate.certificateDER}
				attributes["olcTLSCertificateKey;binary"] = [][]byte{certificate.privateKeyDER}
			}
			seedGlobalTLSAttributes(t, store, attributes)
			_, err := ValidateConfiguration(context.Background(), Config{Store: store})
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateConfiguration(): %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateConfiguration() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestGlobalTLSDHParamFileBoundedParsing(t *testing.T) {
	directory := t.TempDir()
	valid := writeGlobalTLSTestDHParameters(
		t,
		directory,
		"valid.pem",
		[]byte(globalTLSTestDHParametersPEM),
	)
	if err := loadGlobalTLSDHParameters(valid); err != nil {
		t.Fatalf("load valid DH parameters: %v", err)
	}

	oversized := filepath.Join(directory, "oversized.pem")
	if err := os.WriteFile(oversized, []byte(globalTLSTestDHParametersPEM), 0o600); err != nil {
		t.Fatalf("write oversized DH parameters: %v", err)
	}
	if err := os.Truncate(oversized, globalTLSMaximumFileSize+1); err != nil {
		t.Fatalf("truncate oversized DH parameters: %v", err)
	}

	for _, test := range []struct {
		name string
		path string
		data []byte
		want string
	}{
		{name: "missing", path: filepath.Join(directory, "missing.pem"), want: "open"},
		{name: "directory", path: directory, want: "regular file"},
		{name: "empty", data: nil, want: "empty"},
		{name: "invalid PEM", data: []byte("not PEM"), want: "PEM"},
		{
			name: "wrong PEM type",
			data: []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"),
			want: "DH PARAMETERS",
		},
		{
			name: "trailing data",
			data: append([]byte(globalTLSTestDHParametersPEM), []byte("trailing")...),
			want: "trailing data",
		},
		{name: "oversized", path: oversized, want: "byte limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := test.path
			if path == "" {
				path = filepath.Join(directory, strings.ReplaceAll(test.name, " ", "-")+".pem")
				if err := os.WriteFile(path, test.data, 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}
			err := loadGlobalTLSDHParameters(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadGlobalTLSDHParameters() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGlobalTLSLegacyDirectivesOnlineReloadAndRollback(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "legacy-directives-reload-server", true)
	directory := t.TempDir()
	certificatePath, keyPath := writeGlobalTLSTestFiles(
		t,
		directory,
		"legacy-directives-server",
		certificate,
	)
	dhPath := writeGlobalTLSTestDHParameters(
		t,
		directory,
		"ffdhe2048.pem",
		[]byte(globalTLSTestDHParametersPEM),
	)
	invalidDHPath := writeGlobalTLSTestDHParameters(
		t,
		directory,
		"invalid-dh.pem",
		[]byte("not DH parameters"),
	)
	randPath := filepath.Join(directory, "missing-and-inert-random-seed")

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(certificatePath)},
		"olcTLSCertificateKeyFile": {[]byte(keyPath)},
		"olcTLSProtocolMin":        {[]byte("3.3")},
		"olcTLSCipherSuite":        {[]byte("ECDHE-ECDSA-AES128-GCM-SHA256")},
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	admin, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Add("olcTLSRandFile", []string{randPath})
	enable.Add("olcTLSDHParamFile", []string{dhPath})
	if err := admin.Modify(enable); err != nil {
		t.Fatalf("enable inert legacy TLS directives: %v", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSRandFile", randPath)
	assertGlobalTLSStoredFile(t, store, "olcTLSDHParamFile", dhPath)
	client := dialGlobalTLSTestClient(t, address, false, nil)
	client.Close()

	invalidFile := ldap.NewModifyRequest("cn=config", nil)
	invalidFile.Replace("olcTLSDHParamFile", []string{invalidDHPath})
	assertGlobalTLSModifyConstraintAndRollback(
		t,
		admin,
		invalidFile,
		store,
		"olcTLSDHParamFile",
		dhPath,
	)

	unsafeDefault := ldap.NewModifyRequest("cn=config", nil)
	unsafeDefault.Delete("olcTLSCipherSuite", nil)
	assertGlobalTLSModifyConstraintAndRollback(
		t,
		admin,
		unsafeDefault,
		store,
		"olcTLSCipherSuite",
		"ECDHE-ECDSA-AES128-GCM-SHA256",
	)

	tls13Only := ldap.NewModifyRequest("cn=config", nil)
	tls13Only.Replace("olcTLSProtocolMin", []string{"3.4"})
	tls13Only.Delete("olcTLSCipherSuite", nil)
	if err := admin.Modify(tls13Only); err != nil {
		t.Fatalf("make DH parameters inert with TLS 1.3 only: %v", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSProtocolMin", "3.4")
	client = dialGlobalTLSTestClient(t, address, false, nil)
	client.Close()

	unsafeDowngrade := ldap.NewModifyRequest("cn=config", nil)
	unsafeDowngrade.Replace("olcTLSProtocolMin", []string{"3.3"})
	assertGlobalTLSModifyConstraintAndRollback(
		t,
		admin,
		unsafeDowngrade,
		store,
		"olcTLSProtocolMin",
		"3.4",
	)
}

func TestOpenLDAPLegacyTLSDirectiveSourceAndConfigurationContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	buildRoot := os.Getenv("OPENLDAP_BUILD_WORK")
	if sourceRoot == "" || buildRoot == "" || os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Skip("verified pinned OpenLDAP source and build are required")
	}
	openSSLSource, err := os.ReadFile(filepath.Join(sourceRoot, "libraries", "libldap", "tls_o.c"))
	if err != nil {
		t.Fatalf("read OpenLDAP tls_o.c: %v", err)
	}
	for _, anchor := range []string{
		"#ifndef URANDOM_DEVICE",
		"tlso_seed_PRNG( const char *randfile )",
		"if ( is_server && lo->ldo_tls_dhfile )",
		"PEM_read_bio_Parameters",
		"SSL_CTX_set0_tmp_dh_pkey",
	} {
		if !strings.Contains(string(openSSLSource), anchor) {
			t.Errorf("OpenLDAP TLS source missing %q", anchor)
		}
	}
	portable, err := os.ReadFile(filepath.Join(buildRoot, "include", "portable.h"))
	if err != nil {
		t.Fatalf("read OpenLDAP portable.h: %v", err)
	}
	if !strings.Contains(string(portable), "#define URANDOM_DEVICE") {
		t.Fatal("pinned modern OpenLDAP build does not use an OS random source")
	}

	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "openldap-legacy-directives", true)
	directory := t.TempDir()
	certificatePath, keyPath := writeGlobalTLSTestFiles(
		t,
		directory,
		"openldap-legacy-directives",
		certificate,
	)
	dhPath := writeGlobalTLSTestDHParameters(
		t,
		directory,
		"ffdhe2048.pem",
		[]byte(globalTLSTestDHParametersPEM),
	)
	invalidDHPath := writeGlobalTLSTestDHParameters(
		t,
		directory,
		"invalid.pem",
		[]byte("not PEM"),
	)
	missingRandPath := filepath.Join(directory, "missing-rand-file")

	for _, test := range []struct {
		name   string
		config string
		wantOK bool
	}{
		{
			name:   "missing RandFile is inert",
			config: "TLSRandFile " + missingRandPath,
			wantOK: true,
		},
		{
			name:   "DH parameters with TLS 1.3 only",
			config: "TLSProtocolMin 3.4\nTLSDHParamFile " + dhPath,
			wantOK: true,
		},
		{
			name:   "DH parameters with exact ECDHE TLS 1.2 suite",
			config: "TLSProtocolMin 3.3\nTLSCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256\nTLSDHParamFile " + dhPath,
			wantOK: true,
		},
		{
			name:   "DH parameters with default TLS 1.2 cipher list",
			config: "TLSProtocolMin 3.3\nTLSDHParamFile " + dhPath,
			wantOK: true,
		},
		{
			name:   "invalid DH parameters",
			config: "TLSProtocolMin 3.4\nTLSDHParamFile " + invalidDHPath,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runOpenLDAPTLSConfigurationCheck(
				t,
				certificatePath,
				keyPath,
				test.config,
			)
			if test.wantOK && err != nil {
				t.Fatalf("OpenLDAP rejected configuration: %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatal("OpenLDAP accepted invalid DH parameters")
			}
		})
	}
}

func writeGlobalTLSTestDHParameters(
	t *testing.T,
	directory,
	name string,
	data []byte,
) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write DH parameters: %v", err)
	}
	return path
}

func assertGlobalTLSModifyConstraintAndRollback(
	t *testing.T,
	client *ldap.Conn,
	request *ldap.ModifyRequest,
	store storage.Store,
	attribute,
	want string,
) {
	t.Helper()
	err := client.Modify(request)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) ||
		ldapError.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Fatalf("online TLS Modify error = %v, want constraintViolation", err)
	}
	assertGlobalTLSStoredFile(t, store, attribute, want)
}

func runOpenLDAPTLSConfigurationCheck(
	t *testing.T,
	certificatePath,
	keyPath,
	extra string,
) error {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "db")
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatalf("create OpenLDAP database directory: %v", err)
	}
	configPath := filepath.Join(directory, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
pidfile %s
argsfile %s
TLSCertificateFile %s
TLSCertificateKeyFile %s
%s

database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(directory, "slapd.pid"),
		filepath.Join(directory, "slapd.args"),
		certificatePath,
		keyPath,
		extra,
		databasePath,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP TLS config: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve OpenLDAP TLS configuration port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release OpenLDAP TLS configuration port: %v", err)
	}
	var output bytes.Buffer
	command := exec.Command(
		tools.slapd,
		"-f", configPath,
		"-h", "ldap://"+address,
		"-d", "0",
	)
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		return fmt.Errorf("start slapd: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stop := func() {
		if command.Process == nil {
			return
		}
		_ = command.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case waitErr := <-done:
			return fmt.Errorf(
				"slapd TLS initialization: %v: %s",
				waitErr,
				strings.TrimSpace(output.String()),
			)
		default:
		}
		connection, dialErr := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			stop()
			return nil
		}
		if time.Now().After(deadline) {
			stop()
			return fmt.Errorf(
				"slapd did not listen after TLS initialization: %v: %s",
				dialErr,
				strings.TrimSpace(output.String()),
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
