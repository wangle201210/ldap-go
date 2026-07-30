package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPasswordCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		password string
	}{
		{name: "environment", password: "environment secret"},
		{name: "stdin LF", input: "stdin secret\n", password: "stdin secret"},
		{name: "stdin CRLF", input: "stdin secret\r\n", password: "stdin secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(
				[]string{"passwd", "-iterations", "10"},
				strings.NewReader(test.input),
				&stdout,
				&stderr,
				func(name string) string {
					if name == passwordEnvironment && test.input == "" {
						return test.password
					}
					return ""
				},
			)
			if exitCode != 0 {
				t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
			}
			stored := []byte(strings.TrimSuffix(stdout.String(), "\n"))
			if !strings.HasPrefix(string(stored), "{PBKDF2-SM3}10$") {
				t.Fatalf("stdout = %q", stdout.String())
			}
			if !auth.VerifyPassword(stored, []byte(test.password)) {
				t.Fatal("generated password does not verify")
			}
			if auth.VerifyPassword(stored, []byte("wrong")) {
				t.Fatal("generated password accepted an incorrect value")
			}
		})
	}
}

func TestPasswordCommandRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		args  []string
		input string
	}{
		{name: "empty", args: []string{"passwd"}},
		{
			name:  "iterations",
			args:  []string{"passwd", "-iterations", "0"},
			input: "secret\n",
		},
		{
			name:  "unexpected argument",
			args:  []string{"passwd", "secret"},
			input: "ignored\n",
		},
		{
			name:  "input limit",
			args:  []string{"passwd"},
			input: strings.Repeat("x", maxPasswordInputSize+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if exitCode := run(
				test.args,
				strings.NewReader(test.input),
				&stdout,
				&stderr,
				func(string) string { return "" },
			); exitCode != 1 {
				t.Fatalf(
					"run() exit code = %d, stdout = %q, stderr = %q",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "error:") {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestImportCommand(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "directory.db")
	input := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"import", "-db", databasePath, "-ldif", "-", "-replace"},
		strings.NewReader(input),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "imported 2 entries") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	store, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	dn, err := directory.ParseDN("uid=alice,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.View(context.Background(), func(tx storage.Reader) error {
		_, err := tx.Get(dn)
		return err
	}); err != nil {
		t.Fatalf("imported entry: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = run(
		[]string{"export", "-db", databasePath, "-ldif", "-"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("export run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dn: uid=alice,dc=example,dc=com") ||
		!strings.Contains(stderr.String(), "exported 2 entries") {
		t.Fatalf("export stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestDatabaseSelectedImportExportCommands(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "partitioned.db")
	configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
entryUUID: 11111111-1111-4111-8111-111111111111

`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"import", "-db", databasePath, "-ldif", "-", "-replace"},
		strings.NewReader(configLDIF),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("config import exit code = %d, stderr = %q", exitCode, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	dataLDIF := `dn: dc=example,dc=com
objectClass: domain
dc: example
description: selected database

`
	exitCode = run(
		[]string{
			"import",
			"-db", databasePath,
			"-ldif", "-",
			"-database", "1",
			"-replace",
		},
		strings.NewReader(dataLDIF),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("data import exit code = %d, stderr = %q", exitCode, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = run(
		[]string{
			"export",
			"-db", databasePath,
			"-ldif", "-",
			"-database", "{1}mdb",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("selected export exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "description: selected database") ||
		!strings.Contains(stderr.String(), "exported 1 entries") {
		t.Fatalf("selected export stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestLoadServerTLSConfigRequiresCertificatePair(t *testing.T) {
	t.Parallel()

	config, err := loadServerTLSConfig("", "")
	if err != nil || config != nil {
		t.Fatalf("loadServerTLSConfig(empty) = %#v, %v", config, err)
	}
	if _, err := loadServerTLSConfig("server.crt", ""); err == nil {
		t.Fatal("certificate without private key was accepted")
	}
	if _, err := loadServerTLSConfig("", "server.key"); err == nil {
		t.Fatal("private key without certificate was accepted")
	}
	if _, err := loadServerTLSConfigWithClientAuth(
		"server.crt",
		"server.key",
		"",
		true,
	); err == nil || !strings.Contains(err.Error(), "-tls-client-ca") {
		t.Fatalf("required TLS client certificate error = %v", err)
	}
}

func TestLoadServerTLCPRequiresDualCertificatePairs(t *testing.T) {
	t.Parallel()

	transport, err := loadServerTLCP("", "", "", "")
	if err != nil || transport != nil {
		t.Fatalf("loadServerTLCP(empty) = %#v, %v", transport, err)
	}
	if _, err := loadServerTLCP(
		"sign.crt",
		"sign.key",
		"",
		"",
	); err == nil {
		t.Fatal("TLCP configuration without encryption certificate was accepted")
	}
	if _, err := loadServerTLCPWithClientAuth(
		"sign.crt",
		"sign.key",
		"enc.crt",
		"enc.key",
		"",
		true,
	); err == nil || !strings.Contains(err.Error(), "-tlcp-client-ca") {
		t.Fatalf("required TLCP client certificate error = %v", err)
	}
}
