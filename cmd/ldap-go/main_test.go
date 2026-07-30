package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

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
