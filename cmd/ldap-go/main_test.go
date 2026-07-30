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
	defer store.Close()
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
}
