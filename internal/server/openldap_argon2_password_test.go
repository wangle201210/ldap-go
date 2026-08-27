package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPArgon2PasswordLifecycle(t *testing.T) {
	const password = "argon2-lifecycle-secret"
	stored := generateLDAPGoPasswordModifyHash(
		t,
		auth.OpenLDAPArgon2HashScheme,
		password,
	)
	if !bytes.HasPrefix(stored, []byte("{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$")) {
		t.Fatalf("generated ARGON2 value = %q", stored)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(aliceDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", [][]byte{stored})
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	assertReferencePasswordBind(t, "ldap://"+address, aliceDN, password)
}

func TestOpenLDAPArgon2PasswordSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	source, err := os.ReadFile(filepath.Join(
		sourceRoot,
		"servers",
		"slapd",
		"pwmods",
		"argon2.c",
	))
	if err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []string{
		"#define SLAPD_ARGON2_ITERATIONS 5",
		"#define SLAPD_ARGON2_MEMORY 7168",
		"#define SLAPD_ARGON2_PARALLELISM 1",
		"#define SLAPD_ARGON2_SALT_LENGTH 16",
		"#define SLAPD_ARGON2_HASH_LENGTH 32",
		`BER_BVC("{ARGON2}")`,
		`strncmp( passwd->bv_val, "$argon2i$"`,
		`strncmp( passwd->bv_val, "$argon2d$"`,
		`strncmp( passwd->bv_val, "$argon2id$"`,
	} {
		if !strings.Contains(string(source), anchor) {
			t.Errorf("OpenLDAP argon2.c is missing %q", anchor)
		}
	}
}
