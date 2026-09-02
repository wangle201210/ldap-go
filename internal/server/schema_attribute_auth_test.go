package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPasswordAuthenticationResolvesAttributeOID(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLPlainConfiguration(t, store, "none")
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		for index := range entry.Attributes {
			if entry.Attributes[index].Description == "userPassword" {
				entry.Attributes[index].Description = "2.5.4.35"
			}
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		_ = client.Close()
		t.Fatalf("simple Bind with password OID: %v", err)
	}
	_ = client.Close()

	raw, err := dialAndBindSASLPlain(address, "", "alice", "secret")
	if err != nil {
		t.Fatalf("PLAIN Bind with password OID: %v", err)
	}
	_ = raw.Close()
}

func TestLDAPWritesUseSchemaAttributeAndValueEquality(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("root-secret"),
	})
	defer stop()
	root, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Bind("cn=admin,dc=example,dc=com", "root-secret"); err != nil {
		t.Fatal(err)
	}

	duplicate := newPersonAddRequest("duplicate-alias")
	duplicate.Attribute("2.5.4.3", []string{"Alias CN"})
	assertLDAPResultCode(
		t,
		root.Add(duplicate),
		ldap.LDAPResultAttributeOrValueExists,
	)

	passwords := newPersonAddRequest("case-password")
	passwords.Attribute("userPassword", []string{"Secret", "secret"})
	if err := root.Add(passwords); err != nil {
		t.Fatalf("add case-distinct octetStringMatch values: %v", err)
	}
	passwordDN := "uid=case-password,ou=people,dc=example,dc=com"
	for _, password := range []string{"Secret", "secret"} {
		client, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Bind(passwordDN, password); err != nil {
			_ = client.Close()
			t.Fatalf("Bind(%q): %v", password, err)
		}
		_ = client.Close()
	}

	duplicateCN := ldap.NewModifyRequest(passwordDN, nil)
	duplicateCN.Add("2.5.4.3", []string{"TEST USER"})
	assertLDAPResultCode(
		t,
		root.Modify(duplicateCN),
		ldap.LDAPResultAttributeOrValueExists,
	)
	replaceCN := ldap.NewModifyRequest(passwordDN, nil)
	replaceCN.Replace("2.5.4.3", []string{"Alias Replaced"})
	if err := root.Modify(replaceCN); err != nil {
		t.Fatalf("replace cn through OID: %v", err)
	}
	matched, err := root.Compare(passwordDN, "cn", "ALIAS REPLACED")
	if err != nil || !matched {
		t.Fatalf("Compare(cn after OID replace) = %v, %v", matched, err)
	}
}
