package server

import (
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestBitStringIndexedPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bits.db")
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{DN: "cn={9}bits,cn=schema,cn=config", Attributes: []directory.Attribute{
			{Description: "olcAttributeTypes", Values: stringValues("( 1.3.6.1.4.1.99999.933.1 NAME 'testBits' EQUALITY 2.5.13.16 SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )")},
			{Description: "olcObjectClasses", Values: stringValues("( 1.3.6.1.4.1.99999.933.2 NAME 'bitsAux' SUP top AUXILIARY MAY testBits )")},
		}}, false); err != nil {
			return err
		}
		dn, _ := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		config, err := writer.Get(dn)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcDbIndex", stringValues("testBits eq"))
		return writer.Put(config, true)
	}); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		t.Run([]string{"initial", "reopened"}[round], func(t *testing.T) {
			address, stop := startServer(t, store, Config{RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("admin-secret")})
			defer stop()
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
				t.Fatal(err)
			}
			if round == 0 {
				modify := ldap.NewModifyRequest(aliceDN, nil)
				modify.Add("objectClass", []string{"bitsAux"})
				modify.Add("testBits", []string{"'001'B", "''B"})
				if err := client.Modify(modify); err != nil {
					t.Fatal(err)
				}
			}
			for value, want := range map[string]int{"'001'B": 1, "'01'B": 0, "''B": 1, "'1'B": 0} {
				result, err := client.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(testBits="+value+")", []string{"testBits"}, nil))
				if err != nil || len(result.Entries) != want {
					t.Fatalf("bit search %q: %+v %v", value, result, err)
				}
				matched, err := client.Compare(aliceDN, "testBits", value)
				if err != nil || matched != (want == 1) {
					t.Fatalf("bit Compare %q: %v %v", value, matched, err)
				}
			}
			if _, err := client.Compare(aliceDN, "testBits", "'012'B"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidAttributeSyntax) {
				t.Fatalf("invalid assertion: %v", err)
			}
			modify := ldap.NewModifyRequest(aliceDN, nil)
			modify.Replace("testBits", []string{"'01'b"})
			if err := client.Modify(modify); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidAttributeSyntax) {
				t.Fatalf("invalid write: %v", err)
			}
		})
		if round == 0 {
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = storage.OpenBolt(path)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
