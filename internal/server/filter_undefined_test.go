package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPSearchTreatsUnavailableMatchingRulesAsUndefined(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("root-secret"),
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "root-secret"); err != nil {
		t.Fatal(err)
	}
	for _, filter := range []string{
		"(cn>=A)",
		"(userPassword=*sec*)",
		"(!(userPassword=*sec*))",
		"(cn:1.2.3:=Alice Example)",
	} {
		result, err := client.Search(ldap.NewSearchRequest(
			"uid=alice,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"dn"},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(%s): %v", filter, err)
		}
		if len(result.Entries) != 0 {
			t.Fatalf("Search(%s) returned %d entries, want undefined/non-match", filter, len(result.Entries))
		}
	}
}

func TestLDAPSearchExtensibleDNAttributesUsesAncestorRDNs(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("root-secret"),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "root-secret"); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		filter string
		want   int
	}{
		{filter: "(ou:dn:caseIgnoreMatch:=people)", want: 1},
		{filter: "(:dn:caseIgnoreMatch:=people)", want: 1},
		{filter: "(ou:caseIgnoreMatch:=people)", want: 0},
	} {
		result, err := client.Search(ldap.NewSearchRequest(
			"uid=alice,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			test.filter,
			[]string{"1.1"},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(%s): %v", test.filter, err)
		}
		if len(result.Entries) != test.want {
			t.Fatalf("Search(%s) entries = %d, want %d", test.filter, len(result.Entries), test.want)
		}
	}
}
