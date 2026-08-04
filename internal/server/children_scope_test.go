package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientChildrenScopeCoreBehavior(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindAliasRootClient(t, address)
	defer client.Close()

	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeChildren,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("children Search(): %v", err)
	}
	got := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		got = append(got, entry.DN)
	}
	slices.Sort(got)
	want := []string{
		"ou=archive,dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("children DNs = %q, want %q", got, want)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		"ou=missing,dc=example,dc=com",
		ldap.ScopeChildren,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultNoSuchObject ||
		ldapErr.MatchedDN != "dc=example,dc=com" {
		t.Fatalf("missing children Search() error = %#v, %v", ldapErr, err)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeChildren,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	ldapErr = nil
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultNoSuchObject ||
		ldapErr.MatchedDN != "" {
		t.Fatalf("empty-base children Search() error = %#v, %v", ldapErr, err)
	}
}

func TestLDAPClientChildrenScopeRequiresBaseSearchAccess(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		baseAccess string
		wantResult uint16
		wantCount  int
	}{
		{
			name:       "hidden",
			baseAccess: "none",
			wantResult: ldap.LDAPResultNoSuchObject,
		},
		{
			name:       "disclose only",
			baseAccess: "disclose",
			wantResult: ldap.LDAPResultInsufficientAccessRights,
		},
		{
			name:       "search",
			baseAccess: "search",
			wantCount:  3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			replaceChildrenScopeAccess(t, store, test.baseAccess)

			address, stop := startServer(t, store, Config{})
			defer stop()
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatalf("DialURL(): %v", err)
			}
			defer client.Close()

			result, err := client.Search(ldap.NewSearchRequest(
				"dc=example,dc=com",
				ldap.ScopeChildren,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"1.1"},
				nil,
			))
			if test.wantResult != ldap.LDAPResultSuccess {
				assertLDAPResultCode(t, err, test.wantResult)
				return
			}
			if err != nil {
				t.Fatalf("children Search(): %v", err)
			}
			if len(result.Entries) != test.wantCount {
				t.Fatalf("children entry count = %d, want %d", len(result.Entries), test.wantCount)
			}
		})
	}
}

func TestLDAPClientChildrenScopeAcrossSubordinateDatabases(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlueConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	request := func(base string) *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			base,
			ldap.ScopeChildren,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		)
	}
	assertSearch := func(base string, result *ldap.SearchResult, err error, want []string) {
		t.Helper()
		if err != nil {
			t.Fatalf("children Search(%q): %v", base, err)
		}
		got := make([]string, len(result.Entries))
		for index, entry := range result.Entries {
			got[index] = entry.DN
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("children Search(%q) DNs = %q, want %q", base, got, want)
		}
	}

	rootResult, err := client.Search(request("dc=example,dc=com"))
	rootWant := []string{
		"cn=core,ou=teams,ou=people,dc=example,dc=com",
		"cn=operators,ou=groups,dc=example,dc=com",
		"cn=router,ou=devices,dc=example,dc=com",
		"ou=devices,dc=example,dc=com",
		"ou=groups,dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"ou=teams,ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
	}
	assertSearch("dc=example,dc=com", rootResult, err, rootWant)

	peopleResult, err := client.Search(request("ou=people,dc=example,dc=com"))
	assertSearch("ou=people,dc=example,dc=com", peopleResult, err, []string{
		"cn=core,ou=teams,ou=people,dc=example,dc=com",
		"ou=teams,ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
	})

	paged, err := client.SearchWithPaging(request("dc=example,dc=com"), 2)
	assertSearch("dc=example,dc=com paged", paged, err, rootWant)
}

func TestLDAPClientChildrenScopeUsesDefaultSearchBase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				{Description: "olcDefaultSearchBase", Values: stringValues("dc=example,dc=com")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed default search base: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindAliasRootClient(t, address)
	defer client.Close()

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"namingContexts"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 || rootDSE.Entries[0].DN != "" {
		t.Fatalf("default-base Root DSE Search() = %#v, %v", rootDSE, err)
	}

	children, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeChildren,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("default-base children Search(): %v", err)
	}
	got := make([]string, len(children.Entries))
	for index, entry := range children.Entries {
		got[index] = entry.DN
	}
	slices.Sort(got)
	want := []string{
		"ou=archive,dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("default-base children DNs = %q, want %q", got, want)
	}
}

func replaceChildrenScopeAccess(t *testing.T, store storage.Store, baseAccess string) {
	t.Helper()
	dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatalf("ParseDN(database config): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			"{0}to dn.base=\"dc=example,dc=com\" by anonymous "+baseAccess+" by * read",
			"{1}to * by anonymous read by * read",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("replace children-scope ACL: %v", err)
	}
}
