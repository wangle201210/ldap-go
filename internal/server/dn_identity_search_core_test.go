package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	searchCoreExactOID = "1.3.6.1.4.1.99999.916.1"
	searchCoreFoldOID  = "1.3.6.1.4.1.99999.916.2"
	searchCoreSuffix   = "exactName=Tenant+foldName=Example"
	searchCorePeopleDN = "foldName=People," + searchCoreSuffix
	searchCoreTeamsDN  = "foldName=Teams," + searchCorePeopleDN
)

const searchCoreConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config
olcDefaultSearchBase: exactName=Tenant+foldName=Example

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}searchcore,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}searchcore
olcAttributeTypes: ( 1.3.6.1.4.1.99999.916.1 NAME ( 'exactName' 'exactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.916.2 NAME ( 'foldName' 'foldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcObjectClasses: ( 1.3.6.1.4.1.99999.916.3 NAME 'dnMultiAVAEntry' SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: exactName=Tenant+foldName=Example
olcAccess: {0}to * by * read

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: foldName=Teams,foldName=People,exactName=Tenant+foldName=Example
olcSubordinate: TRUE
olcAccess: {0}to * by * read

dn: olcDatabase={3}monitor,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMonitorConfig
olcDatabase: {3}monitor
olcAccess: {0}to * by * read

`

const searchCoreParentLDIF = `dn: exactName=Tenant+foldName=Example
objectClass: top
objectClass: dnMultiAVAEntry
cn: Search Root
exactName: Tenant
foldName: Example

dn: foldName=People,exactName=Tenant+foldName=Example
objectClass: top
objectClass: dnMultiAVAEntry
cn: People
foldName: People

dn: exactName=Alpha,foldName=People,exactName=Tenant+foldName=Example
objectClass: top
objectClass: dnMultiAVAEntry
cn: Exact Alpha
exactName: Alpha

dn: exactName=alpha,foldName=People,exactName=Tenant+foldName=Example
objectClass: top
objectClass: dnMultiAVAEntry
cn: Exact alpha
exactName: alpha

dn: cn=Grandchild,exactName=Alpha,foldName=People,exactName=Tenant+foldName=Example
objectClass: top
objectClass: organizationalRole
cn: Grandchild

`

const searchCoreChildLDIF = `dn: foldName=Teams,foldName=People,exactName=Tenant+foldName=Example
objectClass: top
objectClass: dnMultiAVAEntry
cn: Teams
foldName: Teams

dn: cn=Platform,foldName=Teams,foldName=People,exactName=Tenant+foldName=Example
objectClass: top
objectClass: organizationalRole
cn: Platform

`

func TestDNIdentitySearchCore(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			t.Helper()
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}

	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			client := startDNIdentitySearchCoreServer(t, backend.open(t))

			t.Run("request base identity and syntax", func(t *testing.T) {
				assertDNIdentitySearchCoreBaseEquivalence(t, client)
			})
			t.Run("scope and glue", func(t *testing.T) {
				assertDNIdentitySearchCoreScopes(t, client)
			})
			t.Run("paging", func(t *testing.T) {
				assertDNIdentitySearchCorePaging(t, client)
			})
			t.Run("default and fixed bases", func(t *testing.T) {
				assertDNIdentitySearchCoreFixedBases(t, client)
			})
		})
	}
}

func assertDNIdentitySearchCoreBaseEquivalence(t *testing.T, client *ldap.Conn) {
	t.Helper()
	equivalentRoot := searchCoreFoldOID +
		`=\20EXAMPLE\20+exactAlias=Tenant`
	assertDNIdentitySearchCoreDNs(
		t,
		searchDNIdentitySearchCore(t, client, equivalentRoot, ldap.ScopeBaseObject),
		[]string{searchCoreSuffix},
	)

	equivalentPeople := `foldAlias=\20PEOPLE\20,` + equivalentRoot
	assertDNIdentitySearchCoreDNs(
		t,
		searchDNIdentitySearchCore(t, client, equivalentPeople, ldap.ScopeBaseObject),
		[]string{searchCorePeopleDN},
	)

	exactUpper := "exactAlias=Alpha," + equivalentPeople
	assertDNIdentitySearchCoreDNs(
		t,
		searchDNIdentitySearchCore(t, client, exactUpper, ldap.ScopeBaseObject),
		[]string{"exactName=Alpha," + searchCorePeopleDN},
	)
	exactLower := "exactAlias=alpha," + equivalentPeople
	assertDNIdentitySearchCoreDNs(
		t,
		searchDNIdentitySearchCore(t, client, exactLower, ldap.ScopeBaseObject),
		[]string{"exactName=alpha," + searchCorePeopleDN},
	)

	duplicate := "exactAlias=Alpha+" + searchCoreExactOID +
		"=Alpha," + equivalentPeople
	_, err := client.Search(newDNIdentitySearchCoreRequest(
		duplicate,
		ldap.ScopeBaseObject,
	))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultInvalidDNSyntax {
		t.Fatalf("duplicate alias/OID Search() = %v, want invalidDNSyntax", err)
	}
}

func assertDNIdentitySearchCoreScopes(t *testing.T, client *ldap.Conn) {
	t.Helper()
	equivalentPeople := `foldAlias=PEOPLE,` + searchCoreFoldOID +
		"=example+exactAlias=Tenant"
	tests := []struct {
		name  string
		scope int
		want  []string
	}{
		{name: "base", scope: ldap.ScopeBaseObject, want: []string{
			searchCorePeopleDN,
		}},
		{name: "one", scope: ldap.ScopeSingleLevel, want: []string{
			"exactName=Alpha," + searchCorePeopleDN,
			"exactName=alpha," + searchCorePeopleDN,
			searchCoreTeamsDN,
		}},
		{name: "subtree", scope: ldap.ScopeWholeSubtree, want: []string{
			searchCorePeopleDN,
			"exactName=Alpha," + searchCorePeopleDN,
			"exactName=alpha," + searchCorePeopleDN,
			"cn=Grandchild,exactName=Alpha," + searchCorePeopleDN,
			searchCoreTeamsDN,
			"cn=Platform," + searchCoreTeamsDN,
		}},
		{name: "children", scope: ldap.ScopeChildren, want: []string{
			"exactName=Alpha," + searchCorePeopleDN,
			"exactName=alpha," + searchCorePeopleDN,
			"cn=Grandchild,exactName=Alpha," + searchCorePeopleDN,
			searchCoreTeamsDN,
			"cn=Platform," + searchCoreTeamsDN,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertDNIdentitySearchCoreDNs(
				t,
				searchDNIdentitySearchCore(t, client, equivalentPeople, test.scope),
				test.want,
			)
		})
	}
}

func assertDNIdentitySearchCorePaging(t *testing.T, client *ldap.Conn) {
	t.Helper()
	request := newDNIdentitySearchCoreRequest(
		`foldAlias=people,foldAlias=example+exactAlias=Tenant`,
		ldap.ScopeWholeSubtree,
	)
	result, err := client.SearchWithPaging(request, 1)
	if err != nil {
		t.Fatalf("SearchWithPaging(): %v", err)
	}
	assertDNIdentitySearchCoreDNs(t, result, []string{
		searchCorePeopleDN,
		"exactName=Alpha," + searchCorePeopleDN,
		"exactName=alpha," + searchCorePeopleDN,
		"cn=Grandchild,exactName=Alpha," + searchCorePeopleDN,
		searchCoreTeamsDN,
		"cn=Platform," + searchCoreTeamsDN,
	})
}

func assertDNIdentitySearchCoreFixedBases(t *testing.T, client *ldap.Conn) {
	t.Helper()
	defaultResult := searchDNIdentitySearchCore(t, client, "", ldap.ScopeWholeSubtree)
	if len(defaultResult.Entries) != 7 {
		t.Fatalf("default-base Search() returned %d entries, want 7", len(defaultResult.Entries))
	}
	assertDNIdentitySearchCoreCount(t, client, "", ldap.ScopeBaseObject, 1)
	assertDNIdentitySearchCoreCount(t, client, "CN=SUBSCHEMA", ldap.ScopeBaseObject, 1)
	assertDNIdentitySearchCoreCount(t, client, "CN=MONITOR", ldap.ScopeBaseObject, 1)
}

func assertDNIdentitySearchCoreCount(
	t *testing.T,
	client *ldap.Conn,
	base string,
	scope int,
	want int,
) {
	t.Helper()
	result := searchDNIdentitySearchCore(t, client, base, scope)
	if len(result.Entries) != want {
		t.Fatalf("Search(base=%q, scope=%d) returned %d entries, want %d", base, scope, len(result.Entries), want)
	}
}

func searchDNIdentitySearchCore(
	t *testing.T,
	client *ldap.Conn,
	base string,
	scope int,
) *ldap.SearchResult {
	t.Helper()
	result, err := client.Search(newDNIdentitySearchCoreRequest(base, scope))
	if err != nil {
		t.Fatalf("Search(base=%q, scope=%d): %v", base, scope, err)
	}
	return result
}

func newDNIdentitySearchCoreRequest(base string, scope int) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	)
}

func assertDNIdentitySearchCoreDNs(
	t *testing.T,
	result *ldap.SearchResult,
	want []string,
) {
	t.Helper()
	got := make([]string, len(result.Entries))
	for index, entry := range result.Entries {
		got[index] = entry.DN
	}
	slices.Sort(got)
	want = slices.Clone(want)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("Search DNs = %q, want %q", got, want)
	}
}

func startDNIdentitySearchCoreServer(
	t *testing.T,
	store storage.Store,
) *ldap.Conn {
	t.Helper()
	t.Cleanup(func() { _ = store.Close() })
	imports := []struct {
		database string
		ldif     string
		skip     bool
	}{
		{database: "0", ldif: searchCoreConfigLDIF, skip: true},
		{database: "1", ldif: searchCoreParentLDIF},
		{database: "2", ldif: searchCoreChildLDIF},
	}
	for _, imported := range imports {
		if _, err := migration.ImportLDIF(
			context.Background(),
			store,
			strings.NewReader(imported.ldif),
			migration.ImportOptions{
				Database:             imported.database,
				Replace:              true,
				SkipSchemaValidation: imported.skip,
			},
		); err != nil {
			t.Fatalf("ImportLDIF(database=%s): %v", imported.database, err)
		}
	}
	address, stop := startDNIdentitySearchCoreListener(t, store)
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func startDNIdentitySearchCoreListener(
	t *testing.T,
	store storage.Store,
) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
	return fmt.Sprint(listener.Addr()), stop
}
