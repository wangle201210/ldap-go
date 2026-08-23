package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const dnIdentityRuntimeConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}dnidentity,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}dnidentity
olcAttributeTypes: ( 1.3.6.1.4.1.99999.914.1 NAME 'exactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.914.2 NAME 'foldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.914.3 NAME 'dnIdentityRuntimeEntry' SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=admin,dc=example,dc=com
olcRootPW: admin-secret

`

const dnIdentityRuntimeContentLDIF = `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: exactName=Alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityRuntimeEntry
cn: Exact Upper
exactName: Alice

dn: exactName=alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityRuntimeEntry
cn: Exact Lower
exactName: alice

dn: foldName=Alice Smith,dc=example,dc=com
objectClass: top
objectClass: dnIdentityRuntimeEntry
cn: Folded Name
foldName: Alice Smith
`

func TestDNIdentityRuntimeOpenLDAPSemantics(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) storage.Store {
				t.Helper()
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}
	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			testDNIdentityRuntimeOpenLDAPSemantics(t, backend.open)
		})
	}
}

func testDNIdentityRuntimeOpenLDAPSemantics(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	t.Run("caseExact base searches remain distinct", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)

		t.Run("upper-case value", func(t *testing.T) {
			upper := searchDNIdentityRuntimeBase(
				t,
				client,
				"exactName=Alice,dc=example,dc=com",
			)
			assertDNIdentityRuntimeAttribute(t, upper, "exactName", "Alice")
			assertDNIdentityRuntimeAttribute(t, upper, "cn", "Exact Upper")
		})

		t.Run("lower-case value", func(t *testing.T) {
			lower := searchDNIdentityRuntimeBase(
				t,
				client,
				"exactName=alice,dc=example,dc=com",
			)
			assertDNIdentityRuntimeAttribute(t, lower, "exactName", "alice")
			assertDNIdentityRuntimeAttribute(t, lower, "cn", "Exact Lower")
		})
	})

	t.Run("caseIgnore base and compare use normalized DN identity", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		const equivalentDN = "foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM"

		t.Run("base search", func(t *testing.T) {
			entry := searchDNIdentityRuntimeBase(t, client, equivalentDN)
			assertDNIdentityRuntimeAttribute(t, entry, "foldName", "Alice Smith")
			assertDNIdentityRuntimeAttribute(t, entry, "cn", "Folded Name")
		})

		t.Run("compare", func(t *testing.T) {
			matched, err := client.Compare(equivalentDN, "foldName", " alice   SMITH ")
			if err != nil {
				t.Fatalf("Compare(caseIgnore equivalent DN): %v", err)
			}
			if !matched {
				t.Fatal("Compare(caseIgnore equivalent DN) = false, want true")
			}
		})
	})

	t.Run("caseExact add accepts a distinct case", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		request := newDNIdentityRuntimeAdd(
			"exactName=ALICE,dc=example,dc=com",
			"exactName",
			"ALICE",
			"Exact All Caps",
		)
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(caseExact distinct case): %v", err)
		}
	})

	t.Run("caseExact add rejects a space-equivalent duplicate", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		request := newDNIdentityRuntimeAdd(
			"exactName=\\20Alice\\20,dc=example,dc=com",
			"exactName",
			" Alice ",
			"Exact Space Duplicate",
		)
		assertDNIdentityRuntimeResultCode(
			t,
			client.Add(request),
			ldap.LDAPResultEntryAlreadyExists,
		)
	})

	t.Run("caseIgnore add rejects a case-and-space-equivalent duplicate", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		request := newDNIdentityRuntimeAdd(
			"foldName=\\20ALICE\\20\\20SMITH\\20,dc=example,dc=com",
			"foldName",
			" ALICE  SMITH ",
			"Folded Duplicate",
		)
		assertDNIdentityRuntimeResultCode(
			t,
			client.Add(request),
			ldap.LDAPResultEntryAlreadyExists,
		)
	})

	t.Run("delete removes only the selected caseExact entry", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		const upperDN = "exactName=Alice,dc=example,dc=com"
		const lowerDN = "exactName=alice,dc=example,dc=com"

		if err := client.Del(ldap.NewDelRequest(upperDN, nil)); err != nil {
			t.Fatalf("Delete(%s): %v", upperDN, err)
		}
		_, err := client.Search(newDNIdentityRuntimeBaseSearch(upperDN))
		assertDNIdentityRuntimeResultCode(t, err, ldap.LDAPResultNoSuchObject)

		lower := searchDNIdentityRuntimeBase(t, client, lowerDN)
		assertDNIdentityRuntimeAttribute(t, lower, "exactName", "alice")
		assertDNIdentityRuntimeAttribute(t, lower, "cn", "Exact Lower")
	})
}

func startDNIdentityRuntimeServer(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) *ldap.Conn {
	t.Helper()

	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dnIdentityRuntimeConfigLDIF),
		migration.ImportOptions{
			Database:             "0",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(cn=config): %v", err)
	}
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dnIdentityRuntimeContentLDIF),
		migration.ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(content): %v", err)
	}

	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(root): %v", err)
	}
	return client
}

func newDNIdentityRuntimeBaseSearch(dn string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "exactName", "foldName"},
		nil,
	)
}

func searchDNIdentityRuntimeBase(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) *ldap.Entry {
	t.Helper()
	result, err := client.Search(newDNIdentityRuntimeBaseSearch(dn))
	if err != nil {
		t.Fatalf("Search(base=%q): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(base=%q) returned %d entries, want 1", dn, len(result.Entries))
	}
	return result.Entries[0]
}

func assertDNIdentityRuntimeAttribute(
	t *testing.T,
	entry *ldap.Entry,
	attribute string,
	want string,
) {
	t.Helper()
	if got := entry.GetAttributeValues(attribute); len(got) != 1 || got[0] != want {
		t.Fatalf("%s on %q = %q, want [%q]", attribute, entry.DN, got, want)
	}
}

func newDNIdentityRuntimeAdd(
	dn string,
	namingAttribute string,
	namingValue string,
	commonName string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"top", "dnIdentityRuntimeEntry"})
	request.Attribute("cn", []string{commonName})
	request.Attribute(namingAttribute, []string{namingValue})
	return request
}

func assertDNIdentityRuntimeResultCode(t *testing.T, err error, want uint16) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != want {
		t.Fatalf("LDAP error = %v, want result code %d", err, want)
	}
}
