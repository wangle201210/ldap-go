package server

import (
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityRuntimeCoreWriteSemantics(t *testing.T) {
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
			testDNIdentityRuntimeCoreWriteSemantics(t, backend.open)
		})
	}
}

func testDNIdentityRuntimeCoreWriteSemantics(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	const (
		baseDN  = "dc=example,dc=com"
		upperDN = "exactName=Alice," + baseDN
		lowerDN = "exactName=alice," + baseDN
	)

	t.Run("ModifyDN keeps a caseExact sibling distinct", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		const renamedDN = "exactName=Upper Renamed," + baseDN

		if err := client.ModifyDN(ldap.NewModifyDNRequest(
			upperDN,
			"exactName=Upper Renamed",
			true,
			"",
		)); err != nil {
			t.Fatalf("ModifyDN(%q): %v", upperDN, err)
		}

		upper := requireDNIdentityRuntimeEntryByCN(t, client, "Exact Upper")
		assertDNIdentityRuntimeEntryDN(t, upper, renamedDN)
		assertDNIdentityRuntimeAttribute(t, upper, "exactName", "Upper Renamed")

		lower := requireDNIdentityRuntimeEntryByCN(t, client, "Exact Lower")
		assertDNIdentityRuntimeEntryDN(t, lower, lowerDN)
		assertDNIdentityRuntimeAttribute(t, lower, "exactName", "alice")
	})

	t.Run("subtree ModifyDN moves only true caseExact descendants", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		const (
			destinationDN     = "cn=destination," + baseDN
			upperChildDN      = "cn=Upper Child," + upperDN
			lowerChildDN      = "cn=Lower Child," + lowerDN
			movedUpperDN      = "exactName=Alice," + destinationDN
			movedUpperChildDN = "cn=Upper Child," + movedUpperDN
		)

		addDNIdentityRuntimeEntry(t, client, destinationDN, "destination")
		addDNIdentityRuntimeEntry(t, client, upperChildDN, "Upper Child")
		addDNIdentityRuntimeEntry(t, client, lowerChildDN, "Lower Child")

		if err := client.ModifyDN(ldap.NewModifyDNRequest(
			upperDN,
			"exactName=Alice",
			true,
			destinationDN,
		)); err != nil {
			t.Fatalf("ModifyDN(subtree %q): %v", upperDN, err)
		}

		upper := requireDNIdentityRuntimeEntryByCN(t, client, "Exact Upper")
		assertDNIdentityRuntimeEntryDN(t, upper, movedUpperDN)
		upperChild := requireDNIdentityRuntimeEntryByCN(t, client, "Upper Child")
		assertDNIdentityRuntimeEntryDN(t, upperChild, movedUpperChildDN)

		lower := requireDNIdentityRuntimeEntryByCN(t, client, "Exact Lower")
		assertDNIdentityRuntimeEntryDN(t, lower, lowerDN)
		lowerChild := requireDNIdentityRuntimeEntryByCN(t, client, "Lower Child")
		assertDNIdentityRuntimeEntryDN(t, lowerChild, lowerChildDN)
	})

	t.Run("non-leaf detection does not merge caseExact siblings", func(t *testing.T) {
		client := startDNIdentityRuntimeServer(t, openStore)
		const upperChildDN = "cn=Upper Child," + upperDN
		addDNIdentityRuntimeEntry(t, client, upperChildDN, "Upper Child")

		if err := client.Del(ldap.NewDelRequest(lowerDN, nil)); err != nil {
			t.Fatalf("Delete(caseExact leaf %q): %v", lowerDN, err)
		}
		if entries := searchDNIdentityRuntimeEntriesByCN(t, client, "Exact Lower"); len(entries) != 0 {
			t.Fatalf("deleted caseExact sibling still visible: %#v", entries)
		}

		assertDNIdentityRuntimeResultCode(
			t,
			client.Del(ldap.NewDelRequest(upperDN, nil)),
			ldap.LDAPResultNotAllowedOnNonLeaf,
		)
		upper := requireDNIdentityRuntimeEntryByCN(t, client, "Exact Upper")
		assertDNIdentityRuntimeEntryDN(t, upper, upperDN)
		child := requireDNIdentityRuntimeEntryByCN(t, client, "Upper Child")
		assertDNIdentityRuntimeEntryDN(t, child, upperChildDN)
	})

	t.Run("caseIgnore equivalent source DN can be renamed and deleted", func(t *testing.T) {
		const equivalentSourceDN = "foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM"

		t.Run("rename", func(t *testing.T) {
			client := startDNIdentityRuntimeServer(t, openStore)
			const renamedDN = "foldName=Renamed User," + baseDN
			if err := client.ModifyDN(ldap.NewModifyDNRequest(
				equivalentSourceDN,
				"foldName=Renamed User",
				true,
				"",
			)); err != nil {
				t.Fatalf("ModifyDN(caseIgnore equivalent source %q): %v", equivalentSourceDN, err)
			}
			renamed := requireDNIdentityRuntimeEntryByCN(t, client, "Folded Name")
			assertDNIdentityRuntimeEntryDN(t, renamed, renamedDN)
			assertDNIdentityRuntimeAttribute(t, renamed, "foldName", "Renamed User")
		})

		t.Run("delete", func(t *testing.T) {
			client := startDNIdentityRuntimeServer(t, openStore)
			if err := client.Del(ldap.NewDelRequest(equivalentSourceDN, nil)); err != nil {
				t.Fatalf("Delete(caseIgnore equivalent DN %q): %v", equivalentSourceDN, err)
			}
			if entries := searchDNIdentityRuntimeEntriesByCN(t, client, "Folded Name"); len(entries) != 0 {
				t.Fatalf("deleted caseIgnore entry still visible: %#v", entries)
			}
		})
	})
}

func addDNIdentityRuntimeEntry(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	commonName string,
) {
	t.Helper()
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"top", "dnIdentityRuntimeEntry"})
	request.Attribute("cn", []string{commonName})
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(%q): %v", dn, err)
	}
}

func requireDNIdentityRuntimeEntryByCN(
	t *testing.T,
	client *ldap.Conn,
	commonName string,
) *ldap.Entry {
	t.Helper()
	entries := searchDNIdentityRuntimeEntriesByCN(t, client, commonName)
	if len(entries) != 1 {
		t.Fatalf("Search(cn=%q) returned %d entries, want 1", commonName, len(entries))
	}
	return entries[0]
}

func searchDNIdentityRuntimeEntriesByCN(
	t *testing.T,
	client *ldap.Conn,
	commonName string,
) []*ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(cn="+ldap.EscapeFilter(commonName)+")",
		[]string{"cn", "exactName", "foldName"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(cn=%q): %v", commonName, err)
	}
	return result.Entries
}

func assertDNIdentityRuntimeEntryDN(t *testing.T, entry *ldap.Entry, want string) {
	t.Helper()
	if entry.DN != want {
		t.Fatalf("entry DN = %q, want %q", entry.DN, want)
	}
}
