package server

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityCoreWritePaths(t *testing.T) {
	for _, backend := range dnIdentityCoreWriteBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Run("add modify and delete preserve schema identity", func(t *testing.T) {
				client := startDNMultiAVALocalServer(t, backend.open)
				const (
					canonicalDN = "exactName=Carol+foldName=Platform,dc=example,dc=com"
					lookupDN    = "foldName=PLATFORM+" + dnMultiAVAExactOID + "=Carol,DC=EXAMPLE,DC=COM"
				)

				add := newDNMultiAVAAdd(
					"foldAlias=Platform+exactAlias=Carol,dc=example,dc=com",
					"Core Write",
					map[string][]string{
						"exactAlias": {"Carol"},
						"foldAlias":  {"Platform"},
					},
				)
				if err := client.Add(add); err != nil {
					t.Fatalf("Add(alias multi-AVA): %v", err)
				}
				entry := searchDNIdentityCoreWriteBase(t, client, lookupDN)
				if entry.DN != canonicalDN {
					t.Fatalf("canonical Add DN = %q, want %q", entry.DN, canonicalDN)
				}

				modify := ldap.NewModifyRequest(lookupDN, nil)
				modify.Replace("cn", []string{"Core Write Modified"})
				if err := client.Modify(modify); err != nil {
					t.Fatalf("Modify(equivalent alias/OID DN): %v", err)
				}
				entry = searchDNIdentityCoreWriteBase(t, client, canonicalDN)
				assertDNIdentityRuntimeAttribute(t, entry, "cn", "Core Write Modified")

				duplicate := newDNMultiAVAAdd(
					"exactName=Carol+foldName=platform,dc=example,dc=com",
					"Equivalent Duplicate",
					map[string][]string{
						"exactName": {"Carol"},
						"foldName":  {"platform"},
					},
				)
				assertDNIdentityRuntimeResultCode(
					t,
					client.Add(duplicate),
					ldap.LDAPResultEntryAlreadyExists,
				)

				if err := client.Del(ldap.NewDelRequest(lookupDN, nil)); err != nil {
					t.Fatalf("Delete(equivalent alias/OID DN): %v", err)
				}
				_, err := client.Search(newDNIdentityRuntimeBaseSearch(canonicalDN))
				assertDNIdentityRuntimeResultCode(t, err, ldap.LDAPResultNoSuchObject)
			})

			t.Run("caseExact siblings stay isolated", func(t *testing.T) {
				client := startDNMultiAVALocalServer(t, backend.open)
				const (
					upperDN = "exactName=Alice+foldName=Engineering,dc=example,dc=com"
					lowerDN = "exactName=alice+foldName=engineering,dc=example,dc=com"
				)

				modify := ldap.NewModifyRequest(upperDN, nil)
				modify.Replace("cn", []string{"Exact Upper Modified"})
				if err := client.Modify(modify); err != nil {
					t.Fatalf("Modify(caseExact upper): %v", err)
				}
				assertDNIdentityRuntimeAttribute(
					t,
					searchDNIdentityCoreWriteBase(t, client, lowerDN),
					"cn",
					"Exact Lower",
				)

				if err := client.Del(ldap.NewDelRequest(upperDN, nil)); err != nil {
					t.Fatalf("Delete(caseExact upper): %v", err)
				}
				assertDNIdentityRuntimeAttribute(
					t,
					searchDNIdentityCoreWriteBase(t, client, lowerDN),
					"cn",
					"Exact Lower",
				)
			})

			t.Run("subtree modifyDN moves only matching identity", func(t *testing.T) {
				client := startDNMultiAVALocalServer(t, backend.open)
				const (
					upperDN         = "exactName=Alice+foldName=Engineering,dc=example,dc=com"
					lowerDN         = "exactName=alice+foldName=engineering,dc=example,dc=com"
					upperChildDN    = "cn=Upper Child," + upperDN
					lowerChildDN    = "cn=Lower Child," + lowerDN
					destinationDN   = "cn=destination,dc=example,dc=com"
					movedUpperDN    = "exactName=Alice+foldName=ENGINEERING," + destinationDN
					movedUpperChild = "cn=Upper Child," + movedUpperDN
				)

				addDNIdentityCoreWriteEntry(t, client, destinationDN, "destination")
				addDNIdentityCoreWriteEntry(t, client, upperChildDN, "Upper Child")
				addDNIdentityCoreWriteEntry(t, client, lowerChildDN, "Lower Child")

				if err := client.ModifyDN(ldap.NewModifyDNRequest(
					"foldAlias=engineering+"+dnMultiAVAExactOID+"=Alice,dc=example,dc=com",
					"foldAlias=ENGINEERING+"+dnMultiAVAExactOID+"=Alice",
					true,
					"cn=destination,DC=EXAMPLE,DC=COM",
				)); err != nil {
					t.Fatalf("ModifyDN(schema-equivalent subtree): %v", err)
				}

				searchDNIdentityCoreWriteBase(t, client, movedUpperDN)
				searchDNIdentityCoreWriteBase(t, client, movedUpperChild)
				searchDNIdentityCoreWriteBase(t, client, lowerDN)
				searchDNIdentityCoreWriteBase(t, client, lowerChildDN)
			})

			t.Run("modifyDN reports OpenLDAP-compatible errors", func(t *testing.T) {
				client := startDNMultiAVALocalServer(t, backend.open)
				const (
					upperDN      = "exactName=Alice+foldName=Engineering,dc=example,dc=com"
					upperChildDN = "cn=Upper Child," + upperDN
				)
				addDNIdentityCoreWriteEntry(t, client, upperChildDN, "Upper Child")

				invalidAdd := newDNMultiAVAAdd(
					"exactAlias=One+"+dnMultiAVAExactOID+"=Two+foldName=three,dc=example,dc=com",
					"Invalid Add",
					map[string][]string{
						"exactAlias":       {"One"},
						dnMultiAVAExactOID: {"Two"},
						"foldName":         {"three"},
					},
				)
				assertDNIdentityRuntimeResultCode(
					t,
					client.Add(invalidAdd),
					ldap.LDAPResultInvalidDNSyntax,
				)

				assertDNIdentityRuntimeResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(
					upperDN,
					"exactAlias=One+"+dnMultiAVAExactOID+"=Two+foldName=three",
					true,
					"",
				)), ldap.LDAPResultInvalidDNSyntax)

				assertDNIdentityRuntimeResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(
					upperDN,
					"foldAlias=ENGINEERING+"+dnMultiAVAExactOID+"=Alice",
					true,
					"",
				)), ldap.LDAPResultEntryAlreadyExists)

				assertDNIdentityRuntimeResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(
					upperDN,
					"exactName=Alice+foldName=Engineering",
					true,
					upperChildDN,
				)), ldap.LDAPResultLoopDetect)

				assertDNIdentityRuntimeResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(
					upperDN,
					"exactName=Alice+foldName=Engineering",
					true,
					"dc=outside,dc=com",
				)), ldap.LDAPResultAffectsMultipleDSAs)

				assertDNIdentityRuntimeResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(
					upperDN,
					"exactName=Alice+foldName=Engineering",
					true,
					"cn=missing,dc=example,dc=com",
				)), ldap.LDAPResultNoSuchObject)
			})

			t.Run("naming contexts keep caseExact roots distinct", func(t *testing.T) {
				testDNIdentityCoreWriteNamingContexts(t, backend.open)
			})
		})
	}
}

type dnIdentityCoreWriteBackend struct {
	name string
	open func(*testing.T) storage.Store
}

func dnIdentityCoreWriteBackends() []dnIdentityCoreWriteBackend {
	return []dnIdentityCoreWriteBackend{
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
}

func addDNIdentityCoreWriteEntry(
	t *testing.T,
	client *ldap.Conn,
	dn,
	commonName string,
) {
	t.Helper()
	request := newDNMultiAVAAdd(dn, commonName, nil)
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(%q): %v", dn, err)
	}
}

func searchDNIdentityCoreWriteBase(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(base=%q): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(base=%q) returned %d entries, want 1", dn, len(result.Entries))
	}
	return result.Entries[0]
}

func testDNIdentityCoreWriteNamingContexts(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	t.Helper()
	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	registry := newDNMultiAVARegistry(t)
	runtime := &runtimeState{schema: registry}

	err := store.Update(context.Background(), func(writer storage.Writer) error {
		for index, rawDN := range []string{"exactName=Root", "exactName=root"} {
			partition := storage.OpenLDAPDatabasePartition(
				"{"+string(rune('1'+index))+"}mdb",
				nil,
			)
			partitionWriter := storage.WriterInPartitionWithNormalizer(
				writer,
				partition,
				registry,
			)
			if err := partitionWriter.Put(directory.Entry{
				DN: rawDN,
				Attributes: []directory.Attribute{{
					Description: "exactName",
					Values:      [][]byte{[]byte(rawDN[len("exactName="):])},
				}},
			}, false); err != nil {
				return err
			}
		}
		return refreshRuntimeNamingContexts(writer, runtime)
	})
	if err != nil {
		t.Fatalf("refreshRuntimeNamingContexts(): %v", err)
	}

	err = store.View(context.Background(), func(reader storage.Reader) error {
		contexts, err := reader.NamingContexts()
		if err != nil {
			return err
		}
		sort.Strings(contexts)
		want := []string{"exactName=Root", "exactName=root"}
		if len(contexts) != len(want) {
			t.Fatalf("NamingContexts() = %q, want %q", contexts, want)
		}
		for index := range want {
			if contexts[index] != want[index] {
				t.Fatalf("NamingContexts() = %q, want %q", contexts, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read NamingContexts(): %v", err)
	}
}
