package server

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityOnlineWriteMigratesLateLegacyEntry(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			t.Helper()
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}

	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)

			const databaseConfigDN = "olcDatabase={1}mdb,cn=config"
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				dn, err := directory.ParseDN(databaseConfigDN)
				if err != nil {
					return err
				}
				entry, err := writer.Get(dn)
				if err != nil {
					return err
				}
				entry.ReplaceValues("olcDbIndex", stringValues("uid eq"))
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatalf("configure equality index: %v", err)
			}

			registry, err := schema.NewBuiltinRegistry()
			if err != nil {
				t.Fatalf("NewBuiltinRegistry(): %v", err)
			}
			indexNormalizer, _, err := loadDatabaseEqualityIndexes(directory.Entry{
				DN: databaseConfigDN,
				Attributes: []directory.Attribute{{
					Description: "olcDbIndex",
					Values:      stringValues("uid eq"),
				}},
			}, registry)
			if err != nil {
				t.Fatalf("loadDatabaseEqualityIndexes(): %v", err)
			}

			address, stop := startServer(t, store, Config{
				RootDN:              "cn=admin,dc=example,dc=com",
				RootPassword:        []byte("admin-secret"),
				MaxSearchCandidates: 1,
			})
			t.Cleanup(stop)
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatalf("DialURL(): %v", err)
			}
			defer client.Close()
			if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
				t.Fatalf("root Bind(): %v", err)
			}
			assertDNIdentityIndexedSearch(t, client, "alice", "uid=alice,ou=people,dc=example,dc=com")

			const (
				legacyDN = "uid=legacy,ou=people,dc=example,dc=com"
				onlineDN = "uid=online,ou=people,dc=example,dc=com"
			)
			partition := configuredDatabasePartition("{1}mdb")
			legacyEntry := directory.Entry{
				DN: legacyDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("legacy")},
					{Description: "cn", Values: stringValues("Legacy User")},
					{Description: "sn", Values: stringValues("User")},
				},
			}
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				return writer.PutIn(partition, legacyEntry, false)
			}); err != nil {
				t.Fatalf("inject legacy PutIn entry: %v", err)
			}

			legacyParsed, err := directory.ParseDN(legacyDN)
			if err != nil {
				t.Fatalf("ParseDN(%q): %v", legacyDN, err)
			}
			err = store.View(context.Background(), func(reader storage.Reader) error {
				_, err := storage.ReaderInPartitionWithNormalizer(
					reader,
					partition,
					indexNormalizer,
				).Get(legacyParsed)
				return err
			})
			if !errors.Is(err, storage.ErrDNIdentityMigrationRequired) {
				t.Fatalf("schema-aware read after raw PutIn = %v, want ErrDNIdentityMigrationRequired", err)
			}

			assertDNIdentityIndexedSearch(t, client, "legacy", legacyDN)

			add := ldap.NewAddRequest(onlineDN, nil)
			add.Attribute("objectClass", []string{"inetOrgPerson"})
			add.Attribute("uid", []string{"online"})
			add.Attribute("cn", []string{"Online User"})
			add.Attribute("sn", []string{"User"})
			if err := client.Add(add); err != nil {
				t.Fatalf("online LDAP Add(): %v", err)
			}

			for _, dn := range []string{legacyDN, onlineDN} {
				result, err := client.Search(ldap.NewSearchRequest(
					dn,
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"uid"},
					nil,
				))
				if err != nil {
					t.Fatalf("Search(base=%q): %v", dn, err)
				}
				if len(result.Entries) != 1 {
					t.Fatalf("Search(base=%q) entries = %d, want 1", dn, len(result.Entries))
				}
			}

			for uid, wantDN := range map[string]string{
				"legacy": legacyDN,
				"online": onlineDN,
			} {
				var candidateDNs []string
				err := store.View(context.Background(), func(reader storage.Reader) error {
					planned, candidates, err := storage.ForEachFilterCandidate(
						storage.ReaderInPartitionWithNormalizer(
							reader,
							partition,
							indexNormalizer,
						),
						directory.Filter{
							Kind:      directory.FilterEquality,
							Attribute: "uid",
							Assertion: []byte(uid),
						},
						func(entry directory.Entry) error {
							candidateDNs = append(candidateDNs, entry.DN)
							return nil
						},
					)
					if err != nil {
						return err
					}
					if !planned || candidates != 1 {
						t.Fatalf("uid=%q index planned=%v candidates=%d, want true/1", uid, planned, candidates)
					}
					return nil
				})
				if err != nil {
					t.Fatalf("read uid=%q equality index: %v", uid, err)
				}
				if len(candidateDNs) != 1 || candidateDNs[0] != wantDN {
					t.Fatalf("uid=%q index candidates = %q, want [%q]", uid, candidateDNs, wantDN)
				}
			}
		})
	}
}

func assertDNIdentityIndexedSearch(
	t *testing.T,
	client *ldap.Conn,
	uid,
	wantDN string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid="+uid+")",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("indexed Search(uid=%q): %v", uid, err)
	}
	if len(result.Entries) != 1 || result.Entries[0].DN != wantDN {
		t.Fatalf("indexed Search(uid=%q) entries = %#v, want %q", uid, result.Entries, wantDN)
	}
}
