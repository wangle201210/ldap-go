package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestCollectiveWriterIndexBoundaryWithoutLocalSource(t *testing.T) {
	for _, backend := range dnIdentityCoreWriteBackends() {
		for _, role := range []string{"autonomousArea", "collectiveAttributeSpecificArea"} {
			t.Run(backend.name+"/"+role, func(t *testing.T) {
				store := backend.open(t)
				t.Cleanup(func() { _ = store.Close() })
				registry := collectiveServerRegistry(t)
				normalizer, _, err := loadDatabaseEqualityIndexes(directory.Entry{
					DN:         "olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{{Description: "olcDbIndex", Values: stringValues("objectClass eq")}},
				}, registry)
				if err != nil {
					t.Fatal(err)
				}
				const base = "ou=People,dc=example,dc=com"
				const isolated = "ou=Isolated," + base
				person := collectiveServerPerson("uid=alice,"+isolated, nil)
				source := collectiveServerSource("cn=outer,"+base, "{}", directory.Attribute{
					Description: "c-description", Values: stringValues("Outer"),
				})
				if err := store.Update(t.Context(), func(writer storage.Writer) error {
					indexed := storage.WriterInPartitionWithNormalizer(writer, "db", normalizer)
					for _, entry := range []directory.Entry{
						collectiveAdministrativePointEntry(base, "collectiveAttributeSpecificArea"),
						source,
						collectiveAdministrativePointEntry(isolated, role),
						person,
					} {
						if err := indexed.Put(entry, false); err != nil {
							return err
						}
					}
					actual, err := buildCollectiveAttributePlan(registry, indexed)
					if err != nil {
						return err
					}
					reference, err := buildCollectiveAttributePlan(registry, collectiveUnplannedReader{indexed})
					if err != nil {
						return err
					}
					got, err := actual.apply(person)
					if err != nil {
						return err
					}
					want, err := reference.apply(person)
					if err != nil {
						return err
					}
					if len(want.Values("c-description")) != 0 {
						t.Fatal("full-scan fixture did not isolate the nested administrative area")
					}
					if !got.Equal(want) {
						t.Fatalf("indexed c-description=%q, full scan=%q: nested %s without a source must block outer inheritance",
							got.Values("c-description"), want.Values("c-description"), role)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
