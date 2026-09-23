package server

import (
	"errors"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type collectiveUnplannedReader struct{ storage.Reader }

func (reader collectiveUnplannedReader) NormalizeDNIdentity(dn directory.DN) (directory.DN, error) {
	return storage.NormalizeReaderDN(reader.Reader, dn)
}

func TestCollectiveWriterIndexSeesTransactionChanges(t *testing.T) {
	for _, backend := range dnIdentityCoreWriteBackends() {
		t.Run(backend.name, func(t *testing.T) {
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
			person := collectiveServerPerson("uid=alice,"+base, nil)
			source := collectiveServerSource("cn=shared,"+base, "{}", directory.Attribute{
				Description: "c-description", Values: stringValues("Shared"),
			})
			sourceDN, err := registry.NormalizeDN(source.DN)
			if err != nil {
				t.Fatal(err)
			}
			check := func(reader storage.Reader, sources int, value string) error {
				t.Helper()
				planned, count, err := storage.ForEachFilterCandidate(reader, directory.Filter{
					Kind: directory.FilterEquality, Attribute: "objectClass", Assertion: []byte("collectiveAttributeSubentry"),
				}, func(directory.Entry) error { return nil })
				if err != nil || !planned || count != sources {
					t.Fatalf("writer plan = %v/%d/%v, want true/%d/nil", planned, count, err, sources)
				}
				actual, err := buildCollectiveAttributePlan(registry, reader)
				if err != nil {
					return err
				}
				reference, err := buildCollectiveAttributePlan(registry, collectiveUnplannedReader{reader})
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
				if !got.Equal(want) || len(actual.sources) != sources {
					t.Fatal("indexed collective plan differs from live full scan")
				}
				if sources == 0 {
					assertCollectiveStringValues(t, got.Values("c-description"))
				} else {
					assertCollectiveStringValues(t, got.Values("c-description"), value)
				}
				return nil
			}
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				indexed := storage.WriterInPartitionWithNormalizer(writer, "db", normalizer)
				for _, entry := range []directory.Entry{collectiveAdministrativePointEntry(base, "collectiveAttributeSpecificArea"), person} {
					if err := indexed.Put(entry, false); err != nil {
						return err
					}
				}
				if err := check(indexed, 0, ""); err != nil {
					return err
				}
				if err := indexed.Put(source, false); err != nil {
					return err
				}
				if err := check(indexed, 1, "Shared"); err != nil {
					return err
				}
				source.ReplaceValues("c-description", stringValues("Changed"))
				if err := indexed.Put(source, true); err != nil {
					return err
				}
				if err := check(indexed, 1, "Changed"); err != nil {
					return err
				}
				if err := indexed.Delete(sourceDN); err != nil {
					return err
				}
				return check(indexed, 0, "")
			}); err != nil {
				t.Fatal(err)
			}
			abort := errors.New("rollback collective source")
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				indexed := storage.WriterInPartitionWithNormalizer(writer, "db", normalizer)
				if err := indexed.Put(source, false); err != nil {
					return err
				}
				if err := check(indexed, 1, "Changed"); err != nil {
					return err
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatalf("rollback: %v", err)
			}
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				return check(storage.WriterInPartitionWithNormalizer(writer, "db", normalizer), 0, "")
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
