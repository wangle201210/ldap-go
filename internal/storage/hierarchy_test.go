package storage

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

type hierarchyTestNormalizer struct{ testDNNormalizer }

func (hierarchyTestNormalizer) HierarchyIdentityFingerprint() ([32]byte, bool) {
	return [32]byte{1}, true
}

func hierarchyDN(t *testing.T, raw string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(raw, hierarchyTestNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	return dn
}

func hierarchyAssert(t *testing.T, reader Reader, base string, want bool) {
	t.Helper()
	scoped := ReaderInPartitionWithNormalizer(reader, "db", hierarchyTestNormalizer{})
	handled, got, err := HasDescendants(scoped, hierarchyDN(t, base))
	if err != nil || !handled || got != want {
		t.Fatalf("HasDescendants(%q) = %v/%v/%v, want true/%v/nil", base, handled, got, err, want)
	}
}

func newHierarchyTestStore(t *testing.T) *Bolt {
	t.Helper()
	store, err := OpenBolt(filepath.Join(t.TempDir(), "hierarchy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer Writer) error {
		for _, raw := range []string{"dc=example", "uid=parent,dc=example", "uid=child,uid=parent,dc=example", "uid=unrelated,dc=example"} {
			if err := PutInWithDN(writer, "db", directory.Entry{DN: raw}, hierarchyDN(t, raw), false); err != nil {
				return err
			}
		}
		_, err := EnsureHierarchyIndex(writer, "db", hierarchyTestNormalizer{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestHierarchySubtreeOrderAndOwnership(t *testing.T) {
	for _, format := range []string{"v1", "v2", "v3", "json", "mixed"} {
		t.Run(format, func(t *testing.T) {
			store := newDeletePreflightStore(t, format)
			var captured, expected []directory.Entry
			if err := store.Update(t.Context(), func(writer Writer) error {
				if _, err := EnsureHierarchyIndex(writer, "db", hierarchyTestNormalizer{}); err != nil {
					return err
				}
				scoped := WriterInPartitionWithNormalizer(writer, "db", hierarchyTestNormalizer{})
				for _, raw := range []string{"", "dc=example", "uid=parent,dc=example", "exactName=Root,dc=example", "exactName=root,dc=example"} {
					base := hierarchyDN(t, raw)
					var want, got []directory.Entry
					if err := scoped.ForEach(func(entry directory.Entry) error {
						dn := hierarchyDN(t, entry.DN)
						if base.Equal(dn) || base.AncestorOf(dn) {
							want = append(want, entry)
							captured = append(captured, entry)
							return nil
						}
						return nil
					}); err != nil {
						return err
					}
					handled, err := ForEachSubtreeEntry(scoped, base, func(entry directory.Entry) error {
						got = append(got, entry)
						expected = append(expected, entry)
						return nil
					})
					if err != nil || !handled || !reflect.DeepEqual(got, want) {
						t.Fatalf("subtree %q: handled=%v err=%v, entries/hints/order differ", raw, handled, err)
					}
				}
				hierarchyAssert(t, writer, "uid=parent,dc=example", true)
				hierarchyAssert(t, writer, "exactName=Root,dc=example", true)
				hierarchyAssert(t, writer, "exactName=root,dc=example", false)
				return writer.Clear()
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(captured, expected) {
				t.Fatal("subtree entries borrowed transaction memory")
			}
		})
	}
}

func TestHierarchyMutationTransactionAndLegacyMigration(t *testing.T) {
	store := newHierarchyTestStore(t)
	rollback := errors.New("rollback")
	if err := store.Update(t.Context(), func(writer Writer) error {
		scoped := WriterInPartitionWithNormalizer(writer, "db", hierarchyTestNormalizer{})
		child := hierarchyDN(t, "uid=child,uid=parent,dc=example")
		if err := scoped.Delete(child); err != nil {
			return err
		}
		hierarchyAssert(t, writer, "uid=parent,dc=example", false)
		if err := scoped.Put(directory.Entry{DN: "uid=orphan,uid=missing,uid=parent,dc=example"}, false); err != nil {
			return err
		}
		hierarchyAssert(t, writer, "uid=parent,dc=example", true)
		if err := scoped.Put(directory.Entry{DN: "uid=parent,dc=example", Attributes: []directory.Attribute{{Description: "description", Values: [][]byte{[]byte("replacement")}}}}, true); err != nil {
			return err
		}
		if _, ready, err := ValidateHierarchyIndex(writer, "db", hierarchyTestNormalizer{}); err != nil || !ready {
			t.Fatalf("in-tx index invalid: %v/%v", ready, err)
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback error: %v", err)
	}
	if err := store.View(t.Context(), func(reader Reader) error {
		hierarchyAssert(t, reader, "uid=parent,dc=example", true)
		_, err := reader.GetIn("db", hierarchyDN(t, "uid=child,uid=parent,dc=example"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(t.Context(), func(writer Writer) error {
		if err := writer.PutIn("db", directory.Entry{DN: "uid=legacy,dc=example"}, false); err != nil {
			return err
		}
		scoped := WriterInPartitionWithNormalizerLegacy(writer, "db", hierarchyTestNormalizer{})
		if handled, _, err := HasDescendants(scoped, hierarchyDN(t, "dc=example")); handled || err != nil {
			t.Fatalf("legacy partition did not fall back: %v/%v", handled, err)
		}
		if err := scoped.Put(directory.Entry{DN: "uid=new,uid=legacy,dc=example"}, false); err != nil {
			return err
		}
		hierarchyAssert(t, writer, "uid=legacy,dc=example", true)
		report, err := MigrateSchemaAwareDNIdentities(writer, "db", hierarchyTestNormalizer{})
		if err != nil || report.Migrated != 0 || report.AlreadyCurrent != 6 {
			t.Fatalf("repeat migration: %+v/%v", report, err)
		}
		_, ready, err := ValidateHierarchyIndex(writer, "db", hierarchyTestNormalizer{})
		if !ready && err == nil {
			return errors.New("repeat migration lost complete index")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHierarchyPersistenceAndMaintenance(t *testing.T) {
	store := newHierarchyTestStore(t)
	backup := filepath.Join(t.TempDir(), "backup.db")
	if _, err := store.Backup(t.Context(), backup, false); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if _, err := RestoreBolt(t.Context(), backup, restored, false); err != nil {
		t.Fatal(err)
	}
	if _, err := RebuildBolt(t.Context(), restored); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenBoltReadOnly(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.View(t.Context(), func(reader Reader) error {
		hierarchyAssert(t, reader, "uid=parent,dc=example", true)
		_, ready, err := ValidateHierarchyIndex(reader, "db", hierarchyTestNormalizer{})
		if err != nil || !ready {
			t.Fatalf("persisted index invalid: %v/%v", ready, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type hierarchyUnknownReader struct{ Reader }

func (reader hierarchyUnknownReader) MaintenanceStorageReader() Reader { return reader.Reader }

func TestHierarchyUnsupportedFallback(t *testing.T) {
	store := newHierarchyTestStore(t)
	if err := store.View(t.Context(), func(reader Reader) error {
		base := hierarchyDN(t, "dc=example")
		for _, unsupported := range []Reader{
			reader,
			ReaderInPartition(reader, "db"),
			ReaderInPartitionWithNormalizer(reader, "db", testDNNormalizer{}),
			ReaderInPartitionWithNormalizer(reader, "", hierarchyTestNormalizer{}),
			ReaderInPartitionWithNormalizer(reader, "db\x00nested", hierarchyTestNormalizer{}),
			hierarchyUnknownReader{ReaderInPartitionWithNormalizer(reader, "db", hierarchyTestNormalizer{})},
			ReaderInPartitionWithNormalizer(hierarchyUnknownReader{reader}, "db", hierarchyTestNormalizer{}),
		} {
			if handled, _, err := HasDescendants(unsupported, base); handled || err != nil {
				t.Fatalf("unsupported reader %T handled=%v err=%v", unsupported, handled, err)
			}
			if handled, err := ForEachSubtreeEntry(unsupported, base, func(directory.Entry) error {
				t.Fatal("unsupported reader invoked callback")
				return nil
			}); handled || err != nil {
				t.Fatalf("unsupported iterator %T handled=%v err=%v", unsupported, handled, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHierarchyCorruption(t *testing.T) {
	for _, damage := range []string{"manifest-missing", "manifest-version", "manifest-short", "mapping-missing", "locator-missing", "path-mismatch", "cross-partition", "nested-row", "count"} {
		t.Run(damage, func(t *testing.T) {
			store := newHierarchyTestStore(t)
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				rows, manifest, _, err := tx.hierarchyPartition("db")
				if err != nil {
					return err
				}
				identity := hierarchyDN(t, "uid=child,uid=parent,dc=example").Key()
				path, err := directory.DNHierarchyPath(identity)
				if err != nil {
					return err
				}
				switch damage {
				case "manifest-missing":
					return rows.Delete(hierarchyManifestKey)
				case "manifest-version":
					encoded := bytes.Clone(rows.Get(hierarchyManifestKey))
					encoded[0]++
					return rows.Put(hierarchyManifestKey, encoded)
				case "manifest-short":
					return rows.Put(hierarchyManifestKey, []byte{1})
				case "mapping-missing":
					return rows.Delete(path)
				case "locator-missing":
					return tx.entries.Delete([]byte(partitionedEntryKey("db", identity)))
				case "cross-partition":
					return rows.Put(path, []byte(partitionedEntryKey("other", identity)))
				case "path-mismatch":
					return rows.Put(append(path, 1), []byte(partitionedEntryKey("db", identity)))
				case "nested-row":
					_, err := rows.CreateBucket([]byte{2})
					return err
				default:
					manifest.count++
					return putHierarchyManifest(rows, manifest)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.View(t.Context(), func(reader Reader) error {
				_, _, err := ValidateHierarchyIndex(reader, "db", hierarchyTestNormalizer{})
				return err
			}); err == nil {
				t.Fatal("validation accepted corrupt index")
			}
			if strings.HasPrefix(damage, "manifest") {
				if err := store.Update(t.Context(), func(writer Writer) error {
					_, err := EnsureHierarchyIndex(writer, "db", hierarchyTestNormalizer{})
					return err
				}); err == nil {
					t.Fatal("ensure silently repaired malformed manifest")
				}
			}
			if err := store.db.View(func(tx *bolt.Tx) error { return checkBoltHierarchyIndexes(t.Context(), tx) }); err == nil {
				t.Fatal("maintenance accepted corrupt index")
			}
		})
	}
}

func TestHierarchyBoundedValidationAndCallbackErrors(t *testing.T) {
	store := newHierarchyTestStore(t)
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		unrelated := hierarchyDN(t, "uid=unrelated,dc=example")
		if err := tx.entries.Put([]byte(partitionedEntryKey("db", unrelated.Key())), []byte("broken unrelated entry")); err != nil {
			return err
		}
		hierarchyAssert(t, writer, "uid=parent,dc=example", true)
		scoped := WriterInPartitionWithNormalizer(writer, "db", hierarchyTestNormalizer{})
		stop := errors.New("callback stop")
		calls := 0
		handled, err := ForEachSubtreeEntry(scoped, hierarchyDN(t, "uid=parent,dc=example"), func(directory.Entry) error {
			calls++
			return stop
		})
		if !handled || !errors.Is(err, stop) || calls != 1 {
			t.Fatalf("callback stop = %v/%v/%d", handled, err, calls)
		}
		child := hierarchyDN(t, "uid=child,uid=parent,dc=example")
		if err := tx.entries.Put([]byte(partitionedEntryKey("db", child.Key())), []byte("broken relevant entry")); err != nil {
			return err
		}
		calls = 0
		_, err = ForEachSubtreeEntry(scoped, hierarchyDN(t, "uid=parent,dc=example"), func(directory.Entry) error { calls++; return nil })
		if err == nil || calls != 0 {
			t.Fatal("relevant corruption did not fail before callbacks")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		tx.ctx = ctx
		_, _, err = HasDescendants(scoped, unrelated)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type hierarchyIndexedTestSchema struct{ indexTestSchema }

func (hierarchyIndexedTestSchema) HierarchyIdentityFingerprint() ([32]byte, bool) {
	return [32]byte{2}, true
}

func (hierarchyIndexedTestSchema) IndexEntryValuesReadOnly() bool { return true }

func TestHierarchyEqualityIndexedMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indexed-hierarchy.db")
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	schema := hierarchyIndexedTestSchema{indexTestSchema{config: indexTestCNConfig()}}
	if err := store.Update(t.Context(), func(writer Writer) error {
		scoped := WriterInPartitionWithNormalizer(writer, "db", schema)
		for _, entry := range []directory.Entry{
			indexTestEntry("dc=example", "Root", "root"),
			indexTestEntry("uid=child,dc=example", "Before", "child"),
		} {
			if err := scoped.Put(entry, false); err != nil {
				return err
			}
		}
		for _, entry := range []directory.Entry{
			indexTestEntry("uid=child,dc=example", "After", "child"),
			indexTestEntry("uid=child,dc=example", "After", "modified-unindexed-value"),
		} {
			if err := scoped.Put(entry, true); err != nil {
				return err
			}
			if _, ready, err := ValidateHierarchyIndex(writer, "db", schema); err != nil || !ready {
				t.Fatalf("indexed replace lost hierarchy: %v/%v", ready, err)
			}
		}
		old, err := directory.ParseDNWithNormalizer("uid=child,dc=example", schema)
		if err != nil {
			return err
		}
		if err := scoped.Delete(old); err != nil {
			return err
		}
		base, err := directory.ParseDNWithNormalizer("dc=example", schema)
		if err != nil {
			return err
		}
		if handled, found, err := HasDescendants(scoped, base); err != nil || !handled || found {
			t.Fatalf("indexed delete did not update hierarchy: %v/%v/%v", handled, found, err)
		}
		if err := scoped.Put(indexTestEntry("uid=moved,dc=example", "After", "moved"), false); err != nil {
			return err
		}
		if handled, found, err := HasDescendants(scoped, base); err != nil || !handled || !found {
			t.Fatalf("indexed move did not update hierarchy: %v/%v/%v", handled, found, err)
		}
		_, ready, err := ValidateHierarchyIndex(writer, "db", schema)
		if !ready && err == nil {
			return errors.New("indexed hierarchy is incomplete")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBoltWithNormalizer(t.Context(), path, schema); err != nil {
		t.Fatal(err)
	}
}
