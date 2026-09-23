package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestHierarchyExplicitRepair(t *testing.T) {
	for _, damage := range []string{"manifest", "missing-map", "same-count-rename", "partition-value", "root-value"} {
		t.Run(damage, func(t *testing.T) {
			store := newHierarchyTestStore(t)
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				rows, _, _, err := tx.hierarchyPartition("db")
				if err != nil {
					return err
				}
				old := hierarchyDN(t, "uid=child,uid=parent,dc=example")
				path, err := directory.DNHierarchyPath(old.Key())
				if err != nil {
					return err
				}
				switch damage {
				case "manifest":
					return rows.Put(hierarchyManifestKey, []byte{255})
				case "missing-map":
					return rows.Delete(path)
				case "partition-value":
					root := tx.tx.Bucket(hierarchyBucket)
					if err := root.DeleteBucket(hierarchyPartitionKey("db")); err != nil {
						return err
					}
					return root.Put(hierarchyPartitionKey("db"), []byte("corrupt"))
				case "root-value":
					if err := tx.tx.DeleteBucket(hierarchyBucket); err != nil {
						return err
					}
					return tx.tx.Cursor().Bucket().Put(hierarchyBucket, []byte("corrupt"))
				default:
					// Simulate an old binary: change physical entries without hooks,
					// leaving both persisted counts and schema fingerprint unchanged.
					moved := hierarchyDN(t, "uid=moved,uid=unrelated,dc=example")
					entry := directory.Entry{DN: moved.String()}
					value, err := encodeEntry(entry, moved.Key(), entry.DN)
					if err != nil {
						return err
					}
					if err := tx.entries.Delete([]byte(partitionedEntryKey("db", old.Key()))); err != nil {
						return err
					}
					return tx.entries.Put([]byte(partitionedEntryKey("db", moved.Key())), value)
				}
			}); err != nil {
				t.Fatal(err)
			}
			validate := func() error {
				return store.View(t.Context(), func(reader Reader) error {
					_, _, err := ValidateHierarchyIndex(reader, "db", hierarchyTestNormalizer{})
					return err
				})
			}
			if err := validate(); err == nil {
				t.Fatal("startup validation accepted stale/corrupt hierarchy")
			}
			abort := errors.New("abort repaired transaction")
			if err := store.Update(t.Context(), func(writer Writer) error {
				if handled, err := RebuildHierarchyIndex(writer, "db", hierarchyTestNormalizer{}); err != nil || !handled {
					t.Fatalf("repair: %v/%v", handled, err)
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if err := validate(); err == nil {
				t.Fatal("aborted repair changed persisted state")
			}
			if err := store.Update(t.Context(), func(writer Writer) error {
				_, err := RebuildHierarchyIndex(writer, "db", hierarchyTestNormalizer{})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := validate(); err != nil {
				t.Fatal(err)
			}
			if damage == "same-count-rename" {
				if err := store.View(t.Context(), func(reader Reader) error {
					hierarchyAssert(t, reader, "uid=parent,dc=example", false)
					hierarchyAssert(t, reader, "uid=unrelated,dc=example", true)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHierarchyRepairRejectsAuthoritativeCorruptionBeforeReplacement(t *testing.T) {
	store := newHierarchyTestStore(t)
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		rows, _, _, err := tx.hierarchyPartition("db")
		if err != nil {
			return err
		}
		if err := rows.Put(hierarchyManifestKey, []byte("bad manifest")); err != nil {
			return err
		}
		key := []byte(partitionedEntryKey("db", hierarchyDN(t, "uid=child,uid=parent,dc=example").Key()))
		if err := tx.entries.Put(key, []byte("bad source")); err != nil {
			return err
		}
		_, repairErr := RebuildHierarchyIndex(writer, "db", hierarchyTestNormalizer{})
		if repairErr == nil {
			t.Fatal("repair accepted malformed authoritative entry")
		}
		if !bytes.Equal(rows.Get(hierarchyManifestKey), []byte("bad manifest")) || !bytes.Equal(tx.entries.Get(key), []byte("bad source")) {
			t.Fatal("failed authoritative validation changed buckets")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHierarchyAbsentHooksDoNotCheckContext(t *testing.T) {
	store := newHierarchyTestStore(t)
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		if err := tx.clearHierarchyIndexes(); err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		tx.ctx = ctx
		for _, hook := range []func() error{
			func() error { return tx.hierarchyPutEntry([]byte("legacy"), []byte("legacy")) },
			func() error { return tx.hierarchyDeleteEntry([]byte("legacy")) },
			func() error { return tx.invalidateHierarchyIndex("db") },
			tx.clearHierarchyIndexes,
		} {
			if err := hook(); err != nil {
				t.Fatalf("absent hook added cancellation checkpoint: %v", err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHierarchyNoncanonicalIdentityRequiresMigration(t *testing.T) {
	store := newHierarchyTestStore(t)
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		dn := hierarchyDN(t, "uid=child,uid=parent,dc=example")
		payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(dn.Key(), "dn:v2:"))
		if err != nil {
			return err
		}
		// DN parsing accepts this nonminimal RDN-count varint. Persisted
		// hierarchy paths deliberately require canonical schema identities.
		payload = append([]byte{payload[0] | 0x80, 0}, payload[1:]...)
		identity := "dn:v2:" + base64.RawURLEncoding.EncodeToString(payload)
		if _, err := directory.ParseDNWithIdentityKey(dn.String(), identity); err != nil {
			t.Fatalf("fixture must remain accepted by ordinary DN parsing: %v", err)
		}
		value, err := encodeEntry(directory.Entry{DN: dn.String()}, identity, dn.String())
		if err != nil {
			return err
		}
		if err := tx.entries.Delete([]byte(partitionedEntryKey("db", dn.Key()))); err != nil {
			return err
		}
		if err := tx.entries.Put([]byte(partitionedEntryKey("db", identity)), value); err != nil {
			return err
		}
		if _, _, err := ValidateHierarchyIndex(writer, "db", hierarchyTestNormalizer{}); err == nil {
			t.Fatal("startup validation accepted noncanonical physical identity")
		}
		scoped := WriterInPartitionWithNormalizer(writer, "db", hierarchyTestNormalizer{})
		if handled, found, err := HasDescendants(scoped, hierarchyDN(t, "uid=parent,dc=example")); !handled || found || err == nil {
			t.Fatalf("stale mapping became a false leaf: %v/%v/%v", handled, found, err)
		}
		report, err := MigrateSchemaAwareDNIdentities(writer, "db", hierarchyTestNormalizer{})
		if err != nil || report.Migrated != 1 {
			t.Fatalf("explicit migration did not canonicalize identity: %+v/%v", report, err)
		}
		hierarchyAssert(t, writer, "uid=parent,dc=example", true)
		_, ready, err := ValidateHierarchyIndex(writer, "db", hierarchyTestNormalizer{})
		if !ready && err == nil {
			return errors.New("migration did not publish complete hierarchy")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHierarchyReadOnlyOptionalIndex(t *testing.T) {
	for _, state := range []string{"missing", "different-schema", "corrupt", "ready"} {
		t.Run(state, func(t *testing.T) {
			store := newHierarchyTestStore(t)
			path := store.db.Path()
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				rows, manifest, _, err := tx.hierarchyPartition("db")
				if err != nil {
					return err
				}
				switch state {
				case "missing":
					return tx.clearHierarchyIndexes()
				case "different-schema":
					manifest.fingerprint[0]++
					return putHierarchyManifest(rows, manifest)
				case "corrupt":
					return rows.Put(hierarchyManifestKey, []byte("bad"))
				default:
					return nil
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			readonly, err := OpenBoltReadOnly(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := readonly.View(t.Context(), func(reader Reader) error {
				handled, ready, err := ValidateHierarchyIndex(reader, "db", hierarchyTestNormalizer{})
				switch state {
				case "corrupt":
					if err == nil || !handled || ready {
						t.Fatalf("read-only corruption accepted: %v/%v/%v", handled, ready, err)
					}
				case "ready":
					if err != nil || !handled || !ready {
						t.Fatalf("read-only ready index: %v/%v/%v", handled, ready, err)
					}
				default:
					if err != nil || handled || ready {
						t.Fatalf("optional index requested write: %v/%v/%v", handled, ready, err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := readonly.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("read-only validation changed database: %v", err)
			}
		})
	}
}

func TestHierarchyEnsureRestoresMissingIdentityMarker(t *testing.T) {
	store := newHierarchyTestStore(t)
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		if err := tx.meta.Delete(boltSchemaAwareDNMigrationMetadataKey("db")); err != nil {
			return err
		}
		if _, err := EnsureHierarchyIndex(writer, "db", hierarchyTestNormalizer{}); err != nil {
			return err
		}
		hierarchyAssert(t, writer, "uid=parent,dc=example", true)
		return checkBoltHierarchyIndexes(t.Context(), tx.tx)
	}); err != nil {
		t.Fatal(err)
	}
}
