package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
	bolt "go.etcd.io/bbolt"
)

func TestHierarchyStartupAndOfflineRepair(t *testing.T) {
	for _, damage := range []string{"missing-index", "malformed-manifest", "missing-map", "same-count-rename"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "directory.db")
			store, err := storage.OpenBolt(path)
			if err != nil {
				t.Fatal(err)
			}
			seedOfflineToolStore(t, store)
			if err := PrepareOfflineDNIdentities(t.Context(), store); err != nil {
				t.Fatal(err)
			}
			var database runtimeDatabase
			var oldDN, movedDN directory.DN
			var moved directory.Entry
			if err := store.View(t.Context(), func(reader storage.Reader) error {
				_, runtime, err := buildOfflineRuntime(reader, store)
				if err != nil {
					return err
				}
				oldDN, err = runtime.schema.NormalizeDN(offlineAliceDN)
				if err != nil {
					return err
				}
				database = *databaseForNormalizedDN(runtime, oldDN)
				moved, err = reader.GetIn(database.partition, oldDN)
				if err != nil {
					return err
				}
				moved.DN = strings.Replace(offlineAliceDN, "uid=alice", "uid=moved", 1)
				moved.ReplaceValues("uid", stringValues("moved"))
				movedDN, err = runtime.schema.NormalizeDN(moved.DN)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			// Reopening a healthy index uses the same startup validator, even
			// though the persisted schema fingerprint is already current.
			store, err = storage.OpenBolt(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := PrepareOfflineDNIdentities(t.Context(), store); err != nil {
				t.Fatalf("warm reopen: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := bolt.Open(path, 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = raw.Update(func(tx *bolt.Tx) error {
				root := tx.Bucket([]byte("indexes:hierarchy:v1"))
				rows := root.Bucket(append([]byte{0}, database.partition...))
				switch damage {
				case "missing-index":
					return tx.DeleteBucket([]byte("indexes:hierarchy:v1"))
				case "malformed-manifest":
					return rows.Put([]byte{0}, []byte{255})
				case "missing-map":
					path, err := directory.DNHierarchyPath(oldDN.Key())
					if err != nil {
						return err
					}
					return rows.Delete(path)
				default:
					// A previous binary can rename without updating this index.
					// Entry counts and schema fingerprints remain unchanged.
					value, err := json.Marshal(struct {
						directory.Entry
						Identity string `json:"dnIdentity"`
						Source   string `json:"dnSource"`
					}{moved, movedDN.Key(), moved.DN})
					if err != nil {
						return err
					}
					entries := tx.Bucket([]byte("entries"))
					if err := entries.Delete([]byte(database.partition + "\x00" + oldDN.Key())); err != nil {
						return err
					}
					return entries.Put([]byte(database.partition+"\x00"+movedDN.Key()), value)
				}
			})
			closeErr := raw.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("damage: %v/%v", err, closeErr)
			}
			if damage == "missing-index" {
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				readonly, err := storage.OpenBoltReadOnly(path)
				if err != nil {
					t.Fatal(err)
				}
				startupErr := PrepareOfflineDNIdentities(t.Context(), readonly)
				closeErr := readonly.Close()
				after, err := os.ReadFile(path)
				if startupErr != nil || closeErr != nil || err != nil || !bytes.Equal(before, after) {
					t.Fatalf("optional read-only startup: %v/%v/%v", startupErr, closeErr, err)
				}
			}
			store, err = storage.OpenBolt(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if damage == "missing-map" {
				var instance *Server
				var runtime *runtimeState
				if err := store.View(t.Context(), func(reader storage.Reader) error {
					var err error
					instance, runtime, err = buildOfflineRuntime(reader, store)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				// One unmigrated partition must not suppress completeness
				// validation for another partition whose schema is current.
				runtime.databases = append(runtime.databases, runtimeDatabase{
					name: "{2}mdb", partition: "new-unmigrated-partition", dnNormalizer: runtime.schema,
				})
				if err := instance.migrateRuntimeDNIdentities(t.Context(), runtime); err == nil {
					t.Fatal("another partition's migration hid stale hierarchy")
				}
			}
			startupErr := PrepareOfflineDNIdentities(t.Context(), store)
			if damage == "missing-index" {
				if startupErr != nil {
					t.Fatalf("current-schema upgrade failed: %v", startupErr)
				}
			} else {
				if startupErr == nil || !strings.Contains(startupErr.Error(), "hierarchy") {
					t.Fatalf("startup did not reject corrupt hierarchy: %v", startupErr)
				}
				if _, err := New(Config{Store: store}); err == nil {
					t.Fatal("managed server startup accepted corrupt hierarchy")
				}
				if damage == "same-count-rename" {
					_, err = ReindexOfflineSelected(t.Context(), store, OfflineReindexOptions{Database: "1"})
				} else {
					_, err = ReindexOffline(t.Context(), store, "1", false)
				}
				if err != nil {
					t.Fatalf("explicit offline repair: %v", err)
				}
				if err := PrepareOfflineDNIdentities(t.Context(), store); err != nil {
					t.Fatalf("startup after repair: %v", err)
				}
			}
			if err := store.View(t.Context(), func(reader storage.Reader) error {
				handled, ready, err := storage.ValidateHierarchyIndex(reader, database.partition, database.dnNormalizer)
				if err != nil || !handled || !ready {
					t.Fatalf("repaired index: %v/%v/%v", handled, ready, err)
				}
				if damage == "same-count-rename" {
					entry, err := reader.GetIn(database.partition, movedDN)
					if err != nil || !entry.Equal(moved) {
						t.Fatalf("repair changed authoritative moved entry: %v", err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHierarchyOfflineReindexLegacyStorage(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "full"
		if selected {
			name = "selected-full"
		}
		t.Run(name, func(t *testing.T) {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "legacy.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			seedOfflineToolStore(t, store)
			// Offline reindex must also support a database that has never
			// undergone server startup or schema-aware physical-key migration.
			if selected {
				_, err = ReindexOfflineSelected(t.Context(), store, OfflineReindexOptions{Database: "1"})
			} else {
				_, err = ReindexOffline(t.Context(), store, "1", false)
			}
			if err != nil {
				t.Fatalf("legacy offline reindex: %v", err)
			}
			if err := PrepareOfflineDNIdentities(t.Context(), store); err != nil {
				t.Fatal(err)
			}
		})
	}
}
