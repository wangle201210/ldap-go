package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

func TestEntryCountMaintenanceRejectsCorruption(t *testing.T) {
	for _, corruption := range []struct {
		name   string
		mutate func(*bolt.Tx) error
	}{
		{"wrong count", func(tx *bolt.Tx) error {
			return tx.Bucket(entryCountsBucket).Put(boltEntryCountKey("people"), binary.BigEndian.AppendUint64(nil, 8))
		}},
		{"missing count", func(tx *bolt.Tx) error {
			return tx.Bucket(entryCountsBucket).Delete(boltEntryCountKey("people"))
		}},
		{"orphan count", func(tx *bolt.Tx) error {
			return tx.Bucket(entryCountsBucket).Put(boltEntryCountKey("missing"), binary.BigEndian.AppendUint64(nil, 1))
		}},
		{"malformed value", func(tx *bolt.Tx) error {
			return tx.Bucket(entryCountsBucket).Put(boltEntryCountKey("people"), []byte{1})
		}},
		{"malformed key", func(tx *bolt.Tx) error {
			return tx.Bucket(entryCountsBucket).Put([]byte("people"), binary.BigEndian.AppendUint64(nil, 2))
		}},
		{"nested bucket", func(tx *bolt.Tx) error {
			_, err := tx.Bucket(entryCountsBucket).CreateBucket([]byte("nested"))
			return err
		}},
		{"bucket replaced by value", func(tx *bolt.Tx) error {
			if err := tx.DeleteBucket(entryCountsBucket); err != nil {
				return err
			}
			return tx.Cursor().Bucket().Put(entryCountsBucket, []byte("not a bucket"))
		}},
	} {
		t.Run(corruption.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			source := filepath.Join(dir, "source.db")
			store, err := OpenBolt(source)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Update(ctx, func(w Writer) error {
				for _, dn := range []string{"uid=a,dc=example", "uid=b,dc=example"} {
					if err := w.PutIn("people", directory.Entry{DN: dn}, false); err != nil {
						return err
					}
				}
				return w.Put(directory.Entry{DN: "cn=config"}, false)
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.db.Update(corruption.mutate); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"check", "backup", "restore", "rebuild"} {
				t.Run(operation, func(t *testing.T) {
					target := filepath.Join(dir, operation+".db")
					seedMaintenanceDatabase(t, target)
					original, err := os.ReadFile(target)
					if err != nil {
						t.Fatal(err)
					}
					switch operation {
					case "check":
						_, err = CheckBolt(ctx, source)
					case "backup":
						_, err = BackupBolt(ctx, source, target, true)
					case "restore":
						_, err = RestoreBolt(ctx, source, target, true)
					case "rebuild":
						_, err = RebuildBolt(ctx, source)
					}
					if err == nil || !strings.Contains(err.Error(), "entry count") {
						t.Fatalf("expected entry count rejection, got %v", err)
					}
					after, err := os.ReadFile(target)
					if err != nil || !bytes.Equal(original, after) {
						t.Fatalf("destination changed: %v", err)
					}
				})
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("source changed: %v", err)
			}
		})
	}
}

func TestEntryCountMaintenanceLegacyAndRoundTrip(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "current"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			source := filepath.Join(dir, "source.db")
			store, err := OpenBolt(source)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Update(ctx, func(w Writer) error {
				if err := w.Put(directory.Entry{DN: "cn=config"}, false); err != nil {
					return err
				}
				for _, dn := range []string{"dc=example", "uid=a,dc=example"} {
					if err := w.PutIn("people", directory.Entry{DN: dn}, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if legacy {
				if err := store.db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(entryCountsBucket) }); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if report, err := CheckBolt(ctx, source); err != nil || report.Entries != 3 {
				t.Fatalf("check: %#v %v", report, err)
			}
			backup := filepath.Join(dir, "backup.db")
			if _, err := BackupBolt(ctx, source, backup, false); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatalf("read-only maintenance changed source: %v", err)
			}
			restored := filepath.Join(dir, "restored.db")
			if _, err := RestoreBolt(ctx, backup, restored, false); err != nil {
				t.Fatal(err)
			}
			if _, err := RebuildBolt(ctx, restored); err != nil {
				t.Fatal(err)
			}
			store, err = OpenBolt(restored)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.View(ctx, func(reader Reader) error {
				assertPartitionEntryCount(t, reader, "", 1)
				assertPartitionEntryCount(t, reader, "people", 2)
				assertPartitionEntryCount(t, reader, "empty", 0)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := CheckBolt(ctx, restored); err != nil {
				t.Fatal(err)
			}
		})
	}
}
