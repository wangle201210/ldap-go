package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

func TestStoreContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		open func(*testing.T) Store
	}{
		{
			name: "memory",
			open: func(t *testing.T) Store {
				t.Helper()
				return NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) Store {
				t.Helper()
				store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runStoreContract(t, test.open(t))
		})
	}
}

func runStoreContract(t *testing.T, store Store) {
	t.Helper()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})

	ctx := context.Background()
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "cn", Values: [][]byte{[]byte("Alice"), {0x00, 0xff}}},
		},
	}
	if err := store.Update(ctx, func(tx Writer) error {
		if err := tx.Put(entry, false); err != nil {
			return err
		}
		if err := tx.SetNamingContexts([]string{"dc=example,dc=com"}); err != nil {
			return err
		}
		return tx.SetMetadata("sync/context", []byte{0x00, 0xff, 0x10})
	}); err != nil {
		t.Fatalf("initial Update(): %v", err)
	}

	dn := mustDN(t, entry.DN)
	if err := store.View(ctx, func(tx Reader) error {
		got, err := tx.Get(dn)
		if err != nil {
			return err
		}
		if !entry.Equal(got) {
			t.Fatalf("Get() = %#v, want %#v", got, entry)
		}
		contexts, err := tx.NamingContexts()
		if err != nil {
			return err
		}
		if len(contexts) != 1 || contexts[0] != "dc=example,dc=com" {
			t.Fatalf("NamingContexts() = %v", contexts)
		}
		metadata, err := tx.Metadata("sync/context")
		if err != nil {
			return err
		}
		if !bytes.Equal(metadata, []byte{0x00, 0xff, 0x10}) {
			t.Fatalf("Metadata() = %x", metadata)
		}
		metadata[0] = 0xff
		return nil
	}); err != nil {
		t.Fatalf("View(): %v", err)
	}

	rollback := errors.New("rollback")
	if err := store.Update(ctx, func(tx Writer) error {
		if err := tx.Delete(dn); err != nil {
			return err
		}
		if err := tx.SetMetadata("sync/context", []byte("rolled back")); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback Update() error = %v", err)
	}

	if err := store.View(ctx, func(tx Reader) error {
		_, err := tx.Get(dn)
		if err != nil {
			return err
		}
		metadata, err := tx.Metadata("sync/context")
		if err != nil {
			return err
		}
		if !bytes.Equal(metadata, []byte{0x00, 0xff, 0x10}) {
			t.Fatalf("metadata changed after rollback: %x", metadata)
		}
		if _, err := tx.Metadata("missing"); !errors.Is(
			err,
			ErrMetadataNotFound,
		) {
			t.Fatalf("missing Metadata() error = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("entry disappeared after rollback: %v", err)
	}

	other := entry.Clone()
	other.ReplaceValues("cn", [][]byte{[]byte("Other Alice")})
	if err := store.Update(ctx, func(tx Writer) error {
		return tx.PutIn("other-database", other, false)
	}); err != nil {
		t.Fatalf("partitioned Update(): %v", err)
	}
	if err := store.View(ctx, func(tx Reader) error {
		defaultEntry, err := tx.GetIn("", dn)
		if err != nil {
			return err
		}
		if !entry.Equal(defaultEntry) {
			t.Fatalf("GetIn(default) = %#v, want %#v", defaultEntry, entry)
		}
		otherEntry, err := tx.GetIn("other-database", dn)
		if err != nil {
			return err
		}
		if !other.Equal(otherEntry) {
			t.Fatalf("GetIn(other) = %#v, want %#v", otherEntry, other)
		}
		if _, err := tx.Get(dn); !errors.Is(err, ErrEntryAmbiguous) {
			t.Fatalf("Get() error = %v, want ErrEntryAmbiguous", err)
		}
		partitions := make(map[string]int)
		if err := tx.ForEachPartition(func(partition string, _ directory.Entry) error {
			partitions[partition]++
			return nil
		}); err != nil {
			return err
		}
		if partitions[""] != 1 || partitions["other-database"] != 1 {
			t.Fatalf("partition counts = %v", partitions)
		}
		return nil
	}); err != nil {
		t.Fatalf("partitioned View(): %v", err)
	}
}

func TestBoltReadsAndNormalizesLegacyEntryKeys(t *testing.T) {
	t.Parallel()

	store, err := OpenBolt(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	entry := directory.Entry{
		DN: "uid=legacy,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "cn", Values: [][]byte{[]byte("Legacy")}},
		},
	}
	dn := mustDN(t, entry.DN)
	value, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(entriesBucket).Put([]byte(dn.Key()), value)
	}); err != nil {
		t.Fatalf("seed legacy key: %v", err)
	}

	if err := store.View(context.Background(), func(reader Reader) error {
		got, err := reader.GetIn("", dn)
		if err != nil {
			return err
		}
		if !entry.Equal(got) {
			t.Fatalf("GetIn() = %#v, want %#v", got, entry)
		}
		count := 0
		if err := reader.ForEachIn("", func(got directory.Entry) error {
			count++
			if !entry.Equal(got) {
				return fmt.Errorf("ForEachIn() entry = %#v, want %#v", got, entry)
			}
			return nil
		}); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("ForEachIn() count = %d, want 1", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("read legacy key: %v", err)
	}

	entry.ReplaceValues("cn", [][]byte{[]byte("Normalized")})
	if err := store.Update(context.Background(), func(writer Writer) error {
		return writer.PutIn("", entry, true)
	}); err != nil {
		t.Fatalf("normalize legacy key: %v", err)
	}
	if err := store.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(entriesBucket)
		if bucket.Get([]byte(dn.Key())) != nil {
			t.Fatal("legacy key remained after replacement")
		}
		if bucket.Get([]byte(partitionedEntryKey("", dn.Key()))) == nil {
			t.Fatal("partitioned replacement key was not written")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect normalized key: %v", err)
	}
}

func mustDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
