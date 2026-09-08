package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

func TestPartitionEntryCountTransactions(t *testing.T) {
	for _, test := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{"memory", func(*testing.T) Store { return NewMemory() }},
		{"bolt", func(t *testing.T) Store {
			store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
			if err != nil {
				t.Fatal(err)
			}
			return store
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := test.open(t)
			t.Cleanup(func() { _ = store.Close() })
			ctx := context.Background()
			alice := directory.Entry{DN: "uid=alice,dc=example"}
			bob := directory.Entry{DN: "uid=bob,dc=example"}
			if err := store.Update(ctx, func(writer Writer) error {
				assertPartitionEntryCount(t, writer, "people", 0)
				if err := writer.PutIn("people", alice, false); err != nil {
					return err
				}
				if err := writer.PutIn("people", bob, false); err != nil {
					return err
				}
				if err := writer.Put(directory.Entry{DN: "cn=config"}, false); err != nil {
					return err
				}
				assertPartitionEntryCount(t, writer, "people", 2)
				assertPartitionEntryCount(t, writer, "", 1)
				alice.ReplaceValues("description", [][]byte{[]byte("updated")})
				if err := writer.PutIn("people", alice, true); err != nil {
					return err
				}
				assertPartitionEntryCount(t, writer, "people", 2)
				if err := writer.DeleteIn("people", mustDN(t, bob.DN)); err != nil {
					return err
				}
				assertPartitionEntryCount(t, writer, "people", 1)
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			rollback := errors.New("rollback")
			if err := store.Update(ctx, func(writer Writer) error {
				if err := writer.PutIn("people", bob, false); err != nil {
					return err
				}
				if err := writer.DeleteIn("people", mustDN(t, alice.DN)); err != nil {
					return err
				}
				assertPartitionEntryCount(t, writer, "people", 1)
				return rollback
			}); !errors.Is(err, rollback) {
				t.Fatalf("rollback error = %v", err)
			}
			if err := store.View(ctx, func(reader Reader) error {
				assertPartitionEntryCount(t, reader, "people", 1)
				assertPartitionEntryCount(t, reader, "", 1)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Update(ctx, func(writer Writer) error {
				if err := writer.Clear(); err != nil {
					return err
				}
				assertPartitionEntryCount(t, writer, "people", 0)
				assertPartitionEntryCount(t, writer, "", 0)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBoltPartitionEntryCountBackfillAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), func(writer Writer) error {
		for _, entry := range []directory.Entry{{DN: "uid=a,dc=example"}, {DN: "uid=b,dc=example"}} {
			if err := writer.PutIn("people", entry, false); err != nil {
				return err
			}
		}
		return writer.PutIn("other", directory.Entry{DN: "dc=other"}, false)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(entryCountsBucket)
	}); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.View(context.Background(), func(reader Reader) error {
		assertPartitionEntryCount(t, reader, "people", 2)
		assertPartitionEntryCount(t, reader, "other", 1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	readOnly, err := OpenBoltReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := readOnly.View(context.Background(), func(reader Reader) error {
		assertPartitionEntryCount(t, reader, "people", 2)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertPartitionEntryCount(
	t *testing.T,
	reader Reader,
	partition string,
	want uint64,
) {
	t.Helper()
	got, err := PartitionEntryCount(reader, partition)
	if err != nil || got != want {
		t.Fatalf("PartitionEntryCount(%q) = %d, %v; want %d", partition, got, err, want)
	}
}
