package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

func TestBoltServerModeSurvivesStandardReopen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := OpenBoltForServer(path)
	if err != nil {
		t.Fatalf("OpenBoltForServer(): %v", err)
	}
	for index := 0; index < 64; index++ {
		entry := directory.Entry{
			DN: fmt.Sprintf("uid=user-%03d,dc=example,dc=com", index),
			Attributes: []directory.Attribute{{
				Description: "uid",
				Values:      [][]byte{[]byte(fmt.Sprintf("user-%03d", index))},
			}},
		}
		if err := store.Update(context.Background(), func(writer Writer) error {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
			return writer.SetMetadata("last-write", []byte(entry.DN))
		}); err != nil {
			t.Fatalf("Update(%d): %v", index, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	reopened, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer reopened.Close()
	if err := reopened.View(context.Background(), func(reader Reader) error {
		count := 0
		if err := reader.ForEach(func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 64 {
			return fmt.Errorf("entry count = %d, want 64", count)
		}
		value, err := reader.Metadata("last-write")
		if err != nil {
			return err
		}
		want := "uid=user-063,dc=example,dc=com"
		if string(value) != want {
			return fmt.Errorf("last-write = %q, want %q", value, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("View(): %v", err)
	}
}

func TestBoltServerModeFallsBackWhenSynchronizedDescriptorFails(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := OpenBoltForServer(path)
	if err != nil {
		t.Fatalf("OpenBoltForServer(): %v", err)
	}
	if store.durableMeta == nil {
		_ = store.Close()
		t.Skip("platform uses standard bbolt synchronization")
	}
	if err := store.durableMeta.Close(); err != nil {
		t.Fatalf("close synchronized descriptor: %v", err)
	}
	entry := directory.Entry{DN: "dc=example,dc=com"}
	if err := store.Update(context.Background(), func(writer Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("Update() after descriptor failure: %v", err)
	}
	if store.singleSync || store.db.NoSync || store.durableMeta != nil {
		t.Fatalf(
			"fallback state = singleSync:%t noSync:%t descriptor:%v",
			store.singleSync,
			store.db.NoSync,
			store.durableMeta,
		)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	reopened, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer reopened.Close()
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := reopened.View(context.Background(), func(reader Reader) error {
		_, err := reader.Get(dn)
		return err
	}); err != nil {
		t.Fatalf("Get() after reopen: %v", err)
	}
}

func TestBoltServerModeUsesSafeGrowthPolicy(t *testing.T) {
	t.Parallel()

	store, err := OpenBoltForServer(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatalf("OpenBoltForServer(): %v", err)
	}
	defer store.Close()
	want := runtime.GOOS == "darwin"
	if store.db.NoGrowSync != want {
		t.Fatalf("NoGrowSync = %t, want %t", store.db.NoGrowSync, want)
	}
	if store.db.AllocSize != boltAllocationSize {
		t.Fatalf("AllocSize = %d, want %d", store.db.AllocSize, boltAllocationSize)
	}
}

func TestBoltReadOnlyExposesCurrentSnapshotRevision(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer Writer) error {
		return writer.SetMetadata("revision", []byte("present"))
	}); err != nil {
		t.Fatalf("Update(): %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	readOnly, err := OpenBoltReadOnly(path)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(): %v", err)
	}
	defer readOnly.Close()
	current, ok := readOnly.CurrentStorageSnapshotRevision()
	if !ok || current == 0 {
		t.Fatalf("current revision = %d, %t", current, ok)
	}
	if err := readOnly.View(context.Background(), func(reader Reader) error {
		revision, ok := ReaderSnapshotRevision(reader)
		if !ok || revision != current {
			return fmt.Errorf("reader revision = %d, %t; current = %d", revision, ok, current)
		}
		return nil
	}); err != nil {
		t.Fatalf("View(): %v", err)
	}
}

func TestBoltBulkUpdateUsesDenserPages(t *testing.T) {
	t.Parallel()

	leafPages := func(t *testing.T, bulk bool) int {
		t.Helper()
		store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
		if err != nil {
			t.Fatalf("OpenBolt(): %v", err)
		}
		update := store.Update
		if bulk {
			update = store.UpdateBulk
		}
		value := make([]byte, 128)
		if err := update(context.Background(), func(writer Writer) error {
			if err := writer.Clear(); err != nil {
				return err
			}
			for index := 0; index < 2000; index++ {
				if err := writer.SetMetadata(
					fmt.Sprintf("bulk-%05d", index),
					value,
				); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("Update(bulk=%t): %v", bulk, err)
		}
		pages := 0
		if err := store.db.View(func(tx *bolt.Tx) error {
			pages = tx.Bucket(metaBucket).Stats().LeafPageN
			return nil
		}); err != nil {
			t.Fatalf("View(bulk=%t): %v", bulk, err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close(bulk=%t): %v", bulk, err)
		}
		return pages
	}

	regularPages := leafPages(t, false)
	bulkPages := leafPages(t, true)
	if bulkPages >= regularPages {
		t.Fatalf("bulk leaf pages = %d, regular = %d", bulkPages, regularPages)
	}
}
