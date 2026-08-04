package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

const maintenanceMetadataKey = "sync/context"

type maintenanceSnapshot struct {
	entries  map[string]directory.Entry
	contexts []string
	metadata []byte
}

func TestBoltMaintenanceRoundTrip(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	sourcePath := filepath.Join(directoryPath, "source.db")
	backupPath := filepath.Join(directoryPath, "backup.db")
	restoredPath := filepath.Join(directoryPath, "restored.db")
	seedMaintenanceDatabase(t, sourcePath)
	want := readMaintenanceSnapshot(t, sourcePath)

	report, err := CheckBolt(context.Background(), sourcePath)
	if err != nil {
		t.Fatalf("CheckBolt(): %v", err)
	}
	assertMaintenanceReport(t, report)

	report, err = BackupBolt(context.Background(), sourcePath, backupPath, false)
	if err != nil {
		t.Fatalf("BackupBolt(): %v", err)
	}
	assertMaintenanceReport(t, report)
	assertPrivateDatabaseMode(t, backupPath)

	mutateMaintenanceDatabase(t, sourcePath)
	assertMaintenanceSnapshot(t, backupPath, want)

	report, err = RestoreBolt(context.Background(), backupPath, restoredPath, false)
	if err != nil {
		t.Fatalf("RestoreBolt(): %v", err)
	}
	assertMaintenanceReport(t, report)
	assertPrivateDatabaseMode(t, restoredPath)
	assertMaintenanceSnapshot(t, restoredPath, want)

	report, err = RebuildBolt(context.Background(), restoredPath)
	if err != nil {
		t.Fatalf("RebuildBolt(): %v", err)
	}
	assertMaintenanceReport(t, report)
	assertPrivateDatabaseMode(t, restoredPath)
	assertMaintenanceSnapshot(t, restoredPath, want)
}

func TestBoltMaintenanceRefusesUnexpectedReplacement(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	sourcePath := filepath.Join(directoryPath, "source.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	seedMaintenanceDatabase(t, sourcePath)
	seedMaintenanceDatabase(t, destinationPath)
	mutateMaintenanceDatabase(t, destinationPath)
	wantDestination := readMaintenanceSnapshot(t, destinationPath)

	if _, err := BackupBolt(
		context.Background(),
		sourcePath,
		destinationPath,
		false,
	); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("BackupBolt() error = %v, want replacement refusal", err)
	}
	assertMaintenanceSnapshot(t, destinationPath, wantDestination)

	if _, err := RestoreBolt(
		context.Background(),
		sourcePath,
		destinationPath,
		false,
	); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("RestoreBolt() error = %v, want replacement refusal", err)
	}
	assertMaintenanceSnapshot(t, destinationPath, wantDestination)

	if _, err := BackupBolt(
		context.Background(),
		sourcePath,
		destinationPath,
		true,
	); err != nil {
		t.Fatalf("BackupBolt(replace): %v", err)
	}
	assertMaintenanceSnapshot(t, destinationPath, readMaintenanceSnapshot(t, sourcePath))
}

func TestRestoreRejectsInvalidBackupWithoutChangingDestination(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "invalid.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	if err := os.WriteFile(backupPath, []byte("not a bbolt database"), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	seedMaintenanceDatabase(t, destinationPath)
	want := readMaintenanceSnapshot(t, destinationPath)

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); err == nil || !strings.Contains(err.Error(), "backup is invalid") {
		t.Fatalf("RestoreBolt() error = %v, want invalid backup", err)
	}
	assertMaintenanceSnapshot(t, destinationPath, want)
}

func TestBoltMaintenanceHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	sourcePath := filepath.Join(directoryPath, "source.db")
	seedMaintenanceDatabase(t, sourcePath)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "check",
			run: func() error {
				_, err := CheckBolt(ctx, sourcePath)
				return err
			},
		},
		{
			name: "backup",
			run: func() error {
				_, err := BackupBolt(
					ctx,
					sourcePath,
					filepath.Join(directoryPath, "backup.db"),
					false,
				)
				return err
			},
		},
		{
			name: "restore",
			run: func() error {
				_, err := RestoreBolt(
					ctx,
					sourcePath,
					filepath.Join(directoryPath, "restore.db"),
					false,
				)
				return err
			},
		},
		{
			name: "rebuild",
			run: func() error {
				_, err := RebuildBolt(ctx, sourcePath)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestCheckBoltRejectsLogicalCorruption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*bolt.Tx) error
		message string
	}{
		{
			name: "invalid entry",
			mutate: func(tx *bolt.Tx) error {
				return tx.Bucket(entriesBucket).Put([]byte("\x00dc=example,dc=com"), []byte("{"))
			},
			message: "decode entry",
		},
		{
			name: "mismatched key",
			mutate: func(tx *bolt.Tx) error {
				entry := []byte(`{"DN":"dc=other,dc=com","Attributes":null}`)
				return tx.Bucket(entriesBucket).Put([]byte("\x00dc=example,dc=com"), entry)
			},
			message: "does not match normalized DN",
		},
		{
			name: "unknown metadata",
			mutate: func(tx *bolt.Tx) error {
				return tx.Bucket(metaBucket).Put([]byte("unknown"), []byte("value"))
			},
			message: "unknown metadata key",
		},
		{
			name: "duplicate naming context",
			mutate: func(tx *bolt.Tx) error {
				return tx.Bucket(metaBucket).Put(
					contextsKey,
					[]byte(`["DC=example,DC=com","dc=example,dc=com"]`),
				)
			},
			message: "are equivalent",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "database.db")
			store, err := OpenBolt(databasePath)
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			if err := store.db.Update(test.mutate); err != nil {
				t.Fatalf("mutate database: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("Close(): %v", err)
			}
			if _, err := CheckBolt(context.Background(), databasePath); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("CheckBolt() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestCheckBoltRequiresStorageBuckets(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "database.db")
	database, err := bolt.Open(databasePath, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open(): %v", err)
	}
	if err := database.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket(entriesBucket)
		return err
	}); err != nil {
		t.Fatalf("create entries bucket: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	if _, err := CheckBolt(context.Background(), databasePath); err == nil ||
		!strings.Contains(err.Error(), "required entries or metadata bucket is missing") {
		t.Fatalf("CheckBolt() error = %v", err)
	}
}

func seedMaintenanceDatabase(t *testing.T, path string) {
	t.Helper()
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	entries := []struct {
		partition string
		entry     directory.Entry
	}{
		{
			entry: directory.Entry{
				DN: "cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("olcGlobal")}},
				},
			},
		},
		{
			partition: "database-one",
			entry: directory.Entry{
				DN: "dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "dc", Values: [][]byte{[]byte("example")}},
				},
			},
		},
		{
			partition: "database-one",
			entry: directory.Entry{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "cn", Values: [][]byte{[]byte("Alice"), {0x00, 0xff}}},
				},
			},
		},
		{
			partition: "database-two",
			entry: directory.Entry{
				DN: "dc=other,dc=com",
				Attributes: []directory.Attribute{
					{Description: "dc", Values: [][]byte{[]byte("other")}},
				},
			},
		},
	}
	err = store.Update(context.Background(), func(writer Writer) error {
		for _, item := range entries {
			if err := writer.PutIn(item.partition, item.entry, false); err != nil {
				return err
			}
		}
		if err := writer.SetNamingContexts([]string{
			"dc=example,dc=com",
			"dc=other,dc=com",
		}); err != nil {
			return err
		}
		return writer.SetMetadata(maintenanceMetadataKey, []byte{0x00, 0xff, 0x10})
	})
	if err != nil {
		_ = store.Close()
		t.Fatalf("seed database: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
}

func mutateMaintenanceDatabase(t *testing.T, path string) {
	t.Helper()
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	err = store.Update(context.Background(), func(writer Writer) error {
		return writer.PutIn("database-one", directory.Entry{
			DN: "uid=bob,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "cn", Values: [][]byte{[]byte("Bob")}},
			},
		}, false)
	})
	if err != nil {
		_ = store.Close()
		t.Fatalf("mutate database: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
}

func readMaintenanceSnapshot(t *testing.T, path string) maintenanceSnapshot {
	t.Helper()
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()
	snapshot := maintenanceSnapshot{entries: make(map[string]directory.Entry)}
	err = store.View(context.Background(), func(reader Reader) error {
		if err := reader.ForEachPartition(func(partition string, entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			snapshot.entries[partitionedEntryKey(partition, dn.Key())] = entry
			return nil
		}); err != nil {
			return err
		}
		var err error
		snapshot.contexts, err = reader.NamingContexts()
		if err != nil {
			return err
		}
		snapshot.metadata, err = reader.Metadata(maintenanceMetadataKey)
		return err
	})
	if err != nil {
		t.Fatalf("read database snapshot: %v", err)
	}
	return snapshot
}

func assertMaintenanceSnapshot(t *testing.T, path string, want maintenanceSnapshot) {
	t.Helper()
	got := readMaintenanceSnapshot(t, path)
	if !reflect.DeepEqual(got.contexts, want.contexts) {
		t.Errorf("naming contexts = %v, want %v", got.contexts, want.contexts)
	}
	if !bytes.Equal(got.metadata, want.metadata) {
		t.Errorf("metadata = %x, want %x", got.metadata, want.metadata)
	}
	if len(got.entries) != len(want.entries) {
		t.Fatalf("entry count = %d, want %d", len(got.entries), len(want.entries))
	}
	for key, wantEntry := range want.entries {
		gotEntry, exists := got.entries[key]
		if !exists || !wantEntry.Equal(gotEntry) {
			t.Errorf("entry %q = %#v, want %#v", key, gotEntry, wantEntry)
		}
	}
}

func assertMaintenanceReport(t *testing.T, report CheckReport) {
	t.Helper()
	if report.Entries != 4 || report.Metadata != 2 || report.FileSize <= 0 {
		t.Fatalf("report = %#v", report)
	}
	wantPartitions := []string{"", "database-one", "database-two"}
	if !reflect.DeepEqual(report.Partitions, wantPartitions) {
		t.Fatalf("partitions = %v, want %v", report.Partitions, wantPartitions)
	}
}

func assertPrivateDatabaseMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(): %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("database mode = %o, want 600", info.Mode().Perm())
	}
}
