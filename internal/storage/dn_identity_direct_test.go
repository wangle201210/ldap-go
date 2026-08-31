package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

type countingDNNormalizer struct {
	calls *atomic.Int64
}

type countingIndexSchema struct {
	indexTestSchema
	calls *atomic.Int64
}

func (schema countingIndexSchema) NormalizeDNAttribute(
	attributeType string,
	value []byte,
) (string, []byte, error) {
	schema.calls.Add(1)
	return schema.indexTestSchema.NormalizeDNAttribute(attributeType, value)
}

func (normalizer countingDNNormalizer) NormalizeDNAttribute(
	attributeType string,
	value []byte,
) (string, []byte, error) {
	normalizer.calls.Add(1)
	return (testCanonicalDNNormalizer{}).NormalizeDNAttribute(attributeType, value)
}

func (countingDNNormalizer) CanonicalDNAttributeName(
	attributeType string,
) (string, error) {
	return (testCanonicalDNNormalizer{}).CanonicalDNAttributeName(attributeType)
}

func TestBoltSchemaAwarePointOperationsDoNotScaleNormalizerWork(t *testing.T) {
	t.Parallel()

	type operationCounts struct {
		get, replace, delete int64
	}
	run := func(t *testing.T, entries int) operationCounts {
		t.Helper()
		store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
		if err != nil {
			t.Fatalf("OpenBolt(): %v", err)
		}
		defer store.Close()

		ctx := context.Background()
		var calls atomic.Int64
		normalizer := countingDNNormalizer{calls: &calls}
		if err := store.Update(ctx, func(writer Writer) error {
			scoped := WriterInPartitionWithNormalizer(writer, "db", normalizer)
			for index := 0; index < entries; index++ {
				entry := directory.Entry{
					DN: fmt.Sprintf(
						"uid=user%06d,dc=example,dc=com",
						index,
					),
				}
				if err := scoped.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed %d entries: %v", entries, err)
		}

		target := fmt.Sprintf("userid=USER%06d,DC=EXAMPLE,DC=COM", entries/2)
		targetDN, err := directory.ParseDN(target)
		if err != nil {
			t.Fatal(err)
		}
		calls.Store(0)
		if err := store.View(ctx, func(reader Reader) error {
			_, err := ReaderInPartitionWithNormalizer(
				reader,
				"db",
				normalizer,
			).Get(targetDN)
			return err
		}); err != nil {
			t.Fatalf("Get(%d entries): %v", entries, err)
		}
		counts := operationCounts{get: calls.Load()}

		calls.Store(0)
		if err := store.Update(ctx, func(writer Writer) error {
			return WriterInPartitionWithNormalizer(
				writer,
				"db",
				normalizer,
			).Put(directory.Entry{
				DN: target,
				Attributes: []directory.Attribute{{
					Description: "description",
					Values:      [][]byte{[]byte("updated")},
				}},
			}, true)
		}); err != nil {
			t.Fatalf("replace (%d entries): %v", entries, err)
		}
		counts.replace = calls.Load()

		calls.Store(0)
		if err := store.Update(ctx, func(writer Writer) error {
			return WriterInPartitionWithNormalizer(
				writer,
				"db",
				normalizer,
			).Delete(targetDN)
		}); err != nil {
			t.Fatalf("Delete(%d entries): %v", entries, err)
		}
		counts.delete = calls.Load()
		return counts
	}

	small := run(t, 32)
	large := run(t, 4096)
	if small != large {
		t.Fatalf("normalizer work scales with entries: 32=%+v 4096=%+v", small, large)
	}
	if small.get > 3 || small.replace > 6 || small.delete > 3 {
		t.Fatalf("point operation normalizer work is unexpectedly high: %+v", small)
	}
}

func TestForEachPhysicalEntrySkipsDNNormalization(t *testing.T) {
	t.Parallel()

	store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer store.Close()
	var calls atomic.Int64
	normalizer := countingDNNormalizer{calls: &calls}
	if err := store.Update(context.Background(), func(writer Writer) error {
		scoped := WriterInPartitionWithNormalizer(writer, "db", normalizer)
		for _, dn := range []string{
			"uid=alice,dc=example,dc=com",
			"uid=bob,dc=example,dc=com",
		} {
			if err := scoped.Put(directory.Entry{DN: dn}, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed schema-aware entries: %v", err)
	}
	calls.Store(0)
	count := 0
	if err := store.View(context.Background(), func(reader Reader) error {
		streamed, err := ForEachPhysicalEntry(
			ReaderInPartitionWithNormalizer(reader, "db", normalizer),
			func(entry directory.Entry) error {
				count++
				if _, normalized := entry.NormalizedDNHint(); normalized {
					t.Fatalf("physical entry %q unexpectedly has a DN hint", entry.DN)
				}
				return nil
			},
		)
		if !streamed {
			t.Fatal("schema-aware Bolt reader did not stream physical entries")
		}
		return err
	}); err != nil {
		t.Fatalf("ForEachPhysicalEntry(): %v", err)
	}
	if count != 2 || calls.Load() != 0 {
		t.Fatalf("physical iteration count/calls = %d/%d, want 2/0", count, calls.Load())
	}
}

func TestBoltIndexedReplaceDoesNotScaleNormalizerWork(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, entries int) int64 {
		t.Helper()
		store, err := OpenBolt(filepath.Join(t.TempDir(), "indexed.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		var calls atomic.Int64
		schema := countingIndexSchema{
			indexTestSchema: indexTestSchema{config: indexTestCNConfig()},
			calls:           &calls,
		}
		if err := store.Update(context.Background(), func(writer Writer) error {
			scoped := WriterInPartitionWithNormalizer(writer, "db", schema)
			for index := 0; index < entries; index++ {
				entry := indexTestEntry(
					fmt.Sprintf("cn=user%06d,dc=example", index),
					fmt.Sprintf("user%06d", index),
					fmt.Sprintf("u%06d", index),
				)
				if err := scoped.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed indexed entries: %v", err)
		}
		calls.Store(0)
		target := indexTestEntry(
			fmt.Sprintf("CN=USER%06d,DC=EXAMPLE", entries/2),
			"updated",
			fmt.Sprintf("u%06d", entries/2),
		)
		if err := store.Update(context.Background(), func(writer Writer) error {
			return WriterInPartitionWithNormalizer(writer, "db", schema).Put(target, true)
		}); err != nil {
			t.Fatalf("replace indexed entry: %v", err)
		}
		return calls.Load()
	}

	small := run(t, 32)
	large := run(t, 2048)
	if small != large || small > 4 {
		t.Fatalf("indexed replace normalizer work scales: 32=%d 2048=%d", small, large)
	}
}

func TestBoltDNIdentityMigrationSurvivesMaintenanceLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	directoryPath := t.TempDir()
	sourcePath := filepath.Join(directoryPath, "source.db")
	backupPath := filepath.Join(directoryPath, "backup.db")
	restoredPath := filepath.Join(directoryPath, "restored.db")
	store, err := OpenBolt(sourcePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	entries := []directory.Entry{
		{DN: "exactName=Alice,dc=example,dc=com"},
		{DN: "uid=Alice,dc=example,dc=com"},
		{DN: "userid=Platform+1.3.6.1.4.1.99999.900=Carol,domainComponent=example,dc=com"},
	}
	if err := store.Update(ctx, func(writer Writer) error {
		for _, entry := range entries {
			if err := writer.PutIn("db", entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed legacy entries: %v", err)
	}
	legacyLookup, _ := directory.ParseDN("userid=ALICE,dc=example,dc=com")
	if err := store.View(ctx, func(reader Reader) error {
		_, err := ReaderInPartitionWithNormalizer(
			reader,
			"db",
			testCanonicalDNNormalizer{},
		).Get(legacyLookup)
		return err
	}); !errors.Is(err, ErrDNIdentityMigrationRequired) {
		t.Fatalf("unmigrated lookup error = %v, want migration required", err)
	}
	if err := store.Update(ctx, func(writer Writer) error {
		report, err := MigrateSchemaAwareDNIdentities(
			writer,
			"db",
			testCanonicalDNNormalizer{},
		)
		if err == nil && (report.Entries != 3 || report.Migrated != 3) {
			t.Fatalf("first migration report = %+v", report)
		}
		return err
	}); err != nil {
		t.Fatalf("MigrateSchemaAwareDNIdentities(): %v", err)
	}
	if err := store.Update(ctx, func(writer Writer) error {
		report, err := MigrateSchemaAwareDNIdentities(
			writer,
			"db",
			testCanonicalDNNormalizer{},
		)
		if err == nil && (report.Migrated != 0 || report.AlreadyCurrent != 3) {
			t.Fatalf("repeat migration report = %+v", report)
		}
		return err
	}); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	assertDirectMigrationLookups(t, store)
	if err := store.Close(); err != nil {
		t.Fatalf("Close before reopen: %v", err)
	}
	store, err = OpenBolt(sourcePath)
	if err != nil {
		t.Fatalf("OpenBolt(reopen source): %v", err)
	}
	assertDirectMigrationLookups(t, store)
	if _, err := store.Backup(ctx, backupPath, false); err != nil {
		t.Fatalf("online backup: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	for _, path := range []string{sourcePath, backupPath} {
		if _, err := CheckBoltWithNormalizer(
			ctx,
			path,
			testCanonicalDNNormalizer{},
		); err != nil {
			t.Fatalf("CheckBoltWithNormalizer(%q): %v", path, err)
		}
	}
	if _, err := RestoreBolt(ctx, backupPath, restoredPath, false); err != nil {
		t.Fatalf("RestoreBolt(): %v", err)
	}
	restored, err := OpenBolt(restoredPath)
	if err != nil {
		t.Fatalf("OpenBolt(restored): %v", err)
	}
	defer restored.Close()
	assertDirectMigrationLookups(t, restored)
}

func TestBoltDNIdentityMigrationRebuildsEqualityPostings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "indexed-migration.db")
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	schema := indexTestSchema{config: indexTestCNConfig()}
	if err := store.Update(ctx, func(writer Writer) error {
		for _, entry := range []directory.Entry{
			indexTestEntry("cn=Alpha,dc=example", "Alpha", "alpha"),
			indexTestEntry("cn=Beta,dc=example", "Beta", "beta"),
		} {
			if err := writer.PutIn("db", entry, false); err != nil {
				return err
			}
		}
		if err := RebuildEqualityIndexes(writer, "db", schema); err != nil {
			return err
		}
		report, err := MigrateSchemaAwareDNIdentities(writer, "db", schema)
		if err == nil && report.Migrated != 2 {
			t.Fatalf("migration report = %+v", report)
		}
		return err
	}); err != nil {
		t.Fatalf("migrate indexed partition: %v", err)
	}
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind:      directory.FilterEquality,
		Attribute: "cn",
		Assertion: []byte("ALPHA"),
	}, true, []string{"cn=Alpha,dc=example"})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBoltWithNormalizer(ctx, path, schema); err != nil {
		t.Fatalf("CheckBoltWithNormalizer(): %v", err)
	}
}

func TestCheckBoltRejectsReadyPartitionContainingLegacyKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stale-marker.db")
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), func(writer Writer) error {
		return WriterInPartitionWithNormalizer(
			writer,
			"db",
			testCanonicalDNNormalizer{},
		).Put(directory.Entry{DN: "uid=Current,dc=example,dc=com"}, false)
	}); err != nil {
		t.Fatal(err)
	}
	legacy := directory.Entry{DN: "uid=Legacy,dc=example,dc=com"}
	legacyDN, _ := directory.ParseDN(legacy.DN)
	value, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(entriesBucket).Put(
			[]byte(partitionedEntryKey("db", legacyDN.Key())),
			value,
		)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBolt(context.Background(), path); err == nil ||
		!strings.Contains(err.Error(), "marked schema-aware") {
		t.Fatalf("CheckBolt() error = %v, want stale marker rejection", err)
	}
}

func assertDirectMigrationLookups(t *testing.T, store Store) {
	t.Helper()
	lookups := []string{
		"exactName=Alice,dc=example,dc=com",
		"0.9.2342.19200300.100.1.1=ALICE,DC=EXAMPLE,DC=COM",
		"exactName=Carol+uid=PLATFORM,dc=example,dc=com",
	}
	if err := store.View(context.Background(), func(reader Reader) error {
		scoped := ReaderInPartitionWithNormalizer(
			reader,
			"db",
			testCanonicalDNNormalizer{},
		)
		for _, value := range lookups {
			dn, err := directory.ParseDN(value)
			if err != nil {
				return err
			}
			if _, err := scoped.Get(dn); err != nil {
				return fmt.Errorf("Get(%q): %w", value, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
