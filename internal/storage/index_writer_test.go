package storage

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type writerIndexValidationPoison struct {
	indexTestSchema
	current bool
	reads   int
	writes  int
}

func (schema *writerIndexValidationPoison) EqualityIndexValidation(string, uint64) (bool, bool) {
	schema.reads++
	return schema.current, true
}

func (schema *writerIndexValidationPoison) StoreEqualityIndexValidation(string, uint64, bool) {
	schema.writes++
}

type writerIndexRevisionDecorator struct{ Writer }

func (writer writerIndexRevisionDecorator) StorageSnapshotRevision() (uint64, bool) {
	return 123, true
}

func (writer writerIndexRevisionDecorator) MaintenanceStorageReader() Reader {
	return writer.Writer
}

func (writer writerIndexRevisionDecorator) MaintenanceStorageWriter() Writer {
	return writer.Writer
}

func writerIndexEquality(attribute, value string) directory.Filter {
	return directory.Filter{Kind: directory.FilterEquality, Attribute: attribute, Assertion: []byte(value)}
}

func requireWriterIndexCandidates(t *testing.T, reader Reader, filter directory.Filter, wantPlanned bool, want ...string) []directory.Entry {
	t.Helper()
	var entries []directory.Entry
	planned, count, err := ForEachFilterCandidate(reader, filter, func(entry directory.Entry) error {
		entries = append(entries, entry)
		return nil
	})
	if err != nil || planned != wantPlanned || count != len(entries) {
		t.Fatalf("candidates planned=%v count=%d error=%v, want planned=%v rows=%d", planned, count, err, wantPlanned, len(entries))
	}
	dns := make([]string, len(entries))
	for index, entry := range entries {
		dns[index] = entry.DN
	}
	expected := slices.Clone(want)
	slices.Sort(dns)
	slices.Sort(expected)
	if !slices.Equal(dns, expected) {
		t.Fatalf("candidate DNs = %q, want %q", dns, want)
	}
	return entries
}

func requireWriterIndexCacheUnused(t *testing.T, schema *writerIndexValidationPoison) {
	t.Helper()
	if schema.reads != 0 || schema.writes != 0 {
		t.Fatalf("writer accessed snapshot validation cache: reads=%d writes=%d", schema.reads, schema.writes)
	}
}

func TestWriterEqualityIndexLiveTransaction(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			store := openIndexTestStore(t, backend)
			t.Cleanup(func() { _ = store.Close() })
			schema := &writerIndexValidationPoison{indexTestSchema: indexTestSchema{config: indexTestCNConfig()}, current: true}
			filter := writerIndexEquality("commonName", "ALICE")
			if err := store.Update(t.Context(), func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizer(writerIndexRevisionDecorator{writer}, "db", schema)
				// A poisoned positive cache must not make a missing index authoritative.
				requireWriterIndexCandidates(t, indexed, filter, false)
				if err := indexed.Put(indexTestEntry("uid=alice,dc=example", "Alice", "alice"), false); err != nil {
					return err
				}
				// A poisoned negative cache must not hide the newly built live index.
				schema.current = false
				entries := requireWriterIndexCandidates(t, indexed, filter, true, "uid=alice,dc=example")
				entries[0].Attributes[0].Values[0][0] = 'X'
				entries = requireWriterIndexCandidates(t, indexed, filter, true, "uid=alice,dc=example")
				if got := string(entries[0].Attributes[0].Values[0]); got != "Alice" {
					t.Fatalf("candidate exposed mutable storage bytes: %q", got)
				}
				if err := indexed.Put(indexTestEntry("uid=bob,dc=example", "Alice", "bob"), false); err != nil {
					return err
				}
				other := WriterInPartitionWithNormalizer(writer, "other", schema)
				if err := other.Put(indexTestEntry("uid=elsewhere,dc=example", "Alice", "elsewhere"), false); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, filter, true, "uid=alice,dc=example", "uid=bob,dc=example")
				if err := indexed.Put(indexTestEntry("uid=alice,dc=example", "Updated", "alice"), true); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, filter, true, "uid=bob,dc=example")
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Updated"), true, "uid=alice,dc=example")
				if err := indexed.Delete(mustDN(t, "uid=bob,dc=example")); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, filter, true)
				requireWriterIndexCandidates(t, indexed, directory.Filter{Kind: directory.FilterPresent, Attribute: "cn"}, true, "uid=alice,dc=example")
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("uid", "alice"), false)
				requireWriterIndexCacheUnused(t, schema)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWriterEqualityIndexInvalidationAndSchemaChanges(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			store := openIndexTestStore(t, backend)
			t.Cleanup(func() { _ = store.Close() })
			schema := &writerIndexValidationPoison{indexTestSchema: indexTestSchema{config: indexTestCNConfig()}, current: true}
			nextConfig := indexTestCNConfig()
			nextConfig.Attributes = append(nextConfig.Attributes, EqualityIndexAttribute{
				Attribute: "0.9.2342.19200300.100.1.1", EqualityRule: "caseignorematch", Equality: true,
			})
			nextSchema := &writerIndexValidationPoison{indexTestSchema: indexTestSchema{config: nextConfig}, current: true}
			if err := store.Update(t.Context(), func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizerLegacy(writer, "db", schema)
				if err := indexed.Put(indexTestEntry("uid=alice,dc=example", "Alice", "alice"), false); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Alice"), true, "uid=alice,dc=example")
				if err := writer.PutIn("db", indexTestEntry("uid=raw,dc=example", "Raw", "raw"), false); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Alice"), false)
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Raw"), false)
				var scanned int
				if err := indexed.ForEach(func(directory.Entry) error { scanned++; return nil }); err != nil {
					return err
				}
				if scanned != 2 {
					t.Fatalf("legacy fallback scanned %d rows, want 2", scanned)
				}
				if _, err := MigrateSchemaAwareDNIdentities(writer, "db", schema); err != nil {
					return err
				}
				if err := RebuildEqualityIndexes(writer, "db", schema); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Raw"), true, "uid=raw,dc=example")
				next := WriterInPartitionWithNormalizer(writer, "db", nextSchema)
				requireWriterIndexCandidates(t, next, writerIndexEquality("cn", "Alice"), false)
				if err := RebuildEqualityIndexes(writer, "db", nextSchema); err != nil {
					return err
				}
				nextSchema.current = false
				requireWriterIndexCandidates(t, next, writerIndexEquality("userid", "RAW"), true, "uid=raw,dc=example")
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Alice"), false)
				if err := RebuildEqualityIndexes(writer, "db", schema); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, next, writerIndexEquality("userid", "RAW"), false)
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Alice"), true, "uid=alice,dc=example")
				requireWriterIndexCacheUnused(t, schema)
				requireWriterIndexCacheUnused(t, nextSchema)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWriterEqualityIndexRollbackAndCallbackErrors(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			store := openIndexTestStore(t, backend)
			t.Cleanup(func() { _ = store.Close() })
			schema := &writerIndexValidationPoison{indexTestSchema: indexTestSchema{config: indexTestCNConfig()}, current: true}
			if err := store.Update(t.Context(), func(writer Writer) error {
				return WriterInPartitionWithNormalizer(writer, "db", schema).Put(indexTestEntry("uid=alice,dc=example", "Alice", "alice"), false)
			}); err != nil {
				t.Fatal(err)
			}
			rollback := errors.New("rollback live indexed query")
			err := store.Update(t.Context(), func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
				if err := indexed.Delete(mustDN(t, "uid=alice,dc=example")); err != nil {
					return err
				}
				if err := indexed.Put(indexTestEntry("uid=bob,dc=example", "Bob", "bob"), false); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Alice"), true)
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Bob"), true, "uid=bob,dc=example")
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("rollback = %v", err)
			}
			if err := store.Update(t.Context(), func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Alice"), true, "uid=alice,dc=example")
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Bob"), true)
				callbackError := errors.New("stop indexed callback")
				calls := 0
				planned, count, err := ForEachFilterCandidate(indexed, writerIndexEquality("cn", "Alice"), func(directory.Entry) error {
					calls++
					return callbackError
				})
				if !planned || calls != 1 || count != 0 || !errors.Is(err, callbackError) {
					t.Fatalf("callback planned=%v calls=%d count=%d error=%v", planned, calls, count, err)
				}
				requireWriterIndexCacheUnused(t, schema)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWriterEqualityIndexCancellationAndFallback(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			store := openIndexTestStore(t, backend)
			t.Cleanup(func() { _ = store.Close() })
			schema := &writerIndexValidationPoison{indexTestSchema: indexTestSchema{config: indexTestCNConfig()}, current: true}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			err := store.Update(ctx, func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
				if err := indexed.Put(indexTestEntry("uid=alice,dc=example", "Alice", "alice"), false); err != nil {
					return err
				}
				requireWriterIndexCandidates(t, indexed, writerIndexEquality("cn", "Alice"), true, "uid=alice,dc=example")
				requireWriterIndexCandidates(t, WriterInPartitionWithNormalizer(writer, "db", testDNNormalizer{}), writerIndexEquality("cn", "Alice"), false)
				requireWriterIndexCandidates(t, WriterInPartition(writer, "db"), writerIndexEquality("cn", "Alice"), false)
				cancel()
				planned, count, err := ForEachFilterCandidate(indexed, writerIndexEquality("cn", "Alice"), func(directory.Entry) error {
					t.Fatal("canceled writer invoked a callback")
					return nil
				})
				if planned || count != 0 || !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled query planned=%v count=%d error=%v", planned, count, err)
				}
				requireWriterIndexCacheUnused(t, schema)
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled transaction = %v", err)
			}
		})
	}
}
