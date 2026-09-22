package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type boltModifyReadOnlySchema struct {
	indexTestSchema
}

func (boltModifyReadOnlySchema) IndexEntryValuesReadOnly() bool { return true }

type boltModifyReuseSchema struct {
	boltModifyReadOnlySchema
	calls    []string
	failAt   int
	failure  error
	cancelAt int
	cancel   context.CancelFunc
}

func (schema *boltModifyReuseSchema) EqualityIndexValues(entry directory.Entry, attribute string) ([][]byte, error) {
	schema.calls = append(schema.calls, string(entry.Attributes[0].Values[0]))
	if len(schema.calls) == schema.failAt {
		return nil, schema.failure
	}
	if len(schema.calls) == schema.cancelAt {
		schema.cancel()
	}
	return schema.indexTestSchema.EqualityIndexValues(entry, attribute)
}

func newBoltModifyReuseFixture(t testing.TB, photoBytes int) (*Bolt, indexTestSchema, directory.Entry) {
	t.Helper()
	store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	schema := indexTestSchema{config: indexTestCNConfig()}
	entry := indexTestEntry("uid=alice,dc=example", "Alice", "alice")
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "jpegPhoto", Values: [][]byte{bytes.Repeat([]byte{0xff}, photoBytes)},
	})
	if err := store.Update(t.Context(), func(writer Writer) error {
		return WriterInPartitionWithNormalizer(writer, "db", schema).Put(entry, false)
	}); err != nil {
		t.Fatal(err)
	}
	return store, schema, entry
}

func boltModifyReuseSnapshot(t *testing.T, store *Bolt) map[string]map[string][]byte {
	t.Helper()
	snapshot := make(map[string]map[string][]byte)
	if err := store.View(t.Context(), func(reader Reader) error {
		tx := reader.(*boltTx)
		for _, name := range [][]byte{entriesBucket, entryCountsBucket, metaBucket,
			equalityIndexBucket, equalityIndexConfigBucket, equalityIndexRefBucket} {
			values := make(map[string][]byte)
			if err := tx.tx.Bucket(name).ForEach(func(key, value []byte) error {
				values[string(key)] = bytes.Clone(value)
				return nil
			}); err != nil {
				return err
			}
			snapshot[string(name)] = values
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestBoltIndexedModifyReuseSnapshots(t *testing.T) {
	for _, value := range []string{"Bobby", " ALICE "} {
		t.Run(value, func(t *testing.T) {
			store, baseSchema, before := newBoltModifyReuseFixture(t, 64<<10)
			schema := &boltModifyReuseSchema{boltModifyReadOnlySchema: boltModifyReadOnlySchema{baseSchema}}
			after := before.Clone()
			after.Attributes[0].Values[0] = []byte(value)
			after.Attributes[2].Values[0][0] = 42
			after.Attributes[2].RawNormalized = true
			var retainedBefore, retainedAfter directory.Entry
			if err := store.Update(t.Context(), func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
				dn := mustDN(t, before.DN)
				var err error
				retainedBefore, err = indexed.Get(dn)
				if err != nil {
					return err
				}
				if err := indexed.Put(after, true); err != nil {
					return err
				}
				retainedAfter, err = indexed.Get(dn)
				assertPartitionEntryCount(t, writer, "db", 1)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			wantCalls := []string{"Alice", value}
			if value == "Bobby" {
				wantCalls = append(wantCalls, "Alice", value)
			}
			if !reflect.DeepEqual(schema.calls, wantCalls) {
				t.Fatalf("normalization calls = %v, want %v", schema.calls, wantCalls)
			}
			if !reflect.DeepEqual(retainedBefore.Attributes, before.Attributes) ||
				!reflect.DeepEqual(retainedAfter.Attributes, after.Attributes) {
				t.Fatal("replacement changed the retained before/after entry snapshots")
			}
			retainedBefore.Attributes[2].Values[0][0] = 10
			retainedAfter.Attributes[2].Values[0][0] = 20
			if err := store.View(t.Context(), func(reader Reader) error {
				got, err := ReaderInPartitionWithNormalizer(reader, "db", baseSchema).Get(mustDN(t, before.DN))
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got.Attributes, after.Attributes) {
					t.Fatal("retained entry values alias persisted data")
				}
				assertPartitionEntryCount(t, reader, "db", 1)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			assertIndexDNs(t, store, baseSchema, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte(value),
			}, true, []string{before.DN})
			if value == "Bobby" {
				assertIndexDNs(t, store, baseSchema, directory.Filter{
					Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Alice"),
				}, true, nil)
			}
			assertIndexPlanMatchesScan(t, store, baseSchema, directory.Filter{
				Kind: directory.FilterPresent, Attribute: "cn",
			}, true)
		})
	}
}

func TestBoltIndexedModifyReuseRollback(t *testing.T) {
	for _, test := range []struct {
		name      string
		failAt    int
		cancelAt  int
		rollback  bool
		corrupt   bool
		wantCalls int
	}{
		{name: "old terms", failAt: 1, wantCalls: 1},
		{name: "new terms", failAt: 2, wantCalls: 2},
		{name: "removal terms", failAt: 3, wantCalls: 3},
		{name: "insertion terms", failAt: 4, wantCalls: 4},
		{name: "cancel before deletion", cancelAt: 2, wantCalls: 3},
		{name: "cancel after insertion", cancelAt: 4, wantCalls: 4},
		{name: "caller rollback", rollback: true, wantCalls: 4},
		{name: "corruption before normalization", corrupt: true, failAt: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, baseSchema, before := newBoltModifyReuseFixture(t, 64<<10)
			initial := boltModifyReuseSnapshot(t, store)
			revision, _ := store.CurrentStorageSnapshotRevision()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("injected normalization failure")
			rollback := errors.New("caller rollback")
			schema := &boltModifyReuseSchema{
				boltModifyReadOnlySchema: boltModifyReadOnlySchema{baseSchema}, failAt: test.failAt, failure: failure,
				cancelAt: test.cancelAt, cancel: cancel,
			}
			after := before.Clone()
			after.Attributes[0].Values[0] = []byte("Bobby")
			var corruptionError error
			err := store.Update(ctx, func(writer Writer) error {
				if test.corrupt {
					dn, err := directory.ParseDNWithNormalizer(before.DN, baseSchema)
					if err != nil {
						return err
					}
					tx := writer.(*boltTx)
					key := []byte(partitionedEntryKey("db", dn.Key()))
					encoded := append(bytes.Clone(tx.entries.Get(key)), 0)
					_, corruptionError = decodeAndValidateEntry(dn.Key(), encoded)
					if corruptionError == nil {
						t.Fatal("fixture did not corrupt the stored entry")
					}
					if err := tx.entries.Put(key, encoded); err != nil {
						return err
					}
				}
				if err := WriterInPartitionWithNormalizer(writer, "db", schema).Put(after, true); err != nil {
					return err
				}
				if test.rollback {
					return rollback
				}
				return nil
			})
			switch {
			case test.corrupt:
				if err == nil || err.Error() != corruptionError.Error() {
					t.Fatalf("error = %v, want original validation error %v", err, corruptionError)
				}
			case test.failAt != 0:
				want := fmt.Sprintf("normalize entry %q equality index 2.5.4.3: %v", before.DN, failure)
				if !errors.Is(err, failure) || err.Error() != want {
					t.Fatalf("error = %v, want %s", err, want)
				}
			case test.cancelAt != 0:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want cancellation", err)
				}
			case test.rollback:
				if !errors.Is(err, rollback) {
					t.Fatalf("error = %v, want rollback", err)
				}
			}
			wantCalls := []string{"Alice", "Bobby", "Alice", "Bobby"}[:test.wantCalls]
			if len(schema.calls) != len(wantCalls) || len(wantCalls) > 0 && !reflect.DeepEqual(schema.calls, wantCalls) {
				t.Fatalf("normalization calls = %v, want %v", schema.calls, wantCalls)
			}
			if !reflect.DeepEqual(boltModifyReuseSnapshot(t, store), initial) {
				t.Fatal("failed replacement changed entries, counts, indexes, references, or metadata")
			}
			if got, _ := store.CurrentStorageSnapshotRevision(); got != revision {
				t.Fatalf("failed replacement advanced revision from %d to %d", revision, got)
			}
		})
	}
}

type boltModifyMutatingSchema struct {
	indexTestSchema
	mutate func(directory.Entry)
	calls  int
}

func (schema *boltModifyMutatingSchema) EqualityIndexValues(entry directory.Entry, attribute string) ([][]byte, error) {
	values, err := schema.indexTestSchema.EqualityIndexValues(entry, attribute)
	schema.calls++
	if schema.calls == 1 {
		schema.mutate(entry)
	}
	return values, err
}

func TestBoltIndexedModifyReuseUnknownSchemaMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(directory.Entry)
	}{
		{"value bytes", func(entry directory.Entry) { entry.Attributes[0].Values[0][0] = 'X' }},
		{"attribute descriptor", func(entry directory.Entry) { entry.Attributes[0].Description = "description" }},
		{"value descriptor", func(entry directory.Entry) { entry.Attributes[0].Values[0] = []byte("Changed") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, baseSchema, before := newBoltModifyReuseFixture(t, 1024)
			schema := &boltModifyMutatingSchema{indexTestSchema: baseSchema, mutate: test.mutate}
			after := before.Clone()
			after.Attributes[0].Values[0] = []byte("Bobby")
			if err := store.Update(t.Context(), func(writer Writer) error {
				return WriterInPartitionWithNormalizer(writer, "db", schema).Put(after, true)
			}); err != nil {
				t.Fatal(err)
			}
			if schema.calls != 4 {
				t.Fatalf("normalization calls = %d, want 4", schema.calls)
			}
			assertIndexDNs(t, store, baseSchema, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Alice"),
			}, true, nil)
			assertIndexDNs(t, store, baseSchema, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Bobby"),
			}, true, []string{before.DN})
		})
	}
}

func BenchmarkBoltIndexedModifyDecodeReuse(b *testing.B) {
	for _, photoBytes := range []int{1024, 64 << 10} {
		b.Run(fmt.Sprintf("photo=%d", photoBytes), func(b *testing.B) {
			store, baseSchema, before := newBoltModifyReuseFixture(b, photoBytes)
			schema := boltModifyReadOnlySchema{baseSchema}
			dn, err := directory.ParseDNWithNormalizer(before.DN, schema)
			if err != nil {
				b.Fatal(err)
			}
			after := [2]directory.Entry{before.Clone(), before.Clone()}
			after[0].Attributes[0].Values[0] = []byte("Bobby")
			after[1].Attributes[0].Values[0] = []byte("Carol")
			version := 0
			b.ReportAllocs()
			for b.Loop() {
				// Rollback excludes durable commit cost; both values differ from
				// the seeded Alice posting and exercise the changed-terms branch.
				tx, err := store.db.Begin(true)
				if err != nil {
					b.Fatal(err)
				}
				writer := newBoltTx(b.Context(), tx)
				writeErr := writer.putInWithEqualityIndexes("db", after[version], dn, true, schema)
				rollbackErr := tx.Rollback()
				if writeErr != nil || rollbackErr != nil {
					b.Fatalf("replace: %v; rollback: %v", writeErr, rollbackErr)
				}
				version ^= 1
			}
		})
	}
}
