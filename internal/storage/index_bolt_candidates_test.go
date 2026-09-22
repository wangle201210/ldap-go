package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func newBoltCandidateStore(t testing.TB, count int) (*Bolt, indexTestSchema, directory.Filter) {
	t.Helper()
	store, err := OpenBolt(filepath.Join(t.TempDir(), "candidates.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	schema := indexTestSchema{config: indexTestCNConfig()}
	schema.config.Attributes = append(schema.config.Attributes, EqualityIndexAttribute{
		Attribute: "0.9.2342.19200300.100.1.1", EqualityRule: "caseignorematch", Equality: true,
	})
	if err := UpdateBulk(context.Background(), store, func(writer Writer) error {
		indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
		for i := 0; i < count; i++ {
			entry := benchmarkBinaryEntryCodecEntry()
			entry.DN = fmt.Sprintf("uid=user%06d,dc=example", i)
			entry.Attributes[1].Values = [][]byte{[]byte(fmt.Sprintf("user%06d", i))}
			entry.Attributes[2].Values = [][]byte{[]byte("shared")}
			for _, name := range []string{
				"createTimestamp", "modifyTimestamp", "entryCSN", "entryUUID",
				"creatorsName", "modifiersName", "structuralObjectClass", "subschemaSubentry",
			} {
				entry.Attributes = append(entry.Attributes, directory.Attribute{
					Description: name, Values: [][]byte{[]byte("benchmark")}, RawNormalized: true,
				})
			}
			if err := indexed.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("shared"),
	}
}

func boltCandidateReferences(t testing.TB, tx *boltTx) []string {
	t.Helper()
	refs, err := tx.equalityIndexPostings("db", "2.5.4.3", equalityIndexValue, []byte("shared"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(refs)
	return refs
}

func boltCandidateKey(t testing.TB, tx *boltTx, reference string) []byte {
	t.Helper()
	partition, identity, err := decodeEqualityIndexEntryReference(tx.equalityIndexRefs.Get([]byte(reference)))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(partitionedEntryKey(partition, identity))
}

func TestBoltEqualityCandidatesOrderStopAndOwnership(t *testing.T) {
	for _, format := range []string{"v1", "v2", "v3", "json", "mixed"} {
		t.Run(format, func(t *testing.T) {
			store, schema, filter := newBoltCandidateStore(t, minEncodedEqualityIndexCandidates+1)
			if err := store.Update(context.Background(), func(writer Writer) error {
				tx := writer.(*boltTx)
				for i, ref := range boltCandidateReferences(t, tx) {
					key := boltCandidateKey(t, tx, ref)
					_, identity := splitPartitionedEntryKey(string(key))
					stored, err := decodeStoredEntry(tx.entries.Get(key))
					if err != nil {
						return err
					}
					entryFormat := format
					if format == "mixed" {
						entryFormat = []string{"v1", "v2", "v3"}[i%3]
					}
					encoded := encodeCandidateTestEntry(t, stored.Entry, identity, entryFormat)
					if err := tx.entries.Put(key, encoded); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			var retained, want []directory.Entry
			if err := store.View(context.Background(), func(reader Reader) error {
				tx := reader.(*boltTx)
				scoped := ReaderInPartitionWithNormalizer(indexMaintenanceReader{Reader: reader}, "db", schema).(schemaAwarePartitionReader)
				_, lazy, err := tx.prevalidateEqualityIndexCandidates("db", boltCandidateReferences(t, tx))
				if err != nil || lazy != (format != "json") {
					t.Fatalf("lazy/error = %v/%v for %s", lazy, err, format)
				}
				want, _, err = scoped.planEqualityIndexCandidates(filter)
				if err != nil {
					return err
				}
				stop := errors.New("callback stop")
				for _, stopAt := range []int{1, 4, 9, 0} {
					var got []directory.Entry
					planned, count, err := ForEachFilterCandidate(scoped, filter, func(entry directory.Entry) error {
						got = append(got, entry)
						if len(got) == stopAt {
							return stop
						}
						return nil
					})
					wantCount, wantErr := len(want), error(nil)
					if stopAt != 0 {
						wantCount, wantErr = stopAt-1, stop
					}
					if !planned || count != wantCount || err != wantErr || !reflect.DeepEqual(got, want[:len(got)]) {
						t.Fatalf("stop %d: planned/count/err = %v/%d/%v; entries match = %v", stopAt, planned, count, err, reflect.DeepEqual(got, want[:len(got)]))
					}
					if stopAt == 0 {
						retained = got
					}
				}
				// Mutating and appending one value cannot reach another value or Bolt.
				second := bytes.Clone(retained[0].Attributes[0].Values[1])
				retained[0].Attributes[0].Values[0][0] ^= 0xff
				retained[0].Attributes[0].Values[0] = append(retained[0].Attributes[0].Values[0], "extended"...)
				if !bytes.Equal(retained[0].Attributes[0].Values[1], second) {
					t.Fatal("appending value changed adjacent value")
				}
				fresh, _, err := scoped.planEqualityIndexCandidates(filter)
				if err != nil || !reflect.DeepEqual(fresh, want) {
					t.Fatalf("callback mutation changed stored entries: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Unmap Bolt before inspecting every retained value and identity hint.
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(retained[1:], want[1:]) {
				t.Fatal("retained entries changed after transaction and database close")
			}
			for _, entry := range retained {
				if identity, ok := entry.DNIdentity(); !ok || identity == "" {
					t.Fatal("lost owned identity")
				}
			}
		})
	}
}

func TestBoltEqualityCandidatesPreCallbackErrors(t *testing.T) {
	markerKey := genericMetadataKey(schemaAwareDNMigrationMetadataKey("db"))
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *boltTx, []string) error
	}{
		{"missing-reference", func(t *testing.T, tx *boltTx, refs []string) error {
			return tx.equalityIndexRefs.Delete([]byte(refs[len(refs)-1]))
		}},
		{"invalid-reference-id", func(t *testing.T, tx *boltTx, refs []string) error {
			key := equalityIndexPostingKey("db", "2.5.4.3", equalityIndexValue, []byte("shared"), string(bytes.Repeat([]byte{0xff}, 9)))
			return tx.equalityIndexes.Put(key, nil)
		}},
		{"truncated-reference", func(t *testing.T, tx *boltTx, refs []string) error {
			return tx.equalityIndexRefs.Put([]byte(refs[len(refs)-1]), []byte{0})
		}},
		{"trailing-reference", func(t *testing.T, tx *boltTx, refs []string) error {
			ref := []byte(refs[len(refs)-1])
			return tx.equalityIndexRefs.Put(ref, append(bytes.Clone(tx.equalityIndexRefs.Get(ref)), 0))
		}},
		{"cross-partition", func(t *testing.T, tx *boltTx, refs []string) error {
			return tx.equalityIndexRefs.Put([]byte(refs[len(refs)-1]), encodeEqualityIndexEntryReference("other", "dn:v2:key"))
		}},
		{"missing-entry", func(t *testing.T, tx *boltTx, refs []string) error {
			return tx.entries.Delete(boltCandidateKey(t, tx, refs[len(refs)-1]))
		}},
		{"invalid-marker-before-entry", func(t *testing.T, tx *boltTx, refs []string) error {
			if err := tx.entries.Put(boltCandidateKey(t, tx, refs[0]), []byte("bad")); err != nil {
				return err
			}
			return tx.meta.Put(markerKey, []byte{99})
		}},
		{"missing-marker-checks-binding", func(t *testing.T, tx *boltTx, refs []string) error {
			key := boltCandidateKey(t, tx, refs[len(refs)-1])
			stored, err := decodeStoredEntry(tx.entries.Get(key))
			if err != nil {
				return err
			}
			if err := tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, "dn:v2:wrong", "v2")); err != nil {
				return err
			}
			return tx.meta.Delete(markerKey)
		}},
		{"earlier-entry-before-late-reference", func(t *testing.T, tx *boltTx, refs []string) error {
			if err := tx.entries.Put(boltCandidateKey(t, tx, refs[0]), []byte("bad entry")); err != nil {
				return err
			}
			return tx.equalityIndexRefs.Delete([]byte(refs[len(refs)-1]))
		}},
		{"legacy-reference-before-late-corruption", func(t *testing.T, tx *boltTx, refs []string) error {
			if err := tx.entries.Put(boltCandidateKey(t, tx, refs[len(refs)-1]), []byte("bad entry")); err != nil {
				return err
			}
			return tx.equalityIndexRefs.Put([]byte(refs[0]), encodeEqualityIndexEntryReference("db", "invalid dn"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, schema, filter := newBoltCandidateStore(t, minEncodedEqualityIndexCandidates+1)
			if err := store.Update(context.Background(), func(writer Writer) error {
				tx := writer.(*boltTx)
				return test.mutate(t, tx, boltCandidateReferences(t, tx))
			}); err != nil {
				t.Fatal(err)
			}
			assertBoltCandidateErrorBeforeCallback(t, store, schema, filter)
		})
	}
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		for _, damage := range []string{"truncated", "trailing", "invalid-payload"} {
			t.Run(format+"/"+damage, func(t *testing.T) {
				store, schema, filter := newBoltCandidateStore(t, minEncodedEqualityIndexCandidates+1)
				if err := store.Update(context.Background(), func(writer Writer) error {
					tx := writer.(*boltTx)
					refs := boltCandidateReferences(t, tx)
					key := boltCandidateKey(t, tx, refs[len(refs)-1])
					stored, err := decodeStoredEntry(tx.entries.Get(key))
					if err != nil {
						return err
					}
					_, identity := splitPartitionedEntryKey(string(key))
					value := encodeCandidateTestEntry(t, stored.Entry, identity, format)
					switch damage {
					case "truncated":
						value = value[:len(value)-1]
					case "trailing":
						value = append(value, 0xff)
					case "invalid-payload":
						if format == "json" {
							value = []byte(`{"attributes":[{"values":["invalid base64!"]}]}`)
						} else if format == "v3" {
							value[6] = 0xff
							value[7] = 0xff // Bits beyond the 14 attributes.
						} else {
							value[5] = 0xff // DN field length.
						}
					}
					return tx.entries.Put(key, value)
				}); err != nil {
					t.Fatal(err)
				}
				assertBoltCandidateErrorBeforeCallback(t, store, schema, filter)
			})
		}
	}
}

func assertBoltCandidateErrorBeforeCallback(t *testing.T, store *Bolt, schema indexTestSchema, filter directory.Filter) {
	t.Helper()
	if err := store.View(context.Background(), func(reader Reader) error {
		scoped := ReaderInPartitionWithNormalizer(reader, "db", schema).(schemaAwarePartitionReader)
		_, wantPlanned, wantErr := scoped.planEqualityIndexCandidates(filter)
		if wantErr == nil {
			t.Fatal("corruption fixture was accepted by eager planner")
		}
		calls := 0
		planned, count, err := ForEachFilterCandidate(scoped, filter, func(directory.Entry) error {
			calls++
			return errors.New("stop before late corruption")
		})
		if planned != wantPlanned || calls != 0 || count != 0 || err == nil || err.Error() != wantErr.Error() || reflect.TypeOf(err) != reflect.TypeOf(wantErr) {
			t.Fatalf("planned/calls/count/error = %v/%d/%d/%v, want %v/0/0/%v", planned, calls, count, err, wantPlanned, wantErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoltEqualityCandidatesCancellation(t *testing.T) {
	const size = minEncodedEqualityIndexCandidates + 1
	store, schema, filter := newBoltCandidateStore(t, size)
	if err := store.View(context.Background(), func(reader Reader) error {
		tx := reader.(*boltTx)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		tx.ctx = ctx
		scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
		calls := 0
		planned, count, err := ForEachFilterCandidate(scoped, filter, func(directory.Entry) error {
			calls++
			cancel()
			return nil
		})
		if !planned || count != size || calls != size || err != nil {
			t.Fatalf("cancellation during callbacks = %v/%d/%d/%v", planned, count, calls, err)
		}
		planned, count, err = ForEachFilterCandidate(scoped, filter, func(directory.Entry) error {
			t.Fatal("callback after prevalidation cancellation")
			return nil
		})
		if planned || count != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-callback cancellation = %v/%d/%v", planned, count, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoltEqualityCandidatesFallbacks(t *testing.T) {
	for _, mode := range []string{"write-transaction", "missing-marker", "display-reference", "legacy-entry", "mixed-json", "and-filter", "presence-filter", "missing-config", "stale-config"} {
		t.Run(mode, func(t *testing.T) {
			const size = minEncodedEqualityIndexCandidates + 1
			store, schema, filter := newBoltCandidateStore(t, size)
			if err := store.Update(context.Background(), func(writer Writer) error {
				tx := writer.(*boltTx)
				refs := boltCandidateReferences(t, tx)
				ref := []byte(refs[len(refs)-1])
				key := boltCandidateKey(t, tx, string(ref))
				stored, err := decodeStoredEntry(tx.entries.Get(key))
				if err != nil {
					return err
				}
				switch mode {
				case "missing-marker":
					return tx.meta.Delete(genericMetadataKey(schemaAwareDNMigrationMetadataKey("db")))
				case "display-reference", "legacy-entry":
					if mode == "legacy-entry" {
						dn, err := directory.ParseDN(stored.DN)
						if err != nil {
							return err
						}
						value, err := encodeEntry(stored.Entry, "", "")
						if err != nil {
							return err
						}
						if err := tx.entries.Put([]byte(partitionedEntryKey("db", dn.Key())), value); err != nil {
							return err
						}
						if err := tx.entries.Delete(key); err != nil {
							return err
						}
					}
					return tx.equalityIndexRefs.Put(ref, encodeEqualityIndexEntryReference("db", stored.DN))
				case "mixed-json":
					_, identity := splitPartitionedEntryKey(string(key))
					return tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, "json"))
				case "and-filter":
					filter = directory.Filter{Kind: directory.FilterAnd, Children: []directory.Filter{filter}}
				case "presence-filter":
					filter = directory.Filter{Kind: directory.FilterPresent, Attribute: "cn"}
				case "missing-config":
					return tx.equalityIndexConfigs.Delete([]byte("db"))
				case "stale-config":
					return tx.equalityIndexConfigs.Put([]byte("db"), []byte(`{"version":1}`))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			visit := func(reader Reader) error {
				tx := reader.(*boltTx)
				scoped := ReaderInPartitionWithNormalizer(reader, "db", schema).(schemaAwarePartitionReader)
				if mode != "and-filter" && mode != "presence-filter" && mode != "missing-config" && mode != "stale-config" {
					if _, valid, err := tx.prevalidateEqualityIndexCandidates("db", boltCandidateReferences(t, tx)); valid || err != nil {
						t.Fatalf("fallback eligibility/error = %v/%v", valid, err)
					}
				}
				want, wantPlanned, err := scoped.planEqualityIndexCandidates(filter)
				if err != nil {
					return err
				}
				var got []directory.Entry
				planned, count, err := ForEachFilterCandidate(scoped, filter, func(entry directory.Entry) error {
					got = append(got, entry)
					if mode == "write-transaction" && len(got) == 1 {
						// The eager snapshot must survive callback mutation of a later entry.
						refs := boltCandidateReferences(t, tx)
						return tx.entries.Delete(boltCandidateKey(t, tx, refs[len(refs)-1]))
					}
					return nil
				})
				if err != nil || planned != wantPlanned || count != len(want) || !reflect.DeepEqual(got, want) {
					t.Fatalf("fallback planned/count/error = %v/%d/%v; want %v/%d; entries match = %v", planned, count, err, wantPlanned, len(want), reflect.DeepEqual(got, want))
				}
				return nil
			}
			var err error
			if mode == "write-transaction" {
				err = store.Update(context.Background(), func(writer Writer) error { return visit(writer) })
			} else {
				err = store.View(context.Background(), visit)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Cancel at deterministic storage read boundaries, including within reference
// validation, to compare the original planner's planned flag and callback count.
type candidateCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (ctx *candidateCancelContext) Err() error {
	ctx.remaining--
	if ctx.remaining == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestBoltEqualityCandidatesCancellationBoundaries(t *testing.T) {
	for _, mode := range []string{"binary", "late-json", "early-corrupt", "late-corrupt"} {
		t.Run(mode, func(t *testing.T) {
			store, schema, filter := newBoltCandidateStore(t, minEncodedEqualityIndexCandidates+1)
			if mode != "binary" {
				if err := store.Update(context.Background(), func(writer Writer) error {
					tx := writer.(*boltTx)
					refs := boltCandidateReferences(t, tx)
					index := len(refs) - 1
					if mode == "early-corrupt" {
						index = 0
					}
					key := boltCandidateKey(t, tx, refs[index])
					value := tx.entries.Get(key)
					if mode == "late-json" {
						stored, err := decodeStoredEntry(value)
						if err != nil {
							return err
						}
						_, identity := splitPartitionedEntryKey(string(key))
						value = encodeCandidateTestEntry(t, stored.Entry, identity, "json")
					} else {
						value = bytes.Clone(value[:len(value)-1])
					}
					return tx.entries.Put(key, value)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.View(context.Background(), func(reader Reader) error {
				tx := reader.(*boltTx)
				for _, cancelAt := range []int{1, 2, 3, 64, 130, 132, 133, 134, 200, 261, 262, 263, 264, 1000} {
					var wantPlanned bool
					var wantCount, wantRemaining int
					var wantErr error
					for _, eager := range []bool{true, false} {
						ctx, cancel := context.WithCancel(context.Background())
						checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
						tx.ctx = checked
						scoped := ReaderInPartitionWithNormalizer(reader, "db", schema).(schemaAwarePartitionReader)
						if eager {
							entries, planned, err := scoped.planEqualityIndexCandidates(filter)
							wantPlanned, wantCount, wantErr = planned, len(entries), err
							wantRemaining = checked.remaining
						} else {
							calls := 0
							planned, count, err := ForEachFilterCandidate(scoped, filter, func(directory.Entry) error { calls++; return nil })
							if planned != wantPlanned || count != wantCount || calls != wantCount ||
								fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) ||
								checked.remaining != wantRemaining {
								t.Errorf("cancel at %d: planned/count/calls/error/remaining = %v/%d/%d/%v/%d; want %v/%d/%d/%v/%d", cancelAt, planned, count, calls, err, checked.remaining, wantPlanned, wantCount, wantCount, wantErr, wantRemaining)
							}
						}
						cancel()
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type candidateDoneCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	cancelAt  int
	doneCalls int
}

func (ctx *candidateDoneCancelContext) Done() <-chan struct{} {
	ctx.doneCalls++
	if ctx.doneCalls == ctx.cancelAt {
		ctx.cancel()
	}
	return ctx.Context.Done()
}

func TestBoltEqualityCandidatesCancellationDuringPrevalidation(t *testing.T) {
	const size = minEncodedEqualityIndexCandidates + 1
	store, schema, filter := newBoltCandidateStore(t, size)
	if err := store.View(context.Background(), func(reader Reader) error {
		tx := reader.(*boltTx)
		for _, cancelAt := range []int{1, 3, size + 1, size + 2, size + 4, 2*size + 1} {
			ctx, cancel := context.WithCancel(context.Background())
			polled := &candidateDoneCancelContext{Context: ctx, cancel: cancel, cancelAt: cancelAt}
			tx.ctx = polled
			scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
			calls := 0
			planned, count, err := ForEachFilterCandidate(scoped, filter, func(directory.Entry) error { calls++; return nil })
			cancel()
			if !planned || count != 0 || calls != 0 || !errors.Is(err, context.Canceled) || polled.doneCalls != cancelAt {
				t.Fatalf("cancel at Done poll %d: planned/count/calls/error/polls = %v/%d/%d/%v/%d", cancelAt, planned, count, calls, err, polled.doneCalls)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkBoltBroadEqualityCandidates(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("N=%d", size), func(b *testing.B) {
			store, schema, filter := newBoltCandidateStore(b, size)
			benchmarkBoltEqualityCandidates(b, store, schema, filter, size)
		})
	}
}

func benchmarkBoltEqualityCandidates(b *testing.B, store *Bolt, schema indexTestSchema, filter directory.Filter, size int) {
	b.Helper()
	for _, stopFirst := range []bool{false, true} {
		b.Run(fmt.Sprintf("StopFirst=%v", stopFirst), func(b *testing.B) {
			stop := errors.New("stop")
			b.ReportAllocs()
			for b.Loop() {
				if err := store.View(context.Background(), func(reader Reader) error {
					scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
					planned, count, err := ForEachFilterCandidate(scoped, filter, func(entry directory.Entry) error {
						if len(entry.Attributes) != 14 {
							b.Fatal("unexpected entry")
						}
						if stopFirst {
							return stop
						}
						return nil
					})
					if stopFirst && planned && count == 0 && err == stop || !stopFirst && planned && count == size && err == nil {
						return nil
					}
					return fmt.Errorf("planned/count/error = %v/%d/%v", planned, count, err)
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	for _, matches := range []int{0, 1} {
		b.Run(fmt.Sprintf("UIDMatches=%d", matches), func(b *testing.B) {
			assertion := "missing"
			if matches == 1 {
				assertion = "user000000"
			}
			filter := directory.Filter{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte(assertion)}
			b.ReportAllocs()
			for b.Loop() {
				if err := store.View(context.Background(), func(reader Reader) error {
					planned, count, err := ForEachFilterCandidate(ReaderInPartitionWithNormalizer(reader, "db", schema), filter, func(directory.Entry) error { return nil })
					if err != nil || !planned || count != matches {
						return fmt.Errorf("planned/count/error = %v/%d/%v", planned, count, err)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBoltBroadEqualityCandidateHeap(b *testing.B) {
	store, schema, filter := newBoltCandidateStore(b, 100000)
	stop := errors.New("stop")
	var retained int64
	for b.Loop() {
		// Clear both generations of fixture-related sync.Pool storage.
		runtime.GC()
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		if err := store.View(context.Background(), func(reader Reader) error {
			scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
			planned, count, err := ForEachFilterCandidate(scoped, filter, func(entry directory.Entry) error {
				runtime.GC()
				var during runtime.MemStats
				runtime.ReadMemStats(&during)
				retained = int64(during.HeapAlloc) - int64(before.HeapAlloc)
				runtime.KeepAlive(entry)
				return stop
			})
			if !planned || count != 0 || err != stop {
				return fmt.Errorf("planned/count/error = %v/%d/%v", planned, count, err)
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(retained), "live-B")
}
