package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type readOnlyCandidateIterator func(Reader, directory.Filter, func(directory.Entry) error) (bool, int, error)

func readOnlyCandidateProjections(entry directory.Entry) []directory.Entry {
	return []directory.Entry{
		entry.Select([]string{"cn", "uid"}, false),
		entry.Select([]string{"*"}, false),
		entry.Select([]string{"*"}, true),
		entry.Select([]string{"1.1"}, false),
	}
}

func TestReadOnlyCandidatePipelineProjectionAfterUnmap(t *testing.T) {
	for _, mode := range []string{"v1", "v2", "v3", "json", "mixed", "dense", "small", "threshold"} {
		t.Run(mode, func(t *testing.T) {
			size := minEncodedEqualityIndexCandidates + 1
			if mode == "small" {
				size = minEncodedEqualityIndexCandidates - 1
			} else if mode == "threshold" {
				size = minEncodedEqualityIndexCandidates
			}
			store, schema, filter := newBoltCandidateStore(t, size)
			if err := store.Update(context.Background(), func(writer Writer) error {
				tx := writer.(*boltTx)
				for i, reference := range boltCandidateReferences(t, tx) {
					key := boltCandidateKey(t, tx, reference)
					stored, err := decodeStoredEntry(tx.entries.Get(key))
					if err != nil {
						return err
					}
					stored.Attributes = append(stored.Attributes,
						directory.Attribute{Description: "Description;lang-EN", Values: [][]byte{nil, {}, {0, 0xff}}},
						directory.Attribute{Description: "description;LANG-en", RawNormalized: true},
					)
					format := mode
					switch mode {
					case "mixed", "dense":
						format = []string{"v3", "v2", "v1"}[i%3]
						if mode == "dense" && i%3 == 1 {
							for range 2 {
								stored.Attributes = append(stored.Attributes, directory.Attribute{
									Description: "dense", Values: make([][]byte, 65),
								})
							}
							format = "v3"
						}
					case "small", "threshold":
						format = "v3"
					}
					_, identity := splitPartitionedEntryKey(string(key))
					if err := tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, format)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			var retained, wantClones []directory.Entry
			var projections, wantProjections [][]directory.Entry
			if err := store.View(context.Background(), func(reader Reader) error {
				tx := reader.(*boltTx)
				scoped := ReaderInPartitionWithNormalizer(indexMaintenanceReader{Reader: reader}, "db", schema).(schemaAwarePartitionReader)
				want, planned, err := scoped.planEqualityIndexCandidates(filter)
				if err != nil || !planned || len(want) != size {
					t.Fatalf("owned plan = %v/%d/%v", planned, len(want), err)
				}
				original := make(map[string][]byte)
				for _, ref := range boltCandidateReferences(t, tx) {
					key := boltCandidateKey(t, tx, ref)
					original[string(key)] = bytes.Clone(tx.entries.Get(key))
				}
				for _, entry := range want {
					wantClones = append(wantClones, entry.Clone())
					wantProjections = append(wantProjections, readOnlyCandidateProjections(entry))
				}
				stop := errors.New("callback stop")
				for _, stopAt := range []int{1, 4, 0} {
					calls := 0
					planned, count, err := ForEachReadOnlyFilterCandidate(scoped, filter, func(entry directory.Entry) error {
						if !reflect.DeepEqual(entry, want[calls]) {
							t.Fatalf("callback %d differs from owned row", calls)
						}
						if stopAt == 0 {
							retained = append(retained, entry.Clone())
							projections = append(projections, readOnlyCandidateProjections(entry))
						}
						calls++
						if calls == stopAt {
							return stop
						}
						return nil
					})
					wantCount, wantCalls, wantErr := size, size, error(nil)
					if stopAt != 0 {
						wantCount, wantCalls, wantErr = stopAt-1, stopAt, stop
					}
					if !planned || count != wantCount || calls != wantCalls || err != wantErr {
						t.Fatalf("stop %d: planned/count/calls/error = %v/%d/%d/%v", stopAt, planned, count, calls, err)
					}
				}
				for key, value := range original {
					if !bytes.Equal(tx.entries.Get([]byte(key)), value) {
						t.Fatal("callback projection changed exact stored bytes")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(retained, wantClones) || !reflect.DeepEqual(projections, wantProjections) {
				t.Fatal("clones or projections changed after arena reuse and Bolt unmap")
			}
			for i := range retained {
				identity, ok := retained[i].DNIdentity()
				wantIdentity, _ := wantClones[i].DNIdentity()
				if !ok || identity != wantIdentity {
					t.Fatal("clone did not retain an owned identity")
				}
			}
			retained[0].Attributes[0].Values[0][0] ^= 0xff
			projections[0][1].Attributes[0].Values[0] = append(projections[0][1].Attributes[0].Values[0], "extension"...)
			if !reflect.DeepEqual(retained[1:], wantClones[1:]) || !reflect.DeepEqual(projections[1:], wantProjections[1:]) {
				t.Fatal("mutating owned output reached another row")
			}
		})
	}
}

func assertReadOnlyCandidateErrorParity(t *testing.T, reader Reader, filter directory.Filter, iterate readOnlyCandidateIterator) {
	t.Helper()
	var wantPlanned bool
	var wantErr error
	for i, visit := range []readOnlyCandidateIterator{ForEachFilterCandidate, iterate} {
		calls := 0
		planned, count, err := visit(reader, filter, func(directory.Entry) error {
			calls++
			return errors.New("callback before late corruption")
		})
		if calls != 0 || count != 0 || err == nil {
			t.Fatalf("corruption calls/count/error = %d/%d/%v", calls, count, err)
		}
		if i == 0 {
			wantPlanned, wantErr = planned, err
		} else if planned != wantPlanned || fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) {
			t.Fatalf("planned/error = %v/%v, want %v/%v", planned, err, wantPlanned, wantErr)
		}
	}
}

func TestReadOnlyCandidatePreCallbackErrors(t *testing.T) {
	for _, size := range []int{4, minEncodedEqualityIndexCandidates + 1} {
		for _, damage := range []string{"missing-reference", "cross-partition", "missing-entry", "bad-marker", "reference-after-bad-entry", "bad-flags", "v1", "v2", "v3", "json"} {
			t.Run(fmt.Sprintf("N%d/%s", size, damage), func(t *testing.T) {
				store, schema, filter := newBoltCandidateStore(t, size)
				if err := store.Update(context.Background(), func(writer Writer) error {
					tx := writer.(*boltTx)
					refs := boltCandidateReferences(t, tx)
					ref := []byte(refs[len(refs)-1])
					key := boltCandidateKey(t, tx, string(ref))
					switch damage {
					case "reference-after-bad-entry":
						if err := tx.entries.Put(boltCandidateKey(t, tx, refs[0]), []byte("bad entry")); err != nil {
							return err
						}
						fallthrough
					case "missing-reference":
						return tx.equalityIndexRefs.Delete(ref)
					case "cross-partition":
						return tx.equalityIndexRefs.Put(ref, encodeEqualityIndexEntryReference("other", "dn:v2:key"))
					case "missing-entry":
						return tx.entries.Delete(key)
					case "bad-marker":
						return tx.meta.Put(genericMetadataKey(schemaAwareDNMigrationMetadataKey("db")), []byte{99})
					}
					stored, err := decodeStoredEntry(tx.entries.Get(key))
					if err != nil {
						return err
					}
					_, identity := splitPartitionedEntryKey(string(key))
					encoded := encodeCandidateTestEntry(t, stored.Entry, identity, damage)
					if damage == "bad-flags" {
						encoded[7] = 0xff
					} else {
						encoded = encoded[:len(encoded)-1]
					}
					return tx.entries.Put(key, encoded)
				}); err != nil {
					t.Fatal(err)
				}
				if err := store.View(context.Background(), func(reader Reader) error {
					scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
					assertReadOnlyCandidateErrorParity(t, scoped, filter, ForEachReadOnlyFilterCandidate)
					if size == 4 {
						assertReadOnlyCandidateErrorParity(t, scoped, filter, func(r Reader, f directory.Filter, fn func(directory.Entry) error) (bool, int, error) {
							return ForEachBoundedReadOnlyFilterCandidate(r, f, 4, fn)
						})
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestReadOnlyCandidateCancellationParity(t *testing.T) {
	const size = minEncodedEqualityIndexCandidates + 1
	store, schema, filter := newBoltCandidateStore(t, size)
	if err := store.View(context.Background(), func(reader Reader) error {
		tx := reader.(*boltTx)
		scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
		for _, cancelAt := range []int{1, 2, 3, 64, 130, 132, 133, 134, 200, 261, 262, 263, 264, 1000} {
			var wantPlanned bool
			var wantCount, wantRemaining int
			var wantErr error
			for i, iterate := range []readOnlyCandidateIterator{ForEachFilterCandidate, ForEachReadOnlyFilterCandidate} {
				ctx, cancel := context.WithCancel(context.Background())
				checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
				tx.ctx = checked
				calls := 0
				planned, count, err := iterate(scoped, filter, func(directory.Entry) error { calls++; return nil })
				if i == 0 {
					wantPlanned, wantCount, wantErr, wantRemaining = planned, count, err, checked.remaining
				} else if planned != wantPlanned || count != wantCount || calls != wantCount || checked.remaining != wantRemaining || fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) {
					t.Fatalf("cancel %d: planned/count/error/remaining = %v/%d/%v/%d, want %v/%d/%v/%d", cancelAt, planned, count, err, checked.remaining, wantPlanned, wantCount, wantErr, wantRemaining)
				}
				cancel()
			}
		}
		for _, cancelAt := range []int{1, 3, size + 1, size + 2, size + 4, 2*size + 1} {
			ctx, cancel := context.WithCancel(context.Background())
			polled := &candidateDoneCancelContext{Context: ctx, cancel: cancel, cancelAt: cancelAt}
			tx.ctx = polled
			planned, count, err := ForEachReadOnlyFilterCandidate(scoped, filter, func(directory.Entry) error {
				t.Fatal("callback after prevalidation cancellation")
				return nil
			})
			cancel()
			if !planned || count != 0 || !errors.Is(err, context.Canceled) || polled.doneCalls != cancelAt {
				t.Fatalf("Done cancel %d: planned/count/error/polls = %v/%d/%v/%d", cancelAt, planned, count, err, polled.doneCalls)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		tx.ctx = ctx
		planned, count, err := ForEachReadOnlyFilterCandidate(scoped, filter, func(directory.Entry) error { cancel(); return nil })
		if !planned || count != size || err != nil {
			t.Fatalf("callback cancellation = %v/%d/%v", planned, count, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkBoltBroadReadOnlyCandidateSelect(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("N=%d", size), func(b *testing.B) {
			store, schema, filter := newBoltCandidateStore(b, size)
			for _, variant := range []struct {
				name    string
				iterate readOnlyCandidateIterator
			}{{"Owned", ForEachFilterCandidate}, {"ReadOnly", ForEachReadOnlyFilterCandidate}} {
				b.Run(variant.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if err := store.View(context.Background(), func(reader Reader) error {
							retained := make([]directory.Entry, 0, size)
							planned, count, err := variant.iterate(ReaderInPartitionWithNormalizer(reader, "db", schema), filter, func(entry directory.Entry) error {
								retained = append(retained, entry.Select([]string{"uid", "cn"}, false))
								return nil
							})
							if !planned || count != size || len(retained) != size || err != nil {
								return fmt.Errorf("planned/count/error = %v/%d/%v", planned, count, err)
							}
							if len(retained[size-1].Attributes) != 2 {
								b.Fatal("unexpected projection")
							}
							return nil
						}); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
