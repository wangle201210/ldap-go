package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func newSmallGroupCandidateStore(t testing.TB, count, members int, format string) (*Bolt, indexTestSchema, directory.Filter) {
	t.Helper()
	store, schema, filter := newBoltCandidateStore(t, count)
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		refs := boltCandidateReferences(t, tx)
		locators := make([][]byte, len(refs))
		for i, ref := range refs {
			locators[i] = bytes.Clone(tx.equalityIndexRefs.Get([]byte(ref)))
			key := boltCandidateKey(t, tx, ref)
			stored, err := decodeStoredEntry(tx.entries.Get(key))
			if err != nil {
				return err
			}
			stored.Attributes[0].Values = [][]byte{[]byte("top"), []byte("groupOfNames")}
			values := make([][]byte, members)
			for j := range values {
				values[j] = []byte(fmt.Sprintf("uid=member%06d,ou=group%d,dc=example", j, i))
			}
			stored.Attributes = append(stored.Attributes, directory.Attribute{
				Description: "member", Values: values, RawNormalized: true,
			})
			_, identity := splitPartitionedEntryKey(string(key))
			if err := tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, format)); err != nil {
				return err
			}
		}
		// Posting order deliberately differs from the physical entry order.
		for i, ref := range refs {
			if err := tx.equalityIndexRefs.Put([]byte(ref), locators[len(refs)-1-i]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return store, schema, filter
}

func TestReadOnlySmallCandidatesLargeGroupsAfterUnmap(t *testing.T) {
	for _, size := range []int{1, 2, 4} {
		for _, format := range []string{"v1", "v2", "v3", "json"} {
			t.Run(fmt.Sprintf("N%d/%s", size, format), func(t *testing.T) {
				store, schema, filter := newSmallGroupCandidateStore(t, size, 1000, format)
				var owned, clones []directory.Entry
				var projections, wantProjections [][]directory.Entry
				var identities, names, dns []string
				if err := store.View(t.Context(), func(reader Reader) error {
					tx := reader.(*boltTx)
					scoped := ReaderInPartitionWithNormalizer(indexMaintenanceReader{Reader: reader}, "db", schema).(schemaAwarePartitionReader)
					for _, optIn := range []bool{false, true} {
						var encoded []encodedEqualityIndexCandidate
						entries, planned, err := scoped.planEqualityIndexCandidatesWithEncoded(filter, &encoded, optIn)
						wantEncoded := optIn && format != "json"
						if err != nil || !planned || len(encoded)+len(entries) != size || (len(encoded) == size) != wantEncoded {
							t.Fatalf("opt-in %v: entries/encoded/planned/error = %d/%d/%v/%v", optIn, len(entries), len(encoded), planned, err)
						}
					}
					planned, count, err := ForEachFilterCandidate(scoped, filter, func(entry directory.Entry) error {
						owned = append(owned, entry)
						wantProjections = append(wantProjections, readOnlyCandidateProjections(entry))
						return nil
					})
					if err != nil || !planned || count != size {
						t.Fatalf("owned planned/count/error = %v/%d/%v", planned, count, err)
					}
					original := make(map[string][]byte)
					for _, ref := range boltCandidateReferences(t, tx) {
						key := boltCandidateKey(t, tx, ref)
						original[string(key)] = bytes.Clone(tx.entries.Get(key))
					}
					stop := errors.New("callback stop")
					for _, stopAt := range []int{1, size, 0} {
						calls := 0
						planned, count, err := ForEachReadOnlyFilterCandidate(scoped, filter, func(entry directory.Entry) error {
							if !reflect.DeepEqual(entry, owned[calls]) {
								t.Fatalf("callback %d differs from owned", calls)
							}
							identity, _ := entry.DNIdentity()
							value := entry.Attributes[len(entry.Attributes)-1].Values[999]
							if format != "json" {
								encoded := tx.entries.Get([]byte(partitionedEntryKey("db", identity)))
								position := bytes.Index(encoded, value)
								if position < 0 || &value[0] != &encoded[position] {
									t.Fatal("1,000-member group payload was copied")
								}
							}
							if stopAt == 0 {
								clones = append(clones, entry.Clone())
								projections = append(projections, readOnlyCandidateProjections(entry))
								identities = append(identities, identity)
								dns = append(dns, entry.DN)
								for _, attribute := range entry.Attributes {
									names = append(names, attribute.Description)
								}
							}
							calls++
							if calls == stopAt {
								return stop
							}
							return nil
						})
						wantCount, wantCalls, wantErr := size, size, error(nil)
						if stopAt > 0 {
							wantCount, wantCalls, wantErr = stopAt-1, stopAt, stop
						}
						if !planned || count != wantCount || calls != wantCalls || !errors.Is(err, wantErr) {
							t.Fatalf("stop %d: planned/count/calls/error = %v/%d/%d/%v", stopAt, planned, count, calls, err)
						}
					}
					for key, value := range original {
						if !bytes.Equal(tx.entries.Get([]byte(key)), value) {
							t.Fatal("read-only iteration changed stored bytes")
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(clones, owned) || !reflect.DeepEqual(projections, wantProjections) {
					t.Fatal("clones or projections changed after Bolt unmap")
				}
				var wantNames []string
				for i, entry := range owned {
					identity, _ := entry.DNIdentity()
					if identities[i] != identity || dns[i] != entry.DN {
						t.Fatal("DN or identity retained borrowed bytes")
					}
					for _, attribute := range entry.Attributes {
						wantNames = append(wantNames, attribute.Description)
					}
				}
				if !slices.Equal(names, wantNames) {
					t.Fatal("attribute descriptions retained borrowed bytes")
				}
				memberIndex := len(clones[0].Attributes) - 1
				clones[0].Attributes[memberIndex].Values[999][0] ^= 0xff
				if !reflect.DeepEqual(projections, wantProjections) || !reflect.DeepEqual(clones[1:], owned[1:]) ||
					bytes.Equal(clones[0].Attributes[memberIndex].Values[999], owned[0].Attributes[memberIndex].Values[999]) {
					t.Fatal("retained outputs share mutable member values")
				}
			})
		}
	}
}

func TestReadOnlySmallCandidatesBorrowBoundedRows(t *testing.T) {
	for _, size := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("N%d", size), func(t *testing.T) {
			store, schema, filter := newSmallGroupCandidateStore(t, size, 1, "v3")
			if err := store.View(t.Context(), func(reader Reader) error {
				tx := reader.(*boltTx)
				refs := boltCandidateReferences(t, tx)
				for _, variant := range []struct {
					iterate readOnlyCandidateIterator
					borrow  bool
				}{{ForEachFilterCandidate, false}, {ForEachReadOnlyFilterCandidate, size > 1}} {
					calls := 0
					planned, count, err := variant.iterate(ReaderInPartitionWithNormalizer(reader, "db", schema), filter, func(entry directory.Entry) error {
						value := entry.Attributes[len(entry.Attributes)-1].Values[0]
						encoded := tx.entries.Get(boltCandidateKey(t, tx, refs[calls]))
						position := bytes.Index(encoded, value)
						if position < 0 || (&value[0] == &encoded[position]) != variant.borrow {
							t.Fatalf("callback %d: expected borrowed = %v", calls, variant.borrow)
						}
						calls++
						return nil
					})
					if err != nil || !planned || count != size || calls != size {
						t.Fatalf("planned/count/calls/error = %v/%d/%d/%v", planned, count, calls, err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadOnlySmallCandidatesCancellationAndCorruption(t *testing.T) {
	for _, size := range []int{0, 1, 2, 4} {
		for _, mode := range []string{"binary", "late-json", "late-corrupt", "unrecognized", "missing-reference", "missing-marker", "bad-marker"} {
			t.Run(fmt.Sprintf("N%d/%s", size, mode), func(t *testing.T) {
				store, schema, filter := newSmallGroupCandidateStore(t, max(1, size), 1000, "v3")
				if err := store.Update(t.Context(), func(writer Writer) error {
					tx := writer.(*boltTx)
					refs := boltCandidateReferences(t, tx)
					ref := refs[len(refs)-1]
					key := boltCandidateKey(t, tx, ref)
					switch mode {
					case "late-json":
						stored, err := decodeStoredEntry(tx.entries.Get(key))
						if err != nil {
							return err
						}
						_, identity := splitPartitionedEntryKey(string(key))
						return tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, "json"))
					case "late-corrupt":
						value := bytes.Clone(tx.entries.Get(key))
						return tx.entries.Put(key, value[:len(value)-1])
					case "unrecognized":
						return tx.entries.Put(key, []byte{0, 'L', 'G', 'E', 99})
					case "missing-reference":
						return tx.equalityIndexRefs.Delete([]byte(ref))
					case "missing-marker":
						return tx.meta.Delete(genericMetadataKey(schemaAwareDNMigrationMetadataKey("db")))
					case "bad-marker":
						return tx.meta.Put(genericMetadataKey(schemaAwareDNMigrationMetadataKey("db")), []byte{99})
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if size == 0 {
					filter.Assertion = []byte("missing")
				}
				if err := store.View(t.Context(), func(reader Reader) error {
					tx := reader.(*boltTx)
					scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
					// Sweep every owned Err checkpoint plus one beyond completion.
					for cancelAt := 1; cancelAt <= 2*size+4; cancelAt++ {
						var wantPlanned bool
						var wantCount, wantCalls, wantRemaining int
						var wantErr error
						for i, iterate := range []readOnlyCandidateIterator{ForEachFilterCandidate, ForEachReadOnlyFilterCandidate} {
							ctx, cancel := context.WithCancel(t.Context())
							checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
							tx.ctx = checked
							calls := 0
							planned, count, err := iterate(scoped, filter, func(directory.Entry) error { calls++; return nil })
							cancel()
							if i == 0 {
								wantPlanned, wantCount, wantCalls, wantRemaining, wantErr = planned, count, calls, checked.remaining, err
							} else if planned != wantPlanned || count != wantCount || calls != wantCalls || checked.remaining != wantRemaining ||
								fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) {
								t.Fatalf("cancel %d: planned/count/calls/remaining/error = %v/%d/%d/%d/%v; want %v/%d/%d/%d/%v",
									cancelAt, planned, count, calls, checked.remaining, err, wantPlanned, wantCount, wantCalls, wantRemaining, wantErr)
							}
							corrupt := mode == "bad-marker" || size > 0 && (mode == "late-corrupt" || mode == "unrecognized" || mode == "missing-reference")
							if corrupt && (err == nil || calls != 0 || count != 0) {
								t.Fatalf("late corruption reached callbacks: %v/%d/%d/%v", planned, count, calls, err)
							}
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestReadOnlySmallCandidatesDoneAndCallbackCancellation(t *testing.T) {
	for _, size := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("N%d", size), func(t *testing.T) {
			store, schema, filter := newSmallGroupCandidateStore(t, size, 1000, "v3")
			if err := store.View(t.Context(), func(reader Reader) error {
				tx := reader.(*boltTx)
				scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
				for cancelAt := 1; cancelAt <= 2*size+1; cancelAt++ {
					ctx, cancel := context.WithCancel(t.Context())
					polled := &candidateDoneCancelContext{Context: ctx, cancel: cancel, cancelAt: cancelAt}
					tx.ctx = polled
					planned, count, err := ForEachReadOnlyFilterCandidate(scoped, filter, func(directory.Entry) error {
						t.Fatal("callback after prevalidation cancellation")
						return nil
					})
					cancel()
					if !planned || count != 0 || !errors.Is(err, context.Canceled) || polled.doneCalls != cancelAt {
						t.Fatalf("Done cancel %d: planned/count/polls/error = %v/%d/%d/%v", cancelAt, planned, count, polled.doneCalls, err)
					}
				}
				for _, iterate := range []readOnlyCandidateIterator{ForEachFilterCandidate, ForEachReadOnlyFilterCandidate} {
					ctx, cancel := context.WithCancel(t.Context())
					tx.ctx = ctx
					calls := 0
					planned, count, err := iterate(scoped, filter, func(directory.Entry) error { calls++; cancel(); return nil })
					cancel()
					if !planned || count != size || calls != size || err != nil {
						t.Fatalf("post-callback cancellation = %v/%d/%d/%v", planned, count, calls, err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
