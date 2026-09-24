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

// Frozen bounded implementation before borrowing, including its Err checkpoints.
func forEachBoundedOwnedCandidate(reader Reader, filter directory.Filter, maxCandidates int, fn func(directory.Entry) error) (bool, int, error) {
	if maxCandidates <= 0 || filter.Kind != directory.FilterEquality {
		return false, 0, nil
	}
	scoped, ok := reader.(schemaAwarePartitionReader)
	if !ok {
		return false, 0, nil
	}
	tx, ok := maintenanceReader(scoped.Reader).(*boltTx)
	if !ok || tx.tx.Writable() {
		return false, 0, nil
	}
	schema, ok := scoped.normalizer.(EqualityIndexSchema)
	if !ok {
		return false, 0, nil
	}
	current, err := scoped.currentEqualityIndex(tx, schema)
	if err != nil || !current {
		return false, 0, err
	}
	attribute, equality, _, err := schema.ResolveEqualityIndexAttribute(filter.Attribute)
	if err != nil || !equality {
		return false, 0, err
	}
	normalized, err := schema.NormalizeEqualityIndexAssertion(filter.Attribute, filter.Assertion)
	if err != nil {
		return false, 0, err
	}
	references, bounded, err := tx.boundedEqualityIndexPostings(scoped.partition, attribute, normalized, maxCandidates)
	if err != nil {
		return true, 0, err
	}
	if !bounded {
		return false, 0, nil
	}
	entries, err := tx.equalityIndexEntries(scoped.partition, references, schema)
	if err != nil {
		return true, 0, err
	}
	for index, entry := range entries {
		if err := fn(entry); err != nil {
			return true, index, err
		}
	}
	return true, len(entries), nil
}

func TestBoundedReadOnlyBorrowOwnership(t *testing.T) {
	for _, size := range []int{1, 2, 4} {
		for _, format := range []string{"v1", "v2", "v3", "json"} {
			t.Run(fmt.Sprintf("N%d/%s", size, format), func(t *testing.T) {
				store, schema, filter := newSmallGroupCandidateStore(t, size, 1000, format)
				var owned, clones []directory.Entry
				var projections, wantProjections [][]directory.Entry
				var text, wantText []string
				if err := store.View(t.Context(), func(reader Reader) error {
					tx := reader.(*boltTx)
					scoped := ReaderInPartitionWithNormalizer(indexMaintenanceReader{Reader: reader}, "db", schema)
					planned, count, err := forEachBoundedOwnedCandidate(scoped, filter, 4, func(entry directory.Entry) error {
						owned = append(owned, entry)
						wantProjections = append(wantProjections, readOnlyCandidateProjections(entry))
						identity, _ := entry.DNIdentity()
						wantText = append(wantText, entry.DN, identity)
						for _, attribute := range entry.Attributes {
							wantText = append(wantText, attribute.Description)
						}
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
						planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(entry directory.Entry) error {
							if !reflect.DeepEqual(entry, owned[calls]) {
								t.Fatalf("callback %d changed posting order, identity, or values", calls)
							}
							identity, _ := entry.DNIdentity()
							value := entry.Attributes[len(entry.Attributes)-1].Values[999]
							encoded := tx.entries.Get([]byte(partitionedEntryKey("db", identity)))
							position := bytes.Index(encoded, value)
							borrowed := position >= 0 && &value[0] == &encoded[position]
							if borrowed != (format != "json") {
								t.Fatalf("1,000-member group borrowed = %v for %s", borrowed, format)
							}
							if stopAt == 0 {
								clones = append(clones, entry.Clone())
								projections = append(projections, readOnlyCandidateProjections(entry))
								text = append(text, entry.DN, identity)
								for _, attribute := range entry.Attributes {
									text = append(text, attribute.Description)
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
							t.Fatal("bounded iteration changed stored bytes")
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(clones, owned) || !reflect.DeepEqual(projections, wantProjections) || !slices.Equal(text, wantText) {
					t.Fatal("clones, projections, or strings changed after arena reuse and Bolt unmap")
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

func TestBoundedReadOnlyBorrowAdaptiveDecoder(t *testing.T) {
	for _, size := range []int{1, 2, 4} {
		for _, total := range []int{0, 4096, 4097} {
			t.Run(fmt.Sprintf("N%d/values%d", size, total), func(t *testing.T) {
				store, schema, filter := newSmallGroupCandidateStore(t, size, 1, "v3")
				if total != 0 {
					if err := store.Update(t.Context(), func(writer Writer) error {
						tx := writer.(*boltTx)
						for _, ref := range boltCandidateReferences(t, tx) {
							key := boltCandidateKey(t, tx, ref)
							stored, err := decodeStoredEntry(tx.entries.Get(key))
							if err != nil {
								return err
							}
							member := len(stored.Attributes) - 1
							otherValues := 0
							for _, attribute := range stored.Attributes[:member] {
								otherValues += len(attribute.Values)
							}
							values := make([][]byte, total-otherValues)
							for index := range values {
								values[index] = []byte(fmt.Sprintf("uid=member%06d,dc=example", index))
							}
							stored.Attributes[member].Values = values
							_, identity := splitPartitionedEntryKey(string(key))
							if err := tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, "v3")); err != nil {
								return err
							}
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				if err := store.View(t.Context(), func(reader Reader) error {
					tx := reader.(*boltTx)
					scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
					planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(entry directory.Entry) error {
						identity, _ := entry.DNIdentity()
						encoded := tx.entries.Get([]byte(partitionedEntryKey("db", identity)))
						value := entry.Attributes[len(entry.Attributes)-1].Values[0]
						position := bytes.Index(encoded, value)
						borrowed := position >= 0 && &value[0] == &encoded[position]
						wantBorrowed := total <= 4096 && (size > 1 || total > 0)
						if (len(encoded) < 8*1024) != (total == 0) || borrowed != wantBorrowed {
							t.Fatalf("encoded bytes/borrowed = %d/%v, want borrowed %v", len(encoded), borrowed, wantBorrowed)
						}
						return nil
					})
					if !planned || count != size || err != nil {
						t.Fatalf("planned/count/error = %v/%d/%v", planned, count, err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestBoundedReadOnlyBorrowErrorCheckpoints(t *testing.T) {
	for _, size := range []int{0, 1, 2, 4} {
		for _, mode := range []string{"binary", "late-json", "late-corrupt", "unrecognized", "missing-reference", "missing-entry", "cross-partition", "bad-entry-before-missing-reference", "missing-marker", "bad-marker"} {
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
					case "bad-entry-before-missing-reference":
						if err := tx.entries.Put(boltCandidateKey(t, tx, refs[0]), []byte("bad entry")); err != nil {
							return err
						}
						fallthrough
					case "missing-reference":
						return tx.equalityIndexRefs.Delete([]byte(ref))
					case "missing-entry":
						return tx.entries.Delete(key)
					case "cross-partition":
						return tx.equalityIndexRefs.Put([]byte(ref), encodeEqualityIndexEntryReference("other", "dn:v2:key"))
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
					for cancelAt := 1; cancelAt <= 2*size+5; cancelAt++ {
						var wantPlanned bool
						var wantCount, wantCalls, wantRemaining int
						var wantEntries []directory.Entry
						var wantErr error
						for index, iterate := range []func(Reader, directory.Filter, int, func(directory.Entry) error) (bool, int, error){forEachBoundedOwnedCandidate, ForEachBoundedReadOnlyFilterCandidate} {
							ctx, cancel := context.WithCancel(t.Context())
							checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
							tx.ctx = checked
							var entries []directory.Entry
							planned, count, err := iterate(scoped, filter, 4, func(entry directory.Entry) error {
								entries = append(entries, entry.Clone())
								return nil
							})
							cancel()
							if index == 0 {
								wantPlanned, wantCount, wantCalls, wantRemaining, wantErr = planned, count, len(entries), checked.remaining, err
								wantEntries = entries
							} else if planned != wantPlanned || count != wantCount || len(entries) != wantCalls || checked.remaining != wantRemaining ||
								fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) || !reflect.DeepEqual(entries, wantEntries) {
								t.Fatalf("cancel %d: planned/count/calls/remaining/error = %v/%d/%d/%d/%v; want %v/%d/%d/%d/%v",
									cancelAt, planned, count, len(entries), checked.remaining, err, wantPlanned, wantCount, wantCalls, wantRemaining, wantErr)
							}
							corrupt := mode == "bad-marker" || size > 0 && mode != "binary" && mode != "late-json" && mode != "missing-marker"
							if corrupt && (err == nil || count != 0 || len(entries) != 0) {
								t.Fatal("corruption was not reported before the first callback")
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

func TestBoundedReadOnlyBorrowDoneAndCallbackCancellation(t *testing.T) {
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
					planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(directory.Entry) error {
						t.Fatal("callback after prevalidation cancellation")
						return nil
					})
					cancel()
					if !planned || count != 0 || !errors.Is(err, context.Canceled) || polled.doneCalls != cancelAt {
						t.Fatalf("Done cancel %d: planned/count/polls/error = %v/%d/%d/%v", cancelAt, planned, count, polled.doneCalls, err)
					}
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				tx.ctx = ctx
				calls := 0
				planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(directory.Entry) error { calls++; cancel(); return nil })
				if !planned || count != size || calls != size || err != nil {
					t.Fatalf("callback cancellation = %v/%d/%d/%v", planned, count, calls, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type boundedBorrowReferenceSchema struct {
	indexTestSchema
	references []string
	err        error
}

func (schema *boundedBorrowReferenceSchema) ResolveEqualityIndexDNReference(reference string) (directory.DN, error) {
	schema.references = append(schema.references, reference)
	if schema.err != nil {
		return directory.DN{}, schema.err
	}
	return directory.ParseDNWithNormalizer(reference, schema.indexTestSchema)
}

func TestBoundedReadOnlyBorrowLegacyCustomSchema(t *testing.T) {
	for _, mode := range []string{"physical", "display", "legacy-entry", "resolver-error", "resolver-before-corruption"} {
		t.Run(mode, func(t *testing.T) {
			store, schema, filter := newSmallGroupCandidateStore(t, 4, 1000, "v3")
			var reference string
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				refs := boltCandidateReferences(t, tx)
				key := boltCandidateKey(t, tx, refs[0])
				stored, err := decodeStoredEntry(tx.entries.Get(key))
				if err != nil {
					return err
				}
				reference = stored.DN
				if mode == "physical" {
					return nil
				}
				if mode == "legacy-entry" {
					dn, err := directory.ParseDN(reference)
					if err != nil {
						return err
					}
					encoded, err := encodeEntry(stored.Entry, "", "")
					if err != nil {
						return err
					}
					if err := tx.entries.Put([]byte(partitionedEntryKey("db", dn.Key())), encoded); err != nil {
						return err
					}
					if err := tx.entries.Delete(key); err != nil {
						return err
					}
				}
				if mode == "resolver-before-corruption" {
					if err := tx.entries.Put(boltCandidateKey(t, tx, refs[3]), []byte("corrupt entry")); err != nil {
						return err
					}
				}
				return tx.equalityIndexRefs.Put([]byte(refs[0]), encodeEqualityIndexEntryReference("db", reference))
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.View(t.Context(), func(reader Reader) error {
				custom := &boundedBorrowReferenceSchema{indexTestSchema: schema}
				if mode == "resolver-error" || mode == "resolver-before-corruption" {
					custom.err = errors.New("custom reference rejected")
				}
				scoped := ReaderInPartitionWithNormalizer(reader, "db", custom)
				var wantEntries []directory.Entry
				var wantReferences []string
				var wantErr error
				for index, iterate := range []func(Reader, directory.Filter, int, func(directory.Entry) error) (bool, int, error){forEachBoundedOwnedCandidate, ForEachBoundedReadOnlyFilterCandidate} {
					custom.references = nil
					var entries []directory.Entry
					planned, count, err := iterate(scoped, filter, 4, func(entry directory.Entry) error {
						entries = append(entries, entry.Clone())
						return nil
					})
					wantCount := 4
					if custom.err != nil {
						wantCount = 0
					}
					if !planned || count != wantCount || len(entries) != wantCount || !errors.Is(err, custom.err) {
						t.Fatalf("planned/count/calls/error = %v/%d/%d/%v", planned, count, len(entries), err)
					}
					if index == 0 {
						wantEntries, wantReferences, wantErr = entries, slices.Clone(custom.references), err
					} else if !reflect.DeepEqual(entries, wantEntries) || !slices.Equal(custom.references, wantReferences) ||
						fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) {
						t.Fatal("legacy fallback changed entries, reference callbacks, or error order")
					}
					if mode == "physical" && len(custom.references) != 0 || mode != "physical" && !slices.Equal(custom.references, []string{reference}) {
						t.Fatalf("unexpected reference callbacks: %v", custom.references)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
