package storage

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Frozen before physical-order prefetching for comparisons in the same binary.
func (tx *boltTx) prevalidateEqualityIndexCandidatesGetReference(
	partition string,
	references []string,
) ([]encodedEqualityIndexCandidate, bool, error) {
	if tx.tx.Writable() || strings.IndexByte(partition, 0) >= 0 {
		return nil, false, nil
	}
	marker := tx.meta.Get(genericMetadataKey(schemaAwareDNMigrationMetadataKey(partition)))
	if len(marker) != 1 || int(marker[0]) != schemaAwareDNIdentityFormatVersion {
		return nil, false, nil
	}
	select {
	case <-tx.ctx.Done():
		return nil, false, nil
	default:
	}
	candidates := make([]encodedEqualityIndexCandidate, 0, len(references))
	key := append([]byte(partition), 0)
	prefixLength := len(key)
	for _, entryID := range references {
		select {
		case <-tx.ctx.Done():
			return nil, false, nil
		default:
		}
		if len(entryID) != equalityIndexEntryIDSize || tx.equalityIndexRefs == nil {
			return nil, false, nil
		}
		reference := tx.equalityIndexRefs.Get([]byte(entryID))
		if reference == nil {
			return nil, false, nil
		}
		referencePartition, position, err := readLengthPrefixed(reference, 0)
		if err != nil {
			return nil, false, nil
		}
		identity, position, err := readLengthPrefixed(reference, position)
		if err != nil || position != len(reference) || string(referencePartition) != partition ||
			!bytes.HasPrefix(identity, []byte(schemaAwareDNKeyPrefix)) {
			return nil, false, nil
		}
		key = append(key[:prefixLength], identity...)
		value := tx.entries.Get(key)
		if !validBinaryCandidateEntry(value) {
			return nil, false, nil
		}
		candidates = append(candidates, encodedEqualityIndexCandidate{value: value, identity: identity})
	}
	// Match equalityIndexEntries' checkpoints only after fallback is ruled out.
	if _, err := tx.schemaAwareDNIdentityReady(partition); err != nil {
		return nil, false, err
	}
	for range references {
		if err := tx.ctx.Err(); err != nil {
			return nil, false, err
		}
	}
	return candidates, true, nil
}

func physicalBoltCandidateReferences(t testing.TB, tx *boltTx) []string {
	t.Helper()
	references := boltCandidateReferences(t, tx)
	physical := make([]struct {
		reference string
		key       []byte
	}, len(references))
	for index, reference := range references {
		physical[index].reference = reference
		physical[index].key = boltCandidateKey(t, tx, reference)
	}
	sort.Slice(physical, func(i, j int) bool {
		return bytes.Compare(physical[i].key, physical[j].key) < 0
	})
	for index := range references {
		references[index] = physical[index].reference
	}
	return references
}

func TestBoltEqualityCandidatesPhysicalGapsAndDuplicates(t *testing.T) {
	const count = minEncodedEqualityIndexCandidates
	store, _, _ := newBoltCandidateStore(t, count*(maxEqualityCandidateCursorSteps+2))
	if err := store.View(context.Background(), func(reader Reader) error {
		tx := reader.(*boltTx)
		physical := physicalBoltCandidateReferences(t, tx)
		for _, stride := range []int{1, maxEqualityCandidateCursorSteps, maxEqualityCandidateCursorSteps + 1, maxEqualityCandidateCursorSteps + 2} {
			references := make([]string, 0, count+1)
			for index := range count {
				references = append(references, physical[index*stride])
			}
			references = append(references, references[count/2])
			sort.Strings(references)
			want, wantValid, wantErr := tx.prevalidateEqualityIndexCandidatesGetReference("db", references)
			got, valid, err := tx.prevalidateEqualityIndexCandidates("db", references)
			if wantErr != nil || !wantValid || err != nil || !valid || !reflect.DeepEqual(got, want) {
				t.Fatalf("stride %d: valid/error = %v/%v; want %v/%v; candidates match = %v", stride, valid, err, wantValid, wantErr, reflect.DeepEqual(got, want))
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoltEqualityCandidatesPhysicalFailureOrder(t *testing.T) {
	for _, damage := range []string{"first-missing", "last-missing", "opposite-errors"} {
		t.Run(damage, func(t *testing.T) {
			store, schema, filter := newBoltCandidateStore(t, minEncodedEqualityIndexCandidates+1)
			if err := store.Update(context.Background(), func(writer Writer) error {
				tx := writer.(*boltTx)
				physical := physicalBoltCandidateReferences(t, tx)
				switch damage {
				case "first-missing":
					return tx.entries.Delete(boltCandidateKey(t, tx, physical[0]))
				case "last-missing":
					return tx.entries.Delete(boltCandidateKey(t, tx, physical[len(physical)-1]))
				default:
					// The physically earlier error must lose to the earlier posting ID.
					for index := 1; index < len(physical); index++ {
						if physical[index-1] > physical[index] {
							if err := tx.entries.Delete(boltCandidateKey(t, tx, physical[index-1])); err != nil {
								return err
							}
							return tx.entries.Put(boltCandidateKey(t, tx, physical[index]), []byte("bad entry"))
						}
					}
					return fmt.Errorf("fixture has no opposite physical/posting order")
				}
			}); err != nil {
				t.Fatal(err)
			}
			assertBoltCandidateErrorBeforeCallback(t, store, schema, filter)
		})
	}
}

func BenchmarkBoltEqualityCandidatePrefetch(b *testing.B) {
	store, _, _ := newBoltCandidateStore(b, 100000)
	if err := store.View(context.Background(), func(reader Reader) error {
		tx := reader.(*boltTx)
		references := boltCandidateReferences(b, tx)
		physical := physicalBoltCandidateReferences(b, tx)
		dense128 := append([]string(nil), physical[:128]...)
		sort.Strings(dense128)
		for _, shape := range []struct {
			name       string
			references []string
		}{
			{"Dense100K", references},
			{"Sparse128", references[:128]},
			{"Dense128", dense128},
			{"Sparse4096", references[:4096]},
		} {
			b.Run(shape.name, func(b *testing.B) {
				for _, implementation := range []struct {
					name     string
					prefetch func(string, []string) ([]encodedEqualityIndexCandidate, bool, error)
				}{
					{"OriginalGet", tx.prevalidateEqualityIndexCandidatesGetReference},
					{"Current", tx.prevalidateEqualityIndexCandidates},
				} {
					b.Run(implementation.name, func(b *testing.B) {
						b.ReportAllocs()
						for b.Loop() {
							candidates, valid, err := implementation.prefetch("db", shape.references)
							if err != nil || !valid || len(candidates) != len(shape.references) {
								b.Fatalf("prefetch count/valid/error = %d/%v/%v", len(candidates), valid, err)
							}
						}
					})
				}
			})
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
}
