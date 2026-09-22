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

func TestReadOnlyPhysicalScanMatchesOwned(t *testing.T) {
	for _, format := range []string{"v1", "v2", "v3", "json", "mixed"} {
		t.Run(format, func(t *testing.T) {
			store, schema, _ := newBoltCandidateStore(t, 25)
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				for i, ref := range boltCandidateReferences(t, tx) {
					key := boltCandidateKey(t, tx, ref)
					stored, err := decodeStoredEntry(tx.entries.Get(key))
					if err != nil {
						return err
					}
					stored.Attributes = append(stored.Attributes, directory.Attribute{Description: "description;lang-EN", Values: [][]byte{nil, {}, {0, 255}}})
					mode := format
					if mode == "mixed" {
						mode = []string{"v1", "v2", "v3", "json"}[i%4]
					}
					_, identity := splitPartitionedEntryKey(string(key))
					if err := tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, mode)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			var want, got []directory.Entry
			if err := store.View(t.Context(), func(reader Reader) error {
				scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
				streamed, err := ForEachStablePhysicalEntry(scoped, func(entry directory.Entry) error {
					want = append(want, entry.Select([]string{"*"}, false))
					return nil
				})
				if !streamed || err != nil {
					return fmt.Errorf("reference: %v/%v", streamed, err)
				}
				streamed, err = ForEachReadOnlyStablePhysicalEntry(scoped, func(entry directory.Entry) error {
					if _, ok := entry.DNIdentity(); !ok {
						t.Fatal("missing owned identity")
					}
					got = append(got, entry.Select([]string{"*"}, false))
					return nil
				})
				if !streamed {
					return errors.New("read-only scan not selected")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || len(got) != 25 {
				t.Fatal("physical order, values or retained ownership differ after unmap")
			}
		})
	}
}

func TestReadOnlyPhysicalScanErrorsAndCancellation(t *testing.T) {
	store, schema, _ := newBoltCandidateStore(t, 12)
	for _, corrupt := range []bool{false, true} {
		if corrupt {
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				refs := physicalBoltCandidateReferences(t, tx)
				return tx.entries.Put(boltCandidateKey(t, tx, refs[len(refs)-1]), []byte("broken"))
			}); err != nil {
				t.Fatal(err)
			}
		}
		for _, cancelAt := range []int{1, 2, 5, 14, 100} {
			for _, stopAt := range []int{0, 3} {
				if err := store.View(t.Context(), func(reader Reader) error {
					tx := reader.(*boltTx)
					scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
					originalContext := tx.ctx
					defer func() { tx.ctx = originalContext }()
					var wantRows []string
					var wantErr error
					var wantStream bool
					var wantRemaining int
					for _, readonly := range []bool{false, true} {
						ctx, cancel := context.WithCancel(context.Background())
						checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
						tx.ctx = checked
						var rows []string
						visit := func(entry directory.Entry) error {
							rows = append(rows, entry.DN)
							if len(rows) == stopAt {
								return errors.New("stop")
							}
							return nil
						}
						iterate := ForEachStablePhysicalEntry
						if readonly {
							iterate = ForEachReadOnlyStablePhysicalEntry
						}
						streamed, err := iterate(scoped, visit)
						cancel()
						if !readonly {
							wantRows, wantErr, wantStream, wantRemaining = rows, err, streamed, checked.remaining
						} else if !reflect.DeepEqual(rows, wantRows) || fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) || streamed != wantStream || checked.remaining != wantRemaining {
							t.Fatalf("corrupt=%v cancel=%d stop=%d: rows/error/checkpoints differ", corrupt, cancelAt, stopAt)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestReadOnlyPhysicalScanDoesNotModifyRows(t *testing.T) {
	store, schema, _ := newBoltCandidateStore(t, 2)
	if err := store.Update(t.Context(), func(writer Writer) error {
		streamed, err := ForEachReadOnlyStablePhysicalEntry(ReaderInPartitionWithNormalizer(writer, "db", schema), func(directory.Entry) error { t.Fatal("borrowed writable transaction"); return nil })
		if streamed || err != nil {
			t.Fatalf("writable fallback = %v/%v", streamed, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.View(t.Context(), func(reader Reader) error {
		tx := reader.(*boltTx)
		original := map[string][]byte{}
		for _, ref := range boltCandidateReferences(t, tx) {
			key := boltCandidateKey(t, tx, ref)
			original[string(key)] = bytes.Clone(tx.entries.Get(key))
		}
		_, err := ForEachReadOnlyStablePhysicalEntry(ReaderInPartitionWithNormalizer(reader, "db", schema), func(entry directory.Entry) error {
			selected := entry.Select([]string{"*"}, false)
			for _, attr := range selected.Attributes {
				for _, value := range attr.Values {
					clear(value)
				}
			}
			return nil
		})
		for key, want := range original {
			if !bytes.Equal(tx.entries.Get([]byte(key)), want) {
				t.Fatal("selected output modified stored data")
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkReadOnlyPhysicalScan(b *testing.B) {
	store, schema, _ := newBoltCandidateStore(b, 10000)
	for _, readonly := range []bool{false, true} {
		b.Run(fmt.Sprint(readonly), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := store.View(b.Context(), func(reader Reader) error {
					iterate := ForEachStablePhysicalEntry
					if readonly {
						iterate = ForEachReadOnlyStablePhysicalEntry
					}
					count := 0
					_, err := iterate(ReaderInPartitionWithNormalizer(reader, "db", schema), func(directory.Entry) error { count++; return nil })
					if err == nil && count != 10000 {
						return fmt.Errorf("count=%d", count)
					}
					return err
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
