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

func TestBoundedReadOnlyCandidateLimits(t *testing.T) {
	for _, size := range []int{1, 4, 5, 129} {
		t.Run(fmt.Sprintf("N%d", size), func(t *testing.T) {
			store, schema, filter := newBoltCandidateStore(t, size)
			if err := store.View(context.Background(), func(reader Reader) error {
				scoped := ReaderInPartitionWithNormalizer(reader, "db", schema).(schemaAwarePartitionReader)
				want, _, err := scoped.planEqualityIndexCandidates(filter)
				if err != nil {
					return err
				}
				for _, limit := range []int{-1, 0, 1, 4} {
					var got []directory.Entry
					planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, limit, func(entry directory.Entry) error {
						got = append(got, entry.Clone())
						return nil
					})
					wantPlanned, wantCount := limit > 0 && size <= limit, 0
					if wantPlanned {
						wantCount = size
						for i := range got {
							if !reflect.DeepEqual(got[i], want[i].Clone()) {
								t.Fatal("bounded callback order or entry differs from owned")
							}
						}
					}
					if planned != wantPlanned || count != wantCount || len(got) != wantCount || err != nil {
						t.Fatalf("limit %d: planned/count/calls/error = %v/%d/%d/%v", limit, planned, count, len(got), err)
					}
				}
				filter.Assertion = []byte("absent")
				planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(directory.Entry) error {
					t.Fatal("callback for absent posting")
					return nil
				})
				if !planned || count != 0 || err != nil {
					t.Fatalf("absent posting = %v/%d/%v", planned, count, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBoundedReadOnlyCandidateRawPostingCutoff(t *testing.T) {
	store, schema, filter := newBoltCandidateStore(t, 129)
	if err := store.Update(context.Background(), func(writer Writer) error {
		tx := writer.(*boltTx)
		refs := boltCandidateReferences(t, tx)
		// All raw postings reference one corrupt row. The fifth must reject the
		// bound before deduplicating references or decoding even the first row.
		first := bytes.Clone(tx.equalityIndexRefs.Get([]byte(refs[0])))
		key := boltCandidateKey(t, tx, refs[0])
		for _, ref := range refs {
			if err := tx.equalityIndexRefs.Put([]byte(ref), first); err != nil {
				return err
			}
		}
		return tx.entries.Put(key, []byte("corrupt entry"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.View(context.Background(), func(reader Reader) error {
		tx := reader.(*boltTx)
		checked := &candidateCancelContext{Context: context.Background(), remaining: 1000}
		tx.ctx = checked
		references, bounded, err := tx.boundedEqualityIndexPostings("db", "2.5.4.3", []byte("shared"), 4)
		if bounded || references != nil || err != nil || checked.remaining != 994 {
			t.Fatalf("limited scan refs/bounded/error/Err calls = %d/%v/%v/%d", len(references), bounded, err, 1000-checked.remaining)
		}
		checked.remaining = 1000
		planned, count, err := ForEachBoundedReadOnlyFilterCandidate(ReaderInPartitionWithNormalizer(reader, "db", schema), filter, 4, func(directory.Entry) error {
			t.Fatal("callback for more than four raw postings")
			return nil
		})
		if planned || count != 0 || err != nil || checked.remaining != 993 {
			t.Fatalf("over-limit planned/count/error/Err calls = %v/%d/%v/%d", planned, count, err, 1000-checked.remaining)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedReadOnlyCandidateUnsupported(t *testing.T) {
	for _, mode := range []string{"unscoped", "write", "presence", "and", "unindexed", "missing-config", "stale-config"} {
		t.Run(mode, func(t *testing.T) {
			store, schema, filter := newBoltCandidateStore(t, 4)
			if err := store.Update(context.Background(), func(writer Writer) error {
				tx := writer.(*boltTx)
				if mode == "missing-config" {
					return tx.equalityIndexConfigs.Delete([]byte("db"))
				}
				if mode == "stale-config" {
					return tx.equalityIndexConfigs.Put([]byte("db"), []byte(`{"version":1}`))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			visit := func(reader Reader) error {
				scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
				switch mode {
				case "unscoped":
					scoped = reader
				case "presence":
					filter = directory.Filter{Kind: directory.FilterPresent, Attribute: "cn"}
				case "and":
					filter = directory.Filter{Kind: directory.FilterAnd, Children: []directory.Filter{filter}}
				case "unindexed":
					filter.Attribute = "sn"
				}
				planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(directory.Entry) error {
					t.Fatal("callback on unsupported bounded path")
					return nil
				})
				if planned || count != 0 || err != nil {
					t.Fatalf("unsupported result = %v/%d/%v", planned, count, err)
				}
				return nil
			}
			var err error
			if mode == "write" {
				err = store.Update(context.Background(), func(writer Writer) error { return visit(writer) })
			} else {
				err = store.View(context.Background(), visit)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	store := NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.View(context.Background(), func(reader Reader) error {
		planned, count, err := ForEachBoundedReadOnlyFilterCandidate(ReaderInPartitionWithNormalizer(reader, "db", indexTestSchema{config: indexTestCNConfig()}), directory.Filter{Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("shared")}, 4, func(directory.Entry) error {
			t.Fatal("bounded callback from unsupported memory store")
			return nil
		})
		if planned || count != 0 || err != nil {
			t.Fatalf("memory result = %v/%d/%v", planned, count, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedReadOnlyCandidateStopAndCancellation(t *testing.T) {
	store, schema, filter := newBoltCandidateStore(t, 4)
	if err := store.View(context.Background(), func(reader Reader) error {
		tx := reader.(*boltTx)
		scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
		stop := errors.New("callback stop")
		calls := 0
		planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(directory.Entry) error {
			calls++
			if calls == 3 {
				return stop
			}
			return nil
		})
		if !planned || count != 2 || calls != 3 || err != stop {
			t.Fatalf("callback stop = %v/%d/%d/%v", planned, count, calls, err)
		}
		for cancelAt := 1; cancelAt <= 11; cancelAt++ {
			ctx, cancel := context.WithCancel(context.Background())
			tx.ctx = &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
			planned, count, err := ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(directory.Entry) error {
				t.Fatal("callback before validation finished")
				return nil
			})
			cancel()
			if planned != (cancelAt > 1) || count != 0 || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel at %d = %v/%d/%v", cancelAt, planned, count, err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		tx.ctx = ctx
		planned, count, err = ForEachBoundedReadOnlyFilterCandidate(scoped, filter, 4, func(directory.Entry) error { cancel(); return nil })
		if !planned || count != 4 || err != nil {
			t.Fatalf("callback cancellation = %v/%d/%v", planned, count, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
