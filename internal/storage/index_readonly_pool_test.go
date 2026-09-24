package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Pool inspection stays in serial tests. Hold existing idle decoders without
// replacing the global channel or inspecting a decoder owned by an iterator.
func holdIdleReadOnlyCandidateDecoders(t *testing.T) {
	t.Helper()
	var held []*readOnlyCandidateDecoder
	for len(idleReadOnlyCandidateDecoders) > 0 {
		held = append(held, acquireReadOnlyCandidateDecoder())
	}
	t.Cleanup(func() {
		for _, decoder := range held {
			releaseReadOnlyCandidateDecoder(decoder)
		}
	})
}

func assertReadOnlyCandidateDecoderCleared(t *testing.T, decoder *readOnlyCandidateDecoder) {
	t.Helper()
	for i, attribute := range decoder.attributes {
		if attribute.Description != "" || attribute.Values != nil || attribute.RawNormalized {
			t.Fatalf("attribute descriptor %d retained data", i)
		}
	}
	for i, value := range decoder.values {
		if value != nil {
			t.Fatalf("fixed value descriptor %d retained a payload reference", i)
		}
	}
	for i, value := range decoder.overflowValues[:cap(decoder.overflowValues)] {
		if value != nil {
			t.Fatalf("overflow descriptor %d retained a payload reference", i)
		}
	}
	if len(decoder.names) != 0 {
		t.Errorf("name cache retained %d entries", len(decoder.names))
	}
	if cap(decoder.overflowValues) > maxReadOnlyCandidateBorrowedValues {
		t.Errorf("overflow capacity = %d, exceeds bound", cap(decoder.overflowValues))
	}
}

func TestReadOnlyCandidatePoolClearsWholeCapacity(t *testing.T) {
	for _, full := range []bool{false, true} {
		for _, length := range []int{0, 1, maxReadOnlyCandidateBorrowedValues} {
			t.Run(fmt.Sprintf("full%v/length%d", full, length), func(t *testing.T) {
				holdIdleReadOnlyCandidateDecoders(t)
				if full {
					for range cap(idleReadOnlyCandidateDecoders) {
						releaseReadOnlyCandidateDecoder(new(readOnlyCandidateDecoder))
					}
				}
				payload := []byte("borrowed\x00payload\xffmust survive release")
				original := bytes.Clone(payload)
				decoder := &readOnlyCandidateDecoder{
					overflowValues: make([][]byte, maxReadOnlyCandidateBorrowedValues),
					names:          make(map[string]string),
				}
				for i := range decoder.attributes {
					decoder.attributes[i] = directory.Attribute{
						Description: string(payload), Values: [][]byte{payload}, RawNormalized: true,
					}
				}
				for i := range decoder.values {
					decoder.values[i] = payload
				}
				arena := decoder.overflowValues
				for i := range arena {
					arena[i] = payload
				}
				for i := range maxReadOnlyCandidateNames {
					decoder.names[fmt.Sprintf("name%d", i)] = string(payload)
				}
				decoder.overflowValues = arena[:length]
				releaseReadOnlyCandidateDecoder(decoder)
				if !full {
					if got := acquireReadOnlyCandidateDecoder(); got != decoder {
						t.Fatal("released decoder was not returned for reuse")
					}
				} else if len(idleReadOnlyCandidateDecoders) != cap(idleReadOnlyCandidateDecoders) {
					t.Fatal("release changed the full pool's size")
				}
				// The decoder is either reacquired or dropped, so it is exclusively ours.
				assertReadOnlyCandidateDecoderCleared(t, decoder)
				for i, value := range arena {
					if value != nil {
						t.Fatalf("original overflow backing array retained descriptor %d", i)
					}
				}
				if !bytes.Equal(payload, original) {
					t.Fatal("release cleared borrowed payload bytes")
				}
				if full {
					for range cap(idleReadOnlyCandidateDecoders) {
						if acquireReadOnlyCandidateDecoder() == decoder {
							t.Fatal("full pool retained an additional decoder")
						}
					}
				}
			})
		}
	}
}

func TestReadOnlyCandidatePoolBoundAndExclusiveAcquire(t *testing.T) {
	holdIdleReadOnlyCandidateDecoders(t)
	if cap(idleReadOnlyCandidateDecoders) != 16 {
		t.Fatalf("idle capacity = %d, want 16", cap(idleReadOnlyCandidateDecoders))
	}
	active := make(map[*readOnlyCandidateDecoder]bool)
	for range cap(idleReadOnlyCandidateDecoders) + 4 {
		decoder := acquireReadOnlyCandidateDecoder()
		if active[decoder] {
			t.Fatal("acquire returned a decoder that is still active")
		}
		active[decoder] = true
	}
	for decoder := range active {
		releaseReadOnlyCandidateDecoder(decoder)
	}
	if len(idleReadOnlyCandidateDecoders) != 16 {
		t.Fatalf("idle count = %d, want 16", len(idleReadOnlyCandidateDecoders))
	}
	for range 16 {
		decoder := acquireReadOnlyCandidateDecoder()
		if !active[decoder] {
			t.Fatal("pool returned a duplicate or unknown decoder")
		}
		delete(active, decoder)
		assertReadOnlyCandidateDecoderCleared(t, decoder)
	}
}

func TestReadOnlyCandidatePoolLazyAcquire(t *testing.T) {
	smallEntry := readOnlyOverflowEntry(1)
	smallEntry.Attributes[0].Values[0] = []byte("pool-borrow-probe")
	small := encodeCandidateTestEntry(t, smallEntry, "", "v3")
	large := encodeCandidateTestEntry(t, readOnlyOverflowEntry(1000), "", "v3")
	if len(small) >= 8*1024 || len(large) < 8*1024 {
		t.Fatal("fixtures do not straddle the single-row ownership threshold")
	}
	for _, test := range []struct {
		name   string
		values [][]byte
		pooled bool
	}{
		{name: "empty"},
		{name: "single-small", values: [][]byte{small}},
		{name: "single-small-error", values: [][]byte{append(bytes.Clone(small), 0)}},
		{name: "single-large", values: [][]byte{large}, pooled: true},
		{name: "multiple-small", values: [][]byte{small, small}, pooled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			holdIdleReadOnlyCandidateDecoders(t)
			encoded := make([]encodedEqualityIndexCandidate, len(test.values))
			for i, value := range test.values {
				encoded[i].value = value
			}
			calls := 0
			count, err := forEachReadOnlyEncodedCandidate(encoded, func(entry directory.Entry) error {
				value := entry.Attributes[0].Values[len(entry.Attributes[0].Values)-1]
				if len(value) == 0 || bytes.Count(test.values[calls], value) != 1 {
					t.Fatal("borrowing probe must be nonempty and unique in the encoded row")
				}
				position := bytes.Index(test.values[calls], value)
				borrowed := &value[0] == &test.values[calls][position]
				if borrowed != test.pooled {
					t.Errorf("borrowed = %v, want %v", borrowed, test.pooled)
				}
				calls++
				return nil
			})
			if test.name == "single-small-error" {
				if err == nil || count != 0 || calls != 0 {
					t.Fatalf("malformed owned row count/calls/error = %d/%d/%v", count, calls, err)
				}
			} else if err != nil || count != len(encoded) || calls != count {
				t.Fatalf("count/calls/error = %d/%d/%v", count, calls, err)
			}
			wantIdle := 0
			if test.pooled {
				wantIdle = 1
			}
			if len(idleReadOnlyCandidateDecoders) != wantIdle {
				t.Fatalf("idle count = %d, want %d", len(idleReadOnlyCandidateDecoders), wantIdle)
			}
			if test.pooled {
				assertReadOnlyCandidateDecoderCleared(t, acquireReadOnlyCandidateDecoder())
			}
		})
	}
}

func TestReadOnlyCandidatePoolReleaseOnEveryExit(t *testing.T) {
	value := encodeCandidateTestEntry(t, readOnlyOverflowEntry(2, 1000), "", "v3")
	malformed := append(bytes.Clone(value), 0)
	original, originalMalformed := bytes.Clone(value), bytes.Clone(malformed)
	stored, err := decodeStoredEntry(value)
	if err != nil {
		t.Fatal(err)
	}
	_, decodeErr := decodeStoredEntry(malformed)
	if decodeErr == nil {
		t.Fatal("malformed fixture decoded successfully")
	}
	stop := errors.New("callback stop")
	for _, mode := range []string{"success", "callback-error", "callback-panic", "decode-error", "cancel-error", "cancel-continue"} {
		for _, at := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/at%d", mode, at), func(t *testing.T) {
				holdIdleReadOnlyCandidateDecoders(t)
				decoder := new(readOnlyCandidateDecoder)
				releaseReadOnlyCandidateDecoder(decoder)
				encoded := []encodedEqualityIndexCandidate{{value: value, identity: []byte("first")}, {value: value, identity: []byte("second")}}
				if mode == "decode-error" {
					encoded[at-1].value = malformed
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var recovered any
				var resultErr error
				count, calls := 0, 0
				func() {
					defer func() { recovered = recover() }()
					count, resultErr = forEachReadOnlyEncodedCandidate(encoded, func(entry directory.Entry) error {
						if &entry.Attributes[0] != &decoder.attributes[0] {
							t.Error("callback did not borrow the acquired decoder")
						}
						if !reflect.DeepEqual(entry, stored.Entry.WithDNIdentityKey(string(encoded[calls].identity))) {
							t.Error("callback changed decoded content, flags, identity, or order")
						}
						calls++
						if calls == at {
							switch mode {
							case "callback-error":
								return stop
							case "callback-panic":
								panic(stop)
							case "cancel-error":
								cancel()
								return ctx.Err()
							case "cancel-continue":
								cancel()
							}
						}
						return nil
					})
				}()
				wantCount, wantCalls, wantErr := 2, 2, error(nil)
				switch mode {
				case "callback-error":
					wantCount, wantCalls, wantErr = at-1, at, stop
				case "cancel-error":
					wantCount, wantCalls, wantErr = at-1, at, context.Canceled
				case "decode-error":
					wantCount, wantCalls, wantErr = at-1, at-1, decodeErr
				}
				if mode == "callback-panic" {
					if recovered != stop || calls != at {
						t.Errorf("panic/calls = %v/%d, want original panic/%d", recovered, calls, at)
					}
				} else if recovered != nil || count != wantCount || calls != wantCalls ||
					fmt.Sprint(resultErr) != fmt.Sprint(wantErr) || reflect.TypeOf(resultErr) != reflect.TypeOf(wantErr) {
					t.Errorf("count/calls/error/panic = %d/%d/%v/%v, want %d/%d/%v/nil", count, calls, resultErr, recovered, wantCount, wantCalls, wantErr)
				}
				if len(idleReadOnlyCandidateDecoders) != 1 {
					t.Fatalf("exit retained %d idle decoders, want 1", len(idleReadOnlyCandidateDecoders))
				}
				if got := acquireReadOnlyCandidateDecoder(); got != decoder {
					t.Fatal("exit did not release the active decoder")
				}
				assertReadOnlyCandidateDecoderCleared(t, decoder)
				if !bytes.Equal(value, original) || !bytes.Equal(malformed, originalMalformed) {
					t.Fatal("iteration or release modified encoded payload bytes")
				}
			})
		}
	}
}

func TestReadOnlyCandidatePoolPlanningCancellation(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(fmt.Sprintf("bounded%v", bounded), func(t *testing.T) {
			store, schema, filter := newSmallGroupCandidateStore(t, 2, 1000, "v3")
			for _, before := range []bool{false, true} {
				t.Run(fmt.Sprintf("before%v", before), func(t *testing.T) {
					holdIdleReadOnlyCandidateDecoders(t)
					if err := store.View(t.Context(), func(reader Reader) error {
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						tx := reader.(*boltTx)
						if before {
							cancel()
							tx.ctx = ctx
						} else {
							tx.ctx = &candidateDoneCancelContext{Context: ctx, cancel: cancel, cancelAt: 1}
						}
						scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
						iterate := ForEachReadOnlyFilterCandidate
						if bounded {
							iterate = func(reader Reader, filter directory.Filter, fn func(directory.Entry) error) (bool, int, error) {
								return ForEachBoundedReadOnlyFilterCandidate(reader, filter, 2, fn)
							}
						}
						calls := 0
						_, count, err := iterate(scoped, filter, func(directory.Entry) error { calls++; return nil })
						if !errors.Is(err, context.Canceled) || count != 0 || calls != 0 {
							t.Errorf("canceled count/calls/error = %d/%d/%v", count, calls, err)
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					if len(idleReadOnlyCandidateDecoders) != 0 {
						t.Fatal("canceled planning acquired a decoder before borrowing")
					}
				})
			}
		})
	}
}

func TestReadOnlyCandidatePoolConcurrentStoresAndClones(t *testing.T) {
	holdIdleReadOnlyCandidateDecoders(t)
	workers := cap(idleReadOnlyCandidateDecoders) + 4
	stores := make([]*Bolt, workers)
	schemas := make([]indexTestSchema, workers)
	filters := make([]directory.Filter, workers)
	want := make([][]directory.Entry, workers)
	clones := make([][]directory.Entry, workers)
	for i := range workers {
		stores[i], schemas[i], filters[i] = newSmallGroupCandidateStore(t, 2, 129+i, "v3")
		if err := stores[i].View(t.Context(), func(reader Reader) error {
			scoped := ReaderInPartitionWithNormalizer(reader, "db", schemas[i])
			planned, count, err := ForEachFilterCandidate(scoped, filters[i], func(entry directory.Entry) error {
				want[i] = append(want[i], entry.Clone())
				return nil
			})
			if err != nil || !planned || count != 2 {
				return fmt.Errorf("owned fixture planned/count/error = %v/%d/%v", planned, count, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	type lease struct {
		worker    int
		attribute *directory.Attribute
		value     *[]byte
	}
	entered := make(chan lease, workers)
	resume := make(chan struct{})
	completed := make(chan error, workers)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var group sync.WaitGroup
	for i := range workers {
		group.Go(func() {
			err := stores[i].View(ctx, func(reader Reader) error {
				tx := reader.(*boltTx)
				original := make(map[string][]byte)
				if err := tx.entries.ForEach(func(key, value []byte) error {
					original[string(key)] = bytes.Clone(value)
					return nil
				}); err != nil {
					return err
				}
				calls := 0
				visit := func(entry directory.Entry) error {
					if calls == 0 {
						member := entry.Attributes[len(entry.Attributes)-1]
						identity, _ := entry.DNIdentity()
						encoded := tx.entries.Get([]byte(partitionedEntryKey("db", identity)))
						value := member.Values[len(member.Values)-1]
						position := bytes.Index(encoded, value)
						if position < 0 || &value[0] != &encoded[position] {
							return errors.New("concurrent fixture did not borrow Bolt payloads")
						}
						entered <- lease{i, &entry.Attributes[0], &member.Values[0]}
						select {
						case <-resume:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					if calls >= len(want[i]) || !reflect.DeepEqual(entry, want[i][calls]) {
						return errors.New("concurrent decoder changed another store's callback")
					}
					clones[i] = append(clones[i], entry.Clone())
					calls++
					return nil
				}
				scoped := ReaderInPartitionWithNormalizer(reader, "db", schemas[i])
				var planned bool
				var count int
				var err error
				if i%2 == 0 {
					planned, count, err = ForEachReadOnlyFilterCandidate(scoped, filters[i], visit)
				} else {
					planned, count, err = ForEachBoundedReadOnlyFilterCandidate(scoped, filters[i], 2, visit)
				}
				if err != nil || !planned || count != 2 || calls != 2 {
					return fmt.Errorf("iteration planned/count/calls/error = %v/%d/%d/%v", planned, count, calls, err)
				}
				for key, value := range original {
					if !bytes.Equal(tx.entries.Get([]byte(key)), value) {
						return errors.New("pool release changed stored payload bytes")
					}
				}
				return nil
			})
			completed <- err
		})
	}
	attributes := make(map[*directory.Attribute]int)
	values := make(map[*[]byte]int)
waitForCallbacks:
	for range workers {
		select {
		case active := <-entered:
			if other, present := attributes[active.attribute]; present {
				t.Errorf("workers %d and %d share active attribute descriptors", other, active.worker)
			}
			if other, present := values[active.value]; present {
				t.Errorf("workers %d and %d share active overflow descriptors", other, active.worker)
			}
			attributes[active.attribute], values[active.value] = active.worker, active.worker
		case err := <-completed:
			t.Errorf("iterator completed before all callbacks overlapped: %v", err)
			break waitForCallbacks
		case <-ctx.Done():
			t.Error(ctx.Err())
			break waitForCallbacks
		}
	}
	close(resume)
	group.Wait()
	close(completed)
	for err := range completed {
		if err != nil {
			t.Error(err)
		}
	}
	if len(idleReadOnlyCandidateDecoders) != cap(idleReadOnlyCandidateDecoders) {
		t.Errorf("idle count after concurrent release = %d, want %d", len(idleReadOnlyCandidateDecoders), cap(idleReadOnlyCandidateDecoders))
	}
	for len(idleReadOnlyCandidateDecoders) > 0 {
		decoder := acquireReadOnlyCandidateDecoder()
		assertReadOnlyCandidateDecoderCleared(t, decoder)
		if _, present := attributes[&decoder.attributes[0]]; !present {
			t.Error("pool returned a duplicate or unknown concurrent decoder")
		}
		delete(attributes, &decoder.attributes[0])
		if _, _, ok := decoder.borrowMetadata(encodeCandidateTestEntry(t, readOnlyOverflowEntry(1000), "", "v3")); !ok {
			t.Fatal("reacquired decoder could not decode a different row")
		}
	}
	for _, store := range stores {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for i := range workers {
		if !reflect.DeepEqual(clones[i], want[i]) {
			t.Fatalf("store %d clones changed after decoder reuse and Bolt unmap", i)
		}
	}
}
