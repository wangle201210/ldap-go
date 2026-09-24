package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func readOnlyOverflowEntry(counts ...int) directory.Entry {
	entry := directory.Entry{DN: "cn=overflow,dc=example"}
	for i, count := range counts {
		attribute := directory.Attribute{Description: fmt.Sprintf("attribute%d", i), RawNormalized: i%2 == 0}
		if count > 0 {
			attribute.Values = make([][]byte, count)
		}
		for j := range count {
			switch j % 19 {
			case 0:
				attribute.Values[j] = nil
			case 1:
				attribute.Values[j] = []byte{}
			case 2:
				attribute.Values[j] = []byte{0, 0xff, 0x80}
			default:
				attribute.Values[j] = []byte(fmt.Sprintf("value%d_%d;", i, j))
			}
		}
		entry.Attributes = append(entry.Attributes, attribute)
	}
	return entry
}

func assertReadOnlyOverflowArena(t *testing.T, decoder *readOnlyCandidateDecoder, entry directory.Entry, encoded []byte) {
	t.Helper()
	entryCodecCheckCapacities(t, storedEntry{Entry: entry})
	count := 0
	for _, attribute := range entry.Attributes {
		count += len(attribute.Values)
	}
	if len(decoder.values) != 128 || cap(decoder.overflowValues) > 4096 {
		t.Fatalf("fixed/overflow arena sizes = %d/%d", len(decoder.values), cap(decoder.overflowValues))
	}
	values := decoder.values[:]
	if count > len(values) {
		values = decoder.overflowValues
	}
	position := 0
	for i, attribute := range entry.Attributes {
		if len(attribute.Values) == 0 {
			if attribute.Values != nil {
				t.Fatalf("attribute %d: empty Values must be nil", i)
			}
			continue
		}
		if &attribute.Values[0] != &values[position] {
			t.Fatalf("attribute %d: descriptors do not use the current arena", i)
		}
		for j, value := range attribute.Values {
			if j%19 <= 2 {
				continue
			}
			offset := bytes.Index(encoded, value)
			if offset < 0 || &value[0] != &encoded[offset] {
				t.Fatalf("attribute %d value %d: payload was copied", i, j)
			}
		}
		position += len(attribute.Values)
	}
}

func TestReadOnlyCandidateOverflowLimits(t *testing.T) {
	for _, counts := range [][]int{
		{128}, {129}, {1000}, {4096}, {4097},
		{63, 0, 65}, {127, 0, 2}, {4, 1000, 1}, {64, 65, 300, 0, 600},
		{127, 1, 1024, 2944}, {127, 1, 1024, 2945}, make([]int, 65),
	} {
		for _, format := range []string{"v1", "v2", "v3", "json"} {
			t.Run(fmt.Sprintf("%v/%s", counts, format), func(t *testing.T) {
				var decoder readOnlyCandidateDecoder
				entry := readOnlyOverflowEntry(counts...)
				encoded := encodeCandidateTestEntry(t, entry, "", format)
				want, err := decodeStoredEntry(encoded)
				if err != nil {
					t.Fatal(err)
				}
				total := 0
				for _, count := range counts {
					total += count
				}
				got, borrowed := decoder.borrow(encoded)
				wantBorrowed := format != "json" && len(counts) <= 64 && total <= 4096
				if borrowed != wantBorrowed {
					t.Fatalf("borrowed = %v, want %v", borrowed, wantBorrowed)
				}
				if borrowed {
					if !reflect.DeepEqual(got, want.Entry) {
						t.Fatal("borrowed entry differs from owned")
					}
					assertReadOnlyOverflowArena(t, &decoder, got, encoded)
				}
				if cap(decoder.overflowValues) > 4096 || total <= 128 && decoder.overflowValues != nil {
					t.Fatal("overflow arena exceeded its bound or allocated for a small row")
				}
				if len(counts) == 1 && total > 4096 && decoder.overflowValues != nil {
					t.Fatal("oversized attribute allocated an overflow arena")
				}
				if borrowed && total > 128 {
					size := 128
					for size < total {
						size *= 2
					}
					if len(decoder.overflowValues) != size {
						t.Fatalf("overflow arena = %d, want geometric capacity %d", len(decoder.overflowValues), size)
					}
				}
				assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, encoded)
			})
		}
	}
}

func TestReadOnlyCandidateOverflowLayoutReuseAndRetention(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	var clones, projections, materialized, expected, expectedProjections []directory.Entry
	var dns, wantDNs, names, wantNames []string
	var previousArena *[]byte
	previousCapacity := 0
	for i, row := range []struct {
		counts []int
		format string
	}{
		{[]int{1, 1000, 0}, "v3"},
		{[]int{0, 3}, "v2"},
		{[]int{127, 2, 300, 0, 1500, 1}, "v1"},
		{[]int{0}, "v3"},
		{nil, "v2"},
		{[]int{1000, 0, 1, 900}, "v3"},
		{[]int{0, 64, 0, 65, 0, 1}, "v2"},
	} {
		entry := readOnlyOverflowEntry(row.counts...)
		entry.DN = fmt.Sprintf("cn=row%d,dc=example", i)
		encoded := encodeCandidateTestEntry(t, entry, "", row.format)
		want, err := decodeStoredEntry(encoded)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := decoder.borrow(encoded)
		if !ok || !reflect.DeepEqual(got, want.Entry) {
			t.Fatalf("row %d: layout, flags, or nil/empty values differ from owned", i)
		}
		assertReadOnlyOverflowArena(t, &decoder, got, encoded)
		if len(decoder.overflowValues) == previousCapacity && &decoder.overflowValues[0] != previousArena {
			t.Fatalf("row %d: overflow descriptors were allocated again", i)
		}
		previousCapacity, previousArena = len(decoder.overflowValues), &decoder.overflowValues[0]
		clones = append(clones, got.Clone())
		projections = append(projections, got.Select([]string{"*"}, false))
		expected = append(expected, want.Entry.Clone())
		expectedProjections = append(expectedProjections, want.Entry.Select([]string{"*"}, false))
		dns, wantDNs = append(dns, got.DN), append(wantDNs, want.DN)
		for j, attribute := range got.Attributes {
			names, wantNames = append(names, attribute.Description), append(wantNames, want.Attributes[j].Description)
		}
		view, err := decoder.decodeMetadata(encoded, nil)
		if err != nil {
			t.Fatal(err)
		}
		materialized = append(materialized, view.Materialize())
		clear(encoded)
	}
	if !reflect.DeepEqual(clones, expected) || !reflect.DeepEqual(projections, expectedProjections) ||
		!reflect.DeepEqual(materialized, expected) || !reflect.DeepEqual(dns, wantDNs) || !reflect.DeepEqual(names, wantNames) {
		t.Fatal("owned output retained borrowed bytes or descriptors across layout reuse")
	}
}

func TestReadOnlyCandidateOverflowErrorsAndRecovery(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	valid := encodeCandidateTestEntry(t, readOnlyOverflowEntry(64, 65, 900), "", "v3")
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		for _, count := range []int{1000, 4097} {
			encoded := encodeCandidateTestEntry(t, readOnlyOverflowEntry(64, 65, count), "", format)
			damaged := [][]byte{encoded[:len(encoded)-1], append(bytes.Clone(encoded), 0xff)}
			if format != "json" {
				badLength := bytes.Clone(encoded)
				position := bytes.Index(badLength, []byte("value2_999;"))
				if position < 1 {
					t.Fatal("missing late value")
				}
				badLength[position-1] = 0xff
				damaged = append(damaged, badLength)
			}
			if format == "v3" {
				badFlags := bytes.Clone(encoded)
				flags, _, err := consumeEntryBinaryField(badFlags[len(entryBinaryV3Prefix):])
				if err != nil {
					t.Fatal(err)
				}
				flags[0] |= 0x80
				damaged = append(damaged, badFlags)
			}
			for i, payload := range damaged {
				t.Run(fmt.Sprintf("%s/%d/damage%d", format, count, i), func(t *testing.T) {
					if _, err := decodeStoredEntry(payload); err == nil {
						t.Fatal("corruption fixture was accepted")
					}
					assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, payload)
					assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, valid)
				})
			}
		}
	}
	for _, count := range []uint64{4097, ^uint64(0)} {
		payload := appendEntryBinaryField(bytes.Clone(entryBinaryPrefix), []byte("cn=overflow"))
		payload = appendEntryBinaryField(payload, nil)
		payload = binary.AppendUvarint(payload, 2)
		payload = appendEntryBinaryField(payload, []byte("first"))
		payload = binary.AppendUvarint(payload, 129)
		for range 129 {
			payload = appendEntryBinaryField(payload, nil)
		}
		payload = appendEntryBinaryField(payload, []byte("last"))
		payload = binary.AppendUvarint(payload, count)
		assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, payload)
		assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, valid)
	}
}

func TestReadOnlyCandidateOverflowLayoutsAfterUnmap(t *testing.T) {
	store, schema, filter := newSmallGroupCandidateStore(t, 4, 1000, "v3")
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		for i, ref := range boltCandidateReferences(t, tx) {
			key := boltCandidateKey(t, tx, ref)
			stored, err := decodeStoredEntry(tx.entries.Get(key))
			if err != nil {
				return err
			}
			member := len(stored.Attributes) - 1
			stored.Attributes[member].Values = readOnlyOverflowEntry([]int{1000, 1, 3000, 1000}[i]).Attributes[0].Values
			_, identity := splitPartitionedEntryKey(string(key))
			if err := tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, []string{"v3", "v2", "v1", "v3"}[i])); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var clones, projections, want, wantProjections []directory.Entry
	if err := store.View(t.Context(), func(reader Reader) error {
		scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
		for i, iterate := range []readOnlyCandidateIterator{ForEachFilterCandidate, ForEachReadOnlyFilterCandidate} {
			planned, count, err := iterate(scoped, filter, func(entry directory.Entry) error {
				if i == 0 {
					want = append(want, entry)
					wantProjections = append(wantProjections, entry.Select([]string{"cn", "member"}, false))
				} else {
					clones = append(clones, entry.Clone())
					projections = append(projections, entry.Select([]string{"cn", "member"}, false))
				}
				return nil
			})
			if !planned || count != 4 || err != nil {
				t.Fatalf("planned/count/error = %v/%d/%v", planned, count, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(clones, want) || !reflect.DeepEqual(projections, wantProjections) {
		t.Fatal("large/small/large output changed after arena reuse and Bolt unmap")
	}
}
