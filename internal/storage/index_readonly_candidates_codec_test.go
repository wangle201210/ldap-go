package storage

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func readOnlyCandidateShapes() []struct {
	name  string
	entry directory.Entry
} {
	shapes := entryCodecDescriptorShapes()
	add := func(name string, attributes []directory.Attribute) {
		shapes = append(shapes, struct {
			name  string
			entry directory.Entry
		}{name, directory.Entry{DN: "cn=test", Attributes: attributes}})
	}
	add("EmptyAttributes", []directory.Attribute{})
	add("ExactDescriptions", []directory.Attribute{
		{Description: "CN;lang-EN", Values: [][]byte{[]byte("upper")}},
		{Description: "cn;lang-en", Values: [][]byte{[]byte("lower")}},
		{Description: "Cn;LANG-en", Values: [][]byte{nil, {}, {0, 0xff}}},
		{Description: "", Values: [][]byte{}},
		{Description: "binary;BINARY", Values: [][]byte{[]byte("\x00\xff\x80")}},
		{Description: strings.Repeat("a", 128)},
		{Description: strings.Repeat("b", 129)},
		{Description: "invalid\x00\xff"},
	})
	for _, counts := range [][2]int{{64, 2}, {65, 1}, {1, 128}, {1, 129}, {64, 3}} {
		attributes := make([]directory.Attribute, counts[0])
		for i := range attributes {
			attributes[i] = directory.Attribute{
				Description: fmt.Sprintf("attribute%d", i), Values: make([][]byte, counts[1]),
			}
			for j := range attributes[i].Values {
				attributes[i].Values[j] = []byte(fmt.Sprintf("value%d/%d", i, j))
			}
		}
		add(fmt.Sprintf("Attributes%dValuesEach%d", counts[0], counts[1]), attributes)
	}
	return shapes
}

func TestReadOnlyCandidateCodecShapes(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	for _, shape := range readOnlyCandidateShapes() {
		for i := range shape.entry.Attributes {
			shape.entry.Attributes[i].RawNormalized = i%2 == 0
		}
		for _, format := range []string{"v3", "v2", "v1", "json"} {
			t.Run(shape.name+"/"+format, func(t *testing.T) {
				encoded := encodeCandidateTestEntry(t, shape.entry, "dn:v2:identity", format)
				original := bytes.Clone(encoded)
				want, err := decodeStoredEntry(encoded)
				if err != nil {
					t.Fatal(err)
				}
				valueCount := 0
				for _, attribute := range want.Attributes {
					valueCount += len(attribute.Values)
				}
				wantBorrowed := format != "json" && len(want.Attributes) <= 64 && valueCount <= 128
				borrowed, ok := decoder.borrow(encoded)
				if ok != wantBorrowed {
					t.Fatalf("borrow gate = %v, want %v", ok, wantBorrowed)
				}
				if ok {
					entryCodecCheckCapacities(t, storedEntry{Entry: borrowed})
					if !reflect.DeepEqual(borrowed, want.Entry) {
						t.Fatal("borrowed bytes, nil/empty slices, descriptions, or flags differ")
					}
				}
				got, err := decoder.decode(encoded)
				if err != nil || !reflect.DeepEqual(got, want.Entry) {
					t.Fatalf("decode differs from owned: %v", err)
				}
				wantEncoded := encodeCandidateTestEntry(t, want.Entry, "dn:v2:identity", format)
				if reencoded := encodeCandidateTestEntry(t, got, "dn:v2:identity", format); !bytes.Equal(reencoded, wantEncoded) {
					t.Fatal("roundtrip changed exact row bytes")
				}
				clone, selected := got.Clone(), got.Select([]string{"*"}, false)
				wantClone, wantSelected := want.Entry.Clone(), want.Entry.Select([]string{"*"}, false)
				if !bytes.Equal(encoded, original) {
					t.Fatal("read-only decode or projection changed row bytes")
				}
				clear(encoded)
				// Reuse every descriptor and clear flags before inspecting owned output.
				replacement := encodeCandidateTestEntry(t, directory.Entry{DN: "cn=other", Attributes: []directory.Attribute{
					{Description: "other", Values: [][]byte{[]byte("replacement")}},
				}}, "", "v2")
				if _, err := decoder.decode(replacement); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(clone, wantClone) || !reflect.DeepEqual(selected, wantSelected) || got.DN != want.DN {
					t.Fatal("clone, selection, or DN retained borrowed data")
				}
			})
		}
	}
}

func TestReadOnlyCandidateDescriptorReuseAndNameBounds(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	entry := directory.Entry{DN: "cn=test", Attributes: []directory.Attribute{
		{Description: "CN;lang-EN", RawNormalized: true, Values: [][]byte{[]byte("first"), {}}},
		{Description: "cn;lang-en", Values: [][]byte{[]byte("second")}},
	}}
	encoded := encodeCandidateTestEntry(t, entry, "", "v3")
	got, ok := decoder.borrow(encoded)
	if !ok || &got.Attributes[0] != &decoder.attributes[0] || &got.Attributes[0].Values[0] != &decoder.values[0] || &got.Attributes[1].Values[0] != &decoder.values[2] {
		t.Fatal("descriptors do not use the bounded arenas")
	}
	position := bytes.Index(encoded, []byte("first"))
	if &got.Attributes[0].Values[0][0] != &encoded[position] {
		t.Fatal("value payload was copied")
	}
	retainedName := got.Attributes[0].Description
	clear(encoded)
	if retainedName != "CN;lang-EN" || decoder.names["cn;lang-en"] != "cn;lang-en" || len(decoder.names) != 2 {
		t.Fatal("names are not owned or exact-case")
	}
	for _, length := range []int{128, 129} {
		name := bytes.Repeat([]byte{'x'}, length)
		if got := decoder.internName(name); got != string(name) {
			t.Fatal("long name changed")
		}
		if _, cached := decoder.names[string(name)]; cached != (length == 128) {
			t.Fatalf("name length %d cached = %v", length, cached)
		}
	}
	for i := range 300 {
		name := fmt.Sprintf("name%d;OPTION", i)
		if got := decoder.internName([]byte(name)); got != name {
			t.Fatal("cache overflow changed spelling")
		}
	}
	if len(decoder.names) != maxReadOnlyCandidateNames {
		t.Fatalf("name cache size = %d", len(decoder.names))
	}
	name := []byte("CN;lang-EN")
	if allocations := testing.AllocsPerRun(100, func() {
		if decoder.internName(name) != "CN;lang-EN" {
			t.Fatal("interning changed spelling")
		}
	}); allocations != 0 {
		t.Fatalf("cached name lookup allocations = %v", allocations)
	}
	entry.Attributes[0].RawNormalized = false
	encoded = encodeCandidateTestEntry(t, entry, "", "v2")
	got, ok = decoder.borrow(encoded)
	if !ok || &got.Attributes[0] != &decoder.attributes[0] || &got.Attributes[0].Values[0] != &decoder.values[0] || got.Attributes[0].RawNormalized {
		t.Fatal("descriptors were not reused or V3 normalization flag leaked into V2")
	}
}

func assertReadOnlyCandidateDecodeMatchesOwned(t testing.TB, decoder *readOnlyCandidateDecoder, value []byte) {
	t.Helper()
	want, wantErr := decodeStoredEntry(value)
	got, err := decoder.decode(value)
	if fmt.Sprint(err) != fmt.Sprint(wantErr) || reflect.TypeOf(err) != reflect.TypeOf(wantErr) || !reflect.DeepEqual(got, want.Entry) {
		t.Fatalf("value %x: got %#v, %v; want %#v, %v", value, got, err, want.Entry, wantErr)
	}
	if err == nil && !reflect.DeepEqual(got.Clone(), want.Entry.Clone()) {
		t.Fatal("clone differs from owned")
	}
}

func TestReadOnlyCandidateCodecDifferential(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	seeds := candidateCodecSeeds(t)
	seeds = append(seeds, []byte("null"), []byte(`{"dn":"cn=test","attributes":[]}`), []byte{0, 'L', 'G', 'E', 4})
	for _, seed := range seeds {
		assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, seed)
		for end := range seed {
			assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, seed[:end])
			for _, mask := range []byte{1, 0x80, 0xff} {
				mutated := bytes.Clone(seed)
				mutated[end] ^= mask
				assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, mutated)
			}
		}
		assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, append(bytes.Clone(seed), 0))
	}
}

func FuzzReadOnlyCandidateDecode(f *testing.F) {
	for _, seed := range candidateCodecSeeds(f) {
		f.Add(seed)
	}
	for _, shape := range readOnlyCandidateShapes() {
		f.Add(encodeCandidateTestEntry(f, shape.entry, "dn:v2:identity", "v3"))
	}
	f.Add([]byte(`{"dn":"cn=test","attributes":[{"description":"a","values":[null,""]}]}`))
	f.Fuzz(func(t *testing.T, value []byte) {
		var decoder readOnlyCandidateDecoder
		assertReadOnlyCandidateDecodeMatchesOwned(t, &decoder, value)
	})
}
