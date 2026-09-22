package storage

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func decoderNameRows() []directory.Entry {
	base := benchmarkBinaryEntryCodecEntry()
	base.Attributes = append(base.Attributes, directory.Attribute{Description: "createTimestamp", Values: [][]byte{[]byte("stamp")}, RawNormalized: true})
	reversed := base.Clone()
	slices.Reverse(reversed.Attributes)
	short := base.Clone()
	short.Attributes = short.Attributes[:1]
	changed := base.Clone()
	for i := range changed.Attributes {
		changed.Attributes[i].Description = strings.ToUpper(changed.Attributes[i].Description)
		changed.Attributes[i].RawNormalized = false
	}
	long := base.Clone()
	long.Attributes = append(long.Attributes, directory.Attribute{Description: strings.Repeat("longName", 128), Values: [][]byte{nil, {}, []byte{0, 255}}})
	return []directory.Entry{base, base, reversed, short, base, changed, changed, long, long, base}
}

func TestReadOnlyDecoderNameReuseTransitions(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	var names []string
	var wantNames []string
	for _, format := range []string{"v3", "v2", "v1", "json"} {
		for _, entry := range decoderNameRows() {
			encoded := encodeCandidateTestEntry(t, entry, "dn:v2:identity", format)
			for _, partial := range [][]byte{encoded[:len(encoded)/2], append(bytes.Clone(encoded), 0)} {
				_, _ = decoder.decode(partial)
			}
			want, err := decodeStoredEntry(encoded)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decoder.decode(encoded)
			if err != nil || !reflect.DeepEqual(got, want.Entry) {
				t.Fatalf("%s reordered row differs: %v", format, err)
			}
			for i, attr := range got.Attributes {
				names = append(names, attr.Description)
				wantNames = append(wantNames, want.Attributes[i].Description)
			}
			clear(encoded)
		}
	}
	if !slices.Equal(names, wantNames) {
		t.Fatal("reused names did not retain independent storage")
	}
	if len(decoder.names) > maxReadOnlyCandidateNames {
		t.Fatal("interning limit changed")
	}
}

func BenchmarkReadOnlyDecoderNameLayouts(b *testing.B) {
	rows := decoderNameRows()
	for _, test := range []struct {
		name    string
		entries []directory.Entry
	}{
		{"stable", rows[:2]}, {"reordered", []directory.Entry{rows[0], rows[2]}},
		{"shrinking", []directory.Entry{rows[0], rows[3]}}, {"case-changes", []directory.Entry{rows[0], rows[5]}},
		{"long-stable", rows[7:9]},
	} {
		b.Run(test.name, func(b *testing.B) {
			encoded := make([][]byte, len(test.entries))
			for i, entry := range test.entries {
				encoded[i] = encodeCandidateTestEntry(b, entry, "dn:v2:identity", "v3")
			}
			var decoder readOnlyCandidateDecoder
			for _, row := range encoded {
				if _, _, ok := decoder.borrowMetadata(row); !ok {
					b.Fatal("fixture not borrowed")
				}
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				dn, attrs, ok := decoder.borrowMetadata(encoded[i])
				if !ok || len(dn) == 0 || len(attrs) != len(test.entries[i].Attributes) {
					b.Fatal(fmt.Sprintf("unexpected row %d", i))
				}
				i = (i + 1) % len(encoded)
			}
		})
	}
}
