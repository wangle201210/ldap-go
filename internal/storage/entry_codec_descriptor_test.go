package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func entryCodecDescriptorShapes() []struct {
	name  string
	entry directory.Entry
} {
	shapes := []struct {
		name  string
		entry directory.Entry
	}{{"Common", benchmarkBinaryEntryCodecEntry()}}
	add := func(name string, attributes []directory.Attribute) {
		shapes = append(shapes, struct {
			name  string
			entry directory.Entry
		}{name, directory.Entry{DN: "cn=test", Attributes: attributes}})
	}
	for _, n := range []int{0, 1, 2, 3, 4, 32, 33} {
		var attrs []directory.Attribute
		for range n {
			attrs = append(attrs, directory.Attribute{Description: "cn", Values: [][]byte{[]byte("x")}})
		}
		add(fmt.Sprintf("Attributes%d", n), attrs)
	}
	for _, n := range []int{4, 5, 8, 9, 64} {
		for _, position := range []int{0, 3, 5} {
			attrs := make([]directory.Attribute, 6)
			for i := range attrs {
				attrs[i] = directory.Attribute{Description: "cn", Values: [][]byte{[]byte("x")}}
			}
			attrs[position].Values = make([][]byte, n)
			for i := range attrs[position].Values {
				attrs[position].Values[i] = []byte{}
			}
			add(fmt.Sprintf("EmptyValues%dAt%d", n, position), attrs)
		}
	}
	for _, count := range []int{2, 3, 4, 8} {
		for _, n := range []int{2, 6, 32} {
			attrs := make([]directory.Attribute, n)
			for i := range attrs {
				attrs[i] = directory.Attribute{Description: "cn", Values: make([][]byte, count)}
				for j := range attrs[i].Values {
					attrs[i].Values[j] = []byte("x")
				}
			}
			add(fmt.Sprintf("Values%dEach%d", count, n), attrs)
		}
	}
	for _, n := range []int{171, 172, 1024} {
		add(fmt.Sprintf("ValueBytes%d", n), []directory.Attribute{
			{Description: "cn", Values: [][]byte{bytes.Repeat([]byte("x"), n)}},
			{Description: "sn", Values: [][]byte{bytes.Repeat([]byte("y"), 62)}},
			{Description: "cn", Values: [][]byte{[]byte("z")}},
			{Description: "sn", Values: [][]byte{[]byte("z")}},
		}) // The first two payloads are exactly 4*64 and 4*64+1 bytes.
	}
	add("OnlyOneNonempty", []directory.Attribute{
		{Description: "cn"}, {Description: "sn", Values: [][]byte{[]byte("x")}},
		{Description: "uid"}, {Description: "mail"},
	})
	add("NilAndEmpty", []directory.Attribute{
		{Description: "cn"}, {Description: "sn", Values: [][]byte{}},
		{Description: "binary", Values: [][]byte{nil, {}, {0, 0xff}, []byte("last")}},
		{Description: "uid", Values: [][]byte{[]byte("alice")}},
	})
	return shapes
}

func entryCodecDescriptorPayload(attributes []directory.Attribute) []byte {
	value := binary.AppendUvarint(nil, uint64(len(attributes)))
	for _, attr := range attributes {
		value = appendEntryBinaryField(value, []byte(attr.Description))
		value = binary.AppendUvarint(value, uint64(len(attr.Values)))
		for _, raw := range attr.Values {
			value = appendEntryBinaryField(value, raw)
		}
	}
	return value
}

func TestBinaryEntryDescriptorOwnership(t *testing.T) {
	t.Parallel()
	for _, shape := range entryCodecDescriptorShapes() {
		for _, version := range []byte{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/V%d", shape.name, version), func(t *testing.T) {
				entry := shape.entry
				payload := entryCodecDescriptorPayload(entry.Attributes)
				binding := entryDNBinding("identity", entry.DN)
				want, err := entryCodecOriginalAttributes([]byte(entry.DN), binding[:], payload)
				if err != nil {
					t.Fatal(err)
				}
				encoded := []byte{0, 'L', 'G', 'E', version}
				if version == 3 {
					flags := make([]byte, (len(entry.Attributes)+7)/8)
					for i := range want.Attributes {
						if i%2 == 0 {
							flags[i/8] |= 1 << uint(i%8)
							want.Attributes[i].RawNormalized = true
						}
					}
					encoded = appendEntryBinaryField(encoded, flags)
				}
				encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
				if version == 1 {
					encoded = appendEntryBinaryField(encoded, []byte("identity"))
					encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
					want.DNIdentity, want.DNSource, want.DNBinding = "identity", entry.DN, nil
				} else {
					encoded = appendEntryBinaryField(encoded, binding[:])
				}
				encoded = append(encoded, payload...)
				got, err := decodeStoredEntry(encoded)
				if err != nil {
					t.Fatal(err)
				}
				other, err := decodeStoredEntry(encoded)
				if err != nil {
					t.Fatal(err)
				}
				clear(encoded)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("decoded entry differs from original: got %#v, want %#v", got, want)
				}
				entryCodecCheckCapacities(t, got)
				for i := range got.Attributes {
					attr := &got.Attributes[i]
					for j, raw := range attr.Values {
						attr.Values[j] = append(raw, '!')
						if !reflect.DeepEqual(attr.Values[j+1:], want.Attributes[i].Values[j+1:]) {
							t.Fatal("appending bytes changed adjacent values")
						}
					}
					attr.Values = append(attr.Values, []byte("extra"))
					attr.Values[len(attr.Values)-1] = []byte("replacement")
					if !reflect.DeepEqual(got.Attributes[i+1:], want.Attributes[i+1:]) {
						t.Fatal("appending descriptors changed adjacent attributes")
					}
				}
				if len(got.DNBinding) > 0 {
					got.DNBinding[0] ^= 0xff
				}
				if !reflect.DeepEqual(other, want) {
					t.Fatal("one decode changed another decode")
				}
			})
		}
	}
}

func entryCodecCheckCapacities(t *testing.T, entry storedEntry) {
	t.Helper()
	if cap(entry.Attributes) != len(entry.Attributes) || cap(entry.DNBinding) != len(entry.DNBinding) {
		t.Fatal("attribute or binding capacity differs from length")
	}
	for _, attr := range entry.Attributes {
		if cap(attr.Values) != len(attr.Values) {
			t.Fatal("descriptor capacity differs from length")
		}
		for _, raw := range attr.Values {
			if raw == nil || cap(raw) != len(raw) {
				t.Fatal("value is nil or capacity differs from length")
			}
		}
	}
}

func entryCodecCompareOriginal(t *testing.T, payload []byte) {
	t.Helper()
	got, err := decodeBinaryStoredEntryAttributes([]byte("cn=test"), nil, payload)
	want, wantErr := entryCodecOriginalAttributes([]byte("cn=test"), nil, payload)
	if fmt.Sprint(err) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
		t.Fatalf("payload %x: got %#v, %v; want %#v, %v", payload, got, err, want, wantErr)
	}
	if err == nil {
		entryCodecCheckCapacities(t, got)
	}
}

func TestBinaryEntryDescriptorDifferential(t *testing.T) {
	t.Parallel()
	for _, shape := range entryCodecDescriptorShapes() {
		t.Run(shape.name, func(t *testing.T) {
			payload := entryCodecDescriptorPayload(shape.entry.Attributes)
			entryCodecCompareOriginal(t, payload)
			entryCodecCompareOriginal(t, append(bytes.Clone(payload), 0))
			for i := range payload {
				entryCodecCompareOriginal(t, payload[:i])
				for _, replacement := range []byte{0, 8, 9, 64, 0x80, 0xff} {
					mutated := bytes.Clone(payload)
					mutated[i] = replacement
					entryCodecCompareOriginal(t, mutated)
				}
			}
		})
	}
	// Accepted nonminimal counts/lengths and overflowing/truncated varints.
	for _, payload := range [][]byte{
		{0x82, 0, 0x81, 0, 'a', 1, 0, 1, 'b', 1, 0},
		{2, 1, 'a', 0x81, 0, 0, 1, 'b', 1, 0},
		{2, 1, 'a', 1, 0x80, 0, 1, 'b', 1, 0},
		binary.AppendUvarint(nil, ^uint64(0)),
		append([]byte{2, 0}, binary.AppendUvarint(nil, ^uint64(0))...),
		append([]byte{2, 0, 1}, bytes.Repeat([]byte{0x80}, 11)...),
	} {
		entryCodecCompareOriginal(t, payload)
	}
}

func FuzzBinaryEntryDescriptorDecode(f *testing.F) {
	for _, shape := range entryCodecDescriptorShapes() {
		f.Add(entryCodecDescriptorPayload(shape.entry.Attributes))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		entryCodecCompareOriginal(t, payload)
	})
}

func BenchmarkBinaryEntryDescriptorShapes(b *testing.B) {
	for _, shape := range entryCodecDescriptorShapes() {
		b.Run(shape.name, func(b *testing.B) {
			benchmarkBinaryEntryCodecDecode(b, shape.entry)
		})
	}
}

// Keep the pre-packing decoder as an independent behavioral oracle, including
// its error ordering and nil/capacity conventions. Do not share the new probe.
func entryCodecOriginalAttributes(dn, binding, value []byte) (storedEntry, error) {
	remaining := value
	attributeCount, remaining, err := consumeEntryBinaryCount(remaining)
	if err != nil {
		return storedEntry{}, fmt.Errorf("attribute count: %w", err)
	}
	if attributeCount > len(remaining) {
		return storedEntry{}, errors.New("attribute count exceeds encoded entry size")
	}
	stored := storedEntry{
		Entry:     directory.Entry{DN: string(dn)},
		DNBinding: binding,
	}
	if attributeCount > 0 {
		stored.Attributes = make([]directory.Attribute, 0, attributeCount)
	}
	for attributeIndex := 0; attributeIndex < attributeCount; attributeIndex++ {
		description, next, fieldErr := consumeEntryBinaryField(remaining)
		if fieldErr != nil {
			return storedEntry{}, fmt.Errorf("attribute %d description: %w", attributeIndex, fieldErr)
		}
		valueCount, next, fieldErr := consumeEntryBinaryCount(next)
		if fieldErr != nil {
			return storedEntry{}, fmt.Errorf("attribute %d value count: %w", attributeIndex, fieldErr)
		}
		if valueCount > len(next) {
			return storedEntry{}, fmt.Errorf("attribute %d value count exceeds encoded entry size", attributeIndex)
		}
		attribute := directory.Attribute{Description: string(description)}
		if valueCount > 0 {
			attribute.Values = make([][]byte, 0, valueCount)
		}
		for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
			encodedValue, afterValue, valueErr := consumeEntryBinaryField(next)
			if valueErr != nil {
				return storedEntry{}, fmt.Errorf("attribute %d value %d: %w", attributeIndex, valueIndex, valueErr)
			}
			attribute.Values = append(attribute.Values, encodedValue)
			next = afterValue
		}
		stored.Attributes = append(stored.Attributes, attribute)
		remaining = next
	}
	if len(remaining) != 0 {
		return storedEntry{}, fmt.Errorf("%d trailing bytes", len(remaining))
	}
	return stored, nil
}
