package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestBinaryEntryCodecRoundTrip(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("top"), []byte("person")}},
			{Description: "jpegPhoto", Values: [][]byte{{0, 0xff, 0x10}, {}}},
			{Description: "description"},
		},
	}
	encoded, err := encodeEntry(entry, "normalized-key", entry.DN)
	if err != nil {
		t.Fatalf("encodeEntry(): %v", err)
	}
	if !bytes.HasPrefix(encoded, entryBinaryPrefix) {
		t.Fatalf("encoded prefix = %x", encoded[:min(len(encoded), len(entryBinaryPrefix))])
	}
	decoded, err := decodeStoredEntry(encoded)
	if err != nil {
		t.Fatalf("decodeStoredEntry(): %v", err)
	}
	wantBinding := entryDNBinding("normalized-key", entry.DN)
	if !reflect.DeepEqual(decoded.Entry, entry) ||
		!bytes.Equal(decoded.DNBinding, wantBinding[:]) ||
		decoded.DNIdentity != "" || decoded.DNSource != "" {
		t.Fatalf("decoded entry = %#v", decoded)
	}
}

func TestBinaryEntryCodecDecodeOwnsEncodedData(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "uid",
			Values:      [][]byte{[]byte("alice"), []byte("second")},
		}},
	}
	encoded, err := encodeEntry(entry, "normalized-key", entry.DN)
	if err != nil {
		t.Fatalf("encodeEntry(): %v", err)
	}
	decoded, err := decodeStoredEntry(encoded)
	if err != nil {
		t.Fatalf("decodeStoredEntry(): %v", err)
	}
	for index := range encoded {
		encoded[index] = 0
	}
	if !reflect.DeepEqual(decoded.Entry, entry) {
		t.Fatalf("decoded entry changed with encoded input: %#v", decoded.Entry)
	}
	wantBinding := entryDNBinding("normalized-key", entry.DN)
	if !bytes.Equal(decoded.DNBinding, wantBinding[:]) {
		t.Fatalf("decoded binding changed with encoded input: %x", decoded.DNBinding)
	}
	second := bytes.Clone(decoded.Attributes[0].Values[1])
	decoded.Attributes[0].Values[0] = append(
		decoded.Attributes[0].Values[0],
		" extended"...,
	)
	if string(decoded.Attributes[0].Values[0]) != "alice extended" {
		t.Fatalf("extended decoded value = %q", decoded.Attributes[0].Values[0])
	}
	if !bytes.Equal(decoded.Attributes[0].Values[1], second) {
		t.Fatalf("extending one decoded value changed another: %q", decoded.Attributes[0].Values[1])
	}
}

func TestEntryCodecReadsBinaryV1(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "uid",
			Values:      [][]byte{[]byte("alice")},
		}},
	}
	encoded := append([]byte(nil), entryBinaryV1Prefix...)
	encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
	encoded = appendEntryBinaryField(encoded, []byte("normalized-key"))
	encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
	encoded = binary.AppendUvarint(encoded, 1)
	encoded = appendEntryBinaryField(encoded, []byte("uid"))
	encoded = binary.AppendUvarint(encoded, 1)
	encoded = appendEntryBinaryField(encoded, []byte("alice"))

	decoded, err := decodeStoredEntry(encoded)
	if err != nil {
		t.Fatalf("decodeStoredEntry(): %v", err)
	}
	if !reflect.DeepEqual(decoded.Entry, entry) ||
		decoded.DNIdentity != "normalized-key" || decoded.DNSource != entry.DN ||
		len(decoded.DNBinding) != 0 {
		t.Fatalf("decoded v1 entry = %#v", decoded)
	}
}

func TestEntryCodecDNBindingRejectsAnotherPhysicalKey(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{DN: "uid=alice,dc=example,dc=com"}
	binding := entryDNBinding("dn:v2:first", entry.DN)
	if err := validateStoredEntryIdentity(
		"dn:v2:second",
		entry,
		"",
		"",
		binding[:],
	); err == nil {
		t.Fatal("validateStoredEntryIdentity() accepted a binding for another key")
	}
}

func TestEntryCodecReadsLegacyJSON(t *testing.T) {
	t.Parallel()

	want := storedEntry{
		Entry: directory.Entry{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{{
				Description: "dc",
				Values:      [][]byte{[]byte("example")},
			}},
		},
		DNIdentity: "legacy-identity",
		DNSource:   "dc=example,dc=com",
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	got, err := decodeStoredEntry(encoded)
	if err != nil {
		t.Fatalf("decodeStoredEntry(): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy decoded entry = %#v, want %#v", got, want)
	}
}

func TestBinaryEntryCodecRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	for _, value := range [][]byte{
		entryBinaryPrefix,
		append(bytes.Clone(entryBinaryPrefix), 0x80),
		append(bytes.Clone(entryBinaryPrefix), 2, 'a'),
		append(bytes.Clone(entryBinaryPrefix), 0, 0, 0, 1),
	} {
		if _, err := decodeStoredEntry(value); err == nil {
			t.Fatalf("decodeStoredEntry(%x) succeeded", value)
		}
	}
}

func TestBinaryEntryCodecAttributeErrors(t *testing.T) {
	t.Parallel()

	overflow := binary.AppendUvarint(nil, ^uint64(0))
	for _, test := range []struct {
		name    string
		payload []byte
		want    string
	}{
		{"attribute-count", nil, "attribute count: invalid count"},
		{"attribute-count-overflow", overflow, "attribute count: count overflows int"},
		{"attribute-count-size", []byte{2, 0}, "attribute count exceeds encoded entry size"},
		{"description-length", []byte{1, 0x80}, "attribute 0 description: invalid length"},
		{"description-truncated", []byte{1, 3, 'c'}, "attribute 0 description: truncated value"},
		{"value-count", []byte{1, 0, 0x80}, "attribute 0 value count: invalid count"},
		{"value-count-overflow", append([]byte{1, 0}, overflow...), "attribute 0 value count: count overflows int"},
		{"value-count-size", []byte{1, 0, 2, 0}, "attribute 0 value count exceeds encoded entry size"},
		{"value-length", []byte{1, 0, 1, 0x80}, "attribute 0 value 0: invalid length"},
		{"value-truncated", []byte{1, 0, 1, 2, 'x'}, "attribute 0 value 0: truncated value"},
		{"second-value", []byte{1, 0, 2, 0, 0x80}, "attribute 0 value 1: invalid length"},
		{"second-attribute", []byte{2, 0, 0, 0x80}, "attribute 1 description: invalid length"},
		{"trailing", []byte{0, 1}, "1 trailing bytes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []struct {
				name   string
				prefix []byte
				header []byte
				wrap   string
			}{
				{"v1", entryBinaryV1Prefix, []byte{0, 0, 0}, "decode entry: "},
				{"v2", entryBinaryPrefix, []byte{0, 0}, "decode entry: "},
				// The invalid bitmap must not mask an earlier payload error.
				{"v3", entryBinaryV3Prefix, []byte{1, 0x80, 0, 0}, ""},
			} {
				t.Run(format.name, func(t *testing.T) {
					encoded := append(bytes.Clone(format.prefix), format.header...)
					encoded = append(encoded, test.payload...)
					got, err := decodeStoredEntry(encoded)
					if err == nil || err.Error() != format.wrap+test.want {
						t.Fatalf("decodeStoredEntry() error = %v, want %q", err, format.wrap+test.want)
					}
					if !reflect.DeepEqual(got, storedEntry{}) {
						t.Fatalf("failed decode returned partial entry: %#v", got)
					}
				})
			}
		})
	}
}

func TestBinaryEntryCodecValueSliceIsolation(t *testing.T) {
	t.Parallel()

	for _, prefix := range [][]byte{entryBinaryV1Prefix, entryBinaryPrefix, entryBinaryV3Prefix} {
		for _, attributes := range [][]directory.Attribute{
			nil,
			{
				{Description: "description"},
				{Description: "uid", Values: [][]byte{[]byte("alice"), {}}},
				{Description: "cn", Values: [][]byte{[]byte("Alice")}},
				{Description: "jpegPhoto", Values: [][]byte{bytes.Repeat([]byte{0xff}, 256)}},
			},
		} {
			want := directory.Entry{DN: "uid=alice", Attributes: attributes}
			encoded := bytes.Clone(prefix)
			if bytes.Equal(prefix, entryBinaryV3Prefix) {
				var flags []byte
				if len(attributes) > 0 {
					attributes[2].RawNormalized = true
					flags = []byte{4}
				}
				encoded = appendEntryBinaryField(encoded, flags)
			}
			encoded = appendEntryBinaryField(encoded, []byte(want.DN))
			encoded = appendEntryBinaryField(encoded, nil)
			if bytes.Equal(prefix, entryBinaryV1Prefix) {
				encoded = appendEntryBinaryField(encoded, nil)
			}
			encoded = binary.AppendUvarint(encoded, uint64(len(attributes)))
			for _, attr := range attributes {
				encoded = appendEntryBinaryField(encoded, []byte(attr.Description))
				encoded = binary.AppendUvarint(encoded, uint64(len(attr.Values)))
				for _, value := range attr.Values {
					encoded = appendEntryBinaryField(encoded, value)
				}
			}
			got, err := decodeStoredEntry(encoded)
			if err != nil {
				t.Fatalf("decodeStoredEntry(%x): %v", prefix, err)
			}
			clear(encoded)
			if !reflect.DeepEqual(got.Entry, want) {
				t.Fatalf("decodeStoredEntry(%x) = %#v, want %#v", prefix, got.Entry, want)
			}
			for _, attr := range got.Attributes {
				if cap(attr.Values) != len(attr.Values) {
					t.Fatalf("%s values capacity = %d, length = %d", attr.Description, cap(attr.Values), len(attr.Values))
				}
				for _, value := range attr.Values {
					if cap(value) != len(value) {
						t.Fatalf("%s value capacity = %d, length = %d", attr.Description, cap(value), len(value))
					}
				}
			}
			if len(got.Attributes) > 0 {
				got.Attributes[1].Values = append(got.Attributes[1].Values, []byte("extra"))
				got.Attributes[1].Values[0] = append(got.Attributes[1].Values[0], '!')
				if !reflect.DeepEqual(got.Attributes[2], want.Attributes[2]) ||
					got.Attributes[1].Values[1] == nil || len(got.Attributes[1].Values[1]) != 0 {
					t.Fatal("appending changed a neighboring attribute or empty value")
				}
			}
		}
	}
}

func TestBinaryEntryCodecNonMinimalVarints(t *testing.T) {
	t.Parallel()

	encoded := append(bytes.Clone(entryBinaryPrefix),
		0x80, 0, 0x80, 0, // Empty DN and binding.
		0x81, 0, 0x81, 0, 'a', 0x81, 0, 0x80, 0,
	)
	got, err := decodeStoredEntry(encoded)
	want := directory.Entry{Attributes: []directory.Attribute{{Description: "a", Values: [][]byte{{}}}}}
	if err != nil || !reflect.DeepEqual(got.Entry, want) {
		t.Fatalf("decodeStoredEntry() = %#v, %v; want %#v", got.Entry, err, want)
	}
}

func TestEntryCodecEmptyCollections(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		attributes []directory.Attribute
		binaryWant []directory.Attribute
	}{
		{"nil-attributes", nil, nil},
		{"empty-attributes", []directory.Attribute{}, nil},
		{"nil-values", []directory.Attribute{{Description: "a"}}, []directory.Attribute{{Description: "a"}}},
		{"empty-values", []directory.Attribute{{Description: "a", Values: [][]byte{}}}, []directory.Attribute{{Description: "a"}}},
		{"empty-value", []directory.Attribute{{Description: "a", Values: [][]byte{nil, {}}}}, []directory.Attribute{{Description: "a", Values: [][]byte{{}, {}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{DN: "cn=test", Attributes: test.attributes}
			encoded, err := encodeEntry(entry, "", "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeStoredEntry(encoded)
			if err != nil || !reflect.DeepEqual(got.Attributes, test.binaryWant) {
				t.Fatalf("binary attributes = %#v, %v; want %#v", got.Attributes, err, test.binaryWant)
			}
			encoded, err = json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			got, err = decodeStoredEntry(encoded)
			if err != nil || !reflect.DeepEqual(got.Entry, entry) {
				t.Fatalf("JSON entry = %#v, %v; want %#v", got.Entry, err, entry)
			}
		})
	}
}

func BenchmarkBinaryEntryCodecDecode(b *testing.B) {
	benchmarkBinaryEntryCodecDecode(b, benchmarkBinaryEntryCodecEntry())
}

func BenchmarkBinaryEntryCodecDecodeShapes(b *testing.B) {
	b.Run("SingleAttribute", func(b *testing.B) {
		entry := benchmarkBinaryEntryCodecEntry()
		entry.Attributes = entry.Attributes[1:2]
		benchmarkBinaryEntryCodecDecode(b, entry)
	})
	b.Run("OperationalV3", func(b *testing.B) {
		entry := benchmarkBinaryEntryCodecEntry()
		for _, name := range []string{
			"createTimestamp", "modifyTimestamp", "entryCSN", "entryUUID",
			"creatorsName", "modifiersName", "structuralObjectClass", "subschemaSubentry",
		} {
			entry.Attributes = append(entry.Attributes, directory.Attribute{
				Description:   name,
				Values:        [][]byte{[]byte("benchmark")},
				RawNormalized: true,
			})
		}
		benchmarkBinaryEntryCodecDecode(b, entry)
	})
	b.Run("ManyValues", func(b *testing.B) {
		entry := benchmarkBinaryEntryCodecEntry()
		entry.Attributes[5].Values = make([][]byte, 64)
		for i := range entry.Attributes[5].Values {
			entry.Attributes[5].Values[i] = []byte("benchmark")
		}
		benchmarkBinaryEntryCodecDecode(b, entry)
	})
}

func benchmarkBinaryEntryCodecEntry() directory.Entry {
	return directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("top"), []byte("person"), []byte("inetOrgPerson")}},
			{Description: "uid", Values: [][]byte{[]byte("alice")}},
			{Description: "cn", Values: [][]byte{[]byte("Alice Example")}},
			{Description: "sn", Values: [][]byte{[]byte("Example")}},
			{Description: "mail", Values: [][]byte{[]byte("alice@example.com")}},
			{Description: "description", Values: [][]byte{bytes.Repeat([]byte("value"), 32)}},
		},
	}
}

func benchmarkBinaryEntryCodecDecode(b *testing.B, entry directory.Entry) {
	b.Helper()
	encoded, err := encodeEntry(entry, "dn:v2:benchmark", entry.DN)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(encoded)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := decodeStoredEntry(encoded); err != nil {
			b.Fatal(err)
		}
	}
}
