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

func BenchmarkBinaryEntryCodecDecode(b *testing.B) {
	entry := directory.Entry{
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
