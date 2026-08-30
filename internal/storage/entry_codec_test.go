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
