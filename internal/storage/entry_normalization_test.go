package storage

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestEntryNormalizationCodec(t *testing.T) {
	entry := directory.Entry{DN: "cn=test"}
	entry.ReplaceValues("cn", [][]byte{[]byte("test")})
	entry.ReplaceRawNormalizedValues("createTimestamp", [][]byte{[]byte("20260101000000Z")})
	cloned := entry.Clone()
	encoded, err := encodeEntry(cloned, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, entryBinaryV3Prefix) {
		t.Fatal("normalization hint was not encoded")
	}
	decoded, err := decodeStoredEntry(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Entry, entry) {
		t.Fatalf("round trip=%+v", decoded.Entry)
	}
	decoded.Entry.ReplaceValues("createTimestamp", [][]byte{[]byte("20260101000000Z")})
	if decoded.Attributes[1].RawNormalized {
		t.Fatal("replacement retained generated provenance")
	}
	for _, offset := range []int{5, 6} {
		bad := bytes.Clone(encoded)
		bad[offset] = 255
		if _, err := decodeStoredEntry(bad); err == nil {
			t.Fatal("accepted malformed normalization bitmap")
		}
	}
}
