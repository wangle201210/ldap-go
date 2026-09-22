package ldapwire

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestSearchResultEntryWithControlsMatchesBERModel(t *testing.T) {
	t.Parallel()

	entries := []directory.Entry{
		{},
		{DN: "dc=example,dc=com", Attributes: []directory.Attribute{}},
		{
			DN: "uid=alice,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "uid", Values: [][]byte{[]byte("alice")}},
				{Description: "description"},
				{Description: "jpegPhoto;binary", Values: [][]byte{
					nil, {}, {0, 0xff, 0x80},
					bytes.Repeat([]byte{0xa5}, 127),
					bytes.Repeat([]byte{0x5a}, 128),
				}},
			},
		},
	}
	controls := []struct {
		name  string
		value []Control
	}{
		{name: "nil"},
		{name: "empty", value: []Control{}},
		{name: "absent-value", value: []Control{{OID: "1.2.3"}}},
		{name: "critical", value: []Control{{OID: "1.2.3", Critical: true}}},
		{name: "explicit-empty", value: []Control{{OID: "1.2.3", HasValue: true}}},
		{name: "implicit-empty", value: []Control{{OID: "1.2.3", Value: []byte{}}}},
		{name: "implicit-value", value: []Control{{OID: "1.2.3", Value: []byte{0, 0xff, 0x80}}}},
		{name: "multiple", value: []Control{
			{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte{0, 0xff}},
			// Control values are opaque, including noncanonical BER and negative integers.
			{OID: "1.2.3", Value: []byte{0x30, 0x81, 3, 0x02, 1, 0xff}},
			{OID: "", Critical: true, HasValue: true},
			{OID: "1.02.3\x00\xff"},
		}},
	}
	for entryIndex, entry := range entries {
		for _, control := range controls {
			for _, messageID := range []int64{
				math.MinInt64, -129, -128, -1, 0, 1, 127, 128, 255, 256,
				32767, 32768, math.MaxInt32, math.MaxInt64,
			} {
				t.Run(fmt.Sprintf("entry%d/%s/id%d", entryIndex, control.name, messageID), func(t *testing.T) {
					assertSearchEntryEncodingMatchesBERModel(t, messageID, entry, control.value)
				})
			}
		}
	}
}

func TestSearchResultEntryControlLengthBoundaries(t *testing.T) {
	t.Parallel()

	for _, length := range []int{0, 1, 117, 118, 119, 120, 125, 126, 127, 128, 255, 256, 65535, 65536} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			value := bytes.Repeat([]byte{0xff}, length)
			entry := directory.Entry{
				DN: strings.Repeat("d", length),
				Attributes: []directory.Attribute{{
					Description: strings.Repeat("a", length),
					Values:      [][]byte{value},
				}},
			}
			assertSearchEntryEncodingMatchesBERModel(t, 128, entry, []Control{
				{OID: "1.2.3", Critical: true, HasValue: true, Value: value},
				{OID: strings.Repeat("1", length), Value: value},
			})
		})
	}
}

func assertSearchEntryEncodingMatchesBERModel(t *testing.T, messageID int64, entry directory.Entry, controls []Control) {
	t.Helper()
	want := encodeMessage(messageID, encodeSearchResultEntry(entry), controls)
	got := EncodeSearchResultEntry(messageID, entry, controls)
	if !bytes.Equal(got, want) {
		t.Fatalf("SearchResultEntry differs from BER model: got %d bytes, want %d", len(got), len(want))
	}
	// Negative IDs retain the existing fallback and conservative size estimate.
	if messageID >= 0 {
		if size := SearchResultEntryEncodedSize(messageID, entry, controls); size != int64(len(got)) {
			t.Fatalf("encoded size = %d, want %d", size, len(got))
		}
	}
	clear(got)
	if again := EncodeSearchResultEntry(messageID, entry, controls); !bytes.Equal(again, want) {
		t.Fatal("encoded result aliases the entry or controls")
	}
}

func BenchmarkEncodeSearchResultEntry(b *testing.B) {
	entry := directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("top"), []byte("person"), []byte("inetOrgPerson")}},
			{Description: "uid", Values: [][]byte{[]byte("alice")}},
			{Description: "cn", Values: [][]byte{[]byte("Alice Example")}},
			{Description: "sn", Values: [][]byte{[]byte("Example")}},
			{Description: "mail", Values: [][]byte{[]byte("alice@example.com")}},
			{Description: "jpegPhoto", Values: [][]byte{bytes.Repeat([]byte{0, 0xff, 0x80, 0x42}, 256)}},
		},
	}
	syncControl := Control{
		OID: "1.3.6.1.4.1.4203.1.9.1.2", HasValue: true,
		Value: EncodeSyncStateValue(SyncStateValue{
			State: SyncStateAdd, EntryUUID: SyncUUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff},
			HasCookie: true, Cookie: []byte("sync-cookie"),
		}),
	}
	for _, test := range []struct {
		name     string
		controls []Control
	}{
		{name: "NoControls"},
		{name: "SyncControl", controls: []Control{syncControl}},
		{name: "MultipleControls", controls: []Control{syncControl, {
			OID: "1.2.3.4", Critical: true, HasValue: true, Value: bytes.Repeat([]byte{0, 0xff}, 128),
		}}},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.Run("Direct", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(SearchResultEntryEncodedSize(128, entry, test.controls))
				for b.Loop() {
					_ = EncodeSearchResultEntry(128, entry, test.controls)
				}
			})
			if len(test.controls) > 0 {
				b.Run("BERModel", func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(SearchResultEntryEncodedSize(128, entry, test.controls))
					for b.Loop() {
						_ = encodeMessage(128, encodeSearchResultEntry(entry), test.controls)
					}
				})
			}
		})
	}
}
