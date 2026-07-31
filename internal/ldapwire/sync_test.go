package ldapwire

import (
	"bytes"
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestSyncRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	for _, want := range []SyncRequestValue{
		{Mode: SyncRefreshOnly},
		{
			Mode:       SyncRefreshAndPersist,
			Cookie:     []byte{},
			HasCookie:  true,
			ReloadHint: true,
		},
		{
			Mode:      SyncRefreshOnly,
			Cookie:    []byte{0x00, 0xff, 0x10},
			HasCookie: true,
		},
	} {
		got, err := DecodeSyncRequestValue(EncodeSyncRequestValue(want))
		if err != nil {
			t.Fatalf("DecodeSyncRequestValue(): %v", err)
		}
		if got.Mode != want.Mode ||
			got.HasCookie != want.HasCookie ||
			got.ReloadHint != want.ReloadHint ||
			!bytes.Equal(got.Cookie, want.Cookie) {
			t.Fatalf("decoded sync request = %#v, want %#v", got, want)
		}
	}
}

func TestDecodeSyncRequestValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	invalidMode := ber.NewSequence("invalid mode")
	invalidMode.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(2),
		"mode",
	))
	wrongOrder := ber.NewSequence("wrong order")
	wrongOrder.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(SyncRefreshOnly),
		"mode",
	))
	wrongOrder.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"reloadHint",
	))
	wrongOrder.AppendChild(octetString([]byte("cookie")))

	assertMalformedSyncRequest(t, nil)
	assertMalformedSyncRequest(t, ber.NewSequence("missing mode").Bytes())
	assertMalformedSyncRequest(t, invalidMode.Bytes())
	assertMalformedSyncRequest(t, wrongOrder.Bytes())
	assertMalformedSyncRequest(
		t,
		append(
			bytes.Clone(EncodeSyncRequestValue(SyncRequestValue{
				Mode: SyncRefreshOnly,
			})),
			0x00,
		),
	)
}

func TestSyncStateValueRoundTrip(t *testing.T) {
	t.Parallel()

	var uuid SyncUUID
	for index := range uuid {
		uuid[index] = byte(index)
	}
	want := SyncStateValue{
		State:     SyncStateModify,
		EntryUUID: uuid,
		Cookie:    []byte{0x00, 0xff},
		HasCookie: true,
	}
	got, err := DecodeSyncStateValue(EncodeSyncStateValue(want))
	if err != nil {
		t.Fatalf("DecodeSyncStateValue(): %v", err)
	}
	if got.State != want.State ||
		got.EntryUUID != want.EntryUUID ||
		got.HasCookie != want.HasCookie ||
		!bytes.Equal(got.Cookie, want.Cookie) {
		t.Fatalf("decoded sync state = %#v, want %#v", got, want)
	}
}

func TestDecodeSyncStateValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	invalidState := ber.NewSequence("invalid state")
	invalidState.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(4),
		"state",
	))
	invalidState.AppendChild(octetString(make([]byte, 16)))
	shortUUID := ber.NewSequence("short UUID")
	shortUUID.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(SyncStateAdd),
		"state",
	))
	shortUUID.AppendChild(octetString(make([]byte, 15)))

	for _, value := range [][]byte{
		nil,
		ber.NewSequence("missing").Bytes(),
		invalidState.Bytes(),
		shortUUID.Bytes(),
	} {
		if _, err := DecodeSyncStateValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf("DecodeSyncStateValue(%x) error = %v", value, err)
		}
	}
}

func TestSyncDoneValueRoundTripAndDefaults(t *testing.T) {
	t.Parallel()

	for _, want := range []SyncDoneValue{
		{},
		{
			Cookie:         []byte{},
			HasCookie:      true,
			RefreshDeletes: true,
		},
	} {
		got, err := DecodeSyncDoneValue(EncodeSyncDoneValue(want))
		if err != nil {
			t.Fatalf("DecodeSyncDoneValue(): %v", err)
		}
		if got.HasCookie != want.HasCookie ||
			got.RefreshDeletes != want.RefreshDeletes ||
			!bytes.Equal(got.Cookie, want.Cookie) {
			t.Fatalf("decoded sync done = %#v, want %#v", got, want)
		}
	}
}

func TestDecodeSyncDoneValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	wrongOrder := ber.NewSequence("wrong order")
	wrongOrder.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"refreshDeletes",
	))
	wrongOrder.AppendChild(octetString([]byte("cookie")))
	for _, value := range [][]byte{
		nil,
		octetString(nil).Bytes(),
		wrongOrder.Bytes(),
	} {
		if _, err := DecodeSyncDoneValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf("DecodeSyncDoneValue(%x) error = %v", value, err)
		}
	}
}

func TestSyncInfoValueRoundTripAndDefaults(t *testing.T) {
	t.Parallel()

	var first SyncUUID
	var second SyncUUID
	for index := range first {
		first[index] = byte(index)
		second[index] = byte(0xff - index)
	}
	tests := []SyncInfoValue{
		{
			Kind:      SyncInfoNewCookie,
			Cookie:    []byte{0x00, 0xff},
			HasCookie: true,
		},
		{
			Kind:        SyncInfoRefreshDelete,
			RefreshDone: true,
		},
		{
			Kind:        SyncInfoRefreshPresent,
			Cookie:      []byte{},
			HasCookie:   true,
			RefreshDone: false,
		},
		{
			Kind:           SyncInfoIDSet,
			Cookie:         []byte("cookie"),
			HasCookie:      true,
			RefreshDeletes: true,
			UUIDs:          []SyncUUID{first, second},
		},
	}
	for _, want := range tests {
		got, err := DecodeSyncInfoValue(EncodeSyncInfoValue(want))
		if err != nil {
			t.Fatalf("DecodeSyncInfoValue(): %v", err)
		}
		if got.Kind != want.Kind ||
			got.HasCookie != want.HasCookie ||
			got.RefreshDone != want.RefreshDone ||
			got.RefreshDeletes != want.RefreshDeletes ||
			!bytes.Equal(got.Cookie, want.Cookie) ||
			!equalSyncUUIDs(got.UUIDs, want.UUIDs) {
			t.Fatalf("decoded sync info = %#v, want %#v", got, want)
		}
	}
}

func TestDecodeSyncInfoValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	invalidUUIDs := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		3,
		nil,
		"syncIdSet",
	)
	set := ber.Encode(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSet,
		nil,
		"syncUUIDs",
	)
	set.AppendChild(octetString(make([]byte, 15)))
	invalidUUIDs.AppendChild(set)
	wrongChoiceType := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		nil,
		"refreshDelete",
	)

	for _, value := range [][]byte{
		nil,
		ber.NewSequence("not a choice").Bytes(),
		invalidUUIDs.Bytes(),
		wrongChoiceType.Bytes(),
		append(
			bytes.Clone(EncodeSyncInfoValue(SyncInfoValue{
				Kind:      SyncInfoNewCookie,
				Cookie:    []byte("cookie"),
				HasCookie: true,
			})),
			0x00,
		),
	} {
		if _, err := DecodeSyncInfoValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf("DecodeSyncInfoValue(%x) error = %v", value, err)
		}
	}
}

func TestEncodeIntermediateResponse(t *testing.T) {
	t.Parallel()

	encoded := EncodeIntermediateResponse(
		17,
		"1.3.6.1.4.1.4203.1.9.1.4",
		[]byte{0x00, 0xff, 0x10},
		[]Control{{
			OID:      "1.2.3",
			Critical: true,
			Value:    []byte{},
			HasValue: true,
		}},
	)
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if len(packet.Children) != 3 {
		t.Fatalf("LDAPMessage child count = %d, want 3", len(packet.Children))
	}
	operation := packet.Children[1]
	if !isPacket(
		operation,
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationIntermediateResponse,
	) || len(operation.Children) != 2 {
		t.Fatalf("intermediate response packet = %#v", operation)
	}
	if !isPacket(
		operation.Children[0],
		ber.ClassContext,
		ber.TypePrimitive,
		0,
	) || string(operation.Children[0].Data.Bytes()) !=
		"1.3.6.1.4.1.4203.1.9.1.4" {
		t.Fatalf("responseName packet = %#v", operation.Children[0])
	}
	if !isPacket(
		operation.Children[1],
		ber.ClassContext,
		ber.TypePrimitive,
		1,
	) || !bytes.Equal(
		operation.Children[1].Data.Bytes(),
		[]byte{0x00, 0xff, 0x10},
	) {
		t.Fatalf("responseValue packet = %#v", operation.Children[1])
	}
}

func assertMalformedSyncRequest(t *testing.T, value []byte) {
	t.Helper()
	if _, err := DecodeSyncRequestValue(value); !errors.Is(
		err,
		ErrMalformedMessage,
	) {
		t.Fatalf("DecodeSyncRequestValue(%x) error = %v", value, err)
	}
}

func equalSyncUUIDs(left, right []SyncUUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
