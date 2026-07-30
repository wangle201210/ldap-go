package ldapwire

import (
	"bytes"
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestVirtualListViewRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []VirtualListViewRequest{
		{
			BeforeCount:  3,
			AfterCount:   4,
			ByOffset:     true,
			Offset:       25,
			ContentCount: 100,
			ContextID:    []byte{0x00, 0xff, 0x10},
			HasContextID: true,
		},
		{
			BeforeCount:    1,
			AfterCount:     2,
			AssertionValue: []byte("B"),
		},
	}
	for _, want := range tests {
		got, err := DecodeVirtualListViewRequestValue(
			EncodeVirtualListViewRequestValue(want),
		)
		if err != nil {
			t.Fatalf("DecodeVirtualListViewRequestValue(): %v", err)
		}
		if got.BeforeCount != want.BeforeCount ||
			got.AfterCount != want.AfterCount ||
			got.ByOffset != want.ByOffset ||
			got.Offset != want.Offset ||
			got.ContentCount != want.ContentCount ||
			got.HasContextID != want.HasContextID ||
			!bytes.Equal(got.AssertionValue, want.AssertionValue) ||
			!bytes.Equal(got.ContextID, want.ContextID) {
			t.Fatalf("decoded VLV request = %#v, want %#v", got, want)
		}
	}
}

func TestDecodeVirtualListViewRequestValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	valid := EncodeVirtualListViewRequestValue(VirtualListViewRequest{
		ByOffset:     true,
		Offset:       1,
		ContentCount: 0,
	})
	missingTarget := ber.NewSequence("missing target")
	missingTarget.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"beforeCount",
	))
	missingTarget.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"afterCount",
	))
	badOffset := ber.NewSequence("bad offset")
	badOffset.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"beforeCount",
	))
	badOffset.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"afterCount",
	))
	badOffset.AppendChild(ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		0,
		nil,
		"byOffset",
	))

	for _, value := range [][]byte{
		nil,
		octetString(nil).Bytes(),
		missingTarget.Bytes(),
		badOffset.Bytes(),
		append(bytes.Clone(valid), 0x00),
	} {
		if _, err := DecodeVirtualListViewRequestValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf(
				"DecodeVirtualListViewRequestValue(%x) error = %v",
				value,
				err,
			)
		}
	}
}

func TestVirtualListViewResponseValueRoundTrip(t *testing.T) {
	t.Parallel()

	want := VirtualListViewResponse{
		TargetPosition: 12,
		ContentCount:   45,
		Result:         ResultSuccess,
		ContextID:      []byte{0x01, 0x00, 0xff},
		HasContextID:   true,
	}
	got, err := DecodeVirtualListViewResponseValue(
		EncodeVirtualListViewResponseValue(want),
	)
	if err != nil {
		t.Fatalf("DecodeVirtualListViewResponseValue(): %v", err)
	}
	if got.TargetPosition != want.TargetPosition ||
		got.ContentCount != want.ContentCount ||
		got.Result != want.Result ||
		got.HasContextID != want.HasContextID ||
		!bytes.Equal(got.ContextID, want.ContextID) {
		t.Fatalf("decoded VLV response = %#v, want %#v", got, want)
	}
}

func TestDecodeVirtualListViewResponseValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	valid := EncodeVirtualListViewResponseValue(VirtualListViewResponse{})
	negative := ber.NewSequence("negative")
	negative.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(-1),
		"targetPosition",
	))
	negative.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"contentCount",
	))
	negative.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(0),
		"result",
	))

	for _, value := range [][]byte{
		nil,
		ber.NewSequence("missing").Bytes(),
		negative.Bytes(),
		append(bytes.Clone(valid), 0x00),
	} {
		if _, err := DecodeVirtualListViewResponseValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf(
				"DecodeVirtualListViewResponseValue(%x) error = %v",
				value,
				err,
			)
		}
	}
}
