package ldapwire

import (
	"errors"
	"math"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestCancelRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	encoded := EncodeCancelRequestValue(42)
	messageID, err := DecodeCancelRequestValue(encoded)
	if err != nil {
		t.Fatalf("DecodeCancelRequestValue(): %v", err)
	}
	if messageID != 42 {
		t.Fatalf("cancelID = %d, want 42", messageID)
	}
}

func TestDecodeCancelRequestValueRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	empty := ber.NewSequence("cancelRequestValue")
	extra := ber.NewSequence("cancelRequestValue")
	extra.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"cancelID",
	))
	extra.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(2),
		"extra",
	))

	tests := map[string][]byte{
		"empty input":        nil,
		"empty sequence":     empty.Bytes(),
		"extra element":      extra.Bytes(),
		"zero ID":            EncodeCancelRequestValue(0),
		"negative ID":        EncodeCancelRequestValue(-1),
		"out of range ID":    EncodeCancelRequestValue(math.MaxInt32 + 1),
		"trailing encoding":  append(EncodeCancelRequestValue(1), 0x00),
		"indefinite length":  {0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
		"non-minimal length": {0x30, 0x81, 0x03, 0x02, 0x01, 0x01},
	}
	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeCancelRequestValue(value)
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("error = %v, want ErrMalformedMessage", err)
			}
		})
	}
}
