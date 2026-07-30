package ldapwire

import (
	"bytes"
	"errors"
	"math"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestPagedResultsValueRoundTrip(t *testing.T) {
	t.Parallel()

	cookie := []byte{0x00, 0xff, 0x10}
	size, decodedCookie, err := DecodePagedResultsValue(
		EncodePagedResultsValue(25, cookie),
	)
	if err != nil {
		t.Fatalf("DecodePagedResultsValue(): %v", err)
	}
	if size != 25 || !bytes.Equal(decodedCookie, cookie) {
		t.Fatalf("decoded value = %d, %x", size, decodedCookie)
	}
}

func TestDecodePagedResultsValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	valid := EncodePagedResultsValue(10, nil)
	negative := ber.NewSequence("negative")
	negative.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(-1),
		"size",
	))
	negative.AppendChild(octetString(nil))
	tooLarge := ber.NewSequence("too large")
	tooLarge.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(math.MaxInt32)+1,
		"size",
	))
	tooLarge.AppendChild(octetString(nil))
	for _, value := range [][]byte{
		nil,
		octetString(nil).Bytes(),
		ber.NewSequence("missing elements").Bytes(),
		append(bytes.Clone(valid), 0x00),
		negative.Bytes(),
		tooLarge.Bytes(),
	} {
		if _, _, err := DecodePagedResultsValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf("DecodePagedResultsValue(%x) error = %v", value, err)
		}
	}
}
