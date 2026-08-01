package ldapwire

import (
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestValueSortControlValueRoundTrip(t *testing.T) {
	t.Parallel()

	for _, want := range []bool{false, true} {
		got, err := DecodeValueSortControlValue(EncodeValueSortControlValue(want))
		if err != nil || got != want {
			t.Fatalf("value sort control round trip = %t, %v, want %t", got, err, want)
		}
	}
}

func TestDecodeValueSortControlValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	emptySequence := ber.NewSequence("empty")
	integerSequence := ber.NewSequence("integer")
	integerSequence.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"integer",
	))
	twoValues := ber.NewSequence("two")
	twoValues.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		false,
		"first",
	))
	twoValues.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"second",
	))
	booleanOnly := ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"boolean",
	)
	validWithTrailing := append(EncodeValueSortControlValue(false), 0)
	for _, value := range [][]byte{
		nil,
		{0x30},
		emptySequence.Bytes(),
		integerSequence.Bytes(),
		twoValues.Bytes(),
		booleanOnly.Bytes(),
		validWithTrailing,
	} {
		if _, err := DecodeValueSortControlValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf("DecodeValueSortControlValue(%x) error = %v", value, err)
		}
	}
}
