package ldapwire

import (
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestSortRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	want := []SortKey{
		{
			AttributeType: "sn",
			OrderingRule:  "caseIgnoreOrderingMatch",
		},
		{
			AttributeType: "uidNumber",
			Reverse:       true,
		},
	}
	got, err := DecodeSortRequestValue(EncodeSortRequestValue(want))
	if err != nil {
		t.Fatalf("DecodeSortRequestValue(): %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("sort keys = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("sort key %d = %#v, want %#v", index, got[index], want[index])
		}
	}
}

func TestDecodeSortRequestValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	valid := EncodeSortRequestValue([]SortKey{{AttributeType: "cn"}})
	missingAttribute := ber.NewSequence("sortKeyList")
	missingAttribute.AppendChild(ber.NewSequence("sortKey"))
	wrongAttribute := ber.NewSequence("sortKeyList")
	wrongAttributeKey := ber.NewSequence("sortKey")
	wrongAttributeKey.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"attributeType",
	))
	wrongAttribute.AppendChild(wrongAttributeKey)
	outOfOrder := ber.NewSequence("sortKeyList")
	outOfOrderKey := ber.NewSequence("sortKey")
	outOfOrderKey.AppendChild(octetString([]byte("cn")))
	outOfOrderKey.AppendChild(ber.NewBoolean(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		true,
		"reverseOrder",
	))
	outOfOrderKey.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"caseIgnoreOrderingMatch",
		"orderingRule",
	))
	outOfOrder.AppendChild(outOfOrderKey)
	invalidBoolean := ber.NewSequence("sortKeyList")
	invalidBooleanKey := ber.NewSequence("sortKey")
	invalidBooleanKey.AppendChild(octetString([]byte("cn")))
	invalidBooleanKey.AppendChild(ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		nil,
		"reverseOrder",
	))
	invalidBoolean.AppendChild(invalidBooleanKey)

	for _, value := range [][]byte{
		nil,
		octetString(nil).Bytes(),
		ber.NewSequence("empty").Bytes(),
		append(valid, 0x00),
		missingAttribute.Bytes(),
		wrongAttribute.Bytes(),
		outOfOrder.Bytes(),
		invalidBoolean.Bytes(),
	} {
		if _, err := DecodeSortRequestValue(value); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf("DecodeSortRequestValue(%x) error = %v", value, err)
		}
	}
}

func TestEncodeSortResultValue(t *testing.T) {
	t.Parallel()

	encoded := EncodeSortResultValue(
		ResultInappropriateMatching,
		"cn",
	)
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 2 ||
		!isPacket(
			packet.Children[0],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
		) ||
		!isPacket(
			packet.Children[1],
			ber.ClassContext,
			ber.TypePrimitive,
			0,
		) {
		t.Fatalf("sort result packet = %#v", packet)
	}
	result, attributeType, err := DecodeSortResultValue(encoded)
	if err != nil {
		t.Fatalf("DecodeSortResultValue(): %v", err)
	}
	if result != ResultInappropriateMatching || attributeType != "cn" {
		t.Fatalf("sort result = %d, %q", result, attributeType)
	}
}
