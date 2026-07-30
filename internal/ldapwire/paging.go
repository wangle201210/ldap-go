package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func DecodePagedResultsValue(value []byte) (int, []byte, error) {
	if len(value) == 0 {
		return 0, nil, malformed("paged results value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return 0, nil, malformed("decode paged results value: %v", err)
	}
	if reader.Len() != 0 {
		return 0, nil, malformed("paged results value has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 2 {
		return 0, nil, malformed("paged results value is not a two-element sequence")
	}
	sizePacket := packet.Children[0]
	if !isPacket(sizePacket, ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger) ||
		sizePacket.Data.Len() == 0 {
		return 0, nil, malformed("paged results size is not an integer")
	}
	size, err := ber.ParseInt64(sizePacket.Data.Bytes())
	if err != nil || size < 0 || size > math.MaxInt32 {
		return 0, nil, malformed("paged results size is invalid")
	}
	cookie, err := packetBytes(packet.Children[1])
	if err != nil {
		return 0, nil, malformed("paged results cookie is not an octet string")
	}
	return int(size), cookie, nil
}

func EncodePagedResultsValue(size int, cookie []byte) []byte {
	value := ber.NewSequence("pagedResultsControlValue")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(size),
		"size",
	))
	value.AppendChild(octetString(cookie))
	return value.Bytes()
}
