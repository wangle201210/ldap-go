package ldapwire

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func DecodeValueSortControlValue(value []byte) (bool, error) {
	if len(value) == 0 {
		return false, malformed("valSort control value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return false, malformed("decode valSort control value: %v", err)
	}
	if reader.Len() != 0 {
		return false, malformed("valSort control value has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 1 {
		return false, malformed("valSort control value is not a one-element sequence")
	}
	raw, err := packetBoolean(packet.Children[0])
	if err != nil {
		return false, malformed("valSort control flag is not a boolean")
	}
	return raw, nil
}

func EncodeValueSortControlValue(raw bool) []byte {
	value := ber.NewSequence("valSortControlValue")
	value.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		raw,
		"raw",
	))
	return value.Bytes()
}
