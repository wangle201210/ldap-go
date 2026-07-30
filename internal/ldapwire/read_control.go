package ldapwire

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func DecodeAttributeSelection(value []byte) ([]string, error) {
	if len(value) == 0 {
		return nil, malformed("attribute selection value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return nil, malformed("decode attribute selection: %v", err)
	}
	if reader.Len() != 0 {
		return nil, malformed("attribute selection has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return nil, malformed("attribute selection is not a sequence")
	}

	attributes := make([]string, 0, len(packet.Children))
	for _, child := range packet.Children {
		attribute, err := packetString(child)
		if err != nil || attribute == "" {
			return nil, malformed("invalid attribute selection element")
		}
		attributes = append(attributes, attribute)
	}
	return attributes, nil
}
