package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type SortKey struct {
	AttributeType string
	OrderingRule  string
	Reverse       bool
}

func DecodeSortRequestValue(value []byte) ([]SortKey, error) {
	if len(value) == 0 {
		return nil, malformed("sort request value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return nil, malformed("decode sort request value: %v", err)
	}
	if reader.Len() != 0 {
		return nil, malformed("sort request value has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) == 0 {
		return nil, malformed("sort request value is not a non-empty sequence")
	}

	keys := make([]SortKey, len(packet.Children))
	for index, child := range packet.Children {
		key, err := decodeSortKey(child)
		if err != nil {
			return nil, malformed("decode sort key %d: %v", index, err)
		}
		keys[index] = key
	}
	return keys, nil
}

func decodeSortKey(packet *ber.Packet) (SortKey, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 1 ||
		len(packet.Children) > 3 {
		return SortKey{}, malformed("sort key is not a one-to-three-element sequence")
	}
	attribute, err := packetString(packet.Children[0])
	if err != nil || attribute == "" {
		return SortKey{}, malformed("sort key attribute type is invalid")
	}

	key := SortKey{AttributeType: attribute}
	next := 1
	if next < len(packet.Children) &&
		isPacket(packet.Children[next], ber.ClassContext, ber.TypePrimitive, 0) {
		if packet.Children[next].Data.Len() == 0 {
			return SortKey{}, malformed("sort key ordering rule is empty")
		}
		key.OrderingRule = string(packet.Children[next].Data.Bytes())
		next++
	}
	if next < len(packet.Children) &&
		isPacket(packet.Children[next], ber.ClassContext, ber.TypePrimitive, 1) {
		if packet.Children[next].Data.Len() != 1 {
			return SortKey{}, malformed("sort key reverse order is not a boolean")
		}
		key.Reverse = packet.Children[next].Data.Bytes()[0] != 0
		next++
	}
	if next != len(packet.Children) {
		return SortKey{}, malformed("sort key contains an unknown or out-of-order field")
	}
	return key, nil
}

func EncodeSortRequestValue(keys []SortKey) []byte {
	value := ber.NewSequence("sortKeyList")
	for _, key := range keys {
		encodedKey := ber.NewSequence("sortKey")
		encodedKey.AppendChild(octetString([]byte(key.AttributeType)))
		if key.OrderingRule != "" {
			encodedKey.AppendChild(ber.NewString(
				ber.ClassContext,
				ber.TypePrimitive,
				0,
				key.OrderingRule,
				"orderingRule",
			))
		}
		if key.Reverse {
			encodedKey.AppendChild(ber.NewBoolean(
				ber.ClassContext,
				ber.TypePrimitive,
				1,
				true,
				"reverseOrder",
			))
		}
		value.AppendChild(encodedKey)
	}
	return value.Bytes()
}

func EncodeSortResultValue(result ResultCode, attributeType string) []byte {
	value := ber.NewSequence("sortResult")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(result),
		"sortResult",
	))
	if attributeType != "" {
		value.AppendChild(ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			0,
			attributeType,
			"attributeType",
		))
	}
	return value.Bytes()
}

func DecodeSortResultValue(value []byte) (ResultCode, string, error) {
	if len(value) == 0 {
		return 0, "", malformed("sort result value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return 0, "", malformed("decode sort result value: %v", err)
	}
	if reader.Len() != 0 {
		return 0, "", malformed("sort result value has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 1 ||
		len(packet.Children) > 2 {
		return 0, "", malformed("sort result value is not a one-or-two-element sequence")
	}
	resultPacket := packet.Children[0]
	if !isPacket(
		resultPacket,
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
	) || resultPacket.Data.Len() == 0 {
		return 0, "", malformed("sort result code is not an enumerated value")
	}
	rawResult, err := ber.ParseInt64(resultPacket.Data.Bytes())
	if err != nil || rawResult < 0 || rawResult > math.MaxInt32 {
		return 0, "", malformed("sort result code is invalid")
	}

	attributeType := ""
	if len(packet.Children) == 2 {
		attributePacket := packet.Children[1]
		if !isPacket(
			attributePacket,
			ber.ClassContext,
			ber.TypePrimitive,
			0,
		) || attributePacket.Data.Len() == 0 {
			return 0, "", malformed("sort result attribute type is invalid")
		}
		attributeType = string(attributePacket.Data.Bytes())
	}
	return ResultCode(rawResult), attributeType, nil
}
