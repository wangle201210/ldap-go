package ldapwire

import ber "github.com/go-asn1-ber/asn1-ber"

func EncodeCancelRequestValue(messageID int64) []byte {
	value := ber.NewSequence("cancelRequestValue")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"cancelID",
	))
	return value.Bytes()
}

func DecodeCancelRequestValue(value []byte) (int64, error) {
	// OpenLDAP's ber_scanf("{i}") consumes only the first integer. It accepts
	// definite BER lengths and ignores tags and data after that integer.
	start, _, err := cancelBERContent(value)
	if err != nil {
		return 0, malformed("decode cancelRequestValue: %v", err)
	}
	value = value[start:]
	start, end, err := cancelBERContent(value)
	if err != nil {
		return 0, malformed("decode cancelID: %v", err)
	}
	integer := value[start:end]
	if len(integer) > 4 {
		return 0, malformed("cancelID exceeds a signed 32-bit integer")
	}
	var messageID int64
	if len(integer) > 0 && integer[0]&0x80 != 0 {
		messageID = -1
	}
	for _, octet := range integer {
		messageID = messageID<<8 | int64(octet)
	}
	return messageID, nil
}

func cancelBERContent(value []byte) (int, int, error) {
	if len(value) < 2 {
		return 0, 0, malformed("truncated BER header")
	}
	position := 1
	tag := uint64(value[0])
	if value[0]&0x1f == 0x1f {
		for {
			if position >= len(value) || position >= 8 {
				return 0, 0, malformed("invalid BER tag")
			}
			octet := value[position]
			tag = tag<<8 | uint64(octet)
			position++
			if octet&0x80 == 0 {
				break
			}
		}
	}
	if tag == ^uint64(0) || position >= len(value) {
		return 0, 0, malformed("invalid BER header")
	}
	length := uint64(value[position])
	position++
	if length&0x80 != 0 {
		octets := int(length & 0x7f)
		if octets == 0 || octets > 8 || octets > len(value)-position {
			return 0, 0, malformed("invalid BER length")
		}
		length = 0
		for _, octet := range value[position : position+octets] {
			length = length<<8 | uint64(octet)
		}
		position += octets
	}
	if length > uint64(len(value)-position) {
		return 0, 0, malformed("truncated BER content")
	}
	return position, position + int(length), nil
}
