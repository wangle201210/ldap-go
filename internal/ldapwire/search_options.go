package ldapwire

import (
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	DomainScopeControlOID   = "1.2.840.113556.1.4.1339"
	SearchOptionsControlOID = "1.2.840.113556.1.4.1340"
)

// DecodeSearchOptionsValue decodes the Microsoft Search Options control value.
// Its permissive tag and boundary handling matches OpenLDAP's ber_scanf("{i}").
func DecodeSearchOptionsValue(value []byte) (int32, error) {
	outerContent, _, err := searchOptionsTLV(value, 0)
	if err != nil {
		return 0, malformed("decode search options container: %v", err)
	}

	integerContent, integerLength, err := searchOptionsTLV(value, outerContent)
	if err != nil {
		return 0, malformed("decode search options flags: %v", err)
	}
	if integerLength > 4 {
		return 0, malformed("search options flags use %d octets", integerLength)
	}
	if integerLength == 0 {
		return 0, nil
	}

	var raw uint32
	for _, octet := range value[integerContent : integerContent+integerLength] {
		raw = raw<<8 | uint32(octet)
	}
	if value[integerContent]&0x80 != 0 && integerLength < 4 {
		raw |= math.MaxUint32 << (integerLength * 8)
	}
	return int32(raw), nil
}

// EncodeSearchOptionsValue encodes flags as a canonical BER sequence containing
// one signed INTEGER.
func EncodeSearchOptionsValue(flags int32) []byte {
	value := ber.NewSequence("SearchOptionsValue")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(flags),
		"flags",
	))
	return value.Bytes()
}

// searchOptionsTLV returns the content offset and length of one definite-length
// BER element. OpenLDAP validates the outer element length but does not use its
// boundary while scanning the child, so callers intentionally retain the full
// input as the child's decoding limit.
func searchOptionsTLV(value []byte, offset int) (int, int, error) {
	if offset < 0 || offset >= len(value) {
		return 0, 0, malformed("BER tag is truncated")
	}

	tagOctets := 1
	if value[offset]&0x1f == 0x1f {
		for {
			if tagOctets >= 8 || offset+tagOctets >= len(value) {
				return 0, 0, malformed("BER tag is truncated or too long")
			}
			octet := value[offset+tagOctets]
			tagOctets++
			if octet&0x80 == 0 {
				break
			}
		}
	}

	lengthOffset := offset + tagOctets
	if lengthOffset >= len(value) {
		return 0, 0, malformed("BER length is truncated")
	}
	firstLength := value[lengthOffset]
	contentOffset := lengthOffset + 1
	var contentLength uint64
	if firstLength&0x80 == 0 {
		contentLength = uint64(firstLength)
	} else {
		lengthOctets := int(firstLength & 0x7f)
		if lengthOctets == 0 {
			return 0, 0, malformed("indefinite BER length is not supported")
		}
		if lengthOctets > 8 || lengthOctets > len(value)-contentOffset {
			return 0, 0, malformed("BER length is truncated or too long")
		}
		for _, octet := range value[contentOffset : contentOffset+lengthOctets] {
			if contentLength > (math.MaxUint64-uint64(octet))/256 {
				return 0, 0, malformed("BER length overflows")
			}
			contentLength = contentLength*256 + uint64(octet)
		}
		contentOffset += lengthOctets
	}

	if contentLength > uint64(len(value)-contentOffset) {
		return 0, 0, malformed("BER content is truncated")
	}
	return contentOffset, int(contentLength), nil
}
