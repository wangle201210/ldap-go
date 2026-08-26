package ldapwire

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const SessionTrackingControlOID = "1.3.6.1.4.1.21008.108.63.1"

type SessionTrackingValue struct {
	SessionSourceIP           []byte
	SessionSourceName         []byte
	FormatOID                 []byte
	SessionTrackingIdentifier []byte
}

// EncodeSessionTrackingValue encodes the session tracking fields as canonical
// OCTET STRING elements in a BER sequence.
func EncodeSessionTrackingValue(value SessionTrackingValue) []byte {
	sequence := ber.NewSequence("SessionIdentifierControlValue")
	for _, field := range [][]byte{
		value.SessionSourceIP,
		value.SessionSourceName,
		value.FormatOID,
		value.SessionTrackingIdentifier,
	} {
		sequence.AppendChild(ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			string(field),
			"",
		))
	}
	return bytes.Clone(sequence.Bytes())
}

// DecodeSessionTrackingValue matches OpenLDAP's session tracking BER parser.
// The outer tag must be a SEQUENCE, but its declared boundary is not used while
// reading the four inner elements. Inner tags are intentionally unrestricted.
// FormatOIDValid reports numeric OID validity separately because OpenLDAP 2.6.13
// treats an invalid format OID as a successful, ignored control.
func DecodeSessionTrackingValue(
	encoded []byte,
) (value SessionTrackingValue, formatOIDValid bool, err error) {
	if len(encoded) == 0 || encoded[0] != 0x30 {
		return SessionTrackingValue{}, false, malformed(
			"session tracking value is not a sequence",
		)
	}

	cursor, _, err := searchOptionsTLV(encoded, 0)
	if err != nil {
		return SessionTrackingValue{}, false, malformed(
			"decode session tracking sequence: %v",
			err,
		)
	}

	fields := [4][]byte{}
	for index := range fields {
		contentOffset, contentLength, decodeErr := searchOptionsTLV(encoded, cursor)
		if decodeErr != nil {
			return SessionTrackingValue{}, false, malformed(
				"decode session tracking field %d: %v",
				index+1,
				decodeErr,
			)
		}
		switch index {
		case 0:
			if contentLength > 128 {
				return SessionTrackingValue{}, false, malformed(
					"session tracking source IP exceeds 128 bytes",
				)
			}
		case 1:
			if contentLength > 65536 {
				return SessionTrackingValue{}, false, malformed(
					"session tracking source name exceeds 65536 bytes",
				)
			}
		case 2:
			if contentLength == 0 {
				return SessionTrackingValue{}, false, malformed(
					"session tracking format OID is empty",
				)
			}
			if contentLength > 1024 {
				return SessionTrackingValue{}, false, malformed(
					"session tracking format OID exceeds 1024 bytes",
				)
			}
		}

		end := contentOffset + contentLength
		fields[index] = bytes.Clone(encoded[contentOffset:end])
		cursor = end
	}

	// OpenLDAP's final ber_skip_tag() treats one incomplete trailing tag byte
	// as end-of-input, but rejects any complete or longer fifth element.
	if trailing := len(encoded) - cursor; trailing != 0 && trailing != 1 {
		return SessionTrackingValue{}, false, malformed(
			"session tracking value has trailing data",
		)
	}

	value = SessionTrackingValue{
		SessionSourceIP:           fields[0],
		SessionSourceName:         fields[1],
		FormatOID:                 fields[2],
		SessionTrackingIdentifier: fields[3],
	}
	return value, validSessionTrackingNumericOID(value.FormatOID), nil
}

// validSessionTrackingNumericOID follows OpenLDAP's numericoidValidate,
// including its acceptance of a single numeric arc.
func validSessionTrackingNumericOID(value []byte) bool {
	if len(value) == 0 {
		return false
	}

	for offset := 0; ; {
		if offset >= len(value) || value[offset] < '0' || value[offset] > '9' {
			return false
		}
		if value[offset] == '0' && offset+1 < len(value) && value[offset+1] != '.' {
			return false
		}

		for offset < len(value) && value[offset] >= '0' && value[offset] <= '9' {
			offset++
		}
		if offset == len(value) {
			return true
		}
		if value[offset] != '.' {
			return false
		}
		offset++
	}
}
