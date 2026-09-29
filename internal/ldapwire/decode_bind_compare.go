package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// decodeBindCompareFrame recognizes Simple Bind and Compare requests without
// controls and with minimal definite lengths. Other encodings use the BER decoder.
func decodeBindCompareFrame(frame []byte) (Message, bool) {
	content, rest, ok := definiteRequestElement(frame, 0x30)
	if !ok || len(rest) != 0 ||
		(ber.MaxPacketLengthBytes > 0 && int64(len(content)) > ber.MaxPacketLengthBytes) {
		return Message{}, false
	}
	idBytes, rest, ok := definiteRequestElement(content, 0x02)
	if !ok || len(idBytes) == 0 {
		return Message{}, false
	}
	id, err := ber.ParseInt64(idBytes)
	if err != nil || id <= 0 || id > math.MaxInt32 || len(rest) == 0 {
		return Message{}, false
	}
	tag := rest[0]
	depth := 2 // Bind's primitive fields are at depth 2; Compare's AVA adds a level.
	switch tag {
	case 0x60:
	case 0x6e:
		depth = 3
	default:
		return Message{}, false
	}
	if ber.MaxNestingDepth > 0 && ber.MaxNestingDepth <= depth {
		return Message{}, false
	}
	operation, rest, ok := definiteRequestElement(rest, tag)
	if !ok || len(rest) != 0 {
		return Message{}, false
	}

	if tag == 0x60 {
		versionBytes, rest, ok := definiteRequestElement(operation, 0x02)
		if !ok || len(versionBytes) == 0 {
			return Message{}, false
		}
		version, err := ber.ParseInt64(versionBytes)
		if err != nil || version < 0 || version > math.MaxInt32 {
			return Message{}, false
		}
		name, rest, ok := definiteRequestElement(rest, 0x04)
		if !ok {
			return Message{}, false
		}
		password, rest, ok := definiteRequestElement(rest, 0x80)
		if !ok || len(rest) != 0 {
			return Message{}, false
		}

		// Allocate owned fields only after validating the complete shape. Empty
		// byte values stay nil, matching the packet decoder's bytes.Buffer data.
		var simple []byte
		if len(password) > 0 {
			simple = bytes.Clone(password)
		}
		return Message{ID: id, Request: BindRequest{
			Version: int(version), Name: string(name), Authentication: Authentication{Simple: simple},
		}}, true
	}

	dn, rest, ok := definiteRequestElement(operation, 0x04)
	if !ok {
		return Message{}, false
	}
	assertion, rest, ok := definiteRequestElement(rest, 0x30)
	if !ok || len(rest) != 0 {
		return Message{}, false
	}
	attribute, rest, ok := definiteRequestElement(assertion, 0x04)
	if !ok || len(attribute) == 0 {
		return Message{}, false
	}
	value, rest, ok := definiteRequestElement(rest, 0x04)
	if !ok || len(rest) != 0 {
		return Message{}, false
	}

	var ownedValue []byte
	if len(value) > 0 {
		ownedValue = bytes.Clone(value)
	}
	return Message{ID: id, Request: CompareRequest{
		DN: string(dn), Attribute: string(attribute), Assertion: ownedValue,
	}}, true
}

// The fixed request shape bounds traversal; each child is bounded by its parent.
// Unsupported lengths fall back without constructing errors or partial requests.
func definiteRequestElement(data []byte, tag byte) (value, rest []byte, ok bool) {
	if len(data) < 2 || data[0] != tag {
		return nil, nil, false
	}
	headerLength := 2
	length := uint64(data[1])
	if data[1]&0x80 != 0 {
		lengthBytes := int(data[1] & 0x7f)
		if lengthBytes == 0 || lengthBytes > 8 || lengthBytes > len(data)-2 || data[2] == 0 {
			return nil, nil, false
		}
		headerLength += lengthBytes
		length = 0
		for _, octet := range data[2:headerLength] {
			length = length<<8 | uint64(octet)
		}
		if length < 128 {
			return nil, nil, false
		}
	}
	if length > uint64(len(data)-headerLength) {
		return nil, nil, false
	}
	end := headerLength + int(length)
	return data[headerLength:end], data[end:], true
}
