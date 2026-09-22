package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

// decodeShortSearchFrame recognizes only short-form lengths, a leaf equality or
// presence filter, and no controls. Every mismatch falls back to the BER decoder,
// which remains responsible for errors and all other accepted BER encodings.
func decodeShortSearchFrame(frame []byte) (Message, bool) {
	content, rest, ok := shortSearchElement(frame, 0x30)
	if !ok || len(rest) != 0 ||
		(ber.MaxPacketLengthBytes > 0 && int64(len(content)) > ber.MaxPacketLengthBytes) ||
		(ber.MaxNestingDepth > 0 && ber.MaxNestingDepth <= 3) {
		return Message{}, false
	}
	idBytes, rest, ok := shortSearchElement(content, 0x02)
	if !ok || len(idBytes) == 0 {
		return Message{}, false
	}
	id, err := ber.ParseInt64(idBytes)
	if err != nil || id <= 0 || id > math.MaxInt32 {
		return Message{}, false
	}
	operation, rest, ok := shortSearchElement(rest, 0x63)
	if !ok || len(rest) != 0 {
		return Message{}, false
	}

	base, rest, ok := shortSearchElement(operation, 0x04)
	if !ok {
		return Message{}, false
	}
	var numbers [4]int64
	for i, tag := range [...]byte{0x0a, 0x0a, 0x02, 0x02} {
		var value []byte
		value, rest, ok = shortSearchElement(rest, tag)
		if !ok || len(value) == 0 {
			return Message{}, false
		}
		numbers[i], err = ber.ParseInt64(value)
		if err != nil || numbers[i] < math.MinInt32 || numbers[i] > math.MaxInt32 {
			return Message{}, false
		}
	}
	boolean, rest, ok := shortSearchElement(rest, 0x01)
	if !ok || len(boolean) != 1 || len(rest) == 0 {
		return Message{}, false
	}
	filterTag := rest[0]
	if filterTag != 0xa3 && filterTag != 0x87 {
		return Message{}, false
	}
	filterValue, rest, ok := shortSearchElement(rest, filterTag)
	if !ok {
		return Message{}, false
	}
	attribute := filterValue
	var assertion []byte
	if filterTag == 0xa3 {
		attribute, filterValue, ok = shortSearchElement(filterValue, 0x04)
		if !ok {
			return Message{}, false
		}
		assertion, filterValue, ok = shortSearchElement(filterValue, 0x04)
		if !ok || len(filterValue) != 0 {
			return Message{}, false
		}
	}
	if len(attribute) == 0 {
		return Message{}, false
	}
	selection, rest, ok := shortSearchElement(rest, 0x30)
	if !ok || len(rest) != 0 {
		return Message{}, false
	}
	count := 0
	for rest = selection; len(rest) > 0; count++ {
		_, rest, ok = shortSearchElement(rest, 0x04)
		if !ok {
			return Message{}, false
		}
	}

	// Allocate only after the entire bounded shape has been validated. Copy values
	// so the returned request owns its data, just like the packet-based decoder.
	attributes := make([]string, count)
	for i := range attributes {
		var value []byte
		value, selection, _ = shortSearchElement(selection, 0x04)
		attributes[i] = string(value)
	}
	filter := directory.Filter{Kind: directory.FilterPresent, Attribute: string(attribute)}
	if filterTag == 0xa3 {
		filter.Kind = directory.FilterEquality
		if len(assertion) > 0 {
			filter.Assertion = bytes.Clone(assertion)
		}
	}
	return Message{ID: id, Request: SearchRequest{
		BaseDN: string(base), Scope: directory.Scope(numbers[0]),
		DerefAliases: int(numbers[1]), SizeLimit: int(numbers[2]), TimeLimit: int(numbers[3]),
		TypesOnly: boolean[0] != 0, Filter: filter, Attributes: attributes,
	}}, true
}

// shortSearchElement deliberately supports neither high tags nor long or
// indefinite lengths. The enclosing frame bounds all work to 127 content bytes.
func shortSearchElement(data []byte, tag byte) (value, rest []byte, ok bool) {
	if len(data) < 2 || data[0] != tag || data[1] >= 0x80 || int(data[1]) > len(data)-2 {
		return nil, nil, false
	}
	end := 2 + int(data[1])
	return data[2:end], data[end:], true
}
