package ldapwire

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

const maxFilterDepth = 64

func decodeFilter(packet *ber.Packet, depth int) (directory.Filter, error) {
	if depth > maxFilterDepth {
		return directory.Filter{}, malformed("filter nesting exceeds %d", maxFilterDepth)
	}
	if packet == nil || packet.ClassType != ber.ClassContext {
		return directory.Filter{}, malformed("filter is not context-specific")
	}

	filter := directory.Filter{Kind: directory.FilterKind(packet.Tag)}
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr:
		if packet.TagType != ber.TypeConstructed {
			return directory.Filter{}, malformed("set filter is not constructed")
		}
		filter.Children = make([]directory.Filter, 0, len(packet.Children))
		for _, child := range packet.Children {
			decoded, err := decodeFilter(child, depth+1)
			if err != nil {
				return directory.Filter{}, err
			}
			filter.Children = append(filter.Children, decoded)
		}
		return filter, nil

	case directory.FilterNot:
		if packet.TagType != ber.TypeConstructed || len(packet.Children) != 1 {
			return directory.Filter{}, malformed("not filter requires one child")
		}
		child, err := decodeFilter(packet.Children[0], depth+1)
		if err != nil {
			return directory.Filter{}, err
		}
		filter.Children = []directory.Filter{child}
		return filter, nil

	case directory.FilterEquality,
		directory.FilterGreaterOrEqual,
		directory.FilterLessOrEqual,
		directory.FilterApprox:
		if packet.TagType != ber.TypeConstructed || len(packet.Children) != 2 {
			return directory.Filter{}, malformed("invalid attribute value assertion")
		}
		attribute, err := packetString(packet.Children[0])
		if err != nil || attribute == "" {
			return directory.Filter{}, malformed("invalid filter attribute")
		}
		assertion, err := packetBytes(packet.Children[1])
		if err != nil {
			return directory.Filter{}, malformed("invalid filter assertion")
		}
		filter.Attribute = attribute
		filter.Assertion = assertion
		return filter, nil

	case directory.FilterPresent:
		if packet.TagType != ber.TypePrimitive || packet.Data.Len() == 0 {
			return directory.Filter{}, malformed("invalid present filter")
		}
		filter.Attribute = string(packet.Data.Bytes())
		return filter, nil

	case directory.FilterSubstrings:
		if packet.TagType != ber.TypeConstructed || len(packet.Children) != 2 {
			return directory.Filter{}, malformed("invalid substring filter")
		}
		attribute, err := packetString(packet.Children[0])
		if err != nil || attribute == "" {
			return directory.Filter{}, malformed("invalid substring attribute")
		}
		parts := packet.Children[1]
		if !isPacket(parts, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
			len(parts.Children) == 0 {
			return directory.Filter{}, malformed("substring filter has no components")
		}
		filter.Attribute = attribute
		for index, part := range parts.Children {
			if part.ClassType != ber.ClassContext || part.TagType != ber.TypePrimitive {
				return directory.Filter{}, malformed("invalid substring component")
			}
			value := bytes.Clone(part.Data.Bytes())
			switch part.Tag {
			case 0:
				if index != 0 || filter.Substring.Initial != nil {
					return directory.Filter{}, malformed("invalid initial substring")
				}
				filter.Substring.Initial = value
			case 1:
				filter.Substring.Any = append(filter.Substring.Any, value)
			case 2:
				if index != len(parts.Children)-1 || filter.Substring.Final != nil {
					return directory.Filter{}, malformed("invalid final substring")
				}
				filter.Substring.Final = value
			default:
				return directory.Filter{}, malformed("unknown substring component %d", part.Tag)
			}
		}
		return filter, nil

	case directory.FilterExtensible:
		if packet.TagType != ber.TypeConstructed {
			return directory.Filter{}, malformed("invalid extensible filter")
		}
		var hasAssertion bool
		for _, child := range packet.Children {
			if child.ClassType != ber.ClassContext || child.TagType != ber.TypePrimitive {
				return directory.Filter{}, malformed("invalid matching rule assertion")
			}
			switch child.Tag {
			case 1:
				filter.MatchingRule = string(child.Data.Bytes())
			case 2:
				filter.Attribute = string(child.Data.Bytes())
			case 3:
				filter.Assertion = bytes.Clone(child.Data.Bytes())
				hasAssertion = true
			case 4:
				if child.Data.Len() != 1 {
					return directory.Filter{}, malformed("invalid dnAttributes value")
				}
				filter.DNAttributes = child.Data.Bytes()[0] != 0
			default:
				return directory.Filter{}, malformed("unknown matching rule element %d", child.Tag)
			}
		}
		if !hasAssertion || (filter.Attribute == "" && filter.MatchingRule == "") {
			return directory.Filter{}, malformed("incomplete matching rule assertion")
		}
		return filter, nil

	default:
		return directory.Filter{}, malformed("unknown filter choice %d", packet.Tag)
	}
}
