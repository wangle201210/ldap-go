package ldapwire

import (
	"bytes"
	"fmt"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

// EncodeRequestMessage encodes a parsed LDAP request for forwarding to
// another DSA. The message ID may be replaced by the caller before encoding.
func EncodeRequestMessage(message Message) ([]byte, error) {
	if message.ID <= 0 || message.ID > math.MaxInt32 {
		return nil, fmt.Errorf("invalid LDAP message ID %d", message.ID)
	}
	operation, err := encodeRequest(message.Request)
	if err != nil {
		return nil, err
	}
	return encodeMessage(message.ID, operation, message.Controls), nil
}

func encodeRequest(request Request) (*ber.Packet, error) {
	switch request := request.(type) {
	case BindRequest:
		packet := ber.Encode(
			ber.ClassApplication,
			ber.TypeConstructed,
			ApplicationBindRequest,
			nil,
			"BindRequest",
		)
		packet.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			int64(request.Version),
			"version",
		))
		packet.AppendChild(octetString([]byte(request.Name)))
		if request.Authentication.IsSASL {
			authentication := ber.Encode(
				ber.ClassContext,
				ber.TypeConstructed,
				3,
				nil,
				"sasl",
			)
			authentication.AppendChild(octetString(
				[]byte(request.Authentication.SASLMechanism),
			))
			if request.Authentication.HasSASLCredentials {
				authentication.AppendChild(octetString(
					request.Authentication.SASLCredentials,
				))
			}
			packet.AppendChild(authentication)
		} else {
			packet.AppendChild(contextPrimitive(
				0,
				request.Authentication.Simple,
				"simple",
			))
		}
		return packet, nil

	case SearchRequest:
		filter, err := encodeFilter(request.Filter, 0)
		if err != nil {
			return nil, err
		}
		packet := ber.Encode(
			ber.ClassApplication,
			ber.TypeConstructed,
			ApplicationSearchRequest,
			nil,
			"SearchRequest",
		)
		packet.AppendChild(octetString([]byte(request.BaseDN)))
		packet.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
			int64(request.Scope),
			"scope",
		))
		packet.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
			int64(request.DerefAliases),
			"derefAliases",
		))
		packet.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			int64(request.SizeLimit),
			"sizeLimit",
		))
		packet.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			int64(request.TimeLimit),
			"timeLimit",
		))
		packet.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			request.TypesOnly,
			"typesOnly",
		))
		packet.AppendChild(filter)
		attributes := ber.NewSequence("attributes")
		for _, attribute := range request.Attributes {
			attributes.AppendChild(octetString([]byte(attribute)))
		}
		packet.AppendChild(attributes)
		return packet, nil

	case UnbindRequest:
		return ber.Encode(
			ber.ClassApplication,
			ber.TypePrimitive,
			ApplicationUnbindRequest,
			nil,
			"UnbindRequest",
		), nil

	case AddRequest:
		packet := ber.Encode(
			ber.ClassApplication,
			ber.TypeConstructed,
			ApplicationAddRequest,
			nil,
			"AddRequest",
		)
		packet.AppendChild(octetString([]byte(request.Entry.DN)))
		attributes := ber.NewSequence("attributes")
		for _, attribute := range request.Entry.Attributes {
			attributes.AppendChild(encodeAttribute(attribute))
		}
		packet.AppendChild(attributes)
		return packet, nil

	case ModifyRequest:
		packet := ber.Encode(
			ber.ClassApplication,
			ber.TypeConstructed,
			ApplicationModifyRequest,
			nil,
			"ModifyRequest",
		)
		packet.AppendChild(octetString([]byte(request.DN)))
		changes := ber.NewSequence("changes")
		for _, modification := range request.Changes {
			change := ber.NewSequence("change")
			change.AppendChild(ber.NewInteger(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagEnumerated,
				int64(modification.Operation),
				"operation",
			))
			change.AppendChild(encodeAttribute(modification.Attribute))
			changes.AppendChild(change)
		}
		packet.AppendChild(changes)
		return packet, nil

	case DeleteRequest:
		return applicationPrimitive(
			ApplicationDeleteRequest,
			[]byte(request.DN),
			"DeleteRequest",
		), nil

	case ModifyDNRequest:
		packet := ber.Encode(
			ber.ClassApplication,
			ber.TypeConstructed,
			ApplicationModifyDNRequest,
			nil,
			"ModifyDNRequest",
		)
		packet.AppendChild(octetString([]byte(request.DN)))
		packet.AppendChild(octetString([]byte(request.NewRDN)))
		packet.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			request.DeleteOldRDN,
			"deleteOldRDN",
		))
		if request.HasNewSuperior {
			packet.AppendChild(contextPrimitive(
				0,
				[]byte(request.NewSuperior),
				"newSuperior",
			))
		}
		return packet, nil

	case CompareRequest:
		packet := ber.Encode(
			ber.ClassApplication,
			ber.TypeConstructed,
			ApplicationCompareRequest,
			nil,
			"CompareRequest",
		)
		packet.AppendChild(octetString([]byte(request.DN)))
		assertion := ber.NewSequence("assertion")
		assertion.AppendChild(octetString([]byte(request.Attribute)))
		assertion.AppendChild(octetString(request.Assertion))
		packet.AppendChild(assertion)
		return packet, nil

	case AbandonRequest:
		return ber.NewInteger(
			ber.ClassApplication,
			ber.TypePrimitive,
			ApplicationAbandonRequest,
			request.MessageID,
			"AbandonRequest",
		), nil

	case ExtendedRequest:
		packet := ber.Encode(
			ber.ClassApplication,
			ber.TypeConstructed,
			ApplicationExtendedRequest,
			nil,
			"ExtendedRequest",
		)
		packet.AppendChild(contextPrimitive(
			0,
			[]byte(request.Name),
			"requestName",
		))
		if request.HasValue {
			packet.AppendChild(contextPrimitive(
				1,
				request.Value,
				"requestValue",
			))
		}
		return packet, nil

	default:
		return nil, fmt.Errorf("cannot encode LDAP request type %T", request)
	}
}

func encodeAttribute(attribute directory.Attribute) *ber.Packet {
	packet := ber.NewSequence("attribute")
	packet.AppendChild(octetString([]byte(attribute.Description)))
	values := ber.Encode(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSet,
		nil,
		"values",
	)
	for _, value := range attribute.Values {
		values.AppendChild(octetString(value))
	}
	packet.AppendChild(values)
	return packet
}

func encodeFilter(filter directory.Filter, depth int) (*ber.Packet, error) {
	if depth > maxFilterDepth {
		return nil, fmt.Errorf("filter nesting exceeds %d", maxFilterDepth)
	}
	packet := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(filter.Kind),
		nil,
		"filter",
	)
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr:
		for _, child := range filter.Children {
			encoded, err := encodeFilter(child, depth+1)
			if err != nil {
				return nil, err
			}
			packet.AppendChild(encoded)
		}
		return packet, nil

	case directory.FilterNot:
		if len(filter.Children) != 1 {
			return nil, fmt.Errorf("not filter requires exactly one child")
		}
		child, err := encodeFilter(filter.Children[0], depth+1)
		if err != nil {
			return nil, err
		}
		packet.AppendChild(child)
		return packet, nil

	case directory.FilterEquality,
		directory.FilterGreaterOrEqual,
		directory.FilterLessOrEqual,
		directory.FilterApprox:
		if filter.Attribute == "" {
			return nil, fmt.Errorf("attribute value filter has no attribute")
		}
		packet.AppendChild(octetString([]byte(filter.Attribute)))
		packet.AppendChild(octetString(filter.Assertion))
		return packet, nil

	case directory.FilterSubstrings:
		if filter.Attribute == "" {
			return nil, fmt.Errorf("substring filter has no attribute")
		}
		packet.AppendChild(octetString([]byte(filter.Attribute)))
		parts := ber.NewSequence("substrings")
		if filter.Substring.Initial != nil {
			parts.AppendChild(contextPrimitive(
				0,
				filter.Substring.Initial,
				"initial",
			))
		}
		for _, value := range filter.Substring.Any {
			parts.AppendChild(contextPrimitive(1, value, "any"))
		}
		if filter.Substring.Final != nil {
			parts.AppendChild(contextPrimitive(
				2,
				filter.Substring.Final,
				"final",
			))
		}
		if len(parts.Children) == 0 {
			return nil, fmt.Errorf("substring filter has no components")
		}
		packet.AppendChild(parts)
		return packet, nil

	case directory.FilterPresent:
		if filter.Attribute == "" {
			return nil, fmt.Errorf("present filter has no attribute")
		}
		return contextPrimitive(
			uint64(filter.Kind),
			[]byte(filter.Attribute),
			"present",
		), nil

	case directory.FilterExtensible:
		if filter.Attribute == "" && filter.MatchingRule == "" {
			return nil, fmt.Errorf("extensible filter has no type or matching rule")
		}
		if filter.MatchingRule != "" {
			packet.AppendChild(contextPrimitive(
				1,
				[]byte(filter.MatchingRule),
				"matchingRule",
			))
		}
		if filter.Attribute != "" {
			packet.AppendChild(contextPrimitive(
				2,
				[]byte(filter.Attribute),
				"type",
			))
		}
		packet.AppendChild(contextPrimitive(
			3,
			filter.Assertion,
			"matchValue",
		))
		if filter.DNAttributes {
			packet.AppendChild(contextPrimitive(
				4,
				[]byte{0xff},
				"dnAttributes",
			))
		}
		return packet, nil

	default:
		return nil, fmt.Errorf("unknown filter kind %d", filter.Kind)
	}
}

func applicationPrimitive(tag uint64, value []byte, description string) *ber.Packet {
	packet := ber.Encode(
		ber.ClassApplication,
		ber.TypePrimitive,
		ber.Tag(tag),
		nil,
		description,
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}

func contextPrimitive(tag uint64, value []byte, description string) *ber.Packet {
	packet := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		ber.Tag(tag),
		nil,
		description,
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}
