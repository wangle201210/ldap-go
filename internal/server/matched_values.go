package server

import (
	"bytes"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

type matchedValuesConnection struct {
	net.Conn
	messageID int64
	registry  *schema.Registry
	request   *matchedValuesControlRequest
	typesOnly bool
}

func (connection *matchedValuesConnection) Write(value []byte) (int, error) {
	transformed, err := connection.transform(value)
	if err != nil {
		return 0, err
	}
	if err := ldapwire.Write(connection.Conn, transformed); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (connection *matchedValuesConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface{ beginFinalResponse() error }); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}

func (connection *matchedValuesConnection) transform(value []byte) ([]byte, error) {
	if connection == nil || connection.request == nil || connection.typesOnly ||
		len(connection.request.filters) == 0 {
		return value, nil
	}
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		return nil, fmt.Errorf("decode matched-values LDAP response: %w", err)
	}
	if len(packet.Children) < 2 ||
		packet.Children[1].ClassType != ber.ClassApplication ||
		packet.Children[1].Tag != ldapwire.ApplicationSearchResultEntry {
		return value, nil
	}
	messageID, err := syncConsumerPacketInteger(packet.Children[0])
	if err != nil || messageID != connection.messageID {
		return value, nil
	}
	entry, err := decodeTranslucentSearchEntry(packet)
	if err != nil {
		return nil, fmt.Errorf("decode matched-values search entry: %w", err)
	}
	controls, err := decodePBindResponseControls(packet)
	if err != nil {
		return nil, fmt.Errorf("decode matched-values entry controls: %w", err)
	}
	entry = applyMatchedValuesFilter(
		connection.registry,
		entry,
		connection.request.filters,
	)
	return ldapwire.EncodeSearchResultEntry(messageID, entry, controls), nil
}

func applyMatchedValuesFilter(
	registry *schema.Registry,
	entry directory.Entry,
	filters []directory.Filter,
) directory.Entry {
	filtered := directory.Entry{DN: entry.DN}
	for _, attribute := range entry.Attributes {
		matched := directory.Attribute{Description: attribute.Description}
		for _, value := range attribute.Values {
			for _, filter := range filters {
				if matchedValuesFilterMatches(registry, attribute.Description, value, filter) {
					matched.Values = append(matched.Values, bytes.Clone(value))
					break
				}
			}
		}
		if len(matched.Values) != 0 || registry.IsOperational(attribute.Description) {
			filtered.Attributes = append(filtered.Attributes, matched)
		}
	}
	return filtered
}

func matchedValuesFilterMatches(
	registry *schema.Registry,
	attribute string,
	value []byte,
	filter directory.Filter,
) bool {
	if registry == nil {
		return false
	}
	if filter.Kind != directory.FilterExtensible &&
		!registry.AttributeDescriptionSubtype(attribute, filter.Attribute) {
		return false
	}
	switch filter.Kind {
	case directory.FilterPresent:
		return true
	case directory.FilterEquality:
		comparison, err := registry.Compare(attribute, "", value, filter.Assertion)
		return err == nil && comparison == 0
	case directory.FilterSubstrings:
		matches, err := registry.MatchSubstring(attribute, value, filter.Substring)
		return err == nil && matches
	case directory.FilterGreaterOrEqual:
		comparison, err := registry.CompareOrdering(attribute, "", value, filter.Assertion)
		return err == nil && comparison >= 0
	case directory.FilterLessOrEqual:
		comparison, err := registry.CompareOrdering(attribute, "", value, filter.Assertion)
		return err == nil && comparison <= 0
	case directory.FilterApprox:
		// OpenLDAP 2.6.13 accepts this RFC item but omits it from the
		// matched-values execution switch, so it never selects a value.
		return false
	case directory.FilterExtensible:
		if filter.Attribute != "" &&
			!registry.AttributeDescriptionSubtype(attribute, filter.Attribute) {
			return false
		}
		comparison, err := registry.Compare(
			attribute,
			filter.MatchingRule,
			value,
			filter.Assertion,
		)
		return err == nil && comparison == 0
	default:
		return false
	}
}

func withoutMatchedValuesControl(controls []ldapwire.Control) []ldapwire.Control {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID != ldapwire.MatchedValuesControlOID {
			filtered = append(filtered, control)
		}
	}
	return filtered
}
