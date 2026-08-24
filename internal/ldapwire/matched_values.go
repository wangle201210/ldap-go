package ldapwire

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

const MatchedValuesControlOID = "1.2.826.0.1.3344810.2.3"

// DecodeValuesReturnFilter decodes the RFC 3876 ValuesReturnFilter control
// value. Unlike an LDAP Search filter, its outer sequence contains only simple
// filter items and combines them as a value-level union.
func DecodeValuesReturnFilter(value []byte) ([]directory.Filter, error) {
	if len(value) == 0 {
		return nil, malformed("values return filter is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return nil, malformed("decode values return filter: %v", err)
	}
	if reader.Len() != 0 {
		return nil, malformed("values return filter has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return nil, malformed("values return filter is not a sequence")
	}
	filters := make([]directory.Filter, 0, len(packet.Children))
	for _, child := range packet.Children {
		if child.ClassType != ber.ClassContext || child.Tag < 3 || child.Tag > 9 {
			// OpenLDAP treats unknown choices as a computed/undefined item.
			filters = append(filters, directory.Filter{Kind: directory.FilterComputed})
			continue
		}
		filter, err := decodeFilter(child, 0)
		if err != nil {
			return nil, malformed("decode simple values return filter: %v", err)
		}
		filters = append(filters, filter)
	}
	return filters, nil
}
