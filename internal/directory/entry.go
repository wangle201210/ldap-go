package directory

import (
	"bytes"
	"slices"
	"strings"
)

// Attribute preserves the attribute description and raw LDAP values exactly as
// received. Normalized values belong in indexes, not in the stored entry.
type Attribute struct {
	Description string   `json:"description"`
	Values      [][]byte `json:"values"`
}

// Entry is the storage-neutral representation of one LDAP entry.
type Entry struct {
	DN         string      `json:"dn"`
	Attributes []Attribute `json:"attributes"`
}

func (e Entry) Clone() Entry {
	out := Entry{
		DN:         e.DN,
		Attributes: make([]Attribute, len(e.Attributes)),
	}
	for i, attribute := range e.Attributes {
		out.Attributes[i].Description = attribute.Description
		out.Attributes[i].Values = cloneValues(attribute.Values)
	}
	return out
}

func (e Entry) Values(description string) [][]byte {
	for _, attribute := range e.Attributes {
		if equalAttributeDescription(attribute.Description, description) {
			return cloneValues(attribute.Values)
		}
	}
	return nil
}

func (e Entry) HasAttribute(description string) bool {
	for _, attribute := range e.Attributes {
		if equalAttributeDescription(attribute.Description, description) {
			return true
		}
	}
	return false
}

func (e Entry) Select(requested []string, typesOnly bool) Entry {
	out := Entry{DN: e.DN}
	if selectsNoAttributes(requested) {
		return out
	}

	all := len(requested) == 0 || slices.ContainsFunc(requested, func(value string) bool {
		return value == "*"
	})

	for _, attribute := range e.Attributes {
		if !all && !slices.ContainsFunc(requested, func(value string) bool {
			return equalAttributeDescription(value, attribute.Description)
		}) {
			continue
		}

		selected := Attribute{Description: attribute.Description}
		if !typesOnly {
			selected.Values = cloneValues(attribute.Values)
		}
		out.Attributes = append(out.Attributes, selected)
	}
	return out
}

func (e Entry) Without(descriptions ...string) Entry {
	out := Entry{DN: e.DN}
	for _, attribute := range e.Attributes {
		if slices.ContainsFunc(descriptions, func(description string) bool {
			return equalAttributeDescription(attribute.Description, description)
		}) {
			continue
		}
		out.Attributes = append(out.Attributes, Attribute{
			Description: attribute.Description,
			Values:      cloneValues(attribute.Values),
		})
	}
	return out
}

func (e Entry) Equal(other Entry) bool {
	if e.DN != other.DN || len(e.Attributes) != len(other.Attributes) {
		return false
	}
	for i := range e.Attributes {
		if e.Attributes[i].Description != other.Attributes[i].Description ||
			len(e.Attributes[i].Values) != len(other.Attributes[i].Values) {
			return false
		}
		for j := range e.Attributes[i].Values {
			if !bytes.Equal(e.Attributes[i].Values[j], other.Attributes[i].Values[j]) {
				return false
			}
		}
	}
	return true
}

func cloneValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for i := range values {
		cloned[i] = bytes.Clone(values[i])
	}
	return cloned
}

func equalAttributeDescription(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func selectsNoAttributes(requested []string) bool {
	if len(requested) != 1 {
		return false
	}
	return requested[0] == "1.1"
}
