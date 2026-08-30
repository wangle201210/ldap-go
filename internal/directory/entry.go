package directory

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrNoSuchAttribute       = errors.New("no such attribute")
	ErrAttributeValueExists  = errors.New("attribute or value exists")
	ErrInvalidIncrementValue = errors.New("invalid increment value")
)

// Attribute preserves the attribute description and raw LDAP values exactly as
// received. Normalized values belong in indexes, not in the stored entry.
type Attribute struct {
	Description string   `json:"description"`
	Values      [][]byte `json:"values"`
}

// Entry is the storage-neutral representation of one LDAP entry.
type Entry struct {
	DN           string      `json:"dn"`
	Attributes   []Attribute `json:"attributes"`
	dnIdentity   string
	normalizedDN *DN
	dnOrderKey   string
}

func (e Entry) Clone() Entry {
	out := Entry{
		DN:           e.DN,
		Attributes:   make([]Attribute, len(e.Attributes)),
		dnIdentity:   e.dnIdentity,
		normalizedDN: e.normalizedDN,
		dnOrderKey:   e.dnOrderKey,
	}
	for i, attribute := range e.Attributes {
		out.Attributes[i].Description = attribute.Description
		out.Attributes[i].Values = cloneValues(attribute.Values)
	}
	return out
}

// WithDNIdentity returns a copy carrying a transient normalized storage key.
// The hint is intentionally excluded from JSON and LDAP entry equality.
func (e Entry) WithDNIdentity(dn DN) Entry {
	e.dnIdentity = dn.Key()
	e.normalizedDN = &dn
	return e
}

func (e Entry) DNIdentity() (string, bool) {
	return e.dnIdentity, e.dnIdentity != ""
}

// WithNormalizedDNHint attaches immutable storage-derived DN information that
// is intentionally excluded from JSON and LDAP equality.
func (e Entry) WithNormalizedDNHint(dn DN, orderKey string) Entry {
	e.dnIdentity = dn.Key()
	e.normalizedDN = &dn
	e.dnOrderKey = orderKey
	return e
}

func (e Entry) NormalizedDNHint() (DN, bool) {
	if e.normalizedDN == nil {
		return DN{}, false
	}
	return *e.normalizedDN, true
}

func (e Entry) DNOrderKeyHint() (string, bool) {
	return e.dnOrderKey, e.dnOrderKey != ""
}

func (e Entry) WithoutDNIdentity() Entry {
	e.dnIdentity = ""
	return e
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
	return e.SelectWith(requested, typesOnly, nil)
}

func (e Entry) SelectWith(
	requested []string,
	typesOnly bool,
	isOperational func(string) bool,
) Entry {
	return e.SelectWithMatcher(requested, typesOnly, isOperational, nil)
}

func (e Entry) SelectWithMatcher(
	requested []string,
	typesOnly bool,
	isOperational func(string) bool,
	isDescriptionSubtype func(candidate, requested string) bool,
) Entry {
	out := Entry{DN: e.DN}
	if selectsNoAttributes(requested) {
		return out
	}

	allUserAttributes := len(requested) == 0 || slices.ContainsFunc(requested, func(value string) bool {
		return strings.EqualFold(value, "*")
	})
	allOperationalAttributes := slices.ContainsFunc(requested, func(value string) bool {
		return strings.EqualFold(value, "+")
	})

	for _, attribute := range e.Attributes {
		explicitlyRequested := slices.ContainsFunc(requested, func(value string) bool {
			if isDescriptionSubtype != nil {
				return isDescriptionSubtype(attribute.Description, value)
			}
			return equalAttributeDescription(value, attribute.Description)
		})
		operational := isOperational != nil && isOperational(attribute.Description)
		if !explicitlyRequested &&
			(!operational || !allOperationalAttributes) &&
			(operational || !allUserAttributes) {
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

func (e Entry) HasValue(description string, value []byte) bool {
	for _, existing := range e.Values(description) {
		if EqualValue(existing, value) {
			return true
		}
	}
	return false
}

func (e *Entry) AddValues(description string, values [][]byte) error {
	if len(values) == 0 {
		return ErrNoSuchAttribute
	}
	index := e.attributeIndex(description)
	if index < 0 {
		e.Attributes = append(e.Attributes, Attribute{
			Description: description,
			Values:      cloneValues(values),
		})
		return nil
	}
	for _, value := range values {
		if e.HasValue(description, value) {
			return ErrAttributeValueExists
		}
	}
	e.Attributes[index].Values = append(e.Attributes[index].Values, cloneValues(values)...)
	return nil
}

func (e *Entry) DeleteValues(description string, values [][]byte) error {
	index := e.attributeIndex(description)
	if index < 0 {
		return ErrNoSuchAttribute
	}
	if len(values) == 0 {
		e.Attributes = append(e.Attributes[:index], e.Attributes[index+1:]...)
		return nil
	}
	for _, value := range values {
		if !e.HasValue(description, value) {
			return ErrNoSuchAttribute
		}
	}

	remaining := make([][]byte, 0, len(e.Attributes[index].Values))
	for _, existing := range e.Attributes[index].Values {
		if slices.ContainsFunc(values, func(value []byte) bool {
			return EqualValue(existing, value)
		}) {
			continue
		}
		remaining = append(remaining, bytes.Clone(existing))
	}
	if len(remaining) == 0 {
		e.Attributes = append(e.Attributes[:index], e.Attributes[index+1:]...)
	} else {
		e.Attributes[index].Values = remaining
	}
	return nil
}

func (e *Entry) ReplaceValues(description string, values [][]byte) {
	index := e.attributeIndex(description)
	if len(values) == 0 {
		if index >= 0 {
			e.Attributes = append(e.Attributes[:index], e.Attributes[index+1:]...)
		}
		return
	}
	if index < 0 {
		e.Attributes = append(e.Attributes, Attribute{
			Description: description,
			Values:      cloneValues(values),
		})
		return
	}
	e.Attributes[index].Values = cloneValues(values)
}

func (e *Entry) Increment(description string, increment []byte) error {
	index := e.attributeIndex(description)
	if index < 0 || len(e.Attributes[index].Values) != 1 {
		return ErrNoSuchAttribute
	}
	delta, err := strconv.ParseInt(string(increment), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIncrementValue, err)
	}
	current, err := strconv.ParseInt(string(e.Attributes[index].Values[0]), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIncrementValue, err)
	}
	next, err := addInt64(current, delta)
	if err != nil {
		return err
	}
	e.Attributes[index].Values = [][]byte{[]byte(strconv.FormatInt(next, 10))}
	return nil
}

func (e *Entry) EnsureRDNValues(dn DN) {
	for _, attribute := range dn.RDNValues() {
		if !e.HasValue(attribute.Type, attribute.Value) {
			_ = e.AddValues(attribute.Type, [][]byte{attribute.Value})
		}
	}
}

func (e *Entry) DeleteRDNValues(dn DN) {
	for _, attribute := range dn.RDNValues() {
		if e.HasValue(attribute.Type, attribute.Value) {
			_ = e.DeleteValues(attribute.Type, [][]byte{attribute.Value})
		}
	}
}

func EqualValue(left, right []byte) bool {
	return compareDirectoryValue(left, right) == 0
}

func (e Entry) attributeIndex(description string) int {
	for i := range e.Attributes {
		if equalAttributeDescription(e.Attributes[i].Description, description) {
			return i
		}
	}
	return -1
}

func addInt64(left, right int64) (int64, error) {
	result := left + right
	if (right > 0 && result < left) || (right < 0 && result > left) {
		return 0, ErrInvalidIncrementValue
	}
	return result, nil
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
