package schema

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func attributeHasOrderedValues(attribute AttributeType) bool {
	values := attribute.Extensions["X-ORDERED"]
	return len(values) == 1 && values[0] == "VALUES"
}

func (registry *Registry) HasOrderedValues(description string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute, found := registry.attributes[schemaKey(baseAttributeDescription(description))]
	return found && attributeHasOrderedValues(*attribute)
}

// ParseOrderedValue separates a valid OpenLDAP {n} prefix. A value beginning
// with an invalid brace prefix is rejected because slapd's ordered-value sort
// rejects it even when the underlying syntax could otherwise accept it.
func ParseOrderedValue(value []byte) (int, []byte, bool, error) {
	if len(value) == 0 || value[0] != '{' {
		return 0, bytes.Clone(value), false, nil
	}
	end := bytes.IndexByte(value, '}')
	if end < 2 {
		return 0, nil, false, errors.New("invalid ordered value prefix")
	}
	for _, character := range value[1:end] {
		if character < '0' || character > '9' {
			return 0, nil, false, errors.New("invalid ordered value prefix")
		}
	}
	order, err := strconv.Atoi(string(value[1:end]))
	if err != nil {
		return 0, nil, false, errors.New("ordered value index is too large")
	}
	return order, bytes.Clone(value[end+1:]), true, nil
}

func FormatOrderedValue(order int, value []byte) []byte {
	prefix := []byte("{" + strconv.Itoa(order) + "}")
	result := make([]byte, 0, len(prefix)+len(value))
	result = append(result, prefix...)
	return append(result, value...)
}

func compareOrderedAssertion(
	rule string,
	stored, assertion []byte,
) (int, error) {
	storedOrder, storedValue, storedIndexed, err := ParseOrderedValue(stored)
	if err != nil {
		return 0, err
	}
	assertionOrder, assertionValue, assertionIndexed, err := ParseOrderedValue(assertion)
	if err != nil {
		return 0, err
	}
	if assertionIndexed {
		if !storedIndexed || storedOrder < assertionOrder {
			return -1, nil
		}
		if storedOrder > assertionOrder {
			return 1, nil
		}
		if len(assertionValue) == 0 {
			return 0, nil
		}
	}
	return compareWithRule(rule, storedValue, assertionValue)
}

func NormalizeOrderedValues(values [][]byte) ([][]byte, error) {
	type item struct {
		order   int
		value   []byte
		indexed bool
		input   int
	}
	items := make([]item, len(values))
	indexed := false
	unindexed := false
	for index, value := range values {
		order, content, hasOrder, err := ParseOrderedValue(value)
		if err != nil {
			return nil, err
		}
		items[index] = item{order: order, value: content, indexed: hasOrder, input: index}
		indexed = indexed || hasOrder
		unindexed = unindexed || !hasOrder
	}
	if indexed && unindexed {
		return nil, errors.New("ordered attribute mixes indexed and unindexed values")
	}
	if indexed {
		sort.SliceStable(items, func(left, right int) bool {
			if items[left].order != items[right].order {
				return items[left].order < items[right].order
			}
			return items[left].input < items[right].input
		})
		for index := 1; index < len(items); index++ {
			if items[index-1].order == items[index].order {
				return nil, fmt.Errorf("duplicate ordered value index %d", items[index].order)
			}
		}
	}
	result := make([][]byte, len(items))
	for index := range items {
		result[index] = FormatOrderedValue(index, items[index].value)
	}
	return result, nil
}

// NormalizeOrderedEntryValues applies slapd's initial Add/slapadd numbering to
// all X-ORDERED VALUES attributes without changing non-ordered attributes.
func (registry *Registry) NormalizeOrderedEntryValues(entry *directory.Entry) error {
	if entry == nil {
		return errors.New("entry is required")
	}
	for index := range entry.Attributes {
		attribute := &entry.Attributes[index]
		if !registry.HasOrderedValues(attribute.Description) {
			continue
		}
		values, err := NormalizeOrderedValues(attribute.Values)
		if err != nil {
			return fmt.Errorf("attribute %q: %w", attribute.Description, err)
		}
		attribute.Values = values
	}
	return nil
}
