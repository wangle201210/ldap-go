package server

import (
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func prettyRDNAttribute(runtime *runtimeState, attribute directory.Attribute) (directory.Attribute, bool, error) {
	base, _, _ := strings.Cut(attribute.Description, ";")
	if !runtime.rdnAttributes[strings.ToLower(base)] || len(attribute.Values) == 0 {
		return attribute, false, nil
	}
	values := make([][]byte, len(attribute.Values))
	ordered := runtime.schema.HasOrderedValues(attribute.Description)
	for index, value := range attribute.Values {
		var order int
		var numbered bool
		if ordered {
			var err error
			order, value, numbered, err = schema.ParseOrderedValue(value)
			if err != nil {
				return attribute, false, err
			}
		}
		pretty, err := runtime.schema.PrettyRDNValue(value)
		if err != nil {
			return attribute, false, err
		}
		if numbered {
			pretty = schema.FormatOrderedValue(order, pretty)
		}
		values[index] = pretty
	}
	attribute.Values = values
	attribute.RawNormalized = false
	return attribute, true, nil
}

func prettyRDNEntry(runtime *runtimeState, entry *directory.Entry) error {
	if len(runtime.rdnAttributes) == 0 {
		return nil
	}
	var attributes []directory.Attribute
	for index, attribute := range entry.Attributes {
		pretty, changed, err := prettyRDNAttribute(runtime, attribute)
		if err != nil {
			return err
		}
		if changed {
			if attributes == nil {
				attributes = append([]directory.Attribute(nil), entry.Attributes...)
			}
			attributes[index] = pretty
		}
	}
	if attributes != nil {
		entry.Attributes = attributes
	}
	return nil
}

func prettyRDNModifications(runtime *runtimeState, changes []ldapwire.Modification) ([]ldapwire.Modification, error) {
	if len(runtime.rdnAttributes) == 0 {
		return changes, nil
	}
	var result []ldapwire.Modification
	for index, change := range changes {
		pretty, changed, err := prettyRDNAttribute(runtime, change.Attribute)
		if err != nil {
			return nil, err
		}
		if changed {
			if result == nil {
				result = append([]ldapwire.Modification(nil), changes...)
			}
			result[index].Attribute = pretty
		}
	}
	if result == nil {
		return changes, nil
	}
	return result, nil
}
