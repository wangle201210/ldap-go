package server

import (
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func configurationAttributeName(registry *schema.Registry, description string) string {
	base, options, tagged := strings.Cut(description, ";")
	attribute, known := registry.AttributeType(base)
	if !known {
		return description
	}
	if tagged {
		return attribute.Name() + ";" + options
	}
	return attribute.Name()
}

func validateConfigurationAttributeOptions(registry *schema.Registry, attributes []directory.Attribute) error {
	for _, attribute := range attributes {
		if !strings.Contains(attribute.Description, ";") {
			continue
		}
		if err := registry.ValidateAttributeDescription(attribute.Description); err != nil {
			return operationFailed(ldapwire.ResultUndefinedAttributeType, err.Error())
		}
	}
	return nil
}

// Configuration parsers use canonical field names. Normalize a read view rather
// than rewriting imported data, and copy only the attribute slice when needed.
func canonicalConfigurationEntry(registry *schema.Registry, entry directory.Entry) directory.Entry {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil || !isConfigurationDN(dn) {
		return entry
	}
	var attributes []directory.Attribute
	seen := make(map[string]int, len(entry.Attributes))
	for index, attribute := range entry.Attributes {
		name := configurationAttributeName(registry, attribute.Description)
		key := strings.ToLower(name)
		if previous, duplicate := seen[key]; duplicate {
			if attributes == nil {
				attributes = make([]directory.Attribute, index, len(entry.Attributes))
				copy(attributes, entry.Attributes[:index])
			}
			values := make([][]byte, 0, len(attributes[previous].Values)+len(attribute.Values))
			values = append(values, attributes[previous].Values...)
			attributes[previous].Values = append(values, attribute.Values...)
			continue
		}
		if name != attribute.Description {
			if attributes == nil {
				attributes = make([]directory.Attribute, index, len(entry.Attributes))
				copy(attributes, entry.Attributes[:index])
			}
		}
		if attributes != nil {
			attribute.Description = name
			seen[key] = len(attributes)
			attributes = append(attributes, attribute)
		} else {
			seen[key] = index
		}
	}
	if attributes != nil {
		entry.Attributes = attributes
	}
	return entry
}

func canonicalConfigurationModifications(registry *schema.Registry, changes []ldapwire.Modification) []ldapwire.Modification {
	var prepared []ldapwire.Modification
	for index, change := range changes {
		name := configurationAttributeName(registry, change.Attribute.Description)
		if name != change.Attribute.Description {
			if prepared == nil {
				prepared = append([]ldapwire.Modification(nil), changes...)
			}
			prepared[index].Attribute.Description = name
		}
	}
	if prepared == nil {
		return changes
	}
	return prepared
}

type configurationAttributeReader struct {
	storage.Reader
	registry *schema.Registry
}

func (reader configurationAttributeReader) Get(dn directory.DN) (directory.Entry, error) {
	entry, err := reader.Reader.Get(dn)
	if err == nil {
		entry = canonicalConfigurationEntry(reader.registry, entry)
	}
	return entry, err
}
func (reader configurationAttributeReader) GetIn(partition string, dn directory.DN) (directory.Entry, error) {
	entry, err := reader.Reader.GetIn(partition, dn)
	if err == nil {
		entry = canonicalConfigurationEntry(reader.registry, entry)
	}
	return entry, err
}
func (reader configurationAttributeReader) ForEach(fn func(directory.Entry) error) error {
	return reader.Reader.ForEach(func(entry directory.Entry) error { return fn(canonicalConfigurationEntry(reader.registry, entry)) })
}
func (reader configurationAttributeReader) ForEachIn(partition string, fn func(directory.Entry) error) error {
	return reader.Reader.ForEachIn(partition, func(entry directory.Entry) error { return fn(canonicalConfigurationEntry(reader.registry, entry)) })
}
func (reader configurationAttributeReader) ForEachPartition(fn func(string, directory.Entry) error) error {
	return reader.Reader.ForEachPartition(func(partition string, entry directory.Entry) error {
		return fn(partition, canonicalConfigurationEntry(reader.registry, entry))
	})
}
