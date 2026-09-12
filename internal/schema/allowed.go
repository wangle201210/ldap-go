package schema

import (
	"fmt"
	"strings"
)

var openLDAPAllowedAttributeTypes = []string{
	"( 1.2.840.113556.1.4.911 NAME 'allowedChildClasses' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " DESC 'Child classes allowed for a given object' NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.2.840.113556.1.4.912 NAME 'allowedChildClassesEffective' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " DESC 'Child classes allowed for a given object according to ACLs' NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.2.840.113556.1.4.913 NAME 'allowedAttributes' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " DESC 'Attributes allowed for a given object' NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.2.840.113556.1.4.914 NAME 'allowedAttributesEffective' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " DESC 'Attributes allowed for a given object according to ACLs' NO-USER-MODIFICATION USAGE dSAOperation )",
}

// RegisterOpenLDAPAllowedSchema registers the operational attributes from
// OpenLDAP 2.6.13's allowed module. When the module or overlay is active, call
// before schema import to resolve references and again afterwards to reject
// incompatible replacements. Compatible definitions are retained.
func RegisterOpenLDAPAllowedSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP allowed schema: nil registry")
	}
	attributes := make([]AttributeType, len(openLDAPAllowedAttributeTypes))
	for index, description := range openLDAPAllowedAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP allowed attribute type: %w", err)
		}
		attributes[index] = attribute
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()

	// Validate the complete set before adding anything, including conflicting
	// aliases, so a failed registration leaves the registry unchanged.
	missing := make([]AttributeType, 0, len(attributes))
	for _, want := range attributes {
		var existing *AttributeType
		for _, key := range schemaKeys(want.OID, want.Names) {
			if byKey := registry.attributes[key]; byKey != nil {
				if existing != nil && existing != byKey {
					return fmt.Errorf("register OpenLDAP allowed attribute type %q: identifiers conflict", want.Name())
				}
				existing = byKey
			}
		}
		if existing != nil {
			if !compatibleAllowedAttribute(*existing, want) {
				return fmt.Errorf("register OpenLDAP allowed attribute type %q: incompatible existing definition", want.Name())
			}
			continue
		}
		missing = append(missing, want)
	}
	for _, attribute := range missing {
		copy := cloneAttributeType(attribute)
		for _, key := range schemaKeys(copy.OID, copy.Names) {
			registry.attributes[key] = &copy
		}
	}
	return nil
}

func compatibleAllowedAttribute(got, want AttributeType) bool {
	if got.OID != want.OID || !strings.EqualFold(got.Name(), want.Name()) ||
		got.Hidden || got.Obsolete || got.Superior != "" ||
		canonicalMatchingRule(got.Equality) != canonicalMatchingRule(want.Equality) ||
		got.Ordering != "" || got.Substring != "" || got.Syntax != want.Syntax ||
		got.SyntaxLength != 0 || got.SingleValue || got.Collective ||
		!got.NoUserModification || got.Usage != UsageDSAOperation {
		return false
	}
	for name := range got.Extensions {
		// Descriptive provenance does not change matching or value handling.
		if !strings.EqualFold(name, "X-ORIGIN") && !strings.EqualFold(name, "X-SCHEMA-FILE") {
			return false
		}
	}
	return true
}
