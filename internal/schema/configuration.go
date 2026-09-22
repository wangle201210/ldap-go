package schema

import (
	"fmt"
	"maps"
	"strings"
)

// RegisterOpenLDAPConfigurationSchema installs OpenLDAP 2.6.13's core
// cn=config catalog. Content schema (including top, cn, and labeledURI) must
// already exist. Registration is atomic and idempotent; it enables no runtime
// options, backends, overlays, or native modules.
func RegisterOpenLDAPConfigurationSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP configuration schema: nil registry")
	}
	attributes := make([]AttributeType, len(openLDAPConfigurationAttributeTypes))
	for index, description := range openLDAPConfigurationAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return fmt.Errorf("parse configuration attribute: %w", err)
		}
		attributes[index] = attribute
	}
	classes := make([]ObjectClass, len(openLDAPConfigurationObjectClasses))
	for index, description := range openLDAPConfigurationObjectClasses {
		class, err := ParseObjectClass(description)
		if err != nil {
			return fmt.Errorf("parse configuration object class: %w", err)
		}
		classes[index] = class
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()

	// Copy the maps while holding the registry lock so concurrent registrations
	// cannot be lost. Existing definitions are never mutated through shared
	// pointers; this also keeps failed installs and earlier clones unchanged.
	staged := &Registry{
		attributes:    maps.Clone(registry.attributes),
		objectClasses: maps.Clone(registry.objectClasses),
		syntaxes:      registry.syntaxes,
	}
	for _, want := range attributes {
		var existing *AttributeType
		for _, key := range schemaKeys(want.OID, want.Names) {
			if candidate := staged.attributes[key]; candidate != nil {
				if existing != nil && existing != candidate {
					return fmt.Errorf("configuration attribute %q: identifiers conflict", want.Name())
				}
				existing = candidate
			}
		}
		if existing == nil {
			if err := staged.RegisterAttributeType(want); err != nil {
				return err
			}
			continue
		}
		if !staged.compatibleConfigurationAttribute(*existing, want) {
			return fmt.Errorf("configuration attribute %q: incompatible existing definition", want.Name())
		}
		copy := cloneAttributeType(*existing)
		copy.Hidden = false
		if copy.Description == "" {
			copy.Description = want.Description
		}
		for _, key := range schemaKeys(copy.OID, copy.Names) {
			staged.attributes[key] = &copy
		}
	}
	for _, want := range classes {
		var existing *ObjectClass
		for _, key := range schemaKeys(want.OID, want.Names) {
			if candidate := staged.objectClasses[key]; candidate != nil {
				if existing != nil && existing != candidate {
					return fmt.Errorf("configuration object class %q: identifiers conflict", want.Name())
				}
				existing = candidate
			}
		}
		if existing == nil {
			if err := staged.RegisterObjectClass(want); err != nil {
				return err
			}
			continue
		}
		if !staged.compatibleConfigurationObjectClass(*existing, want) {
			return fmt.Errorf("configuration object class %q: incompatible existing definition", want.Name())
		}
		copy := cloneObjectClass(*existing)
		copy.Hidden = false
		if copy.Description == "" {
			copy.Description = want.Description
		}
		for _, key := range schemaKeys(copy.OID, copy.Names) {
			staged.objectClasses[key] = &copy
		}
	}

	for _, attribute := range attributes {
		if err := staged.validateConfigurationAttribute(attribute.OID); err != nil {
			return err
		}
	}
	for _, class := range classes {
		closure := make(map[string]*ObjectClass)
		if err := staged.collectObjectClass(staged.objectClasses[schemaKey(class.OID)], closure, make(map[string]bool)); err != nil {
			return err
		}
		for _, ancestor := range closure {
			for _, names := range [][]string{ancestor.Must, ancestor.May} {
				for _, name := range names {
					if err := staged.validateConfigurationAttribute(name); err != nil {
						return fmt.Errorf("configuration class %q: %w", class.Name(), err)
					}
				}
			}
		}
	}
	registry.attributes = staged.attributes
	registry.objectClasses = staged.objectClasses
	registry.preparedNames.clear()
	return nil
}

func (registry *Registry) validateConfigurationAttribute(name string) error {
	attribute := registry.attributes[schemaKey(name)]
	if attribute == nil {
		return fmt.Errorf("unknown configuration attribute %q", name)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return err
	}
	if registry.syntaxes[effective.Syntax] == nil {
		return fmt.Errorf("configuration attribute %q: unknown syntax %q", name, effective.Syntax)
	}
	return nil
}

func (registry *Registry) compatibleConfigurationAttribute(got, want AttributeType) bool {
	if !strings.EqualFold(got.Name(), want.Name()) || !compatibleConfigurationExtensions(got.Extensions, want.Extensions) {
		return false
	}
	got.Superior = configurationAttributeOID(registry, got.Superior)
	want.Superior = configurationAttributeOID(registry, want.Superior)
	got.Equality, want.Equality = configurationMatchingRule(got.Equality), configurationMatchingRule(want.Equality)
	got.Ordering, want.Ordering = configurationMatchingRule(got.Ordering), configurationMatchingRule(want.Ordering)
	got.Substring, want.Substring = configurationMatchingRule(got.Substring), configurationMatchingRule(want.Substring)
	return compatibleMetaAttribute(got, want)
}

func configurationMatchingRule(rule string) string {
	// Native configuration schema references these rules even though the Go
	// matcher does not implement them. Resolve metadata aliases only; do not
	// add them to executable matching rules or subschema rule publication.
	normalized := canonicalMatchingRule(rule)
	switch normalized {
	case "2.5.13.34":
		return "certificateexactmatch"
	case "1.3.6.1.4.1.4203.666.4.13":
		return "privatekeymatch"
	default:
		return normalized
	}
}

func (registry *Registry) compatibleConfigurationObjectClass(got, want ObjectClass) bool {
	if !strings.EqualFold(got.Name(), want.Name()) || !compatibleConfigurationExtensions(got.Extensions, want.Extensions) {
		return false
	}
	got, want = cloneObjectClass(got), cloneObjectClass(want)
	for _, class := range []*ObjectClass{&got, &want} {
		for index, name := range class.Superiors {
			if parent := registry.objectClasses[schemaKey(name)]; parent != nil {
				class.Superiors[index] = parent.OID
			}
		}
		for _, names := range [][]string{class.Must, class.May} {
			for index, name := range names {
				names[index] = configurationAttributeOID(registry, name)
			}
		}
	}
	return compatibleMetaObjectClass(got, want)
}

func configurationAttributeOID(registry *Registry, name string) string {
	if attribute := registry.attributes[schemaKey(name)]; attribute != nil {
		return attribute.OID
	}
	return name
}

func compatibleConfigurationExtensions(got, want map[string][]string) bool {
	// Provenance is descriptive; all other extensions, especially X-ORDERED,
	// must agree in both directions to preserve matching and value handling.
	for key, values := range got {
		if strings.EqualFold(key, "X-ORIGIN") || strings.EqualFold(key, "X-SCHEMA-FILE") {
			continue
		}
		if !metaExtensionsContain(want, map[string][]string{key: values}) {
			return false
		}
	}
	return metaExtensionsContain(got, want)
}
