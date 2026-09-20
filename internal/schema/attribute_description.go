package schema

import "fmt"

// ValidateAttributeDescription checks registered names/OIDs and option syntax
// without applying a value validator. Configuration values may use formats
// interpreted by their directive handlers rather than ordinary LDAP syntaxes.
func (registry *Registry) ValidateAttributeDescription(description string) error {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute, known := registry.attributes[schemaKey(baseAttributeDescription(description))]
	if !known {
		return fmt.Errorf("undefined attribute type %q", description)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return err
	}
	return registry.validateAttributeDescription(description, effective)
}
