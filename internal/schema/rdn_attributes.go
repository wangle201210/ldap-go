package schema

// RDNAttributeDescriptions identifies attributes whose syntax uses rdnPretty,
// including aliases, attribute inheritance, and X-SUBST chains. Runtime builders
// retain these keys so ordinary writes do not scan schema or allocate formatters.
func (registry *Registry) RDNAttributeDescriptions() ([]string, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	resolved := make(map[*AttributeType]bool)
	var descriptions []string
	for key, attribute := range registry.attributes {
		usesRDN, found := resolved[attribute]
		if !found {
			effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
			if err != nil {
				return nil, err
			}
			syntax := registry.syntaxes[schemaKey(effective.Syntax)]
			usesRDN = syntax != nil && syntax.validatorIdentity == SyntaxRDN
			resolved[attribute] = usesRDN
		}
		if usesRDN {
			descriptions = append(descriptions, key)
		}
	}
	return descriptions, nil
}
