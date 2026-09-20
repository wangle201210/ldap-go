package schema

// SchemaDescriptionAssertionError preserves the distinction between malformed OID
// syntax and an unknown descriptor. Native Compare treats the latter as false,
// while filter evaluation must retain undefined (including under NOT).
type SchemaDescriptionAssertionError struct {
	Unknown bool
}

// MatchingRuleAssertionError is retained for matching-rule assertion callers.
type MatchingRuleAssertionError = SchemaDescriptionAssertionError

func (err *SchemaDescriptionAssertionError) Error() string {
	if err.Unknown {
		return "unrecognized schema identifier"
	}
	return "invalid schema assertion syntax"
}

func (registry *Registry) schemaDescriptionAssertionOIDLocked(attributeOID string, value []byte) (string, error) {
	assertion := string(value)
	if !validObjectIdentifier(assertion) {
		return "", &SchemaDescriptionAssertionError{}
	}
	switch attributeOID {
	case "2.5.21.5":
		if attribute := registry.attributes[schemaKey(assertion)]; attribute != nil {
			return attribute.OID, nil
		}
	case "2.5.21.6":
		if class := registry.objectClasses[schemaKey(assertion)]; class != nil {
			return class.OID, nil
		}
	}
	if assertion[0] >= '0' && assertion[0] <= '9' {
		return assertion, nil
	}
	return "", &SchemaDescriptionAssertionError{Unknown: true}
}

func matchingRuleAssertionOID(value []byte) (string, error) {
	assertion := string(value)
	if !validObjectIdentifier(assertion) {
		return "", &MatchingRuleAssertionError{}
	}
	if known, found := BuiltinMatchingRule(assertion); found {
		return known.OID, nil
	}
	if assertion[0] >= '0' && assertion[0] <= '9' {
		return assertion, nil
	}
	return "", &MatchingRuleAssertionError{Unknown: true}
}
