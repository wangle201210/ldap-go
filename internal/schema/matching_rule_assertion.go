package schema

// MatchingRuleAssertionError preserves the distinction between malformed OID
// syntax and an unknown descriptor. Native Compare treats the latter as false,
// while filter evaluation must retain undefined (including under NOT).
type MatchingRuleAssertionError struct {
	Unknown bool
}

func (err *MatchingRuleAssertionError) Error() string {
	if err.Unknown {
		return "unrecognized matching rule identifier"
	}
	return "invalid matching rule assertion syntax"
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
