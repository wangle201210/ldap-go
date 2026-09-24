package schema

import (
	"errors"
	"fmt"
)

// NormalizeEqualityAssertionCachedDN is NormalizeEqualityAssertion with opt-in
// DN normalization reuse. Like NormalizeDNCached, schema definitions (including
// externally shared Names slices) must change only through registry methods.
// It shares that cache's bounds and invalidation, validates assertion syntax on
// every call, and returns independently owned bytes. Other matching rules keep
// the uncached behavior.
func (registry *Registry) NormalizeEqualityAssertionCachedDN(
	attributeName string,
	value []byte,
) ([]byte, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	return registry.normalizeEqualityAssertionLocked(attributeName, value, true)
}

func (registry *Registry) normalizeEqualityAssertionLocked(
	attributeName string,
	value []byte,
	cacheDN bool,
) ([]byte, error) {
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return nil, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	if effective.Equality == "" {
		return nil, fmt.Errorf("attribute %q has no equality matching rule", attributeName)
	}

	assertionSyntax := effective.Syntax
	assertionLength := effective.SyntaxLength
	rule := canonicalMatchingRule(effective.Equality)
	switch rule {
	case "integerfirstcomponentmatch":
		assertionSyntax = SyntaxInteger
		assertionLength = 0
	case "objectidentifierfirstcomponentmatch":
		assertionSyntax = SyntaxOID
		assertionLength = 0
	}
	if err := registry.validateSyntax(assertionSyntax, assertionLength, value); err != nil {
		return nil, fmt.Errorf("attribute %q assertion: %w", attributeName, err)
	}
	if cacheDN && rule == "distinguishednamematch" {
		dn, err := registry.normalizeDNCachedLocked(string(value))
		if err != nil {
			return nil, errors.New("distinguishedNameMatch received invalid DN")
		}
		return []byte(dn.normalizedString()), nil
	}
	return registry.normalizeWithRuleLocked(effective.Equality, value)
}
