package schema

import (
	"fmt"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// ValidateFilterAssertion checks matching semantics even when the entry has no
// candidate values. In particular, NOT must not turn invalid assertions into
// matches merely because an attribute is absent.
func (registry *Registry) ValidateFilterAssertion(filter directory.Filter) error {
	if err := registry.validateFilterAttributeDescription(filter.Attribute); err != nil {
		return err
	}
	switch filter.Kind {
	case directory.FilterPresent:
		return nil
	case directory.FilterEquality:
		attribute, _, _ := registry.EffectiveAttributeType(filter.Attribute)
		if canonicalMatchingRule(attribute.Equality) == "objectidentifierfirstcomponentmatch" {
			_, err := registry.Compare(filter.Attribute, "", []byte("( 0 )"), filter.Assertion)
			return err
		}
		_, err := registry.NormalizeEqualityAssertion(filter.Attribute, filter.Assertion)
		return err
	case directory.FilterGreaterOrEqual, directory.FilterLessOrEqual:
		_, err := registry.CompareOrdering(filter.Attribute, "", filter.Assertion, filter.Assertion)
		return err
	case directory.FilterSubstrings:
		_, err := registry.MatchSubstring(filter.Attribute, nil, filter.Substring)
		return err
	case directory.FilterApprox:
		_, err := registry.MatchApproximate(filter.Attribute, filter.Assertion, filter.Assertion)
		return err
	case directory.FilterExtensible:
		left := filter.Assertion
		rule := filter.MatchingRule
		if rule == "" {
			attribute, _, _ := registry.EffectiveAttributeType(filter.Attribute)
			rule = attribute.Equality
		}
		if canonicalMatchingRule(rule) == "objectidentifierfirstcomponentmatch" || canonicalMatchingRule(rule) == "integerfirstcomponentmatch" {
			left = []byte("( 0 )")
		}
		_, err := registry.Compare(filter.Attribute, filter.MatchingRule, left, filter.Assertion)
		return err
	}
	return nil
}

func (registry *Registry) validateFilterAttributeDescription(description string) error {
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
	// Filters identify attributes; unlike writes they do not transfer values
	// and need not request the binary transfer option.
	return registry.validateAttributeDescriptionOptions(description, effective, false)
}
