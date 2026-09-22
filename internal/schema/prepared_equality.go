package schema

import (
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// PreparedEqualityMatcher resolves a fixed assertion for repeated top-level
// equality matching within one immutable runtime, like PreparedSubstringMatcher.
// Its state is bounded by the schema and assertion, not the entries scanned.
// Match collapses undefined to false and must not be used to evaluate children
// of NOT (or other filters that need the three-valued result).
type PreparedEqualityMatcher struct {
	attributes map[string]struct{}
	options    map[string]struct{}
	classes    map[string]struct{}
	assertion  string
}

// PrepareEqualityMatcher currently supports only objectClass (2.5.4.0) with
// objectIdentifierMatch. An error means the caller must use the general filter
// path; it does not mean the filter cannot match. The registry must remain
// immutable for the matcher's lifetime.
func (registry *Registry) PrepareEqualityMatcher(
	description string,
	assertion []byte,
) (*PreparedEqualityMatcher, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(description))]
	if !ok {
		return nil, fmt.Errorf("undefined attribute type %q", description)
	}
	if attribute.OID != "2.5.4.0" || attributeHasOrderedValues(*attribute) {
		return nil, fmt.Errorf("attribute %q uses the general equality matcher", description)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	if canonicalMatchingRule(effective.Equality) != "objectidentifiermatch" {
		return nil, fmt.Errorf("unsupported prepared equality matching rule %q", effective.Equality)
	}

	_, options := splitAttributeDescription(description)
	matcher := &PreparedEqualityMatcher{
		attributes: make(map[string]struct{}),
		options:    options,
		assertion:  strings.ToLower(string(assertion)),
	}
	for key, candidate := range registry.attributes {
		if registry.attributeTypeSubtype(candidate, attribute, make(map[string]bool)) {
			matcher.attributes[key] = struct{}{}
		}
	}
	if ancestor, known := registry.objectClasses[schemaKey(string(assertion))]; known {
		matcher.classes = make(map[string]struct{})
		for key, candidate := range registry.objectClasses {
			if registry.isSubclass(candidate, ancestor, make(map[string]bool)) {
				matcher.classes[key] = struct{}{}
			}
		}
	}
	return matcher, nil
}

// Match returns the same boolean and error as a top-level FilterEquality's
// MatchWith(entry, registry). It reads entry values without cloning them.
func (matcher *PreparedEqualityMatcher) Match(entry directory.Entry) (bool, error) {
	if matcher == nil {
		return false, errors.New("prepared equality matcher is nil")
	}
	for _, attribute := range entry.Attributes {
		if _, selected := matcher.attributes[schemaKey(baseAttributeDescription(attribute.Description))]; !selected {
			continue
		}
		if len(matcher.options) != 0 {
			_, options := splitAttributeDescription(attribute.Description)
			if !attributeOptionsSubtype(options, matcher.options) {
				continue
			}
		}
		for _, value := range attribute.Values {
			// Only known-class lookup trims spaces. The raw fallback deliberately
			// uses strings.ToLower, including its handling of invalid UTF-8.
			lower := strings.ToLower(string(value))
			if _, descendant := matcher.classes[strings.TrimSpace(lower)]; descendant {
				return true, nil
			}
			if lower == matcher.assertion {
				return true, nil
			}
		}
	}
	// Absent attributes and undefined assertions both produce false, nil at
	// the root, so no absent-value assertion validation is needed here.
	return false, nil
}
