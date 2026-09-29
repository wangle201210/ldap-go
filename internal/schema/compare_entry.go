package schema

import (
	"bytes"
	"errors"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// CompareEntryAttribute selects and compares values under one schema snapshot,
// without copying the entry's read-only values. Presence includes attributes
// with no values. The first matching value or comparison error ends the scan.
func (registry *Registry) CompareEntryAttribute(
	entry directory.Entry,
	description string,
	assertion []byte,
) (present, matched bool, err error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	var ruleReady, dnRule, assertionReady bool
	var normalizedAssertion []byte
	for _, attribute := range entry.Attributes {
		if !registry.attributeDescriptionSubtype(attribute.Description, description) {
			continue
		}
		present = true
		for _, value := range attribute.Values {
			if !ruleReady {
				ruleReady = true
				requested := registry.attributes[schemaKey(baseAttributeDescription(description))]
				if requested != nil && !attributeHasOrderedValues(*requested) &&
					(requested.Equality == "" || canonicalMatchingRule(requested.Equality) == "distinguishednamematch") {
					if effective, err := registry.effectiveAttributeType(requested, make(map[string]bool)); err == nil {
						dnRule = canonicalMatchingRule(effective.Equality) == "distinguishednamematch"
					}
				}
			}
			var comparison int
			var err error
			if dnRule {
				// Keep left-to-right comparison order while normalizing the fixed
				// assertion only once within this schema snapshot.
				left, leftErr := registry.normalizeWithRuleLocked("distinguishedNameMatch", value)
				var rightErr error
				if !assertionReady {
					normalizedAssertion, rightErr = registry.normalizeWithRuleLocked("distinguishedNameMatch", assertion)
					assertionReady = true
				}
				if leftErr != nil || rightErr != nil {
					return true, false, errors.New("distinguishedNameMatch received invalid DN")
				}
				comparison = bytes.Compare(left, normalizedAssertion)
			} else {
				comparison, err = registry.compareLocked(description, "", value, assertion)
			}
			if err != nil {
				return true, false, err
			}
			if comparison == 0 {
				return true, true, nil
			}
		}
	}
	return present, false, nil
}
