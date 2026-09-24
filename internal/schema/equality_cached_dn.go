package schema

import "github.com/wangle201210/ldap-go/internal/directory"

// EvaluateEqualityCachedDN is EvaluateEquality with opt-in DN normalization
// reuse. Like NormalizeDNCached, it requires schema definitions (including
// externally shared Names slices) to change only through registry methods.
// Cache bounds and invalidation are shared with NormalizeDNCached. Other rules
// and ordered values retain the general evaluator's semantics.
func (registry *Registry) EvaluateEqualityCachedDN(
	entry directory.Entry,
	description string,
	assertion []byte,
) (directory.FilterResult, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, known := registry.attributes[schemaKey(baseAttributeDescription(description))]
	if known && !attributeHasOrderedValues(*attribute) {
		effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
		if err == nil && canonicalMatchingRule(effective.Equality) == "distinguishednamematch" {
			return registry.evaluateDNEqualityCachedLocked(entry, description, assertion)
		}
	}
	return registry.evaluateEqualityLocked(entry, description, assertion)
}

func (registry *Registry) evaluateDNEqualityCachedLocked(
	entry directory.Entry,
	description string,
	assertion []byte,
) (result directory.FilterResult, hasValues bool) {
	result = directory.FilterFalseResult
	var normalizedAssertion string
	for _, attribute := range entry.Attributes {
		if !registry.attributeDescriptionSubtype(attribute.Description, description) {
			continue
		}
		for _, value := range attribute.Values {
			if !hasValues {
				// An absent attribute must keep the original false/hasValues=false
				// pair; Filter performs absent-assertion validation separately.
				dn, err := registry.normalizeDNCachedLocked(string(assertion))
				if err != nil {
					return directory.FilterUndefinedResult, true
				}
				normalizedAssertion = dn.normalizedString()
				hasValues = true
			}
			dn, err := registry.normalizeDNCachedLocked(string(value))
			if err != nil {
				result = directory.FilterUndefinedResult
				continue
			}
			if dn.normalizedString() == normalizedAssertion {
				return directory.FilterTrueResult, true
			}
		}
	}
	return result, hasValues
}
