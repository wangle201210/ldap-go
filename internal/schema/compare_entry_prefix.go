package schema

import (
	"bytes"
	"errors"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	minDNPrefixValues = 32
	maxDNPrefixValues = 4096
	maxDNPrefixBytes  = 256 << 10
	maxDNPrefixFill   = 1
)

type dnPrefixValue struct {
	raw        string
	normalized string
}

// DNComparisonPrefix owns successful raw-to-normalized DN translations. It is
// immutable after return and may be shared by concurrent callers. Every use
// rechecks the current raw value; this is not an entry or comparison-result cache.
type DNComparisonPrefix struct {
	registry    *Registry
	generation  uint64
	description string
	values      []dnPrefixValue
	retained    int
}

// RetainedBytes conservatively charges this token's strings, descriptors and
// capacity. It is a per-token bound, not a global or in-flight memory budget.
func (prefix *DNComparisonPrefix) RetainedBytes() int {
	if prefix == nil {
		return 0
	}
	return prefix.retained
}

// CompareEntryAttributeWithDNPrefix opts into bounded normalization reuse with the same
// immutable-schema contract as CompareEntryAttributeCachedDN. Only a single
// exact, option-free DN attribute with at least 32 values qualifies. At most
// one visited successful value extends the prefix per call. Other values use
// the original comparison path, and matching/error order remains left-to-right.
// The caller owns retention of returned tokens; no global cache is installed.
func (registry *Registry) CompareEntryAttributeWithDNPrefix(
	entry directory.Entry,
	description string,
	assertion []byte,
	previous *DNComparisonPrefix,
) (present, matched bool, next *DNComparisonPrefix, err error) {
	registry.mu.RLock()
	values, eligible := registry.dnPrefixValuesLocked(entry, description)
	if !eligible {
		registry.mu.RUnlock()
		present, matched, err = registry.CompareEntryAttributeCachedDN(entry, description, assertion)
		return present, matched, nil, err
	}
	defer registry.mu.RUnlock()
	if previous != nil && previous.registry == registry &&
		previous.generation == registry.preparedNames.generation && previous.description == description {
		next = previous
	}
	original := next
	filled := 0
	var normalizedAssertion []byte
	var assertionReady, planReady bool
	var plan simpleDNComparison
	for index, value := range values {
		cached := next != nil && index < len(next.values) && next.values[index].raw == string(value)
		if cached {
			if !assertionReady {
				var err error
				normalizedAssertion, err = registry.normalizeCompareDNLocked(assertion, true)
				if err != nil {
					return true, false, next, errors.New("distinguishedNameMatch received invalid DN")
				}
				assertionReady = true
			}
			if next.values[index].normalized == string(normalizedAssertion) {
				return true, true, next, nil
			}
			continue
		}
		if assertionReady && !planReady {
			planReady = true
			plan = registry.prepareSimpleDNComparisonLocked(normalizedAssertion)
		}
		canFill := filled < maxDNPrefixFill && index < maxDNPrefixValues && len(value) <= maxCachedDNInput &&
			((next == nil && index == 0) || (next != nil && index <= len(next.values)))
		if !canFill {
			if matched, handled := plan.match(registry, value); handled {
				if matched {
					return true, true, next, nil
				}
				continue
			}
		}
		left, leftErr := registry.normalizeCompareDNLocked(value, true)
		var rightErr error
		if !assertionReady {
			normalizedAssertion, rightErr = registry.normalizeCompareDNLocked(assertion, true)
			assertionReady = true
		}
		if leftErr != nil || rightErr != nil {
			return true, false, next, errors.New("distinguishedNameMatch received invalid DN")
		}
		if canFill {
			if updated, stored := registry.extendDNPrefix(next, original, description, index, value, left); stored {
				next = updated
				filled++
			} else {
				filled = maxDNPrefixFill
			}
		}
		if bytes.Equal(left, normalizedAssertion) {
			return true, true, next, nil
		}
		if !planReady {
			planReady = true
			plan = registry.prepareSimpleDNComparisonLocked(normalizedAssertion)
		}
	}
	return true, false, next, nil
}

func (registry *Registry) dnPrefixValuesLocked(entry directory.Entry, description string) ([][]byte, bool) {
	if description == "" || len(description) > 128 || strings.Contains(description, ";") {
		return nil, false
	}
	requested := registry.attributes[schemaKey(description)]
	if requested == nil || attributeHasOrderedValues(*requested) ||
		(requested.Equality != "" && canonicalMatchingRule(requested.Equality) != "distinguishednamematch") {
		return nil, false
	}
	effective, err := registry.effectiveAttributeType(requested, make(map[string]bool))
	if err != nil || canonicalMatchingRule(effective.Equality) != "distinguishednamematch" {
		return nil, false
	}
	var selected [][]byte
	found := false
	for _, attribute := range entry.Attributes {
		if !registry.dnPrefixAttributeSelectedLocked(attribute.Description, description, requested) {
			continue
		}
		if found || attribute.Description != description {
			return nil, false
		}
		found, selected = true, attribute.Values
	}
	return selected, found && len(selected) >= minDNPrefixValues
}

// The request has no options and resolves to requested. Avoid allocating folded
// camel-case names while checking all attributes, including those after a match.
func (registry *Registry) dnPrefixAttributeSelectedLocked(candidate, description string, requested *AttributeType) bool {
	if candidate == description {
		return true
	}
	var folded [128]byte
	if len(candidate) == 0 || len(candidate) > len(folded) {
		return registry.attributeDescriptionSubtype(candidate, description)
	}
	for index := range len(candidate) {
		value := candidate[index]
		switch {
		case value >= 'A' && value <= 'Z':
			value += 'a' - 'A'
		case value >= 'a' && value <= 'z', value >= '0' && value <= '9', value == '.', value == '-':
		default:
			return registry.attributeDescriptionSubtype(candidate, description)
		}
		folded[index] = value
	}
	attribute := registry.attributes[string(folded[:len(candidate)])]
	return attribute != nil && registry.attributeTypeSubtype(attribute, requested, make(map[string]bool))
}

// The registry read lock covers normalization and publication. Copy-on-write
// preserves all previously returned tokens, including callers still using them.
func (registry *Registry) extendDNPrefix(prefix, original *DNComparisonPrefix, description string, index int, raw, normalized []byte) (*DNComparisonPrefix, bool) {
	if len(normalized) > 4096 {
		return prefix, false
	}
	capacity := min(maxDNPrefixValues, index+maxDNPrefixFill)
	payload := 2 * (len(raw) + len(normalized))
	if prefix != nil && index == len(prefix.values) {
		payload += prefix.retained - 128 - 2*len(prefix.description) - 64*cap(prefix.values)
	} else {
		for i := 0; i < index; i++ {
			payload += 2 * (len(prefix.values[i].raw) + len(prefix.values[i].normalized))
		}
	}
	if prefix != nil && prefix != original && index == len(prefix.values) && index < cap(prefix.values) {
		capacity = cap(prefix.values)
	}
	retained := 128 + 2*len(description) + 64*capacity + payload
	if retained > maxDNPrefixBytes {
		return prefix, false
	}
	if prefix == nil || prefix == original || index != len(prefix.values) || index == cap(prefix.values) {
		updated := &DNComparisonPrefix{
			registry: registry, generation: registry.preparedNames.generation,
			description: strings.Clone(description), values: make([]dnPrefixValue, index, capacity),
		}
		if prefix != nil {
			copy(updated.values, prefix.values[:index])
		}
		prefix = updated
	}
	prefix.values = append(prefix.values, dnPrefixValue{raw: string(raw), normalized: string(normalized)})
	prefix.retained = retained
	return prefix, true
}
