package schema

import (
	"bytes"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type simpleDNComparisonPart struct {
	name      []byte
	value     []byte
	attribute *AttributeType
	fold      bool
}

type simpleDNComparison struct {
	parts       [8]simpleDNComparisonPart
	count       int
	tail        [512]byte
	tailLength  int
	tailReady   bool
	tailMatches bool
}

// The caller holds Registry.mu. Parts borrow the already-owned normalized
// assertion and are used only within the current comparison, never cached.
func (registry *Registry) prepareSimpleDNComparisonLocked(assertion []byte) simpleDNComparison {
	var plan simpleDNComparison
	depth, simple := directory.SimpleDNDepthBytes(assertion)
	if !simple || depth > len(plan.parts) {
		return plan
	}
	for i := range depth {
		rdn, rest, _ := bytes.Cut(assertion, []byte(","))
		name, value, _ := bytes.Cut(rdn, []byte("="))
		attribute := registry.attributes[schemaKey(string(name))]
		if attribute == nil {
			return simpleDNComparison{}
		}
		effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
		if err != nil {
			return simpleDNComparison{}
		}
		var fold bool
		switch canonicalMatchingRule(effective.Equality) {
		case "caseignorematch", "caseignoreia5match":
			fold = true
		case "caseexactmatch", "caseexactia5match":
		default:
			return simpleDNComparison{}
		}
		plan.parts[i] = simpleDNComparisonPart{name: name, value: value, attribute: attribute, fold: fold}
		assertion = rest
	}
	plan.count = depth
	return plan
}

func (plan *simpleDNComparison) match(registry *Registry, value []byte) (matched, handled bool) {
	if plan.count == 0 {
		return false, false
	}
	head, tail, hasTail := bytes.Cut(value, []byte(","))
	if plan.tailReady && hasTail && bytes.Equal(tail, plan.tail[:plan.tailLength]) {
		name, actual, simple := directory.ParseSimpleRDNBytes(head)
		if !simple {
			return false, false
		}
		leafMatches, eligible := plan.parts[0].match(registry, name, actual)
		return leafMatches && plan.tailMatches, eligible
	}
	depth, simple := directory.SimpleDNDepthBytes(value)
	if !simple || depth != plan.count {
		return false, false
	}
	matched = true
	tailMatches := true
	for i := range depth {
		rdn, rest, _ := bytes.Cut(value, []byte(","))
		name, actual, _ := bytes.Cut(rdn, []byte("="))
		partMatches, eligible := plan.parts[i].match(registry, name, actual)
		if !eligible {
			return false, false
		}
		if !partMatches {
			matched = false
			if i > 0 {
				tailMatches = false
			}
		}
		value = rest
	}
	// Publish only a fully validated tail. Own its bytes so later caller changes
	// cannot turn a previously valid suffix into a trusted invalid one.
	if hasTail && len(tail) <= len(plan.tail) {
		copy(plan.tail[:], tail)
		plan.tailLength, plan.tailReady, plan.tailMatches = len(tail), true, tailMatches
	}
	return matched, true
}

func (part *simpleDNComparisonPart) match(registry *Registry, name, value []byte) (matched, eligible bool) {
	if !bytes.Equal(name, part.name) {
		attribute := registry.attributes[string(name)]
		if attribute == nil {
			attribute = registry.attributes[schemaKey(string(name))]
		}
		if attribute != part.attribute {
			return false, false
		}
	}
	return equalSimpleDNValue(value, part.value, part.fold), true
}

func equalSimpleDNValue(actual, expected []byte, fold bool) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, c := range actual {
		if fold && c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != expected[i] {
			return false
		}
	}
	return true
}
