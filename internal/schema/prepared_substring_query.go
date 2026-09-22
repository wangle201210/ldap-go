package schema

import (
	"math/bits"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// PreparedSubstringQueryPlan separates classification from substring evaluation
// so callers can handle special or invisible entries before matching their values.
// It is immutable and can be shared by concurrent readers; it retains no entries.
type PreparedSubstringQueryPlan struct {
	substring *PreparedSubstringMatcher
	classes   *PreparedObjectClassMatcher
	fused     bool
}

// WithObjectClasses combines two immutable matchers without changing either.
// Different registries or attribute generations retain the separate match paths.
func (matcher *PreparedSubstringMatcher) WithObjectClasses(classes *PreparedObjectClassMatcher) *PreparedSubstringQueryPlan {
	return &PreparedSubstringQueryPlan{
		substring: matcher,
		classes:   classes,
		fused: matcher != nil && classes != nil && matcher.sourceRegistry != nil &&
			matcher.sourceRegistry == classes.sourceRegistry &&
			matcher.nameGeneration == classes.nameGeneration,
	}
}

// Classify returns the same flags as the object class matcher and an opaque
// selection for Match. It never evaluates substring values. A nil class matcher
// produces zero flags, as PreparedObjectClassMatcher.Match does.
func (plan *PreparedSubstringQueryPlan) Classify(entry directory.Entry) (flags, selected uint64) {
	if !plan.fused || len(entry.Attributes) > 64 {
		return plan.classes.Match(entry), 0
	}
	for index, attribute := range entry.Attributes {
		roles := plan.substring.attributes.roles(attribute.Description)
		if roles&preparedAttributeTarget != 0 {
			selected |= uint64(1) << index
		}
		if roles&preparedAttributeObjectClass != 0 {
			flags |= plan.classes.matchValues(attribute.Values)
		}
	}
	return flags, selected
}

// Match evaluates a top-level substring filter using the selection returned by
// this plan's Classify for the same unchanged entry. Callers may omit Match after
// classification. Borrowed entries must stay within their original lifetime.
func (plan *PreparedSubstringQueryPlan) Match(entry directory.Entry, selected uint64) (bool, error) {
	if !plan.fused || len(entry.Attributes) > 64 {
		return plan.substring.Match(entry)
	}
	for selected != 0 {
		index := bits.TrailingZeros64(selected)
		if plan.substring.matchValues(entry.Attributes[index].Values) {
			return true, nil
		}
		selected &= selected - 1
	}
	return false, nil
}
