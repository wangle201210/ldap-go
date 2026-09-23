package schema

import (
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	maxPreparedSubstringCursorDescriptionBytes = 128
	maxPreparedSubstringCursorCopies           = 4 * 64
)

// PreparedSubstringQueryCursor caches attribute roles for one sequential scan.
// It is not safe for concurrent use; independent cursors may share a plan.
// Only owned descriptions of at most 128 bytes at 64 positions are retained,
// never entry attributes, values, or match results. At most 256 descriptions are
// copied over the cursor's lifetime, bounding allocation churn for mixed layouts.
type PreparedSubstringQueryCursor struct {
	plan              *PreparedSubstringQueryPlan
	slots             [64]preparedSubstringCursorSlot
	descriptionCopies int
}

type preparedSubstringCursorSlot struct {
	description string
	roles       preparedAttributeRole
	valid       bool
}

// NewCursor creates independent scan state without changing the immutable plan.
// Classify and Match retain the plan's semantics, including for nil matchers.
func (plan *PreparedSubstringQueryPlan) NewCursor() *PreparedSubstringQueryCursor {
	return &PreparedSubstringQueryCursor{plan: plan}
}

// Classify returns the plan's flags and selection without evaluating substring
// values. Attribute roles may be reused, but class values are read on every call.
func (cursor *PreparedSubstringQueryCursor) Classify(entry directory.Entry) (flags, selected uint64) {
	plan := cursor.plan
	if !plan.fused || len(entry.Attributes) > len(cursor.slots) {
		return plan.Classify(entry)
	}
	for index, attribute := range entry.Attributes {
		slot := &cursor.slots[index]
		roles := slot.roles
		if !slot.valid || slot.description != attribute.Description {
			roles = plan.substring.attributes.roles(attribute.Description)
			if len(attribute.Description) > maxPreparedSubstringCursorDescriptionBytes {
				*slot = preparedSubstringCursorSlot{}
			} else if cursor.descriptionCopies < maxPreparedSubstringCursorCopies {
				*slot = preparedSubstringCursorSlot{
					description: strings.Clone(attribute.Description),
					roles:       roles,
					valid:       true,
				}
				cursor.descriptionCopies++
			}
		}
		if roles&preparedAttributeTarget != 0 {
			selected |= uint64(1) << index
		}
		if roles&preparedAttributeObjectClass != 0 {
			flags |= plan.classes.matchValues(attribute.Values)
		}
	}
	return flags, selected
}

// Match evaluates values using the selection from Classify for the same unchanged
// entry. It retains nothing; borrowed entries keep their original lifetime limits.
func (cursor *PreparedSubstringQueryCursor) Match(entry directory.Entry, selected uint64) (bool, error) {
	return cursor.plan.Match(entry, selected)
}
