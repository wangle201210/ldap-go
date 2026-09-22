package storage

import (
	"bytes"
	"errors"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// ForEachBoundedReadOnlyFilterCandidate visits at most maxCandidates raw equality
// postings from a current index in a read-only Bolt snapshot. Its callback has
// the same READ-ONLY ownership contract as ForEachReadOnlyFilterCandidate.
//
// A nonpositive limit, unsupported reader/filter, missing or incompatible index,
// or an additional posting returns (false, 0, nil) without decoding any entries
// or invoking fn. The caller must then use its general search path. The posting
// scan reads at most maxCandidates+1 matching keys, in the same snapshot used
// for validation and callbacks. No uniqueness assumption or deduplication is
// applied before checking the bound.
//
// Once bounded, all references and entries are validated by the original owned
// planner before the first callback. Index/context errors are returned, callback
// order is unchanged, and counts exclude a callback that returns an error.
func ForEachBoundedReadOnlyFilterCandidate(
	reader Reader,
	filter directory.Filter,
	maxCandidates int,
	fn func(directory.Entry) error,
) (planned bool, candidates int, err error) {
	if maxCandidates <= 0 || filter.Kind != directory.FilterEquality {
		return false, 0, nil
	}
	scoped, ok := reader.(schemaAwarePartitionReader)
	if !ok {
		return false, 0, nil
	}
	tx, ok := maintenanceReader(scoped.Reader).(*boltTx)
	if !ok || tx.tx.Writable() {
		return false, 0, nil
	}
	schema, ok := scoped.normalizer.(EqualityIndexSchema)
	if !ok {
		return false, 0, nil
	}
	current, err := scoped.currentEqualityIndex(tx, schema)
	if err != nil || !current {
		return false, 0, err
	}
	attribute, equality, _, err := schema.ResolveEqualityIndexAttribute(filter.Attribute)
	if err != nil || !equality {
		return false, 0, err
	}
	normalized, err := schema.NormalizeEqualityIndexAssertion(filter.Attribute, filter.Assertion)
	if err != nil {
		return false, 0, err
	}
	references, bounded, err := tx.boundedEqualityIndexPostings(scoped.partition, attribute, normalized, maxCandidates)
	if err != nil {
		return true, 0, err
	}
	if !bounded {
		return false, 0, nil
	}
	// The limited cursor scan already returns the same sorted reference order.
	entries, err := tx.equalityIndexEntries(scoped.partition, references, schema)
	if err != nil {
		return true, 0, err
	}
	for _, entry := range entries {
		if err := fn(entry); err != nil {
			return true, candidates, err
		}
		candidates++
	}
	return true, candidates, nil
}

func (tx *boltTx) boundedEqualityIndexPostings(
	partition, attribute string,
	value []byte,
	maxCandidates int,
) ([]string, bool, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, false, err
	}
	if tx.equalityIndexes == nil {
		return nil, true, nil
	}
	prefix := equalityIndexPostingPrefix(partition, attribute, equalityIndexValue, value)
	var references []string
	cursor := tx.equalityIndexes.Cursor()
	for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return nil, false, err
		}
		if len(key) == len(prefix) {
			return nil, false, errors.New("equality index posting has no entry key")
		}
		if len(references) == maxCandidates {
			return nil, false, nil
		}
		references = append(references, string(key[len(prefix):]))
	}
	return references, true, nil
}
