package storage

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
)

// Selective lookups are cheaper to decode once through the eager planner.
const minEncodedEqualityIndexCandidates = 128

const maxEqualityCandidateCursorSteps = 4

// Both slices borrow Bolt memory inside the read transaction. Callback entries
// own their decoded data and a string copy of the identity.
type encodedEqualityIndexCandidate struct {
	value    []byte
	identity []byte
}

// A failed check restarts through equalityIndexEntries, preserving its exact
// validation errors and their order, including errors before legacy references.
// Eligibility polls Done without consuming the eager planner's Err checkpoints.
func (tx *boltTx) prevalidateEqualityIndexCandidates(
	partition string,
	references []string,
) ([]encodedEqualityIndexCandidate, bool, error) {
	if tx.tx.Writable() || strings.IndexByte(partition, 0) >= 0 {
		return nil, false, nil
	}
	marker := tx.meta.Get(genericMetadataKey(schemaAwareDNMigrationMetadataKey(partition)))
	if len(marker) != 1 || int(marker[0]) != schemaAwareDNIdentityFormatVersion {
		return nil, false, nil
	}
	select {
	case <-tx.ctx.Done():
		return nil, false, nil
	default:
	}
	candidates := make([]encodedEqualityIndexCandidate, 0, len(references))
	for _, entryID := range references {
		select {
		case <-tx.ctx.Done():
			return nil, false, nil
		default:
		}
		if len(entryID) != equalityIndexEntryIDSize || tx.equalityIndexRefs == nil {
			return nil, false, nil
		}
		reference := tx.equalityIndexRefs.Get([]byte(entryID))
		if reference == nil {
			return nil, false, nil
		}
		referencePartition, position, err := readLengthPrefixed(reference, 0)
		if err != nil {
			return nil, false, nil
		}
		identity, position, err := readLengthPrefixed(reference, position)
		if err != nil || position != len(reference) || string(referencePartition) != partition ||
			!bytes.HasPrefix(identity, []byte(schemaAwareDNKeyPrefix)) {
			return nil, false, nil
		}
		candidates = append(candidates, encodedEqualityIndexCandidate{identity: identity})
	}
	// Sort pointers so physical reads are local while callbacks retain posting order.
	ordered := make([]*encodedEqualityIndexCandidate, len(candidates))
	for index := range candidates {
		ordered[index] = &candidates[index]
	}
	slices.SortFunc(ordered, func(left, right *encodedEqualityIndexCandidate) int {
		return bytes.Compare(left.identity, right.identity)
	})
	cursor := tx.entries.Cursor()
	key := append([]byte(partition), 0)
	prefixLength := len(key)
	var found, value []byte
	for _, candidate := range ordered {
		select {
		case <-tx.ctx.Done():
			return nil, false, nil
		default:
		}
		key = append(key[:prefixLength], candidate.identity...)
		for steps := 0; found != nil && bytes.Compare(found, key) < 0 && steps < maxEqualityCandidateCursorSteps; steps++ {
			found, value = cursor.Next()
		}
		if found == nil || bytes.Compare(found, key) < 0 {
			found, value = cursor.Seek(key)
		}
		if !bytes.Equal(found, key) || !validBinaryCandidateEntry(value) {
			return nil, false, nil
		}
		candidate.value = value
	}
	// Match equalityIndexEntries' checkpoints only after fallback is ruled out.
	if _, err := tx.schemaAwareDNIdentityReady(partition); err != nil {
		return nil, false, err
	}
	for range references {
		if err := tx.ctx.Err(); err != nil {
			return nil, false, err
		}
	}
	return candidates, true, nil
}

// Mirror the binary decoder's structural checks without allocating decoded
// attributes or values. JSON and unrecognized encodings use the eager planner.
// No identity validation is omitted: equalityIndexEntries also trusts the ready
// marker for physical references and only calls decodeStoredEntry on this path.
func validBinaryCandidateEntry(value []byte) bool {
	var flags []byte
	var err error
	v1 := false
	v3 := false
	switch {
	case bytes.HasPrefix(value, entryBinaryV3Prefix):
		v3 = true
		flags, value, err = consumeEntryBinaryField(value[len(entryBinaryV3Prefix):])
		if err != nil {
			return false
		}
	case bytes.HasPrefix(value, entryBinaryPrefix):
		value = value[len(entryBinaryPrefix):]
	case bytes.HasPrefix(value, entryBinaryV1Prefix):
		v1 = true
		value = value[len(entryBinaryV1Prefix):]
	default:
		return false
	}
	_, value, err = consumeEntryBinaryField(value)
	if err != nil {
		return false
	}
	binding, value, err := consumeEntryBinaryField(value)
	if err != nil {
		return false
	}
	if v1 {
		_, value, err = consumeEntryBinaryField(value)
		if err != nil {
			return false
		}
	} else if len(binding) != 0 && len(binding) != sha256.Size {
		return false
	}
	attributeCount, value, err := consumeEntryBinaryCount(value)
	if err != nil || attributeCount > len(value) {
		return false
	}
	for range attributeCount {
		_, value, err = consumeEntryBinaryField(value)
		if err != nil {
			return false
		}
		var valueCount int
		valueCount, value, err = consumeEntryBinaryCount(value)
		if err != nil || valueCount > len(value) {
			return false
		}
		for range valueCount {
			_, value, err = consumeEntryBinaryField(value)
			if err != nil {
				return false
			}
		}
	}
	if len(value) != 0 {
		return false
	}
	if v3 {
		if len(flags) != (attributeCount+7)/8 {
			return false
		}
		if remainder := attributeCount % 8; remainder != 0 && flags[len(flags)-1]>>uint(remainder) != 0 {
			return false
		}
	}
	return true
}
