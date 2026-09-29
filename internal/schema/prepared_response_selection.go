package schema

import (
	"bytes"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	responseValueBlockSize = 4096
	responseValuePackMin   = 8
)

// SelectForResponse selects owned attributes for an immediate LDAP response.
// It has Select's selection and metadata semantics, but packs sufficiently large
// value lists into blocks of at most 4096 bytes. Packed values have cap == len
// and independent bytes, even when source values overlap. Larger values are
// cloned individually. Retaining a packed value can retain its whole block;
// use Select or deep-clone the result before caching or long-term retention.
func (selection *PreparedAttributeSelection) SelectForResponse(
	entry directory.Entry,
	typesOnly bool,
) directory.Entry {
	result := directory.Entry{DN: entry.DN}
	if selection == nil || selection.empty {
		return result
	}
	for _, attribute := range entry.Attributes {
		if !selection.SelectsAttribute(attribute.Description) {
			continue
		}
		value := directory.Attribute{Description: attribute.Description}
		if !typesOnly {
			value.Values = cloneResponseValues(attribute.Values)
		}
		result.Attributes = append(result.Attributes, value)
	}
	return result
}

func cloneResponseValues(values [][]byte) [][]byte {
	if len(values) < responseValuePackMin {
		return clonePreparedValues(values)
	}
	cloned := make([][]byte, len(values))
	for start := 0; start < len(values); {
		value := values[start]
		if len(value) == 0 || len(value) > responseValueBlockSize {
			cloned[start] = bytes.Clone(value)
			start++
			continue
		}

		// Size each block before allocating, including the final partial block.
		end, size := start, 0
		for end < len(values) && len(values[end]) <= responseValueBlockSize-size {
			size += len(values[end])
			end++
		}
		block := make([]byte, size)
		offset := 0
		for index := start; index < end; index++ {
			value := values[index]
			if len(value) == 0 {
				// Preserve nil versus empty without retaining a block for either.
				cloned[index] = bytes.Clone(value)
				continue
			}
			next := offset + len(value)
			cloned[index] = block[offset:next:next]
			copy(cloned[index], value)
			offset = next
		}
		start = end
	}
	return cloned
}
