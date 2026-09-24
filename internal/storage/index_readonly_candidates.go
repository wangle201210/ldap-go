package storage

import (
	"bytes"
	"crypto/sha256"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	maxReadOnlyCandidateAttributes     = 64
	maxReadOnlyCandidateValues         = 128  // Fixed descriptor arena for small rows.
	maxReadOnlyCandidateBorrowedValues = 4096 // Total across all attributes in one row.
	maxReadOnlyCandidateNames          = 128
	maxReadOnlyCandidateNameBytes      = 128
)

// One decoder is owned by one candidate iteration. Descriptors are overwritten
// between callbacks; payloads borrow Bolt. Recycled decoders retain no data.
type readOnlyCandidateDecoder struct {
	attributes     [maxReadOnlyCandidateAttributes]directory.Attribute
	values         [maxReadOnlyCandidateValues][]byte
	overflowValues [][]byte
	names          map[string]string
}

// Fixed capacity bounds idle storage independently of GC or workload history.
// Active iterators own their decoders exclusively, just as without recycling.
var idleReadOnlyCandidateDecoders = make(chan *readOnlyCandidateDecoder, 16)

func acquireReadOnlyCandidateDecoder() *readOnlyCandidateDecoder {
	select {
	case decoder := <-idleReadOnlyCandidateDecoders:
		return decoder
	default:
		return new(readOnlyCandidateDecoder)
	}
}

func releaseReadOnlyCandidateDecoder(decoder *readOnlyCandidateDecoder) {
	// Clear descriptors, not their payload bytes: those still belong to Bolt.
	clear(decoder.attributes[:])
	clear(decoder.values[:])
	clear(decoder.overflowValues[:cap(decoder.overflowValues)])
	clear(decoder.names)
	select {
	case idleReadOnlyCandidateDecoders <- decoder:
	default:
	}
}

func (decoder *readOnlyCandidateDecoder) decode(value []byte) (directory.Entry, error) {
	if entry, ok := decoder.borrow(value); ok {
		return entry, nil
	}
	// Keep the owned decoder authoritative for unsupported shapes and all errors,
	// including the different V1/V2/V3 error wrapping and validation order.
	stored, err := decodeStoredEntry(value)
	return stored.Entry, err
}

func (decoder *readOnlyCandidateDecoder) borrow(value []byte) (directory.Entry, bool) {
	dn, attributes, ok := decoder.borrowMetadata(value)
	if !ok {
		return directory.Entry{}, false
	}
	return directory.Entry{DN: string(dn), Attributes: attributes}, true
}

// borrowMetadata checks fields with the original parsers, including counts,
// binding length, trailing bytes, and normalization flags. DN bytes and values
// are borrowed; descriptions are owned. Callers must validate the DN against
// the physical identity before exposing a row. A failed gate uses the owned decoder.
func (decoder *readOnlyCandidateDecoder) borrowMetadata(value []byte) ([]byte, []directory.Attribute, bool) {
	var flags []byte
	var err error
	v1, v3 := false, false
	switch {
	case bytes.HasPrefix(value, entryBinaryV3Prefix):
		v3 = true
		flags, value, err = consumeEntryBinaryField(value[len(entryBinaryV3Prefix):])
		if err != nil {
			return nil, nil, false
		}
	case bytes.HasPrefix(value, entryBinaryPrefix):
		value = value[len(entryBinaryPrefix):]
	case bytes.HasPrefix(value, entryBinaryV1Prefix):
		v1 = true
		value = value[len(entryBinaryV1Prefix):]
	default:
		return nil, nil, false
	}
	dn, value, err := consumeEntryBinaryField(value)
	if err != nil {
		return nil, nil, false
	}
	binding, value, err := consumeEntryBinaryField(value)
	if err != nil {
		return nil, nil, false
	}
	if v1 {
		// V1 identity/source metadata does not replace the physical identity
		// supplied by the iterator.
		_, value, err = consumeEntryBinaryField(value)
		if err != nil {
			return nil, nil, false
		}
	} else if len(binding) != 0 && len(binding) != sha256.Size {
		return nil, nil, false
	}
	attributeCount, value, err := consumeEntryBinaryCount(value)
	if err != nil || attributeCount > len(value) || attributeCount > len(decoder.attributes) {
		return nil, nil, false
	}
	usedValues := 0
	values := decoder.values[:]
	for i := range attributeCount {
		description, next, err := consumeEntryBinaryField(value)
		if err != nil {
			return nil, nil, false
		}
		valueCount, next, err := consumeEntryBinaryCount(next)
		if err != nil || valueCount > len(next) || valueCount > maxReadOnlyCandidateBorrowedValues-usedValues {
			return nil, nil, false
		}
		// Stable row layouts can reuse the previous owned name at this slot.
		// Exact byte comparison keeps reordered and mixed-case rows on fallback.
		name := decoder.attributes[i].Description
		if name == "" || len(description) == 0 || name[0] != description[0] || name != string(description) {
			name = decoder.internName(description)
		}
		attribute := directory.Attribute{Description: name}
		if valueCount > 0 {
			end := usedValues + valueCount
			if end > len(values) {
				if end > len(decoder.overflowValues) {
					size := len(values)
					for size < end {
						size = min(maxReadOnlyCandidateBorrowedValues, 2*size)
					}
					decoder.overflowValues = make([][]byte, size)
				}
				copy(decoder.overflowValues, values[:usedValues])
				values = decoder.overflowValues
				// Growth moves descriptors only. Rebind earlier attributes in this
				// row so all value slices use the current arena, including after
				// multiple growths. Empty attributes keep nil Values.
				position := 0
				for j := range i {
					count := len(decoder.attributes[j].Values)
					if count > 0 {
						next := position + count
						decoder.attributes[j].Values = values[position:next:next]
						position = next
					}
				}
			}
			attribute.Values = values[usedValues:end:end]
			usedValues = end
		}
		for j := range valueCount {
			attribute.Values[j], next, err = consumeEntryBinaryField(next)
			if err != nil {
				return nil, nil, false
			}
		}
		decoder.attributes[i] = attribute
		value = next
	}
	if len(value) != 0 {
		return nil, nil, false
	}
	if v3 {
		if len(flags) != (attributeCount+7)/8 {
			return nil, nil, false
		}
		if remainder := attributeCount % 8; remainder != 0 && flags[len(flags)-1]>>uint(remainder) != 0 {
			return nil, nil, false
		}
		for i := range attributeCount {
			decoder.attributes[i].RawNormalized = flags[i/8]&(1<<uint(i%8)) != 0
		}
	}
	var attributes []directory.Attribute
	if attributeCount > 0 {
		attributes = decoder.attributes[:attributeCount:attributeCount]
	}
	return dn, attributes, true
}

func (decoder *readOnlyCandidateDecoder) internName(name []byte) string {
	if len(name) > maxReadOnlyCandidateNameBytes {
		return string(name)
	}
	if interned, ok := decoder.names[string(name)]; ok {
		return interned
	}
	owned := string(name)
	if len(decoder.names) < maxReadOnlyCandidateNames {
		if decoder.names == nil {
			decoder.names = make(map[string]string)
		}
		decoder.names[owned] = owned
	}
	return owned
}
