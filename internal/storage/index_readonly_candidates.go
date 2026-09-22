package storage

import (
	"bytes"
	"crypto/sha256"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	maxReadOnlyCandidateAttributes = 64
	maxReadOnlyCandidateValues     = 128 // Total across all attributes in one row.
	maxReadOnlyCandidateNames      = 128
	maxReadOnlyCandidateNameBytes  = 128
)

// One decoder belongs to one candidate iteration, never a pool or transaction
// cache. Descriptors are overwritten between callbacks; payloads borrow Bolt.
type readOnlyCandidateDecoder struct {
	attributes [maxReadOnlyCandidateAttributes]directory.Attribute
	values     [maxReadOnlyCandidateValues][]byte
	names      map[string]string
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

// borrow is called only after the planner has prevalidated every candidate.
// It still checks fields with the original parsers, including counts, binding,
// trailing bytes, and normalization flags; a failed gate uses the owned decoder.
func (decoder *readOnlyCandidateDecoder) borrow(value []byte) (directory.Entry, bool) {
	var flags []byte
	var err error
	v1, v3 := false, false
	switch {
	case bytes.HasPrefix(value, entryBinaryV3Prefix):
		v3 = true
		flags, value, err = consumeEntryBinaryField(value[len(entryBinaryV3Prefix):])
		if err != nil {
			return directory.Entry{}, false
		}
	case bytes.HasPrefix(value, entryBinaryPrefix):
		value = value[len(entryBinaryPrefix):]
	case bytes.HasPrefix(value, entryBinaryV1Prefix):
		v1 = true
		value = value[len(entryBinaryV1Prefix):]
	default:
		return directory.Entry{}, false
	}
	dn, value, err := consumeEntryBinaryField(value)
	if err != nil {
		return directory.Entry{}, false
	}
	binding, value, err := consumeEntryBinaryField(value)
	if err != nil {
		return directory.Entry{}, false
	}
	if v1 {
		// V1 identity/source metadata is not part of the callback entry. The API
		// attaches an owned copy of the prevalidated physical reference identity.
		_, value, err = consumeEntryBinaryField(value)
		if err != nil {
			return directory.Entry{}, false
		}
	} else if len(binding) != 0 && len(binding) != sha256.Size {
		return directory.Entry{}, false
	}
	attributeCount, value, err := consumeEntryBinaryCount(value)
	if err != nil || attributeCount > len(value) || attributeCount > len(decoder.attributes) {
		return directory.Entry{}, false
	}
	usedValues := 0
	for i := range attributeCount {
		description, next, err := consumeEntryBinaryField(value)
		if err != nil {
			return directory.Entry{}, false
		}
		valueCount, next, err := consumeEntryBinaryCount(next)
		if err != nil || valueCount > len(next) || valueCount > len(decoder.values)-usedValues {
			return directory.Entry{}, false
		}
		attribute := directory.Attribute{Description: decoder.internName(description)}
		if valueCount > 0 {
			end := usedValues + valueCount
			attribute.Values = decoder.values[usedValues:end:end]
			usedValues = end
		}
		for j := range valueCount {
			attribute.Values[j], next, err = consumeEntryBinaryField(next)
			if err != nil {
				return directory.Entry{}, false
			}
		}
		decoder.attributes[i] = attribute
		value = next
	}
	if len(value) != 0 {
		return directory.Entry{}, false
	}
	if v3 {
		if len(flags) != (attributeCount+7)/8 {
			return directory.Entry{}, false
		}
		if remainder := attributeCount % 8; remainder != 0 && flags[len(flags)-1]>>uint(remainder) != 0 {
			return directory.Entry{}, false
		}
		for i := range attributeCount {
			decoder.attributes[i].RawNormalized = flags[i/8]&(1<<uint(i%8)) != 0
		}
	}
	entry := directory.Entry{DN: string(dn)}
	if attributeCount > 0 {
		entry.Attributes = decoder.attributes[:attributeCount:attributeCount]
	}
	return entry, true
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
