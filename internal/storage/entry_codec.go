package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var entryBinaryPrefix = []byte{0, 'L', 'G', 'E', 1}

type storedEntry struct {
	directory.Entry
	DNIdentity string `json:"dnIdentity,omitempty"`
	DNSource   string `json:"dnSource,omitempty"`
}

func encodeEntry(entry directory.Entry, identity, source string) ([]byte, error) {
	if identity == "" {
		source = ""
	}
	capacity := len(entryBinaryPrefix) + len(entry.DN) + len(identity) + len(source) + 32
	for _, attribute := range entry.Attributes {
		capacity += len(attribute.Description) + 16
		for _, value := range attribute.Values {
			capacity += len(value) + binary.MaxVarintLen64
		}
	}
	encoded := make([]byte, 0, capacity)
	encoded = append(encoded, entryBinaryPrefix...)
	encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
	encoded = appendEntryBinaryField(encoded, []byte(identity))
	encoded = appendEntryBinaryField(encoded, []byte(source))
	encoded = binary.AppendUvarint(encoded, uint64(len(entry.Attributes)))
	for _, attribute := range entry.Attributes {
		encoded = appendEntryBinaryField(encoded, []byte(attribute.Description))
		encoded = binary.AppendUvarint(encoded, uint64(len(attribute.Values)))
		for _, value := range attribute.Values {
			encoded = appendEntryBinaryField(encoded, value)
		}
	}
	return encoded, nil
}

func appendEntryBinaryField(destination, value []byte) []byte {
	destination = binary.AppendUvarint(destination, uint64(len(value)))
	return append(destination, value...)
}

func decodeStoredEntry(value []byte) (storedEntry, error) {
	if !bytes.HasPrefix(value, entryBinaryPrefix) {
		var stored storedEntry
		if err := json.Unmarshal(value, &stored); err != nil {
			return storedEntry{}, fmt.Errorf("decode entry: %w", err)
		}
		return stored, nil
	}
	stored, err := decodeBinaryStoredEntry(value[len(entryBinaryPrefix):])
	if err != nil {
		return storedEntry{}, fmt.Errorf("decode entry: %w", err)
	}
	return stored, nil
}

func decodeBinaryStoredEntry(value []byte) (storedEntry, error) {
	dn, remaining, err := consumeEntryBinaryField(value)
	if err != nil {
		return storedEntry{}, fmt.Errorf("DN: %w", err)
	}
	identity, remaining, err := consumeEntryBinaryField(remaining)
	if err != nil {
		return storedEntry{}, fmt.Errorf("DN identity: %w", err)
	}
	source, remaining, err := consumeEntryBinaryField(remaining)
	if err != nil {
		return storedEntry{}, fmt.Errorf("DN source: %w", err)
	}
	attributeCount, remaining, err := consumeEntryBinaryCount(remaining)
	if err != nil {
		return storedEntry{}, fmt.Errorf("attribute count: %w", err)
	}
	if attributeCount > len(remaining) {
		return storedEntry{}, errors.New("attribute count exceeds encoded entry size")
	}
	stored := storedEntry{
		Entry: directory.Entry{
			DN: string(dn),
		},
		DNIdentity: string(identity),
		DNSource:   string(source),
	}
	if attributeCount > 0 {
		stored.Attributes = make([]directory.Attribute, 0, attributeCount)
	}
	for attributeIndex := 0; attributeIndex < attributeCount; attributeIndex++ {
		description, next, fieldErr := consumeEntryBinaryField(remaining)
		if fieldErr != nil {
			return storedEntry{}, fmt.Errorf("attribute %d description: %w", attributeIndex, fieldErr)
		}
		valueCount, next, fieldErr := consumeEntryBinaryCount(next)
		if fieldErr != nil {
			return storedEntry{}, fmt.Errorf("attribute %d value count: %w", attributeIndex, fieldErr)
		}
		if valueCount > len(next) {
			return storedEntry{}, fmt.Errorf("attribute %d value count exceeds encoded entry size", attributeIndex)
		}
		attribute := directory.Attribute{
			Description: string(description),
		}
		if valueCount > 0 {
			attribute.Values = make([][]byte, 0, valueCount)
		}
		for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
			encodedValue, afterValue, valueErr := consumeEntryBinaryField(next)
			if valueErr != nil {
				return storedEntry{}, fmt.Errorf(
					"attribute %d value %d: %w",
					attributeIndex,
					valueIndex,
					valueErr,
				)
			}
			attribute.Values = append(attribute.Values, bytes.Clone(encodedValue))
			next = afterValue
		}
		stored.Attributes = append(stored.Attributes, attribute)
		remaining = next
	}
	if len(remaining) != 0 {
		return storedEntry{}, fmt.Errorf("%d trailing bytes", len(remaining))
	}
	return stored, nil
}

func consumeEntryBinaryField(value []byte) ([]byte, []byte, error) {
	length, count := binary.Uvarint(value)
	if count <= 0 {
		return nil, nil, errors.New("invalid length")
	}
	value = value[count:]
	if length > uint64(len(value)) {
		return nil, nil, errors.New("truncated value")
	}
	return value[:int(length)], value[int(length):], nil
}

func consumeEntryBinaryCount(value []byte) (int, []byte, error) {
	count, width := binary.Uvarint(value)
	if width <= 0 {
		return 0, nil, errors.New("invalid count")
	}
	if count > uint64(math.MaxInt) {
		return 0, nil, errors.New("count overflows int")
	}
	return int(count), value[width:], nil
}
