package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var (
	entryBinaryV1Prefix = []byte{0, 'L', 'G', 'E', 1}
	entryBinaryPrefix   = []byte{0, 'L', 'G', 'E', 2}
)

type storedEntry struct {
	directory.Entry
	DNIdentity string `json:"dnIdentity,omitempty"`
	DNSource   string `json:"dnSource,omitempty"`
	DNBinding  []byte `json:"-"`
}

func encodeEntry(entry directory.Entry, identity, source string) ([]byte, error) {
	if identity == "" {
		source = ""
	}
	capacity := len(entryBinaryPrefix) + len(entry.DN) + sha256.Size + 32
	for _, attribute := range entry.Attributes {
		capacity += len(attribute.Description) + 16
		for _, value := range attribute.Values {
			capacity += len(value) + binary.MaxVarintLen64
		}
	}
	encoded := make([]byte, 0, capacity)
	encoded = append(encoded, entryBinaryPrefix...)
	encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
	var binding []byte
	if identity != "" {
		digest := entryDNBinding(identity, source)
		binding = digest[:]
	}
	encoded = appendEntryBinaryField(encoded, binding)
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
	if bytes.HasPrefix(value, entryBinaryPrefix) {
		stored, err := decodeBinaryStoredEntry(value[len(entryBinaryPrefix):])
		if err != nil {
			return storedEntry{}, fmt.Errorf("decode entry: %w", err)
		}
		return stored, nil
	}
	if bytes.HasPrefix(value, entryBinaryV1Prefix) {
		stored, err := decodeBinaryStoredEntryV1(value[len(entryBinaryV1Prefix):])
		if err != nil {
			return storedEntry{}, fmt.Errorf("decode entry: %w", err)
		}
		return stored, nil
	}
	{
		var stored storedEntry
		if err := json.Unmarshal(value, &stored); err != nil {
			return storedEntry{}, fmt.Errorf("decode entry: %w", err)
		}
		return stored, nil
	}
}

func decodeBinaryStoredEntry(value []byte) (storedEntry, error) {
	dn, remaining, err := consumeEntryBinaryField(value)
	if err != nil {
		return storedEntry{}, fmt.Errorf("DN: %w", err)
	}
	binding, remaining, err := consumeEntryBinaryField(remaining)
	if err != nil {
		return storedEntry{}, fmt.Errorf("DN binding: %w", err)
	}
	if len(binding) != 0 && len(binding) != sha256.Size {
		return storedEntry{}, fmt.Errorf("DN binding has invalid length %d", len(binding))
	}
	return decodeBinaryStoredEntryAttributes(dn, binding, remaining)
}

func decodeBinaryStoredEntryV1(value []byte) (storedEntry, error) {
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
	stored, err := decodeBinaryStoredEntryAttributes(dn, nil, remaining)
	if err != nil {
		return storedEntry{}, err
	}
	stored.DNIdentity = string(identity)
	stored.DNSource = string(source)
	return stored, nil
}

func decodeBinaryStoredEntryAttributes(
	dn,
	binding,
	value []byte,
) (storedEntry, error) {
	remaining := value
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
		DNBinding: bytes.Clone(binding),
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

func entryDNBinding(identity, source string) [sha256.Size]byte {
	hash := sha256.New()
	var length [8]byte
	for _, value := range []string{identity, source} {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
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
