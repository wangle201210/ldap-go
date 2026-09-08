package storage

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var entryBinaryV3Prefix = []byte{0, 'L', 'G', 'E', 3}

// V3 prefixes the V2 payload with a compact per-attribute normalization bitmap.
// V1/V2 and JSON remain readable; entries without hints still use V2.
func appendEntryNormalizationHeader(dst []byte, entry directory.Entry) []byte {
	hasHints := false
	for _, attr := range entry.Attributes {
		hasHints = hasHints || attr.RawNormalized
	}
	if !hasHints {
		return append(dst, entryBinaryPrefix...)
	}
	dst = append(dst, entryBinaryV3Prefix...)
	size := (len(entry.Attributes) + 7) / 8
	dst = binary.AppendUvarint(dst, uint64(size))
	start := len(dst)
	dst = append(dst, make([]byte, size)...)
	for i, attr := range entry.Attributes {
		if attr.RawNormalized {
			dst[start+i/8] |= 1 << uint(i%8)
		}
	}
	return dst
}

func decodeNormalizedStoredEntry(value []byte) (storedEntry, error) {
	owned := bytes.Clone(value[len(entryBinaryV3Prefix):])
	flags, remaining, err := consumeEntryBinaryField(owned)
	if err != nil {
		return storedEntry{}, err
	}
	stored, err := decodeBinaryStoredEntry(remaining)
	if err != nil {
		return storedEntry{}, err
	}
	if len(flags) != (len(stored.Attributes)+7)/8 {
		return storedEntry{}, errors.New("invalid normalization bitmap length")
	}
	for i, flag := range flags {
		for bit := range 8 {
			if flag&(1<<uint(bit)) == 0 {
				continue
			}
			index := i*8 + bit
			if index >= len(stored.Attributes) {
				return storedEntry{}, errors.New("invalid normalization bitmap bit")
			}
			stored.Attributes[index].RawNormalized = true
		}
	}
	return stored, nil
}
