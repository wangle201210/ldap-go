package directory

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// DNHierarchyPath encodes a canonical schema-aware identity in root-to-leaf
// order. An ancestor path is a complete byte prefix of every descendant path.
// The format deliberately has no total RDN count; each RDN is length-framed.
func DNHierarchyPath(identity string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(identity, schemaAwareDNKeyPrefix)
	if !ok {
		return nil, errors.New("hierarchy requires a schema-aware DN identity")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return nil, errors.New("hierarchy DN identity is not canonically encoded")
	}
	rdns, err := decodeDNIdentityParts(payload)
	if err != nil {
		return nil, fmt.Errorf("hierarchy DN RDNs: %w", err)
	}
	if !bytes.Equal(payload, encodeDNIdentityParts(rdns...)) {
		return nil, errors.New("hierarchy DN identity has noncanonical lengths")
	}
	for _, rdn := range rdns {
		avas, err := decodeDNIdentityParts(rdn)
		if err != nil || len(avas) == 0 || !bytes.Equal(rdn, encodeDNIdentityParts(avas...)) {
			return nil, errors.New("hierarchy DN identity has an invalid RDN")
		}
		for i, ava := range avas {
			parts, err := decodeDNIdentityParts(ava)
			if err != nil || len(parts) != 2 || len(parts[0]) == 0 ||
				!bytes.Equal(ava, encodeDNIdentityParts(parts...)) {
				return nil, errors.New("hierarchy DN identity has an invalid AVA")
			}
			if i > 0 && bytes.Compare(avas[i-1], ava) >= 0 {
				return nil, errors.New("hierarchy DN identity AVAs are not canonical")
			}
		}
	}
	path := make([]byte, 1, len(payload)+1)
	path[0] = 1
	for i := len(rdns) - 1; i >= 0; i-- {
		path = binary.AppendUvarint(path, uint64(len(rdns[i])))
		path = append(path, rdns[i]...)
	}
	return path, nil
}
