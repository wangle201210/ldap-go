package directory

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Frozen pre-optimization implementations are independent oracles for exact
// validation errors, accepted encodings, and reconstructed DN representations.
func referenceParseDN(value string) (DN, error) {
	parsed, err := ldap.ParseDN(value)
	if err != nil {
		return DN{}, fmt.Errorf("parse DN %q: %w", value, err)
	}
	if err := validateUniqueDNAttributeTypes(parsed); err != nil {
		return DN{}, fmt.Errorf("parse DN %q: %w", value, err)
	}
	return DN{
		parsed:      parsed,
		canonical:   strings.ToLower(parsed.String()),
		displayRDNs: referenceFormatDNRDNs(parsed, false),
	}, nil
}

func referenceParseDNWithIdentityKey(value, key string) (DN, error) {
	dn, err := referenceParseDN(value)
	if err != nil {
		return DN{}, err
	}
	if !strings.HasPrefix(key, schemaAwareDNKeyPrefix) {
		if err := dn.ValidateIdentityKey(key); err != nil {
			return DN{}, err
		}
		return dn, nil
	}
	encoded := strings.TrimPrefix(key, schemaAwareDNKeyPrefix)
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	// Strict decoding checks unused tail bits but still ignores CR and LF.
	if err != nil || strings.ContainsAny(encoded, "\r\n") {
		return DN{}, errors.New("schema-aware DN key is not canonically encoded")
	}
	rdns, err := referenceDecodeDNIdentityParts(payload)
	if err != nil {
		return DN{}, fmt.Errorf("decode schema-aware DN key RDNs: %w", err)
	}
	if len(rdns) != len(dn.parsed.RDNs) {
		return DN{}, fmt.Errorf(
			"schema-aware DN key has %d RDNs, display DN has %d",
			len(rdns),
			len(dn.parsed.RDNs),
		)
	}
	dn.identityRDNs = make([][]byte, len(rdns))
	dn.normalizedRDNs = make([]string, len(rdns))
	dn.attributeTypes = make([][]string, len(rdns))
	for rdnIndex, encodedRDN := range rdns {
		avas, decodeErr := referenceDecodeDNIdentityParts(encodedRDN)
		if decodeErr != nil {
			return DN{}, fmt.Errorf("decode schema-aware DN key RDN %d: %w", rdnIndex, decodeErr)
		}
		type normalizedAVA struct {
			attributeType string
			value         string
		}
		normalized := make([]normalizedAVA, 0, len(avas))
		for _, ava := range avas {
			parts, partsErr := referenceDecodeDNIdentityParts(ava)
			if partsErr != nil || len(parts) != 2 || len(parts[0]) == 0 {
				return DN{}, fmt.Errorf("schema-aware DN key RDN %d contains an invalid AVA", rdnIndex)
			}
			attributeType := string(parts[0])
			normalized = append(normalized, normalizedAVA{
				attributeType: attributeType,
				value: attributeType + "=" +
					referenceEscapeDNValue(string(parts[1])),
			})
		}
		sort.Slice(normalized, func(left, right int) bool {
			return normalized[left].attributeType < normalized[right].attributeType
		})
		dn.attributeTypes[rdnIndex] = make([]string, len(normalized))
		normalizedValues := make([]string, len(normalized))
		for index := range normalized {
			dn.attributeTypes[rdnIndex][index] = normalized[index].attributeType
			normalizedValues[index] = normalized[index].value
		}
		dn.identityRDNs[rdnIndex] = bytes.Clone(encodedRDN)
		dn.normalizedRDNs[rdnIndex] = strings.Join(normalizedValues, "+")
	}
	dn.identityLevel = schemaAwareDNIdentityLevel
	dn.canonical = key
	return dn, nil
}

func referenceDecodeDNIdentityParts(encoded []byte) ([][]byte, error) {
	count, bytesRead := binary.Uvarint(encoded)
	if bytesRead == 0 {
		return nil, errors.New("truncated part count")
	}
	if bytesRead < 0 {
		return nil, errors.New("part count overflows uint64")
	}
	encoded = encoded[bytesRead:]
	if count > uint64(len(encoded))+1 {
		return nil, errors.New("part count exceeds encoded payload")
	}
	parts := make([][]byte, 0, int(count))
	for index := uint64(0); index < count; index++ {
		length, lengthBytes := binary.Uvarint(encoded)
		if lengthBytes == 0 {
			return nil, fmt.Errorf("part %d has a truncated length", index)
		}
		if lengthBytes < 0 {
			return nil, fmt.Errorf("part %d length overflows uint64", index)
		}
		encoded = encoded[lengthBytes:]
		if length > uint64(len(encoded)) {
			return nil, fmt.Errorf("part %d length exceeds encoded payload", index)
		}
		parts = append(parts, encoded[:int(length)])
		encoded = encoded[int(length):]
	}
	if len(encoded) != 0 {
		return nil, errors.New("trailing bytes after encoded parts")
	}
	return parts, nil
}

func referenceIdentityKeyInScope(base DN, candidateKey string, scope Scope) (bool, error) {
	if !base.hasSchemaAwareIdentity() {
		return false, errors.New("scope base has no schema-aware identity")
	}
	if !strings.HasPrefix(candidateKey, schemaAwareDNKeyPrefix) {
		return false, errors.New("candidate has no schema-aware identity key")
	}
	encoded := strings.TrimPrefix(candidateKey, schemaAwareDNKeyPrefix)
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	// Strict decoding checks unused tail bits but still ignores CR and LF.
	if err != nil || strings.ContainsAny(encoded, "\r\n") {
		return false, errors.New("candidate schema-aware DN key is not canonically encoded")
	}
	candidateRDNs, err := referenceDecodeDNIdentityParts(payload)
	if err != nil {
		return false, fmt.Errorf("decode candidate schema-aware DN key: %w", err)
	}
	equal := len(base.identityRDNs) == len(candidateRDNs)
	ancestor := len(base.identityRDNs) < len(candidateRDNs)
	if equal || ancestor {
		offset := len(candidateRDNs) - len(base.identityRDNs)
		for index := range base.identityRDNs {
			if !bytes.Equal(base.identityRDNs[index], candidateRDNs[index+offset]) {
				equal = false
				ancestor = false
				break
			}
		}
	}
	switch scope {
	case ScopeBase:
		return equal, nil
	case ScopeSingleLevel:
		return ancestor && len(candidateRDNs) == len(base.identityRDNs)+1, nil
	case ScopeWholeSubtree:
		return equal || ancestor, nil
	case ScopeChildren:
		return ancestor, nil
	default:
		return false, nil
	}
}

func referenceFormatDNRDNs(parsed *ldap.DN, preserveAttributeCase bool) []string {
	formatted := make([]string, len(parsed.RDNs))
	for rdnIndex, rdn := range parsed.RDNs {
		avas := make([]string, len(rdn.Attributes))
		for attributeIndex, attribute := range rdn.Attributes {
			attributeType := attribute.Type
			if !preserveAttributeCase {
				attributeType = strings.ToLower(attributeType)
			}
			avas[attributeIndex] = attributeType + "=" + referenceEscapeDNValue(attribute.Value)
		}
		sort.Strings(avas)
		formatted[rdnIndex] = strings.Join(avas, "+")
	}
	return formatted
}

func referenceEscapeDNValue(value string) string {
	const hex = "0123456789abcdef"
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		escapeCharacter := (index == 0 && (character == ' ' || character == '#')) ||
			(index == len(value)-1 && character == ' ')
		switch character {
		case '"', '+', ',', ';', '<', '>', '\\':
			escapeCharacter = true
		}
		if escapeCharacter {
			builder.WriteByte('\\')
			builder.WriteByte(character)
			continue
		}
		if character < ' ' || character > '~' {
			builder.WriteByte('\\')
			builder.WriteByte(hex[character>>4])
			builder.WriteByte(hex[character&0x0f])
			continue
		}
		builder.WriteByte(character)
	}
	return builder.String()
}
