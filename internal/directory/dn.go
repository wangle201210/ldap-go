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

type DN struct {
	parsed         *ldap.DN
	canonical      string
	identityRDNs   [][]byte
	displayRDNs    []string
	normalizedRDNs []string
	attributeTypes [][]string
	identityLevel  uint8
}

const schemaAwareDNIdentityLevel = 2

const schemaAwareDNKeyPrefix = "dn:v2:"

// DNAttributeNormalizer resolves an attribute type to its canonical schema
// identifier and normalizes a naming value with its equality matching rule.
type DNAttributeNormalizer interface {
	NormalizeDNAttribute(
		attributeType string,
		value []byte,
	) (canonicalType string, normalizedValue []byte, err error)
}

// DNAttributeCanonicalNamer optionally supplies the schema's preferred
// attribute description for the pretty form of a DN.
type DNAttributeCanonicalNamer interface {
	CanonicalDNAttributeName(attributeType string) (string, error)
}

type AttributeValue struct {
	Type  string
	Value []byte
}

func ParseDN(value string) (DN, error) {
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
		displayRDNs: formatDNRDNs(parsed, false),
	}, nil
}

func validateUniqueDNAttributeTypes(parsed *ldap.DN) error {
	for rdnIndex, rdn := range parsed.RDNs {
		seen := make(map[string]struct{}, len(rdn.Attributes))
		for _, attribute := range rdn.Attributes {
			canonical, _, _ := strings.Cut(attribute.Type, ";")
			canonical = strings.ToLower(strings.TrimSpace(canonical))
			if !validDNAttributeType(canonical) {
				return fmt.Errorf(
					"RDN %d contains invalid attribute type %q",
					rdnIndex,
					attribute.Type,
				)
			}
			if _, duplicate := seen[canonical]; duplicate {
				return fmt.Errorf(
					"RDN %d contains duplicate attribute type %q",
					rdnIndex,
					canonical,
				)
			}
			seen[canonical] = struct{}{}
		}
	}
	return nil
}

func validDNAttributeType(value string) bool {
	if value == "" {
		return false
	}
	if value[0] >= '0' && value[0] <= '9' {
		for _, arc := range strings.Split(value, ".") {
			if arc == "" || len(arc) > 1 && arc[0] == '0' {
				return false
			}
			for index := range arc {
				if arc[index] < '0' || arc[index] > '9' {
					return false
				}
			}
		}
		return true
	}
	if !asciiDNAttributeLetter(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiDNAttributeLetter(character) &&
			(character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}

func asciiDNAttributeLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

// ParseDNWithNormalizer builds a schema-aware identity key while retaining the
// original parsed DN for display and RDN access. The v2 key is self-identifying
// and cannot collide with legacy lowercase-string keys.
func ParseDNWithNormalizer(value string, normalizer DNAttributeNormalizer) (DN, error) {
	if normalizer == nil {
		return DN{}, errors.New("DN attribute normalizer is required")
	}
	dn, err := ParseDN(value)
	if err != nil {
		return DN{}, err
	}

	identityRDNs := make([][]byte, len(dn.parsed.RDNs))
	displayRDNs := make([]string, len(dn.parsed.RDNs))
	normalizedRDNs := make([]string, len(dn.parsed.RDNs))
	attributeTypes := make([][]string, len(dn.parsed.RDNs))
	canonicalNamer, hasCanonicalNamer := normalizer.(DNAttributeCanonicalNamer)
	for rdnIndex, rdn := range dn.parsed.RDNs {
		type normalizedAVA struct {
			attributeType string
			display       string
			normalized    string
			identity      []byte
		}
		avas := make([]normalizedAVA, len(rdn.Attributes))
		canonicalTypes := make(map[string]struct{}, len(rdn.Attributes))
		attributeTypes[rdnIndex] = make([]string, len(rdn.Attributes))
		for attributeIndex, attribute := range rdn.Attributes {
			canonicalType, normalizedValue, err := normalizer.NormalizeDNAttribute(
				attribute.Type,
				[]byte(attribute.Value),
			)
			if err != nil {
				return DN{}, fmt.Errorf(
					"normalize DN attribute %q: %w",
					attribute.Type,
					err,
				)
			}
			canonicalType = strings.ToLower(strings.TrimSpace(canonicalType))
			if canonicalType == "" {
				return DN{}, fmt.Errorf(
					"normalize DN attribute %q: canonical type is empty",
					attribute.Type,
				)
			}
			if _, duplicate := canonicalTypes[canonicalType]; duplicate {
				return DN{}, fmt.Errorf(
					"normalize DN RDN %d: canonical attribute type %q appears more than once",
					rdnIndex,
					canonicalType,
				)
			}
			canonicalTypes[canonicalType] = struct{}{}
			identity := encodeDNIdentityParts(
				[]byte(canonicalType),
				normalizedValue,
			)
			displayName := strings.ToLower(attribute.Type)
			if hasCanonicalNamer {
				canonicalName, err := canonicalNamer.CanonicalDNAttributeName(
					attribute.Type,
				)
				if err != nil {
					return DN{}, fmt.Errorf(
						"canonicalize DN attribute %q: %w",
						attribute.Type,
						err,
					)
				}
				displayName = canonicalName
			}
			avas[attributeIndex] = normalizedAVA{
				attributeType: displayName,
				display:       displayName + "=" + escapeDNValue(attribute.Value),
				normalized: displayName + "=" +
					escapeDNValue(string(normalizedValue)),
				identity: identity,
			}
			attributeTypes[rdnIndex][attributeIndex] = displayName
		}
		// OpenLDAP canonicalizes AttributeDescriptions before sorting AVAs.
		// Sorting the complete display string is observably different when
		// attribute names are equal prefixes, so compare names first.
		sort.SliceStable(avas, func(left, right int) bool {
			return avas[left].attributeType < avas[right].attributeType
		})
		attributes := make([][]byte, len(avas))
		displayAVAs := make([]string, len(avas))
		normalizedAVAs := make([]string, len(avas))
		for index, ava := range avas {
			attributes[index] = ava.identity
			displayAVAs[index] = ava.display
			normalizedAVAs[index] = ava.normalized
		}
		sort.Slice(attributes, func(left, right int) bool {
			return bytes.Compare(attributes[left], attributes[right]) < 0
		})
		identityRDNs[rdnIndex] = encodeDNIdentityParts(attributes...)
		displayRDNs[rdnIndex] = strings.Join(displayAVAs, "+")
		normalizedRDNs[rdnIndex] = strings.Join(normalizedAVAs, "+")
	}

	dn.identityRDNs = identityRDNs
	dn.displayRDNs = displayRDNs
	dn.normalizedRDNs = normalizedRDNs
	dn.attributeTypes = attributeTypes
	dn.identityLevel = schemaAwareDNIdentityLevel
	dn.canonical = encodeDNIdentity(identityRDNs)
	return dn, nil
}

// ParseDNWithIdentityKey reconstructs a schema-aware DN from its validated
// physical identity key without rerunning schema matching rules.
func ParseDNWithIdentityKey(value, key string) (DN, error) {
	dn, err := ParseDN(value)
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
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return DN{}, errors.New("schema-aware DN key is not canonically encoded")
	}
	rdns, err := decodeDNIdentityParts(payload)
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
		avas, decodeErr := decodeDNIdentityParts(encodedRDN)
		if decodeErr != nil {
			return DN{}, fmt.Errorf("decode schema-aware DN key RDN %d: %w", rdnIndex, decodeErr)
		}
		type normalizedAVA struct {
			attributeType string
			value         string
		}
		normalized := make([]normalizedAVA, 0, len(avas))
		for _, ava := range avas {
			parts, partsErr := decodeDNIdentityParts(ava)
			if partsErr != nil || len(parts) != 2 || len(parts[0]) == 0 {
				return DN{}, fmt.Errorf("schema-aware DN key RDN %d contains an invalid AVA", rdnIndex)
			}
			attributeType := string(parts[0])
			normalized = append(normalized, normalizedAVA{
				attributeType: attributeType,
				value: attributeType + "=" +
					escapeDNValue(string(parts[1])),
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

// LegacyKey returns the historical case-folded textual key used as the first
// component of deterministic storage ordering.
func (dn DN) LegacyKey() string {
	if dn.parsed == nil {
		return ""
	}
	return strings.ToLower(dn.parsed.String())
}

func (dn DN) String() string {
	return strings.Join(dn.displayRDNs, ",")
}

func (dn DN) Key() string {
	return dn.canonical
}

// NormalizedString returns the LDAP normalized textual DN. Schema-aware DNs
// use preferred attribute names, OpenLDAP AVA ordering, and values normalized
// by each attribute's equality matching rule. Legacy DNs retain their existing
// lowercase textual key behavior. Unlike Key, this value is suitable for LDAP
// interfaces such as back-sql's o_req_ndn parameter.
func (dn DN) NormalizedString() string {
	if dn.hasSchemaAwareIdentity() {
		return strings.Join(dn.normalizedRDNs, ",")
	}
	return dn.canonical
}

// ValidateIdentityKey checks the physical shape of a legacy or v2 DN key
// against this parsed DN. Matching-rule semantics are established when the v2
// key is created; this method validates its unambiguous encoding and RDN shape.
func (dn DN) ValidateIdentityKey(key string) error {
	if !strings.HasPrefix(key, schemaAwareDNKeyPrefix) {
		if key != strings.ToLower(dn.parsed.String()) {
			return fmt.Errorf("legacy key does not match normalized DN %q", dn.Key())
		}
		return nil
	}

	encoded := strings.TrimPrefix(key, schemaAwareDNKeyPrefix)
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode schema-aware DN key: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return errors.New("schema-aware DN key is not canonically encoded")
	}
	rdns, err := decodeDNIdentityParts(payload)
	if err != nil {
		return fmt.Errorf("decode schema-aware DN key RDNs: %w", err)
	}
	if len(rdns) != len(dn.parsed.RDNs) {
		return fmt.Errorf(
			"schema-aware DN key has %d RDNs, DN has %d",
			len(rdns),
			len(dn.parsed.RDNs),
		)
	}
	for rdnIndex, encodedRDN := range rdns {
		avas, err := decodeDNIdentityParts(encodedRDN)
		if err != nil {
			return fmt.Errorf("decode schema-aware DN key RDN %d: %w", rdnIndex, err)
		}
		if len(avas) != len(dn.parsed.RDNs[rdnIndex].Attributes) {
			return fmt.Errorf(
				"schema-aware DN key RDN %d has %d AVAs, DN has %d",
				rdnIndex,
				len(avas),
				len(dn.parsed.RDNs[rdnIndex].Attributes),
			)
		}
		for index, ava := range avas {
			if index > 0 && bytes.Compare(avas[index-1], ava) > 0 {
				return fmt.Errorf("schema-aware DN key RDN %d AVAs are not sorted", rdnIndex)
			}
			parts, err := decodeDNIdentityParts(ava)
			if err != nil {
				return fmt.Errorf(
					"decode schema-aware DN key RDN %d AVA %d: %w",
					rdnIndex,
					index,
					err,
				)
			}
			if len(parts) != 2 || len(parts[0]) == 0 {
				return fmt.Errorf(
					"schema-aware DN key RDN %d AVA %d must contain type and value",
					rdnIndex,
					index,
				)
			}
		}
	}
	return nil
}

func (dn DN) Depth() int {
	return len(dn.parsed.RDNs)
}

func (dn DN) Equal(other DN) bool {
	if dn.hasSchemaAwareIdentity() && other.hasSchemaAwareIdentity() {
		return dn.canonical == other.canonical
	}
	return dn.parsed.EqualFold(other.parsed)
}

// EqualExact compares parsed RDN values without applying schema equality
// matching. Attribute type spelling is case-insensitive, as required by LDAP.
func (dn DN) EqualExact(other DN) bool {
	return dn.parsed.Equal(other.parsed)
}

func (dn DN) AncestorOf(other DN) bool {
	if dn.hasSchemaAwareIdentity() && other.hasSchemaAwareIdentity() {
		if len(dn.identityRDNs) >= len(other.identityRDNs) {
			return false
		}
		offset := len(other.identityRDNs) - len(dn.identityRDNs)
		for index := range dn.identityRDNs {
			if !bytes.Equal(dn.identityRDNs[index], other.identityRDNs[index+offset]) {
				return false
			}
		}
		return true
	}
	return dn.parsed.AncestorOfFold(other.parsed)
}

func (dn DN) Parent() (DN, bool) {
	if len(dn.parsed.RDNs) == 0 {
		return DN{}, false
	}
	parent := &ldap.DN{RDNs: dn.parsed.RDNs[1:]}
	if dn.hasSchemaAwareIdentity() {
		identityRDNs := append([][]byte(nil), dn.identityRDNs[1:]...)
		return DN{
			parsed:         parent,
			canonical:      encodeDNIdentity(identityRDNs),
			identityRDNs:   identityRDNs,
			displayRDNs:    append([]string(nil), dn.displayRDNs[1:]...),
			normalizedRDNs: append([]string(nil), dn.normalizedRDNs[1:]...),
			attributeTypes: append([][]string(nil), dn.attributeTypes[1:]...),
			identityLevel:  schemaAwareDNIdentityLevel,
		}, true
	}
	return DN{
		parsed:      parent,
		canonical:   strings.ToLower(parent.String()),
		displayRDNs: append([]string(nil), dn.displayRDNs[1:]...),
	}, true
}

func ComposeDN(rdn string, superior DN) (DN, error) {
	parsedRDN, err := ParseDN(rdn)
	if err != nil {
		return DN{}, err
	}
	if parsedRDN.Depth() != 1 {
		return DN{}, errors.New("new RDN must contain exactly one relative distinguished name")
	}
	if superior.Depth() == 0 {
		return parsedRDN, nil
	}
	return ParseDN(parsedRDN.String() + "," + superior.String())
}

func ComposeLocalName(localName, superior DN) (DN, error) {
	if localName.Depth() == 0 {
		return superior, nil
	}
	if superior.Depth() == 0 {
		return localName, nil
	}
	if localName.hasSchemaAwareIdentity() && superior.hasSchemaAwareIdentity() {
		parsed := &ldap.DN{RDNs: make([]*ldap.RelativeDN, 0, localName.Depth()+superior.Depth())}
		parsed.RDNs = append(parsed.RDNs, localName.parsed.RDNs...)
		parsed.RDNs = append(parsed.RDNs, superior.parsed.RDNs...)
		identityRDNs := make([][]byte, 0, len(localName.identityRDNs)+len(superior.identityRDNs))
		identityRDNs = append(identityRDNs, localName.identityRDNs...)
		identityRDNs = append(identityRDNs, superior.identityRDNs...)
		return DN{
			parsed:       parsed,
			canonical:    encodeDNIdentity(identityRDNs),
			identityRDNs: identityRDNs,
			displayRDNs: append(
				append([]string(nil), localName.displayRDNs...),
				superior.displayRDNs...,
			),
			normalizedRDNs: append(
				append([]string(nil), localName.normalizedRDNs...),
				superior.normalizedRDNs...,
			),
			attributeTypes: append(
				append([][]string(nil), localName.attributeTypes...),
				superior.attributeTypes...,
			),
			identityLevel: schemaAwareDNIdentityLevel,
		}, nil
	}
	return ParseDN(localName.String() + "," + superior.String())
}

func (dn DN) ReplaceAncestor(oldBase, newBase DN) (DN, error) {
	if !oldBase.Equal(dn) && !oldBase.AncestorOf(dn) {
		return DN{}, errors.New("DN is outside the old naming subtree")
	}
	prefixLength := dn.Depth() - oldBase.Depth()
	rdns := make([]*ldap.RelativeDN, 0, prefixLength+newBase.Depth())
	rdns = append(rdns, dn.parsed.RDNs[:prefixLength]...)
	rdns = append(rdns, newBase.parsed.RDNs...)
	replaced := &ldap.DN{RDNs: rdns}
	if dn.hasSchemaAwareIdentity() && oldBase.hasSchemaAwareIdentity() &&
		newBase.hasSchemaAwareIdentity() {
		identityRDNs := make([][]byte, 0, prefixLength+len(newBase.identityRDNs))
		identityRDNs = append(identityRDNs, dn.identityRDNs[:prefixLength]...)
		identityRDNs = append(identityRDNs, newBase.identityRDNs...)
		return DN{
			parsed:       replaced,
			canonical:    encodeDNIdentity(identityRDNs),
			identityRDNs: identityRDNs,
			displayRDNs: append(
				append([]string(nil), dn.displayRDNs[:prefixLength]...),
				newBase.displayRDNs...,
			),
			normalizedRDNs: append(
				append([]string(nil), dn.normalizedRDNs[:prefixLength]...),
				newBase.normalizedRDNs...,
			),
			attributeTypes: append(
				append([][]string(nil), dn.attributeTypes[:prefixLength]...),
				newBase.attributeTypes...,
			),
			identityLevel: schemaAwareDNIdentityLevel,
		}, nil
	}
	return DN{
		parsed:    replaced,
		canonical: strings.ToLower(replaced.String()),
		displayRDNs: append(
			append([]string(nil), dn.displayRDNs[:prefixLength]...),
			newBase.displayRDNs...,
		),
	}, nil
}

func formatDNRDNs(parsed *ldap.DN, preserveAttributeCase bool) []string {
	formatted := make([]string, len(parsed.RDNs))
	for rdnIndex, rdn := range parsed.RDNs {
		avas := make([]string, len(rdn.Attributes))
		for attributeIndex, attribute := range rdn.Attributes {
			attributeType := attribute.Type
			if !preserveAttributeCase {
				attributeType = strings.ToLower(attributeType)
			}
			avas[attributeIndex] = attributeType + "=" + escapeDNValue(attribute.Value)
		}
		sort.Strings(avas)
		formatted[rdnIndex] = strings.Join(avas, "+")
	}
	return formatted
}

func escapeDNValue(value string) string {
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

func (dn DN) hasSchemaAwareIdentity() bool {
	return dn.identityLevel == schemaAwareDNIdentityLevel
}

func encodeDNIdentity(rdns [][]byte) string {
	encoded := encodeDNIdentityParts(rdns...)
	return schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(encoded)
}

func encodeDNIdentityParts(parts ...[]byte) []byte {
	result := make([]byte, 0)
	result = binary.AppendUvarint(result, uint64(len(parts)))
	for _, part := range parts {
		result = binary.AppendUvarint(result, uint64(len(part)))
		result = append(result, part...)
	}
	return result
}

func decodeDNIdentityParts(encoded []byte) ([][]byte, error) {
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

func (dn DN) RDNValues() []AttributeValue {
	if dn.Depth() == 0 {
		return nil
	}
	values := make([]AttributeValue, 0, len(dn.parsed.RDNs[0].Attributes))
	for index, attribute := range dn.parsed.RDNs[0].Attributes {
		attributeType := attribute.Type
		if dn.hasSchemaAwareIdentity() && len(dn.attributeTypes) > 0 &&
			index < len(dn.attributeTypes[0]) {
			attributeType = dn.attributeTypes[0][index]
		}
		values = append(values, AttributeValue{
			Type:  attributeType,
			Value: []byte(attribute.Value),
		})
	}
	return values
}

// AllAttributeTypesMatch reports whether every AVA attribute type is accepted
// without allocating an intermediate list.
func (dn DN) AllAttributeTypesMatch(accept func(string) bool) bool {
	if accept == nil || dn.parsed == nil {
		return false
	}
	if dn.hasSchemaAwareIdentity() && len(dn.attributeTypes) == len(dn.parsed.RDNs) {
		for _, rdn := range dn.attributeTypes {
			for _, attributeType := range rdn {
				if !accept(attributeType) {
					return false
				}
			}
		}
		return true
	}
	for _, rdn := range dn.parsed.RDNs {
		for _, attribute := range rdn.Attributes {
			if !accept(attribute.Type) {
				return false
			}
		}
	}
	return true
}

type Scope int

const (
	ScopeBase Scope = iota
	ScopeSingleLevel
	ScopeWholeSubtree
	ScopeChildren
)

func InScope(base, candidate DN, scope Scope) bool {
	switch scope {
	case ScopeBase:
		return base.Equal(candidate)
	case ScopeSingleLevel:
		return base.AncestorOf(candidate) && candidate.Depth() == base.Depth()+1
	case ScopeWholeSubtree:
		return base.Equal(candidate) || base.AncestorOf(candidate)
	case ScopeChildren:
		return base.AncestorOf(candidate)
	default:
		return false
	}
}

// IdentityKeyInScope evaluates scope directly against a validated schema-aware
// physical key without constructing the candidate's display DN.
func IdentityKeyInScope(base DN, candidateKey string, scope Scope) (bool, error) {
	if !base.hasSchemaAwareIdentity() {
		return false, errors.New("scope base has no schema-aware identity")
	}
	if !strings.HasPrefix(candidateKey, schemaAwareDNKeyPrefix) {
		return false, errors.New("candidate has no schema-aware identity key")
	}
	encoded := strings.TrimPrefix(candidateKey, schemaAwareDNKeyPrefix)
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return false, errors.New("candidate schema-aware DN key is not canonically encoded")
	}
	candidateRDNs, err := decodeDNIdentityParts(payload)
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
