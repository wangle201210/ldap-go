package directory

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Frozen 9d66cbc normalization loop, independent of singleton result assembly.
func referenceNormalizeDNWith(dn DN, normalizer DNAttributeNormalizer) (DN, error) {
	if normalizer == nil {
		return DN{}, errors.New("DN attribute normalizer is required")
	}
	if dn.parsed == nil {
		var err error
		dn, err = ParseDN("")
		if err != nil {
			return DN{}, err
		}
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
				return DN{}, fmt.Errorf("normalize DN attribute %q: %w", attribute.Type, err)
			}
			canonicalType = strings.ToLower(strings.TrimSpace(canonicalType))
			if canonicalType == "" {
				return DN{}, fmt.Errorf("normalize DN attribute %q: canonical type is empty", attribute.Type)
			}
			if _, duplicate := canonicalTypes[canonicalType]; duplicate {
				return DN{}, fmt.Errorf(
					"normalize DN RDN %d: canonical attribute type %q appears more than once",
					rdnIndex, canonicalType,
				)
			}
			canonicalTypes[canonicalType] = struct{}{}
			identity := encodeDNIdentityParts([]byte(canonicalType), normalizedValue)
			displayName := strings.ToLower(attribute.Type)
			if hasCanonicalNamer {
				canonicalName, err := canonicalNamer.CanonicalDNAttributeName(attribute.Type)
				if err != nil {
					return DN{}, fmt.Errorf("canonicalize DN attribute %q: %w", attribute.Type, err)
				}
				displayName = canonicalName
			}
			avas[attributeIndex] = normalizedAVA{
				attributeType: displayName,
				display:       displayName + "=" + escapeDNValue(attribute.Value),
				normalized:    displayName + "=" + escapeDNValue(string(normalizedValue)),
				identity:      identity,
			}
			attributeTypes[rdnIndex][attributeIndex] = displayName
		}
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
