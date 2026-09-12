package schema

import (
	"fmt"
	"strings"
)

type builtinMatchingRuleDefinition struct {
	oid, name, syntax string
	extensible        bool
	hidden            bool
	compatibility     string
}

const (
	matchingRuleCountrySyntax   = "1.3.6.1.4.1.1466.115.121.1.11"
	matchingRuleSubstringSyntax = "1.3.6.1.4.1.1466.115.121.1.58"
	maxMatchingRuleSchemaBytes  = 16 << 20
	maxMatchingRuleApplies      = 1 << 20
)

// Each call returns independent values; no mutable catalog is exposed or
// installed in the registry. Metadata follows OpenLDAP 2.6.13, commit
// d172686d3d270bc961b78f3ff00d7019c8dfb094, schema_init.c and aci.c.
// Only rules with an implemented matcher are included. Synthetic IA5 ordering
// names have no native OIDs and are deliberately absent.
func builtinMatchingRuleDefinitions() []builtinMatchingRuleDefinition {
	return []builtinMatchingRuleDefinition{
		{"1.3.6.1.4.1.4203.666.4.4", "directoryStringApproxMatch", SyntaxDirectoryString, true, true, ""},
		{"1.3.6.1.4.1.4203.666.4.5", "IA5StringApproxMatch", SyntaxIA5String, true, true, ""},
		{"2.5.13.0", "objectIdentifierMatch", SyntaxOID, true, false, ""},
		{"2.5.13.1", "distinguishedNameMatch", SyntaxDistinguishedName, true, false, ""},
		{"2.5.13.2", "caseIgnoreMatch", SyntaxDirectoryString, true, false, "directoryStringSyntaxes"},
		{"2.5.13.3", "caseIgnoreOrderingMatch", SyntaxDirectoryString, true, false, "directoryStringSyntaxes"},
		{"2.5.13.4", "caseIgnoreSubstringsMatch", matchingRuleSubstringSyntax, false, false, "directoryStringSyntaxes"},
		{"2.5.13.5", "caseExactMatch", SyntaxDirectoryString, true, false, "directoryStringSyntaxes"},
		{"2.5.13.6", "caseExactOrderingMatch", SyntaxDirectoryString, true, false, "directoryStringSyntaxes"},
		{"2.5.13.7", "caseExactSubstringsMatch", matchingRuleSubstringSyntax, false, false, "directoryStringSyntaxes"},
		{"2.5.13.8", "numericStringMatch", SyntaxNumericString, true, false, ""},
		{"2.5.13.9", "numericStringOrderingMatch", SyntaxNumericString, true, false, ""},
		{"2.5.13.10", "numericStringSubstringsMatch", matchingRuleSubstringSyntax, false, false, ""},
		{"2.5.13.11", "caseIgnoreListMatch", SyntaxPostalAddress, true, false, ""},
		{"2.5.13.12", "caseIgnoreListSubstringsMatch", matchingRuleSubstringSyntax, false, false, ""},
		{"2.5.13.13", "booleanMatch", SyntaxBoolean, true, false, ""},
		{"2.5.13.14", "integerMatch", SyntaxInteger, true, false, ""},
		{"2.5.13.15", "integerOrderingMatch", SyntaxInteger, true, false, ""},
		{"2.5.13.17", "octetStringMatch", SyntaxOctetString, true, false, ""},
		{"2.5.13.18", "octetStringOrderingMatch", SyntaxOctetString, true, false, ""},
		{"2.5.13.19", "octetStringSubstringsMatch", SyntaxOctetString, false, false, ""},
		{"2.5.13.20", "telephoneNumberMatch", SyntaxTelephoneNumber, true, false, ""},
		{"2.5.13.21", "telephoneNumberSubstringsMatch", matchingRuleSubstringSyntax, false, false, ""},
		{"2.5.13.23", "uniqueMemberMatch", SyntaxNameAndOptionalUID, true, false, ""},
		{"2.5.13.27", "generalizedTimeMatch", SyntaxGeneralizedTime, true, false, ""},
		{"2.5.13.28", "generalizedTimeOrderingMatch", SyntaxGeneralizedTime, true, false, ""},
		{"2.5.13.29", "integerFirstComponentMatch", SyntaxInteger, true, false, "integerFirstComponentMatchSyntaxes"},
		{"2.5.13.30", "objectIdentifierFirstComponentMatch", SyntaxOID, true, false, "objectIdentifierFirstComponentMatchSyntaxes"},
		{"1.3.6.1.4.1.1466.109.114.1", "caseExactIA5Match", SyntaxIA5String, true, false, ""},
		{"1.3.6.1.4.1.1466.109.114.2", "caseIgnoreIA5Match", SyntaxIA5String, true, false, ""},
		{"1.3.6.1.4.1.1466.109.114.3", "caseIgnoreIA5SubstringsMatch", SyntaxIA5String, false, false, ""},
		{"1.3.6.1.4.1.4203.1.2.1", "caseExactIA5SubstringsMatch", SyntaxIA5String, false, false, ""},
		{"1.3.6.1.1.16.2", "UUIDMatch", SyntaxUUID, false, false, ""},
		{"1.3.6.1.1.16.3", "UUIDOrderingMatch", SyntaxUUID, false, false, ""},
		{"1.3.6.1.4.1.4203.666.11.2.2", "CSNMatch", SyntaxCSN, false, true, ""},
		{"1.3.6.1.4.1.4203.666.11.2.3", "CSNOrderingMatch", SyntaxCSN, true, true, ""},
		{"1.3.6.1.4.1.4203.666.4.12", "authzMatch", SyntaxAuthz, false, true, ""},
		{"1.3.6.1.4.1.4203.666.4.2", "OpenLDAPaciMatch", SyntaxOpenLDAPACI, false, true, ""},
	}
}

func (definition builtinMatchingRuleDefinition) matchingRule() MatchingRule {
	return MatchingRule{
		OID: definition.oid, Names: []string{definition.name}, Syntax: definition.syntax,
	}
}

// BuiltinMatchingRule resolves a native name or OID without modifying a
// registry. The returned value is independent of subsequent lookups. Hidden
// implemented rules are recognized here but are never published as schema.
func BuiltinMatchingRule(name string) (MatchingRule, bool) {
	for _, definition := range builtinMatchingRuleDefinitions() {
		if name == definition.oid || strings.EqualFold(name, definition.name) {
			return definition.matchingRule(), true
		}
	}
	return MatchingRule{}, false
}

// MatchingRuleDescriptions returns public implemented rules in stable catalog
// order, including attribute substring rules that are not extensible rules.
func (registry *Registry) MatchingRuleDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return builtinMatchingRuleDescriptions()
}

func builtinMatchingRuleDescriptions() []string {
	var descriptions []string
	for _, definition := range builtinMatchingRuleDefinitions() {
		if !definition.hidden {
			descriptions = append(descriptions, FormatMatchingRule(definition.matchingRule()))
		}
	}
	return descriptions
}

// MatchingRuleUseDescriptions returns native APPLIES declarations. Invalid
// attribute inheritance returns no declarations; MatchingRuleSchema exposes
// the error for callers that compile an immutable runtime schema.
func (registry *Registry) MatchingRuleUseDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	uses, _ := registry.matchingRuleUseDescriptionsLocked()
	return uses
}

// MatchingRuleSchema computes both publications under one read lock. Runtime
// builders can retain this snapshot instead of traversing attributes for every
// subschema search. Neither successful nor failed compilation mutates registry.
// Publication is limited to 16 MiB and 1<<20 attribute-rule relationships.
func (registry *Registry) MatchingRuleSchema() (rules, uses []string, err error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	uses, err = registry.matchingRuleUseDescriptionsLocked()
	if err != nil {
		return nil, nil, err
	}
	return builtinMatchingRuleDescriptions(), uses, nil
}

type matchingRuleAttribute struct {
	name, syntax, equality string
}

func (registry *Registry) matchingRuleUseDescriptionsLocked() ([]string, error) {
	attributes := uniqueAttributeTypes(registry.attributes)
	resolved := make(map[*AttributeType]matchingRuleAttribute, len(attributes))
	public := make([]matchingRuleAttribute, 0, len(attributes))
	for _, attribute := range attributes {
		if attribute.Hidden {
			continue
		}
		effective, err := registry.matchingRuleAttributeLocked(
			registry.attributes[schemaKey(attribute.OID)], resolved,
		)
		if err != nil {
			return nil, err
		}
		public = append(public, effective)
	}

	var descriptions []string
	outputBytes, relationships := 0, 0
	for _, description := range builtinMatchingRuleDescriptions() {
		outputBytes += len(description)
	}
	for _, definition := range builtinMatchingRuleDefinitions() {
		if definition.hidden || !definition.extensible && definition.compatibility == "" {
			continue
		}
		var applies []string
		attributeBytes := 0
		for _, attribute := range public {
			if definition.usableWith(attribute) {
				if relationships == maxMatchingRuleApplies {
					return nil, fmt.Errorf("matching rule schema exceeds %d APPLIES relationships", maxMatchingRuleApplies)
				}
				if len(attribute.name) > maxMatchingRuleSchemaBytes-outputBytes-attributeBytes {
					return nil, fmt.Errorf("matching rule schema exceeds %d bytes", maxMatchingRuleSchemaBytes)
				}
				relationships++
				attributeBytes += len(attribute.name)
				applies = append(applies, attribute.name)
			}
		}
		if len(applies) == 0 {
			continue
		}
		description := FormatMatchingRuleUse(MatchingRuleUse{
			OID: definition.oid, Names: []string{definition.name}, Applies: applies,
		})
		if len(description) > maxMatchingRuleSchemaBytes-outputBytes {
			return nil, fmt.Errorf("matching rule schema exceeds %d bytes", maxMatchingRuleSchemaBytes)
		}
		outputBytes += len(description)
		descriptions = append(descriptions, description)
	}
	return descriptions, nil
}

// Resolve each SUP chain once without recursive stack growth. Hidden parents
// still supply inherited equality and syntax to their public descendants.
func (registry *Registry) matchingRuleAttributeLocked(
	attribute *AttributeType,
	resolved map[*AttributeType]matchingRuleAttribute,
) (matchingRuleAttribute, error) {
	var path []*AttributeType
	visiting := make(map[*AttributeType]bool)
	current := attribute
	var inherited matchingRuleAttribute
	for {
		if effective, ok := resolved[current]; ok {
			inherited = effective
			break
		}
		if visiting[current] {
			return matchingRuleAttribute{}, fmt.Errorf("attribute type inheritance cycle at %q", current.Name())
		}
		visiting[current] = true
		path = append(path, current)
		if current.Superior == "" {
			break
		}
		superior, ok := registry.attributes[schemaKey(current.Superior)]
		if !ok {
			return matchingRuleAttribute{}, fmt.Errorf(
				"attribute type %q has unknown superior %q", current.Name(), current.Superior,
			)
		}
		current = superior
	}
	for index := len(path) - 1; index >= 0; index-- {
		current = path[index]
		inherited.name = current.Name()
		if current.Syntax != "" {
			inherited.syntax = current.Syntax
		}
		if current.Equality != "" {
			inherited.equality = current.Equality
		}
		resolved[current] = inherited
	}
	return resolved[attribute], nil
}

// mr.c:mr_usable_with_at permits EXT rules through assertion syntax, assigned
// equality, or syntax inheritance; compatible syntaxes are a separate path.
// The two public case-string substring rules use only that last path.
func (definition builtinMatchingRuleDefinition) usableWith(attribute matchingRuleAttribute) bool {
	if definition.extensible && (attribute.syntax == definition.syntax ||
		attribute.equality == definition.oid || strings.EqualFold(attribute.equality, definition.name) ||
		matchingRuleSyntaxSuperior(attribute.syntax, definition.syntax)) {
		return true
	}
	for _, syntax := range matchingRuleCompatibleSyntaxes(definition.compatibility) {
		if attribute.syntax == syntax {
			return true
		}
	}
	return false
}

func matchingRuleCompatibleSyntaxes(name string) []string {
	switch name {
	case "directoryStringSyntaxes":
		return []string{matchingRuleCountrySyntax, SyntaxPrintableString, SyntaxTelephoneNumber}
	case "integerFirstComponentMatchSyntaxes":
		return []string{SyntaxInteger, SyntaxDITStructureRule}
	case "objectIdentifierFirstComponentMatchSyntaxes":
		return []string{
			SyntaxOID, SyntaxAttributeType, SyntaxDITContentRule,
			"1.3.6.1.4.1.1466.115.121.1.54", // LDAP Syntax Description
			"1.3.6.1.4.1.1466.115.121.1.30", // Matching Rule Description
			"1.3.6.1.4.1.1466.115.121.1.31", // Matching Rule Use Description
			SyntaxNameForm, SyntaxObjectClass,
		}
	default:
		return nil
	}
}

func matchingRuleSyntaxSuperior(syntax, superior string) bool {
	// schema_init.c:country_gen_syn is the only built-in SUP list. syntax.c
	// explicitly leaves ssyn_sups empty for X-SUBST: sharing a validator does
	// not make a syntax equal to, or a subtype of, its substitute.
	return syntax == matchingRuleCountrySyntax &&
		(superior == SyntaxDirectoryString || superior == SyntaxIA5String || superior == SyntaxPrintableString)
}
