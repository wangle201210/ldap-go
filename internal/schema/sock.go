package schema

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	openLDAPSockDatabaseAttributeOID = "1.3.6.1.4.1.4203.1.12.2.3.2.7"
	openLDAPSockDatabaseObjectOID    = "1.3.6.1.4.1.4203.1.12.2.4.2.7"
	ldapGoSockExtensionOID           = "1.3.6.1.4.1.4203.666.11.99.9"
	ldapGoSockCallbackTimeoutName    = "olcOvSocketCallbackTimeout"
)

var openLDAPSockAttributeTypes = []string{
	"( " + openLDAPSockDatabaseAttributeOID + ".1 NAME 'olcDbSocketPath' DESC 'Pathname for Unix domain socket' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSockDatabaseAttributeOID + ".2 NAME 'olcDbSocketExtensions' DESC 'binddn, peername, or ssf' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPSockDatabaseAttributeOID + ".3 NAME 'olcOvSocketOps' DESC 'Operation types to forward' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPSockDatabaseAttributeOID + ".4 NAME 'olcOvSocketResps' DESC 'Response types to forward' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPSockDatabaseAttributeOID + ".5 NAME 'olcOvSocketDNpat' DESC 'DN pattern to match' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
}

var ldapGoSockExtensionAttributeTypes = []string{
	"( " + ldapGoSockExtensionOID + ".1 NAME '" + ldapGoSockCallbackTimeoutName + "' DESC 'Maximum time to wait for a socket overlay response callback consumer' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE X-ORIGIN 'ldap-go extension' )",
}

var openLDAPSockObjectClasses = []string{
	"( " + openLDAPSockDatabaseObjectOID + ".1 NAME 'olcDbSocketConfig' DESC 'Socket backend configuration' SUP olcDatabaseConfig MUST olcDbSocketPath MAY olcDbSocketExtensions )",
	"( " + openLDAPSockDatabaseObjectOID + ".2 NAME 'olcOvSocketConfig' DESC 'Socket overlay configuration' SUP olcOverlayConfig MUST olcDbSocketPath MAY ( olcDbSocketExtensions $ olcOvSocketOps $ olcOvSocketResps $ olcOvSocketDNpat ) )",
}

var openLDAPSockExtensionNames = map[string]struct{}{
	"binddn":   {},
	"peername": {},
	"ssf":      {},
	"connid":   {},
}

// RegisterOpenLDAPSockSchema registers the cn=config schema exposed by the
// OpenLDAP 2.6.13 back-sock database backend and sock overlay.
func RegisterOpenLDAPSockSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP back-sock schema: nil registry")
	}

	attributeGroups := [][]string{
		openLDAPSockAttributeTypes,
		ldapGoSockExtensionAttributeTypes,
	}
	for _, descriptions := range attributeGroups {
		for _, description := range descriptions {
			attribute, err := ParseAttributeType(description)
			if err != nil {
				return fmt.Errorf("parse OpenLDAP back-sock attribute type: %w", err)
			}
			if err := registerCompatibleSockAttribute(registry, attribute); err != nil {
				return err
			}
		}
	}
	for _, description := range openLDAPSockObjectClasses {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP back-sock object class: %w", err)
		}
		objectClass = extendSockOverlayWithCallbackTimeout(objectClass)
		if err := registerCompatibleSockObjectClass(registry, objectClass); err != nil {
			return err
		}
	}
	return nil
}

func extendSockOverlayWithCallbackTimeout(objectClass ObjectClass) ObjectClass {
	if !strings.EqualFold(objectClass.Name(), "olcOvSocketConfig") ||
		containsAllSockNames(objectClass.May, []string{ldapGoSockCallbackTimeoutName}) {
		return objectClass
	}
	objectClass.May = append(objectClass.May, ldapGoSockCallbackTimeoutName)
	return objectClass
}

// ValidateOpenLDAPSockExtensions applies the value constraint implemented by
// OpenLDAP's back-sock config driver. Each cn=config value may contain one or
// more whitespace-separated, case-insensitive extension names.
func ValidateOpenLDAPSockExtensions(values ...string) error {
	for valueIndex, value := range values {
		if !utf8.ValidString(value) {
			return fmt.Errorf(
				"olcDbSocketExtensions value %d is not valid UTF-8",
				valueIndex,
			)
		}
		fields := strings.FieldsFunc(value, isOpenLDAPConfigSpace)
		if len(fields) == 0 {
			return fmt.Errorf(
				"olcDbSocketExtensions value %d is empty",
				valueIndex,
			)
		}
		for _, field := range fields {
			if _, ok := openLDAPSockExtensionNames[strings.ToLower(field)]; !ok {
				return fmt.Errorf(
					"olcDbSocketExtensions value %q is not one of binddn, peername, ssf, or connid",
					field,
				)
			}
		}
	}
	return nil
}

func isOpenLDAPConfigSpace(character rune) bool {
	switch character {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

func registerCompatibleSockAttribute(registry *Registry, want AttributeType) error {
	existing, found, err := findSockAttribute(registry, want)
	if err != nil {
		return err
	}
	if !found {
		if err := registry.RegisterAttributeType(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP back-sock attribute type %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if !compatibleSockAttribute(existing, want) {
		return fmt.Errorf(
			"register OpenLDAP back-sock attribute type %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func findSockAttribute(
	registry *Registry,
	want AttributeType,
) (AttributeType, bool, error) {
	existing, found := registry.AttributeType(want.OID)
	for _, name := range want.Names {
		byName, ok := registry.AttributeType(name)
		if !ok {
			continue
		}
		if found && !strings.EqualFold(existing.OID, byName.OID) {
			return AttributeType{}, false, fmt.Errorf(
				"register OpenLDAP back-sock attribute type %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	return existing, found, nil
}

func compatibleSockAttribute(got, want AttributeType) bool {
	gotUsage := got.Usage
	if gotUsage == "" {
		gotUsage = UsageUserApplications
	}
	wantUsage := want.Usage
	if wantUsage == "" {
		wantUsage = UsageUserApplications
	}
	return strings.EqualFold(got.OID, want.OID) &&
		containsAllSockNames(got.Names, want.Names) &&
		strings.EqualFold(got.Superior, want.Superior) &&
		strings.EqualFold(got.Equality, want.Equality) &&
		strings.EqualFold(got.Ordering, want.Ordering) &&
		strings.EqualFold(got.Substring, want.Substring) &&
		strings.EqualFold(got.Syntax, want.Syntax) &&
		got.SyntaxLength == want.SyntaxLength &&
		got.Obsolete == want.Obsolete &&
		got.SingleValue == want.SingleValue &&
		got.Collective == want.Collective &&
		got.NoUserModification == want.NoUserModification &&
		gotUsage == wantUsage &&
		sockExtensionsContain(got.Extensions, want.Extensions)
}

func registerCompatibleSockObjectClass(registry *Registry, want ObjectClass) error {
	existing, found, err := findSockObjectClass(registry, want)
	if err != nil {
		return err
	}
	if !found {
		if err := registry.RegisterObjectClass(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP back-sock object class %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if compatibleSockObjectClass(existing, want) {
		return nil
	}
	if strings.EqualFold(want.Name(), "olcOvSocketConfig") &&
		containsAllSockNames(want.May, []string{ldapGoSockCallbackTimeoutName}) {
		openLDAPDefinition := want
		openLDAPDefinition.May = removeSockName(
			append([]string(nil), want.May...),
			ldapGoSockCallbackTimeoutName,
		)
		if compatibleSockObjectClass(existing, openLDAPDefinition) {
			if err := registry.UpsertObjectClass(want); err != nil {
				return fmt.Errorf(
					"extend OpenLDAP back-sock object class %q: %w",
					want.Name(), err,
				)
			}
			return nil
		}
	}
	if !compatibleSockObjectClass(existing, want) {
		return fmt.Errorf(
			"register OpenLDAP back-sock object class %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func removeSockName(values []string, target string) []string {
	filtered := values[:0]
	for _, value := range values {
		if !strings.EqualFold(value, target) {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func findSockObjectClass(
	registry *Registry,
	want ObjectClass,
) (ObjectClass, bool, error) {
	existing, found := registry.ObjectClass(want.OID)
	for _, name := range want.Names {
		byName, ok := registry.ObjectClass(name)
		if !ok {
			continue
		}
		if found && !strings.EqualFold(existing.OID, byName.OID) {
			return ObjectClass{}, false, fmt.Errorf(
				"register OpenLDAP back-sock object class %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	return existing, found, nil
}

func compatibleSockObjectClass(got, want ObjectClass) bool {
	return strings.EqualFold(got.OID, want.OID) &&
		containsAllSockNames(got.Names, want.Names) &&
		got.Obsolete == want.Obsolete &&
		got.Kind == want.Kind &&
		equalSockNameSet(got.Superiors, want.Superiors) &&
		equalSockNameSet(got.Must, want.Must) &&
		equalSockNameSet(got.May, want.May) &&
		sockExtensionsContain(got.Extensions, want.Extensions)
}

func containsAllSockNames(values, required []string) bool {
	for _, requiredValue := range required {
		found := false
		for _, value := range values {
			if strings.EqualFold(value, requiredValue) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func equalSockNameSet(left, right []string) bool {
	return len(left) == len(right) &&
		containsAllSockNames(left, right) &&
		containsAllSockNames(right, left)
}

func sockExtensionsContain(got, required map[string][]string) bool {
	for requiredKey, requiredValues := range required {
		var gotValues []string
		found := false
		for gotKey, values := range got {
			if strings.EqualFold(gotKey, requiredKey) {
				gotValues = values
				found = true
				break
			}
		}
		if !found || !equalSockNameSet(gotValues, requiredValues) {
			return false
		}
	}
	return true
}
