package schema

import (
	"fmt"
	"strings"
)

const (
	openLDAPMetaDatabaseAttributeOID = "1.3.6.1.4.1.4203.1.12.2.3.2"
	openLDAPMetaDatabaseObjectOID    = "1.3.6.1.4.1.4203.1.12.2.4.2"
)

// These are the back-ldap/back-meta attributes consumed by the pinned
// back-meta differential and its production configuration parser. OpenLDAP
// registers back-ldap before back-meta, so the externally visible
// olcDbNetworkTimeout definition includes back-ldap's equality rule.
var openLDAPMetaAttributeTypes = []string{
	"( " + openLDAPMetaDatabaseAttributeOID + ".0.14 NAME 'olcDbURI' DESC 'URI (list) for remote DSA' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.1 NAME 'olcDbStartTLS' DESC 'StartTLS' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.7 NAME 'olcDbIDAssertBind' DESC 'Remote Identity Assertion administrative identity auth bind configuration' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.9 NAME 'olcDbIDAssertAuthzFrom' DESC 'Remote Identity Assertion authz rules' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " X-ORDERED 'VALUES' )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.10 NAME 'olcDbRebindAsUser' DESC 'Rebind as user' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.11 NAME 'olcDbChaseReferrals' DESC 'Chase referrals' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.12 NAME 'olcDbTFSupport' DESC 'Absolute filters support' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.14 NAME 'olcDbTimeout' DESC 'Per-operation timeouts' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.15 NAME 'olcDbIdleTimeout' DESC 'connection idle timeout' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.16 NAME 'olcDbConnTtl' DESC 'connection ttl' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.17 NAME 'olcDbNetworkTimeout' DESC 'connection network timeout' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.18 NAME 'olcDbProtocolVersion' DESC 'protocol version' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.19 NAME 'olcDbSingleConn' DESC 'cache a single connection per identity' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.20 NAME 'olcDbCancel' DESC 'abandon/ignore/exop operations when appropriate' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.21 NAME 'olcDbQuarantine' DESC 'Quarantine database if connection fails and retry according to rule' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.22 NAME 'olcDbUseTemporaryConn' DESC 'Use temporary connections if the cached one is busy' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.23 NAME 'olcDbConnectionPoolMax' DESC 'Max size of privileged connections pool' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.24 NAME 'olcDbSessionTrackingRequest' DESC 'Add session tracking control to proxied requests' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.25 NAME 'olcDbNoRefs' DESC 'Do not return search reference responses' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.26 NAME 'olcDbNoUndefFilter' DESC 'Do not propagate undefined search filters' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.29 NAME 'olcDbKeepalive' DESC 'TCP keepalive' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.30 NAME 'olcDbTcpUserTimeout' DESC 'TCP User Timeout' SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.101 NAME 'olcDbRewrite' DESC 'DN rewriting rules' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " X-ORDERED 'VALUES' )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.102 NAME 'olcDbMap' DESC 'Map attribute and objectclass names' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " X-ORDERED 'VALUES' )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.103 NAME 'olcDbSubtreeExclude' DESC 'DN of subtree to exclude from target' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.104 NAME 'olcDbSubtreeInclude' DESC 'DN of subtree to include in target' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.105 NAME 'olcDbDefaultTarget' DESC 'Specify the default target' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.106 NAME 'olcDbDnCacheTtl' DESC 'dncache ttl' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.107 NAME 'olcDbBindTimeout' DESC 'bind timeout' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.108 NAME 'olcDbOnErr' DESC 'error handling' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.109 NAME 'olcDbPseudoRootBindDefer' DESC 'error handling' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.110 NAME 'olcDbNretries' DESC 'retry handling' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.111 NAME 'olcDbClientPr' DESC 'PagedResults handling' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.112 NAME 'olcDbFilter' DESC 'Filter regex pattern to include in target' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPMetaDatabaseAttributeOID + ".3.100 NAME 'olcMetaSub' DESC 'Placeholder to name a Target entry' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE X-ORDERED 'SIBLINGS' )",
}

var openLDAPMetaObjectClasses = []string{
	"( " + openLDAPMetaDatabaseObjectOID + ".3.2 NAME 'olcMetaConfig' DESC 'Meta backend configuration' SUP olcDatabaseConfig STRUCTURAL MAY ( olcDbConnTtl $ olcDbDnCacheTtl $ olcDbIdleTimeout $ olcDbOnErr $ olcDbPseudoRootBindDefer $ olcDbSingleConn $ olcDbUseTemporaryConn $ olcDbConnectionPoolMax $ olcDbBindTimeout $ olcDbCancel $ olcDbChaseReferrals $ olcDbClientPr $ olcDbDefaultTarget $ olcDbNetworkTimeout $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbNretries $ olcDbProtocolVersion $ olcDbQuarantine $ olcDbRebindAsUser $ olcDbSessionTrackingRequest $ olcDbStartTLS $ olcDbTFSupport ) )",
	"( " + openLDAPMetaDatabaseObjectOID + ".3.3 NAME 'olcMetaTargetConfig' DESC 'Meta target configuration' SUP olcConfig STRUCTURAL MUST ( olcMetaSub $ olcDbURI ) MAY ( olcDbIDAssertAuthzFrom $ olcDbIDAssertBind $ olcDbMap $ olcDbRewrite $ olcDbSubtreeExclude $ olcDbSubtreeInclude $ olcDbTimeout $ olcDbKeepalive $ olcDbTcpUserTimeout $ olcDbFilter $ olcDbBindTimeout $ olcDbCancel $ olcDbChaseReferrals $ olcDbClientPr $ olcDbDefaultTarget $ olcDbNetworkTimeout $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbNretries $ olcDbProtocolVersion $ olcDbQuarantine $ olcDbRebindAsUser $ olcDbSessionTrackingRequest $ olcDbStartTLS $ olcDbTFSupport ) )",
}

// RegisterOpenLDAPMetaSchema registers the cn=config schema exposed by
// OpenLDAP 2.6.13 for the back-meta fields ldap-go consumes. Legacy slapd.conf
// directives such as suffixmassage are not schema aliases.
func RegisterOpenLDAPMetaSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP back-meta schema: nil registry")
	}

	for _, description := range openLDAPMetaAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP back-meta attribute type: %w", err)
		}
		if err := registerCompatibleMetaAttribute(registry, attribute); err != nil {
			return err
		}
	}
	for _, description := range openLDAPMetaObjectClasses {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP back-meta object class: %w", err)
		}
		if err := registerCompatibleMetaObjectClass(registry, objectClass); err != nil {
			return err
		}
	}
	return nil
}

func registerCompatibleMetaAttribute(
	registry *Registry,
	want AttributeType,
) error {
	existing, found := registry.AttributeType(want.OID)
	for _, name := range want.Names {
		byName, ok := registry.AttributeType(name)
		if !ok {
			continue
		}
		if found && !strings.EqualFold(existing.OID, byName.OID) {
			return fmt.Errorf(
				"register OpenLDAP back-meta attribute type %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	if !found {
		if err := registry.RegisterAttributeType(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP back-meta attribute type %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if !compatibleMetaAttribute(existing, want) {
		return fmt.Errorf(
			"register OpenLDAP back-meta attribute type %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func compatibleMetaAttribute(got, want AttributeType) bool {
	gotUsage := got.Usage
	if gotUsage == "" {
		gotUsage = UsageUserApplications
	}
	wantUsage := want.Usage
	if wantUsage == "" {
		wantUsage = UsageUserApplications
	}
	return strings.EqualFold(got.OID, want.OID) &&
		metaContainsAllFold(got.Names, want.Names) &&
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
		metaExtensionsContain(got.Extensions, want.Extensions)
}

func registerCompatibleMetaObjectClass(
	registry *Registry,
	want ObjectClass,
) error {
	existing, found := registry.ObjectClass(want.OID)
	for _, name := range want.Names {
		byName, ok := registry.ObjectClass(name)
		if !ok {
			continue
		}
		if found && !strings.EqualFold(existing.OID, byName.OID) {
			return fmt.Errorf(
				"register OpenLDAP back-meta object class %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	if !found {
		if err := registry.RegisterObjectClass(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP back-meta object class %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if !compatibleMetaObjectClass(existing, want) {
		return fmt.Errorf(
			"register OpenLDAP back-meta object class %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func compatibleMetaObjectClass(got, want ObjectClass) bool {
	return strings.EqualFold(got.OID, want.OID) &&
		metaContainsAllFold(got.Names, want.Names) &&
		got.Obsolete == want.Obsolete &&
		got.Kind == want.Kind &&
		metaEqualFoldSet(got.Superiors, want.Superiors) &&
		metaEqualFoldSet(got.Must, want.Must) &&
		metaEqualFoldSet(got.May, want.May) &&
		metaExtensionsContain(got.Extensions, want.Extensions)
}

func metaContainsAllFold(values, required []string) bool {
	for _, target := range required {
		found := false
		for _, value := range values {
			if strings.EqualFold(value, target) {
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

func metaEqualFoldSet(left, right []string) bool {
	return len(left) == len(right) &&
		metaContainsAllFold(left, right) &&
		metaContainsAllFold(right, left)
}

func metaExtensionsContain(got, required map[string][]string) bool {
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
		if !found || !metaEqualFoldSet(gotValues, requiredValues) {
			return false
		}
	}
	return true
}
