package schema

import (
	"fmt"
	"slices"
	"strings"
)

const (
	openLDAPAutoCASchemaOID       = "1.3.6.1.4.1.4203.666.11.11"
	openLDAPAutoCAConfigAttrOID   = "1.3.6.1.4.1.4203.1.12.2.3.3.22"
	openLDAPAutoCAConfigObjectOID = "1.3.6.1.4.1.4203.1.12.2.4.3.22"
	openLDAPCertificateSyntax     = "1.3.6.1.4.1.1466.115.121.1.8"
	openLDAPPKCS8Syntax           = "1.2.840.113549.1.8.1.1"
	ldapGoAutoCAProfileAttrOID    = openLDAPAutoCAConfigAttrOID + ".10"
	ldapGoAutoCAProfileAttrName   = "olcAutoCAProfile"
)

var openLDAPAutoCAFoundationAttributeTypes = []string{
	"( 2.5.4.36 NAME 'userCertificate' DESC 'RFC2256: X.509 user certificate, use ;binary' EQUALITY certificateExactMatch SYNTAX " + openLDAPCertificateSyntax + " )",
	"( 2.5.4.37 NAME 'cACertificate' DESC 'RFC2256: X.509 CA certificate, use ;binary' EQUALITY certificateExactMatch SYNTAX " + openLDAPCertificateSyntax + " )",
	"( 1.3.6.1.4.1.4203.666.1.60 NAME 'pKCS8PrivateKey' DESC 'PKCS#8 PrivateKeyInfo, use ;binary' EQUALITY privateKeyMatch SYNTAX " + openLDAPPKCS8Syntax + " )",
}

var openLDAPAutoCAAttributeTypes = []string{
	"( " + openLDAPAutoCASchemaOID + ".1.1 NAME 'cAPrivateKey' DESC 'X.509 CA private key, use ;binary' SUP pKCS8PrivateKey )",
	"( " + openLDAPAutoCASchemaOID + ".1.2 NAME 'userPrivateKey' DESC 'X.509 user private key, use ;binary' SUP pKCS8PrivateKey )",
	"( " + openLDAPAutoCAConfigAttrOID + ".1 NAME 'olcAutoCAuserClass' DESC 'ObjectClass of user entries' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".2 NAME 'olcAutoCAserverClass' DESC 'ObjectClass of server entries' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".3 NAME 'olcAutoCAuserKeybits' DESC 'Size of PrivateKey for user entries' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".4 NAME 'olcAutoCAserverKeybits' DESC 'Size of PrivateKey for server entries' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".5 NAME 'olcAutoCAKeybits' DESC 'Size of PrivateKey for CA certificate' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".6 NAME 'olcAutoCAuserDays' DESC 'Lifetime of user certificates in days' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".7 NAME 'olcAutoCAserverDays' DESC 'Lifetime of server certificates in days' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".8 NAME 'olcAutoCADays' DESC 'Lifetime of CA certificate in days' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAutoCAConfigAttrOID + ".9 NAME 'olcAutoCAlocalDN' DESC 'DN of local server cert' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
}

var ldapGoAutoCAExtensionAttributeTypes = []string{
	"( " + ldapGoAutoCAProfileAttrOID + " NAME '" + ldapGoAutoCAProfileAttrName + "' DESC 'ldap-go AutoCA certificate profile' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE X-ORIGIN 'ldap-go extension' )",
}

var openLDAPAutoCAFoundationObjectClasses = []string{
	"( 2.5.6.21 NAME 'pkiUser' DESC 'RFC2587: a PKI user' SUP top AUXILIARY MAY userCertificate )",
	"( 2.5.6.22 NAME 'pkiCA' DESC 'RFC2587: PKI certificate authority' SUP top AUXILIARY MAY ( authorityRevocationList $ certificateRevocationList $ cACertificate $ crossCertificatePair ) )",
}

var openLDAPAutoCAObjectClasses = []string{
	"( " + openLDAPAutoCASchemaOID + ".2.1 NAME 'autoCA' DESC 'Automated PKI certificate authority' SUP pkiCA AUXILIARY MAY cAPrivateKey )",
	"( " + openLDAPAutoCASchemaOID + ".2.2 NAME 'autoCAuser' DESC 'Automated PKI CA user' SUP pkiUser AUXILIARY MAY userPrivateKey )",
	"( " + openLDAPAutoCAConfigObjectOID + ".1 NAME 'olcAutoCAConfig' DESC 'AutoCA configuration' SUP olcOverlayConfig MAY ( olcAutoCAuserClass $ olcAutoCAserverClass $ olcAutoCAuserKeybits $ olcAutoCAserverKeybits $ olcAutoCAKeybits $ olcAutoCAuserDays $ olcAutoCAserverDays $ olcAutoCADays $ olcAutoCAlocalDN ) )",
}

// RegisterOpenLDAPAutoCASchema registers the schema consumed by OpenLDAP
// 2.6.13's autoca overlay plus the explicitly labelled ldap-go profile
// extension. It does not install Search hooks or key generation.
func RegisterOpenLDAPAutoCASchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP AutoCA schema: nil registry")
	}

	attributeGroups := [][]string{
		openLDAPAutoCAFoundationAttributeTypes,
		openLDAPAutoCAAttributeTypes,
		ldapGoAutoCAExtensionAttributeTypes,
	}
	for _, descriptions := range attributeGroups {
		for _, description := range descriptions {
			attribute, err := ParseAttributeType(description)
			if err != nil {
				return fmt.Errorf("parse OpenLDAP AutoCA attribute type: %w", err)
			}
			if err := registerCompatibleAutoCAAttribute(registry, attribute); err != nil {
				return err
			}
		}
	}

	objectClassGroups := [][]string{
		openLDAPAutoCAFoundationObjectClasses,
		openLDAPAutoCAObjectClasses,
	}
	for _, descriptions := range objectClassGroups {
		for _, description := range descriptions {
			objectClass, err := ParseObjectClass(description)
			if err != nil {
				return fmt.Errorf("parse OpenLDAP AutoCA object class: %w", err)
			}
			objectClass = extendAutoCAConfigWithLDAPGoProfile(objectClass)
			if err := registerCompatibleAutoCAObjectClass(registry, objectClass); err != nil {
				return err
			}
		}
	}
	return nil
}

func extendAutoCAConfigWithLDAPGoProfile(objectClass ObjectClass) ObjectClass {
	if !strings.EqualFold(objectClass.Name(), "olcAutoCAConfig") ||
		containsFold(objectClass.May, ldapGoAutoCAProfileAttrName) {
		return objectClass
	}
	objectClass.May = append(objectClass.May, ldapGoAutoCAProfileAttrName)
	return objectClass
}

func registerCompatibleAutoCAAttribute(
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
				"register OpenLDAP AutoCA attribute type %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	if !found {
		if err := registry.RegisterAttributeType(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP AutoCA attribute type %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if !compatibleAutoCAAttribute(existing, want) {
		return fmt.Errorf(
			"register OpenLDAP AutoCA attribute type %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func compatibleAutoCAAttribute(got, want AttributeType) bool {
	gotUsage := got.Usage
	if gotUsage == "" {
		gotUsage = UsageUserApplications
	}
	wantUsage := want.Usage
	if wantUsage == "" {
		wantUsage = UsageUserApplications
	}
	return strings.EqualFold(got.OID, want.OID) &&
		containsFold(got.Names, want.Name()) &&
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
		gotUsage == wantUsage
}

func registerCompatibleAutoCAObjectClass(
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
				"register OpenLDAP AutoCA object class %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	if !found {
		if err := registry.RegisterObjectClass(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP AutoCA object class %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if strings.EqualFold(want.Name(), "olcAutoCAConfig") {
		openLDAPDefinition := cloneObjectClass(want)
		openLDAPDefinition.May = slices.DeleteFunc(
			openLDAPDefinition.May,
			func(value string) bool {
				return strings.EqualFold(value, ldapGoAutoCAProfileAttrName)
			},
		)
		if compatibleAutoCAObjectClass(existing, openLDAPDefinition) {
			if err := registry.UpsertObjectClass(want); err != nil {
				return fmt.Errorf(
					"extend OpenLDAP AutoCA object class %q: %w",
					want.Name(), err,
				)
			}
			return nil
		}
	}
	if !compatibleAutoCAObjectClass(existing, want) {
		if compatibleOpenLDAPAutoCAConfigWithoutProfile(existing, want) {
			if err := registry.UpsertObjectClass(want); err != nil {
				return fmt.Errorf(
					"register OpenLDAP AutoCA object class %q: %w",
					want.Name(), err,
				)
			}
			return nil
		}
		return fmt.Errorf(
			"register OpenLDAP AutoCA object class %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func compatibleOpenLDAPAutoCAConfigWithoutProfile(got, want ObjectClass) bool {
	if !strings.EqualFold(want.Name(), "olcAutoCAConfig") ||
		!containsFold(want.May, ldapGoAutoCAProfileAttrName) ||
		containsFold(got.May, ldapGoAutoCAProfileAttrName) {
		return false
	}
	withoutProfile := want
	withoutProfile.May = slices.DeleteFunc(
		append([]string(nil), want.May...),
		func(value string) bool {
			return strings.EqualFold(value, ldapGoAutoCAProfileAttrName)
		},
	)
	return compatibleAutoCAObjectClass(got, withoutProfile)
}

func compatibleAutoCAObjectClass(got, want ObjectClass) bool {
	return strings.EqualFold(got.OID, want.OID) &&
		containsFold(got.Names, want.Name()) &&
		got.Obsolete == want.Obsolete &&
		got.Kind == want.Kind &&
		equalFoldSet(got.Superiors, want.Superiors) &&
		equalFoldSet(got.Must, want.Must) &&
		equalFoldSet(got.May, want.May)
}

func containsFold(values []string, target string) bool {
	return slices.ContainsFunc(values, func(value string) bool {
		return strings.EqualFold(value, target)
	})
}

func equalFoldSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !containsFold(right, value) {
			return false
		}
	}
	return true
}
