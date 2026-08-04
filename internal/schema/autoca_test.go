package schema

import (
	"strings"
	"testing"
)

func TestRegisterOpenLDAPAutoCASchema(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}

	// AutoCA is part of the server's built-in schema. Explicit registration
	// remains supported for callers that assemble or extend a registry.
	if err := RegisterOpenLDAPAutoCASchema(registry); err != nil {
		t.Fatalf("RegisterOpenLDAPAutoCASchema(): %v", err)
	}

	attributeTests := []struct {
		name        string
		oid         string
		description string
		superior    string
		equality    string
		syntax      string
		singleValue bool
	}{
		{"userCertificate", "2.5.4.36", "RFC2256: X.509 user certificate, use ;binary", "", "certificateExactMatch", openLDAPCertificateSyntax, false},
		{"cACertificate", "2.5.4.37", "RFC2256: X.509 CA certificate, use ;binary", "", "certificateExactMatch", openLDAPCertificateSyntax, false},
		{"pKCS8PrivateKey", "1.3.6.1.4.1.4203.666.1.60", "PKCS#8 PrivateKeyInfo, use ;binary", "", "privateKeyMatch", openLDAPPKCS8Syntax, false},
		{"cAPrivateKey", openLDAPAutoCASchemaOID + ".1.1", "X.509 CA private key, use ;binary", "pKCS8PrivateKey", "", "", false},
		{"userPrivateKey", openLDAPAutoCASchemaOID + ".1.2", "X.509 user private key, use ;binary", "pKCS8PrivateKey", "", "", false},
		{"olcAutoCAuserClass", openLDAPAutoCAConfigAttrOID + ".1", "ObjectClass of user entries", "", "caseIgnoreMatch", SyntaxDirectoryString, true},
		{"olcAutoCAserverClass", openLDAPAutoCAConfigAttrOID + ".2", "ObjectClass of server entries", "", "caseIgnoreMatch", SyntaxDirectoryString, true},
		{"olcAutoCAuserKeybits", openLDAPAutoCAConfigAttrOID + ".3", "Size of PrivateKey for user entries", "", "integerMatch", SyntaxInteger, true},
		{"olcAutoCAserverKeybits", openLDAPAutoCAConfigAttrOID + ".4", "Size of PrivateKey for server entries", "", "integerMatch", SyntaxInteger, true},
		{"olcAutoCAKeybits", openLDAPAutoCAConfigAttrOID + ".5", "Size of PrivateKey for CA certificate", "", "integerMatch", SyntaxInteger, true},
		{"olcAutoCAuserDays", openLDAPAutoCAConfigAttrOID + ".6", "Lifetime of user certificates in days", "", "integerMatch", SyntaxInteger, true},
		{"olcAutoCAserverDays", openLDAPAutoCAConfigAttrOID + ".7", "Lifetime of server certificates in days", "", "integerMatch", SyntaxInteger, true},
		{"olcAutoCADays", openLDAPAutoCAConfigAttrOID + ".8", "Lifetime of CA certificate in days", "", "integerMatch", SyntaxInteger, true},
		{"olcAutoCAlocalDN", openLDAPAutoCAConfigAttrOID + ".9", "DN of local server cert", "", "distinguishedNameMatch", SyntaxDistinguishedName, true},
		// olcAutoCAProfile is a ldap-go extension, not an OpenLDAP definition.
		{ldapGoAutoCAProfileAttrName, ldapGoAutoCAProfileAttrOID, "ldap-go AutoCA certificate profile", "", "caseIgnoreMatch", SyntaxDirectoryString, true},
	}
	for _, test := range attributeTests {
		t.Run(test.name, func(t *testing.T) {
			attribute, ok := registry.AttributeType(test.name)
			if !ok {
				t.Fatalf("attribute type %q is not registered", test.name)
			}
			if attribute.OID != test.oid ||
				attribute.Description != test.description ||
				attribute.Superior != test.superior ||
				attribute.Equality != test.equality ||
				attribute.Syntax != test.syntax ||
				attribute.SingleValue != test.singleValue {
				t.Fatalf("attribute type %q = %#v", test.name, attribute)
			}
		})
	}

	objectClassTests := []struct {
		name      string
		oid       string
		superiors []string
		kind      ObjectClassKind
		must      []string
		may       []string
	}{
		{"pkiUser", "2.5.6.21", []string{"top"}, ObjectClassAuxiliary, nil, []string{"userCertificate"}},
		{"pkiCA", "2.5.6.22", []string{"top"}, ObjectClassAuxiliary, nil, []string{"authorityRevocationList", "certificateRevocationList", "cACertificate", "crossCertificatePair"}},
		{"autoCA", openLDAPAutoCASchemaOID + ".2.1", []string{"pkiCA"}, ObjectClassAuxiliary, nil, []string{"cAPrivateKey"}},
		{"autoCAuser", openLDAPAutoCASchemaOID + ".2.2", []string{"pkiUser"}, ObjectClassAuxiliary, nil, []string{"userPrivateKey"}},
		{"olcAutoCAConfig", openLDAPAutoCAConfigObjectOID + ".1", []string{"olcOverlayConfig"}, ObjectClassStructural, nil, []string{
			"olcAutoCAuserClass", "olcAutoCAserverClass",
			"olcAutoCAuserKeybits", "olcAutoCAserverKeybits",
			"olcAutoCAKeybits", "olcAutoCAuserDays",
			"olcAutoCAserverDays", "olcAutoCADays", "olcAutoCAlocalDN",
			ldapGoAutoCAProfileAttrName,
		}},
	}

	// The profile selector is intentionally and explicitly a ldap-go extension.
	profile, ok := registry.AttributeType(ldapGoAutoCAProfileAttrName)
	if !ok {
		t.Fatalf("ldap-go extension %q is not registered", ldapGoAutoCAProfileAttrName)
	}
	if origins := profile.Extensions["X-ORIGIN"]; len(origins) != 1 || origins[0] != "ldap-go extension" {
		t.Fatalf("ldap-go extension %q X-ORIGIN = %q", ldapGoAutoCAProfileAttrName, origins)
	}
	for _, test := range objectClassTests {
		t.Run(test.name, func(t *testing.T) {
			objectClass, ok := registry.ObjectClass(test.name)
			if !ok {
				t.Fatalf("object class %q is not registered", test.name)
			}
			if objectClass.OID != test.oid || objectClass.Kind != test.kind ||
				!equalFoldSet(objectClass.Superiors, test.superiors) ||
				!equalFoldSet(objectClass.Must, test.must) ||
				!equalFoldSet(objectClass.May, test.may) {
				t.Fatalf("object class %q = %#v", test.name, objectClass)
			}
		})
	}

	for _, description := range []string{
		"cACertificate;binary", "cAPrivateKey;binary",
		"userCertificate;binary", "userPrivateKey;binary",
	} {
		attribute, ok := registry.AttributeType(description)
		if !ok {
			t.Fatalf("binary attribute description %q is unresolved", description)
		}
		if !strings.EqualFold(attribute.Name(), strings.TrimSuffix(description, ";binary")) {
			t.Fatalf("binary attribute description %q resolved to %q", description, attribute.Name())
		}
	}
}

func TestRegisterOpenLDAPAutoCASchemaWithLDAPGoProfileIsIdempotent(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := RegisterOpenLDAPAutoCASchema(registry); err != nil {
		t.Fatalf("first RegisterOpenLDAPAutoCASchema(): %v", err)
	}
	if err := RegisterOpenLDAPAutoCASchema(registry); err != nil {
		t.Fatalf("second RegisterOpenLDAPAutoCASchema(): %v", err)
	}
	config, ok := registry.ObjectClass("olcAutoCAConfig")
	if !ok || !containsFold(config.May, ldapGoAutoCAProfileAttrName) {
		t.Fatalf("idempotent registration lost ldap-go extension: %#v", config)
	}
}

func TestRegisterOpenLDAPAutoCASchemaReusesCompatibleDefinitions(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 2.5.4.36 NAME 'userCertificate' DESC 'preloaded core schema' EQUALITY certificateExactMatch SYNTAX " + openLDAPCertificateSyntax + " )",
		"( 2.5.6.21 NAME 'pkiUser' DESC 'preloaded PKI schema' SUP top AUXILIARY MAY userCertificate )",
	} {
		if strings.Contains(description, "2.5.4.36") {
			attribute, parseErr := ParseAttributeType(description)
			if parseErr != nil {
				t.Fatalf("parse preloaded attribute type: %v", parseErr)
			}
			if err := registry.UpsertAttributeType(attribute); err != nil {
				t.Fatalf("preload attribute type: %v", err)
			}
			continue
		}
		objectClass, parseErr := ParseObjectClass(description)
		if parseErr != nil {
			t.Fatalf("parse preloaded object class: %v", parseErr)
		}
		if err := registry.UpsertObjectClass(objectClass); err != nil {
			t.Fatalf("preload object class: %v", err)
		}
	}
	if err := RegisterOpenLDAPAutoCASchema(registry); err != nil {
		t.Fatalf("RegisterOpenLDAPAutoCASchema(): %v", err)
	}
}

func TestRegisterOpenLDAPAutoCASchemaReusesCompatibleLDAPGoProfileExtension(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	profile, err := ParseAttributeType(
		"( " + ldapGoAutoCAProfileAttrOID + " NAME '" + ldapGoAutoCAProfileAttrName + "' DESC 'preloaded ldap-go extension' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	)
	if err != nil {
		t.Fatalf("parse compatible ldap-go extension: %v", err)
	}
	if err := registry.UpsertAttributeType(profile); err != nil {
		t.Fatalf("preload compatible ldap-go extension: %v", err)
	}
	config, err := ParseObjectClass(openLDAPAutoCAObjectClasses[len(openLDAPAutoCAObjectClasses)-1])
	if err != nil {
		t.Fatalf("parse unmodified OpenLDAP olcAutoCAConfig: %v", err)
	}
	if err := registry.UpsertObjectClass(config); err != nil {
		t.Fatalf("preload unmodified OpenLDAP olcAutoCAConfig: %v", err)
	}

	if err := RegisterOpenLDAPAutoCASchema(registry); err != nil {
		t.Fatalf("RegisterOpenLDAPAutoCASchema(): %v", err)
	}
	updated, ok := registry.ObjectClass("olcAutoCAConfig")
	if !ok || !containsFold(updated.May, ldapGoAutoCAProfileAttrName) {
		t.Fatalf("compatible OpenLDAP config was not extended: %#v", updated)
	}
}

func TestRegisterOpenLDAPAutoCASchemaRejectsConflicts(t *testing.T) {
	registry := NewRegistry()
	if err := registry.ParseAndRegisterAttributeType(
		"( 2.5.4.36 NAME 'userCertificate' EQUALITY octetStringMatch SYNTAX " + SyntaxOctetString + " )",
	); err != nil {
		t.Fatalf("preload conflicting attribute type: %v", err)
	}
	err := RegisterOpenLDAPAutoCASchema(registry)
	if err == nil || !strings.Contains(err.Error(), "incompatible existing definition") {
		t.Fatalf("RegisterOpenLDAPAutoCASchema() error = %v", err)
	}
}

func TestRegisterOpenLDAPAutoCASchemaRejectsConflictingLDAPGoProfileExtension(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	profile, err := ParseAttributeType(
		"( " + ldapGoAutoCAProfileAttrOID + " NAME '" + ldapGoAutoCAProfileAttrName + "' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	)
	if err != nil {
		t.Fatalf("parse conflicting ldap-go extension: %v", err)
	}
	if err := registry.UpsertAttributeType(profile); err != nil {
		t.Fatalf("preload conflicting ldap-go extension: %v", err)
	}
	err = RegisterOpenLDAPAutoCASchema(registry)
	if err == nil || !strings.Contains(err.Error(), "incompatible existing definition") {
		t.Fatalf("RegisterOpenLDAPAutoCASchema() error = %v", err)
	}
}

func TestOpenLDAPAutoCADefinitionsRemainUnmodifiedByLDAPGoProfileExtension(t *testing.T) {
	for _, description := range openLDAPAutoCAAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			t.Fatalf("ParseAttributeType(): %v", err)
		}
		if strings.EqualFold(attribute.Name(), ldapGoAutoCAProfileAttrName) {
			t.Fatalf("ldap-go extension leaked into OpenLDAP attribute definitions")
		}
	}
	config, err := ParseObjectClass(openLDAPAutoCAObjectClasses[len(openLDAPAutoCAObjectClasses)-1])
	if err != nil {
		t.Fatalf("ParseObjectClass(): %v", err)
	}
	if containsFold(config.May, ldapGoAutoCAProfileAttrName) {
		t.Fatalf("ldap-go extension changed the stored OpenLDAP object class definition")
	}
}

func TestRegisterOpenLDAPAutoCASchemaRejectsNilRegistry(t *testing.T) {
	err := RegisterOpenLDAPAutoCASchema(nil)
	if err == nil || err.Error() != "register OpenLDAP AutoCA schema: nil registry" {
		t.Fatalf("RegisterOpenLDAPAutoCASchema(nil) error = %v", err)
	}
}
