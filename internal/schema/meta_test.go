package schema

import (
	"reflect"
	"strings"
	"testing"
)

func TestRegisterOpenLDAPMetaSchema(t *testing.T) {
	registry := NewRegistry()
	if err := RegisterOpenLDAPMetaSchema(registry); err != nil {
		t.Fatalf("RegisterOpenLDAPMetaSchema(): %v", err)
	}

	attributeTests := []struct {
		name        string
		oid         string
		description string
		equality    string
		syntax      string
		singleValue bool
		extensions  map[string][]string
	}{
		{
			name:        "olcDbURI",
			oid:         openLDAPMetaDatabaseAttributeOID + ".0.14",
			description: "URI (list) for remote DSA",
			equality:    "caseExactMatch",
			syntax:      SyntaxDirectoryString,
			singleValue: true,
		},
		{
			name:        "olcDbIDAssertBind",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.7",
			description: "Remote Identity Assertion administrative identity auth bind configuration",
			equality:    "caseIgnoreMatch",
			syntax:      SyntaxDirectoryString,
			singleValue: true,
		},
		{
			name:        "olcDbIDAssertAuthzFrom",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.9",
			description: "Remote Identity Assertion authz rules",
			equality:    "caseIgnoreMatch",
			syntax:      SyntaxDirectoryString,
			extensions:  map[string][]string{"X-ORDERED": {"VALUES"}},
		},
		{
			name:        "olcDbChaseReferrals",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.11",
			description: "Chase referrals",
			equality:    "booleanMatch",
			syntax:      SyntaxBoolean,
			singleValue: true,
		},
		{
			name:        "olcDbNetworkTimeout",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.17",
			description: "connection network timeout",
			equality:    "caseIgnoreMatch",
			syntax:      SyntaxDirectoryString,
			singleValue: true,
		},
		{
			name:        "olcDbRewrite",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.101",
			description: "DN rewriting rules",
			equality:    "caseIgnoreMatch",
			syntax:      SyntaxDirectoryString,
			extensions:  map[string][]string{"X-ORDERED": {"VALUES"}},
		},
		{
			name:        "olcDbBindTimeout",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.107",
			description: "bind timeout",
			equality:    "integerMatch",
			syntax:      SyntaxInteger,
			singleValue: true,
		},
		{
			name:        "olcDbNretries",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.110",
			description: "retry handling",
			equality:    "caseIgnoreMatch",
			syntax:      SyntaxDirectoryString,
			singleValue: true,
		},
		{
			name:        "olcMetaSub",
			oid:         openLDAPMetaDatabaseAttributeOID + ".3.100",
			description: "Placeholder to name a Target entry",
			equality:    "caseIgnoreMatch",
			syntax:      SyntaxDirectoryString,
			singleValue: true,
			extensions:  map[string][]string{"X-ORDERED": {"SIBLINGS"}},
		},
	}
	for _, test := range attributeTests {
		t.Run(test.name, func(t *testing.T) {
			attribute, ok := registry.AttributeType(test.name)
			if !ok {
				t.Fatalf("attribute type %q is not registered", test.name)
			}
			if attribute.OID != test.oid ||
				!reflect.DeepEqual(attribute.Names, []string{test.name}) ||
				attribute.Description != test.description ||
				attribute.Superior != "" ||
				attribute.Equality != test.equality ||
				attribute.Ordering != "" ||
				attribute.Substring != "" ||
				attribute.Syntax != test.syntax ||
				attribute.SingleValue != test.singleValue {
				t.Fatalf("attribute type %q = %#v", test.name, attribute)
			}
			if len(test.extensions) == 0 {
				if len(attribute.Extensions) != 0 {
					t.Fatalf("attribute type %q extensions = %v", test.name, attribute.Extensions)
				}
			} else if !reflect.DeepEqual(attribute.Extensions, test.extensions) {
				t.Fatalf("attribute type %q extensions = %v, want %v", test.name, attribute.Extensions, test.extensions)
			}
		})
	}

	objectClassTests := []struct {
		name        string
		oid         string
		description string
		superiors   []string
		must        []string
		may         []string
	}{
		{
			name:        "olcMetaConfig",
			oid:         openLDAPMetaDatabaseObjectOID + ".3.2",
			description: "Meta backend configuration",
			superiors:   []string{"olcDatabaseConfig"},
			may: []string{
				"olcDbConnTtl", "olcDbDnCacheTtl", "olcDbIdleTimeout",
				"olcDbOnErr", "olcDbPseudoRootBindDefer", "olcDbSingleConn",
				"olcDbUseTemporaryConn", "olcDbConnectionPoolMax",
				"olcDbBindTimeout", "olcDbCancel", "olcDbChaseReferrals",
				"olcDbClientPr", "olcDbDefaultTarget", "olcDbNetworkTimeout",
				"olcDbNoRefs", "olcDbNoUndefFilter", "olcDbNretries",
				"olcDbProtocolVersion", "olcDbQuarantine", "olcDbRebindAsUser",
				"olcDbSessionTrackingRequest", "olcDbStartTLS", "olcDbTFSupport",
			},
		},
		{
			name:        "olcMetaTargetConfig",
			oid:         openLDAPMetaDatabaseObjectOID + ".3.3",
			description: "Meta target configuration",
			superiors:   []string{"olcConfig"},
			must:        []string{"olcMetaSub", "olcDbURI"},
			may: []string{
				"olcDbIDAssertAuthzFrom", "olcDbIDAssertBind", "olcDbMap",
				"olcDbRewrite", "olcDbSubtreeExclude", "olcDbSubtreeInclude",
				"olcDbTimeout", "olcDbKeepalive", "olcDbTcpUserTimeout",
				"olcDbFilter", "olcDbBindTimeout", "olcDbCancel",
				"olcDbChaseReferrals", "olcDbClientPr", "olcDbDefaultTarget",
				"olcDbNetworkTimeout", "olcDbNoRefs", "olcDbNoUndefFilter",
				"olcDbNretries", "olcDbProtocolVersion", "olcDbQuarantine",
				"olcDbRebindAsUser", "olcDbSessionTrackingRequest",
				"olcDbStartTLS", "olcDbTFSupport",
			},
		},
	}
	for _, test := range objectClassTests {
		t.Run(test.name, func(t *testing.T) {
			objectClass, ok := registry.ObjectClass(test.name)
			if !ok {
				t.Fatalf("object class %q is not registered", test.name)
			}
			if objectClass.OID != test.oid ||
				!reflect.DeepEqual(objectClass.Names, []string{test.name}) ||
				objectClass.Description != test.description ||
				!reflect.DeepEqual(objectClass.Superiors, test.superiors) ||
				objectClass.Kind != ObjectClassStructural ||
				!reflect.DeepEqual(objectClass.Must, test.must) ||
				!reflect.DeepEqual(objectClass.May, test.may) {
				t.Fatalf("object class %q = %#v", test.name, objectClass)
			}
		})
	}

	for _, directive := range []string{"uri", "idassert-bind", "suffixmassage"} {
		if _, ok := registry.AttributeType(directive); ok {
			t.Fatalf("legacy directive %q was incorrectly registered as a schema alias", directive)
		}
	}
}

func TestRegisterOpenLDAPMetaSchemaIsIdempotent(t *testing.T) {
	registry := NewRegistry()
	for call := 1; call <= 2; call++ {
		if err := RegisterOpenLDAPMetaSchema(registry); err != nil {
			t.Fatalf("RegisterOpenLDAPMetaSchema() call %d: %v", call, err)
		}
	}
}

func TestRegisterOpenLDAPMetaSchemaReusesCompatibleDefinitions(t *testing.T) {
	registry := NewRegistry()
	attribute, err := ParseAttributeType(openLDAPMetaAttributeTypes[0])
	if err != nil {
		t.Fatalf("parse compatible attribute type: %v", err)
	}
	attribute.Description = "preloaded shared back-ldap definition"
	attribute.Names = append(attribute.Names, "preloadedMetaURI")
	attribute.Extensions["X-ORIGIN"] = []string{"local schema"}
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatalf("register compatible attribute type: %v", err)
	}

	objectClass, err := ParseObjectClass(openLDAPMetaObjectClasses[1])
	if err != nil {
		t.Fatalf("parse compatible object class: %v", err)
	}
	objectClass.Description = "preloaded back-meta target definition"
	objectClass.Names = append(objectClass.Names, "preloadedMetaTarget")
	objectClass.Extensions["X-ORIGIN"] = []string{"local schema"}
	if err := registry.RegisterObjectClass(objectClass); err != nil {
		t.Fatalf("register compatible object class: %v", err)
	}

	if err := RegisterOpenLDAPMetaSchema(registry); err != nil {
		t.Fatalf("RegisterOpenLDAPMetaSchema(): %v", err)
	}
	if _, ok := registry.AttributeType("preloadedMetaURI"); !ok {
		t.Fatal("compatible preloaded attribute alias was discarded")
	}
	if _, ok := registry.ObjectClass("preloadedMetaTarget"); !ok {
		t.Fatal("compatible preloaded object class alias was discarded")
	}
}

func TestRegisterOpenLDAPMetaSchemaRejectsAttributeConflict(t *testing.T) {
	registry := NewRegistry()
	attribute, err := ParseAttributeType(openLDAPMetaAttributeTypes[0])
	if err != nil {
		t.Fatalf("parse conflicting attribute type: %v", err)
	}
	attribute.Equality = "caseIgnoreMatch"
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatalf("register conflicting attribute type: %v", err)
	}

	err = RegisterOpenLDAPMetaSchema(registry)
	if err == nil || !strings.Contains(err.Error(), "incompatible existing definition") {
		t.Fatalf("RegisterOpenLDAPMetaSchema() error = %v", err)
	}
}

func TestRegisterOpenLDAPMetaSchemaRejectsIdentifierConflict(t *testing.T) {
	registry := NewRegistry()
	byOID, err := ParseAttributeType(openLDAPMetaAttributeTypes[0])
	if err != nil {
		t.Fatalf("parse OID definition: %v", err)
	}
	byOID.Names = []string{"preloadedMetaURI"}
	if err := registry.RegisterAttributeType(byOID); err != nil {
		t.Fatalf("register OID definition: %v", err)
	}
	byName := byOID
	byName.OID = openLDAPMetaDatabaseAttributeOID + ".9.999"
	byName.Names = []string{"olcDbURI"}
	if err := registry.RegisterAttributeType(byName); err != nil {
		t.Fatalf("register name definition: %v", err)
	}

	err = RegisterOpenLDAPMetaSchema(registry)
	if err == nil || !strings.Contains(err.Error(), "identifiers conflict") {
		t.Fatalf("RegisterOpenLDAPMetaSchema() error = %v", err)
	}
}

func TestRegisterOpenLDAPMetaSchemaRejectsObjectClassConflict(t *testing.T) {
	registry := NewRegistry()
	objectClass, err := ParseObjectClass(openLDAPMetaObjectClasses[1])
	if err != nil {
		t.Fatalf("parse conflicting object class: %v", err)
	}
	objectClass.Must = []string{"olcMetaSub"}
	if err := registry.RegisterObjectClass(objectClass); err != nil {
		t.Fatalf("register conflicting object class: %v", err)
	}

	err = RegisterOpenLDAPMetaSchema(registry)
	if err == nil || !strings.Contains(err.Error(), "incompatible existing definition") {
		t.Fatalf("RegisterOpenLDAPMetaSchema() error = %v", err)
	}
}

func TestRegisterOpenLDAPMetaSchemaRejectsNilRegistry(t *testing.T) {
	err := RegisterOpenLDAPMetaSchema(nil)
	if err == nil || err.Error() != "register OpenLDAP back-meta schema: nil registry" {
		t.Fatalf("RegisterOpenLDAPMetaSchema(nil) error = %v", err)
	}
}
