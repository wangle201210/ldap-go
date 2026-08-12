package schema

import (
	"reflect"
	"strings"
	"testing"
)

func TestRegisterOpenLDAPSQLSchemaComplete(t *testing.T) {
	type expectedAttribute struct {
		suffix      string
		name        string
		description string
		equality    string
		syntax      string
		singleValue bool
	}
	expected := []expectedAttribute{
		{".1", "olcDbHost", "Hostname of SQL server", "caseExactMatch", SyntaxDirectoryString, true},
		{".2", "olcDbName", "Name of SQL database", "caseExactMatch", SyntaxDirectoryString, true},
		{".3", "olcDbUser", "Username for SQL session", "caseExactMatch", SyntaxDirectoryString, true},
		{".4", "olcDbPass", "Password for SQL session", "caseExactMatch", SyntaxDirectoryString, true},
		{".20", "olcSqlConcatPattern", "Pattern used to concatenate strings", "caseExactMatch", SyntaxDirectoryString, true},
		{".21", "olcSqlSubtreeCond", "Where-clause template for a subtree search condition", "caseExactMatch", SyntaxDirectoryString, true},
		{".22", "olcSqlChildrenCond", "Where-clause template for a children search condition", "caseExactMatch", SyntaxDirectoryString, true},
		{".23", "olcSqlDnMatchCond", "Where-clause template for a DN match search condition", "caseExactMatch", SyntaxDirectoryString, true},
		{".24", "olcSqlOcQuery", "Query used to collect objectClass mapping data", "caseExactMatch", SyntaxDirectoryString, true},
		{".25", "olcSqlAtQuery", "Query used to collect attributeType mapping data", "caseExactMatch", SyntaxDirectoryString, true},
		{".26", "olcSqlInsEntryStmt", "Statement used to insert a new entry", "caseExactMatch", SyntaxDirectoryString, true},
		{".27", "olcSqlCreateNeedsSelect", "Whether entry creation needs a subsequent select", "booleanMatch", SyntaxBoolean, true},
		{".28", "olcSqlUpperFunc", "Function that converts a value to uppercase", "caseExactMatch", SyntaxDirectoryString, true},
		{".29", "olcSqlUpperNeedsCast", "Whether olcSqlUpperFunc needs an explicit cast", "booleanMatch", SyntaxBoolean, true},
		{".30", "olcSqlStrcastFunc", "Function that converts a value to a string", "caseExactMatch", SyntaxDirectoryString, true},
		{".31", "olcSqlDelEntryStmt", "Statement used to delete an existing entry", "caseExactMatch", SyntaxDirectoryString, true},
		{".32", "olcSqlRenEntryStmt", "Statement used to rename an entry", "caseExactMatch", SyntaxDirectoryString, true},
		{".33", "olcSqlDelObjclassesStmt", "Statement used to delete the ID of an entry", "caseExactMatch", SyntaxDirectoryString, true},
		{".34", "olcSqlHasLDAPinfoDnRu", "Whether the dn_ru column is present", "booleanMatch", SyntaxBoolean, true},
		{".35", "olcSqlFailIfNoMapping", "Whether to fail on unknown attribute mappings", "booleanMatch", SyntaxBoolean, true},
		{".36", "olcSqlAllowOrphans", "Whether to allow adding entries with no parent", "booleanMatch", SyntaxBoolean, true},
		{".37", "olcSqlBaseObject", "Manage an in-memory baseObject entry", "caseExactMatch", SyntaxDirectoryString, true},
		{".38", "olcSqlLayer", "Helper used to map DNs between LDAP and SQL", "caseExactMatch", SyntaxDirectoryString, false},
		{".39", "olcSqlUseSubtreeShortcut", "Collect all entries when searchBase is DB suffix", "booleanMatch", SyntaxBoolean, true},
		{".40", "olcSqlFetchAllAttrs", "Require all attributes to always be loaded", "booleanMatch", SyntaxBoolean, true},
		{".41", "olcSqlFetchAttrs", "Set of attributes to always fetch", "caseIgnoreMatch", SyntaxDirectoryString, true},
		{".42", "olcSqlCheckSchema", "Check schema after modifications", "booleanMatch", SyntaxBoolean, true},
		{".43", "olcSqlAliasingKeyword", "The aliasing keyword", "caseExactMatch", SyntaxDirectoryString, true},
		{".44", "olcSqlAliasingQuote", "Quoting char of the aliasing keyword", "caseIgnoreMatch", SyntaxDirectoryString, true},
		{".45", "olcSqlAutocommit", "", "booleanMatch", SyntaxBoolean, true},
		{".46", "olcSqlIdQuery", "Query used to collect entryID mapping data", "caseExactMatch", SyntaxDirectoryString, true},
	}
	if len(expected) != 31 {
		t.Fatalf("test fixture contains %d attribute types, want 31", len(expected))
	}
	if len(openLDAPSQLAttributeTypes) != len(expected) {
		t.Fatalf("OpenLDAP back-sql attribute descriptions = %d, want %d", len(openLDAPSQLAttributeTypes), len(expected))
	}

	registry := NewRegistry()
	if err := RegisterOpenLDAPSQLSchema(registry); err != nil {
		t.Fatalf("RegisterOpenLDAPSQLSchema(): %v", err)
	}
	if got := len(registry.AttributeTypeDescriptions()); got != len(expected) {
		t.Fatalf("registered attribute types = %d, want %d", got, len(expected))
	}
	if got := len(registry.ObjectClassDescriptions()); got != 1 {
		t.Fatalf("registered object classes = %d, want 1", got)
	}

	for _, want := range expected {
		t.Run(want.name, func(t *testing.T) {
			attribute, ok := registry.AttributeType(want.name)
			if !ok {
				t.Fatalf("attribute type %q is not registered", want.name)
			}
			if attribute.OID != openLDAPSQLDatabaseAttributeOID+want.suffix ||
				!reflect.DeepEqual(attribute.Names, []string{want.name}) ||
				attribute.Description != want.description ||
				attribute.Superior != "" ||
				attribute.Equality != want.equality ||
				attribute.Ordering != "" ||
				attribute.Substring != "" ||
				attribute.Syntax != want.syntax ||
				attribute.SyntaxLength != 0 ||
				attribute.Obsolete ||
				attribute.SingleValue != want.singleValue ||
				attribute.Collective ||
				attribute.NoUserModification ||
				attribute.Usage != UsageUserApplications ||
				len(attribute.Extensions) != 0 {
				t.Fatalf("attribute type %q = %#v", want.name, attribute)
			}
		})
	}

	objectClass, ok := registry.ObjectClass("olcSqlConfig")
	if !ok {
		t.Fatal("olcSqlConfig is not registered")
	}
	wantMay := []string{
		"olcDbHost",
		"olcDbUser",
		"olcDbPass",
		"olcSqlConcatPattern",
		"olcSqlSubtreeCond",
		"olcsqlChildrenCond",
		"olcSqlDnMatchCond",
		"olcSqlOcQuery",
		"olcSqlAtQuery",
		"olcSqlInsEntryStmt",
		"olcSqlCreateNeedsSelect",
		"olcSqlUpperFunc",
		"olcSqlUpperNeedsCast",
		"olcSqlStrCastFunc",
		"olcSqlDelEntryStmt",
		"olcSqlRenEntryStmt",
		"olcSqlDelObjClassesStmt",
		"olcSqlHasLDAPInfoDnRu",
		"olcSqlFailIfNoMapping",
		"olcSqlAllowOrphans",
		"olcSqlBaseObject",
		"olcSqlLayer",
		"olcSqlUseSubtreeShortcut",
		"olcSqlFetchAllAttrs",
		"olcSqlFetchAttrs",
		"olcSqlCheckSchema",
		"olcSqlAliasingKeyword",
		"olcSqlAliasingQuote",
		"olcSqlAutocommit",
		"olcSqlIdQuery",
	}
	if objectClass.OID != openLDAPSQLDatabaseObjectOID+".1" ||
		!reflect.DeepEqual(objectClass.Names, []string{"olcSqlConfig"}) ||
		objectClass.Description != "SQL backend configuration" ||
		!reflect.DeepEqual(objectClass.Superiors, []string{"olcDatabaseConfig"}) ||
		objectClass.Kind != ObjectClassStructural ||
		!reflect.DeepEqual(objectClass.Must, []string{"olcDbName"}) ||
		!reflect.DeepEqual(objectClass.May, wantMay) ||
		len(objectClass.Extensions) != 0 {
		t.Fatalf("olcSqlConfig = %#v", objectClass)
	}

	for _, description := range openLDAPSQLAttributeTypes {
		if _, err := ParseAttributeType(description); err != nil {
			t.Fatalf("parse emitted attribute type %q: %v", description, err)
		}
	}
	for _, description := range openLDAPSQObjectClasses {
		if _, err := ParseObjectClass(description); err != nil {
			t.Fatalf("parse emitted object class %q: %v", description, err)
		}
	}
}

func TestRegisterOpenLDAPSQLSchemaIsIdempotentAndCompatible(t *testing.T) {
	registry := NewRegistry()
	attribute, err := ParseAttributeType(openLDAPSQLAttributeTypes[0])
	if err != nil {
		t.Fatalf("parse compatible attribute type: %v", err)
	}
	attribute.Description = "preloaded SQL host definition"
	attribute.Names = append(attribute.Names, "preloadedSQLHost")
	attribute.Extensions["X-ORIGIN"] = []string{"local schema"}
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatalf("register compatible attribute type: %v", err)
	}
	objectClass, err := ParseObjectClass(openLDAPSQObjectClasses[0])
	if err != nil {
		t.Fatalf("parse compatible object class: %v", err)
	}
	objectClass.Description = "preloaded SQL backend definition"
	objectClass.Names = append(objectClass.Names, "preloadedSQLConfig")
	objectClass.Extensions["X-ORIGIN"] = []string{"local schema"}
	if err := registry.RegisterObjectClass(objectClass); err != nil {
		t.Fatalf("register compatible object class: %v", err)
	}

	for call := 1; call <= 2; call++ {
		if err := RegisterOpenLDAPSQLSchema(registry); err != nil {
			t.Fatalf("RegisterOpenLDAPSQLSchema() call %d: %v", call, err)
		}
	}
	if _, ok := registry.AttributeType("preloadedSQLHost"); !ok {
		t.Fatal("compatible attribute alias was discarded")
	}
	if _, ok := registry.ObjectClass("preloadedSQLConfig"); !ok {
		t.Fatal("compatible object class alias was discarded")
	}
}

func TestRegisterOpenLDAPSQLSchemaRejectsConflicts(t *testing.T) {
	t.Run("nil registry", func(t *testing.T) {
		err := RegisterOpenLDAPSQLSchema(nil)
		if err == nil || err.Error() != "register OpenLDAP back-sql schema: nil registry" {
			t.Fatalf("RegisterOpenLDAPSQLSchema(nil) error = %v", err)
		}
	})

	t.Run("incompatible attribute", func(t *testing.T) {
		registry := NewRegistry()
		attribute, err := ParseAttributeType(openLDAPSQLAttributeTypes[0])
		if err != nil {
			t.Fatalf("parse attribute type: %v", err)
		}
		attribute.Equality = "caseIgnoreMatch"
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatalf("register attribute type: %v", err)
		}
		err = RegisterOpenLDAPSQLSchema(registry)
		if err == nil || !strings.Contains(err.Error(), "incompatible existing definition") {
			t.Fatalf("RegisterOpenLDAPSQLSchema() error = %v", err)
		}
	})

	t.Run("attribute identifier conflict", func(t *testing.T) {
		registry := NewRegistry()
		byOID, err := ParseAttributeType(openLDAPSQLAttributeTypes[0])
		if err != nil {
			t.Fatalf("parse OID attribute type: %v", err)
		}
		byOID.Names = []string{"otherSQLHost"}
		if err := registry.RegisterAttributeType(byOID); err != nil {
			t.Fatalf("register OID attribute type: %v", err)
		}
		byName, err := ParseAttributeType(openLDAPSQLAttributeTypes[0])
		if err != nil {
			t.Fatalf("parse named attribute type: %v", err)
		}
		byName.OID = openLDAPSQLDatabaseAttributeOID + ".999"
		if err := registry.RegisterAttributeType(byName); err != nil {
			t.Fatalf("register named attribute type: %v", err)
		}
		err = RegisterOpenLDAPSQLSchema(registry)
		if err == nil || !strings.Contains(err.Error(), "identifiers conflict") {
			t.Fatalf("RegisterOpenLDAPSQLSchema() error = %v", err)
		}
	})

	t.Run("incompatible object class", func(t *testing.T) {
		registry := NewRegistry()
		objectClass, err := ParseObjectClass(openLDAPSQObjectClasses[0])
		if err != nil {
			t.Fatalf("parse object class: %v", err)
		}
		objectClass.Must = nil
		if err := registry.RegisterObjectClass(objectClass); err != nil {
			t.Fatalf("register object class: %v", err)
		}
		err = RegisterOpenLDAPSQLSchema(registry)
		if err == nil || !strings.Contains(err.Error(), "incompatible existing definition") {
			t.Fatalf("RegisterOpenLDAPSQLSchema() error = %v", err)
		}
	})
}

func TestNewBuiltinRegistryIncludesOpenLDAPSQLSchema(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if _, ok := registry.AttributeType("olcSqlIdQuery"); !ok {
		t.Fatal("olcSqlIdQuery is not registered by NewBuiltinRegistry")
	}
	if _, ok := registry.ObjectClass("olcSqlConfig"); !ok {
		t.Fatal("olcSqlConfig is not registered by NewBuiltinRegistry")
	}
}
