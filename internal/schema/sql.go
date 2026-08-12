package schema

import (
	"fmt"
	"strings"
)

const (
	openLDAPSQLDatabaseAttributeOID = "1.3.6.1.4.1.4203.1.12.2.3.2.6"
	openLDAPSQLDatabaseObjectOID    = "1.3.6.1.4.1.4203.1.12.2.4.2.6"
)

var openLDAPSQLAttributeTypes = []string{
	"( " + openLDAPSQLDatabaseAttributeOID + ".1 NAME 'olcDbHost' DESC 'Hostname of SQL server' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".2 NAME 'olcDbName' DESC 'Name of SQL database' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".3 NAME 'olcDbUser' DESC 'Username for SQL session' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".4 NAME 'olcDbPass' DESC 'Password for SQL session' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".20 NAME 'olcSqlConcatPattern' DESC 'Pattern used to concatenate strings' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".21 NAME 'olcSqlSubtreeCond' DESC 'Where-clause template for a subtree search condition' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".22 NAME 'olcSqlChildrenCond' DESC 'Where-clause template for a children search condition' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".23 NAME 'olcSqlDnMatchCond' DESC 'Where-clause template for a DN match search condition' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".24 NAME 'olcSqlOcQuery' DESC 'Query used to collect objectClass mapping data' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".25 NAME 'olcSqlAtQuery' DESC 'Query used to collect attributeType mapping data' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".26 NAME 'olcSqlInsEntryStmt' DESC 'Statement used to insert a new entry' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".27 NAME 'olcSqlCreateNeedsSelect' DESC 'Whether entry creation needs a subsequent select' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".28 NAME 'olcSqlUpperFunc' DESC 'Function that converts a value to uppercase' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".29 NAME 'olcSqlUpperNeedsCast' DESC 'Whether olcSqlUpperFunc needs an explicit cast' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".30 NAME 'olcSqlStrcastFunc' DESC 'Function that converts a value to a string' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".31 NAME 'olcSqlDelEntryStmt' DESC 'Statement used to delete an existing entry' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".32 NAME 'olcSqlRenEntryStmt' DESC 'Statement used to rename an entry' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".33 NAME 'olcSqlDelObjclassesStmt' DESC 'Statement used to delete the ID of an entry' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".34 NAME 'olcSqlHasLDAPinfoDnRu' DESC 'Whether the dn_ru column is present' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".35 NAME 'olcSqlFailIfNoMapping' DESC 'Whether to fail on unknown attribute mappings' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".36 NAME 'olcSqlAllowOrphans' DESC 'Whether to allow adding entries with no parent' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".37 NAME 'olcSqlBaseObject' DESC 'Manage an in-memory baseObject entry' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".38 NAME 'olcSqlLayer' DESC 'Helper used to map DNs between LDAP and SQL' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".39 NAME 'olcSqlUseSubtreeShortcut' DESC 'Collect all entries when searchBase is DB suffix' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".40 NAME 'olcSqlFetchAllAttrs' DESC 'Require all attributes to always be loaded' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".41 NAME 'olcSqlFetchAttrs' DESC 'Set of attributes to always fetch' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".42 NAME 'olcSqlCheckSchema' DESC 'Check schema after modifications' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".43 NAME 'olcSqlAliasingKeyword' DESC 'The aliasing keyword' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".44 NAME 'olcSqlAliasingQuote' DESC 'Quoting char of the aliasing keyword' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".45 NAME 'olcSqlAutocommit' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( " + openLDAPSQLDatabaseAttributeOID + ".46 NAME 'olcSqlIdQuery' DESC 'Query used to collect entryID mapping data' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
}

var openLDAPSQObjectClasses = []string{
	"( " + openLDAPSQLDatabaseObjectOID + ".1 NAME 'olcSqlConfig' DESC 'SQL backend configuration' SUP olcDatabaseConfig MUST olcDbName MAY ( olcDbHost $ olcDbUser $ olcDbPass $ olcSqlConcatPattern $ olcSqlSubtreeCond $ olcsqlChildrenCond $ olcSqlDnMatchCond $ olcSqlOcQuery $ olcSqlAtQuery $ olcSqlInsEntryStmt $ olcSqlCreateNeedsSelect $ olcSqlUpperFunc $ olcSqlUpperNeedsCast $ olcSqlStrCastFunc $ olcSqlDelEntryStmt $ olcSqlRenEntryStmt $ olcSqlDelObjClassesStmt $ olcSqlHasLDAPInfoDnRu $ olcSqlFailIfNoMapping $ olcSqlAllowOrphans $ olcSqlBaseObject $ olcSqlLayer $ olcSqlUseSubtreeShortcut $ olcSqlFetchAllAttrs $ olcSqlFetchAttrs $ olcSqlCheckSchema $ olcSqlAliasingKeyword $ olcSqlAliasingQuote $ olcSqlAutocommit $ olcSqlIdQuery ) )",
}

// RegisterOpenLDAPSQLSchema registers the cn=config schema exposed by the
// OpenLDAP 2.6.13 back-sql database backend.
func RegisterOpenLDAPSQLSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP back-sql schema: nil registry")
	}

	for _, description := range openLDAPSQLAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP back-sql attribute type: %w", err)
		}
		if err := registerCompatibleSQLAttribute(registry, attribute); err != nil {
			return err
		}
	}
	for _, description := range openLDAPSQObjectClasses {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP back-sql object class: %w", err)
		}
		if err := registerCompatibleSQLObjectClass(registry, objectClass); err != nil {
			return err
		}
	}
	return nil
}

func registerCompatibleSQLAttribute(registry *Registry, want AttributeType) error {
	existing, found, err := findSQLAttribute(registry, want)
	if err != nil {
		return err
	}
	if !found {
		if err := registry.RegisterAttributeType(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP back-sql attribute type %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if !compatibleSQLAttribute(existing, want) {
		return fmt.Errorf(
			"register OpenLDAP back-sql attribute type %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func findSQLAttribute(
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
				"register OpenLDAP back-sql attribute type %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	return existing, found, nil
}

func compatibleSQLAttribute(got, want AttributeType) bool {
	gotUsage := got.Usage
	if gotUsage == "" {
		gotUsage = UsageUserApplications
	}
	wantUsage := want.Usage
	if wantUsage == "" {
		wantUsage = UsageUserApplications
	}
	return strings.EqualFold(got.OID, want.OID) &&
		sqlContainsAllFold(got.Names, want.Names) &&
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
		sqlExtensionsContain(got.Extensions, want.Extensions)
}

func registerCompatibleSQLObjectClass(registry *Registry, want ObjectClass) error {
	existing, found, err := findSQLObjectClass(registry, want)
	if err != nil {
		return err
	}
	if !found {
		if err := registry.RegisterObjectClass(want); err != nil {
			return fmt.Errorf(
				"register OpenLDAP back-sql object class %q: %w",
				want.Name(), err,
			)
		}
		return nil
	}
	if !compatibleSQLObjectClass(existing, want) {
		return fmt.Errorf(
			"register OpenLDAP back-sql object class %q: incompatible existing definition",
			want.Name(),
		)
	}
	return nil
}

func findSQLObjectClass(
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
				"register OpenLDAP back-sql object class %q: identifiers conflict",
				want.Name(),
			)
		}
		existing, found = byName, true
	}
	return existing, found, nil
}

func compatibleSQLObjectClass(got, want ObjectClass) bool {
	return strings.EqualFold(got.OID, want.OID) &&
		sqlContainsAllFold(got.Names, want.Names) &&
		got.Obsolete == want.Obsolete &&
		got.Kind == want.Kind &&
		sqlEqualFoldSet(got.Superiors, want.Superiors) &&
		sqlEqualFoldSet(got.Must, want.Must) &&
		sqlEqualFoldSet(got.May, want.May) &&
		sqlExtensionsContain(got.Extensions, want.Extensions)
}

func sqlContainsAllFold(values, required []string) bool {
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

func sqlEqualFoldSet(left, right []string) bool {
	return len(left) == len(right) &&
		sqlContainsAllFold(left, right) &&
		sqlContainsAllFold(right, left)
}

func sqlExtensionsContain(got, required map[string][]string) bool {
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
		if !found || !sqlEqualFoldSet(gotValues, requiredValues) {
			return false
		}
	}
	return true
}
