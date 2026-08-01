package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseOpenLDAPConstraintRules(t *testing.T) {
	t.Parallel()

	database := constraintTestDatabase(t)
	tests := []struct {
		name  string
		raw   string
		kind  constraintKind
		check func(*testing.T, constraintRule)
	}{
		{
			name: "ordered regex",
			raw:  "{0}mail regex ^[[:alnum:]]+@example.com$",
			kind: constraintRegex,
			check: func(t *testing.T, rule constraintRule) {
				if !rule.regular.MatchString("alice@example.com") ||
					rule.regular.MatchString("alice@invalid.example") {
					t.Fatalf("compiled regex does not match POSIX ERE: %v", rule.regular)
				}
			},
		},
		{
			name: "negative regex",
			raw:  "mail negregex '@notallowed\\.example$'",
			kind: constraintNegativeRegex,
		},
		{
			name: "size",
			raw:  "jpegPhoto size 131072",
			kind: constraintSize,
			check: func(t *testing.T, rule constraintRule) {
				if rule.limit != 131072 {
					t.Fatalf("size limit = %d", rule.limit)
				}
			},
		},
		{
			name: "count and restriction",
			raw: "mail count 3 " +
				"restrict=\"ldap:///ou=users,dc=example,dc=com??one?" +
				"(objectClass=inetOrgPerson)\"",
			kind: constraintCount,
			check: func(t *testing.T, rule constraintRule) {
				if rule.limit != 3 || rule.restrict == nil ||
					rule.restrict.base == nil ||
					rule.restrict.scope != directory.ScopeSingleLevel ||
					rule.restrict.filter == nil {
					t.Fatalf("count rule = %#v", rule)
				}
			},
		},
		{
			name: "URI",
			raw: "uid uri \"ldap:///ou=groups,dc=example,dc=com?uid?one?" +
				"(objectClass=inetOrgPerson)\"",
			kind: constraintURI,
			check: func(t *testing.T, rule constraintRule) {
				if rule.uri == nil || rule.uri.base == nil ||
					rule.uri.scope != directory.ScopeSingleLevel ||
					len(rule.uri.attributes) != 1 ||
					rule.uri.attributes[0] != "uid" {
					t.Fatalf("URI rule = %#v", rule)
				}
			},
		},
		{
			name: "set",
			raw: "cn,sn,givenName set " +
				"\"(this/givenName + [ ] + this/sn) & this/cn\"",
			kind: constraintSet,
			check: func(t *testing.T, rule constraintRule) {
				if len(rule.attributes) != 3 ||
					rule.value != "(this/givenName + [ ] + this/sn) & this/cn" {
					t.Fatalf("set rule = %#v", rule)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule, err := parseConstraintRule(test.raw, database)
			if err != nil {
				t.Fatalf("parseConstraintRule(%q): %v", test.raw, err)
			}
			if rule.kind != test.kind {
				t.Fatalf("kind = %d, want %d", rule.kind, test.kind)
			}
			if test.check != nil {
				test.check(t, rule)
			}
		})
	}
}

func TestParseOpenLDAPConstraintRulesRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	database := constraintTestDatabase(t)
	for name, raw := range map[string]string{
		"missing fields":          "mail count",
		"empty attribute":         ",mail count 1",
		"duplicate attribute":     "mail,MAIL count 1",
		"unknown type":            "mail unknown value",
		"invalid regex":           "mail regex [",
		"negative size":           "mail size -1",
		"non-numeric count":       "mail count one",
		"remote URI":              "uid uri ldap://catalog.example/dc=example?uid?sub",
		"URI without attributes":  "uid uri ldap:///dc=example,dc=com??sub",
		"URI with extensions":     "uid uri ldap:///dc=example,dc=com?uid?sub??bindname=x",
		"restrict attributes":     "mail count 1 restrict=ldap:///dc=example,dc=com?mail?sub",
		"restrict outside suffix": "mail count 1 restrict=ldap:///dc=outside,dc=com??sub",
		"duplicate restrict": "mail count 1 " +
			"restrict=ldap:///dc=example,dc=com??sub " +
			"restrict=ldap:///dc=example,dc=com??sub",
		"unknown extra":        "mail count 1 unsupported=value",
		"invalid order prefix": "{x}mail count 1",
		"invalid scope":        "uid uri ldap:///dc=example,dc=com?uid?invalid",
		"invalid filter":       "uid uri ldap:///dc=example,dc=com?uid?sub?(broken",
	} {
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseConstraintRule(raw, database); err == nil {
				t.Fatalf("parseConstraintRule(%q) succeeded", raw)
			}
		})
	}
}

func TestValidateConstraintSchema(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	database := constraintTestDatabase(t)
	valid, err := parseConstraintRule(
		"mail uri ldap:///dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)",
		database,
	)
	if err != nil {
		t.Fatalf("parse valid rule: %v", err)
	}
	configuration := constraintRuntimeConfiguration{rules: []constraintRule{valid}}
	if err := validateConstraintSchema(registry, &configuration); err != nil {
		t.Fatalf("validateConstraintSchema(valid): %v", err)
	}

	invalid := valid
	invalid.attributes = []string{"notInSchema"}
	configuration.rules = []constraintRule{invalid}
	if err := validateConstraintSchema(registry, &configuration); err == nil ||
		!strings.Contains(err.Error(), "notInSchema") {
		t.Fatalf("validateConstraintSchema(undefined) error = %v", err)
	}

	invalid.attributes = []string{"cn;;lang-en"}
	configuration.rules = []constraintRule{invalid}
	if err := validateConstraintSchema(registry, &configuration); err == nil ||
		!strings.Contains(err.Error(), "invalid attribute description") {
		t.Fatalf("validateConstraintSchema(malformed description) error = %v", err)
	}
}

func TestConstraintSetExpressionEvaluation(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	node, err := parseConstraintSetExpression(
		"(this/givenName + [ ] + this/sn) & this/cn",
	)
	if err != nil {
		t.Fatalf("parseConstraintSetExpression(): %v", err)
	}
	runtime := &runtimeState{schema: registry}
	entry := directory.Entry{
		DN: "uid=john,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "givenName", Values: stringValues("JOHN")},
			{Description: "sn", Values: stringValues("DOE")},
			{Description: "cn", Values: stringValues("John Doe")},
		},
	}
	values, err := (constraintSetEvaluation{
		runtime: runtime,
		target:  entry,
	}).evaluate(node)
	if err != nil {
		t.Fatalf("evaluate(valid): %v", err)
	}
	if _, found := values["john doe"]; !found || len(values) != 1 {
		t.Fatalf("valid set result = %#v", values)
	}

	entry.ReplaceValues("cn", stringValues("John Wrong"))
	values, err = (constraintSetEvaluation{
		runtime: runtime,
		target:  entry,
	}).evaluate(node)
	if err != nil {
		t.Fatalf("evaluate(invalid): %v", err)
	}
	if len(values) != 0 {
		t.Fatalf("invalid set result = %#v", values)
	}
}

func TestConstraintSetExpressionChasesEntriesAndAcceptsOpenLDAPPaths(
	t *testing.T,
) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	database := constraintTestDatabase(t)
	database.partition = "constraint-test"
	runtime := &runtimeState{
		schema:    registry,
		databases: []runtimeDatabase{database},
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	manager := directory.Entry{
		DN: "uid=manager,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "uid", Values: stringValues("boss")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(database.partition, manager, false)
	}); err != nil {
		t.Fatalf("seed manager: %v", err)
	}
	target := directory.Entry{
		DN: "uid=worker,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "aliasedObjectName",
				Values:      stringValues(manager.DN),
			},
		},
	}
	node, err := parseConstraintSetExpression(
		"this->aliasedEntryName/0.9.2342.19200300.100.1.1 & [boss]",
	)
	if err != nil {
		t.Fatalf("parse OpenLDAP path: %v", err)
	}
	if err := validateConstraintSetSchema(registry, node); err != nil {
		t.Fatalf("validate OpenLDAP path: %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		values, evaluateErr := (constraintSetEvaluation{
			runtime: runtime,
			reader:  reader,
			target:  target,
		}).evaluate(node)
		if evaluateErr != nil {
			return evaluateErr
		}
		if _, found := values["boss"]; !found || len(values) != 1 {
			t.Fatalf("chased set result = %#v", values)
		}
		urlNode, parseErr := parseConstraintSetExpression(
			"[ldap:///dc=example,dc=com??one?(uid=boss)]/uid & [boss]",
		)
		if parseErr != nil {
			return parseErr
		}
		values, evaluateErr = (constraintSetEvaluation{
			runtime: runtime,
			reader:  reader,
			target:  target,
		}).evaluate(urlNode)
		if evaluateErr != nil {
			return evaluateErr
		}
		if _, found := values["boss"]; !found || len(values) != 1 {
			t.Fatalf("LDAP URL set result = %#v", values)
		}
		return nil
	}); err != nil {
		t.Fatalf("evaluate chased set: %v", err)
	}
}

func TestConstraintSetExpressionRejectsMalformedSyntax(t *testing.T) {
	t.Parallel()

	for _, expression := range []string{
		"",
		"this +",
		"(this",
		"this unknown user",
		"this/",
		"this/-x",
		"[unterminated",
	} {
		if _, err := parseConstraintSetExpression(expression); err == nil {
			t.Fatalf("parseConstraintSetExpression(%q) succeeded", expression)
		}
	}
}

func TestConstraintAttributeDescriptionEquality(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if !constraintAttributeDescriptionsEqual(
		registry,
		"aliasedObjectName",
		"aliasedEntryName",
	) {
		t.Fatal("schema aliases did not identify the same attribute type")
	}
	if !constraintAttributeDescriptionsEqual(
		registry,
		"aliasedObjectName;LANG-en;binary",
		"aliasedEntryName;binary;lang-EN",
	) {
		t.Fatal("equivalent attribute options did not match")
	}
	if constraintAttributeDescriptionsEqual(registry, "cn;lang-en", "cn") {
		t.Fatal("different attribute options matched")
	}
}

func TestValidateConstraintAttributeDescription(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{
		"cn",
		"cn;lang-en;binary",
		"0.9.2342.19200300.100.1.1",
	} {
		if err := validateConstraintAttributeDescription(valid); err != nil {
			t.Fatalf("valid description %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"",
		"1",
		"1..2",
		"1.02.3",
		"cn-",
		"cn;;binary",
		"cn;9invalid",
		"cn;binary;BINARY",
	} {
		if err := validateConstraintAttributeDescription(invalid); err == nil {
			t.Fatalf("invalid description %q was accepted", invalid)
		}
	}
}

func TestLoadRuntimeDatabasesLoadsConstraintOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: "olcOverlay={0}constraint,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}constraint")},
				{
					Description: "olcConstraintAttribute",
					Values: stringValues(
						"{0}mail regex ^.+@example[.]com$",
						"{1}description count 2",
					),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed constraint configuration: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databases[databaseIndexForDN(databases, suffix)]
	if database.constraint == nil || len(database.constraint.rules) != 2 ||
		database.constraint.rules[0].kind != constraintRegex ||
		database.constraint.rules[1].kind != constraintCount {
		t.Fatalf("constraint runtime configuration = %#v", database.constraint)
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidConstraintPlacement(t *testing.T) {
	t.Parallel()

	for name, entries := range map[string][]directory.Entry{
		"duplicate": {
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				},
			},
			constraintOverlayEntry("{0}"),
			constraintOverlayEntry("{1}"),
		},
		"frontend": {
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				}},
			},
			{
				DN: "olcOverlay={0}constraint,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcOverlay", Values: stringValues("{0}constraint")},
					{
						Description: "olcConstraintAttribute",
						Values:      stringValues("mail count 1"),
					},
				},
			},
		},
	} {
		entries := entries
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(
				context.Background(),
				func(writer storage.Writer) error {
					for _, entry := range entries {
						if err := writer.Put(entry, false); err != nil {
							return err
						}
					}
					return nil
				},
			); err != nil {
				t.Fatalf("seed invalid constraint configuration: %v", err)
			}
			if _, err := loadRuntimeDatabases(
				context.Background(),
				store,
			); err == nil {
				t.Fatal("invalid constraint placement was accepted")
			}
		})
	}
}

func constraintOverlayEntry(order string) directory.Entry {
	return directory.Entry{
		DN: "olcOverlay=" + order + "constraint,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues(order + "constraint")},
			{
				Description: "olcConstraintAttribute",
				Values:      stringValues("mail count 1"),
			},
		},
	}
}

func constraintTestDatabase(t *testing.T) runtimeDatabase {
	t.Helper()
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	return runtimeDatabase{
		name:     "{1}mdb",
		suffixes: []directory.DN{suffix},
	}
}
