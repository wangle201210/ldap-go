package schema

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestDITContentRuleDescriptionRoundTrip(t *testing.T) {
	t.Parallel()

	description := "{7}( 2.16.840.1.113730.3.2.2 " +
		"NAME ( 'inetOrgPersonRule' 'applicationPersonRule' ) " +
		"DESC 'application\\27s content rule' OBSOLETE " +
		"AUX ( posixAccount $ dynamicObject ) " +
		"MUST uid MAY mail NOT description " +
		"X-ORIGIN ( 'RFC 4512' 'application' ) )"
	got, err := ParseDITContentRule(description)
	if err != nil {
		t.Fatalf("ParseDITContentRule(): %v", err)
	}
	want := DITContentRule{
		OID:         "2.16.840.1.113730.3.2.2",
		Names:       []string{"inetOrgPersonRule", "applicationPersonRule"},
		Description: "application's content rule",
		Obsolete:    true,
		Auxiliary:   []string{"posixAccount", "dynamicObject"},
		Must:        []string{"uid"},
		May:         []string{"mail"},
		Not:         []string{"description"},
		Extensions: map[string][]string{
			"X-ORIGIN": {"RFC 4512", "application"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("content rule = %#v, want %#v", got, want)
	}

	formatted := FormatDITContentRule(got)
	roundTripped, err := ParseDITContentRule(formatted)
	if err != nil {
		t.Fatalf("parse formatted content rule %q: %v", formatted, err)
	}
	if !reflect.DeepEqual(roundTripped, want) {
		t.Fatalf("round-tripped content rule = %#v, want %#v", roundTripped, want)
	}
}

func TestParseDITContentRuleRejectsMalformedDescriptions(t *testing.T) {
	t.Parallel()

	for name, description := range map[string]string{
		"not enclosed":    "( 1.2.3",
		"missing OID":     "( )",
		"unknown field":   "( 1.2.3 SUP top )",
		"empty list":      "( 1.2.3 AUX ( ) )",
		"missing value":   "( 1.2.3 MUST )",
		"duplicate field": "( 1.2.3 MUST cn MUST sn )",
	} {
		description := description
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDITContentRule(description); err == nil {
				t.Fatalf("ParseDITContentRule(%q) succeeded", description)
			}
		})
	}
}

func TestDITContentRuleSyntaxValidation(t *testing.T) {
	t.Parallel()

	if err := validateSyntax(
		SyntaxDITContentRule,
		0,
		[]byte("( 2.5.6.6 NAME 'personRule' MUST uid )"),
	); err != nil {
		t.Fatalf("validateSyntax(valid DIT content rule): %v", err)
	}
	if err := validateSyntax(
		SyntaxDITContentRule,
		0,
		[]byte("( 2.5.6.6 UNKNOWN uid )"),
	); err == nil {
		t.Fatal("validateSyntax() accepted malformed DIT content rule")
	}
}

func TestDITContentRuleRegistrationValidation(t *testing.T) {
	t.Parallel()

	newRegistry := func(t *testing.T) *Registry {
		t.Helper()
		registry, err := NewBuiltinRegistry()
		if err != nil {
			t.Fatalf("NewBuiltinRegistry(): %v", err)
		}
		if err := registry.ParseAndRegisterAttributeType(
			"( 1.3.6.1.4.1.99999.1 NAME 'applicationCode' " +
				"EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
		); err != nil {
			t.Fatalf("register applicationCode: %v", err)
		}
		if err := registry.ParseAndRegisterObjectClass(
			"( 1.3.6.1.4.1.99999.2 NAME 'applicationAux' SUP top " +
				"AUXILIARY MUST applicationCode )",
		); err != nil {
			t.Fatalf("register applicationAux: %v", err)
		}
		return registry
	}

	for name, contentRule := range map[string]DITContentRule{
		"unknown structural class": {
			OID: "1.3.6.1.4.1.99999.404",
		},
		"non-structural class": {
			OID: "dynamicObject",
		},
		"unknown auxiliary class": {
			OID:       "inetOrgPerson",
			Auxiliary: []string{"missingAux"},
		},
		"non-auxiliary class": {
			OID:       "inetOrgPerson",
			Auxiliary: []string{"person"},
		},
		"unknown attribute": {
			OID:  "inetOrgPerson",
			Must: []string{"missingAttribute"},
		},
		"operational attribute": {
			OID: "inetOrgPerson",
			May: []string{"entryUUID"},
		},
		"attribute repeated across fields": {
			OID:  "inetOrgPerson",
			Must: []string{"applicationCode"},
			Not:  []string{"1.3.6.1.4.1.99999.1"},
		},
		"duplicate rule name": {
			OID:   "inetOrgPerson",
			Names: []string{"duplicateRule", "duplicateRule"},
		},
	} {
		contentRule := contentRule
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := newRegistry(t).RegisterDITContentRule(contentRule); err == nil {
				t.Fatalf("RegisterDITContentRule(%#v) succeeded", contentRule)
			}
		})
	}
}

func TestDITContentRuleEntryValidation(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.1 NAME 'applicationCode' " +
			"EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.3 NAME 'applicationLabel' " +
			"EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("register attribute type: %v", err)
		}
	}
	if err := registry.ParseAndRegisterObjectClass(
		"( 1.3.6.1.4.1.99999.2 NAME 'applicationAux' SUP top " +
			"AUXILIARY MUST applicationCode )",
	); err != nil {
		t.Fatalf("register applicationAux: %v", err)
	}
	if err := registry.RegisterDITContentRule(DITContentRule{
		OID:       "inetOrgPerson",
		Names:     []string{"inetOrgPersonRule"},
		Auxiliary: []string{"applicationAux"},
		Must:      []string{"uid"},
		May:       []string{"applicationLabel"},
		Not:       []string{"description"},
	}); err != nil {
		t.Fatalf("RegisterDITContentRule(): %v", err)
	}

	valid := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: byteValues(
					"inetOrgPerson",
					"applicationAux",
				),
			},
			{Description: "uid", Values: byteValues("alice")},
			{Description: "cn", Values: byteValues("Alice")},
			{Description: "sn", Values: byteValues("Example")},
			{Description: "applicationCode", Values: byteValues("portal")},
			{Description: "applicationLabel", Values: byteValues("Portal")},
		},
	}
	if err := registry.ValidateEntry(valid); err != nil {
		t.Fatalf("ValidateEntry(valid): %v", err)
	}

	for name, mutate := range map[string]func(*directory.Entry){
		"missing rule MUST": func(entry *directory.Entry) {
			entry.ReplaceValues("uid", nil)
		},
		"precluded attribute": func(entry *directory.Entry) {
			entry.ReplaceValues("description", byteValues("blocked"))
		},
		"unlisted auxiliary": func(entry *directory.Entry) {
			entry.ReplaceValues(
				"objectClass",
				byteValues("inetOrgPerson", "dynamicObject"),
			)
			entry.ReplaceValues("applicationCode", nil)
		},
		"attribute not allowed": func(entry *directory.Entry) {
			entry.ReplaceValues("postalCode", byteValues("10000"))
		},
	} {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entry := valid.Clone()
			mutate(&entry)
			var violation *Violation
			if err := registry.ValidateEntry(entry); !errors.As(err, &violation) {
				t.Fatalf("ValidateEntry() error = %v, want schema violation", err)
			}
		})
	}

	unregulated := directory.Entry{
		DN: "cn=lease,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      byteValues("organizationalRole", "dynamicObject"),
			},
			{Description: "cn", Values: byteValues("lease")},
			{Description: "entryTtl", Values: byteValues("60")},
		},
	}
	if err := registry.ValidateEntry(unregulated); err != nil {
		t.Fatalf("ValidateEntry(unregulated auxiliary class): %v", err)
	}
}

func TestDITContentRuleAppliesOnlyToExactStructuralClass(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.RegisterDITContentRule(DITContentRule{
		OID: "person",
		Not: []string{"description"},
	}); err != nil {
		t.Fatalf("RegisterDITContentRule(person): %v", err)
	}
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      byteValues("inetOrgPerson"),
			},
			{Description: "uid", Values: byteValues("alice")},
			{Description: "cn", Values: byteValues("Alice")},
			{Description: "sn", Values: byteValues("Example")},
			{Description: "description", Values: byteValues("allowed")},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(subclass): %v", err)
	}
}

func TestObsoleteDITContentRuleRejectsEntry(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.RegisterDITContentRule(DITContentRule{
		OID:      "organizationalRole",
		Names:    []string{"obsoleteRoleRule"},
		Obsolete: true,
	}); err != nil {
		t.Fatalf("RegisterDITContentRule(): %v", err)
	}
	entry := directory.Entry{
		DN: "cn=role,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      byteValues("organizationalRole"),
			},
			{Description: "cn", Values: byteValues("role")},
		},
	}
	var violation *Violation
	err = registry.ValidateEntry(entry)
	if !errors.As(err, &violation) ||
		!strings.Contains(err.Error(), "content rule 'obsoleteRoleRule' is obsolete") {
		t.Fatalf("ValidateEntry(obsolete rule) error = %v", err)
	}
}

func TestDITContentRuleUpsertCloneAndPublication(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.UpsertDITContentRule(DITContentRule{
		OID:   "inetOrgPerson",
		Names: []string{"oldRule"},
		May:   []string{"description"},
	}); err != nil {
		t.Fatalf("UpsertDITContentRule(old): %v", err)
	}
	if err := registry.UpsertDITContentRule(DITContentRule{
		OID:   "2.16.840.1.113730.3.2.2",
		Names: []string{"newRule"},
		Must:  []string{"uid"},
	}); err != nil {
		t.Fatalf("UpsertDITContentRule(new): %v", err)
	}
	if _, found := registry.DITContentRule("oldRule"); found {
		t.Fatal("old content-rule name remained registered")
	}
	rule, found := registry.DITContentRule("newRule")
	if !found || rule.OID != "2.16.840.1.113730.3.2.2" {
		t.Fatalf("new content rule = %#v, found %t", rule, found)
	}

	cloned := registry.Clone()
	if err := cloned.UpsertDITContentRule(DITContentRule{
		OID:   "inetOrgPerson",
		Names: []string{"cloneRule"},
		May:   []string{"mail"},
	}); err != nil {
		t.Fatalf("clone UpsertDITContentRule(): %v", err)
	}
	if _, found := registry.DITContentRule("cloneRule"); found {
		t.Fatal("clone mutation changed source registry")
	}

	descriptions := registry.DITContentRuleDescriptions()
	if len(descriptions) != 1 ||
		!strings.Contains(descriptions[0], "NAME 'newRule'") ||
		!strings.Contains(descriptions[0], "MUST uid") {
		t.Fatalf("DIT content-rule descriptions = %q", descriptions)
	}
}

func TestObjectClassAttributeIdentifiersUseCanonicalOID(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entry := directory.Entry{
		DN: "cn=role,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "2.5.4.0",
				Values:      byteValues("organizationalRole"),
			},
			{Description: "2.5.4.3", Values: byteValues("role")},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(attribute OIDs): %v", err)
	}
}
