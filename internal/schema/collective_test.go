package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const collectiveDescriptionDefinition = "" +
	"( 1.2.3.4 NAME ( 'c-description' 'collectiveDescription' ) " +
	"SUP description COLLECTIVE )"

func TestBuiltinCollectiveAttributeTypesAndMatching(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, name := range []string{
		"c-l",
		"c-st",
		"c-street",
		"c-o",
		"c-ou",
		"c-PostalAddress",
		"c-PostalCode",
		"c-PostOfficeBox",
		"c-PhysicalDeliveryOfficeName",
		"c-TelephoneNumber",
		"c-TelexNumber",
		"c-FacsimileTelephoneNumber",
		"c-InternationalISDNNumber",
	} {
		if !registry.IsCollective(name) {
			t.Fatalf("%s is not registered as collective", name)
		}
	}

	for _, test := range []struct {
		attribute string
		left      string
		right     string
	}{
		{
			attribute: "c-TelephoneNumber",
			left:      "+86 21-5555 0100",
			right:     "+862155550100",
		},
		{
			attribute: "c-InternationalISDNNumber",
			left:      "123 456",
			right:     "123456",
		},
		{
			attribute: "c-PostalAddress",
			left:      " Main  Street $ SHANGHAI ",
			right:     "main street$shanghai",
		},
		{
			attribute: "c-PostalAddress",
			left:      ` Main\24Office\5CWest $ SHANGHAI `,
			right:     `main\24office\5cwest$shanghai`,
		},
	} {
		comparison, err := registry.Compare(
			test.attribute,
			"",
			[]byte(test.left),
			[]byte(test.right),
		)
		if err != nil {
			t.Fatalf("Compare(%s): %v", test.attribute, err)
		}
		if comparison != 0 {
			t.Fatalf("Compare(%s) = %d, want 0", test.attribute, comparison)
		}
	}

	matches, err := registry.MatchSubstring(
		"c-TelephoneNumber",
		[]byte("+86 21-5555 0100"),
		directory.Substring{Initial: []byte("+8621"), Final: []byte("0100")},
	)
	if err != nil {
		t.Fatalf("MatchSubstring(c-TelephoneNumber): %v", err)
	}
	if !matches {
		t.Fatal("telephoneNumberSubstringsMatch did not normalize separators")
	}

	matches, err = registry.MatchSubstring(
		"c-PostalAddress",
		[]byte(`Alpha\24Beta$Gamma`),
		directory.Substring{Any: [][]byte{[]byte("ha$be")}},
	)
	if err != nil {
		t.Fatalf("MatchSubstring(c-PostalAddress escaped line): %v", err)
	}
	if !matches {
		t.Fatal("caseIgnoreListSubstringsMatch did not decode an escaped dollar")
	}

	matches, err = registry.MatchSubstring(
		"c-PostalAddress",
		[]byte("Alpha$Beta"),
		directory.Substring{Any: [][]byte{[]byte("hab")}},
	)
	if err != nil {
		t.Fatalf("MatchSubstring(c-PostalAddress line boundary): %v", err)
	}
	if matches {
		t.Fatal("caseIgnoreListSubstringsMatch crossed a postal-address line")
	}
}

func TestAttributeDescriptionHierarchyResolution(t *testing.T) {
	t.Parallel()

	registry := collectiveTestRegistry(t)
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "c-description;x-origin;lang-en",
				Values:      collectiveByteValues("Shared"),
			},
			{
				Description: "description",
				Values:      collectiveByteValues("Local"),
			},
		},
	}

	for _, description := range []string{
		"collectiveDescription;lang-en",
		"1.2.3.4;x-origin",
		"description;lang-en",
	} {
		values := registry.AttributeValues(entry, description)
		if len(values) != 1 || string(values[0]) != "Shared" {
			t.Fatalf("AttributeValues(%q) = %q, want Shared", description, values)
		}
	}
	values := registry.AttributeValues(entry, "description")
	if len(values) != 2 ||
		string(values[0]) != "Shared" ||
		string(values[1]) != "Local" {
		t.Fatalf("AttributeValues(description) = %q", values)
	}
	if registry.HasAttributeDescription(entry, "description;lang-fr") {
		t.Fatal("lang-fr unexpectedly matched lang-en")
	}

	filter := directory.Filter{
		Kind:      directory.FilterEquality,
		Attribute: "collectiveDescription;lang-en",
		Assertion: []byte("shared"),
	}
	matches, err := filter.MatchWith(entry, registry)
	if err != nil {
		t.Fatalf("MatchWith(attribute alias): %v", err)
	}
	if !matches {
		t.Fatal("attribute alias filter did not match a subtype with more options")
	}

	selected := entry.SelectWithMatcher(
		[]string{"description;lang-en"},
		false,
		registry.IsOperational,
		registry.AttributeDescriptionSubtype,
	)
	if len(selected.Attributes) != 1 ||
		selected.Attributes[0].Description != "c-description;x-origin;lang-en" {
		t.Fatalf("hierarchy selection = %#v", selected.Attributes)
	}
}

func TestCollectiveAttributeSchemaAndEntryConstraints(t *testing.T) {
	t.Parallel()

	registry := collectiveTestRegistry(t)
	if !registry.IsCollective("c-description") ||
		!registry.IsCollective("collectiveDescription") ||
		!registry.IsCollective("1.2.3.4") ||
		registry.IsCollective("description") {
		t.Fatal("collective attribute identification is incorrect")
	}
	if !registry.IsOperational("collectiveAttributeSubentries") ||
		!registry.IsOperational("collectiveExclusions") {
		t.Fatal("RFC 3671 operational attributes are not operational")
	}

	collectiveSubentry := directory.Entry{
		DN: "cn=shared,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: collectiveByteValues(
					"subentry",
					"collectiveAttributeSubentry",
				),
			},
			{Description: "cn", Values: collectiveByteValues("shared")},
			{Description: "subtreeSpecification", Values: collectiveByteValues("{}")},
			{Description: "c-description", Values: collectiveByteValues("shared value")},
		},
	}
	if err := registry.ValidateEntry(collectiveSubentry); err != nil {
		t.Fatalf("ValidateEntry(collective subentry): %v", err)
	}

	ordinaryEntry := collectivePersonEntry()
	ordinaryEntry.Attributes[0].Values = append(
		ordinaryEntry.Attributes[0].Values,
		[]byte("extensibleObject"),
	)
	ordinaryEntry.Attributes = append(ordinaryEntry.Attributes, directory.Attribute{
		Description: "c-description",
		Values:      collectiveByteValues("not allowed"),
	})
	assertViolation(
		t,
		registry.ValidateEntry(ordinaryEntry),
		ViolationDisallowedAttribute,
	)

	classWithoutSubentry := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: collectiveByteValues(
					"domain",
					"collectiveAttributeSubentry",
				),
			},
			{Description: "dc", Values: collectiveByteValues("example")},
		},
	}
	assertViolation(
		t,
		registry.ValidateEntry(classWithoutSubentry),
		ViolationStructuralObjectClass,
	)

	entryWithExclusions := collectivePersonEntry()
	entryWithExclusions.Attributes = append(
		entryWithExclusions.Attributes,
		directory.Attribute{
			Description: "collectiveExclusions",
			Values: collectiveByteValues(
				"1.2.3.4",
				"excludeAllCollectiveAttributes",
			),
		},
	)
	if err := registry.ValidateEntry(entryWithExclusions); err != nil {
		t.Fatalf("ValidateEntry(collective exclusions): %v", err)
	}

	entryWithExclusions.ReplaceValues(
		"collectiveExclusions",
		collectiveByteValues("1.02"),
	)
	assertViolation(
		t,
		registry.ValidateEntry(entryWithExclusions),
		ViolationSyntax,
	)

	namingEntry := collectiveSubentry.Clone()
	namingEntry.DN = "c-description=shared,dc=example,dc=com"
	assertViolation(t, registry.ValidateEntry(namingEntry), ViolationNaming)

	malformedSpecification := collectiveSubentry.Clone()
	malformedSpecification.ReplaceValues(
		"subtreeSpecification",
		collectiveByteValues("{ minimum -1 }"),
	)
	assertViolation(
		t,
		registry.ValidateEntry(malformedSpecification),
		ViolationSyntax,
	)
}

func TestCollectiveAttributeDefinitionConstraints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(*Registry) error
	}{
		{
			name: "single-valued",
			run: func(registry *Registry) error {
				return registry.ParseAndRegisterAttributeType(
					"( 1.2.3.4 NAME 'c-bad' SUP description " +
						"COLLECTIVE SINGLE-VALUE )",
				)
			},
		},
		{
			name: "operational",
			run: func(registry *Registry) error {
				return registry.ParseAndRegisterAttributeType(
					"( 1.2.3.4 NAME 'c-bad' EQUALITY caseIgnoreMatch " +
						"SYNTAX " + SyntaxDirectoryString + " COLLECTIVE " +
						"USAGE directoryOperation )",
				)
			},
		},
		{
			name: "non-collective subtype",
			run: func(registry *Registry) error {
				if err := registry.ParseAndRegisterAttributeType(
					collectiveDescriptionDefinition,
				); err != nil {
					return err
				}
				return registry.ParseAndRegisterAttributeType(
					"( 1.2.3.5 NAME 'badSubtype' SUP c-description )",
				)
			},
		},
		{
			name: "late collective superior",
			run: func(registry *Registry) error {
				if err := registry.ParseAndRegisterAttributeType(
					"( 1.2.3.5 NAME 'badSubtype' SUP futureCollective )",
				); err != nil {
					return err
				}
				return registry.ParseAndRegisterAttributeType(
					"( 1.2.3.4 NAME 'futureCollective' SUP description " +
						"COLLECTIVE )",
				)
			},
		},
		{
			name: "object class may",
			run: func(registry *Registry) error {
				if err := registry.ParseAndRegisterAttributeType(
					collectiveDescriptionDefinition,
				); err != nil {
					return err
				}
				return registry.ParseAndRegisterObjectClass(
					"( 1.2.3.5 NAME 'badClass' SUP top AUXILIARY " +
						"MAY c-description )",
				)
			},
		},
		{
			name: "late object class reference",
			run: func(registry *Registry) error {
				if err := registry.ParseAndRegisterObjectClass(
					"( 1.2.3.5 NAME 'badClass' SUP top AUXILIARY " +
						"MAY futureCollective )",
				); err != nil {
					return err
				}
				return registry.ParseAndRegisterAttributeType(
					"( 1.2.3.4 NAME 'futureCollective' SUP description " +
						"COLLECTIVE )",
				)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			registry, err := NewBuiltinRegistry()
			if err != nil {
				t.Fatalf("NewBuiltinRegistry(): %v", err)
			}
			if err := test.run(registry); err == nil {
				t.Fatal("invalid collective schema definition was accepted")
			}
		})
	}
}

func collectiveTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		collectiveDescriptionDefinition,
	); err != nil {
		t.Fatalf("register collective description: %v", err)
	}
	return registry
}

func collectivePersonEntry() directory.Entry {
	return directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: collectiveByteValues(
					"inetOrgPerson",
				),
			},
			{Description: "uid", Values: collectiveByteValues("alice")},
			{Description: "cn", Values: collectiveByteValues("Alice")},
			{Description: "sn", Values: collectiveByteValues("Example")},
		},
	}
}

func collectiveByteValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}
