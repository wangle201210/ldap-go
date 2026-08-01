package schema

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestNameFormDescriptionRoundTrip(t *testing.T) {
	t.Parallel()

	description := "{4}( 1.3.6.1.4.1.99999.10 " +
		"NAME ( 'applicationNameForm' 'legacyApplicationNameForm' ) " +
		"DESC 'application\\27s name form' OBSOLETE " +
		"OC applicationEntry MUST applicationID MAY ( cn $ uid ) " +
		"X-ORIGIN ( 'RFC 4512' 'application' ) )"
	got, err := ParseNameForm(description)
	if err != nil {
		t.Fatalf("ParseNameForm(): %v", err)
	}
	want := NameForm{
		OID:         "1.3.6.1.4.1.99999.10",
		Names:       []string{"applicationNameForm", "legacyApplicationNameForm"},
		Description: "application's name form",
		Obsolete:    true,
		ObjectClass: "applicationEntry",
		Must:        []string{"applicationID"},
		May:         []string{"cn", "uid"},
		Extensions: map[string][]string{
			"X-ORIGIN": {"RFC 4512", "application"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("name form = %#v, want %#v", got, want)
	}
	formatted := FormatNameForm(got)
	roundTripped, err := ParseNameForm(formatted)
	if err != nil {
		t.Fatalf("parse formatted name form %q: %v", formatted, err)
	}
	if !reflect.DeepEqual(roundTripped, want) {
		t.Fatalf("round-tripped name form = %#v, want %#v", roundTripped, want)
	}
}

func TestDITStructureRuleDescriptionRoundTrip(t *testing.T) {
	t.Parallel()

	description := "{2}( 17 NAME ( 'applicationRule' 'legacyApplicationRule' ) " +
		"DESC 'application\\27s structure rule' OBSOLETE " +
		"FORM applicationNameForm SUP ( 4 9 ) X-ORIGIN 'RFC 4512' )"
	got, err := ParseDITStructureRule(description)
	if err != nil {
		t.Fatalf("ParseDITStructureRule(): %v", err)
	}
	want := DITStructureRule{
		RuleID:      17,
		Names:       []string{"applicationRule", "legacyApplicationRule"},
		Description: "application's structure rule",
		Obsolete:    true,
		Form:        "applicationNameForm",
		Superiors:   []int{4, 9},
		Extensions: map[string][]string{
			"X-ORIGIN": {"RFC 4512"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("structure rule = %#v, want %#v", got, want)
	}
	formatted := FormatDITStructureRule(got)
	roundTripped, err := ParseDITStructureRule(formatted)
	if err != nil {
		t.Fatalf("parse formatted structure rule %q: %v", formatted, err)
	}
	if !reflect.DeepEqual(roundTripped, want) {
		t.Fatalf("round-tripped structure rule = %#v, want %#v", roundTripped, want)
	}
}

func TestParseNameFormRejectsMalformedDescriptions(t *testing.T) {
	t.Parallel()

	for name, description := range map[string]string{
		"missing OID":        "( )",
		"descriptor OID":     "( applicationNameForm OC person MUST cn )",
		"missing OC":         "( 1.2.3 MUST cn )",
		"missing MUST":       "( 1.2.3 OC person )",
		"duplicate field":    "( 1.2.3 OC person MUST cn MUST sn )",
		"unknown field":      "( 1.2.3 OC person MUST cn SUP top )",
		"malformed OID":      "( 1.02.3 OC person MUST cn )",
		"empty required set": "( 1.2.3 OC person MUST ( ) )",
	} {
		description := description
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseNameForm(description); err == nil {
				t.Fatalf("ParseNameForm(%q) succeeded", description)
			}
		})
	}
}

func TestParseDITStructureRuleRejectsMalformedDescriptions(t *testing.T) {
	t.Parallel()

	for name, description := range map[string]string{
		"missing ID":      "( )",
		"negative ID":     "( -1 FORM applicationNameForm )",
		"non-numeric ID":  "( rule FORM applicationNameForm )",
		"overflowing ID":  "( 2147483648 FORM applicationNameForm )",
		"missing FORM":    "( 1 NAME 'rule' )",
		"duplicate field": "( 1 FORM one FORM two )",
		"invalid SUP":     "( 1 FORM one SUP two )",
		"dollar in SUP":   "( 1 FORM one SUP ( 2 $ 3 ) )",
		"empty SUP":       "( 1 FORM one SUP ( ) )",
		"unknown field":   "( 1 FORM one OC person )",
	} {
		description := description
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDITStructureRule(description); err == nil {
				t.Fatalf("ParseDITStructureRule(%q) succeeded", description)
			}
		})
	}
}

func TestNameFormAndDITStructureRuleRegistration(t *testing.T) {
	t.Parallel()

	registry := newDITStructureRegistry(t)
	if err := registry.ParseAndRegisterNameForm(
		"( 1.3.6.1.4.1.99999.10 NAME 'domainNameForm' " +
			"OC domain MUST dc )",
	); err != nil {
		t.Fatalf("register domain name form: %v", err)
	}
	if err := registry.ParseAndRegisterDITStructureRule(
		"( 1 NAME 'domainRule' FORM domainNameForm )",
	); err != nil {
		t.Fatalf("register domain structure rule: %v", err)
	}

	nameForm, found := registry.NameForm("domainNameForm")
	if !found || nameForm.ObjectClass != "0.9.2342.19200300.100.4.13" {
		t.Fatalf("domain name form = %#v, found %t", nameForm, found)
	}
	structureRule, found := registry.DITStructureRule("domainRule")
	if !found || structureRule.RuleID != 1 ||
		structureRule.Form != nameForm.OID {
		t.Fatalf("domain structure rule = %#v, found %t", structureRule, found)
	}

	cloned := registry.Clone()
	if err := cloned.UpsertNameForm(NameForm{
		OID:         nameForm.OID,
		Names:       []string{"replacementDomainNameForm"},
		ObjectClass: "domain",
		Must:        []string{"dc"},
	}); err != nil {
		t.Fatalf("clone UpsertNameForm(): %v", err)
	}
	if _, found := registry.NameForm("replacementDomainNameForm"); found {
		t.Fatal("name form mutation leaked from cloned registry")
	}

	nameFormDescriptions := registry.NameFormDescriptions()
	structureRuleDescriptions := registry.DITStructureRuleDescriptions()
	if len(nameFormDescriptions) != 1 ||
		!strings.Contains(nameFormDescriptions[0], "OC 0.9.2342.19200300.100.4.13") ||
		len(structureRuleDescriptions) != 1 ||
		!strings.Contains(structureRuleDescriptions[0], "FORM "+nameForm.OID) {
		t.Fatalf(
			"published definitions = %#v, %#v",
			nameFormDescriptions,
			structureRuleDescriptions,
		)
	}
}

func TestNameFormRegistrationRejectsInvalidDefinitions(t *testing.T) {
	t.Parallel()

	for name, nameForm := range map[string]NameForm{
		"non-numeric OID": {
			OID: "form", ObjectClass: "domain", Must: []string{"dc"},
		},
		"unknown object class": {
			OID: "1.2.3", ObjectClass: "missing", Must: []string{"dc"},
		},
		"non-structural class": {
			OID: "1.2.3", ObjectClass: "top", Must: []string{"dc"},
		},
		"missing MUST": {
			OID: "1.2.3", ObjectClass: "domain",
		},
		"unknown attribute": {
			OID: "1.2.3", ObjectClass: "domain", Must: []string{"missing"},
		},
		"operational attribute": {
			OID: "1.2.3", ObjectClass: "domain", Must: []string{"entryUUID"},
		},
		"collective attribute": {
			OID: "1.2.3", ObjectClass: "domain", Must: []string{"c-o"},
		},
		"attribute alias repeated": {
			OID: "1.2.3", ObjectClass: "domain",
			Must: []string{"dc"}, May: []string{"domainComponent"},
		},
		"name repeated": {
			OID: "1.2.3", Names: []string{"form", "form"},
			ObjectClass: "domain", Must: []string{"dc"},
		},
	} {
		nameForm := nameForm
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := newDITStructureRegistry(t).RegisterNameForm(nameForm); err == nil {
				t.Fatalf("RegisterNameForm(%#v) succeeded", nameForm)
			}
		})
	}
}

func TestDITStructureRuleRegistrationRejectsInvalidHierarchy(t *testing.T) {
	t.Parallel()

	newRegistry := func(t *testing.T) *Registry {
		t.Helper()
		registry := newDITStructureRegistry(t)
		if err := registry.ParseAndRegisterNameForm(
			"( 1.3.6.1.4.1.99999.10 NAME 'domainNameForm' " +
				"OC domain MUST dc )",
		); err != nil {
			t.Fatalf("register domain name form: %v", err)
		}
		return registry
	}

	for name, structureRule := range map[string]DITStructureRule{
		"negative ID":  {RuleID: -1, Form: "domainNameForm"},
		"unknown form": {RuleID: 1, Form: "missing"},
		"unknown superior": {
			RuleID: 2, Form: "domainNameForm", Superiors: []int{1},
		},
		"self superior": {
			RuleID: 1, Form: "domainNameForm", Superiors: []int{1},
		},
		"duplicate superior": {
			RuleID: 2, Form: "domainNameForm", Superiors: []int{1, 1},
		},
		"duplicate name": {
			RuleID: 1, Names: []string{"rule", "rule"}, Form: "domainNameForm",
		},
	} {
		structureRule := structureRule
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			registry := newRegistry(t)
			if name == "duplicate superior" {
				if err := registry.RegisterDITStructureRule(DITStructureRule{
					RuleID: 1,
					Form:   "domainNameForm",
				}); err != nil {
					t.Fatalf("register superior: %v", err)
				}
			}
			if err := registry.RegisterDITStructureRule(structureRule); err == nil {
				t.Fatalf("RegisterDITStructureRule(%#v) succeeded", structureRule)
			}
		})
	}

	registry := newRegistry(t)
	if err := registry.RegisterDITStructureRule(DITStructureRule{
		RuleID: 1,
		Form:   "domainNameForm",
	}); err != nil {
		t.Fatalf("register root rule: %v", err)
	}
	if err := registry.RegisterDITStructureRule(DITStructureRule{
		RuleID:    2,
		Form:      "domainNameForm",
		Superiors: []int{1},
	}); err != nil {
		t.Fatalf("register child rule: %v", err)
	}
	if err := registry.UpsertDITStructureRule(DITStructureRule{
		RuleID:    1,
		Form:      "domainNameForm",
		Superiors: []int{2},
	}); err == nil {
		t.Fatal("UpsertDITStructureRule() accepted a hierarchy cycle")
	}
}

func TestGoverningStructureRuleSelection(t *testing.T) {
	t.Parallel()

	registry := newDITStructureRegistry(t)
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.10 NAME 'domainNameForm' OC domain MUST dc )",
		"( 1.3.6.1.4.1.99999.11 NAME 'ouNameForm' OC organizationalUnit MUST ou )",
		"( 1.3.6.1.4.1.99999.12 NAME 'personNameForm' OC inetOrgPerson MUST uid MAY cn )",
	} {
		if err := registry.ParseAndRegisterNameForm(description); err != nil {
			t.Fatalf("register name form: %v", err)
		}
	}
	for _, description := range []string{
		"( 1 NAME 'domainRule' FORM domainNameForm )",
		"( 2 NAME 'ouRule' FORM ouNameForm SUP 1 )",
		"( 3 NAME 'personRule' FORM personNameForm SUP 2 )",
	} {
		if err := registry.ParseAndRegisterDITStructureRule(description); err != nil {
			t.Fatalf("register structure rule: %v", err)
		}
	}

	domain := structureEntry(
		"dc=example",
		"domain",
		map[string]string{"dc": "example"},
	)
	ruleID, governed, err := registry.GoverningStructureRule(domain, nil)
	if err != nil || !governed || ruleID != 1 {
		t.Fatalf("domain governing rule = %d, %t, %v", ruleID, governed, err)
	}
	domain.ReplaceValues("governingStructureRule", [][]byte{[]byte("1")})

	ou := structureEntry(
		"ou=people,dc=example",
		"organizationalUnit",
		map[string]string{"ou": "people"},
	)
	ruleID, governed, err = registry.GoverningStructureRule(ou, &domain)
	if err != nil || !governed || ruleID != 2 {
		t.Fatalf("OU governing rule = %d, %t, %v", ruleID, governed, err)
	}
	ou.ReplaceValues("governingStructureRule", [][]byte{[]byte("2")})

	person := structureEntry(
		"uid=alice,ou=people,dc=example",
		"inetOrgPerson",
		map[string]string{"uid": "alice", "cn": "Alice", "sn": "Example"},
	)
	ruleID, governed, err = registry.GoverningStructureRule(person, &ou)
	if err != nil || !governed || ruleID != 3 {
		t.Fatalf("person governing rule = %d, %t, %v", ruleID, governed, err)
	}

	invalidName := person.Clone()
	invalidName.DN = "cn=Alice,ou=people,dc=example"
	assertViolation(
		t,
		governingRuleError(registry, invalidName, &ou),
		ViolationNaming,
	)

	wrongParent := structureEntry(
		"uid=boss,dc=example",
		"inetOrgPerson",
		map[string]string{"uid": "boss", "cn": "Boss", "sn": "Example"},
	)
	assertViolation(
		t,
		governingRuleError(registry, person, &wrongParent),
		ViolationNaming,
	)
	forgedParent := wrongParent.Clone()
	forgedParent.ReplaceValues(
		"governingStructureRule",
		[][]byte{[]byte("2")},
	)
	assertViolation(
		t,
		governingRuleError(registry, person, &forgedParent),
		ViolationNaming,
	)

	unregulated := structureEntry(
		"cn=role,dc=example",
		"organizationalRole",
		map[string]string{"cn": "role"},
	)
	if _, governed, err := registry.GoverningStructureRule(unregulated, &domain); err != nil || governed {
		t.Fatalf("unregulated governing rule = %t, %v", governed, err)
	}
}

func TestNameFormAndDITStructureRuleSyntaxValidation(t *testing.T) {
	t.Parallel()

	for syntax, value := range map[string]string{
		SyntaxNameForm:         "( 1.2.3 OC person MUST cn )",
		SyntaxDITStructureRule: "( 7 FORM personNameForm SUP ( 1 2 ) )",
	} {
		if err := validateSyntax(syntax, 0, []byte(value)); err != nil {
			t.Fatalf("validateSyntax(%s, %q): %v", syntax, value, err)
		}
		if err := validateSyntax(syntax, 0, []byte("invalid")); err == nil {
			t.Fatalf("validateSyntax(%s) accepted invalid description", syntax)
		}
	}
}

func TestSchemaFirstComponentMatchingRules(t *testing.T) {
	t.Parallel()

	registry := newDITStructureRegistry(t)
	comparisons := []struct {
		attribute string
		value     string
		assertion string
	}{
		{
			attribute: "nameForms",
			value:     "{3}( 1.3.6.1.4.1.99999.10 NAME 'form' OC person MUST cn )",
			assertion: "1.3.6.1.4.1.99999.10",
		},
		{
			attribute: "dITContentRules",
			value:     "( 2.5.6.6 NAME 'personRule' )",
			assertion: "2.5.6.6",
		},
		{
			attribute: "dITStructureRules",
			value:     "{8}( 17 NAME 'personRule' FORM personNameForm )",
			assertion: "17",
		},
	}
	for _, comparison := range comparisons {
		got, err := registry.Compare(
			comparison.attribute,
			"",
			[]byte(comparison.value),
			[]byte(comparison.assertion),
		)
		if err != nil || got != 0 {
			t.Fatalf(
				"Compare(%s) = %d, %v",
				comparison.attribute,
				got,
				err,
			)
		}
	}
}

func newDITStructureRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	return registry
}

func structureEntry(
	dn,
	objectClass string,
	attributes map[string]string,
) directory.Entry {
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte(objectClass)}},
		},
	}
	for name, value := range attributes {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: name,
			Values:      [][]byte{[]byte(value)},
		})
	}
	return entry
}

func governingRuleError(
	registry *Registry,
	entry directory.Entry,
	parent *directory.Entry,
) error {
	_, _, err := registry.GoverningStructureRule(entry, parent)
	return err
}

func TestDITStructureRuleDescriptionOrdering(t *testing.T) {
	t.Parallel()

	registry := newDITStructureRegistry(t)
	if err := registry.ParseAndRegisterNameForm(
		"( 1.3.6.1.4.1.99999.10 NAME 'domainNameForm' OC domain MUST dc )",
	); err != nil {
		t.Fatalf("register name form: %v", err)
	}
	for _, ruleID := range []int{11, 2, 7} {
		if err := registry.RegisterDITStructureRule(DITStructureRule{
			RuleID: ruleID,
			Names:  []string{"rule" + strconv.Itoa(ruleID)},
			Form:   "domainNameForm",
		}); err != nil {
			t.Fatalf("register rule %d: %v", ruleID, err)
		}
	}
	descriptions := registry.DITStructureRuleDescriptions()
	for index, ruleID := range []int{2, 7, 11} {
		if !strings.HasPrefix(
			descriptions[index],
			"( "+strconv.Itoa(ruleID)+" ",
		) {
			t.Fatalf("description order = %#v", descriptions)
		}
	}
}

func TestGoverningStructureRuleErrorIsNamingViolation(t *testing.T) {
	t.Parallel()

	registry := newDITStructureRegistry(t)
	if err := registry.ParseAndRegisterNameForm(
		"( 1.3.6.1.4.1.99999.10 NAME 'domainNameForm' OC domain MUST dc )",
	); err != nil {
		t.Fatalf("register name form: %v", err)
	}
	if err := registry.ParseAndRegisterDITStructureRule(
		"( 1 FORM domainNameForm )",
	); err != nil {
		t.Fatalf("register structure rule: %v", err)
	}
	entry := structureEntry("o=example", "domain", map[string]string{
		"dc": "example",
		"o":  "example",
	})
	_, _, err := registry.GoverningStructureRule(entry, nil)
	var violation *Violation
	if !errors.As(err, &violation) || violation.Kind != ViolationNaming {
		t.Fatalf("GoverningStructureRule() error = %v", err)
	}
}
