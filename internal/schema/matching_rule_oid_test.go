package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestSubstringMatchingRuleNumericOIDs(t *testing.T) {
	for _, test := range []struct {
		oid, name, syntax, value, assertion string
		match                               bool
	}{
		{"2.5.13.4", "caseIgnoreSubstringsMatch", SyntaxDirectoryString, "Alpha Beta", "alpha", true},
		{"2.5.13.7", "caseExactSubstringsMatch", SyntaxDirectoryString, "Alpha Beta", "alpha", false},
		{"1.3.6.1.4.1.1466.109.114.3", "caseIgnoreIA5SubstringsMatch", SyntaxIA5String, "ALPHA@example", "alpha", true},
		{"1.3.6.1.4.1.4203.1.2.1", "caseExactIA5SubstringsMatch", SyntaxIA5String, "ALPHA@example", "alpha", false},
		{"2.5.13.10", "numericStringSubstringsMatch", SyntaxNumericString, "12 34", "1 2", true},
		{"2.5.13.12", "caseIgnoreListSubstringsMatch", SyntaxPostalAddress, "Alpha$Beta", "alpha", true},
		{"2.5.13.21", "telephoneNumberSubstringsMatch", SyntaxTelephoneNumber, "+1 234-567", "+1234", true},
		{"2.5.13.19", "octetStringSubstringsMatch", SyntaxOctetString, "\x00\xffAb C", "\x00\xffAb", true},
		{"2.5.13.19", "octetStringSubstringsMatch", SyntaxOctetString, "\x00\xffAb C", "\x00\xffab", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, rule := range []string{test.name, test.oid} {
				registry := NewRegistry()
				if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.4", Names: []string{"sample"}, Syntax: test.syntax, Substring: rule}); err != nil {
					t.Fatal(err)
				}
				assertion := directory.Substring{Initial: []byte(test.assertion)}
				matched, err := registry.MatchSubstring("sample", []byte(test.value), assertion)
				if err != nil || matched != test.match {
					t.Fatalf("%s general matcher: %v %v", rule, matched, err)
				}
				prepared, err := registry.PrepareSubstringMatcher("sample", assertion)
				if err != nil {
					t.Fatal(err)
				}
				matched, err = prepared.Match(directory.Entry{Attributes: []directory.Attribute{{Description: "sample", Values: [][]byte{[]byte(test.value)}}}})
				if err != nil || matched != test.match {
					t.Fatalf("%s prepared matcher: %v %v", rule, matched, err)
				}
			}
		})
	}
}

func TestMatchingRuleSchemaAssertionAliases(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"matchingRules", "2.5.21.4", "matchingRuleUse", "2.5.21.8"} {
		value := []byte("( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )")
		if attribute == "matchingRuleUse" || attribute == "2.5.21.8" {
			value = []byte("( 2.5.13.2 NAME 'caseIgnoreMatch' APPLIES cn )")
		}
		for _, assertion := range []string{"caseIgnoreMatch", "CASEIGNOREMATCH", "2.5.13.2"} {
			if cmp, err := registry.Compare(attribute, "", value, []byte(assertion)); err != nil || cmp != 0 {
				t.Fatalf("%s %s: cmp=%d err=%v", attribute, assertion, cmp, err)
			}
		}
		if cmp, err := registry.Compare(attribute, "", value, []byte("1.2.3.999")); err != nil || cmp == 0 {
			t.Fatalf("unknown numeric rule: cmp=%d err=%v", cmp, err)
		}
		if _, err := registry.Compare(attribute, "", value, []byte("noSuchRule")); err == nil {
			t.Fatal("unknown symbolic rule treated as known")
		}
	}
}

func TestCountryStringSyntaxUsedByMatchingRules(t *testing.T) {
	registry := NewRegistry()
	if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.4", Names: []string{"countryValue"}, Syntax: SyntaxCountryString, Equality: "caseIgnoreMatch"}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"US", "cn", "12", "  ", "?+"} {
		if err := registry.ValidateAttributeValue("countryValue", []byte(value)); err != nil {
			t.Fatalf("valid CountryString %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "A", "USA", "C\xff", "C\x00", "\xc3\xb6", "U!"} {
		if err := registry.ValidateAttributeValue("countryValue", []byte(value)); err == nil {
			t.Fatalf("invalid CountryString %q accepted", value)
		}
	}
}
