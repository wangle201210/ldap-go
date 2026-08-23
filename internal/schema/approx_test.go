package schema

import (
	"bytes"
	"testing"
)

func TestNormalizeOpenLDAPApproximate(t *testing.T) {
	t.Parallel()

	normalized, ok := normalizeOpenLDAPApproximate([]byte("Jérôme Ångström 中文"))
	if !ok {
		t.Fatal("valid UTF-8 was rejected")
	}
	if want := []byte("Jerome Angstrom "); !bytes.Equal(normalized, want) {
		t.Fatalf("normalized value = %q, want %q", normalized, want)
	}
	if _, ok := normalizeOpenLDAPApproximate([]byte{0xff}); ok {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestOpenLDAPApproximateOrderedWordsAndMetaphone(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		value     string
		assertion string
		want      bool
	}{
		{name: "phonetic surname", value: "Alice Smith", assertion: "Alice Smyth", want: true},
		{name: "asserted subset", value: "Alice Beth Smith", assertion: "Alice Smyth", want: true},
		{name: "word order", value: "Alice Smith", assertion: "Smyth Alice", want: false},
		{name: "missing word", value: "Alice Smith", assertion: "Alice Jones", want: false},
		{name: "accent decomposition", value: "Jérôme Smith", assertion: "Jerome Smyth", want: true},
		{name: "empty assertion", value: "Alice Smith", assertion: "   ", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := matchOpenLDAPApproximate(
				"directoryStringApproxMatch",
				[]byte(test.value),
				[]byte(test.assertion),
			)
			if got != test.want {
				t.Fatalf("match(%q, %q) = %v, want %v", test.value, test.assertion, got, test.want)
			}
		})
	}
	if openLDAPMetaphone([]byte("Smith")) != openLDAPMetaphone([]byte("Smyth")) {
		t.Fatal("Smith and Smyth have different OpenLDAP Metaphone keys")
	}
}

func TestRegistryMatchApproximateUsesAssociatedRuleOrEqualityFallback(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		attribute string
		value     string
		assertion string
		want      bool
	}{
		{name: "directory associated rule", attribute: "cn", value: "Alice Smith", assertion: "Alice Smyth", want: true},
		{name: "IA5 associated rule", attribute: "homeDirectory", value: "Alice Smith", assertion: "Alice Smyth", want: true},
		{name: "integer equality fallback", attribute: "uidNumber", value: "100", assertion: "100", want: true},
		{name: "octet equality fallback", attribute: "userPassword", value: "Secret", assertion: "secret", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := registry.MatchApproximate(
				test.attribute,
				[]byte(test.value),
				[]byte(test.assertion),
			)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("MatchApproximate() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAssociatedApproximateMatchingRule(t *testing.T) {
	t.Parallel()

	for _, equality := range []string{"caseIgnoreMatch", "2.5.13.2", "caseExactMatch"} {
		if rule, ok := AssociatedApproximateMatchingRule(equality); !ok || rule != "directorystringapproxmatch" {
			t.Fatalf("AssociatedApproximateMatchingRule(%q) = %q, %v", equality, rule, ok)
		}
	}
	for _, equality := range []string{"caseIgnoreIA5Match", "caseExactIA5Match"} {
		if rule, ok := AssociatedApproximateMatchingRule(equality); !ok || rule != "ia5stringapproxmatch" {
			t.Fatalf("AssociatedApproximateMatchingRule(%q) = %q, %v", equality, rule, ok)
		}
	}
	if rule, ok := AssociatedApproximateMatchingRule("integerMatch"); ok || rule != "" {
		t.Fatalf("integer associated rule = %q, %v", rule, ok)
	}
}
