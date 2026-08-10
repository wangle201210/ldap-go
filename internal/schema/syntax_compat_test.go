package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestLDAPIntegerOpenLDAPLexicalRulesAndArbitraryPrecision(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	valid := []string{
		"0",
		"1",
		"-1",
		"999999999999999999999999999999999999999999999999999999999999",
		"-999999999999999999999999999999999999999999999999999999999999",
	}
	for _, value := range valid {
		if err := registry.ValidateAttributeValue("uidNumber", []byte(value)); err != nil {
			t.Errorf("ValidateAttributeValue(uidNumber, %q): %v", value, err)
		}
		normalized, err := registry.NormalizeEqualityValue("uidNumber", []byte(value))
		if err != nil {
			t.Errorf("NormalizeEqualityValue(uidNumber, %q): %v", value, err)
			continue
		}
		if string(normalized) != value {
			t.Errorf("NormalizeEqualityValue(uidNumber, %q) = %q", value, normalized)
		}
	}
	for _, value := range []string{"", "+1", "01", "-0", "-01", "-", " 1", "1 "} {
		if err := registry.ValidateAttributeValue("uidNumber", []byte(value)); err == nil {
			t.Errorf("ValidateAttributeValue(uidNumber, %q) succeeded", value)
		}
		if _, err := registry.NormalizeEqualityAssertion("uidNumber", []byte(value)); err == nil {
			t.Errorf("NormalizeEqualityAssertion(uidNumber, %q) succeeded", value)
		}
		normalized, err := registry.NormalizeEqualityValue("uidNumber", []byte(value))
		if err != nil || string(normalized) != value {
			t.Errorf(
				"NormalizeEqualityValue(uidNumber, %q) = %q, %v",
				value,
				normalized,
				err,
			)
		}
	}

	large := []byte("10000000000000000000000000000000000000000")
	comparison, err := registry.CompareOrdering(
		"uidNumber",
		"",
		large,
		[]byte("9999999999999999999999999999999999999999"),
	)
	if err != nil || comparison <= 0 {
		t.Fatalf("large positive comparison = %d, %v", comparison, err)
	}
	comparison, err = registry.CompareOrdering(
		"uidNumber",
		"",
		append([]byte("-"), large...),
		[]byte("-9999999999999999999999999999999999999999"),
	)
	if err != nil || comparison >= 0 {
		t.Fatalf("large negative comparison = %d, %v", comparison, err)
	}
}

func TestGeneralizedTimeOpenLDAPFormsAndNormalization(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	tests := []struct {
		value string
		want  string
	}{
		{value: "2024010203Z", want: "20240102030000Z"},
		{value: "202401020304Z", want: "20240102030400Z"},
		{value: "20240102030405Z", want: "20240102030405Z"},
		{value: "2024010203,5000Z", want: "20240102030000.5Z"},
		{value: "20240102030405.000Z", want: "20240102030405Z"},
		{value: "20240102030405,1200Z", want: "20240102030405.12Z"},
		{value: "20240102030405+08", want: "20240101190405Z"},
		{value: "20240102030405-0830", want: "20240102113405Z"},
		{value: "20240101003060+01", want: "20231231233060Z"},
	}
	for _, test := range tests {
		if err := registry.ValidateAttributeValue("createTimestamp", []byte(test.value)); err != nil {
			t.Errorf("ValidateAttributeValue(createTimestamp, %q): %v", test.value, err)
			continue
		}
		normalized, err := registry.NormalizeEqualityValue(
			"createTimestamp",
			[]byte(test.value),
		)
		if err != nil {
			t.Errorf("NormalizeEqualityValue(createTimestamp, %q): %v", test.value, err)
			continue
		}
		if string(normalized) != test.want {
			t.Errorf("NormalizeEqualityValue(createTimestamp, %q) = %q, want %q", test.value, normalized, test.want)
		}
	}
	for _, value := range []string{
		"2024010203",
		"2024010203z",
		"2024023003Z",
		"2024010224Z",
		"202401020360Z",
		"20240102030461Z",
		"2024010203.Z",
		"2024010203+8",
		"2024010203+2400",
		"2024010203+1260",
	} {
		if err := registry.ValidateAttributeValue("createTimestamp", []byte(value)); err == nil {
			t.Errorf("ValidateAttributeValue(createTimestamp, %q) succeeded", value)
		}
	}

	comparison, err := registry.Compare(
		"createTimestamp",
		"",
		[]byte("20240102030405+08"),
		[]byte("20240101190405Z"),
	)
	if err != nil || comparison != 0 {
		t.Fatalf("equivalent generalized time comparison = %d, %v", comparison, err)
	}
	comparison, err = registry.CompareOrdering(
		"createTimestamp",
		"",
		[]byte("20240102030405Z"),
		[]byte("20240102030405.1Z"),
	)
	if err != nil || comparison >= 0 {
		t.Fatalf("fractional generalized time ordering = %d, %v", comparison, err)
	}
}

func TestAuthzMatchDefaultNormalizerValidatesValues(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	valid := []byte("{0}dn.subtree:ou=people,dc=example,dc=com")
	normalized, err := registry.NormalizeEqualityValue("authzTo", valid)
	if err != nil {
		t.Fatalf("NormalizeEqualityValue(authzTo): %v", err)
	}
	if string(normalized) != string(valid) {
		t.Fatalf("normalized authzTo = %q", normalized)
	}
	if _, err := registry.NormalizeEqualityValue("authzTo", []byte("not an authz rule")); err == nil {
		t.Fatal("NormalizeEqualityValue(authzTo) accepted an invalid rule")
	}

	entry := directory.Entry{
		DN: "cn=authz,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("top", "device", "extensibleObject")},
			{Description: "cn", Values: byteValues("authz")},
			{Description: "authzTo", Values: byteValues("not an authz rule")},
		},
	}
	err = registry.ValidateEntryWithOptions(
		entry,
		EntryValidationOptions{SkipValueSyntax: true},
	)
	assertViolation(t, err, ViolationSyntax)
}
