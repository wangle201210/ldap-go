package schema

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func assertCachedAssertionParity(t *testing.T, registry *Registry, attribute string, value []byte) ([]byte, error) {
	t.Helper()
	want, wantErr := registry.NormalizeEqualityAssertion(attribute, value)
	for range 2 {
		got, gotErr := registry.NormalizeEqualityAssertionCachedDN(attribute, value)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("assertion %s=%q: got %#v, want %#v", attribute, value, got, want)
		}
		for actual, expected := gotErr, wantErr; actual != nil || expected != nil; {
			if reflect.TypeOf(actual) != reflect.TypeOf(expected) || fmt.Sprint(actual) != fmt.Sprint(expected) {
				t.Fatalf("assertion %s=%q: error %T (%v), want %T (%v)", attribute, value, actual, actual, expected, expected)
			}
			actual, expected = errors.Unwrap(actual), errors.Unwrap(expected)
		}
	}
	return want, wantErr
}

func TestNormalizeEqualityAssertionCachedDNParity(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.991", Names: []string{"assertionChild"}, Superior: "member"},
		{OID: "1.2.3.992", Names: []string{"assertionRuleOID"}, Equality: "2.5.13.1", Syntax: SyntaxDistinguishedName},
		{OID: "1.2.3.993", Names: []string{"assertionOrdered"}, Equality: "distinguishedNameMatch", Syntax: SyntaxDistinguishedName, Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
		{OID: "1.2.3.994", Names: []string{"assertionOctetDN"}, Equality: "distinguishedNameMatch", Syntax: SyntaxOctetString},
		{OID: "1.2.3.995", Names: []string{"assertionBadRule"}, Equality: "unsupportedMatch", Syntax: SyntaxOctetString},
		{OID: "1.2.3.996", Names: []string{"assertionBadSyntax"}, Equality: "distinguishedNameMatch", Syntax: "1.2.3.99999"},
		{OID: "1.2.3.997", Names: []string{"assertionBadSuperior"}, Superior: "undefinedSuperior"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		attribute, value string
		invalid          bool
	}{
		{"member", "", false},
		{"MEMBER;binary", "CN=Alice,DC=EXAMPLE,DC=COM", false},
		{"2.5.4.31", "userid=ALICE,dc=example", false},
		{"assertionChild", "registryExactAlias=Alice,dc=example", false},
		{"assertionRuleOID", registryDNExactOID + "=Alice", false},
		{"member", "registryFoldAlias=ENGINEERING+registryExactAlias=Alice,dc=example", false},
		{"member", registryDNExactOID + "=Alice+" + registryDNFoldOID + "=engineering,dc=example", false},
		{"member", `cn=Smith\, Alice+uid=ALICE,dc=example`, false},
		{"member", `cn=\c3\a9\+\00,dc=example`, false},
		{"member", `member=cn\=Alice,dc=example`, false},
		{"assertionOrdered", "cn=Alice", false},
		{"assertionOrdered", "{0}cn=Alice", true},
		{"assertionOrdered", "{bad}cn=Alice", true},
		{"member", "cn=broken,", true},
		{"member", `cn=bad\zz`, true},
		{"member", "cn=\xff", false},
		{"member", "undefinedName=Alice", true},
		{"member", "registryExactName=x+registryExactAlias=y", true},
		{"member", "unknownName=x,member=bad", true},
		{"member", "member=bad,unknownName=x", true},
		{"assertionOctetDN", "broken", true},
		{"assertionBadRule", "cn=Alice", true},
		{"assertionBadSyntax", "cn=Alice", true},
		{"assertionBadSuperior", "broken", true},
		{"undefinedAttribute", "broken", true},
		{"jpegPhoto", "broken", true},
		{"cn", "  ALICE  ", false},
		{"uidNumber", "123", false},
		{"uidNumber", "not-an-integer", true},
		{"dITStructureRules", "17", false},
		{"dITStructureRules", "not-an-integer", true},
		{"attributeTypes", "2.5.4.3", false},
		{"uniqueMember", "cn=Alice#'0101'B", false},
		{"userPassword", "\x00\xff", false},
	} {
		t.Run(test.attribute+"/"+test.value, func(t *testing.T) {
			_, err := assertCachedAssertionParity(t, registry, test.attribute, []byte(test.value))
			if (err != nil) != test.invalid {
				t.Fatalf("error = %v, invalid = %t", err, test.invalid)
			}
		})
	}
}

func TestNormalizeEqualityAssertionCachedDNValidationBeforeCache(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = "cn=Alice"
	mustCachedDN(t, registry, raw)
	attribute := AttributeType{OID: "1.2.3.991", Names: []string{"shortAssertion"}, Superior: "member", Syntax: SyntaxDistinguishedName, SyntaxLength: 4}
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	// Warm the same DN through an unconstrained attribute before each rejection.
	for _, test := range []struct {
		value, want string
	}{
		{raw, `attribute "shortAssertion" assertion: value exceeds syntax length 4`},
		{"broken", `attribute "shortAssertion" assertion: value exceeds syntax length 4`},
		{"bad", `attribute "shortAssertion" assertion: value is not a distinguished name`},
	} {
		assertCachedAssertionParity(t, registry, "member", []byte(raw))
		_, err := assertCachedAssertionParity(t, registry, "shortAssertion", []byte(test.value))
		if err == nil || err.Error() != test.want {
			t.Fatalf("error = %v, want %q", err, test.want)
		}
	}
	attribute.SyntaxLength = 0
	attribute.Syntax = SyntaxInteger
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	assertCachedAssertionParity(t, registry, "member", []byte(raw))
	_, err := assertCachedAssertionParity(t, registry, "shortAssertion", []byte(raw))
	if err == nil || err.Error() != `attribute "shortAssertion" assertion: value is not an integer` {
		t.Fatalf("cached DN bypassed assertion syntax: %v", err)
	}
	_, err = assertCachedAssertionParity(t, registry, "shortAssertion", []byte("1"))
	if err == nil || err.Error() != "distinguishedNameMatch received invalid DN" {
		t.Fatalf("normalization error changed after valid assertion syntax: %v", err)
	}
}

func TestNormalizeEqualityAssertionCachedDNMutationAndOwnership(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = registryDNExactOID + "=Alice"
	input := []byte(raw)
	first, err := registry.NormalizeEqualityAssertionCachedDN("member", input)
	if err != nil {
		t.Fatal(err)
	}
	dn := mustCachedDN(t, registry, raw)
	if string(first) != dn.NormalizedString() || string(first) == dn.Key() {
		t.Fatalf("assertion must retain normalized display bytes: %q", first)
	}
	want := bytes.Clone(first)
	clear(input)
	clear(first)
	second, err := registry.NormalizeEqualityAssertionCachedDN("member", []byte(raw))
	if err != nil || !bytes.Equal(second, want) {
		t.Fatalf("input or output mutation changed cached result: %q, %v", second, err)
	}
	third, err := registry.NormalizeEqualityAssertionCachedDN("member", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	clear(second)
	if !bytes.Equal(third, want) {
		t.Fatal("cache-hit outputs share backing bytes")
	}
	assertCachedAssertionParity(t, registry, "member", []byte("registryExactAlias=Alice"))
	attribute, _ := registry.AttributeType(registryDNExactOID)
	attribute.Names = []string{"renamedExact", "newExactAlias"}
	attribute.Equality = "caseIgnoreMatch"
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	after, err := assertCachedAssertionParity(t, registry, "member", []byte(raw))
	if err != nil || string(after) != "renamedExact=alice" || !bytes.Equal(third, want) {
		t.Fatalf("schema mutation/retained bytes: %q, %q, %v", after, third, err)
	}
	if _, err := assertCachedAssertionParity(t, registry, "member", []byte("registryExactAlias=Alice")); err == nil {
		t.Fatal("removed naming alias survived cache invalidation")
	}
	assertCachedAssertionParity(t, registry, "member", []byte("newExactAlias=Alice"))
	if _, err := assertCachedAssertionParity(t, registry, "member", []byte("newName=Alice")); err == nil {
		t.Fatal("undefined naming attribute accepted")
	}
	if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.991", Names: []string{"newName"}, Equality: "caseExactMatch"}); err != nil {
		t.Fatal(err)
	}
	if _, err := assertCachedAssertionParity(t, registry, "member", []byte("newName=Alice")); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeEqualityAssertionRemainsUncached(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = registryDNExactOID + "=Alice"
	if _, err := registry.NormalizeEqualityAssertion("member", []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if len(registry.dnCache.entries) != 0 {
		t.Fatal("original assertion API populated the cache")
	}
	assertCachedAssertionParity(t, registry, "member", []byte(raw))
	// Only the original API supports direct edits to externally shared names.
	attribute, _ := registry.AttributeType(registryDNExactOID)
	attribute.Names[0] = "externallyChanged"
	got, err := registry.NormalizeEqualityAssertion("member", []byte(raw))
	if err != nil || string(got) != "externallyChanged=Alice" {
		t.Fatalf("original API reused cached normalization: %q, %v", got, err)
	}
}

func TestNormalizeEqualityAssertionCachedDNBoundsAndOtherRules(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	for _, test := range []struct{ attribute, value string }{
		{"cn", "Alice"}, {"uniqueMember", "cn=Alice"}, {"uidNumber", "123"},
	} {
		assertCachedAssertionParity(t, registry, test.attribute, []byte(test.value))
	}
	if len(registry.dnCache.entries) != 0 {
		t.Fatal("non-DN matching rule populated the cache")
	}
	for _, raw := range []string{
		"cn=" + strings.Repeat("x", maxCachedDNInput),
		strings.Repeat("ou=x,", maxCachedDNDepth) + "dc=example",
	} {
		if _, err := assertCachedAssertionParity(t, registry, "member", []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if len(registry.dnCache.entries) != 0 {
			t.Fatal("oversized DN populated the cache")
		}
	}
	for index := range maxCachedDNs + 2 {
		if _, err := assertCachedAssertionParity(t, registry, "member", fmt.Appendf(nil, "cn=%d", index)); err != nil {
			t.Fatal(err)
		}
		if len(registry.dnCache.entries) > maxCachedDNs || registry.dnCache.bytes > maxCachedDNBytes {
			t.Fatal("assertion normalization exceeded shared DN cache bounds")
		}
	}
}
