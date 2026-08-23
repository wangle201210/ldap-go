package schema

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	registryDNExactOID = "1.3.6.1.4.1.99999.918.1"
	registryDNFoldOID  = "1.3.6.1.4.1.99999.918.2"
)

func TestRegistryDNEqMatchingUsesNamingSchema(t *testing.T) {
	registry := newRegistryDNEqRegistry(t)

	exactUpper := []byte("registryExactAlias=Alice,dc=example,dc=com")
	exactLower := []byte("registryExactName=alice,dc=example,dc=com")
	comparison, err := registry.Compare("member", "", exactUpper, exactLower)
	if err != nil {
		t.Fatalf("Compare(member caseExact): %v", err)
	}
	if comparison == 0 {
		t.Fatal("distinguishedNameMatch folded a caseExact naming value")
	}

	aliasMultiAVA := []byte(
		"registryFoldAlias=ENGINEERING+registryExactAlias=Alice," +
			"domainComponent=EXAMPLE,dc=COM",
	)
	oidMultiAVA := []byte(
		registryDNExactOID + "=Alice+" + registryDNFoldOID +
			"=engineering,dc=example,0.9.2342.19200300.100.1.25=com",
	)
	comparison, err = registry.Compare("member", "", aliasMultiAVA, oidMultiAVA)
	if err != nil {
		t.Fatalf("Compare(member alias multi-AVA): %v", err)
	}
	if comparison != 0 {
		t.Fatalf("schema-equivalent multi-AVA DNs compare as %d", comparison)
	}

	normalized, err := registry.NormalizeEqualityValue("member", aliasMultiAVA)
	if err != nil {
		t.Fatalf("NormalizeEqualityValue(member): %v", err)
	}
	const wantNormalized = "registryExactName=Alice+" +
		"registryFoldName=engineering,dc=example,dc=com"
	if got := string(normalized); got != wantNormalized {
		t.Fatalf("normalized member = %q, want %q", got, wantNormalized)
	}
	if bytes.HasPrefix(normalized, []byte("dn:v2:")) {
		t.Fatalf("normalized member exposed internal DN key %q", normalized)
	}

	assertion, err := registry.NormalizeEqualityAssertion("member", oidMultiAVA)
	if err != nil {
		t.Fatalf("NormalizeEqualityAssertion(member): %v", err)
	}
	if string(assertion) != wantNormalized {
		t.Fatalf("normalized member assertion = %q, want %q", assertion, wantNormalized)
	}
}

func TestRegistryUniqueMemberMatchUsesNamingSchemaAndUID(t *testing.T) {
	registry := newRegistryDNEqRegistry(t)
	aliasDN := "registryFoldAlias=ENGINEERING+registryExactAlias=Alice," +
		"dc=example,dc=com"
	oidDN := registryDNExactOID + "=Alice+" + registryDNFoldOID +
		"=engineering,dc=example,dc=com"

	compare := func(left, right string) int {
		t.Helper()
		comparison, err := registry.Compare(
			"uniqueMember",
			"",
			[]byte(left),
			[]byte(right),
		)
		if err != nil {
			t.Fatalf("Compare(uniqueMember, %q, %q): %v", left, right, err)
		}
		return comparison
	}

	if got := compare(aliasDN+"#'0101'B", oidDN+"#'0101'B"); got != 0 {
		t.Fatalf("equivalent uniqueMember values compare as %d", got)
	}
	if got := compare(aliasDN+"#'0101'B", oidDN+"#'0110'B"); got == 0 {
		t.Fatal("uniqueMemberMatch ignored optional UID bits")
	}
	if got := compare(aliasDN+"#'0101'B", oidDN); got == 0 {
		t.Fatal("uniqueMemberMatch ignored optional UID presence")
	}
	if got := compare(
		"registryExactName=alice+registryFoldName=engineering,"+
			"dc=example,dc=com#'0101'B",
		oidDN+"#'0101'B",
	); got == 0 {
		t.Fatal("uniqueMemberMatch folded a caseExact naming value")
	}

	normalized, err := registry.NormalizeEqualityValue(
		"uniqueMember",
		[]byte(aliasDN+"#'0101'B"),
	)
	if err != nil {
		t.Fatalf("NormalizeEqualityValue(uniqueMember): %v", err)
	}
	const want = "registryExactName=Alice+registryFoldName=engineering," +
		"dc=example,dc=com#'0101'B"
	if string(normalized) != want {
		t.Fatalf("normalized uniqueMember = %q, want %q", normalized, want)
	}
}

func TestStoredDNEqNormalizationUsesRegistry(t *testing.T) {
	registry := newRegistryDNEqRegistry(t)
	entry := directory.Entry{
		DN: "cn=registry-dn-values,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("top", "device", "extensibleObject")},
			{Description: "cn", Values: byteValues("registry-dn-values")},
			{
				Description: "member",
				Values: byteValues(
					"registryExactAlias=Alice,dc=example,dc=com",
				),
			},
			{
				Description: "uniqueMember",
				Values: byteValues(
					"registryFoldAlias=ALICE,dc=example,dc=com#'101'B",
				),
			},
		},
	}
	options := EntryValidationOptions{SkipValueSyntax: true}
	if err := registry.ValidateEntryWithOptions(entry, options); err != nil {
		t.Fatalf("ValidateEntryWithOptions(schema DN values): %v", err)
	}

	invalid := entry.Clone()
	invalid.ReplaceValues(
		"member",
		byteValues("undefinedNamingType=Alice,dc=example,dc=com"),
	)
	err := registry.ValidateEntryWithOptions(invalid, options)
	if err == nil || !strings.Contains(err.Error(), "invalid DN") {
		t.Fatalf(
			"ValidateEntryWithOptions(undefined naming type) error = %v, want invalid DN",
			err,
		)
	}
}

func newRegistryDNEqRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( " + registryDNExactOID +
			" NAME ( 'registryExactName' 'registryExactAlias' )" +
			" EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " )",
		"( " + registryDNFoldOID +
			" NAME ( 'registryFoldName' 'registryFoldAlias' )" +
			" EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", description, err)
		}
	}
	return registry
}
