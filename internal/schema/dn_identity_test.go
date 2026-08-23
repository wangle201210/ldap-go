package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestNormalizeDNSchemaAwareIdentity(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.900 NAME ( 'exactName' 'exactAlias' ) " +
			"EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.902 NAME ( 'foldName' 'foldAlias' ) " +
			"EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(): %v", err)
		}
	}

	exactUpper := mustNormalizedDN(t, registry, "exactName=Alice,dc=example,dc=com")
	exactLower := mustNormalizedDN(t, registry, "exactName=alice,dc=example,dc=com")
	if exactUpper.Equal(exactLower) || exactUpper.Key() == exactLower.Key() {
		t.Fatal("caseExactMatch naming values collapsed to one DN identity")
	}
	if got, want := exactUpper.String(), "exactName=Alice,dc=example,dc=com"; got != want {
		t.Fatalf("schema-aware pretty DN = %q, want %q", got, want)
	}
	aliasPretty := mustNormalizedDN(
		t,
		registry,
		"EXACTALIAS=Alice,domainComponent=example,0.9.2342.19200300.100.1.25=com",
	)
	if got, want := aliasPretty.String(), "exactName=Alice,dc=example,dc=com"; got != want {
		t.Fatalf("schema-aware alias pretty DN = %q, want %q", got, want)
	}

	foldName := mustNormalizedDN(t, registry, "foldName=Alice,dc=example,dc=com")
	foldAlias := mustNormalizedDN(
		t,
		registry,
		"foldAlias=  ALICE  ,domainComponent=example,0.9.2342.19200300.100.1.25=com",
	)
	if !foldName.Equal(foldAlias) || foldName.Key() != foldAlias.Key() {
		t.Fatalf("caseIgnore alias identities differ:\n%s\n%s", foldName.Key(), foldAlias.Key())
	}

	multiAVA := mustNormalizedDN(
		t,
		registry,
		"exactName=Alice+foldName=Engineering,dc=example,dc=com",
	)
	reordered := mustNormalizedDN(
		t,
		registry,
		"foldAlias=engineering+exactAlias=Alice,dc=example,dc=com",
	)
	if !multiAVA.Equal(reordered) || multiAVA.Key() != reordered.Key() {
		t.Fatalf("multi-AVA identities depend on AVA order:\n%s\n%s", multiAVA.Key(), reordered.Key())
	}

	parent, ok := multiAVA.Parent()
	if !ok {
		t.Fatal("schema-aware DN has no parent")
	}
	wantParent := mustNormalizedDN(t, registry, "dc=example,dc=com")
	if !parent.Equal(wantParent) || parent.Key() != wantParent.Key() {
		t.Fatalf("Parent() identity = %q, want %q", parent.Key(), wantParent.Key())
	}
	if !wantParent.AncestorOf(multiAVA) {
		t.Fatal("schema-aware parent is not an ancestor")
	}
}

func TestNormalizeDNRejectsUndefinedOrNonMatchingNamingType(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if _, err := registry.NormalizeDN("unknownName=value,dc=example,dc=com"); err == nil {
		t.Fatal("NormalizeDN() accepted an undefined naming attribute")
	}
	if _, err := registry.NormalizeDN("jpegPhoto=value,dc=example,dc=com"); err == nil {
		t.Fatal("NormalizeDN() accepted an attribute without equality matching")
	}
}

func mustNormalizedDN(t *testing.T, registry *Registry, value string) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(value)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", value, err)
	}
	return dn
}
