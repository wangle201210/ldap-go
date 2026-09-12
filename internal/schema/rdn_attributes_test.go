package schema

import (
	"slices"
	"testing"
)

func TestRDNAttributeKeysIncludeAliasesInheritanceAndSubstitution(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := registry.RDNAttributeDescriptions(); err != nil || len(keys) != 0 {
		t.Fatalf("default schema unexpectedly formats RDN values: %v %v", keys, err)
	}
	if err := registry.registerLDAPSyntax(LDAPSyntax{OID: "1.2.3.4", Extensions: map[string][]string{"X-SUBST": {SyntaxRDN}}}); err != nil {
		t.Fatal(err)
	}
	for _, definition := range []string{
		"( 1.2.3.5 NAME ( 'rdnValue' 'rdnAlias' ) SYNTAX 1.2.3.4 )",
		"( 1.2.3.6 NAME 'rdnChild' SUP rdnValue )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := registry.RDNAttributeDescriptions()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"1.2.3.5", "rdnvalue", "rdnalias", "1.2.3.6", "rdnchild"} {
		if !slices.Contains(keys, key) {
			t.Fatalf("missing RDN formatter key %s: %v", key, keys)
		}
	}
}

func TestDirectoryStringSubstitutionEmptyValueUsesNativeObjectIdentity(t *testing.T) {
	registry := NewRegistry()
	if err := registry.registerLDAPSyntax(LDAPSyntax{OID: "1.2.3.4", Extensions: map[string][]string{"X-SUBST": {SyntaxDirectoryString}}}); err != nil {
		t.Fatal(err)
	}
	if err := registry.registerLDAPSyntax(LDAPSyntax{OID: "1.2.3.5", Extensions: map[string][]string{"X-SUBST": {"1.2.3.4"}}}); err != nil {
		t.Fatal(err)
	}
	for index, syntax := range []string{SyntaxDirectoryString, "1.2.3.4", "1.2.3.5"} {
		if err := registry.validateSyntax(syntax, 0, nil); (err == nil) != (index > 0) {
			t.Fatalf("empty %s: %v", syntax, err)
		}
		if err := registry.validateSyntax(syntax, 0, []byte{0xff}); err == nil {
			t.Fatalf("invalid UTF-8 accepted via %s", syntax)
		}
	}
}
