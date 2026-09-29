package schema

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeDNBytesCachedParityAndOwnership(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	stringRegistry := newRegistryDNEqRegistry(t)
	inputs := []string{
		"", " ", "cn=Alice", "CN=ALICE", "2.5.4.3=Alice",
		"registryExactAlias=Alice,dc=example",
		"registryFoldAlias=ENGINEERING+registryExactAlias=Alice,dc=example",
		`cn=Smith\, Alice+uid=ALICE,dc=example`,
		`member=registryExactAlias\=Alice\,dc\=EXAMPLE,dc=com`,
		"broken", `cn=bad\zz`, "undefinedName=Alice",
		"registryExactName=x+registryExactAlias=y", "member=bad,unknownName=x",
		"cn=" + strings.Repeat("x", maxCachedDNInput-3),
		"cn=" + strings.Repeat("x", maxCachedDNInput-2),
		strings.Repeat("ou=x,", maxCachedDNDepth-1) + "dc=example",
		strings.Repeat("ou=x,", maxCachedDNDepth) + "dc=example",
	}
	for i := range maxCachedDNs + 2 {
		inputs = append(inputs, fmt.Sprintf("cn=user%d,dc=example", i))
	}
	for _, raw := range inputs {
		for range 2 {
			input := []byte(raw)
			registry.mu.RLock()
			got, gotErr := registry.normalizeDNBytesCachedLocked(input)
			registry.mu.RUnlock()
			stringRegistry.mu.RLock()
			want, wantErr := stringRegistry.normalizeDNCachedLocked(raw)
			stringRegistry.mu.RUnlock()
			// Exercise both miss and hit ownership before reading returned or
			// cached DNs. Neither path may retain this mutable byte buffer.
			clear(input)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("byte normalization of %q differs from string normalization", raw)
			}
			for actual, expected := gotErr, wantErr; actual != nil || expected != nil; {
				if reflect.TypeOf(actual) != reflect.TypeOf(expected) || fmt.Sprint(actual) != fmt.Sprint(expected) {
					t.Fatalf("%q: error %T (%v), want %T (%v)", raw, actual, actual, expected, expected)
				}
				actual, expected = errors.Unwrap(actual), errors.Unwrap(expected)
			}
			if !reflect.DeepEqual(registry.dnCache.entries, stringRegistry.dnCache.entries) ||
				registry.dnCache.bytes != stringRegistry.dnCache.bytes ||
				registry.dnCache.generation != stringRegistry.dnCache.generation {
				t.Fatalf("byte lookup changed cache contents or accounting for %q", raw)
			}
		}
	}
}

func TestNormalizeDNBytesCachedGeneration(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	input := []byte(registryDNExactOID + "=Alice")
	normalize := func() normalizedDNCacheEntry {
		t.Helper()
		registry.mu.RLock()
		defer registry.mu.RUnlock()
		entry, err := registry.normalizeDNBytesCachedLocked(input)
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	before := normalize()
	generation := registry.dnCache.generation
	attribute, _ := registry.AttributeType(registryDNExactOID)
	attribute.Equality = "caseIgnoreMatch"
	attribute.Names = []string{"renamedExact"}
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	after := normalize()
	if after.normalizedString() != "renamedExact=alice" || after.dn.Equal(before.dn) ||
		before.normalizedString() != "registryExactName=Alice" {
		t.Fatal("byte lookup reused stale normalization or changed the previous result")
	}
	if registry.dnCache.generation == generation || registry.dnCache.generation != registry.preparedNames.generation {
		t.Fatal("byte lookup did not refresh the cache generation")
	}
	if got := normalize(); !reflect.DeepEqual(got, after) {
		t.Fatal("byte lookup did not retain the new generation")
	}
}
