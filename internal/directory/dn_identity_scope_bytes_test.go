package directory

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSimpleDNDepthBytesReference(t *testing.T) {
	check := func(value []byte) {
		t.Helper()
		got, simple := simpleDNDepthBytes(value)
		want, wantSimple := simpleDNDepth(string(value))
		if got != want || simple != wantSimple {
			t.Fatalf("recognize %q: bytes %d/%t, string %d/%t", value, got, simple, want, wantSimple)
		}
	}
	check(nil)
	for _, value := range []string{
		"", "cn=", "cn=a,", "cn=a,,dc=x", "cn=a+uid=b", `cn=a\,b`,
		"cn= Alice", "cn=a ", "cn=a=b", "cn=#6162", "cn=a;b", "cn=\xff", "cn=\u00e9",
		"cn;lang-en=a", "01.2=a", "1.02.3=a", "0=a", "0.0=a", "1..2=a", "1.=a", ".1=a",
		"CN-1=a_b.c-12", "uid=alice,ou=people,dc=example,dc=com",
	} {
		check([]byte(value))
	}
	for _, original := range []string{"uid=alice,ou=people,dc=example,dc=com", "2.5.4.3=a_b.c-12", "CN-1=a"} {
		value := []byte(original)
		for position := range value {
			for replacement := range 256 {
				value[position] = byte(replacement)
				check(value)
			}
			value[position] = original[position]
		}
	}
}

func TestValidateDNIdentityInScopeBytesBorrowedInputs(t *testing.T) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"", "uid=alice,ou=people,dc=example,dc=com", "2.5.4.3=a_b.c-12",
		"cn=Alice+uid=a,dc=example,dc=com", `cn=Smith\, Alice,dc=example,dc=com`,
		"uid=" + strings.Repeat("a", 2048),
	} {
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{dn.Key(), dn.LegacyKey(), dn.Key() + "\r\n", "dn:v2:!", "legacy"} {
			// Both views share storage and have spare capacity into adjacent fields.
			backing := []byte("prefix|" + value + "|" + key + "|suffix")
			original := bytes.Clone(backing)
			valueView := backing[7 : 7+len(value)]
			keyView := backing[8+len(value) : 8+len(value)+len(key)]
			for _, scopeBase := range []DN{base, dn, {}} {
				for scope := Scope(-1); scope <= Scope(4); scope++ {
					checkDNIdentityScopeBytes(t, valueView, keyView, scopeBase, scope)
				}
			}
			if !bytes.Equal(backing, original) {
				t.Fatal("validation modified borrowed input or adjacent fields")
			}
		}
	}
	for _, value := range [][]byte{nil, {}} {
		for _, key := range [][]byte{nil, {}, []byte("dn:v2:AA")} {
			checkDNIdentityScopeBytes(t, value, key, base, ScopeWholeSubtree)
		}
	}
}

func TestValidateDNIdentityInScopeBytesErrorsOwnInputs(t *testing.T) {
	schemaEmpty, err := ParseDNWithNormalizer("", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	dn, err := ParseDNWithNormalizer("cn=a", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, value, key string
		base             DN
	}{
		{"display", "cn", "legacy", schemaEmpty},
		{"legacy_key", "uid=alice,dc=example,dc=com", "legacy", schemaEmpty},
		{"encoding", "cn=a", "dn:v2:A\r\n", schemaEmpty},
		{"nested", "cn=a", encodeDNIdentity([][]byte{nil}), schemaEmpty},
		{"scope_base", "cn=a", dn.Key(), DN{}},
		{"scope_candidate", "cn=a", "cn=a", schemaEmpty},
	} {
		t.Run(test.name, func(t *testing.T) {
			valueBytes, keyBytes := []byte(test.value), []byte(test.key)
			matched, scopeErr, validationErr := ValidateDNIdentityInScopeBytes(valueBytes, keyBytes, test.base, ScopeWholeSubtree)
			want, wantScopeErr, wantValidationErr := referenceValidateDNIdentityInScope(test.value, test.key, test.base, ScopeWholeSubtree)
			if wantScopeErr == nil && wantValidationErr == nil {
				t.Fatal("fixture must produce an error")
			}
			clear(valueBytes)
			clear(keyBytes)
			// Compare the full errors, including wrapped fields, after input reuse.
			if matched != want || !reflect.DeepEqual(scopeErr, wantScopeErr) || !reflect.DeepEqual(validationErr, wantValidationErr) {
				t.Fatalf("errors after input reuse: got %t, %v, %v; want %t, %v, %v", matched, scopeErr, validationErr, want, wantScopeErr, wantValidationErr)
			}
		})
	}
}

func TestValidateDNIdentityInScopeBytesNoAllocs(t *testing.T) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	schemaEmpty, err := ParseDNWithNormalizer("", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	values := []string{"uid=alice,ou=people,dc=example,dc=com", "2.5.4.3=a_b.c-12", "CN-1=a"}
	for _, payloadSize := range []int{1023, 1024} {
		values = append(values, "uid="+strings.Repeat("a", payloadSize-13))
	}
	for _, value := range values {
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		valueBytes, keyBytes := []byte(value), []byte(dn.Key())
		for _, scopeBase := range []DN{base, dn, schemaEmpty} {
			for scope := Scope(-1); scope <= Scope(4); scope++ {
				want, wantErr := IdentityKeyInScope(scopeBase, dn.Key(), scope)
				if wantErr != nil {
					t.Fatal(wantErr)
				}
				allocs := testing.AllocsPerRun(100, func() {
					matched, scopeErr, validationErr := ValidateDNIdentityInScopeBytes(valueBytes, keyBytes, scopeBase, scope)
					if matched != want || scopeErr != nil || validationErr != nil {
						t.Fatalf("scope = %t, %v, %v; want %t", matched, scopeErr, validationErr, want)
					}
				})
				if allocs != 0 {
					t.Fatalf("value bytes=%d, scope=%d allocated %g times", len(value), scope, allocs)
				}
			}
		}
	}
	// Validation checks structure, not equality between display and key values.
	// A large compatible display must not introduce an eager string copy either.
	value := []byte("uid=" + strings.Repeat("a", 64*1024) + ",dc=example,dc=com")
	dn, err := ParseDNWithNormalizer("uid=a,dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(dn.Key())
	checkDNIdentityScopeBytes(t, value, key, base, ScopeSingleLevel)
	if allocs := testing.AllocsPerRun(10, func() {
		matched, scopeErr, validationErr := ValidateDNIdentityInScopeBytes(value, key, base, ScopeSingleLevel)
		if !matched || scopeErr != nil || validationErr != nil {
			t.Fatalf("scope = %t, %v, %v", matched, scopeErr, validationErr)
		}
	}); allocs != 0 {
		t.Fatalf("large display allocated %g times", allocs)
	}
}

func TestValidateDNIdentityInScopeBytesBufferBoundaries(t *testing.T) {
	for _, size := range []int{1023, 1024, 1025, 4096} {
		value := "uid=" + strings.Repeat("a", size-13)
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		encoded := []byte(dn.Key()[len(schemaAwareDNKeyPrefix):])
		if got := base64.RawURLEncoding.DecodedLen(len(encoded)); got != size {
			t.Fatalf("payload size = %d, want %d", got, size)
		}
		checkDNIdentityScopeBytes(t, []byte(value), []byte(dn.Key()), dn, ScopeBase)
	}
}

func BenchmarkValidateDNIdentityInScopeBytes(b *testing.B) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		b.Fatal(err)
	}
	tests := []struct{ name, value string }{
		{"typical", "uid=alice,ou=people,dc=example,dc=com"},
		{"oid", "2.5.4.3=Alice,dc=example,dc=com"},
		{"outside_scope", "uid=alice,dc=other,dc=com"},
		{"multi_fallback", "cn=Alice+uid=a,dc=example,dc=com"},
		{"escaped_fallback", `cn=Smith\, Alice,dc=example,dc=com`},
	}
	for _, size := range []int{1023, 1024, 1025} {
		tests = append(tests, struct{ name, value string }{fmt.Sprintf("payload_bytes=%d", size), "uid=" + strings.Repeat("a", size-13)})
	}
	for _, test := range tests {
		dn, err := ParseDNWithNormalizer(test.value, aliasIdentityNormalizer{})
		if err != nil {
			b.Fatal(err)
		}
		value, key := []byte(test.value), []byte(dn.Key())
		b.Run(test.name, func(b *testing.B) {
			b.Run("string_copies", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_, scopeErr, validationErr := ValidateDNIdentityInScope(string(value), string(key), base, ScopeWholeSubtree)
					if scopeErr != nil || validationErr != nil {
						b.Fatalf("scope: %v; validation: %v", scopeErr, validationErr)
					}
				}
			})
			b.Run("bytes", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_, scopeErr, validationErr := ValidateDNIdentityInScopeBytes(value, key, base, ScopeWholeSubtree)
					if scopeErr != nil || validationErr != nil {
						b.Fatalf("scope: %v; validation: %v", scopeErr, validationErr)
					}
				}
			})
		})
	}
}
