package directory

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestValidateDNIdentityInScopeReference(t *testing.T) {
	values := []string{
		"", " ", "cn=", "dc=com", "dc=example,dc=com", "dc=other,dc=com",
		"ou=people,dc=example,dc=com", "uid=alice,ou=people,dc=example,dc=com",
		"commonName=ALICE,dc=example,dc=com", "2.5.4.3=Alice,dc=example,dc=com",
		"exactName=Alice,dc=example,dc=com", "exactAlias=alice,dc=example,dc=com",
		"exactAlias=Case+commonName=ALICE+uid=a,dc=example,dc=com",
		"uid=A+2.5.4.3=Alice+1.2.3.4=Case,dc=example,dc=com",
		" cn = Alice , dc = example , dc = com ",
		`cn=\ leading\ +uid=Smith\, Alice,dc=example,dc=com`,
		`cn=\00\ff\c3\a9\+\"\;\<\>\\,dc=example,dc=com`,
		"cn=" + strings.Repeat("a", 4096) + ",dc=example,dc=com",
		strings.Repeat("ou=people,", 130) + "dc=example,dc=com",
	}
	dns := make([]DN, len(values))
	bases := []DN{{}}
	for index, value := range values {
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		dns[index] = dn
		legacy, err := ParseDN(value)
		if err != nil {
			t.Fatal(err)
		}
		bases = append(bases, dn, legacy)
	}
	for index, dn := range dns {
		for _, value := range []string{values[index], dn.String()} {
			for _, key := range []string{dn.Key(), dn.LegacyKey()} {
				for _, base := range bases {
					for scope := Scope(-1); scope <= Scope(4); scope++ {
						checkDNIdentityScope(t, value, key, base, scope)
					}
				}
			}
		}
	}
}

func TestValidateDNIdentityInScopeErrorsAndFallbacks(t *testing.T) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	ava := encodeDNIdentityParts([]byte("cn"), []byte("a"))
	otherAVA := encodeDNIdentityParts([]byte("uid"), []byte("b"))
	rdn := encodeDNIdentityParts(ava)
	invalidAVA := encodeDNIdentityParts(nil, []byte("a"))
	invalidRDN := encodeDNIdentityParts(invalidAVA)
	const invalid0 = "schema-aware DN key RDN 0 contains an invalid AVA"
	for _, test := range []struct {
		name, value, key, validationErr string
	}{
		{"valid", "cn=a", encodeDNIdentity([][]byte{rdn}), ""},
		{"legacy", "cn=a", "cn=a", ""},
		{"legacy_mismatch", "cn=a", "cn=b", `legacy key does not match normalized DN "cn=a"`},
		{"encoding", "cn=a", "dn:v2:A\r\n", "schema-aware DN key is not canonically encoded"},
		{"outer_lengths", "cn=a,dc=b", "dn:v2:AgCA", "decode schema-aware DN key RDNs: part 1 has a truncated length"},
		{"missing_rdn", "cn=a", encodeDNIdentity(nil), "schema-aware DN key has 0 RDNs, display DN has 1"},
		{"extra_rdn", "cn=a", encodeDNIdentity([][]byte{rdn, nil}), "schema-aware DN key has 2 RDNs, display DN has 1"},
		{"missing_avas", "cn=a", encodeDNIdentity([][]byte{encodeDNIdentityParts()}), ""},
		{"fewer_avas", "cn=a+uid=b", encodeDNIdentity([][]byte{rdn}), ""},
		{"extra_avas", "cn=a", encodeDNIdentity([][]byte{encodeDNIdentityParts(ava, otherAVA)}), ""},
		{"duplicate_types", "cn=a+uid=b", encodeDNIdentity([][]byte{encodeDNIdentityParts(ava, ava)}), ""},
		{"unsorted_avas", "cn=a+uid=b", encodeDNIdentity([][]byte{encodeDNIdentityParts(otherAVA, ava)}), ""},
		{"arbitrary_type", "cn=a", encodeDNIdentity([][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte{0xff}, nil))}), ""},
		{"nonminimal_varints", "cn=a", encodeDNIdentity([][]byte{encodeDNIdentityParts([]byte{0x82, 0, 0x82, 0, 'c', 'n', 0x81, 0, 'a'})}), ""},
		{"last_ava_invalid", "cn=a+uid=b", encodeDNIdentity([][]byte{encodeDNIdentityParts(ava, invalidAVA)}), invalid0},
		{"fallback_invalid_ava", "cn=a", encodeDNIdentity([][]byte{encodeDNIdentityParts(ava, invalidAVA)}), invalid0},
		{"last_rdn_invalid", "cn=a,dc=b", encodeDNIdentity([][]byte{rdn, invalidRDN}), "schema-aware DN key RDN 1 contains an invalid AVA"},
		{"skipped_prefix_invalid", "cn=a,dc=example,dc=com", encodeDNIdentity(append([][]byte{invalidRDN}, base.identityRDNs...)), invalid0},
		{"mismatched_suffix_invalid", "cn=a,dc=b,dc=c", encodeDNIdentity([][]byte{rdn, rdn, invalidRDN}), "schema-aware DN key RDN 2 contains an invalid AVA"},
		{"earlier_ava_error", "cn=a,dc=b", encodeDNIdentity([][]byte{invalidRDN, nil}), invalid0},
		{"later_length_error", "cn=a+uid=b", encodeDNIdentity([][]byte{{2, 0, 0x80}}), "decode schema-aware DN key RDN 0: part 1 has a truncated length"},
		{"fallback_later_error", "cn=a,dc=b", encodeDNIdentity([][]byte{encodeDNIdentityParts(), nil}), "decode schema-aware DN key RDN 1: truncated part count"},
	} {
		t.Run(test.name, func(t *testing.T) {
			bases := []DN{base, {}, {identityLevel: schemaAwareDNIdentityLevel}}
			if restored, err := referenceParseDNWithIdentityKey(test.value, test.key); err == nil {
				// Accepted AVA cardinality mismatches still retain the entire
				// physical RDN for exact scope comparisons after fallback.
				bases = append(bases, restored)
			}
			for _, scopeBase := range bases {
				for scope := Scope(-1); scope <= Scope(4); scope++ {
					checkDNIdentityScope(t, test.value, test.key, scopeBase, scope)
					_, scopeErr, validationErr := ValidateDNIdentityInScope(test.value, test.key, scopeBase, scope)
					if test.validationErr != "" {
						if validationErr == nil || validationErr.Error() != test.validationErr || scopeErr != nil {
							t.Fatalf("validation error must precede scope: got %v, %v; want %q", scopeErr, validationErr, test.validationErr)
						}
					} else if validationErr != nil {
						t.Fatal(validationErr)
					}
				}
			}
		})
	}
	for _, value := range []string{"cn", "=a", "cn=a+CN=b", "cn;lang-en=a", "bad_type=a", "1.02.3=a", `cn=\`, `cn=\gg`, "cn=#zz"} {
		for _, key := range []string{base.Key(), "dn:v2:!", "dn:v2:A\n", "legacy", ""} {
			for _, scopeBase := range []DN{base, {}} {
				checkDNIdentityScope(t, value, key, scopeBase, ScopeWholeSubtree)
			}
		}
	}
}

func TestValidateDNIdentityInScopePayloadCorpus(t *testing.T) {
	base, err := ParseDNWithNormalizer("cn=a", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range identityPayloadCorpus() {
		key := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(payload)
		for _, value := range []string{"", " ", "cn=", "cn=a", "cn=a,dc=b", "uid=b+cn=a", "cn"} {
			for _, scopeBase := range []DN{base, {}} {
				for scope := Scope(-1); scope <= Scope(4); scope++ {
					checkDNIdentityScope(t, value, key, scopeBase, scope)
				}
			}
		}
	}
}

func TestValidateDNIdentityInScopeEncoding(t *testing.T) {
	base, err := ParseDNWithNormalizer("", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, size := range []int{0, 1, 2, 127, 128, 1011, 1012, 1013, 4096} {
		payload := encodeDNIdentityParts(encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn"), bytes.Repeat([]byte("a"), size))))
		// These value lengths place the whole payload exactly around 1024.
		if size >= 1011 && size <= 1013 && len(payload) != size+12 {
			t.Fatalf("unexpected boundary payload size: %d", len(payload))
		}
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		check := func(encoded string) {
			t.Helper()
			for scope := Scope(-1); scope <= Scope(4); scope++ {
				checkDNIdentityScope(t, "cn=a", schemaAwareDNKeyPrefix+encoded, base, scope)
			}
		}
		check(encoded)
		for _, last := range []byte(alphabet) {
			check(encoded[:len(encoded)-1] + string(last))
		}
		for removed := 1; removed <= 4; removed++ {
			check(encoded[:len(encoded)-removed])
		}
		for _, position := range []int{0, len(encoded) / 2, len(encoded)} {
			for _, inserted := range []string{"\r", "\n", "\r\n", "=", "==", " ", "\t", "!", "+", "/", "\x00", "\xff"} {
				check(encoded[:position] + inserted + encoded[position:])
			}
		}
	}
}

func TestValidateDNIdentityInScopeStackScratch(t *testing.T) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	value := "uid=alice,ou=people,dc=example,dc=com"
	dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		matched, scopeErr, validationErr := ValidateDNIdentityInScope(value, dn.Key(), base, ScopeWholeSubtree)
		if !matched || scopeErr != nil || validationErr != nil {
			t.Fatalf("combined scope = %t, %v, %v", matched, scopeErr, validationErr)
		}
	})
	if allocs != 0 {
		t.Fatalf("common combined validation/scope allocated %g times, want stack scratch", allocs)
	}
}

func BenchmarkValidateDNIdentityInScope(b *testing.B) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		b.Fatal(err)
	}
	tests := []struct{ name, value string }{
		{"empty", ""},
		{"typical", "uid=alice,ou=people,dc=example,dc=com"},
		{"alias_multi", "exactAlias=Alice+commonName=Example+uid=a,dc=example,dc=com"},
		{"escaped", `cn=\ leading\ +uid=Smith\, Alice,dc=example,dc=com`},
		{"long", "cn=" + strings.Repeat("a", 2048) + ",dc=example,dc=com"},
	}
	for _, size := range []int{1023, 1024, 1025} {
		tests = append(tests, struct{ name, value string }{fmt.Sprintf("payload_bytes=%d", size), "uid=" + strings.Repeat("a", size-13)})
	}
	for _, test := range tests {
		dn, err := ParseDNWithNormalizer(test.value, aliasIdentityNormalizer{})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(test.name, func(b *testing.B) {
			for _, operation := range []struct {
				name string
				fn   func(string, string, DN, Scope) (bool, error, error)
			}{
				{"separate", referenceValidateDNIdentityInScope},
				{"combined", ValidateDNIdentityInScope},
			} {
				b.Run(operation.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						_, scopeErr, validationErr := operation.fn(test.value, dn.Key(), base, ScopeWholeSubtree)
						if scopeErr != nil || validationErr != nil {
							b.Fatalf("scope: %v; validation: %v", scopeErr, validationErr)
						}
					}
				})
			}
		})
	}
}
