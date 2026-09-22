package directory

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDNIdentityEncodingMatchesRoundTrip(t *testing.T) {
	base, err := ParseDNWithNormalizer("cn=a", scopeIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(encoded string) {
		t.Helper()
		// This is the original canonical-encoding acceptance rule.
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		canonical := err == nil && base64.RawURLEncoding.EncodeToString(payload) == encoded
		key := schemaAwareDNKeyPrefix + encoded
		_, parseErr := ParseDNWithIdentityKey("cn=a", key)
		_, scopeErr := IdentityKeyInScope(base, key, ScopeWholeSubtree)
		for _, result := range []struct {
			name string
			err  error
			want string
		}{
			{"parse", parseErr, "schema-aware DN key is not canonically encoded"},
			{"scope", scopeErr, "candidate schema-aware DN key is not canonically encoded"},
		} {
			// Canonical bytes may still fail the subsequent identity structure checks.
			rejected := result.err != nil && result.err.Error() == result.want
			if rejected == canonical {
				t.Fatalf("%s encoding %q: canonical=%t, err=%v", result.name, encoded, canonical, result.err)
			}
		}
	}

	// Cover all short lengths, both base64 fast paths, and varint boundaries.
	var lengths []int
	for length := range 33 {
		lengths = append(lengths, length)
	}
	lengths = append(lengths, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, length := range lengths {
		raw := make([]byte, length)
		for index := range raw {
			raw[index] = byte(index*73 + length*19)
		}
		structured := encodeDNIdentityParts(encodeDNIdentityParts(encodeDNIdentityParts(
			[]byte("cn"), bytes.Repeat([]byte("a"), length),
		)))
		for _, payload := range [][]byte{raw, structured} {
			encoded := base64.RawURLEncoding.EncodeToString(payload)
			check(encoded)
			for _, suffix := range []string{"=", "==", "===", "A", "AA", "AAA", "AAAA"} {
				check(encoded + suffix)
			}
			for removed := 1; removed <= 4 && removed <= len(encoded); removed++ {
				check(encoded[:len(encoded)-removed])
			}
			if len(encoded) > 0 {
				// Exhaust all zero/nonzero unused tail-bit combinations.
				for _, last := range []byte(alphabet) {
					check(encoded[:len(encoded)-1] + string(last))
				}
			}
			for position := 0; position <= len(encoded); position++ {
				for _, newline := range []string{"\r", "\n", "\r\n"} {
					check(encoded[:position] + newline + encoded[position:])
				}
			}
			for _, position := range []int{0, len(encoded) / 2, len(encoded)} {
				// Include padding, other whitespace, standard-base64 symbols,
				// NUL, non-ASCII bytes, and valid alphabet bytes as controls.
				for value := range 256 {
					check(encoded[:position] + string([]byte{byte(value)}) + encoded[position:])
				}
			}
		}
	}
}

func TestDNIdentityEncodingPreservesStructuralErrors(t *testing.T) {
	t.Parallel()

	base, err := ParseDNWithNormalizer("cn=a", scopeIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	overflow := append(bytes.Repeat([]byte{0xff}, 9), 2)
	for _, test := range []struct {
		name    string
		payload []byte
		want    string
	}{
		{"empty", nil, "truncated part count"},
		{"truncated_count", []byte{0x80}, "truncated part count"},
		{"count_overflow", overflow, "part count overflows uint64"},
		{"excessive_count", []byte{3}, "part count exceeds encoded payload"},
		{"missing_length", []byte{1}, "part 0 has a truncated length"},
		{"truncated_length", []byte{1, 0x80}, "part 0 has a truncated length"},
		{"length_overflow", append([]byte{1}, overflow...), "part 0 length overflows uint64"},
		{"excessive_length", []byte{1, 1}, "part 0 length exceeds encoded payload"},
		{"trailing_bytes", []byte{0, 0}, "trailing bytes after encoded parts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(test.payload)
			_, parseErr := ParseDNWithIdentityKey("cn=a", key)
			if want := "decode schema-aware DN key RDNs: " + test.want; parseErr == nil || parseErr.Error() != want {
				t.Fatalf("parse error = %v, want %q", parseErr, want)
			}
			got, scopeErr := IdentityKeyInScope(base, key, ScopeWholeSubtree)
			if want := "decode candidate schema-aware DN key: " + test.want; got || scopeErr == nil || scopeErr.Error() != want {
				t.Fatalf("scope = %t, error = %v, want %q", got, scopeErr, want)
			}
		})
	}
	for _, test := range []struct {
		name string
		rdns [][]byte
		want string
	}{
		{"rdn_count", nil, "schema-aware DN key has 0 RDNs, display DN has 1"},
		{"empty_rdn", [][]byte{nil}, "decode schema-aware DN key RDN 0: truncated part count"},
		{"truncated_ava", [][]byte{encodeDNIdentityParts([]byte{1})}, "schema-aware DN key RDN 0 contains an invalid AVA"},
		{"ava_part_count", [][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn")))}, "schema-aware DN key RDN 0 contains an invalid AVA"},
		{"empty_type", [][]byte{encodeDNIdentityParts(encodeDNIdentityParts(nil, []byte("a")))}, "schema-aware DN key RDN 0 contains an invalid AVA"},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := encodeDNIdentity(test.rdns)
			_, err := ParseDNWithIdentityKey("cn=a", key)
			if err == nil || err.Error() != test.want {
				t.Fatalf("parse error = %v, want %q", err, test.want)
			}
			// Scope only validates the outer RDN sequence, not AVA contents.
			if got, err := IdentityKeyInScope(base, key, ScopeWholeSubtree); got || err != nil {
				t.Fatalf("scope = %t, error = %v, want false, nil", got, err)
			}
		})
	}
}

func TestDNIdentityEncodingPreservesGuards(t *testing.T) {
	t.Parallel()

	base, err := ParseDNWithNormalizer("cn=a", scopeIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ParseDN("cn=a")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"cn", "cn=a+cn=b", "=a"} {
		_, want := ParseDN(value)
		if want == nil {
			t.Fatalf("expected invalid display DN %q", value)
		}
		for _, key := range []string{base.Key(), "dn:v2:A\r", "legacy"} {
			_, got := ParseDNWithIdentityKey(value, key)
			if got == nil || got.Error() != want.Error() {
				t.Fatalf("parse %q with key %q: error = %v, want %v", value, key, got, want)
			}
		}
	}
	if got, err := ParseDNWithIdentityKey("cn=a", legacy.Key()); err != nil || got.Key() != legacy.Key() {
		t.Fatalf("legacy parse = %q, error = %v", got.Key(), err)
	}
	if _, err := ParseDNWithIdentityKey("cn=a", "cn=b"); err == nil || err.Error() != `legacy key does not match normalized DN "cn=a"` {
		t.Fatalf("legacy mismatch error = %v", err)
	}
	for _, test := range []struct {
		base DN
		key  string
		want string
	}{
		{DN{}, "dn:v2:A\n", "scope base has no schema-aware identity"},
		{legacy, "legacy", "scope base has no schema-aware identity"},
		{base, "legacy", "candidate has no schema-aware identity key"},
		{base, "DN:v2:AA", "candidate has no schema-aware identity key"},
		{base, "dn:v2:A\r", "candidate schema-aware DN key is not canonically encoded"},
	} {
		for _, scope := range []Scope{Scope(-1), ScopeBase, ScopeSingleLevel, ScopeWholeSubtree, ScopeChildren, Scope(4)} {
			got, err := IdentityKeyInScope(test.base, test.key, scope)
			if got || err == nil || err.Error() != test.want {
				t.Fatalf("scope %d with key %q = %t, error = %v, want %q", scope, test.key, got, err, test.want)
			}
		}
	}
}

func TestDNIdentityEncodingPreservesParsedDNAndScope(t *testing.T) {
	t.Parallel()

	base, err := ParseDNWithNormalizer("dc=example,dc=com", scopeIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"", "dc=Example,dc=COM", "ou=People,dc=example,dc=com",
		"cn=Smith\\, Alice+uid=Alice,ou=People,dc=example,dc=com", "dc=other,dc=com",
	} {
		original, err := ParseDNWithNormalizer(value, scopeIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseDNWithIdentityKey(original.String(), original.Key())
		if err != nil || got.Key() != original.Key() || got.String() != original.String() ||
			got.NormalizedString() != original.NormalizedString() || got.Depth() != original.Depth() ||
			!reflect.DeepEqual(got.RDNValues(), original.RDNValues()) {
			t.Fatalf("restore %q = %#v, error = %v, want %#v", value, got, err, original)
		}
		for scope := Scope(-1); scope <= Scope(4); scope++ {
			got, err := IdentityKeyInScope(base, original.Key(), scope)
			if want := InScope(base, original, scope); err != nil || got != want {
				t.Fatalf("scope %d for %q = %t, error = %v, want %t", scope, value, got, err, want)
			}
		}
	}
}

func BenchmarkDNIdentityKeyValidation(b *testing.B) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", scopeIdentityNormalizer{})
	if err != nil {
		b.Fatal(err)
	}
	for _, value := range []string{
		"cn=a", "uid=alice,ou=people,dc=example,dc=com",
		"cn=" + strings.Repeat("a", 512) + ",dc=example,dc=com",
	} {
		candidate, err := ParseDNWithNormalizer(value, scopeIdentityNormalizer{})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("display_bytes=%d", len(value)), func(b *testing.B) {
			b.Run("parse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := ParseDNWithIdentityKey(value, candidate.Key()); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("scope", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := IdentityKeyInScope(base, candidate.Key(), ScopeWholeSubtree); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
