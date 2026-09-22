package directory

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

func checkDNIdentityEquivalence(t *testing.T, value, key string, base DN, scope Scope) {
	t.Helper()
	want, wantErr := referenceParseDNWithIdentityKey(value, key)
	got, gotErr := ParseDNWithIdentityKey(value, key)
	if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
		t.Fatalf("parse %q / %q:\ngot %#v, %v\nwant %#v, %v", value, key, got, gotErr, want, wantErr)
	}
	wantScope, wantErr := referenceIdentityKeyInScope(base, key, scope)
	gotScope, gotErr := IdentityKeyInScope(base, key, scope)
	if gotScope != wantScope || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatalf("scope %d / %q: got %t, %v; want %t, %v", scope, key, gotScope, gotErr, wantScope, wantErr)
	}
}

func identityPayloadCorpus() [][]byte {
	ava := encodeDNIdentityParts([]byte("cn"), []byte("a"))
	rdn := encodeDNIdentityParts(ava)
	payloads := [][]byte{
		nil, {0}, {0, 0}, {1}, {2}, {3}, {0x80}, {0x80, 0},
		{1, 0x80}, {1, 2, 0}, {0x81, 0, 0x80, 0},
		append(bytes.Repeat([]byte{0xff}, 9), 2),
		append([]byte{1}, append(bytes.Repeat([]byte{0xff}, 9), 2)...),
		ava, rdn, encodeDNIdentityParts(rdn),
		encodeDNIdentityParts(rdn, rdn),
	}
	// Exercise error precedence at every nesting level, including malformed
	// later lengths after an earlier invalid AVA, and accepted non-minimal varints.
	for _, payload := range append([][]byte(nil), payloads...) {
		payloads = append(payloads, encodeDNIdentityParts(payload),
			encodeDNIdentityParts(encodeDNIdentityParts(payload)))
	}
	for _, avas := range [][][]byte{
		nil, {ava, ava},
		{encodeDNIdentityParts([]byte("uid"), []byte("b")), ava},
		{encodeDNIdentityParts(nil, nil)},
		{encodeDNIdentityParts([]byte("cn"))},
		{encodeDNIdentityParts([]byte("cn"), nil, nil)},
		{{0x82, 0, 0x82, 0, 'c', 'n', 0x81, 0, 'a'}},
	} {
		payloads = append(payloads, encodeDNIdentityParts(encodeDNIdentityParts(avas...)))
	}
	for _, payload := range append([][]byte(nil), payloads...) {
		for index := range payload {
			payloads = append(payloads, bytes.Clone(payload[:index]))
			for _, replacement := range []byte{0, 1, 2, 0x7f, 0x80, 0xff} {
				changed := bytes.Clone(payload)
				changed[index] = replacement
				payloads = append(payloads, changed)
			}
		}
	}
	rng := rand.New(rand.NewPCG(23, 71))
	for range 1000 {
		payload := make([]byte, rng.IntN(128))
		for index := range payload {
			payload[index] = byte(rng.Uint32())
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

func TestDNIdentityViewsEquivalent(t *testing.T) {
	base, err := ParseDNWithNormalizer("cn=a", scopeIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range identityPayloadCorpus() {
		want, wantErr := referenceDecodeDNIdentityParts(payload)
		got, gotErr := decodeDNIdentityParts(payload)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
			t.Fatalf("parts %x: got %x, %v; want %x, %v", payload, got, gotErr, want, wantErr)
		}
		key := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(payload)
		for _, value := range []string{"", "cn=a", "cn=a,dc=b", "uid=b+cn=a", "cn"} {
			for scope := Scope(-1); scope <= Scope(4); scope++ {
				checkDNIdentityEquivalence(t, value, key, base, scope)
			}
		}
	}
}

type aliasIdentityNormalizer struct{}

func (aliasIdentityNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	switch strings.ToLower(attribute) {
	case "exactname", "exactalias", "1.2.3.4":
		return "1.2.3.4", bytes.Clone(value), nil
	case "cn", "commonname", "2.5.4.3":
		return "2.5.4.3", []byte(strings.ToLower(string(value))), nil
	default:
		return scopeIdentityNormalizer{}.NormalizeDNAttribute(attribute, value)
	}
}

func (aliasIdentityNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	switch strings.ToLower(attribute) {
	case "exactname", "exactalias", "1.2.3.4":
		return "exactName", nil
	case "cn", "commonname", "2.5.4.3":
		return "cn", nil
	default:
		return strings.ToLower(attribute), nil
	}
}

func TestDNIdentityReconstructionEquivalence(t *testing.T) {
	var dns []DN
	for _, value := range []string{
		"", "dc=com", "dc=example,dc=com", "dc=other,dc=com",
		"cn=Alice,dc=example,dc=com", "commonName=ALICE,dc=example,dc=com",
		"exactName=Alice,dc=example,dc=com", "exactAlias=Alice,dc=example,dc=com",
		"exactName=alice,dc=example,dc=com",
		"uid=A+cn=B+exactName=C,dc=example,dc=com",
		"exactAlias=C+commonName=b+uid=a,dc=example,dc=com",
		`cn=\ leading\ +uid=Smith\, Alice,dc=example,dc=com`,
		`cn=\00\ff\c3\a9\+\"\;\<\>\\,dc=example,dc=com`,
		"cn=" + strings.Repeat("a", 4096) + ",dc=example,dc=com",
		strings.Repeat("ou=people,", 130) + "dc=example,dc=com",
	} {
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		dns = append(dns, dn)
		for _, display := range []string{value, dn.String()} {
			for _, base := range dns {
				for scope := Scope(-1); scope <= Scope(4); scope++ {
					checkDNIdentityEquivalence(t, display, dn.Key(), base, scope)
				}
			}
		}
	}
	for _, pair := range [][2]int{{4, 5}, {6, 7}, {9, 10}} {
		left, _ := ParseDNWithIdentityKey(dns[pair[0]].String(), dns[pair[0]].Key())
		right, _ := ParseDNWithIdentityKey(dns[pair[1]].String(), dns[pair[1]].Key())
		if !left.Equal(right) {
			t.Fatalf("alias/order identity changed: %q != %q", left, right)
		}
	}
	if dns[6].Equal(dns[8]) {
		t.Fatal("case-exact values collapsed")
	}
}

func TestDNIdentityOwnedViews(t *testing.T) {
	original, err := ParseDNWithNormalizer("uid=Alice+cn=Example,ou=People,dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	dn, err := ParseDNWithIdentityKey(original.String(), original.Key())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := referenceParseDNWithIdentityKey(original.String(), original.Key())
	parent, _ := dn.Parent()
	local, _ := ParseDNWithIdentityKey("cn=local", encodeDNIdentity([][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn"), []byte("local")))}))
	composed, err := ComposeLocalName(local, parent)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := dn.ReplaceAncestor(parent, local)
	if err != nil {
		t.Fatal(err)
	}
	for _, rdn := range dn.identityRDNs {
		if cap(rdn) != len(rdn) {
			t.Fatal("RDN view can append into a sibling")
		}
		_ = append(rdn, 0xff)
	}
	values := dn.RDNValues()
	values[0].Value[0] = '!'
	values[0].Type = "changed"
	for range 100 {
		_, err := ParseDNWithIdentityKey(original.String(), original.Key())
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := IdentityKeyInScope(parent, original.Key(), ScopeSingleLevel); !ok || err != nil {
			t.Fatalf("scope: %t, %v", ok, err)
		}
	}
	if !reflect.DeepEqual(dn, want) {
		t.Fatal("retained DN changed after subsequent parses, scopes, or returned-value mutation")
	}
	for _, derived := range []DN{parent, composed, replaced} {
		if err := derived.ValidateIdentityKey(derived.Key()); err != nil {
			t.Fatal(err)
		}
		checkDNIdentityEquivalence(t, derived.String(), derived.Key(), parent, ScopeWholeSubtree)
	}
}

func TestEscapeDNValueEquivalent(t *testing.T) {
	for value := range 256 {
		for _, input := range []string{
			string([]byte{byte(value)}), "a" + string([]byte{byte(value)}),
			string([]byte{byte(value)}) + "z", "a" + string([]byte{byte(value)}) + "z",
		} {
			if got, want := escapeDNValue(input), referenceEscapeDNValue(input); got != want {
				t.Fatalf("escape %q = %q, want %q", input, got, want)
			}
		}
	}
}

func TestDNIdentityScopeBufferBoundaries(t *testing.T) {
	base, err := ParseDNWithNormalizer("", scopeIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1023, 1024, 1025, 16384} {
		payload := binary.AppendUvarint(nil, 1)
		payload = binary.AppendUvarint(payload, uint64(size-3))
		payload = append(payload, make([]byte, size-3)...)
		for _, raw := range [][]byte{payload, payload[:len(payload)-1], append(bytes.Clone(payload), 0)} {
			encoded := base64.RawURLEncoding.EncodeToString(raw)
			for _, text := range []string{encoded, encoded + "\n", encoded + "=", encoded[:len(encoded)-1] + "!"} {
				key := schemaAwareDNKeyPrefix + text
				for scope := Scope(-1); scope <= Scope(4); scope++ {
					checkDNIdentityEquivalence(t, "cn=a", key, base, scope)
				}
			}
		}
	}
}

func FuzzDNIdentityViewsEquivalent(f *testing.F) {
	for _, payload := range identityPayloadCorpus()[:40] {
		f.Add("cn=a", schemaAwareDNKeyPrefix+base64.RawURLEncoding.EncodeToString(payload), int8(2))
		f.Add("cn=a", string(payload), int8(2))
	}
	f.Fuzz(func(t *testing.T, value, key string, scope int8) {
		base, err := ParseDNWithNormalizer("cn=a", scopeIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		checkDNIdentityEquivalence(t, value, key, base, Scope(scope))
		// Also exercise valid base64 around arbitrary nested identity bytes.
		key = schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(key))
		checkDNIdentityEquivalence(t, "cn=a", key, base, Scope(scope))
	})
}

func BenchmarkDNIdentityHotPath(b *testing.B) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct{ name, display string }{
		{"empty", ""},
		{"typical", "uid=alice,ou=people,dc=example,dc=com"},
		{"alias_multi", "exactAlias=Alice+commonName=Example+uid=a,dc=example,dc=com"},
		{"escaped", `cn=\ leading\ +uid=Smith\, Alice,dc=example,dc=com`},
		{"long", "cn=" + strings.Repeat("a", 2048) + ",dc=example,dc=com"},
	} {
		dn, err := ParseDNWithNormalizer(test.display, aliasIdentityNormalizer{})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(test.name, func(b *testing.B) {
			b.Run("parse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := ParseDNWithIdentityKey(test.display, dn.Key()); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("scope", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := IdentityKeyInScope(base, dn.Key(), ScopeWholeSubtree); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
	// Keep the decoded payload exactly at either side of the stack-buffer bound.
	for _, size := range []int{1023, 1024, 1025} {
		payload := binary.AppendUvarint(nil, 1)
		payload = binary.AppendUvarint(payload, uint64(size-3))
		payload = append(payload, make([]byte, size-3)...)
		key := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(payload)
		b.Run(fmt.Sprintf("scope_bytes=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := IdentityKeyInScope(base, key, ScopeWholeSubtree); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// This isolates directory work over distinct entries; it is not an end-to-end
// paging or cold-storage benchmark. The parsed base is reused across each scan.
func BenchmarkDNIdentityScan100K(b *testing.B) {
	base, err := ParseDNWithNormalizer("dc=example,dc=com", scopeIdentityNormalizer{})
	if err != nil {
		b.Fatal(err)
	}
	entries := make([]struct{ display, key string }, 100000)
	for index := range entries {
		display := fmt.Sprintf("uid=user%06d,ou=people,dc=example,dc=com", index)
		dn, err := ParseDNWithNormalizer(display, scopeIdentityNormalizer{})
		if err != nil {
			b.Fatal(err)
		}
		entries[index].display, entries[index].key = display, dn.Key()
	}
	for _, reconstruct := range []bool{false, true} {
		name := "scope"
		if reconstruct {
			name = "parse_and_scope"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for _, entry := range entries {
					if reconstruct {
						if _, err := ParseDNWithIdentityKey(entry.display, entry.key); err != nil {
							b.Fatal(err)
						}
					}
					if matched, err := IdentityKeyInScope(base, entry.key, ScopeWholeSubtree); !matched || err != nil {
						b.Fatalf("scope = %t, %v", matched, err)
					}
				}
			}
		})
	}
}
