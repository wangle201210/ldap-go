package directory

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func checkDNIdentityValidation(t *testing.T, value, key string) error {
	t.Helper()
	got := ValidateDNWithIdentityKey(value, key)
	_, parsedErr := ParseDNWithIdentityKey(value, key)
	_, referenceErr := referenceParseDNWithIdentityKey(value, key)
	// Compare concrete error types and wrapped errors as well as nil and text.
	if !reflect.DeepEqual(got, parsedErr) || !reflect.DeepEqual(got, referenceErr) {
		t.Fatalf("validate %q / %q: got %v; parser %v; reference %v", value, key, got, parsedErr, referenceErr)
	}
	return got
}

func TestValidateDNWithIdentityKeyValid(t *testing.T) {
	for _, value := range []string{
		"", " ", "cn=", "dc=Example,dc=COM",
		"uid=alice,ou=people,dc=example,dc=com",
		"commonName=ALICE,dc=example,dc=com",
		"2.5.4.3=Alice,dc=example,dc=com",
		"exactAlias=Alice+commonName=Example+uid=a,dc=example,dc=com",
		" cn = Alice , ou = People , dc = example , dc = com ",
		`cn=\ leading\ +uid=Smith\, Alice,dc=example,dc=com`,
		`cn=\00\ff\c3\a9\+\"\;\<\>\\,dc=example,dc=com`,
		"cn=" + strings.Repeat("a", 4096) + ",dc=example,dc=com",
		strings.Repeat("ou=people,", 130) + "dc=example,dc=com",
	} {
		dn, err := ParseDNWithNormalizer(value, aliasIdentityNormalizer{})
		if err != nil {
			t.Fatalf("fixture %q: %v", value, err)
		}
		legacy, err := ParseDN(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, display := range []string{value, dn.String()} {
			if err := checkDNIdentityValidation(t, display, dn.Key()); err != nil {
				t.Fatal(err)
			}
		}
		if err := checkDNIdentityValidation(t, value, legacy.Key()); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"", "legacy", "DN:v2:AA", "dn:v1:AA", legacy.Key() + "!"} {
			checkDNIdentityValidation(t, value, key)
		}
	}
	// Display aliases and AVA order need not match the physical key's spelling.
	dn, err := ParseDNWithNormalizer("cn=Alice+exactName=Case,dc=example,dc=com", aliasIdentityNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"exactAlias=Case+commonName=ALICE,dc=example,dc=com",
		"1.2.3.4=Case+2.5.4.3=Alice,dc=example,dc=com",
	} {
		if err := checkDNIdentityValidation(t, value, dn.Key()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidateDNWithIdentityKeyInvalidDisplay(t *testing.T) {
	key := encodeDNIdentity([][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn"), []byte("a")))})
	for _, value := range []string{
		"cn", "=a", "cn=a+CN=b", "cn;lang-en=Alice", "cn=a+cn;lang-en=b", "cn=a,ou=x+OU=y",
		"bad_type=a", "1.02.3=a", "1..2=a", `cn=\`, `cn=\x`, `cn=\gg`, "cn=#zz",
	} {
		_, want := referenceParseDN(value)
		if want == nil {
			t.Fatalf("fixture %q must be invalid", value)
		}
		for _, candidateKey := range []string{key, "", "legacy", "dn:v2:", "dn:v2:!", "dn:v2:A\r\n"} {
			if got := checkDNIdentityValidation(t, value, candidateKey); !reflect.DeepEqual(got, want) {
				t.Fatalf("display must fail before key: got %v, want %v", got, want)
			}
		}
	}
}

func TestValidateDNWithIdentityKeyStructuralErrorsAndFallbacks(t *testing.T) {
	ava := encodeDNIdentityParts([]byte("cn"), []byte("a"))
	otherAVA := encodeDNIdentityParts([]byte("uid"), []byte("b"))
	rdn := encodeDNIdentityParts(ava)
	invalidAVA := encodeDNIdentityParts(nil, []byte("a"))
	invalidRDN := encodeDNIdentityParts(invalidAVA)
	const invalid0 = "schema-aware DN key RDN 0 contains an invalid AVA"
	for _, test := range []struct {
		name, value string
		rdns        [][]byte
		want        string
	}{
		{"missing_rdn", "cn=a", nil, "schema-aware DN key has 0 RDNs, display DN has 1"},
		{"extra_rdn", "cn=a", [][]byte{rdn, nil}, "schema-aware DN key has 2 RDNs, display DN has 1"},
		{"empty_rdn", "cn=a", [][]byte{nil}, "decode schema-aware DN key RDN 0: truncated part count"},
		{"missing_avas", "cn=a", [][]byte{encodeDNIdentityParts()}, ""},
		{"fewer_avas", "cn=a+uid=b", [][]byte{rdn}, ""},
		{"extra_avas", "cn=a", [][]byte{encodeDNIdentityParts(ava, otherAVA)}, ""},
		{"unsorted_avas", "cn=a+uid=b", [][]byte{encodeDNIdentityParts(otherAVA, ava)}, ""},
		{"duplicate_key_types", "cn=a+uid=b", [][]byte{encodeDNIdentityParts(ava, ava)}, ""},
		{"arbitrary_key_type", "cn=a", [][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte{0xff}, nil))}, ""},
		{"empty_type", "cn=a", [][]byte{invalidRDN}, invalid0},
		{"missing_value", "cn=a", [][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn")))}, invalid0},
		{"extra_part", "cn=a", [][]byte{encodeDNIdentityParts(encodeDNIdentityParts([]byte("cn"), nil, nil))}, invalid0},
		{"truncated_value", "cn=a", [][]byte{encodeDNIdentityParts([]byte{2, 2, 'c', 'n', 1})}, invalid0},
		{"last_ava_invalid", "cn=a+uid=b", [][]byte{encodeDNIdentityParts(ava, invalidAVA)}, invalid0},
		{"last_rdn_invalid", "cn=a,dc=b", [][]byte{rdn, invalidRDN}, "schema-aware DN key RDN 1 contains an invalid AVA"},
		{"fallback_invalid_ava", "cn=a", [][]byte{encodeDNIdentityParts(ava, invalidAVA)}, invalid0},
		{"fallback_later_invalid_rdn", "cn=a,dc=b", [][]byte{encodeDNIdentityParts(), nil}, "decode schema-aware DN key RDN 1: truncated part count"},
		{"earlier_ava_before_later_rdn", "cn=a,dc=b", [][]byte{invalidRDN, nil}, invalid0},
		{"later_ava_length_before_content", "cn=a+uid=b", [][]byte{{2, 0, 0x80}}, "decode schema-aware DN key RDN 0: part 1 has a truncated length"},
		{"nonminimal_ava_varints", "cn=a", [][]byte{encodeDNIdentityParts([]byte{0x82, 0, 0x82, 0, 'c', 'n', 0x81, 0, 'a'})}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkDNIdentityValidation(t, test.value, encodeDNIdentity(test.rdns))
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Error() != test.want {
				t.Fatalf("got %v, want %q", err, test.want)
			}
		})
	}
	// Validate the entire outer sequence before inspecting earlier RDN contents.
	key := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte{2, 0, 0x80})
	if err := checkDNIdentityValidation(t, "cn=a,dc=b", key); err == nil ||
		err.Error() != "decode schema-aware DN key RDNs: part 1 has a truncated length" {
		t.Fatalf("outer error precedence: %v", err)
	}
}

func TestValidateDNWithIdentityKeyPayloadCorpus(t *testing.T) {
	for _, payload := range identityPayloadCorpus() {
		key := schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(payload)
		for _, value := range []string{"", " ", "cn=", "cn=a", "cn=a,dc=b", "uid=b+cn=a", "cn"} {
			checkDNIdentityValidation(t, value, key)
		}
	}
}

func TestValidateDNWithIdentityKeyEncoding(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, size := range []int{0, 1, 2, 3, 47, 127, 128, 1011, 1012, 1013, 1023, 1024, 1025, 4096} {
		payload := encodeDNIdentityParts(encodeDNIdentityParts(encodeDNIdentityParts(
			[]byte("cn"), bytes.Repeat([]byte("a"), size),
		)))
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		check := func(encoded string) {
			t.Helper()
			checkDNIdentityValidation(t, "cn=a", schemaAwareDNKeyPrefix+encoded)
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

func BenchmarkValidateDNWithIdentityKey(b *testing.B) {
	for _, test := range []struct{ name, value string }{
		{"empty", ""},
		{"typical", "uid=alice,ou=people,dc=example,dc=com"},
		{"alias_multi", "exactAlias=Alice+commonName=Example+uid=a,dc=example,dc=com"},
		{"escaped", `cn=\ leading\ +uid=Smith\, Alice,dc=example,dc=com`},
		{"long", "cn=" + strings.Repeat("a", 2048) + ",dc=example,dc=com"},
	} {
		dn, err := ParseDNWithNormalizer(test.value, aliasIdentityNormalizer{})
		if err != nil {
			b.Fatal(err)
		}
		b.Run(test.name, func(b *testing.B) {
			b.Run("validate", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if err := ValidateDNWithIdentityKey(test.value, dn.Key()); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("parse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := ParseDNWithIdentityKey(test.value, dn.Key()); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
