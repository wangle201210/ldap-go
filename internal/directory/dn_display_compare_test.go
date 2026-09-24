package directory

import (
	"fmt"
	"strings"
	"testing"
)

func checkDNDisplayCompare(t testing.TB, dn DN, raw string) {
	t.Helper()
	display := dn.String()
	if got, want := dn.DisplayEquals(raw), display == raw; got != want {
		t.Fatalf("DisplayEquals(%q), display %q: got %t, want %t", raw, display, got, want)
	}
	if got, want := dn.DisplaySuffixOf(raw), raw == display || strings.HasSuffix(raw, ","+display); got != want {
		t.Fatalf("DisplaySuffixOf(%q), display %q: got %t, want %t", raw, display, got, want)
	}
}

func dnDisplayCompareVariants(t testing.TB, raw string) []DN {
	t.Helper()
	legacy, err := ParseDN(raw)
	if err != nil {
		t.Fatal(err)
	}
	var variants []DN
	for _, normalizer := range []DNAttributeNormalizer{nil, scopeIdentityNormalizer{}, aliasIdentityNormalizer{}} {
		dn := legacy
		local, err := ParseDN(`cn=Child\, One+uid=Child`)
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := ParseDN("ou=Elsewhere,dc=Other")
		if err != nil {
			t.Fatal(err)
		}
		if normalizer != nil {
			dn, err = legacy.NormalizeWith(normalizer)
			if err != nil {
				t.Fatal(err)
			}
			local, err = local.NormalizeWith(normalizer)
			if err != nil {
				t.Fatal(err)
			}
			replacement, err = replacement.NormalizeWith(normalizer)
			if err != nil {
				t.Fatal(err)
			}
		}
		rebuilt, err := ParseDNWithIdentityKey(raw, dn.Key())
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range []DN{dn, rebuilt} {
			variants = append(variants, source)
			parent, hasParent := source.Parent()
			if hasParent {
				variants = append(variants, parent)
				moved, err := source.ReplaceAncestor(parent, replacement)
				if err != nil {
					t.Fatal(err)
				}
				variants = append(variants, moved)
			}
			composed, err := ComposeDN(local.String(), source)
			if err != nil {
				t.Fatal(err)
			}
			variants = append(variants, composed)
			composed, err = ComposeLocalName(local, source)
			if err != nil {
				t.Fatal(err)
			}
			variants = append(variants, composed)
			replaced, err := source.ReplaceAncestor(source, replacement)
			if err != nil {
				t.Fatal(err)
			}
			variants = append(variants, replaced)
		}
	}
	return variants
}

func TestDNDisplayCompareReference(t *testing.T) {
	inputs := []string{
		"", " ", "cn=", "cn=config", "CN=CONFIG", "dc=Example,dc=COM",
		"cn=Alice,ou=People,dc=example,dc=com", "cn=alice,dc=example,dc=com",
		"commonName=Alice,dc=example,dc=com", "2.5.4.3=Alice,dc=example,dc=com",
		"exactAlias=Case+commonName=ALICE+uid=A,dc=example,dc=com",
		"uid=A+2.5.4.3=ALICE+1.2.3.4=Case,dc=example,dc=com",
		" cn = Alice , dc = example , dc = com ",
		`cn=Smith\, Alice+uid=A\+B,dc=example,dc=com`,
		`cn=\ leading\ +uid=\#hash,dc=com`,
		`cn=\00\ff\c3\a9\+\"\;\<\>\\,dc=com`,
		`cn=\41lice,dc=com`, "cn=\u7528\u6237\u00e9,dc=com", "cn=\xff,dc=com",
		"cn=" + strings.Repeat("x", 4096) + ",dc=com",
		strings.Repeat("ou=People,", 64) + "dc=com",
	}
	for index, input := range inputs {
		t.Run(fmt.Sprintf("input-%02d", index), func(t *testing.T) {
			for variant, dn := range dnDisplayCompareVariants(t, input) {
				t.Run(fmt.Sprintf("variant-%02d", variant), func(t *testing.T) {
					display := dn.String()
					for _, raw := range []string{
						input, display, "", ",", "not a DN", "cn=broken,", "\x00\xff",
						strings.ToUpper(display), strings.ToLower(display),
						"," + display, "cn=Child," + display, `cn=escaped\,` + display,
						"invalid,," + display, "\x00\xff," + display,
						"x" + display, "+" + display, " " + display,
						display + ",", display + "x", display + "\x00",
					} {
						checkDNDisplayCompare(t, dn, raw)
					}
					// Truncate or corrupt every byte of ordinary displays, including separators and escapes.
					if len(display) <= 256 {
						for offset := range len(display) {
							checkDNDisplayCompare(t, dn, display[:offset])
							checkDNDisplayCompare(t, dn, display[offset:])
							changed := display[:offset] + string([]byte{display[offset] ^ 0xff}) + display[offset+1:]
							checkDNDisplayCompare(t, dn, changed)
							checkDNDisplayCompare(t, dn, "cn=Child,"+changed)
						}
					}
				})
			}
		})
	}
}

func TestDNDisplayCompareLiteralBoundaries(t *testing.T) {
	for _, raw := range []string{"", ",", "x,", `x\,`, "x,,", "x", "x, ", "\x00\xff,"} {
		checkDNDisplayCompare(t, DN{}, raw)
	}
	for _, test := range []struct {
		display, raw  string
		equal, suffix bool
	}{
		{"", "", true, true},
		{"", ",", false, true},
		{"", `x\,`, false, true},
		{"", "cn=child", false, false},
		{"dc=com", "dc=com", true, true},
		{"dc=com", ",dc=com", false, true},
		{"dc=com", "invalid,,dc=com", false, true},
		{"dc=com", `cn=escaped\,dc=com`, false, true},
		{"dc=com", "cn=x+dc=com", false, false},
		{"dc=com", "xdc=com", false, false},
		{"dc=com", "dc=COM", false, false},
		{"dc=com", "cn=x,dc=com,", false, false},
		{`cn=Smith\, Alice,dc=com`, `uid=x,cn=Smith\, Alice,dc=com`, false, true},
		{`cn=Smith\, Alice,dc=com`, `cn=Smith\2c Alice,dc=com`, false, false},
	} {
		dn, err := ParseDN(test.display)
		if err != nil {
			t.Fatal(err)
		}
		checkDNDisplayCompare(t, dn, test.raw)
		if equal, suffix := dn.DisplayEquals(test.raw), dn.DisplaySuffixOf(test.raw); equal != test.equal || suffix != test.suffix {
			t.Fatalf("display %q, raw %q: got %t/%t, want %t/%t", dn.String(), test.raw, equal, suffix, test.equal, test.suffix)
		}
	}
}

func TestDNDisplayCompareSameKeyDifferentDisplay(t *testing.T) {
	for _, normalizer := range []DNAttributeNormalizer{nil, scopeIdentityNormalizer{}, aliasIdentityNormalizer{}} {
		left, err := ParseDN("cn=Alice,dc=example,dc=com")
		if err != nil {
			t.Fatal(err)
		}
		right, err := ParseDN("cn=alice,dc=example,dc=com")
		if err != nil {
			t.Fatal(err)
		}
		if normalizer != nil {
			left, err = left.NormalizeWith(normalizer)
			if err != nil {
				t.Fatal(err)
			}
			right, err = right.NormalizeWith(normalizer)
			if err != nil {
				t.Fatal(err)
			}
		}
		if left.Key() != right.Key() || left.String() == right.String() {
			t.Fatal("fixture must share an identity key and have different display bytes")
		}
		for _, dn := range []DN{left, right} {
			for _, raw := range []string{left.String(), right.String(), "uid=Child," + left.String(), "uid=Child," + right.String()} {
				checkDNDisplayCompare(t, dn, raw)
			}
		}
	}
}

func FuzzDNDisplayCompareReference(f *testing.F) {
	for _, seed := range [][2]string{
		{"", `x\,`}, {"dc=com", "invalid,,dc=com"},
		{"dc=com", `cn=escaped\,dc=com`}, {"cn=Alice,dc=com", "cn=alice,dc=com"},
		{`cn=Smith\, Alice+uid=A\+B,dc=com`, `cn=Smith\2c Alice+uid=A\+B,dc=com`},
		{"commonName=\u00e9,dc=com", "\xff,cn=\u00e9,dc=com"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, input, raw string) {
		if len(input)+len(raw) > 4096 {
			return
		}
		checkDNDisplayCompare(t, DN{}, raw)
		legacy, err := ParseDN(input)
		if err != nil {
			return
		}
		dns := []DN{legacy}
		for _, normalizer := range []DNAttributeNormalizer{scopeIdentityNormalizer{}, aliasIdentityNormalizer{}} {
			dn, err := legacy.NormalizeWith(normalizer)
			if err != nil {
				continue
			}
			rebuilt, err := ParseDNWithIdentityKey(input, dn.Key())
			if err != nil {
				t.Fatal(err)
			}
			dns = append(dns, dn, rebuilt)
		}
		for _, dn := range dns {
			checkDNDisplayCompare(t, dn, raw)
			checkDNDisplayCompare(t, dn, dn.String())
			checkDNDisplayCompare(t, dn, raw+","+dn.String())
		}
	})
}

func BenchmarkDNDisplayCompare(b *testing.B) {
	for _, fixture := range []struct{ name, raw string }{
		{"empty", ""}, {"single", "cn=config"},
		{"root", "cn=Admin,ou=People,dc=example,dc=com"},
		{"escaped-multiava", `cn=Smith\, Alice+uid=A\+B,dc=example,dc=com`},
		{"deep", strings.Repeat("ou=People,", 32) + "dc=com"},
	} {
		dn, err := ParseDNWithNormalizer(fixture.raw, aliasIdentityNormalizer{})
		if err != nil {
			b.Fatal(err)
		}
		for _, candidate := range []struct{ name, raw string }{
			{"equal", dn.String()}, {"child", "uid=Child," + dn.String()},
			{"prefix-miss", "x" + dn.String()}, {"tail-miss", dn.String() + "x"},
		} {
			for _, operation := range []struct {
				name string
				call func(DN, string) bool
			}{
				{"equals/direct", DN.DisplayEquals},
				{"equals/string", func(dn DN, raw string) bool { return dn.String() == raw }},
				{"suffix/direct", DN.DisplaySuffixOf},
				{"suffix/string", func(dn DN, raw string) bool {
					text := dn.String()
					return raw == text || strings.HasSuffix(raw, ","+text)
				}},
			} {
				b.Run(fixture.name+"/"+candidate.name+"/"+operation.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						operation.call(dn, candidate.raw)
					}
				})
			}
		}
	}
}
