package directory

import (
	"strings"
	"testing"
)

func checkLegacyDisplayRelation(t testing.TB, left, right DN) {
	t.Helper()
	equal, ancestor, ok := left.SimpleLegacyDisplayRelation(right)
	if !ok {
		return
	}
	a, err := ParseDN(left.String())
	if err != nil {
		t.Fatalf("eligible left display %q cannot parse: %v", left.String(), err)
	}
	b, err := ParseDN(right.String())
	if err != nil {
		t.Fatalf("eligible right display %q cannot parse: %v", right.String(), err)
	}
	if equal != a.Equal(b) || ancestor != a.AncestorOf(b) {
		t.Fatalf("%q vs %q = %t/%t; want %t/%t", left.String(), right.String(), equal, ancestor, a.Equal(b), a.AncestorOf(b))
	}
}

func TestSimpleLegacyDisplayRelationReference(t *testing.T) {
	inputs := []string{"", "cn=config", "CN=CONFIG", "dc=com", "dc=COM", "dc=example,dc=com",
		"cn=alice,dc=example,dc=com", "cn=ALICE,DC=EXAMPLE,DC=COM", "cn=alice,dc=other,dc=com",
		"2.5.4.3=Alice", "cn=a+uid=b,dc=com", `cn=Smith\, Alice,dc=com`, `cn=\61lice,dc=com`,
		"cn=", "cn=two words,dc=com", "cn=é,dc=com", strings.Repeat("cn=a,", 64) + "dc=com"}
	var dns []DN
	for _, raw := range inputs {
		dn, err := ParseDN(raw)
		if err != nil {
			t.Fatal(err)
		}
		dns = append(dns, dn)
		for _, normalizer := range []DNAttributeNormalizer{scopeIdentityNormalizer{}, aliasIdentityNormalizer{}} {
			normalized, err := dn.NormalizeWith(normalizer)
			if err == nil {
				dns = append(dns, normalized)
				physical, err := ParseDNWithIdentityKey(raw, normalized.Key())
				if err != nil {
					t.Fatal(err)
				}
				dns = append(dns, physical)
			}
		}
	}
	for _, left := range dns {
		for _, right := range dns {
			checkLegacyDisplayRelation(t, left, right)
		}
	}
	if _, _, ok := (DN{}).SimpleLegacyDisplayRelation(dns[0]); ok {
		t.Fatal("uninitialized DN used direct comparison")
	}
	base, _ := ParseDN("cn=config")
	user, _ := ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if allocs := testing.AllocsPerRun(100, func() {
		if equal, ancestor, ok := base.SimpleLegacyDisplayRelation(user); equal || ancestor || !ok {
			t.Fatal("ordinary user should be outside configuration suffix")
		}
	}); allocs != 0 {
		t.Fatalf("simple comparison allocated %g times", allocs)
	}
}

func FuzzSimpleLegacyDisplayRelation(f *testing.F) {
	f.Add("cn=config", "uid=alice,dc=com")
	f.Add("dc=EXAMPLE,dc=COM", "cn=Alice,dc=example,dc=com")
	f.Add("", "cn=a+uid=b")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a)+len(b) > 4096 {
			return
		}
		left, err := ParseDN(a)
		if err != nil {
			return
		}
		right, err := ParseDN(b)
		if err != nil {
			return
		}
		checkLegacyDisplayRelation(t, left, right)
		for _, normalizer := range []DNAttributeNormalizer{scopeIdentityNormalizer{}, aliasIdentityNormalizer{}} {
			x, xErr := left.NormalizeWith(normalizer)
			y, yErr := right.NormalizeWith(normalizer)
			if xErr == nil && yErr == nil {
				checkLegacyDisplayRelation(t, x, y)
			}
		}
	})
}

func BenchmarkSimpleLegacyDisplayRelation(b *testing.B) {
	base, _ := ParseDN("cn=config")
	target, _ := ParseDN("uid=alice,ou=people,dc=example,dc=com")
	for _, fast := range []bool{false, true} {
		name := "parse"
		if fast {
			name = "direct"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var eq, ancestor bool
				if fast {
					eq, ancestor, _ = base.SimpleLegacyDisplayRelation(target)
				} else {
					x, err := ParseDN(base.String())
					if err != nil {
						b.Fatal(err)
					}
					y, err := ParseDN(target.String())
					if err != nil {
						b.Fatal(err)
					}
					eq, ancestor = x.Equal(y), x.AncestorOf(y)
				}
				if eq || ancestor {
					b.Fatal("wrong suffix match")
				}
			}
		})
	}
}
