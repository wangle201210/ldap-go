package schema

import (
	"strings"
	"testing"
)

func BenchmarkDNCacheNormalizedText(b *testing.B) {
	for _, workload := range []struct {
		name, raw string
		cold      bool
	}{
		{"root/warm", "", false},
		{"suffix/warm", "DC=EXAMPLE,DC=COM", false},
		{"multiAVA/warm", "CN=Alice+UID=ALICE,OU=People,DC=EXAMPLE,DC=COM", false},
		{"suffix/cold", "DC=EXAMPLE,DC=COM", true},
		{"oversizedInput", "CN=" + strings.Repeat("a", maxCachedDNInput) + ",DC=EXAMPLE,DC=COM", false},
		{"excessDepth", strings.Repeat("OU=People,", maxCachedDNDepth) + "DC=EXAMPLE", false},
	} {
		b.Run(workload.name, func(b *testing.B) {
			for _, operation := range []string{"DNOnly", "DNAndRender", "retainedText"} {
				b.Run(operation, func(b *testing.B) {
					registry, err := NewBuiltinRegistry()
					if err != nil {
						b.Fatal(err)
					}
					want, err := registry.NormalizeDN(workload.raw)
					if err != nil {
						b.Fatal(err)
					}
					wantKey, wantText := want.Key(), want.NormalizedString()
					var normalize func() (string, error)
					var expected string
					switch operation {
					case "DNOnly":
						expected = wantKey
						normalize = func() (string, error) {
							dn, err := registry.NormalizeDNCached(workload.raw)
							return dn.Key(), err
						}
					case "DNAndRender":
						expected = wantText
						normalize = func() (string, error) {
							dn, err := registry.NormalizeDNCached(workload.raw)
							return dn.NormalizedString(), err
						}
					case "retainedText":
						expected = wantText
						normalize = func() (string, error) {
							registry.mu.RLock()
							defer registry.mu.RUnlock()
							entry, err := registry.normalizeDNCachedLocked(workload.raw)
							return entry.normalizedString(), err
						}
					}
					if got, err := normalize(); err != nil || got != expected {
						b.Fatalf("normalization = %q, %v; want %q", got, err, expected)
					}
					b.ReportAllocs()
					for b.Loop() {
						if workload.cold {
							b.StopTimer()
							registry.dnCache.entries = nil
							registry.dnCache.bytes = 0
							b.StartTimer()
						}
						if got, err := normalize(); err != nil || got != expected {
							b.Fatalf("normalization = %q, %v; want %q", got, err, expected)
						}
					}
				})
			}
		})
	}
}

func BenchmarkNormalizeEqualityAssertionCachedDNText(b *testing.B) {
	for _, workload := range []struct{ name, raw string }{
		{"root", ""},
		{"suffix", "DC=EXAMPLE,DC=COM"},
		{"multiAVA", "CN=Alice+UID=ALICE,OU=People,DC=EXAMPLE,DC=COM"},
	} {
		b.Run(workload.name, func(b *testing.B) {
			for _, cached := range []bool{false, true} {
				name := "uncached"
				if cached {
					name = "cached"
				}
				b.Run(name, func(b *testing.B) {
					registry, err := NewBuiltinRegistry()
					if err != nil {
						b.Fatal(err)
					}
					normalize := registry.NormalizeEqualityAssertion
					if cached {
						normalize = registry.NormalizeEqualityAssertionCachedDN
					}
					input := []byte(workload.raw)
					want, err := registry.NormalizeEqualityAssertion("member", input)
					if err != nil {
						b.Fatal(err)
					}
					if got, err := normalize("member", input); err != nil || string(got) != string(want) {
						b.Fatalf("assertion = %q, %v; want %q", got, err, want)
					}
					b.ReportAllocs()
					for b.Loop() {
						if got, err := normalize("member", input); err != nil || string(got) != string(want) {
							b.Fatalf("assertion = %q, %v; want %q", got, err, want)
						}
					}
				})
			}
		})
	}
}
