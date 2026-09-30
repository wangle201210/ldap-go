package schema

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Cold and warm refer to the caller-owned prefix token, not a cold process or
// an empty Registry DN cache. Every implementation gets its own registry and
// primes its normal comparison path before timing. A cold call always receives
// nil; a warm call receives the same immutable, fully primed token each time.
func BenchmarkCompareEntryAttributeWithDNPrefix(b *testing.B) {
	for _, complex := range []bool{false, true} {
		shape := "simple"
		if complex {
			shape = "escaped-multi-AVA"
		}
		for _, count := range []int{10, 1000, 4097} {
			entry := dnPrefixTestEntry(count, complex)
			for _, position := range []struct {
				name  string
				index int
			}{{"first", 0}, {"last", count - 1}, {"missing", -1}} {
				assertion := []byte("cn=missing,ou=People,dc=example")
				if position.index >= 0 {
					assertion = bytes.Clone(entry.Attributes[0].Values[position.index])
				}
				b.Run(fmt.Sprintf("%s/values=%d/%s", shape, count, position.name), func(b *testing.B) {
					benchmarkDNPrefixComparison(b, entry, assertion)
				})
			}
		}
	}
}

func benchmarkDNPrefixComparison(b *testing.B, entry directory.Entry, assertion []byte) {
	for _, implementation := range []string{"oracle", "uncached", "cached-dn", "prefix-cold", "prefix-warm"} {
		b.Run(implementation, func(b *testing.B) {
			registry := equalityEvaluationRegistry(b)
			wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, "member", assertion)
			if wantErr != nil {
				b.Fatalf("invalid benchmark fixture: %v", wantErr)
			}
			var previous *DNComparisonPrefix
			if implementation == "prefix-warm" {
				previous = warmDNPrefixForTest(b, registry, entry, "member", assertion)
			}
			var next *DNComparisonPrefix
			compare := func() (bool, bool, error) {
				present, matched, token, err := registry.CompareEntryAttributeWithDNPrefix(entry, "member", assertion, previous)
				next = token
				return present, matched, err
			}
			switch implementation {
			case "oracle":
				compare = func() (bool, bool, error) {
					return originalCompareEntryAttribute(registry, entry, "member", assertion)
				}
			case "uncached":
				compare = func() (bool, bool, error) {
					return registry.CompareEntryAttribute(entry, "member", assertion)
				}
			case "cached-dn":
				compare = func() (bool, bool, error) {
					return registry.CompareEntryAttributeCachedDN(entry, "member", assertion)
				}
			}
			present, matched, err := compare()
			if present != wantPresent || matched != wantMatched || err != nil {
				b.Fatalf("priming: (%v,%v,%v), want (%v,%v,nil)", present, matched, err, wantPresent, wantMatched)
			}
			b.ReportAllocs()
			for b.Loop() {
				present, matched, err = compare()
			}
			if present != wantPresent || matched != wantMatched || err != nil {
				b.Fatalf("comparison: (%v,%v,%v), want (%v,%v,nil)", present, matched, err, wantPresent, wantMatched)
			}
			if next != nil {
				b.ReportMetric(float64(next.RetainedBytes()), "retained-B/token")
			}
		})
	}
}

// Each row measures a single-value fill from a fixed prefix with 0, 1, ... 7 values.
// Preparation of that prefix is outside b.Loop. Keeping the input token fixed
// prevents a fill benchmark from silently turning into a steady-state warm one.
func BenchmarkCompareEntryAttributeWithDNPrefixFillSingle(b *testing.B) {
	for _, complex := range []bool{false, true} {
		shape := "simple"
		if complex {
			shape = "escaped-multi-AVA"
		}
		for pass := range 8 {
			b.Run(fmt.Sprintf("%s/values=1000/from=%d", shape, pass), func(b *testing.B) {
				registry := equalityEvaluationRegistry(b)
				entry := dnPrefixTestEntry(1000, complex)
				assertion := []byte("cn=missing,ou=People,dc=example")
				wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, "member", assertion)
				if !wantPresent || wantMatched || wantErr != nil {
					b.Fatalf("invalid fill fixture: (%v,%v,%v)", wantPresent, wantMatched, wantErr)
				}
				var previous *DNComparisonPrefix
				for range pass {
					present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, "member", assertion, previous)
					if !present || matched || err != nil || next == nil {
						b.Fatalf("fill setup: (%v,%v,%v), token=%v", present, matched, err, next != nil)
					}
					previous = next
				}
				before := dnPrefixTestBytes(previous)
				present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, "member", assertion, previous)
				if !present || matched || err != nil || dnPrefixTestBytes(next) <= before {
					b.Fatalf("fill priming: (%v,%v,%v), before=%d after=%d", present, matched, err, before, dnPrefixTestBytes(next))
				}
				b.ReportAllocs()
				for b.Loop() {
					present, matched, next, err = registry.CompareEntryAttributeWithDNPrefix(entry, "member", assertion, previous)
				}
				if !present || matched || err != nil || dnPrefixTestBytes(previous) != before || dnPrefixTestBytes(next) <= before {
					b.Fatalf("fill comparison: (%v,%v,%v), before=%d after=%d", present, matched, err, before, dnPrefixTestBytes(next))
				}
				b.ReportMetric(1, "values/call")
				b.ReportMetric(float64(next.RetainedBytes()), "retained-B/token")
			})
		}
	}
}

// Each timed operation is a complete 1001-call episode starting with a nil
// prefix. Last/missing fill one value per call for 1000 calls, then make one warm call;
// first naturally visits and retains only the first value. Registry and entry
// setup, oracle evaluation and one priming episode are outside b.Loop. The
// bounded Registry DN cache is shared across episodes and evolves normally;
// "shared" does not mean all 1000 DNs fit in that cache or stay warm.
func BenchmarkCompareEntryAttributeWithDNPrefixEpisode(b *testing.B) {
	const callsPerEpisode = 1001
	for _, position := range []struct {
		name  string
		index int
	}{{"first", 0}, {"last", 999}, {"missing", -1}} {
		for _, implementation := range []string{"cached-dn", "prefix-progressive"} {
			b.Run("simple/values=1000/"+position.name+"/dn-cache-shared/"+implementation, func(b *testing.B) {
				registry := equalityEvaluationRegistry(b)
				entry := dnPrefixTestEntry(1000, false)
				assertion := []byte("cn=missing,ou=People,dc=example")
				if position.index >= 0 {
					assertion = bytes.Clone(entry.Attributes[0].Values[position.index])
				}
				wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, "member", assertion)
				if !wantPresent || wantErr != nil {
					b.Fatalf("invalid episode fixture: (%v,%v,%v)", wantPresent, wantMatched, wantErr)
				}
				compare := func(previous *DNComparisonPrefix) (bool, bool, *DNComparisonPrefix, error) {
					return registry.CompareEntryAttributeWithDNPrefix(entry, "member", assertion, previous)
				}
				if implementation == "cached-dn" {
					compare = func(_ *DNComparisonPrefix) (bool, bool, *DNComparisonPrefix, error) {
						present, matched, err := registry.CompareEntryAttributeCachedDN(entry, "member", assertion)
						return present, matched, nil, err
					}
				}
				runEpisode := func() (*DNComparisonPrefix, bool) {
					var prefix *DNComparisonPrefix
					valid := true
					for range callsPerEpisode {
						present, matched, next, err := compare(prefix)
						valid = present == wantPresent && matched == wantMatched && err == nil && valid
						prefix = next
					}
					return prefix, valid
				}
				prefix, valid := runEpisode()
				if !valid || implementation == "prefix-progressive" && prefix == nil {
					b.Fatal("invalid priming episode")
				}
				wantRetained := dnPrefixTestBytes(prefix)
				allValid := true
				b.ReportAllocs()
				for b.Loop() {
					prefix, valid = runEpisode()
					allValid = valid && allValid
				}
				if !allValid || dnPrefixTestBytes(prefix) != wantRetained {
					b.Fatal("episode result or final retention changed")
				}
				b.ReportMetric(callsPerEpisode, "calls/episode")
				b.ReportMetric(float64(dnPrefixTestBytes(prefix)), "retained-B/token")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/(float64(b.N)*callsPerEpisode), "ns/call")
			})
		}
	}
}

// This is an artificial cache-reset diagnostic, not a cold-process benchmark.
// Each timed operation includes both lock pairs, discarding the DN cache map,
// and one comparison (including any new map allocation). Both implementations
// get the same reset. Generation and all other Registry caches are preserved;
// the prefix implementation always receives nil. No per-call timer pauses or
// Registry construction are used.
func BenchmarkCompareEntryAttributeWithDNPrefixDNCacheReset(b *testing.B) {
	for _, position := range []struct {
		name  string
		index int
	}{{"first", 0}, {"last", 999}, {"missing", -1}} {
		for _, implementation := range []string{"cached-dn", "prefix-cold"} {
			b.Run("simple/values=1000/"+position.name+"/artificial-reset-included/"+implementation, func(b *testing.B) {
				registry := equalityEvaluationRegistry(b)
				entry := dnPrefixTestEntry(1000, false)
				assertion := []byte("cn=missing,ou=People,dc=example")
				if position.index >= 0 {
					assertion = bytes.Clone(entry.Attributes[0].Values[position.index])
				}
				wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, "member", assertion)
				if !wantPresent || wantErr != nil {
					b.Fatalf("invalid reset fixture: (%v,%v,%v)", wantPresent, wantMatched, wantErr)
				}
				var prefix *DNComparisonPrefix
				compare := func() (bool, bool, error) {
					present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, "member", assertion, nil)
					prefix = next
					return present, matched, err
				}
				if implementation == "cached-dn" {
					compare = func() (bool, bool, error) {
						return registry.CompareEntryAttributeCachedDN(entry, "member", assertion)
					}
				}
				present, matched, err := compare()
				if present != wantPresent || matched != wantMatched || err != nil {
					b.Fatalf("reset priming: (%v,%v,%v)", present, matched, err)
				}
				allValid := true
				b.ReportAllocs()
				for b.Loop() {
					resetDNCacheForPrefixBenchmark(registry)
					present, matched, err = compare()
					allValid = present == wantPresent && matched == wantMatched && err == nil && allValid
				}
				if !allValid {
					b.Fatalf("reset comparison: (%v,%v,%v)", present, matched, err)
				}
				b.ReportMetric(1, "cache-resets/op")
				b.ReportMetric(float64(dnPrefixTestBytes(prefix)), "retained-B/token")
			})
		}
	}
}

func resetDNCacheForPrefixBenchmark(registry *Registry) {
	// Exclude in-flight normalizers while resetting, in the production lock
	// order. In particular, do not reset the schema generation.
	registry.mu.Lock()
	registry.dnCache.mu.Lock()
	registry.dnCache.entries = nil
	registry.dnCache.bytes = 0
	registry.dnCache.mu.Unlock()
	registry.mu.Unlock()
}
