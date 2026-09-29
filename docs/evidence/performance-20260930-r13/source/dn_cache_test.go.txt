package schema

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func mustCachedDN(t *testing.T, registry *Registry, value string) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDNCached(value)
	if err != nil {
		t.Fatalf("NormalizeDNCached(%q): %v", value, err)
	}
	return dn
}

func TestNormalizeDNCachedIdentityAndExactInput(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	inputs := []string{
		"", " ", "cn=Alice", "CN=ALICE", "cn= Alice", "2.5.4.3=Alice",
		"registryExactAlias=Alice,dc=example", "registryExactName=alice,dc=example",
		"registryFoldAlias=ENGINEERING+registryExactAlias=Alice,dc=example",
		registryDNExactOID + "=Alice+" + registryDNFoldOID + "=engineering,dc=example",
		`cn=Smith\, Alice+uid=ALICE,dc=example`,
		`cn=\c3\a9\+\00,dc=example`,
	}
	for _, raw := range inputs {
		want := mustNormalizedDN(t, registry, raw)
		for range 2 {
			got := mustCachedDN(t, registry, raw)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("cached result for %q differs from uncached result", raw)
			}
		}
		if _, ok := registry.dnCache.entries[raw]; !ok {
			t.Fatalf("exact input %q was not cached", raw)
		}
	}
	if len(registry.dnCache.entries) != len(inputs) {
		t.Fatal("equivalent inputs collapsed into one cache entry")
	}
	if !mustCachedDN(t, registry, inputs[2]).Equal(mustCachedDN(t, registry, inputs[5])) ||
		!mustCachedDN(t, registry, inputs[8]).Equal(mustCachedDN(t, registry, inputs[9])) {
		t.Fatal("alias, OID or multi-AVA identity changed")
	}
	if mustCachedDN(t, registry, inputs[6]).Equal(mustCachedDN(t, registry, inputs[7])) {
		t.Fatal("caseExact naming values collapsed")
	}
}

func TestNormalizeDNCachedErrorsAndOrdering(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	mustCachedDN(t, registry, "cn=valid")
	for _, tc := range []struct {
		raw, contains string
	}{
		{"broken", "parse DN"},
		{`cn=bad\zz`, "parse DN"},
		{"unknownName=x,broken", "parse DN"},
		{"unknownName=x,member=bad", `undefined attribute type "unknownName"`},
		{"member=bad,unknownName=x", `normalize DN attribute "member"`},
		{"jpegPhoto=x,unknownName=x", "no equality matching rule"},
		{"cn=x+cn=y", "duplicate attribute type"},
		{"registryExactName=x+registryExactAlias=y", "appears more than once"},
		{"registryExactName=x+registryExactAlias=y,broken", "parse DN"},
		{"member=unknownName\\=x", "distinguishedNameMatch received invalid DN"},
	} {
		_, wantErr := registry.NormalizeDN(tc.raw)
		if wantErr == nil || !strings.Contains(wantErr.Error(), tc.contains) {
			t.Fatalf("uncached error for %q = %v, want %q", tc.raw, wantErr, tc.contains)
		}
		for range 2 {
			got, err := registry.NormalizeDNCached(tc.raw)
			if err == nil || err.Error() != wantErr.Error() || reflect.TypeOf(err) != reflect.TypeOf(wantErr) ||
				!reflect.DeepEqual(got, directory.DN{}) {
				t.Fatalf("cached error for %q = %#v, %v; want zero DN, %v", tc.raw, got, err, wantErr)
			}
		}
		if len(registry.dnCache.entries) != 1 {
			t.Fatal("failed normalization populated the cache")
		}
	}
	if err := registry.RegisterAttributeType(AttributeType{
		OID: "1.2.3.999", Names: []string{"unknownName"}, Equality: "caseIgnoreMatch",
	}); err != nil {
		t.Fatal(err)
	}
	mustCachedDN(t, registry, "unknownName=x")
	if len(registry.dnCache.entries) != 1 || registry.dnCache.generation != registry.preparedNames.generation {
		t.Fatal("registration did not invalidate the previous generation")
	}
}

func TestNormalizeDNCachedInvalidation(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = registryDNExactOID + "=Alice"
	before := mustCachedDN(t, registry, raw)
	mustCachedDN(t, registry, "registryExactAlias=Alice")
	if _, err := registry.NormalizeDNCached("newExactAlias=Alice"); err == nil {
		t.Fatal("new alias already exists")
	}
	child := AttributeType{OID: "1.2.3.998", Names: []string{"cachedChild"}, Superior: registryDNExactOID}
	if err := registry.RegisterAttributeType(child); err != nil {
		t.Fatal(err)
	}
	childBefore := mustCachedDN(t, registry, "cachedChild=Alice")
	mustCachedDN(t, registry, "registryExactAlias=Alice")
	generation := registry.dnCache.generation
	attribute, _ := registry.AttributeType(registryDNExactOID)
	attribute.Names = []string{"renamedExact", "newExactAlias"}
	attribute.Equality = "caseIgnoreMatch"
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	after := mustCachedDN(t, registry, raw)
	if after.Equal(before) || after.String() != "renamedExact=Alice" ||
		after.NormalizedString() != "renamedExact=alice" {
		t.Fatal("replacement retained old naming semantics")
	}
	if registry.dnCache.generation == generation || registry.dnCache.generation != registry.preparedNames.generation ||
		len(registry.dnCache.entries) != 1 || registry.dnCache.bytes != estimatedDNCacheBytes(raw, normalizedDNCacheEntry{dn: after, normalized: after.NormalizedString()}) {
		t.Fatal("replacement retained old cache entries or accounting")
	}
	if _, err := registry.NormalizeDNCached("registryExactAlias=Alice"); err == nil {
		t.Fatal("removed alias was served from the cache")
	}
	if !mustCachedDN(t, registry, "newExactAlias=alice").Equal(after) {
		t.Fatal("new alias did not use the updated equality rule")
	}
	if mustCachedDN(t, registry, "cachedChild=Alice").Equal(childBefore) {
		t.Fatal("superior replacement did not invalidate inherited equality")
	}
	if before.String() != "registryExactName=Alice" || before.NormalizedString() != "registryExactName=Alice" {
		t.Fatal("invalidation mutated a previously returned DN")
	}
}

func TestNormalizeDNObservesExternalNamesMutation(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	names := []string{"firstName"}
	if err := registry.RegisterAttributeType(AttributeType{
		OID: "1.2.3.997", Names: names, Equality: "caseExactMatch",
	}); err != nil {
		t.Fatal(err)
	}
	const raw = "1.2.3.997=Alice"
	check := func(want string) {
		t.Helper()
		if got := mustNormalizedDN(t, registry, raw).String(); got != want+"=Alice" {
			t.Fatalf("uncached DN = %q, want name %q", got, want)
		}
	}
	check("firstName")
	names[0] = "secondName"
	check("secondName")
	attribute, _ := registry.AttributeType("1.2.3.997")
	attribute.Names[0] = "thirdName"
	check("thirdName")
	effective, _, err := registry.EffectiveAttributeType("1.2.3.997")
	if err != nil {
		t.Fatal(err)
	}
	effective.Names[0] = "fourthName"
	check("fourthName")
	if len(registry.dnCache.entries) != 0 {
		t.Fatal("NormalizeDN unexpectedly opted into caching")
	}
}

type dnCacheMutatingNormalizer struct{}

func (dnCacheMutatingNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	clear(value)
	return strings.ToLower(attribute), value, nil
}

func TestNormalizeDNCachedOwnership(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = "registryExactAlias=Alice+uid=ALICE,dc=EXAMPLE,dc=COM"
	want := mustNormalizedDN(t, registry, raw)
	dn := mustCachedDN(t, registry, raw)
	parent, ok := dn.Parent()
	if !ok {
		t.Fatal("missing parent")
	}
	wantParent, _ := want.Parent()
	for _, shared := range []directory.DN{dn, parent} {
		values := shared.RDNValues()
		for i := range values {
			values[i].Type = "changed"
			clear(values[i].Value)
		}
		renormalized, err := shared.NormalizeWith(dnCacheMutatingNormalizer{})
		if err != nil || renormalized.Key() == shared.Key() {
			t.Fatalf("mutating normalizer did not produce a distinct DN: %v", err)
		}
	}
	if !reflect.DeepEqual(dn, want) || !reflect.DeepEqual(parent, wantParent) ||
		!reflect.DeepEqual(mustCachedDN(t, registry, raw), want) {
		t.Fatal("RDNValues, NormalizeWith or Parent mutated cached state")
	}
}

func TestNormalizeDNCachedRecursiveMatching(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	for _, raw := range []string{
		`member=registryExactAlias\=Alice\,dc\=EXAMPLE,dc=com`,
		`uniqueMember=cn\=ALICE\,dc\=EXAMPLE#'01'B,dc=com`,
	} {
		want := mustNormalizedDN(t, registry, raw)
		for range 2 {
			if !reflect.DeepEqual(mustCachedDN(t, registry, raw), want) {
				t.Fatalf("recursive normalization changed for %q", raw)
			}
		}
	}
	if len(registry.dnCache.entries) != 2 {
		t.Fatal("recursive matching populated the outer DN cache")
	}
}

func TestNormalizeDNCachedBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw string
		cached    bool
	}{
		{"input limit", "cn=" + strings.Repeat("a", maxCachedDNInput-3), true},
		{"oversized input", "cn=" + strings.Repeat("a", maxCachedDNInput-2), false},
		{"depth limit", strings.Repeat("cn=x,", maxCachedDNDepth-1) + "cn=x", true},
		{"excess depth", strings.Repeat("cn=x,", maxCachedDNDepth) + "cn=x", false},
		{"escaped separators", "cn=" + strings.Repeat(`x\,`, maxCachedDNDepth+1) + "x", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := newRegistryDNEqRegistry(t)
			want := mustNormalizedDN(t, registry, tc.raw)
			for range 2 {
				if !reflect.DeepEqual(mustCachedDN(t, registry, tc.raw), want) {
					t.Fatal("cache eligibility changed normalization")
				}
			}
			_, cached := registry.dnCache.entries[tc.raw]
			if cached != tc.cached || !cached && registry.dnCache.bytes != 0 {
				t.Fatalf("cached = %v, bytes = %d; want cached = %v", cached, registry.dnCache.bytes, tc.cached)
			}
		})
	}
}

func TestNormalizeDNCachedEviction(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	first := mustCachedDN(t, registry, "cn=0")
	want := mustNormalizedDN(t, registry, "cn=0")
	for i := 1; i < maxCachedDNs; i++ {
		mustCachedDN(t, registry, fmt.Sprintf("cn=%d", i))
	}
	if len(registry.dnCache.entries) != maxCachedDNs {
		t.Fatal("cache did not reach the entry limit")
	}
	mustCachedDN(t, registry, "cn=evict")
	if len(registry.dnCache.entries) != 1 {
		t.Fatal("entry limit did not evict old entries")
	}
	if _, ok := registry.dnCache.entries["cn=0"]; ok {
		t.Fatal("old entry survived eviction")
	}
	if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(mustCachedDN(t, registry, "cn=0"), want) {
		t.Fatal("eviction changed a published or reparsed DN")
	}
}

func TestNormalizeDNCachedMemoryBudget(t *testing.T) {
	t.Parallel()
	for _, nameSize := range []int{2048, maxCachedDNBytes / 8} {
		t.Run(fmt.Sprint(nameSize), func(t *testing.T) {
			registry := NewRegistry()
			if err := registry.RegisterAttributeType(AttributeType{
				OID: "1.2.3.996", Names: []string{strings.Repeat("n", nameSize), "short"}, Equality: "caseExactMatch",
			}); err != nil {
				t.Fatal(err)
			}
			if nameSize == maxCachedDNBytes/8 {
				got := mustCachedDN(t, registry, "short=Alice")
				if got.String() != strings.Repeat("n", nameSize)+"=Alice" {
					t.Fatal("oversized result changed")
				}
				if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
					t.Fatal("oversized result was retained")
				}
				return
			}
			evicted := false
			for i := range maxCachedDNs {
				previous := len(registry.dnCache.entries)
				mustCachedDN(t, registry, fmt.Sprintf("short=%d", i))
				if len(registry.dnCache.entries) < previous {
					evicted = true
				}
				retained := 0
				for raw, dn := range registry.dnCache.entries {
					retained += estimatedDNCacheBytes(raw, dn)
				}
				if retained != registry.dnCache.bytes || retained > maxCachedDNBytes ||
					len(registry.dnCache.entries) > maxCachedDNs {
					t.Fatalf("cache budget/accounting violated: %d / %d", retained, registry.dnCache.bytes)
				}
			}
			if !evicted {
				t.Fatal("memory budget did not evict before the entry limit")
			}
		})
	}
}

func TestNormalizeDNCachedClone(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = "registryExactAlias=Alice"
	original := mustCachedDN(t, registry, raw)
	cloned := registry.Clone()
	if cloned.dnCache.entries != nil || cloned.dnCache.bytes != 0 || cloned.dnCache.generation != 0 {
		t.Fatal("clone inherited cache state")
	}
	if !reflect.DeepEqual(mustCachedDN(t, cloned, raw), original) {
		t.Fatal("clone changed DN normalization")
	}
	attribute, _ := cloned.AttributeType(registryDNExactOID)
	attribute.Equality = "caseIgnoreMatch"
	if err := cloned.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	if mustCachedDN(t, cloned, raw).Equal(original) ||
		!reflect.DeepEqual(mustCachedDN(t, registry, raw), original) {
		t.Fatal("clone and original share cache or schema state")
	}
}

func TestNormalizeDNCachedConcurrency(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	attributes := []AttributeType{
		{OID: "1.2.3.995", Names: []string{"exactName"}, Equality: "caseExactMatch"},
		{OID: "1.2.3.995", Names: []string{"foldName"}, Equality: "caseIgnoreMatch"},
	}
	raws := []string{"1.2.3.995=Alice", "1.2.3.995=Alice,1.2.3.995=Bob"}
	var wants [2][2]directory.DN
	for version, attribute := range attributes {
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		for i, raw := range raws {
			wants[version][i] = mustNormalizedDN(t, registry, raw)
		}
	}
	var workers sync.WaitGroup
	start := make(chan struct{})
	failures := make(chan error, 9)
	for range 8 {
		workers.Go(func() {
			<-start
			for i := range 200 {
				index := i % len(raws)
				got, err := registry.NormalizeDNCached(raws[index])
				if err != nil || !reflect.DeepEqual(got, wants[0][index]) && !reflect.DeepEqual(got, wants[1][index]) {
					failures <- fmt.Errorf("mixed schema generation: %#v, %v", got, err)
					return
				}
			}
		})
	}
	workers.Go(func() {
		<-start
		for i := range 80 {
			version := i % len(attributes)
			if err := registry.UpsertAttributeType(attributes[version]); err != nil {
				failures <- err
				return
			}
			got, err := registry.NormalizeDNCached(raws[0])
			if err != nil || !reflect.DeepEqual(got, wants[version][0]) {
				failures <- fmt.Errorf("stale DN after replacement: %#v, %v", got, err)
				return
			}
		}
	})
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	mustCachedDN(t, registry, raws[0])
	retained := 0
	for raw, dn := range registry.dnCache.entries {
		retained += estimatedDNCacheBytes(raw, dn)
	}
	if registry.dnCache.generation != registry.preparedNames.generation ||
		registry.dnCache.bytes != retained || len(registry.dnCache.entries) > len(raws) {
		t.Fatal("concurrent publication corrupted cache generation or accounting")
	}
}
