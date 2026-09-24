package schema

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestDNCacheNormalizedTextSharedConsumers(t *testing.T) {
	t.Parallel()
	for _, first := range []string{"DN", "equality", "assertion"} {
		t.Run(first, func(t *testing.T) {
			registry := newRegistryDNEqRegistry(t)
			for _, raw := range []string{
				"", " ", "DC=EXAMPLE,DC=COM",
				"registryExactAlias=Alice,dc=EXAMPLE",
				registryDNExactOID + "=alice,dc=example",
				"registryFoldAlias=ENGINEERING+registryExactAlias=Alice,dc=example",
				`cn=Smith\, Alice+uid=ALICE,dc=example`,
				`cn=\c3\a9\+\00,dc=example`,
				`member=registryExactAlias\=Alice\,dc\=EXAMPLE,dc=com`,
			} {
				want := mustNormalizedDN(t, registry, raw)
				entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(raw)}}}
				equality := func() {
					t.Helper()
					got, hasValues := registry.EvaluateEqualityCachedDN(entry, "member", []byte(raw))
					if got != directory.FilterTrueResult || !hasValues {
						t.Fatalf("equality for %q = (%v,%v)", raw, got, hasValues)
					}
				}
				assertion := func() {
					t.Helper()
					assertCachedAssertionParity(t, registry, "member", []byte(raw))
				}
				switch first {
				case "DN":
					mustCachedDN(t, registry, raw)
				case "equality":
					equality()
				case "assertion":
					assertion()
				}
				cached, ok := registry.dnCache.entries[raw]
				if !ok || !reflect.DeepEqual(cached.dn, want) || cached.normalized != want.NormalizedString() {
					t.Fatalf("cache entry for %q changed the DN or its normalized text", raw)
				}
				retained := registry.dnCache.bytes
				for range 2 {
					if !reflect.DeepEqual(mustCachedDN(t, registry, raw), want) {
						t.Fatalf("public DN value changed for %q", raw)
					}
					equality()
					assertion()
					if registry.dnCache.bytes != retained ||
						unsafe.StringData(cached.normalizedString()) != unsafe.StringData(cached.normalized) ||
						unsafe.StringData(registry.dnCache.entries[raw].normalized) != unsafe.StringData(cached.normalized) {
						t.Fatalf("cache hit rerendered text or changed accounting for %q", raw)
					}
				}
			}
		})
	}
}

func TestDNCacheNormalizedTextOwnership(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = "registryExactAlias=Alice+uid=ALICE,dc=EXAMPLE,dc=COM"
	backing := raw + strings.Repeat("!", 1<<20)
	borrowed := backing[:len(raw)]
	want := mustNormalizedDN(t, registry, raw)
	dn := mustCachedDN(t, registry, borrowed)
	for key, cached := range registry.dnCache.entries {
		if unsafe.StringData(key) == unsafe.StringData(borrowed) ||
			unsafe.StringData(cached.normalized) == unsafe.StringData(borrowed) {
			t.Fatal("cache retained the caller's oversized backing string")
		}
	}
	input := []byte(raw)
	output, err := registry.NormalizeEqualityAssertionCachedDN("member", input)
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	clear(output)
	for _, value := range dn.RDNValues() {
		clear(value.Value)
	}
	if _, err := dn.NormalizeWith(dnCacheMutatingNormalizer{}); err != nil {
		t.Fatal(err)
	}
	cached := registry.dnCache.entries[raw]
	if !reflect.DeepEqual(cached.dn, want) || cached.normalized != want.NormalizedString() {
		t.Fatal("caller-owned bytes or derived DN values mutated cached state")
	}
	assertCachedAssertionParity(t, registry, "member", []byte(raw))
}

func TestDNCacheNormalizedTextInvalidation(t *testing.T) {
	t.Parallel()
	registry := newRegistryDNEqRegistry(t)
	const raw = registryDNExactOID + "=Alice,dc=EXAMPLE"
	mustCachedDN(t, registry, raw)
	before := registry.dnCache.entries[raw]
	generation := registry.dnCache.generation
	cloned := registry.Clone()
	if cloned.dnCache.entries != nil || cloned.dnCache.bytes != 0 {
		t.Fatal("clone inherited retained text")
	}
	attribute, _ := registry.AttributeType(registryDNExactOID)
	attribute.Names = []string{"renamedText", "newTextAlias"}
	attribute.Equality = "caseIgnoreMatch"
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	got, err := registry.NormalizeEqualityAssertionCachedDN("member", []byte(raw))
	if err != nil || string(got) != "renamedText=alice,dc=example" {
		t.Fatalf("text after schema mutation = %q, %v", got, err)
	}
	after := registry.dnCache.entries[raw]
	if after.normalized != string(got) || !reflect.DeepEqual(after.dn, mustNormalizedDN(t, registry, raw)) ||
		registry.dnCache.generation == generation || len(registry.dnCache.entries) != 1 {
		t.Fatal("DN and normalized text were not invalidated together")
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("newTextAlias=ALICE,dc=example")}}}
	checkCachedDNEquality(t, registry, entry, equalityLeaf("member", raw))
	if before.normalized != "registryExactName=Alice,dc=example" || before.dn.NormalizedString() != before.normalized {
		t.Fatal("invalidation changed a previously returned entry")
	}
	if _, err := assertCachedAssertionParity(t, registry, "member", []byte("registryExactAlias=Alice,dc=example")); err == nil {
		t.Fatal("removed alias survived invalidation")
	}
	mustCachedDN(t, cloned, raw)
	if cloned.dnCache.entries[raw].normalized != before.normalized {
		t.Fatal("clone's text followed mutation of the original registry")
	}
}

func TestDNCacheNormalizedTextIneligible(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw string
	}{
		{"input", "cn=" + strings.Repeat("a", maxCachedDNInput)},
		{"depth", strings.Repeat("cn=x,", maxCachedDNDepth) + "dc=example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := newRegistryDNEqRegistry(t)
			want := mustNormalizedDN(t, registry, tc.raw)
			registry.mu.RLock()
			entry, err := registry.normalizeDNCachedLocked(tc.raw)
			registry.mu.RUnlock()
			if err != nil || !reflect.DeepEqual(entry.dn, want) || entry.normalized != "" {
				t.Fatalf("ineligible DN was changed or eagerly rendered: %v", err)
			}
			if entry.normalizedString() != want.NormalizedString() {
				t.Fatal("ineligible text fallback changed normalization")
			}
			assertCachedAssertionParity(t, registry, "member", []byte(tc.raw))
			stored := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(tc.raw)}}}
			checkCachedDNEquality(t, registry, stored, equalityLeaf("member", tc.raw))
			if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
				t.Fatal("ineligible text was retained")
			}
		})
	}
}

func TestDNCacheNormalizedTextBudget(t *testing.T) {
	t.Parallel()
	for _, nameSize := range []int{8, 2048, maxCachedDNBytes / 8} {
		t.Run(fmt.Sprint(nameSize), func(t *testing.T) {
			registry := NewRegistry()
			if err := registry.RegisterAttributeType(AttributeType{
				OID: "1.2.3.996", Names: []string{strings.Repeat("n", nameSize), "short"}, Equality: "caseExactMatch",
			}); err != nil {
				t.Fatal(err)
			}
			const firstRaw = "short=first"
			first := mustCachedDN(t, registry, firstRaw)
			if nameSize == maxCachedDNBytes/8 {
				if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
					t.Fatal("oversized normalized text was retained")
				}
				return
			}
			firstText := registry.dnCache.entries[firstRaw].normalized
			for index := range maxCachedDNs {
				mustCachedDN(t, registry, fmt.Sprintf("short=%d", index))
				retained := 0
				for raw, entry := range registry.dnCache.entries {
					dn := entry.dn
					if entry.normalized != dn.NormalizedString() {
						t.Fatal("cache retained text from another DN")
					}
					// Keep the original conservative budget, including its
					// allowance for rendered text, independently of the helper.
					retained += 512 + 512*dn.Depth() + 256*strings.Count(raw, "=") +
						4*(len(raw)+len(dn.Key())+len(dn.String())+len(entry.normalized))
				}
				if retained != registry.dnCache.bytes || retained > maxCachedDNBytes || len(registry.dnCache.entries) > maxCachedDNs {
					t.Fatalf("text budget exceeded: entries=%d, bytes=%d, accounted=%d", len(registry.dnCache.entries), registry.dnCache.bytes, retained)
				}
			}
			if _, ok := registry.dnCache.entries[firstRaw]; ok {
				t.Fatal("DN/text entry survived eviction")
			}
			if firstText != first.NormalizedString() || !reflect.DeepEqual(first, mustNormalizedDN(t, registry, firstRaw)) {
				t.Fatal("eviction changed a previously returned DN or text")
			}
		})
	}
}
