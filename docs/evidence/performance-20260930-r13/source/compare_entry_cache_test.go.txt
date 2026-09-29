package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func checkCompareEntryAttributeCachedDN(t testing.TB, registry *Registry, entry directory.Entry, description string, assertion []byte) (bool, bool, error) {
	t.Helper()
	wantPresent, wantMatched, wantErr := checkCompareEntryAttribute(t, registry, entry, description, assertion)
	before := entry
	before.Attributes = slices.Clone(entry.Attributes)
	for i := range before.Attributes {
		before.Attributes[i].Values = slices.Clone(entry.Attributes[i].Values)
		for j, value := range before.Attributes[i].Values {
			before.Attributes[i].Values[j] = bytes.Clone(value)
		}
	}
	assertionBefore := bytes.Clone(assertion)
	for pass := range 2 {
		present, matched, err := registry.CompareEntryAttributeCachedDN(entry, description, assertion)
		if present != wantPresent || matched != wantMatched || !reflect.DeepEqual(err, wantErr) {
			t.Fatalf("pass %d %s=%q: cached=(%v,%v,%v), oracle=(%v,%v,%v)", pass, description, assertion, present, matched, err, wantPresent, wantMatched, wantErr)
		}
		if !reflect.DeepEqual(entry, before) || !reflect.DeepEqual(assertion, assertionBefore) {
			t.Fatal("cached comparison mutated caller-owned input")
		}
	}
	return wantPresent, wantMatched, wantErr
}

func TestCompareEntryAttributeCachedDNParity(t *testing.T) {
	for _, test := range []struct {
		name, requested, candidate, assertion string
		values                                [][]byte
	}{
		{"absent invalid", "member", "cn", "bad-dn", byteValues("alice")},
		{"empty nil invalid", "member", "member", "bad-dn", nil},
		{"empty slice invalid", "member", "member", "bad-dn", [][]byte{}},
		{"root", "member", "member", "", [][]byte{nil}},
		{"aliases", "member", "2.5.4.31", "cn=alice", byteValues("2.5.4.3=ALICE")},
		{"subtype options", "member;lang-", "cachedMemberAlias;lang-en", "cn=alice", byteValues("CN=Alice")},
		{"OID rule", "cachedOIDMember", "cachedOIDMember", "cn=alice", byteValues("CN=Alice")},
		{"first error", "member", "member", "cn=alice", byteValues("bad-dn", "cn=alice")},
		{"first match", "member", "member", "cn=alice", byteValues("cn=alice", "bad-dn")},
		{"valid miss then error", "member", "member", "cn=alice", byteValues("cn=bob", "bad-dn", "cn=alice")},
		{"valid miss then match", "member", "member", "cn=alice", byteValues("cn=bob", "CN=Alice")},
		{"bad assertion", "member", "member", "bad-dn", byteValues("cn=alice", "bad-dn")},
		{"both bad", "member", "member", "bad-dn", byteValues("bad-dn")},
		{"escaped multi AVA", "member", "member", `uid=a+cn=Smith\2c Alice`, byteValues(`cn=Smith\, Alice+uid=A`)},
		{"ordered index", "cachedOrderedMember", "cachedOrderedMember", "{1}", byteValues("{1}bad-dn")},
		{"ordered first error", "cachedOrderedMember", "cachedOrderedMember", "{1}", byteValues("{bad}cn=x", "{1}bad-dn")},
		{"ordered content", "cachedOrderedMember", "cachedOrderedMember", "cn=alice", byteValues("{0}CN=Alice")},
		{"exact fallback", "cachedExactMember", "cachedExactMember", "cn=alice", byteValues("CN=Alice")},
		{"UID fallback", "uid", "uid", "alice", byteValues("ALICE")},
		{"uniqueMember fallback", "uniqueMember", "uniqueMember", "bad#'10'B", byteValues("bad#'01'B")},
		{"unknown fallback", "missingAttribute", "missingAttribute", "x", byteValues("x")},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, split := range []bool{false, true} {
				registry := cachedDNEqualityRegistry(t)
				entry := directory.Entry{Attributes: []directory.Attribute{{Description: test.candidate, Values: test.values, RawNormalized: true}}}
				if split && len(test.values) > 1 {
					entry.Attributes[0].Values = test.values[:1]
					entry.Attributes = append(entry.Attributes, directory.Attribute{Description: test.candidate + ";lang-en", Values: test.values[1:]})
				}
				checkCompareEntryAttributeCachedDN(t, registry, entry, test.requested, []byte(test.assertion))
				if _, cached := registry.dnCache.entries["bad-dn"]; cached {
					t.Fatal("invalid DN was cached")
				}
				if strings.Contains(test.name, "fallback") || strings.HasPrefix(test.name, "ordered") || strings.HasPrefix(test.name, "empty") || strings.HasPrefix(test.name, "absent") {
					if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
						t.Fatal("fallback or valueless comparison populated the DN cache")
					}
				}
			}
		})
	}
}

func TestCompareEntryAttributeCachedDNOwnership(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("CN=Alice")}}}
	assertion := []byte("cn=alice")
	checkCompareEntryAttributeCachedDN(t, registry, entry, "member", assertion)
	if len(registry.dnCache.entries) != 2 {
		t.Fatal("first stored DN and assertion were not both cached")
	}
	wantStored := mustNormalizedDN(t, registry, "CN=Alice")
	wantAssertion := mustNormalizedDN(t, registry, "cn=alice")
	copy(entry.Attributes[0].Values[0], "CN=Other")
	if _, matched, _ := checkCompareEntryAttributeCachedDN(t, registry, entry, "member", assertion); matched {
		t.Fatal("changed entry reused a comparison result")
	}
	copy(assertion, "cn=other")
	checkCompareEntryAttributeCachedDN(t, registry, entry, "member", assertion)
	if !reflect.DeepEqual(mustCachedDN(t, registry, "CN=Alice"), wantStored) || !reflect.DeepEqual(mustCachedDN(t, registry, "cn=alice"), wantAssertion) {
		t.Fatal("caller buffer reuse corrupted cached DNs")
	}
}

func TestCompareEntryAttributeCachedDNSchemaChange(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("1.2.3.802=ALICE")}}}
	attribute, _ := registry.AttributeType("eqExact")
	for _, rule := range []string{"caseExactMatch", "caseIgnoreMatch", "caseExactMatch"} {
		generation := registry.dnCache.generation
		attribute.Equality = rule
		attribute.Names = []string{"renamedExact"}
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		present, matched, err := checkCompareEntryAttributeCachedDN(t, registry, entry, "member", []byte("1.2.3.802=alice"))
		if !present || err != nil || matched != (rule == "caseIgnoreMatch") {
			t.Fatalf("after %s: (%v,%v,%v)", rule, present, matched, err)
		}
		if registry.dnCache.generation == generation || registry.dnCache.generation != registry.preparedNames.generation {
			t.Fatal("schema mutation did not refresh the DN cache generation")
		}
	}
}

func TestCompareEntryAttributeRemainsUncached(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("1.2.3.802=ALICE")}}}
	checkCompareEntryAttribute(t, registry, entry, "member", []byte("eqExact=ALICE"))
	if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
		t.Fatal("default comparison populated the DN cache")
	}
	checkCompareEntryAttributeCachedDN(t, registry, entry, "member", entry.Attributes[0].Values[0])
	// Direct shared Names edits violate the opt-in contract. Only exercise the
	// default API afterward, with one previously cached DN and one new spelling.
	attribute, _ := registry.AttributeType("eqExact")
	attribute.Names[0] = "externallyChanged"
	if _, matched, err := checkCompareEntryAttribute(t, registry, entry, "member", []byte("eqExact=ALICE")); err != nil || !matched {
		t.Fatalf("default comparison reused stale normalization: matched=%v, err=%v", matched, err)
	}
}

func TestCompareEntryAttributeCachedDNBounds(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, raw := range []string{"cn=" + strings.Repeat("x", maxCachedDNInput), strings.Repeat("ou=x,", maxCachedDNDepth) + "dc=example"} {
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(raw)}}}
		if _, matched, err := checkCompareEntryAttributeCachedDN(t, registry, entry, "member", []byte(raw)); err != nil || !matched {
			t.Fatalf("oversized DN comparison: matched=%v, err=%v", matched, err)
		}
		if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
			t.Fatal("oversized or over-depth DN was retained")
		}
	}
	for i := range maxCachedDNs + 2 {
		raw := fmt.Sprintf("cn=user%d", i)
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(raw)}}}
		checkCompareEntryAttributeCachedDN(t, registry, entry, "member", []byte(raw))
		retained := 0
		for key, dn := range registry.dnCache.entries {
			retained += estimatedDNCacheBytes(key, dn)
		}
		if len(registry.dnCache.entries) == 0 || len(registry.dnCache.entries) > maxCachedDNs || retained != registry.dnCache.bytes || retained > maxCachedDNBytes {
			t.Fatal("comparison exceeded cache bounds or corrupted accounting")
		}
	}
}

func BenchmarkCompareEntryAttributeCachedDN(b *testing.B) {
	group := make([][]byte, 1000)
	for i := range group {
		group[i] = fmt.Appendf(nil, "CN=User%d,OU=People,DC=example,DC=com", i)
	}
	for _, workload := range []struct {
		name, description, assertion string
		values                       [][]byte
	}{
		{"group1000/first", "member", "cn=user0,ou=people,dc=example,dc=com", group},
		{"UID/single", "uid", "alice", byteValues("Alice")},
	} {
		b.Run(workload.name, func(b *testing.B) {
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: workload.description, Values: workload.values}}}
			assertion := []byte(workload.assertion)
			for _, implementation := range []string{"before", "cached"} {
				b.Run(implementation, func(b *testing.B) {
					registry := equalityEvaluationRegistry(b)
					compare := registry.CompareEntryAttribute
					if implementation == "cached" {
						compare = registry.CompareEntryAttributeCachedDN
					}
					// Prime the selected implementation before b.Loop starts timing.
					present, matched, err := compare(entry, workload.description, assertion)
					if !present || !matched || err != nil {
						b.Fatalf("fixture: (%v,%v,%v)", present, matched, err)
					}
					b.ReportAllocs()
					for b.Loop() {
						present, matched, err = compare(entry, workload.description, assertion)
					}
					if !present || !matched || err != nil {
						b.Fatalf("comparison: (%v,%v,%v)", present, matched, err)
					}
				})
			}
		})
	}
}
