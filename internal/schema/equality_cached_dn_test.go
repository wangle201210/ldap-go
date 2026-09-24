package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Preserve every Registry interface used by mixed Filter trees while replacing
// only the equality evaluator selected by EvaluateWith.
type cachedDNEqualityMatcher struct{ *Registry }

func (matcher cachedDNEqualityMatcher) EvaluateEquality(entry directory.Entry, description string, assertion []byte) (directory.FilterResult, bool) {
	return matcher.EvaluateEqualityCachedDN(entry, description, assertion)
}

func cachedDNEqualityRegistry(t *testing.T) *Registry {
	t.Helper()
	registry := newRegistryDNEqRegistry(t)
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.901", Names: []string{"cachedMember", "cachedMemberAlias"}, Superior: "member"},
		{OID: "1.2.3.902", Names: []string{"cachedMemberGrandchild"}, Superior: "cachedMember"},
		{OID: "1.2.3.903", Names: []string{"cachedExactMember"}, Superior: "member", Equality: "caseExactMatch"},
		{OID: "1.2.3.904", Names: []string{"cachedOrderedMember"}, Superior: "member", Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
		{OID: "1.2.3.905", Names: []string{"cachedOrderedChild"}, Superior: "cachedOrderedMember"},
		{OID: "1.2.3.906", Names: []string{"cachedOIDMember"}, Equality: "2.5.13.1", Syntax: SyntaxDistinguishedName},
		{OID: "1.2.3.907", Names: []string{"cachedOrphan"}, Superior: "missingParent", Equality: "distinguishedNameMatch"},
		{OID: "1.2.3.908", Names: []string{"cachedCycleA"}, Superior: "cachedCycleB", Equality: "distinguishedNameMatch"},
		{OID: "1.2.3.909", Names: []string{"cachedCycleB"}, Superior: "cachedCycleA"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func checkCachedDNEquality(t *testing.T, registry *Registry, entry directory.Entry, leaf directory.Filter) (directory.FilterResult, bool, directory.FilterResult) {
	t.Helper()
	before := entry
	before.Attributes = slices.Clone(entry.Attributes)
	for i := range before.Attributes {
		before.Attributes[i].Values = slices.Clone(entry.Attributes[i].Values)
		for j, value := range before.Attributes[i].Values {
			before.Attributes[i].Values[j] = bytes.Clone(value)
		}
	}
	assertionBefore := bytes.Clone(leaf.Assertion)
	truth := equalityNode(directory.FilterAnd)
	falsehood := equalityNode(directory.FilterOr)
	undefined := equalityLeaf("cachedUnknownAttribute", "x")
	not := equalityNode(directory.FilterNot, leaf)
	filters := []directory.Filter{
		leaf, not, equalityNode(directory.FilterNot, not),
		equalityNode(directory.FilterAnd, leaf, undefined),
		equalityNode(directory.FilterAnd, undefined, leaf, falsehood),
		equalityNode(directory.FilterOr, leaf, undefined),
		equalityNode(directory.FilterOr, undefined, leaf, truth),
		equalityNode(directory.FilterNot, equalityNode(directory.FilterOr, not, undefined)),
		equalityNode(directory.FilterNot, equalityNode(directory.FilterAnd, not, undefined)),
	}
	want, wantHasValues := registry.EvaluateEquality(entry, leaf.Attribute, leaf.Assertion)
	wantFilter, wantErr := leaf.EvaluateWith(entry, registry)
	if wantErr != nil {
		t.Fatalf("oracle leaf error: %v", wantErr)
	}
	for pass := range 2 {
		got, hasValues := registry.EvaluateEqualityCachedDN(entry, leaf.Attribute, leaf.Assertion)
		if got != want || hasValues != wantHasValues {
			t.Fatalf("pass %d (%s=%q), values=%+v: cached=(%v,%v), uncached=(%v,%v)",
				pass, leaf.Attribute, leaf.Assertion, entry.Attributes, got, hasValues, want, wantHasValues)
		}
		for i, filter := range filters {
			want, wantErr := filter.EvaluateWith(entry, registry)
			got, gotErr := filter.EvaluateWith(entry, cachedDNEqualityMatcher{registry})
			if got != want || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Fatalf("pass %d tree %d (%s=%q): cached=(%v,%v), uncached=(%v,%v)",
					pass, i, leaf.Attribute, leaf.Assertion, got, gotErr, want, wantErr)
			}
		}
	}
	if !reflect.DeepEqual(entry, before) || !reflect.DeepEqual(leaf.Assertion, assertionBefore) {
		t.Fatal("equality evaluation changed caller-owned input")
	}
	return want, wantHasValues, wantFilter
}

func TestEvaluateEqualityCachedDNValues(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	values := byteValues(
		"", " ", "CN=Alice,DC=example", "2.5.4.3=alice,domainComponent=EXAMPLE", "cn=bob,dc=example",
		"registryExactAlias=Alice", "registryExactName=alice", registryDNExactOID+"=Alice",
		"registryFoldAlias=ENGINEERING+registryExactAlias=Alice,dc=example",
		registryDNExactOID+"=Alice+"+registryDNFoldOID+"=engineering,dc=example",
		`cn=Smith\, Alice+uid=ALICE,dc=example`, `uid=alice+CN=Smith\2c Alice,dc=EXAMPLE`,
		`cn=\c3\a9\+\00,dc=example`, `cn=\c3\a9\2b\00,dc=example`,
		`member=registryExactAlias\=Alice\,dc\=EXAMPLE,dc=com`,
		`2.5.4.31=registryExactName\=Alice\,dc\=example,dc=COM`,
		`uniqueMember=cn\=ALICE\,dc\=EXAMPLE#'01'B,dc=com`,
		`2.5.4.50=2.5.4.3\=alice\,dc\=example#'01'B,dc=com`,
		"not-a-dn", `cn=bad\zz`, `cn=\ff`, "cn=\x00", "cn=\xff", "\xff",
		"missingNamingType=Alice", "jpegPhoto=x", "cn=x+cn=y",
		"registryExactAlias=x+registryExactName=y", `member=missingNamingType\=x`,
	)
	values = append(values, nil)
	for i, assertion := range values {
		t.Run(fmt.Sprintf("assertion-%d", i), func(t *testing.T) {
			leaf := equalityLeaf("member", "")
			leaf.Assertion = assertion
			entries := []directory.Entry{
				{},
				{Attributes: []directory.Attribute{}},
				{Attributes: []directory.Attribute{{Description: "member"}}},
				{Attributes: []directory.Attribute{{Description: "member", Values: [][]byte{}}}},
				{Attributes: []directory.Attribute{{Description: "cn", Values: [][]byte{assertion}}}},
				{Attributes: []directory.Attribute{{Description: "member", Values: values}}},
				{Attributes: []directory.Attribute{
					{Description: "member", Values: byteValues("not-a-dn")},
					{Description: "cachedMemberAlias;lang-en", Values: [][]byte{assertion}},
				}},
			}
			for _, entry := range entries {
				checkCachedDNEquality(t, registry, entry, leaf)
			}
			for _, stored := range values {
				entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: [][]byte{stored}}}}
				checkCachedDNEquality(t, registry, entry, leaf)
			}
		})
	}
}

func TestEvaluateEqualityCachedDNResults(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	for _, tc := range []struct {
		name, description, assertion string
		values                       [][]byte
		want                         directory.FilterResult
		hasValues                    bool
		wantFilter                   directory.FilterResult
	}{
		{"absent valid", "member", "cn=Alice", nil, directory.FilterFalseResult, false, directory.FilterFalseResult},
		{"absent invalid", "member", "bad", nil, directory.FilterFalseResult, false, directory.FilterUndefinedResult},
		{"empty values invalid", "member", "bad", [][]byte{}, directory.FilterFalseResult, false, directory.FilterUndefinedResult},
		{"nil value root", "member", "", [][]byte{nil}, directory.FilterTrueResult, true, directory.FilterTrueResult},
		{"empty value root", "member", "", byteValues(""), directory.FilterTrueResult, true, directory.FilterTrueResult},
		{"invalid assertion", "member", "bad", byteValues("cn=Alice", "bad"), directory.FilterUndefinedResult, true, directory.FilterUndefinedResult},
		{"invalid stored", "member", "cn=Alice", byteValues("bad"), directory.FilterUndefinedResult, true, directory.FilterUndefinedResult},
		{"invalid then match", "member", "cn=alice", byteValues("bad", "CN=Alice"), directory.FilterTrueResult, true, directory.FilterTrueResult},
		{"match then invalid", "member", "cn=alice", byteValues("CN=Alice", "bad"), directory.FilterTrueResult, true, directory.FilterTrueResult},
		{"invalid then miss", "member", "cn=alice", byteValues("bad", "cn=Bob"), directory.FilterUndefinedResult, true, directory.FilterUndefinedResult},
		{"miss", "member", "cn=alice", byteValues("cn=Bob"), directory.FilterFalseResult, true, directory.FilterFalseResult},
		{"exact naming case", "member", "registryExactName=alice", byteValues("registryExactAlias=Alice"), directory.FilterFalseResult, true, directory.FilterFalseResult},
		{"OID equality rule", "cachedOIDMember", "2.5.4.3=alice", byteValues("cn=Alice"), directory.FilterTrueResult, true, directory.FilterTrueResult},
		{"UID mismatch skips bad DNs", "uniqueMember", "bad#'10'B", byteValues("bad#'01'B"), directory.FilterFalseResult, true, directory.FilterFalseResult},
		{"UID length skips bad DNs", "uniqueMember", "bad#'1'B", byteValues("bad#'01'B"), directory.FilterFalseResult, true, directory.FilterFalseResult},
		{"UID absence skips bad DN", "uniqueMember", "bad", byteValues("bad#'01'B"), directory.FilterFalseResult, true, directory.FilterFalseResult},
		{"UID presence skips bad DN", "uniqueMember", "bad#'01'B", byteValues("bad"), directory.FilterFalseResult, true, directory.FilterFalseResult},
		{"equal UID validates DN", "uniqueMember", "bad#'01'B", byteValues("bad#'01'B"), directory.FilterUndefinedResult, true, directory.FilterUndefinedResult},
		{"absent UID assertion validates DN", "uniqueMember", "bad#'10'B", nil, directory.FilterFalseResult, false, directory.FilterUndefinedResult},
		{"invalid UID becomes DN content", "uniqueMember", "cn=Alice#'2'B", byteValues("CN=alice#'2'B"), directory.FilterTrueResult, true, directory.FilterTrueResult},
		{"ordered index bypasses bad content", "cachedOrderedMember", "{1}", byteValues("{bad}cn=x", "{1}bad"), directory.FilterTrueResult, true, directory.FilterTrueResult},
		{"ordered different index skips bad DN", "cachedOrderedMember", "{2}bad", byteValues("{1}bad"), directory.FilterFalseResult, true, directory.FilterFalseResult},
		{"ordered legacy folds exact naming", "cachedOrderedMember", "registryExactName=alice", byteValues("{1}registryExactName=Alice"), directory.FilterTrueResult, true, directory.FilterTrueResult},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: tc.description, Values: tc.values}}}
			got, hasValues, filterResult := checkCachedDNEquality(t, registry, entry, equalityLeaf(tc.description, tc.assertion))
			if got != tc.want || hasValues != tc.hasValues || filterResult != tc.wantFilter {
				t.Fatalf("direct=(%v,%v), filter=%v; want (%v,%v), %v", got, hasValues, filterResult, tc.want, tc.hasValues, tc.wantFilter)
			}
		})
	}
}

func TestEvaluateEqualityCachedDNDescriptions(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	descriptions := []string{
		"member", "MEMBER", "2.5.4.31", " member ",
		"member;lang-en", "member;LANG-EN", "member;lang-en-us", "member;lang-",
		"member;binary;lang-en", "member;lang-en;binary", "member;lang-en;lang-en",
		"member;", " member ; lang-en ; ", "member;unknown", "member;x=y", "member;\xff",
		"cachedMember", "cachedMemberAlias;lang-en", "1.2.3.901;lang-en-us", "cachedMemberGrandchild",
		"cachedExactMember", "cachedOrderedMember", "cachedOrderedChild", "cachedOIDMember",
		"cachedOrphan", "cachedCycleA", "cachedUnknownAttribute", "", ";member", "member\x00",
	}
	for _, requested := range descriptions {
		t.Run(requested, func(t *testing.T) {
			for _, candidate := range descriptions {
				for _, values := range [][][]byte{nil, byteValues("bad", "CN=Alice"), byteValues("{0}cn=Alice")} {
					entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: values}}}
					checkCachedDNEquality(t, registry, entry, equalityLeaf(requested, "cn=alice"))
				}
			}
		})
	}
}

func TestEvaluateEqualityCachedDNFallback(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	for _, tc := range []struct {
		description string
		values      []string
	}{
		{"uniqueMember", []string{"CN=Alice#'01'B", "2.5.4.3=alice#'01'B", "cn=alice#'1'B", "cn=alice", "bad#'01'B", "bad#'10'B", "cn=Alice#'2'B", "cn=alice#'01'b", "cn=alice#''B"}},
		{"cachedOrderedMember", []string{"{0}CN=Alice", "cn=alice", "{1}", "{0}bad", "{bad}cn=alice", "{99999999999999999999999999}cn=x"}},
		{"cachedExactMember", []string{"cn=Alice", "cn=alice", "2.5.4.3=Alice", "not-a-dn"}},
		{"uid", []string{"Alice", "ALICE", ""}},
		{"uidNumber", []string{"42", "+0042", "bad", ""}},
		{"objectClass", []string{"inetOrgPerson", "person", "2.5.6.6", "unknown"}},
		{"jpegPhoto", []string{"photo", ""}},
		{"cachedOrphan", []string{"cn=Alice"}},
		{"cachedCycleA", []string{"cn=Alice"}},
		{"cachedUnknownAttribute", []string{"cn=Alice"}},
	} {
		t.Run(tc.description, func(t *testing.T) {
			for _, assertion := range tc.values {
				for _, stored := range append(singleEqualityValues(byteValues(tc.values...)), nil, [][]byte{}, byteValues(tc.values...)) {
					entry := directory.Entry{Attributes: []directory.Attribute{{Description: tc.description, Values: stored}}}
					checkCachedDNEquality(t, registry, entry, equalityLeaf(tc.description, assertion))
				}
			}
			if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
				t.Fatal("fallback equality populated the DN cache")
			}
		})
	}
}

func TestEvaluateEqualityCachedDNMixedFilters(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	entry := directory.Entry{DN: "registryExactAlias=Alice,dc=example", Attributes: []directory.Attribute{
		{Description: "member", Values: byteValues("bad", "cn=Alice")},
		{Description: "uid", Values: byteValues("ALICE")},
		{Description: "uidNumber", Values: byteValues("42")},
	}}
	for _, child := range []directory.Filter{
		{Kind: directory.FilterPresent, Attribute: "uid"},
		{Kind: directory.FilterApprox, Attribute: "uid", Assertion: []byte("alice")},
		{Kind: directory.FilterSubstrings, Attribute: "uid", Substring: directory.Substring{Initial: []byte("al")}},
		{Kind: directory.FilterGreaterOrEqual, Attribute: "uidNumber", Assertion: []byte("4")},
		{Kind: directory.FilterLessOrEqual, Attribute: "uidNumber", Assertion: []byte("40")},
		{Kind: directory.FilterExtensible, Attribute: "registryExactName", Assertion: []byte("Alice"), MatchingRule: "caseExactMatch", DNAttributes: true},
		{Kind: directory.FilterNot},
	} {
		for _, assertion := range []string{"cn=alice", "cn=bob", "bad"} {
			for _, kind := range []directory.FilterKind{directory.FilterAnd, directory.FilterOr} {
				leaf := equalityLeaf("member", assertion)
				for _, filter := range []directory.Filter{equalityNode(kind, leaf, child), equalityNode(kind, child, leaf)} {
					want, wantErr := filter.EvaluateWith(entry, registry)
					got, gotErr := filter.EvaluateWith(entry, cachedDNEqualityMatcher{registry})
					if got != want || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
						t.Fatalf("tree %+v: cached=(%v,%v), uncached=(%v,%v)", filter, got, gotErr, want, wantErr)
					}
				}
			}
		}
	}
}

func TestEvaluateEqualityCachedDNCacheRouting(t *testing.T) {
	t.Parallel()
	for _, description := range []string{"member", "cachedMemberAlias", "cachedMemberGrandchild", "cachedOIDMember", "cachedOrderedChild"} {
		t.Run(description, func(t *testing.T) {
			registry := cachedDNEqualityRegistry(t)
			const stored, assertion = "CN=Alice", "2.5.4.3=alice"
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: description, Values: byteValues(stored)}}}
			if got, hasValues := registry.EvaluateEquality(entry, description, []byte(assertion)); got != directory.FilterTrueResult || !hasValues {
				t.Fatalf("uncached equality = (%v,%v)", got, hasValues)
			}
			if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
				t.Fatal("EvaluateEquality opted into DN caching")
			}
			checkCachedDNEquality(t, registry, entry, equalityLeaf(description, assertion))
			for _, raw := range []string{stored, assertion} {
				if _, ok := registry.dnCache.entries[raw]; !ok {
					t.Fatalf("equality did not cache %q", raw)
				}
			}
			if len(registry.dnCache.entries) != 2 {
				t.Fatalf("cache contains %d entries, want both exact inputs", len(registry.dnCache.entries))
			}
			generation, retained := registry.dnCache.generation, registry.dnCache.bytes
			if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.910", Names: []string{"cachedUnrelated"}, Superior: "cn"}); err != nil {
				t.Fatal(err)
			}
			registry.EvaluateEquality(entry, description, []byte("cn=Other"))
			if registry.dnCache.generation != generation || registry.dnCache.bytes != retained || len(registry.dnCache.entries) != 2 {
				t.Fatal("EvaluateEquality touched the opt-in cache after a schema mutation")
			}
		})
	}
	t.Run("absent and invalid", func(t *testing.T) {
		registry := cachedDNEqualityRegistry(t)
		checkCachedDNEquality(t, registry, directory.Entry{}, equalityLeaf("member", "cn=Alice"))
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("bad")}}}
		checkCachedDNEquality(t, registry, entry, equalityLeaf("member", "bad"))
		if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
			t.Fatal("absent or failed DN equality retained cache entries")
		}
	})
}

func TestEvaluateEqualityCachedDNMutation(t *testing.T) {
	t.Parallel()
	t.Run("naming schema", func(t *testing.T) {
		registry := cachedDNEqualityRegistry(t)
		if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.911", Names: []string{"cachedNamingChild"}, Superior: registryDNExactOID}); err != nil {
			t.Fatal(err)
		}
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("cachedNamingChild=Alice")}}}
		leaf := equalityLeaf("member", "cachedNamingChild=alice")
		if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != directory.FilterFalseResult {
			t.Fatalf("before superior mutation: %v", got)
		}
		aliasEntry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("registryExactAlias=Alice")}}}
		aliasLeaf := equalityLeaf("member", registryDNExactOID+"=Alice")
		checkCachedDNEquality(t, registry, aliasEntry, aliasLeaf)
		attribute, _ := registry.AttributeType(registryDNExactOID)
		attribute.Names = []string{"cachedRenamedExact", "cachedNewExactAlias"}
		attribute.Equality = "caseIgnoreMatch"
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != directory.FilterTrueResult {
			t.Fatalf("after superior mutation: %v", got)
		}
		if got, _, _ := checkCachedDNEquality(t, registry, aliasEntry, aliasLeaf); got != directory.FilterUndefinedResult {
			t.Fatalf("removed alias survived a warm cache: %v", got)
		}
		aliasEntry.Attributes[0].Values = byteValues("cachedNewExactAlias=alice")
		if got, _, _ := checkCachedDNEquality(t, registry, aliasEntry, aliasLeaf); got != directory.FilterTrueResult {
			t.Fatalf("new alias did not use new matching rule: %v", got)
		}
		entry.Attributes[0].Values = byteValues("cachedLateNaming=Alice")
		leaf = equalityLeaf("member", "cachedLateNaming=Alice")
		if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != directory.FilterUndefinedResult {
			t.Fatalf("unregistered naming type: %v", got)
		}
		if err := registry.ParseAndRegisterAttributeType("( 1.2.3.912 NAME 'cachedLateNaming' SUP cn )"); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != directory.FilterTrueResult {
			t.Fatalf("registration after failed normalization: %v", got)
		}
	})
	t.Run("requested rule and ordering", func(t *testing.T) {
		registry := cachedDNEqualityRegistry(t)
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "cachedMemberGrandchild", Values: byteValues("CN=Alice")}}}
		leaf := equalityLeaf("cachedMemberGrandchild", "cn=alice")
		attribute, _ := registry.AttributeType("cachedMember")
		for _, rule := range []string{"", "caseExactMatch", "2.5.13.1", "uniqueMemberMatch", "distinguishedNameMatch"} {
			attribute.Equality = rule
			if err := registry.UpsertAttributeType(attribute); err != nil {
				t.Fatal(err)
			}
			want := directory.FilterTrueResult
			if rule == "caseExactMatch" {
				want = directory.FilterFalseResult
			}
			if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != want {
				t.Fatalf("inherited rule %q: got %v, want %v", rule, got, want)
			}
		}
		attribute, _ = registry.AttributeType("cachedMemberGrandchild")
		attribute.Extensions = map[string][]string{"X-ORDERED": {"VALUES"}}
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		entry.Attributes[0].Values = byteValues("{1}bad")
		leaf.Assertion = []byte("{1}")
		if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != directory.FilterTrueResult {
			t.Fatalf("ordered flag added after warmup: %v", got)
		}
		attribute.Extensions = nil
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != directory.FilterUndefinedResult {
			t.Fatalf("ordered flag removed: %v", got)
		}
	})
}

func TestEvaluateEqualityCachedDNInputOwnership(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	entry := directory.Entry{DN: "cn=group", Attributes: []directory.Attribute{{Description: "member", Values: byteValues("CN=Alice"), RawNormalized: true}}}
	leaf := equalityLeaf("member", "cn=alice")
	checkCachedDNEquality(t, registry, entry, leaf)
	wantStored := mustNormalizedDN(t, registry, "CN=Alice")
	wantAssertion := mustNormalizedDN(t, registry, "cn=alice")
	copy(entry.Attributes[0].Values[0], "CN=Other")
	copy(leaf.Assertion, "cn=other")
	checkCachedDNEquality(t, registry, entry, leaf)
	if !reflect.DeepEqual(mustCachedDN(t, registry, "CN=Alice"), wantStored) ||
		!reflect.DeepEqual(mustCachedDN(t, registry, "cn=alice"), wantAssertion) {
		t.Fatal("reusing caller buffers corrupted a cached DN")
	}
	leaf.Assertion = []byte("cn=alice")
	if got, _, _ := checkCachedDNEquality(t, registry, entry, leaf); got != directory.FilterFalseResult {
		t.Fatalf("changed entry reused previous equality result: %v", got)
	}
}

func TestEvaluateEqualityCachedDNCacheBounds(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	for _, raw := range []string{
		"cn=" + strings.Repeat("a", maxCachedDNInput),
		strings.Repeat("cn=x,", maxCachedDNDepth) + "cn=x",
	} {
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(raw)}}}
		if got, _, _ := checkCachedDNEquality(t, registry, entry, equalityLeaf("member", raw)); got != directory.FilterTrueResult {
			t.Fatalf("ineligible cache input changed equality: %v", got)
		}
		if len(registry.dnCache.entries) != 0 || registry.dnCache.bytes != 0 {
			t.Fatal("equality retained an oversized or over-depth DN")
		}
	}
	// Exercise eviction through equality, without duplicating the cache's
	// standalone boundary and ownership tests.
	for i := range 2*maxCachedDNs + 1 {
		stored := fmt.Sprintf("cn=stored%d", i)
		assertion := fmt.Sprintf("cn=assertion%d", i)
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(stored)}}}
		got, hasValues := registry.EvaluateEqualityCachedDN(entry, "member", []byte(assertion))
		if got != directory.FilterFalseResult || !hasValues {
			t.Fatalf("distributed equality = (%v,%v)", got, hasValues)
		}
		retained := 0
		for raw, dn := range registry.dnCache.entries {
			retained += estimatedDNCacheBytes(raw, dn)
		}
		if len(registry.dnCache.entries) == 0 || len(registry.dnCache.entries) > maxCachedDNs ||
			retained != registry.dnCache.bytes || retained > maxCachedDNBytes {
			t.Fatalf("equality cache budget: entries=%d, bytes=%d, accounted=%d", len(registry.dnCache.entries), registry.dnCache.bytes, retained)
		}
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("cn=stored0")}}}
	checkCachedDNEquality(t, registry, entry, equalityLeaf("member", "CN=STORED0"))
}

func TestEvaluateEqualityCachedDNConcurrency(t *testing.T) {
	t.Parallel()
	registry := cachedDNEqualityRegistry(t)
	versions := []AttributeType{
		{OID: "1.2.3.913", Names: []string{"cachedConcurrentExact", "cachedConcurrentAlias"}, Equality: "caseExactMatch", Syntax: SyntaxDirectoryString},
		{OID: "1.2.3.913", Names: []string{"cachedConcurrentFold", "cachedConcurrentAlias"}, Equality: "caseIgnoreMatch", Syntax: SyntaxDirectoryString},
	}
	if err := registry.RegisterAttributeType(versions[0]); err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("bad", "cachedConcurrentAlias=Alice+uid=ALICE,dc=EXAMPLE")}}}
	leaf := equalityLeaf("member", "1.2.3.913=Alice+uid=alice,dc=example")
	checkCachedDNEquality(t, registry, entry, leaf)
	var workers sync.WaitGroup
	start := make(chan struct{})
	failures := make(chan error, 9)
	for worker := range 8 {
		workers.Go(func() {
			<-start
			for i := range 100 {
				// Both generations match. Mixing their canonical RDN names in
				// the assertion and stored value would produce a false result.
				got, hasValues := registry.EvaluateEqualityCachedDN(entry, leaf.Attribute, leaf.Assertion)
				if got != directory.FilterTrueResult || !hasValues {
					failures <- fmt.Errorf("worker %d mixed generations: (%v,%v)", worker, got, hasValues)
					return
				}
				if got, err := leaf.EvaluateWith(entry, cachedDNEqualityMatcher{registry}); err != nil || got != directory.FilterTrueResult {
					failures <- fmt.Errorf("worker %d filter: (%v,%v)", worker, got, err)
					return
				}
				other := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(fmt.Sprintf("cn=worker%d-%d", worker, i))}}}
				if got, hasValues := registry.EvaluateEqualityCachedDN(other, "member", []byte("cn=missing")); got != directory.FilterFalseResult || !hasValues {
					failures <- fmt.Errorf("worker %d distributed miss: (%v,%v)", worker, got, hasValues)
					return
				}
			}
		})
	}
	workers.Go(func() {
		<-start
		for i := range 80 {
			if err := registry.UpsertAttributeType(versions[i%len(versions)]); err != nil {
				failures <- err
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
	checkCachedDNEquality(t, registry, entry, leaf)
	retained := 0
	for raw, dn := range registry.dnCache.entries {
		retained += estimatedDNCacheBytes(raw, dn)
	}
	if registry.dnCache.generation != registry.preparedNames.generation || registry.dnCache.bytes != retained ||
		len(registry.dnCache.entries) > maxCachedDNs || retained > maxCachedDNBytes {
		t.Fatal("concurrent equality corrupted cache generation or accounting")
	}
}
