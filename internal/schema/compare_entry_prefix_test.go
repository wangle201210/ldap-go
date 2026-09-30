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

const dnPrefixTestBudget = 256 << 10

func dnPrefixTestEntry(count int, complex bool) directory.Entry {
	values := make([][]byte, count)
	for i := range values {
		if complex {
			values[i] = fmt.Appendf(nil, `uid=User%05d+cn=Smith\, User%05d,ou=People,dc=example`, i, i)
		} else {
			values[i] = fmt.Appendf(nil, "cn=User%05d,ou=People,dc=example", i)
		}
	}
	return directory.Entry{DN: "cn=group,dc=example", Attributes: []directory.Attribute{{Description: "member", Values: values}}}
}

func dnPrefixTestBytes(prefix *DNComparisonPrefix) int {
	if prefix == nil {
		return 0
	}
	return prefix.RetainedBytes()
}

func checkCompareEntryAttributeWithDNPrefix(t testing.TB, registry *Registry, entry directory.Entry, description string, assertion []byte, previous *DNComparisonPrefix) *DNComparisonPrefix {
	t.Helper()
	before := entry
	before.Attributes = slices.Clone(entry.Attributes)
	for i := range before.Attributes {
		before.Attributes[i].Values = slices.Clone(entry.Attributes[i].Values)
		for j, value := range before.Attributes[i].Values {
			before.Attributes[i].Values[j] = bytes.Clone(value)
		}
	}
	assertionBefore := bytes.Clone(assertion)
	previousBytes := dnPrefixTestBytes(previous)
	wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, description, assertion)
	present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, description, assertion, previous)
	if present != wantPresent || matched != wantMatched || !reflect.DeepEqual(err, wantErr) {
		t.Fatalf("%s=%q: prefix=(%v,%v,%T: %v), oracle=(%v,%v,%T: %v)",
			description, assertion, present, matched, err, err, wantPresent, wantMatched, wantErr, wantErr)
	}
	if !reflect.DeepEqual(entry, before) || !reflect.DeepEqual(assertion, assertionBefore) {
		t.Fatal("prefix comparison mutated caller-owned input")
	}
	if dnPrefixTestBytes(previous) != previousBytes {
		t.Fatal("comparison changed the previous token's retained bytes")
	}
	if retained := dnPrefixTestBytes(next); retained < 0 || retained > dnPrefixTestBudget || next != nil && retained == 0 {
		t.Fatalf("invalid per-token retained bytes: %d", retained)
	}
	return next
}

// Fill at most one successful value per call through the public API. Equality
// of the retained-byte count detects exhaustion, an early match, or the budget
// limit without inspecting token fields.
func warmDNPrefixForTest(t testing.TB, registry *Registry, entry directory.Entry, description string, assertion []byte) *DNComparisonPrefix {
	t.Helper()
	wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, description, assertion)
	if wantErr != nil {
		t.Fatalf("invalid warm fixture: %v", wantErr)
	}
	var prefix *DNComparisonPrefix
	for range 4096 + 2 {
		before := dnPrefixTestBytes(prefix)
		present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, description, assertion, prefix)
		if present != wantPresent || matched != wantMatched || err != nil {
			t.Fatalf("warm fixture: (%v,%v,%v), want (%v,%v,nil)", present, matched, err, wantPresent, wantMatched)
		}
		if dnPrefixTestBytes(prefix) != before {
			t.Fatal("warming mutated an older token")
		}
		retained := dnPrefixTestBytes(next)
		if retained < 0 || retained > dnPrefixTestBudget {
			t.Fatalf("warming exceeded the per-token budget: %d", retained)
		}
		prefix = next
		if retained == before {
			return prefix
		}
	}
	t.Fatal("prefix did not stop extending")
	return nil
}

func TestCompareEntryAttributeWithDNPrefixParity(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, complex := range []bool{false, true} {
		for _, count := range []int{10, 31, 32, 1000, 4096, 4097} {
			entry := dnPrefixTestEntry(count, complex)
			for _, position := range []int{0, count - 1, -1} {
				t.Run(fmt.Sprintf("complex=%t/values=%d/position=%d", complex, count, position), func(t *testing.T) {
					assertion := []byte("cn=missing,ou=People,dc=example")
					if position >= 0 {
						assertion = bytes.Clone(entry.Attributes[0].Values[position])
					}
					cold := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, nil)
					if count < 32 && cold != nil || count >= 32 && cold == nil {
						t.Fatalf("unexpected eligibility for %d values: token=%v", count, cold != nil)
					}
					warm := warmDNPrefixForTest(t, registry, entry, "member", assertion)
					checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, warm)
					checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte("bad-dn"), warm)
				})
			}
		}
	}
}

func TestCompareEntryAttributeWithDNPrefixDNFixtures(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	base := dnPrefixTestEntry(32, false)
	warm := warmDNPrefixForTest(t, registry, base, "member", []byte("cn=missing"))
	for _, tc := range simpleDNComparisonCases() {
		for _, position := range []int{0, 1, 2, 7, 8, 31} {
			t.Run(fmt.Sprintf("%s/position=%d", tc.name, position), func(t *testing.T) {
				entry := base.Clone()
				entry.Attributes[0].RawNormalized = true
				entry.Attributes[0].Values[position] = []byte(tc.value)
				assertion := []byte(tc.assertion)
				cold := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, nil)
				checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, cold)
				checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, warm)
			})
		}
	}
}

func TestCompareEntryAttributeWithDNPrefixFallback(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.860", Names: []string{"prefixChild"}, Superior: "member"},
		{OID: "1.2.3.861", Names: []string{"prefixOID"}, Equality: "2.5.13.1", Syntax: SyntaxDistinguishedName},
		{OID: "1.2.3.862", Names: []string{"prefixOrdered"}, Superior: "member", Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	base := dnPrefixTestEntry(32, false)
	warm := warmDNPrefixForTest(t, registry, base, "member", []byte("cn=missing"))
	values := base.Attributes[0].Values
	for _, tc := range []struct {
		name, requested, assertion string
		attributes                 []directory.Attribute
	}{
		{"absent", "member", "bad-dn", nil},
		{"unselected", "member", "bad-dn", []directory.Attribute{{Description: "cn", Values: values}}},
		{"empty nil", "member", "bad-dn", []directory.Attribute{{Description: "member"}}},
		{"empty slice", "member", "bad-dn", []directory.Attribute{{Description: "member", Values: [][]byte{}}}},
		{"small", "member", string(values[0]), []directory.Attribute{{Description: "member", Values: values[:31]}}},
		{"name to OID", "member", string(values[0]), []directory.Attribute{{Description: "2.5.4.31", Values: values}}},
		{"OID to name", "2.5.4.31", string(values[0]), []directory.Attribute{{Description: "member", Values: values}}},
		{"case differs", "MEMBER", string(values[0]), []directory.Attribute{{Description: "member", Values: values}}},
		{"subtype", "member", string(values[0]), []directory.Attribute{{Description: "prefixChild", Values: values}}},
		{"option on stored", "member", string(values[0]), []directory.Attribute{{Description: "member;lang-en", Values: values}}},
		{"option on both", "member;lang-en", string(values[0]), []directory.Attribute{{Description: "member;lang-en", Values: values}}},
		{"option prefix", "member;lang-", string(values[0]), []directory.Attribute{{Description: "member;lang-en", Values: values}}},
		{"option mismatch", "member;lang-en", "bad-dn", []directory.Attribute{{Description: "member;lang-fr", Values: values}}},
		{"two selected", "member", string(values[0]), []directory.Attribute{{Description: "member", Values: values}, {Description: "member", Values: values}}},
		{"empty selected second", "member", string(values[0]), []directory.Attribute{{Description: "member", Values: values}, {Description: "member"}}},
		{"empty selected first", "member", string(values[0]), []directory.Attribute{{Description: "member"}, {Description: "member", Values: values}}},
		{"second selected option", "member", string(values[0]), []directory.Attribute{{Description: "member", Values: values}, {Description: "member;lang-en", Values: values}}},
		{"split below threshold", "member", string(values[31]), []directory.Attribute{{Description: "member", Values: values[:16]}, {Description: "member", Values: values[16:]}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := directory.Entry{DN: base.DN, Attributes: tc.attributes}
			for _, previous := range []*DNComparisonPrefix{nil, warm} {
				if next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, tc.requested, []byte(tc.assertion), previous); next != nil {
					t.Fatal("fallback returned a token")
				}
			}
		})
	}
	for _, description := range []string{"prefixOrdered", "uid", "uniqueMember", "eqExact", "eqNoRule", "eqUnknownRule", "eqOrphan", "eqCycleA", "prefixUnknown"} {
		t.Run(description, func(t *testing.T) {
			entry := base.Clone()
			entry.Attributes[0].Description = description
			if description == "prefixOrdered" {
				entry.Attributes[0].Values[0] = []byte("{1}bad-dn")
			}
			for _, assertion := range []string{string(values[0]), "{1}", "bad-dn"} {
				for _, previous := range []*DNComparisonPrefix{nil, warm} {
					if next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, description, []byte(assertion), previous); next != nil {
						t.Fatal("non-DN, ordered, or invalid rule returned a token")
					}
				}
			}
		})
	}
	for _, description := range []string{"member", "prefixChild", "prefixOID", "2.5.4.31", "MEMBER"} {
		t.Run("eligible/"+description, func(t *testing.T) {
			entry := base.Clone()
			entry.Attributes[0].Description = description
			entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "cn", Values: byteValues("unselected")})
			if next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, description, values[0], nil); next == nil {
				t.Fatal("one exact selected DN attribute did not return a token")
			}
		})
	}
}

func TestCompareEntryAttributeWithDNPrefixStopsInOrder(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	base := dnPrefixTestEntry(32, false)
	warm := warmDNPrefixForTest(t, registry, base, "member", []byte("cn=missing"))
	for _, position := range []int{0, 1, 2, 7, 8, 30} {
		for _, matchFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("position=%d/matchFirst=%t", position, matchFirst), func(t *testing.T) {
				entry := base.Clone()
				pair := byteValues("bad-dn", "cn=target")
				if matchFirst {
					slices.Reverse(pair)
				}
				copy(entry.Attributes[0].Values[position:], pair)
				for _, previous := range []*DNComparisonPrefix{nil, warm} {
					checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte("cn=target"), previous)
				}
			})
		}
	}
	entry := base.Clone()
	entry.Attributes[0].Values[0] = []byte("cn=target")
	for i := 1; i < len(entry.Attributes[0].Values); i++ {
		entry.Attributes[0].Values[i] = []byte("bad-dn")
	}
	one := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte("cn=target"), nil)
	reference := base.Clone()
	reference.Attributes[0].Values[0] = []byte("cn=target")
	first := checkCompareEntryAttributeWithDNPrefix(t, registry, reference, "member", []byte("cn=target"), nil)
	if dnPrefixTestBytes(one) != dnPrefixTestBytes(first) {
		t.Fatal("values after a match changed the retained prefix")
	}
	// The previously unvisited error must be observed when the assertion changes.
	failed := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte("cn=missing"), one)
	entry.Attributes[0].Values[1] = []byte("cn=missing")
	checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte("cn=missing"), failed)

	for _, value := range [][]byte{nil, {}} {
		entry := base.Clone()
		entry.Attributes[0].Values[0] = value
		prefix := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", nil, nil)
		checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte{}, prefix)
		checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte("bad-dn"), prefix)
	}
}

func TestCompareEntryAttributeWithDNPrefixOwnershipAndMutation(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	entry := dnPrefixTestEntry(32, false)
	// Short slices of a large reusable buffer must be owned as short strings.
	backing := make([]byte, 1<<20)
	offset := 0
	for i, raw := range entry.Attributes[0].Values {
		copy(backing[offset:], raw)
		entry.Attributes[0].Values[i] = backing[offset : offset+len(raw)]
		offset += len(raw)
	}
	original := entry.Clone()
	missing := []byte("cn=missing")
	prefix := warmDNPrefixForTest(t, registry, entry, "member", missing)
	owned := warmDNPrefixForTest(t, registry, original, "member", missing)
	if dnPrefixTestBytes(prefix) != dnPrefixTestBytes(owned) {
		t.Fatal("retention depends on input buffer capacity")
	}
	for _, position := range []int{0, 1, 2, 7, 8, 31} {
		copy(entry.Attributes[0].Values[position][3:7], "Else")
		for _, assertion := range [][]byte{original.Attributes[0].Values[position], entry.Attributes[0].Values[position], missing} {
			checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, prefix)
		}
	}
	assertion := bytes.Clone(original.Attributes[0].Values[0])
	checkCompareEntryAttributeWithDNPrefix(t, registry, original, "member", assertion, prefix)
	copy(assertion[3:7], "Else")
	checkCompareEntryAttributeWithDNPrefix(t, registry, original, "member", assertion, prefix)
	checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, prefix)
	checkCompareEntryAttributeWithDNPrefix(t, registry, original, "member", original.Attributes[0].Values[31], prefix)

	reordered := original.Clone()
	slices.Reverse(reordered.Attributes[0].Values)
	reordered.Attributes[0].Values[0] = []byte("bad-dn")
	checkCompareEntryAttributeWithDNPrefix(t, registry, reordered, "member", original.Attributes[0].Values[0], prefix)
	reordered.Attributes[0].Values[0] = bytes.Clone(original.Attributes[0].Values[31])
	checkCompareEntryAttributeWithDNPrefix(t, registry, reordered, "member", original.Attributes[0].Values[0], prefix)
	deleted := original.Clone()
	deleted.Attributes[0].Values = deleted.Attributes[0].Values[:31]
	if next := checkCompareEntryAttributeWithDNPrefix(t, registry, deleted, "member", missing, prefix); next != nil {
		t.Fatal("shrinking below the threshold did not discard the token")
	}
	changedDescription := original.Clone()
	changedDescription.Attributes[0].Description = "manager"
	next := checkCompareEntryAttributeWithDNPrefix(t, registry, changedDescription, "manager", missing, prefix)
	fresh := checkCompareEntryAttributeWithDNPrefix(t, registry, changedDescription, "manager", missing, nil)
	if dnPrefixTestBytes(next) != dnPrefixTestBytes(fresh) {
		t.Fatal("token from a different description was reused")
	}
}

func TestCompareEntryAttributeWithDNPrefixRegistryIdentityAndGeneration(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	entry := dnPrefixTestEntry(32, false)
	entry.Attributes[0].Values[0] = []byte("1.2.3.802=ALICE")
	assertion := []byte("1.2.3.802=alice")
	prefix := warmDNPrefixForTest(t, registry, entry, "member", assertion)
	clone := registry.Clone()
	for _, other := range []*Registry{clone, equalityEvaluationRegistry(t)} {
		next := checkCompareEntryAttributeWithDNPrefix(t, other, entry, "member", assertion, prefix)
		fresh := checkCompareEntryAttributeWithDNPrefix(t, other, entry, "member", assertion, nil)
		if dnPrefixTestBytes(next) != dnPrefixTestBytes(fresh) {
			t.Fatal("another registry reused the source registry's full prefix")
		}
	}
	attribute, _ := registry.AttributeType("eqExact")
	for _, rule := range []string{"caseIgnoreMatch", "caseExactMatch", "caseIgnoreMatch"} {
		attribute.Equality = rule
		attribute.Names = []string{"prefixRenamedExact"}
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, prefix)
		fresh := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, nil)
		if dnPrefixTestBytes(next) != dnPrefixTestBytes(fresh) {
			t.Fatal("schema mutation reused the previous generation's full prefix")
		}
		prefix = next
	}
	// Give two independently mutable clones the same mutation history length,
	// but different naming rules. Identity must distinguish their tokens.
	left, right := clone.Clone(), clone.Clone()
	for i, target := range []*Registry{left, right} {
		attribute, _ := target.AttributeType("eqExact")
		attribute.Equality = []string{"caseExactMatch", "caseIgnoreMatch"}[i]
		if err := target.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	leftToken := warmDNPrefixForTest(t, left, entry, "member", assertion)
	rightToken := checkCompareEntryAttributeWithDNPrefix(t, right, entry, "member", assertion, leftToken)
	checkCompareEntryAttributeWithDNPrefix(t, left, entry, "member", assertion, rightToken)
	checkCompareEntryAttributeWithDNPrefix(t, clone, entry, "member", assertion, leftToken)

	member, _ := registry.AttributeType("member")
	member.Equality = "caseExactMatch"
	if err := registry.UpsertAttributeType(member); err != nil {
		t.Fatal(err)
	}
	if next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, prefix); next != nil {
		t.Fatal("changing the selected attribute's equality rule did not fall back")
	}
}

func TestCompareEntryAttributeWithDNPrefixSingleValueExtension(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	entry := dnPrefixTestEntry(40, false)
	missing := []byte("cn=missing")
	var prefix *DNComparisonPrefix
	var history []*DNComparisonPrefix
	var retained []int
	for pass := range entry.Attributes[0].Values {
		previousBytes := dnPrefixTestBytes(prefix)
		next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, prefix)
		// An early match after exactly one new value must retain the same
		// prefix as a complete scan that continues through the simple DN path.
		stopAtOne := entry.Attributes[0].Values[pass]
		reference := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", stopAtOne, prefix)
		if next == nil || dnPrefixTestBytes(next) <= previousBytes || dnPrefixTestBytes(next) != dnPrefixTestBytes(reference) {
			t.Fatalf("pass %d did not extend by the same single visited value: before=%d, scan=%d, early=%d",
				pass, previousBytes, dnPrefixTestBytes(next), dnPrefixTestBytes(reference))
		}
		if next == prefix {
			t.Fatal("extending a prefix reused the mutable token object")
		}
		prefix = next
		history = append(history, prefix)
		retained = append(retained, dnPrefixTestBytes(prefix))
	}
	for range 3 {
		next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, prefix)
		if dnPrefixTestBytes(next) != dnPrefixTestBytes(prefix) {
			t.Fatal("exhausted prefix continued to grow")
		}
	}
	for i, old := range history {
		if dnPrefixTestBytes(old) != retained[i] {
			t.Fatalf("old token %d changed after a later extension", i)
		}
		branch := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, old)
		if dnPrefixTestBytes(branch) != retained[min(i+1, len(retained)-1)] {
			t.Fatalf("old token %d no longer creates the same independent branch", i)
		}
	}
	for _, assertion := range []string{"cn=another-miss", "cn=" + strings.Repeat("z", 2048)} {
		next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", []byte(assertion), nil)
		if dnPrefixTestBytes(next) != retained[0] {
			t.Fatal("token retention depends on the assertion")
		}
	}
}

func TestCompareEntryAttributeWithDNPrefixLimits(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	missing := []byte("cn=missing")
	t.Run("budget", func(t *testing.T) {
		entry := dnPrefixTestEntry(4097, false)
		for i := range entry.Attributes[0].Values {
			entry.Attributes[0].Values[i] = fmt.Appendf(nil, "cn=%04d%s", i, strings.Repeat("x", 1017))
		}
		// Every raw DN is exactly 1024 bytes, so even the raw strings alone
		// exceed the per-token budget before all input values can be retained.
		prefix := warmDNPrefixForTest(t, registry, entry, "member", missing)
		if prefix == nil || dnPrefixTestBytes(prefix) <= 1024 || dnPrefixTestBytes(prefix) > dnPrefixTestBudget {
			t.Fatalf("invalid budget-limited token: %d", dnPrefixTestBytes(prefix))
		}
		for range 3 {
			next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, prefix)
			if dnPrefixTestBytes(next) != dnPrefixTestBytes(prefix) {
				t.Fatal("budget-limited prefix continued to expand")
			}
		}
		checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", entry.Attributes[0].Values[4096], prefix)
		entry.Attributes[0].Values[4095] = []byte("bad-dn")
		checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", entry.Attributes[0].Values[4096], prefix)
	})
	t.Run("raw length boundary", func(t *testing.T) {
		entry := dnPrefixTestEntry(32, false)
		entry.Attributes[0].Values[0] = []byte("cn=" + strings.Repeat("x", 1021))
		if prefix := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, nil); prefix == nil {
			t.Fatal("1024-byte raw DN was not retained")
		}
		entry.Attributes[0].Values[0] = append(entry.Attributes[0].Values[0], 'x')
		if prefix := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, nil); prefix != nil {
			t.Fatal("prefix extended past a 1025-byte first value")
		}
	})
	t.Run("long value stops extension", func(t *testing.T) {
		entry := dnPrefixTestEntry(32, false)
		entry.Attributes[0].Values[1] = []byte("cn=" + strings.Repeat("x", 1022))
		prefix := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, nil)
		if prefix == nil {
			t.Fatal("the single value preceding the long DN was not retained")
		}
		for range 3 {
			next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, prefix)
			if dnPrefixTestBytes(next) != dnPrefixTestBytes(prefix) {
				t.Fatal("prefix extended past the long raw DN")
			}
		}
		checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", entry.Attributes[0].Values[31], prefix)
		entry.Attributes[0].Values[1] = []byte("cn=repaired")
		if next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", missing, prefix); dnPrefixTestBytes(next) <= dnPrefixTestBytes(prefix) {
			t.Fatal("prefix did not resume after replacing the oversized value")
		}
	})
}

func TestCompareEntryAttributeWithDNPrefixConcurrent(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	base := dnPrefixTestEntry(64, true)
	missing := []byte("cn=missing")
	shared := checkCompareEntryAttributeWithDNPrefix(t, registry, base, "member", missing, nil)
	retained := dnPrefixTestBytes(shared)
	reference := checkCompareEntryAttributeWithDNPrefix(t, registry, base, "member", missing, shared)
	var workers sync.WaitGroup
	failures := make(chan error, 16)
	for worker := range 16 {
		entry := base.Clone()
		if worker%2 != 0 {
			entry.Attributes[0].Values[0] = fmt.Appendf(nil, "cn=worker%d", worker)
		}
		workers.Go(func() {
			prefix := shared
			for round := range 24 {
				assertion := missing
				if round%3 == 0 {
					assertion = entry.Attributes[0].Values[0]
				} else if round%3 == 1 {
					assertion = entry.Attributes[0].Values[63]
				}
				present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, "member", assertion, prefix)
				if !present || matched != (round%3 != 2) || err != nil || next == nil || dnPrefixTestBytes(next) > dnPrefixTestBudget || dnPrefixTestBytes(shared) != retained {
					failures <- fmt.Errorf("worker %d round %d: (%v,%v,%v), retained=%d shared=%d", worker, round, present, matched, err, dnPrefixTestBytes(next), dnPrefixTestBytes(shared))
					return
				}
				prefix = next
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	branch := checkCompareEntryAttributeWithDNPrefix(t, registry, base, "member", missing, shared)
	if dnPrefixTestBytes(branch) != dnPrefixTestBytes(reference) {
		t.Fatal("concurrent branches changed the original shared prefix")
	}
}
