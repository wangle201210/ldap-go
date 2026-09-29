package schema

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func simpleDNTailChecker(t *testing.T, registry *Registry, assertion string) func([]byte, bool) {
	t.Helper()
	normalized, err := registry.NormalizeEqualityAssertion("member", []byte(assertion))
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.RLock()
	plan := registry.prepareSimpleDNComparisonLocked(normalized)
	registry.mu.RUnlock()
	return func(value []byte, wantHandled bool) {
		t.Helper()
		before := bytes.Clone(value)
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: [][]byte{value}}}}
		_, want, wantErr := originalCompareEntryAttribute(registry, entry, "member", []byte(assertion))
		registry.mu.RLock()
		matched, handled := plan.match(registry, value)
		registry.mu.RUnlock()
		if handled != wantHandled || handled && (wantErr != nil || matched != want) {
			t.Fatalf("%q: match=(%v,%v), want handled=%v, oracle=(%v,%v)", value, matched, handled, wantHandled, want, wantErr)
		}
		if !bytes.Equal(value, before) {
			t.Fatal("tail comparison mutated source")
		}
	}
}

func checkSimpleDNTailSequence(t *testing.T, registry *Registry, assertion string, values []string, handled []bool) {
	t.Helper()
	check := simpleDNTailChecker(t, registry, assertion)
	// Force assertion preparation before the sequence starts warming the tail.
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("cn=first-miss")}}}
	for i, value := range values {
		check([]byte(value), handled[i])
		entry.Attributes[0].Values = append(entry.Attributes[0].Values, []byte(value))
		checkCompareEntryAttribute(t, registry, entry, "member", []byte(assertion))
	}
}

func TestSimpleDNTailSequences(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	depth8 := strings.Repeat("ou=people,", 6) + "dc=example"
	for _, tc := range []struct {
		name, assertion string
		values          []string
		handled         []bool
	}{
		{"negative leaf true tail", "cn=alice,dc=example", []string{"cn=bob,dc=example", "cn=ALICE,dc=example"}, []bool{true, true}},
		{"negative leaf false tail", "cn=alice,dc=example", []string{"cn=bob,dc=other", "cn=alice,dc=other", "cn=alice,dc=example"}, []bool{true, true, true}},
		{"tail changes", "cn=alice,dc=example", []string{"cn=bob,dc=example", "cn=alice,dc=other", "cn=bob,dc=example", "cn=alice,dc=example"}, []bool{true, true, true, true}},
		{"case aliases", "uid=alice,dc=example", []string{"uid=bob,DC=EXAMPLE", "USERID=BOB,domainComponent=EXAMPLE", "USERID=ALICE,domainComponent=EXAMPLE"}, []bool{true, true, true}},
		{"OID aliases", "cn=alice,dc=example", []string{"cn=bob,0.9.2342.19200300.100.1.25=EXAMPLE", "2.5.4.3=ALICE,0.9.2342.19200300.100.1.25=EXAMPLE"}, []bool{true, true}},
		{"exact leaf", "eqExact=Alice,dc=example", []string{"eqExact=alice,dc=example", "eqExact=ALICE,dc=example", "eqExact=Alice,dc=example"}, []bool{true, true, true}},
		{"exact tail", "cn=alice,eqExact=Example", []string{"cn=bob,eqExact=example", "cn=alice,eqExact=example", "cn=alice,eqExact=Example"}, []bool{true, true, true}},
		{"depth changes", "cn=alice,dc=example", []string{"cn=bob,dc=example", "cn=alice", "cn=alice,ou=people,dc=example", "cn=alice,dc=example"}, []bool{true, false, false, true}},
		{"single RDN", "cn=alice", []string{"cn=bob", "cn=ALICE"}, []bool{true, true}},
		{"depth eight", "cn=alice," + depth8, []string{"cn=bob," + depth8, "cn=ALICE," + depth8}, []bool{true, true}},
		{"depth nine", "cn=alice,ou=extra," + depth8, []string{"cn=bob,ou=extra," + depth8, "cn=alice,ou=extra," + depth8}, []bool{false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkSimpleDNTailSequence(t, registry, tc.assertion, tc.values, tc.handled)
		})
	}
}

func TestSimpleDNTailFallback(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, leaf := range []string{
		"r12Unknown=x", "eqNoRule=x", "eqUnknownRule=x", "eqCycleA=x", "eqOrphan=x", "uidNumber=bad", "userPassword=x", "uid=alice",
		"broken", "cn=", "cn= ALICE ", `cn=\61lice`, `cn=\`, "cn=alice+uid=alice", "cn=\xff", "cn;lang-en=alice",
	} {
		for _, tail := range []string{"dc=example", "dc=other"} {
			t.Run(leaf+"/"+tail, func(t *testing.T) {
				checkSimpleDNTailSequence(t, registry, "cn=alice,dc=example",
					[]string{"cn=bob," + tail, leaf + "," + tail, leaf + "," + tail, "cn=alice,dc=example"}, []bool{true, false, false, true})
			})
		}
	}
	for _, tail := range []string{
		"ou=other,r12Unknown=x", "ou=other,eqNoRule=x", "ou=other,eqUnknownRule=x", "ou=other,eqCycleA=x", "ou=other,eqOrphan=x",
		"ou=other,uidNumber=bad", "ou=other,broken", "ou=people,dc=example,", `ou=people,dc=\`, "ou=people,dc=x+domainComponent=y",
	} {
		t.Run(tail, func(t *testing.T) {
			checkSimpleDNTailSequence(t, registry, "cn=alice,ou=people,dc=example",
				[]string{"cn=bob," + tail, "cn=alice," + tail, "cn=alice,ou=people,dc=example"}, []bool{false, false, true})
		})
	}
}

func TestSimpleDNTailOwnsSource(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	assertion := "cn=alice,dc=example"
	check := simpleDNTailChecker(t, registry, assertion)
	source := []byte(assertion)
	_, tail, _ := bytes.Cut(source, []byte(","))
	for _, tc := range []struct {
		tail    string
		handled bool
	}{
		{"dc=example", true}, {"dc=changed", true}, {"xx=changed", false},
		{"dc=example", true}, {`dc=exampl\`, false}, {"dc=example", true},
	} {
		copy(tail, tc.tail)
		check(source, tc.handled)
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: append(byteValues("cn=first-miss", "cn=bob,dc=example"), source)}}}
		checkCompareEntryAttribute(t, registry, entry, "member", []byte(assertion))
	}
}

func TestSimpleDNTailBoundaries(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, size := range []int{511, 512, 513, 1024} {
		tail := "dc=" + strings.Repeat("a", size-3)
		checkSimpleDNTailSequence(t, registry, "cn=alice,"+tail,
			[]string{"cn=bob," + tail, "cn=alice," + tail + "b", "cn=bob," + tail, "cn=ALICE," + tail}, []bool{true, true, true, true})
		check := simpleDNTailChecker(t, registry, "cn=alice,"+tail)
		source := []byte("cn=alice," + tail)
		check(source, true)
		source[len(source)-1] = 'b'
		check(source, true)
		source[len(source)-1] = 'a'
		check(source, true)
	}
}

func TestSimpleDNTailPlanIsolation(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	first := simpleDNTailChecker(t, registry, "cn=alice,dc=example")
	second := simpleDNTailChecker(t, registry, "cn=alice,dc=other")
	for range 2 {
		first([]byte("cn=bob,dc=example"), true)
		second([]byte("cn=alice,dc=example"), true)
		first([]byte("cn=ALICE,dc=example"), true)
		second([]byte("cn=ALICE,dc=other"), true)
	}
}

func FuzzCompareEntryAttributeTailReuse(f *testing.F) {
	registry := equalityEvaluationRegistry(f)
	for _, candidate := range []string{
		"uid=target,ou=people,dc=example", "USERID=TARGET,ou=people,dc=example", "uid=other,ou=people,dc=example",
		"uid=target,OU=PEOPLE,domainComponent=EXAMPLE", "uid=target,ou=other,dc=example", "uid=target",
		"r12Unknown=x,ou=people,dc=example", "uid=target,ou=people,r12Unknown=x", "eqCycleA=x,ou=people,dc=example",
		"broken,ou=people,dc=example", `uid=\74arget,ou=people,dc=example`, "uid=target,ou=people,dc=example,",
	} {
		f.Add("uid=warm0,ou=people,dc=example", "uid=warm1,ou=people,dc=example", candidate, "uid=target,ou=people,dc=example")
	}
	f.Fuzz(func(t *testing.T, first, second, candidate, assertion string) {
		if len(first)+len(second)+len(candidate)+len(assertion) > 4096 {
			t.Skip()
		}
		// The second miss fills the tail; only the third value can reuse it.
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(first, second, candidate)}}}
		checkCompareEntryAttribute(t, registry, entry, "member", []byte(assertion))
	})
}
