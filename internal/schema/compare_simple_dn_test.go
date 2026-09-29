package schema

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type simpleDNComparisonCase struct {
	name, assertion, value string
	matched, handled       bool
}

func simpleDNComparisonCases() []simpleDNComparisonCase {
	depth8 := "cn=alice," + strings.Repeat("ou=people,", 6) + "dc=example"
	return []simpleDNComparisonCase{
		{"canonical", "cn=alice,dc=example", "cn=alice,dc=example", true, true},
		{"ASCII fold", "CN=ALICE,DC=EXAMPLE", "cn=Alice,dc=Example", true, true},
		{"alias", "uid=alice,dc=example", "USERID=ALICE,domainComponent=EXAMPLE", true, true},
		{"OID", "cn=alice,dc=example", "2.5.4.3=ALICE,0.9.2342.19200300.100.1.25=EXAMPLE", true, true},
		{"inherited alias", "eqChild=alice", "eqAlias=ALICE", true, true},
		{"rule OID", "eqOIDRule=alice", "1.2.3.812=ALICE", true, true},
		{"exact same", "eqExact=Alice", "1.2.3.802=Alice", true, true},
		{"exact different", "eqExact=Alice", "eqExact=alice", false, true},
		{"IA5 exact same", "homeDirectory=Alice", "HOMEDIRECTORY=Alice", true, true},
		{"IA5 exact different", "homeDirectory=Alice", "homeDirectory=alice", false, true},
		{"mixed rules", "eqExact=Alice,dc=example", "eqExact=Alice,DC=EXAMPLE", true, true},
		{"punctuation", "uid=a-b_c.d9", "userid=A-B_C.D9", true, true},
		{"first value mismatch", "cn=alice,dc=example", "cn=bob,dc=example", false, true},
		{"last value mismatch", "cn=alice,dc=example", "cn=alice,dc=other", false, true},
		{"value length mismatch", "cn=alice", "cn=alicex", false, true},
		{"different type", "cn=alice", "uid=alice", false, false},
		{"subtype is not same type", "uid=alice", "eqChild=alice", false, false},
		{"shorter shape", "cn=alice,dc=example", "cn=alice", false, false},
		{"longer shape", "cn=alice", "cn=alice,dc=example", false, false},
		{"empty DN", "", "", false, false},
		{"empty stored", "cn=alice", "", false, false},
		{"empty AVA", "cn=alice", "cn=", false, false},
		{"nonASCII stored", "cn=k", "cn=\u212a", false, false},
		{"nonASCII assertion", "cn=J\u00f6rg", "cn=j\u00f6rg", false, false},
		{"spaces", "cn=alice", "cn= ALICE ", false, false},
		{"escaped stored", "cn=alice", `cn=\61lice`, false, false},
		{"escaped assertion normalizes simple", `cn=\61lice`, "cn=ALICE", true, true},
		{"escaped comma", `cn=a\,b`, `cn=A\,B`, false, false},
		{"multiAVA stored", "cn=alice,dc=example", "cn=alice+uid=alice,dc=example", false, false},
		{"multiAVA assertion", "uid=alice+cn=alice", "cn=ALICE+uid=ALICE", false, false},
		{"integer rule", "uidNumber=42", "uidNumber=42", false, false},
		{"octet rule", "userPassword=Alice", "userPassword=Alice", false, false},
		{"depth eight", depth8, strings.ToUpper(depth8), true, true},
		{"depth nine", "ou=extra," + depth8, "ou=extra," + depth8, false, false},
		{"depth eight mismatch", depth8, strings.Replace(depth8, "alice", "bob", 1), false, true},
		{"mismatch then missing equals", "cn=alice,dc=example", "cn=bob,broken", false, false},
		{"mismatch then trailing comma", "cn=alice,dc=example", "cn=bob,dc=example,", false, false},
		{"mismatch then escape", "cn=alice,dc=example", `cn=bob,dc=\`, false, false},
		{"mismatch then unknown type", "cn=alice,dc=example", "cn=bob,r10Unknown=x", false, false},
		{"length mismatch then unknown type", "cn=alice,dc=example", "cn=x,r10Unknown=x", false, false},
		{"mismatch then no rule", "cn=alice,dc=example", "cn=bob,eqNoRule=x", false, false},
		{"mismatch then unknown rule", "cn=alice,dc=example", "cn=bob,eqUnknownRule=x", false, false},
		{"mismatch then cycle", "cn=alice,dc=example", "cn=bob,eqCycleA=x", false, false},
		{"mismatch then orphan", "cn=alice,dc=example", "cn=bob,eqOrphan=x", false, false},
		{"mismatch then other rule", "cn=alice,dc=example", "cn=bob,uidNumber=42", false, false},
		{"mismatch then duplicate AVA", "cn=alice,dc=example", "cn=bob,dc=x+domainComponent=y", false, false},
		{"type mismatch then bad tail", "cn=alice,dc=example", "uid=bob,r10Unknown=x", false, false},
		{"mismatch then nonASCII", "cn=alice,dc=example", "cn=bob,dc=\u00e9", false, false},
		{"mismatch then invalid UTF8", "cn=alice,dc=example", "cn=bob,dc=\xff", false, false},
		{"mismatch then option", "cn=alice,dc=example", "cn=bob,dc;lang-en=example", false, false},
		{"mismatch then invalid OID", "cn=alice,dc=example", "cn=bob,0.09.2342.19200300.100.1.25=example", false, false},
	}
}

func TestCompareEntryAttributeSimpleDN(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, tc := range simpleDNComparisonCases() {
		t.Run(tc.name, func(t *testing.T) {
			// The first stored value forces full normalization before the candidate.
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("cn=first-miss", tc.value)}}}
			checkCompareEntryAttribute(t, registry, entry, "member", []byte(tc.assertion))

			registry.mu.RLock()
			defer registry.mu.RUnlock()
			normalized, err := registry.normalizeWithRuleLocked("distinguishedNameMatch", []byte(tc.assertion))
			if err != nil {
				t.Fatal(err)
			}
			value := []byte(tc.value)
			normalizedBefore, valueBefore := bytes.Clone(normalized), bytes.Clone(value)
			prepared := registry.prepareSimpleDNComparisonLocked(normalized)
			matched, handled := prepared.match(registry, value)
			if handled != tc.handled || handled && matched != tc.matched {
				t.Fatalf("match = (%v, %v), want (%v, %v)", matched, handled, tc.matched, tc.handled)
			}
			if !bytes.Equal(normalized, normalizedBefore) || !bytes.Equal(value, valueBefore) {
				t.Fatal("simple comparison mutated normalized assertion or stored value")
			}
		})
	}
}

func TestCompareEntryAttributeSimpleDNOrder(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, values := range [][]string{
		{"bad-dn", "cn=alice"}, {"cn=alice", "bad-dn"},
		{"cn=first-miss", "cn=bob,r10Unknown=x", "cn=alice"},
		{"cn=first-miss", "cn=alice", "cn=bob,r10Unknown=x"},
		{"cn=first-miss", "uid=alice", "cn=alice"},
		{"cn=first-miss", "cn=alice,dc=example", "cn=alice"},
		{"cn=first-miss", `cn=\61lice`, "bad-dn"},
	} {
		for _, split := range []bool{false, true} {
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(values...)}}}
			if split {
				entry.Attributes[0].Values = byteValues(values[0])
				entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "member;lang-en", Values: byteValues(values[1:]...)})
			}
			for _, assertion := range []string{"cn=alice", "bad-dn", "cn=alice,r10Unknown=x"} {
				checkCompareEntryAttribute(t, registry, entry, "member", []byte(assertion))
			}
		}
	}
}

func TestCompareEntryAttributeSimpleDNSchemaChange(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, names := range [][2]string{{"eqChild", "eqChild"}, {"eqExact", "eqExact"}, {"name", "cn"}} {
		attribute, _ := registry.AttributeType(names[0])
		naming, _ := registry.AttributeType(names[1])
		name := names[1]
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("cn=first-miss", name+"=ALICE")}}}
		for _, rule := range []string{"caseExactMatch", "caseIgnoreMatch", "caseExactIA5Match", "caseIgnoreIA5Match", "octetStringMatch"} {
			attribute.Equality = rule
			attribute.Names = []string{"r10Canonical" + names[0], names[0]}
			if err := registry.UpsertAttributeType(attribute); err != nil {
				t.Fatal(err)
			}
			present, matched, err := checkCompareEntryAttribute(t, registry, entry, "member", []byte(naming.OID+"=alice"))
			if !present || err != nil || matched != strings.HasPrefix(rule, "caseIgnore") {
				t.Fatalf("after %s/%s: (%v, %v, %v)", name, rule, present, matched, err)
			}
		}
	}
}

func TestCompareEntryAttributeSimpleDNOwnership(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	shared := []byte("cn=ALICE,dc=EXAMPLE")
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: [][]byte{[]byte("cn=first-miss"), shared}}}}
	checkCompareEntryAttribute(t, registry, entry, "member", shared)
	assertion := bytes.Clone(shared)
	for _, name := range []string{"OTHER", "ALICE", "OTHER"} {
		copy(shared[3:8], name)
		_, matched, err := checkCompareEntryAttribute(t, registry, entry, "member", assertion)
		if err != nil || matched != (name == "ALICE") {
			t.Fatalf("after caller mutation to %s: matched=%v, err=%v", name, matched, err)
		}
	}
}

func FuzzCompareEntryAttributeSimpleDN(f *testing.F) {
	registry := equalityEvaluationRegistry(f)
	for _, tc := range simpleDNComparisonCases() {
		f.Add("cn=first-miss", tc.value, tc.assertion)
	}
	f.Add("bad-dn", "cn=alice", "cn=alice")
	f.Add("cn=alice", "bad-dn", "cn=alice")
	f.Add("cn=first-miss", "cn=alice", "bad-dn")
	f.Fuzz(func(t *testing.T, first, second, assertion string) {
		if len(first)+len(second)+len(assertion) > 4096 {
			t.Skip()
		}
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues(first, second)}}}
		checkCompareEntryAttribute(t, registry, entry, "member", []byte(assertion))
	})
}
