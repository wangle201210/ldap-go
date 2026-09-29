package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestSimpleDNTailLeafOracle(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, tc := range []struct {
		name, assertion, leaf string
		handled               bool
	}{
		{"fold", "cn=alice", "CN=ALICE", true},
		{"alias", "uid=alice", "USERID=ALICE", true},
		{"OID", "cn=alice", "2.5.4.3=ALICE", true},
		{"inherited alias", "eqChild=alice", "EQALIAS=ALICE", true},
		{"rule OID", "eqOIDRule=alice", "1.2.3.812=ALICE", true},
		{"exact hit", "eqExact=Alice", "1.2.3.802=Alice", true},
		{"exact miss", "eqExact=Alice", "eqExact=alice", true},
		{"IA5 exact", "homeDirectory=Alice", "HOMEDIRECTORY=alice", true},
		{"punctuation", "uid=a-b_c.d9", "userid=A-B_C.D9", true},
		{"different type", "cn=alice", "uid=alice", false},
		{"unknown type", "cn=alice", "leafUnknown=alice", false},
		{"invalid OID", "cn=alice", "2.05.4.3=alice", false},
		{"trailing OID dot", "cn=alice", "2.5.4.3.=alice", false},
		{"invalid descriptor", "cn=alice", "cn_1=alice", false},
		{"option", "cn=alice", "cn;lang-en=alice", false},
		{"extra equals", "cn=alice", "cn=alice=x", false},
		{"empty leaf", "cn=alice", "", false},
		{"empty value", "cn=alice", "cn=", false},
		{"escape", "cn=alice", `cn=\61lice`, false},
		{"escaped comma", "cn=alice", `cn=alice\`, false},
		{"multiAVA", "cn=alice", "cn=alice+uid=alice", false},
		{"duplicate alias", "cn=alice", "cn=alice+2.5.4.3=alice", false},
		{"space", "cn=alice", "cn= ALICE ", false},
		{"NUL", "cn=alice", "cn=alice\x00", false},
		{"invalid UTF8", "cn=alice", "cn=alice\xff", false},
		{"Unicode fold", "cn=k", "cn=\u212a", false},
	} {
		for _, tail := range []string{"dc=example", "dc=other"} {
			t.Run(tc.name+"/"+tail, func(t *testing.T) {
				assertion := tc.assertion + ",dc=example"
				normalized, err := registry.NormalizeEqualityAssertion("member", []byte(assertion))
				if err != nil {
					t.Fatal(err)
				}
				registry.mu.RLock()
				plan := registry.prepareSimpleDNComparisonLocked(normalized)
				if plan.count != 2 {
					registry.mu.RUnlock()
					t.Fatal("fixture must prepare a two-RDN comparison")
				}
				warm := string(plan.parts[0].name) + "=warm," + tail
				_, handled := plan.match(registry, []byte(warm))
				registry.mu.RUnlock()
				if !handled || !plan.tailReady || string(plan.tail[:plan.tailLength]) != tail || plan.tailMatches != (tail == "dc=example") {
					t.Fatal("fixture must warm the exact candidate tail with the expected match result")
				}
				checkSimpleDNTailSequence(t, registry, assertion,
					[]string{warm, tc.leaf + "," + tail, tc.leaf + "," + tail, assertion},
					[]bool{true, tc.handled, tc.handled, true})
			})
		}
	}
}

func TestSimpleDNTailLeafFirstError(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	assertion := "cn=alice,dc=example"
	for _, tail := range []string{"dc=example", "dc=other"} {
		for _, invalid := range []string{
			"broken," + tail, "=alice," + tail, "2.05.4.3=alice," + tail,
			"cn=alice+CN=bob," + tail, "leafUnknown=x," + tail,
			"cn=alice,dc=example,", "cn=alice,tailUnknown=x", "cn=alice,dc=x+domainComponent=y",
		} {
			for _, matchFirst := range []bool{false, true} {
				for _, split := range []bool{false, true} {
					values := byteValues(invalid, assertion)
					if matchFirst {
						values[0], values[1] = values[1], values[0]
					}
					// The first miss prepares the plan; the second warms its tail.
					entry := directory.Entry{Attributes: []directory.Attribute{{
						Description: "member", Values: byteValues("cn=first-miss", "cn=warm,"+tail),
					}}}
					if split {
						entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "member;lang-en", Values: values})
					} else {
						entry.Attributes[0].Values = append(entry.Attributes[0].Values, values...)
					}
					present, matched, err := checkCompareEntryAttribute(t, registry, entry, "member", []byte(assertion))
					if !present || matched != matchFirst || (err != nil) != !matchFirst {
						t.Fatalf("tail=%q invalid=%q matchFirst=%v split=%v: (%v,%v,%v)",
							tail, invalid, matchFirst, split, present, matched, err)
					}
				}
			}
		}
	}
}
