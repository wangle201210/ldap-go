package schema

import (
	"strings"
	"testing"
)

func BenchmarkSimpleDNTailLeaf(b *testing.B) {
	registry := equalityEvaluationRegistry(b)
	for _, tc := range []struct {
		name, assertion, leaf string
		matched, handled      bool
	}{
		{"short-hit", "cn=alice", "cn=alice", true, true},
		{"short-miss", "cn=alice", "cn=other", false, true},
		{"fold", "cn=alice", "CN=ALICE", true, true},
		{"alias", "uid=alice", "USERID=ALICE", true, true},
		{"OID", "cn=alice", "2.5.4.3=ALICE", true, true},
		{"exact-miss", "eqExact=Alice", "eqExact=alice", false, true},
		{"long-hit", "cn=" + strings.Repeat("a", 256), "cn=" + strings.Repeat("a", 256), true, true},
		{"long-miss", "cn=" + strings.Repeat("a", 256), "cn=b" + strings.Repeat("a", 255), false, true},
		{"invalid-last-byte", "cn=alice", "cn=" + strings.Repeat("a", 255) + "!", false, false},
	} {
		for _, tail := range []string{"dc=example", "ou=people,dc=example,dc=com"} {
			b.Run(tc.name+"/"+tail, func(b *testing.B) {
				normalized, err := registry.NormalizeEqualityAssertion("member", []byte(tc.assertion+","+tail))
				if err != nil {
					b.Fatal(err)
				}
				registry.mu.RLock()
				defer registry.mu.RUnlock()
				plan := registry.prepareSimpleDNComparisonLocked(normalized)
				if plan.count < 2 {
					b.Fatal("fixture did not prepare a multi-RDN plan")
				}
				warm := []byte(string(plan.parts[0].name) + "=warm," + tail)
				if _, handled := plan.match(registry, warm); !handled || !plan.tailReady {
					b.Fatal("fixture did not warm tail")
				}
				value := []byte(tc.leaf + "," + tail)
				if matched, handled := plan.match(registry, value); matched != tc.matched || handled != tc.handled {
					b.Fatalf("fixture=(%v,%v), want=(%v,%v)", matched, handled, tc.matched, tc.handled)
				}
				b.ReportAllocs()
				for b.Loop() {
					if matched, handled := plan.match(registry, value); matched != tc.matched || handled != tc.handled {
						b.Fatalf("match=(%v,%v), want=(%v,%v)", matched, handled, tc.matched, tc.handled)
					}
				}
			})
		}
	}
}
