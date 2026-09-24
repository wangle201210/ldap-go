package schema

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func BenchmarkEvaluateEqualityCachedDN(b *testing.B) {
	// Six workloads, each measured with both evaluators: twelve timed cases.
	for _, workload := range []struct {
		name       string
		valueCount int
		matchIndex int
		corpusSize int
		cold       bool
	}{
		{"size10/first/warmed", 10, 0, 1, false},
		{"size10/middle/warmed", 10, 5, 1, false},
		{"size10/miss/warmed", 10, 10, 1, false},
		{"size1000/first/warmed", 1000, 0, 1, false},
		{"size1000/middle/cold", 1000, 500, 1, true},
		{"size1000/miss/distributed", 1000, 1000, 16, false},
	} {
		b.Run(workload.name, func(b *testing.B) {
			entries := make([]directory.Entry, workload.corpusSize)
			assertions := make([][]byte, workload.corpusSize)
			for i := range entries {
				values := make([][]byte, workload.valueCount)
				for j := range values {
					values[j] = fmt.Appendf(nil, "CN=User%d-%d,OU=People,DC=example,DC=com", i, j)
				}
				entries[i] = directory.Entry{Attributes: []directory.Attribute{
					{Description: "objectClass", Values: byteValues("groupOfNames")},
					{Description: "cn", Values: byteValues("benchmark group")},
					{Description: "member", Values: values},
				}}
				assertions[i] = fmt.Appendf(nil, "cn=user%d-%d,ou=people,dc=example,dc=com", i, workload.matchIndex)
			}
			want := directory.FilterTrueResult
			if workload.matchIndex == workload.valueCount {
				want = directory.FilterFalseResult
			}
			for _, implementation := range []string{"original", "cached"} {
				b.Run(implementation, func(b *testing.B) {
					registry, err := NewBuiltinRegistry()
					if err != nil {
						b.Fatal(err)
					}
					evaluate := registry.EvaluateEquality
					if implementation == "cached" {
						evaluate = registry.EvaluateEqualityCachedDN
					}
					// Validate fixtures and warm the repeated workloads outside
					// the timer. Distributed misses exceed the bounded cache.
					for i, entry := range entries {
						if got, hasValues := evaluate(entry, "member", assertions[i]); got != want || !hasValues {
							b.Fatalf("fixture %d = (%v,%v), want (%v,true)", i, got, hasValues, want)
						}
					}
					b.ReportAllocs()
					index := 0
					for b.Loop() {
						if workload.cold {
							// Exclude cache reset from component timings; retain
							// ordinary schema state while starting with no DNs.
							b.StopTimer()
							registry.dnCache.entries = nil
							registry.dnCache.bytes = 0
							b.StartTimer()
						}
						if got, hasValues := evaluate(entries[index], "member", assertions[index]); got != want || !hasValues {
							b.Fatalf("equality = (%v,%v), want (%v,true)", got, hasValues, want)
						}
						index++
						if index == len(entries) {
							index = 0
						}
					}
				})
			}
		})
	}
}
