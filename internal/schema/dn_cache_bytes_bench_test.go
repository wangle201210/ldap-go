package schema

import (
	"fmt"
	"testing"
)

func BenchmarkDNCacheByteInput(b *testing.B) {
	for _, workload := range []struct {
		name       string
		corpusSize int
	}{
		{"warm", 1},
		{"distributed", maxCachedDNs + 1},
	} {
		b.Run(workload.name, func(b *testing.B) {
			inputs := make([][]byte, workload.corpusSize)
			for i := range inputs {
				inputs[i] = fmt.Appendf(nil, "CN=User%d,OU=People,DC=example,DC=com", i)
			}
			for _, implementation := range []string{"string", "bytes"} {
				b.Run(implementation, func(b *testing.B) {
					registry, err := NewBuiltinRegistry()
					if err != nil {
						b.Fatal(err)
					}
					normalize := func(value []byte) (normalizedDNCacheEntry, error) {
						registry.mu.RLock()
						defer registry.mu.RUnlock()
						return registry.normalizeDNCachedLocked(string(value))
					}
					if implementation == "bytes" {
						normalize = func(value []byte) (normalizedDNCacheEntry, error) {
							registry.mu.RLock()
							defer registry.mu.RUnlock()
							return registry.normalizeDNBytesCachedLocked(value)
						}
					}
					keys := make([]string, len(inputs))
					for i, input := range inputs {
						dn, err := registry.NormalizeDN(string(input))
						if err != nil {
							b.Fatal(err)
						}
						keys[i] = dn.Key()
						if got, err := normalize(input); err != nil || got.dn.Key() != keys[i] {
							b.Fatalf("fixture %d: normalization = %q, %v", i, got.dn.Key(), err)
						}
					}
					b.ReportAllocs()
					index := 0
					for b.Loop() {
						if got, err := normalize(inputs[index]); err != nil || got.dn.Key() != keys[index] {
							b.Fatalf("normalization = %q, %v; want %q", got.dn.Key(), err, keys[index])
						}
						index++
						if index == len(inputs) {
							index = 0
						}
					}
				})
			}
		})
	}
}
