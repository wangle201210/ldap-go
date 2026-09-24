package storage

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Small rows expose descriptor-arena overhead that large-group benchmarks hide.
func BenchmarkBoltTinyCandidateSelect(b *testing.B) {
	for _, count := range []int{1, 4} {
		for _, borrowed := range []bool{false, true} {
			b.Run(fmt.Sprintf("N%d/borrowed=%t", count, borrowed), func(b *testing.B) {
				store, registry, filter := newBoltCandidateStore(b, count)
				if err := store.View(b.Context(), func(reader Reader) error {
					scoped := ReaderInPartitionWithNormalizer(reader, "db", registry)
					iterate := ForEachFilterCandidate
					if borrowed {
						iterate = ForEachReadOnlyFilterCandidate
					}
					project := func(entry directory.Entry) error {
						selected := entry.Select([]string{"cn"}, false)
						if len(selected.Attributes) != 1 {
							b.Fatal("missing cn")
						}
						return nil
					}
					b.ReportAllocs()
					for b.Loop() {
						planned, visited, err := iterate(scoped, filter, project)
						if err != nil || !planned || visited != count {
							b.Fatalf("planned=%t visited=%d: %v", planned, visited, err)
						}
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			})
		}
	}
}
