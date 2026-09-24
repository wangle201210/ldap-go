package storage

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func BenchmarkBoltSmallGroupCandidateSelect(b *testing.B) {
	for _, groups := range []int{1, 2, 3, 4} {
		for _, members := range []int{1, 1000} {
			b.Run(fmt.Sprintf("Groups=%d/Members=%d", groups, members), func(b *testing.B) {
				store, schema, filter := newSmallGroupCandidateStore(b, groups, members, "v3")
				for _, projection := range []struct {
					name       string
					attributes []string
				}{
					{"CN", []string{"cn"}},
					{"CNMember", []string{"cn", "member"}},
				} {
					b.Run(projection.name, func(b *testing.B) {
						for _, variant := range []struct {
							name    string
							iterate readOnlyCandidateIterator
						}{{"Owned", ForEachFilterCandidate}, {"ReadOnly", ForEachReadOnlyFilterCandidate}} {
							b.Run(variant.name, func(b *testing.B) {
								b.ReportAllocs()
								for b.Loop() {
									var retained []directory.Entry
									if err := store.View(b.Context(), func(reader Reader) error {
										retained = make([]directory.Entry, 0, groups)
										planned, count, err := variant.iterate(ReaderInPartitionWithNormalizer(reader, "db", schema), filter, func(entry directory.Entry) error {
											retained = append(retained, entry.Select(projection.attributes, false))
											return nil
										})
										if err != nil || !planned || count != groups {
											return fmt.Errorf("planned/count/error = %v/%d/%v", planned, count, err)
										}
										return nil
									}); err != nil {
										b.Fatal(err)
									}
									if len(retained) != groups {
										b.Fatalf("retained groups = %d, want %d", len(retained), groups)
									}
									for _, entry := range retained {
										if len(entry.Attributes) != len(projection.attributes) || string(entry.Attributes[0].Values[0]) != "shared" {
											b.Fatal("unexpected group projection")
										}
										if projection.name == "CNMember" && len(entry.Attributes[1].Values) != members {
											b.Fatal("unexpected member count")
										}
									}
								}
							})
						}
					})
				}
			})
		}
	}
}
