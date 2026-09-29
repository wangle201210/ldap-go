package server

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

type routingBenchmarkInput struct {
	database runtimeDatabase
	dn       directory.DN
	base     directory.DN
}

func newRoutingBenchmarkInput(b *testing.B, mode string) *routingBenchmarkInput {
	b.Helper()
	input := &routingBenchmarkInput{}
	raw := "uid=Alice,ou=people,dc=example,dc=com"
	if mode == "legacy-fallback" {
		raw = `cn=Smith\, Alice,ou=people,dc=example,dc=com`
	}
	if mode == "schema-cached" {
		registry, err := schema.NewBuiltinRegistry()
		if err != nil {
			b.Fatal(err)
		}
		input.database.dnNormalizer = &databaseEqualityIndexNormalizer{registry: registry}
	}
	var err error
	input.dn, err = parseRuntimeDN(raw, input.database.dnNormalizer)
	if err != nil {
		b.Fatal(err)
	}
	input.base, err = parseRuntimeDN("dc=example,dc=com", input.database.dnNormalizer)
	if err != nil {
		b.Fatal(err)
	}
	return input
}

// Matched direct callers let the wrappers inline inside the caller even when
// b.Loop prevents inlining the immediate benchmark call. Passing the fixture
// avoids introducing an extra runtimeDatabase copy at that boundary.
func (input *routingBenchmarkInput) equalBefore() bool {
	return routingBeforeEqual(input.database, input.dn, input.base)
}

func (input *routingBenchmarkInput) equalCurrent() bool {
	return databaseDNEqual(input.database, input.dn, input.base)
}

func (input *routingBenchmarkInput) atOrBelowBefore() bool {
	return routingBeforeAtOrBelow(input.database, input.dn, input.base)
}

func (input *routingBenchmarkInput) atOrBelowCurrent() bool {
	return databaseDNAtOrBelow(input.database, input.dn, input.base)
}

func (input *routingBenchmarkInput) strictlyBelowBefore() bool {
	return routingBeforeStrictlyBelow(input.database, input.dn, input.base)
}

func (input *routingBenchmarkInput) strictlyBelowCurrent() bool {
	return databaseDNStrictlyBelow(input.database, input.dn, input.base)
}

func (input *routingBenchmarkInput) normalizeBefore() (directory.DN, error) {
	return routingBeforeNormalize(input.database, input.dn)
}

func (input *routingBenchmarkInput) normalizeCurrent() (directory.DN, error) {
	return normalizeRuntimeDatabaseDN(input.database, input.dn)
}

func BenchmarkDatabaseDNRoutingValueCopy(b *testing.B) {
	for _, mode := range []string{"legacy-simple", "legacy-fallback", "schema-cached"} {
		b.Run(mode, func(b *testing.B) {
			input := newRoutingBenchmarkInput(b, mode)
			// Warm both variants before timing, including the retained schema cache.
			if input.equalBefore() || input.equalCurrent() ||
				!input.atOrBelowBefore() || !input.atOrBelowCurrent() ||
				!input.strictlyBelowBefore() || !input.strictlyBelowCurrent() {
				b.Fatal("unexpected relation fixture")
			}
			want, err := input.normalizeBefore()
			if err != nil {
				b.Fatal(err)
			}
			if got, err := input.normalizeCurrent(); err != nil || !got.Equal(want) {
				b.Fatalf("normalization differs: %v", err)
			}
			b.Run("equal/before", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if input.equalBefore() {
						b.Fatal("unexpected equality")
					}
				}
			})
			b.Run("equal/current", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if input.equalCurrent() {
						b.Fatal("unexpected equality")
					}
				}
			})
			b.Run("at-or-below/before", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if !input.atOrBelowBefore() {
						b.Fatal("expected descendant")
					}
				}
			})
			b.Run("at-or-below/current", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if !input.atOrBelowCurrent() {
						b.Fatal("expected descendant")
					}
				}
			})
			b.Run("strictly-below/before", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if !input.strictlyBelowBefore() {
						b.Fatal("expected strict descendant")
					}
				}
			})
			b.Run("strictly-below/current", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if !input.strictlyBelowCurrent() {
						b.Fatal("expected strict descendant")
					}
				}
			})
			b.Run("normalize/before", func(b *testing.B) {
				b.ReportAllocs()
				var got directory.DN
				var err error
				for b.Loop() {
					got, err = input.normalizeBefore()
					if err != nil {
						b.Fatal(err)
					}
				}
				if !got.Equal(want) {
					b.Fatal("normalization differs")
				}
			})
			b.Run("normalize/current", func(b *testing.B) {
				b.ReportAllocs()
				var got directory.DN
				var err error
				for b.Loop() {
					got, err = input.normalizeCurrent()
					if err != nil {
						b.Fatal(err)
					}
				}
				if !got.Equal(want) {
					b.Fatal("normalization differs")
				}
			})
		})
	}
}

func BenchmarkDatabaseDNRoutingIndexValueCopy(b *testing.B) {
	for _, mode := range []string{"legacy-simple", "legacy-fallback", "schema-cached"} {
		for _, count := range []int{1, 8, 32} {
			b.Run(fmt.Sprintf("%s/databases=%d", mode, count), func(b *testing.B) {
				input := newRoutingBenchmarkInput(b, mode)
				databases := make([]runtimeDatabase, count)
				for index := range databases {
					suffix := input.base
					if index != count-1 {
						var err error
						suffix, err = parseRuntimeDN(fmt.Sprintf("dc=other%d,dc=com", index), input.database.dnNormalizer)
						if err != nil {
							b.Fatal(err)
						}
					}
					databases[index] = runtimeDatabase{
						dnNormalizer: input.database.dnNormalizer,
						suffixes:     []directory.DN{suffix},
					}
				}
				if routingBeforeIndexForDN(databases, input.dn) != count-1 || databaseIndexForDN(databases, input.dn) != count-1 {
					b.Fatal("unexpected routing fixture")
				}
				b.Run("before", func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if routingBeforeIndexForDN(databases, input.dn) != count-1 {
							b.Fatal("incorrect database")
						}
					}
				})
				b.Run("current", func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if databaseIndexForDN(databases, input.dn) != count-1 {
							b.Fatal("incorrect database")
						}
					}
				})
			})
		}
	}
}
