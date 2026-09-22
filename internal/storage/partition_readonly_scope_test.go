package storage

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestReadOnlyPhysicalScopeMatchesSeparateCheck(t *testing.T) {
	store, schema, _ := newBoltCandidateStore(t, 12)
	for _, raw := range []string{"dc=example", "uid=user000005,dc=example", "dc=elsewhere", ""} {
		base, err := directory.ParseDNWithNormalizer(raw, schema)
		if err != nil {
			t.Fatal(err)
		}
		for _, scope := range []directory.Scope{directory.ScopeBase, directory.ScopeSingleLevel, directory.ScopeWholeSubtree, directory.ScopeChildren, 99} {
			err := store.View(t.Context(), func(reader Reader) error {
				scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
				var want, got []string
				streamed, err := ForEachReadOnlyStablePhysicalEntry(scoped, func(entry directory.Entry) error {
					key, _ := entry.DNIdentity()
					matched, scopeErr := directory.IdentityKeyInScope(base, key, scope)
					want = append(want, fmt.Sprintf("%s/%t/%v", entry.DN, matched, scopeErr))
					return nil
				})
				if err != nil || !streamed {
					return fmt.Errorf("reference %v/%v", streamed, err)
				}
				streamed, err = ForEachReadOnlyStablePhysicalEntryInScope(scoped, base, scope, func(entry directory.Entry, matched bool, scopeErr error) error {
					got = append(got, fmt.Sprintf("%s/%t/%v", entry.DN, matched, scopeErr))
					return nil
				})
				if err != nil || !streamed {
					return fmt.Errorf("combined %v/%v", streamed, err)
				}
				if !reflect.DeepEqual(got, want) || len(got) != 12 {
					t.Fatalf("%q scope=%d: callbacks differ", raw, scope)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestReadOnlyPhysicalScopeDefersScopeError(t *testing.T) {
	store, schema, _ := newBoltCandidateStore(t, 3)
	legacy, _ := directory.ParseDN("dc=example")
	stop := errors.New("deadline stop")
	err := store.View(t.Context(), func(reader Reader) error {
		calls := 0
		streamed, err := ForEachReadOnlyStablePhysicalEntryInScope(ReaderInPartitionWithNormalizer(reader, "db", schema), legacy, directory.ScopeWholeSubtree, func(entry directory.Entry, matched bool, scopeErr error) error {
			calls++
			if matched || scopeErr == nil || scopeErr.Error() != "scope base has no schema-aware identity" {
				t.Fatalf("scope=%v/%v", matched, scopeErr)
			}
			return stop
		})
		if !streamed || !errors.Is(err, stop) || calls != 1 {
			t.Fatalf("callback error lost: %v/%v/%d", streamed, err, calls)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkReadOnlyPhysicalScope(b *testing.B) {
	store, schema, _ := newBoltCandidateStore(b, 10000)
	base, err := directory.ParseDNWithNormalizer("dc=example", schema)
	if err != nil {
		b.Fatal(err)
	}
	for _, combined := range []bool{false, true} {
		b.Run(fmt.Sprint(combined), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := store.View(b.Context(), func(reader Reader) error {
					scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
					count := 0
					visit := func(_ directory.Entry, matched bool, scopeErr error) error {
						if scopeErr != nil {
							return scopeErr
						}
						if matched {
							count++
						}
						return nil
					}
					var streamed bool
					var err error
					if combined {
						streamed, err = ForEachReadOnlyStablePhysicalEntryInScope(scoped, base, directory.ScopeWholeSubtree, visit)
					} else {
						streamed, err = ForEachReadOnlyStablePhysicalEntry(scoped, func(entry directory.Entry) error {
							key, _ := entry.DNIdentity()
							matched, scopeErr := directory.IdentityKeyInScope(base, key, directory.ScopeWholeSubtree)
							return visit(entry, matched, scopeErr)
						})
					}
					if err == nil && (!streamed || count != 10000) {
						return fmt.Errorf("stream=%v count=%d", streamed, count)
					}
					return err
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
