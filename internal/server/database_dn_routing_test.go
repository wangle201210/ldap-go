package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type routingAttributeNormalizer func(string, []byte) (string, []byte, error)

func (normalize routingAttributeNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	return normalize(attribute, value)
}

type routingIdentityParser struct {
	directory.DNAttributeNormalizer
	parse func(string) (directory.DN, error)
}

func (parser routingIdentityParser) ParseDNIdentity(raw string) (directory.DN, error) {
	return parser.parse(raw)
}

func routingCallbackNormalizer(parser bool, callback func(string) error) directory.DNAttributeNormalizer {
	if parser {
		// A nil embedded normalizer makes unexpected attribute fallback fail.
		return routingIdentityParser{parse: func(raw string) (directory.DN, error) {
			if err := callback(raw); err != nil {
				return directory.DN{}, err
			}
			return directory.ParseDN(raw)
		}}
	}
	return routingAttributeNormalizer(func(attribute string, value []byte) (string, []byte, error) {
		if err := callback(attribute + "=" + string(value)); err != nil {
			return "", nil, err
		}
		return strings.ToLower(attribute), []byte(strings.ToLower(string(value))), nil
	})
}

func TestDatabaseDNRoutingNormalizerSnapshot(t *testing.T) {
	for _, relation := range []struct {
		name       string
		before     func(runtimeDatabase, directory.DN, directory.DN) bool
		current    func(runtimeDatabase, directory.DN, directory.DN) bool
		left       string
		right      string
		attributes []string
		want       bool
	}{
		{"equal", routingBeforeEqual, databaseDNEqual, "cn=Alice", "cn=alice", []string{"cn=Alice", "cn=alice"}, true},
		{"at-or-below", routingBeforeAtOrBelow, databaseDNAtOrBelow, "cn=Alice,dc=example", "dc=example", []string{"cn=Alice", "dc=example", "dc=example"}, true},
		{"strictly-below", routingBeforeStrictlyBelow, databaseDNStrictlyBelow, "cn=Alice,dc=example", "dc=example", []string{"cn=Alice", "dc=example", "dc=example"}, true},
		{"strict-equal", routingBeforeStrictlyBelow, databaseDNStrictlyBelow, "cn=Alice", "cn=Alice", []string{"cn=Alice", "cn=Alice"}, false},
	} {
		for _, parser := range []bool{false, true} {
			for _, version := range []struct {
				name  string
				match func(runtimeDatabase, directory.DN, directory.DN) bool
			}{{"before", relation.before}, {"current", relation.current}} {
				t.Run(fmt.Sprintf("%s/parser=%t/%s", relation.name, parser, version.name), func(t *testing.T) {
					left := mustLegacyDNIdentityDN(t, relation.left)
					right := mustLegacyDNIdentityDN(t, relation.right)
					wantCalls := relation.attributes
					if parser {
						wantCalls = []string{left.String(), right.String()}
					}
					for _, failAt := range []int{0, 1, len(wantCalls)} {
						t.Run(fmt.Sprintf("fail-at=%d", failAt), func(t *testing.T) {
							var database runtimeDatabase
							var calls []string
							failure := errors.New("normalizer changed")
							replacementCalls := 0
							replacement := routingCallbackNormalizer(parser, func(string) error {
								replacementCalls++
								return failure
							})
							database.dnNormalizer = routingCallbackNormalizer(parser, func(value string) error {
								calls = append(calls, value)
								// Reentrant mutation avoids a data race while exercising
								// replacement during an in-flight comparison.
								database.dnNormalizer = replacement
								if len(calls) == failAt {
									return failure
								}
								return nil
							})
							want := relation.want && failAt == 0
							if got := version.match(database, left, right); got != want {
								t.Fatalf("match = %t, want %t", got, want)
							}
							expected := wantCalls
							if failAt != 0 {
								expected = expected[:failAt]
							}
							if !slices.Equal(calls, expected) || replacementCalls != 0 {
								t.Fatalf("calls = %q, want %q; replacement calls = %d", calls, expected, replacementCalls)
							}
							if version.match(database, left, right) || replacementCalls != 1 {
								t.Fatal("next comparison did not observe the replacement and its error")
							}
						})
					}
				})
			}
		}
	}
}

func TestDatabaseDNRoutingNormalizerChanges(t *testing.T) {
	for _, parser := range []bool{false, true} {
		t.Run(fmt.Sprintf("parser=%t", parser), func(t *testing.T) {
			dn := mustLegacyDNIdentityDN(t, "cn=Alice")
			failure := errors.New("live callback failure")
			var callbackError error
			calls := 0
			database := runtimeDatabase{dnNormalizer: routingCallbackNormalizer(parser, func(string) error {
				calls++
				return callbackError
			})}
			if _, err := normalizeRuntimeDatabaseDN(database, dn); err != nil || calls != 1 {
				t.Fatalf("first normalization: calls=%d, error=%v", calls, err)
			}
			callbackError = failure
			if _, err := normalizeRuntimeDatabaseDN(database, dn); !errors.Is(err, failure) || calls != 2 {
				t.Fatalf("changed normalization: calls=%d, error=%v", calls, err)
			}
			for _, match := range []func(runtimeDatabase, directory.DN, directory.DN) bool{
				databaseDNEqual, databaseDNAtOrBelow, databaseDNStrictlyBelow,
			} {
				calls = 0
				callbackError = nil
				database.dnNormalizer = routingCallbackNormalizer(parser, func(string) error {
					calls++
					if calls == 1 {
						callbackError = failure
						return nil
					}
					return callbackError
				})
				if match(database, dn, dn) || calls != 2 {
					t.Fatalf("second-operand change: calls=%d", calls)
				}
			}
		})
	}
}

func TestDatabaseDNRoutingRefreshesNormalizerPerSuffix(t *testing.T) {
	for _, route := range []struct {
		name  string
		index func([]runtimeDatabase, directory.DN) int
	}{
		{"before", routingBeforeIndexForDN},
		{"current", databaseIndexForDN},
		{"root-override", databaseIndexForRootOverride},
	} {
		t.Run(route.name, func(t *testing.T) {
			databases := []runtimeDatabase{{suffixes: []directory.DN{
				mustLegacyDNIdentityDN(t, "dc=other"),
				mustLegacyDNIdentityDN(t, "dc=example"),
			}}}
			var calls []string
			replacement := routingCallbackNormalizer(true, func(raw string) error {
				calls = append(calls, "new:"+raw)
				return errors.New("replacement failure")
			})
			databases[0].dnNormalizer = routingCallbackNormalizer(true, func(raw string) error {
				calls = append(calls, "old:"+raw)
				databases[0].dnNormalizer = replacement
				return nil
			})
			dn := mustLegacyDNIdentityDN(t, "cn=Alice,dc=example")
			if got := route.index(databases, dn); got != -1 {
				t.Fatalf("route = %d, want -1", got)
			}
			want := []string{"old:" + dn.String(), "old:dc=other", "new:" + dn.String()}
			if !slices.Equal(calls, want) {
				t.Fatalf("calls = %q, want %q", calls, want)
			}
		})
	}
}
