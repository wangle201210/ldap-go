package acl

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestPolicyRulesForSelection(t *testing.T) {
	const suffix = "dc=example,dc=com"
	const child = "ou=people," + suffix
	database := []Rule{{Order: 2, Raw: "database second"}, {Order: 1, Raw: "database first"}}
	global := []Rule{{Order: 1, Raw: "global second"}, {Order: 0, Raw: "global first"}}
	for _, test := range []struct {
		name       string
		global     []Rule
		databases  map[string][]Rule
		target     string
		want       []string
		sharedWith string
	}{
		{name: "empty", target: suffix},
		{name: "database exact", databases: map[string][]Rule{suffix: database}, target: suffix,
			want: []string{"database first", "database second"}, sharedWith: suffix},
		{name: "database descendant empty global", global: []Rule{}, databases: map[string][]Rule{suffix: database}, target: "uid=alice," + suffix,
			want: []string{"database first", "database second"}, sharedWith: suffix},
		{name: "global only", global: global, target: suffix,
			want: []string{"global first", "global second"}, sharedWith: "global"},
		{name: "unmatched database", global: global, databases: map[string][]Rule{suffix: database}, target: "dc=other,dc=com",
			want: []string{"global first", "global second"}, sharedWith: "global"},
		{name: "empty database", global: global, databases: map[string][]Rule{suffix: {}}, target: suffix,
			want: []string{"global first", "global second"}, sharedWith: "global"},
		{name: "database before global", global: global, databases: map[string][]Rule{suffix: database}, target: suffix,
			want: []string{"database first", "database second", "global first", "global second"}},
		{name: "most specific", databases: map[string][]Rule{suffix: database, child: {{Raw: "child"}}}, target: "uid=alice," + child,
			want: []string{"child"}, sharedWith: child},
		{name: "empty child shadows parent", databases: map[string][]Rule{suffix: database, child: nil}, target: child},
		{name: "empty child uses global", global: global, databases: map[string][]Rule{suffix: database, child: nil}, target: child,
			want: []string{"global first", "global second"}, sharedWith: "global"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy(test.global, test.databases)
			if err != nil {
				t.Fatal(err)
			}
			got := policy.rulesFor(staticDN(test.target), nil)
			var names []string
			for _, rule := range got {
				names = append(names, rule.Raw)
			}
			if !slices.Equal(names, test.want) {
				t.Fatalf("rulesFor = %v, want %v", names, test.want)
			}
			if len(got) == 0 {
				return
			}
			if test.sharedWith != "" {
				shared := policy.global
				for _, candidate := range policy.databases {
					if candidate.Suffix.String() == test.sharedWith {
						shared = candidate.Rules
					}
				}
				if len(shared) != len(got) || &got[0] != &shared[0] {
					t.Fatal("single rule set was copied")
				}
			} else {
				// The mixed result must still own its outer slice.
				got[0].Raw = "changed database result"
				got[len(got)-1].Raw = "changed global result"
				if policy.databases[0].Rules[0].Raw != "database first" || policy.global[1].Raw != "global second" {
					t.Fatal("mixed result aliases policy rules")
				}
			}
		})
	}
}

func TestPolicyRulesForNormalizer(t *testing.T) {
	const suffix = "dc=example,dc=com"
	const child = "ou=people," + suffix
	for _, global := range [][]Rule{nil, {{Raw: "global"}}} {
		for _, failChild := range []bool{false, true} {
			policy, err := NewPolicy(global, map[string][]Rule{
				suffix: {{Raw: "parent"}}, child: nil,
			})
			if err != nil {
				t.Fatal(err)
			}
			var calls []string
			normalizer := stubACLDNParser{parse: func(raw string) (directory.DN, error) {
				calls = append(calls, raw)
				if failChild && raw == child {
					return directory.DN{}, errors.New("child normalization failed")
				}
				return directory.ParseDN(raw)
			}}
			wantCalls := []string{child}
			want := slices.Clone(global)
			if failChild {
				wantCalls = append(wantCalls, suffix)
				want = append([]Rule{{Raw: "parent"}}, want...)
			}
			for range 2 {
				calls = nil
				got := policy.rulesFor(staticDN("uid=alice,"+child), normalizer)
				if !reflect.DeepEqual(got, want) || !slices.Equal(calls, wantCalls) {
					t.Fatalf("global=%t failChild=%t: rules=%v calls=%v, want %v and %v", len(global) != 0, failChild, got, calls, want, wantCalls)
				}
			}
		}
	}
}

func TestPolicyRulesForAllowedDoesNotMutate(t *testing.T) {
	for _, placement := range []string{"database", "global", "both"} {
		t.Run(placement, func(t *testing.T) {
			newPolicy := func() *Policy {
				first := mustRule(t, `{0}to dn.regex="^uid=([^,]+),dc=example,dc=com$" attrs=cn by dn.exact,expand="uid=$1,dc=example,dc=com" =s continue by * break`)
				second := mustRule(t, `{1}to attrs=userPassword by anonymous auth`)
				last := mustRule(t, `{2}to * by users +r stop`)
				var global, database []Rule
				switch placement {
				case "database":
					database = []Rule{last, second, first}
				case "global":
					global = []Rule{last, second, first}
				case "both":
					database, global = []Rule{second, first}, []Rule{last}
				}
				policy, err := NewPolicy(global, map[string][]Rule{"dc=example,dc=com": database})
				if err != nil {
					t.Fatal(err)
				}
				return policy
			}
			policy, before := newPolicy(), newPolicy()
			for range 2 {
				for _, test := range []struct {
					subject, attribute string
					required           Privilege
					want               bool
				}{
					{"alice", "cn", Search, true},
					{"alice", "cn", Read, true},
					{"alice", "cn", Write, false},
					{"bob", "cn", Search, false},
					{"bob", "cn", Read, true},
					{"", "cn", Read, false},
					{"", "userPassword", Auth, true},
					{"alice", "userPassword", Read, false},
				} {
					subject := Subject{}
					if test.subject != "" {
						subject.DN = "uid=" + test.subject + ",dc=example,dc=com"
					}
					target := Target{Entry: testEntry(), Attribute: test.attribute}
					if got := policy.Allowed(subject, target, test.required, nil); got != test.want {
						t.Fatalf("Allowed(%q, %q, %b) = %t, want %t", test.subject, test.attribute, test.required, got, test.want)
					}
					if !reflect.DeepEqual(policy, before) {
						t.Fatal("Allowed mutated policy rules")
					}
				}
			}
		})
	}
}

func BenchmarkPolicyRulesFor(b *testing.B) {
	for _, placement := range []string{"empty", "database", "global", "both"} {
		b.Run(placement, func(b *testing.B) {
			rules := []Rule{{Order: 0}, {Order: 1}, {Order: 2}}
			var global, database []Rule
			switch placement {
			case "database":
				database = rules
			case "global":
				global = rules
			case "both":
				database, global = rules, rules
			}
			policy, err := NewPolicy(global, map[string][]Rule{"dc=example,dc=com": database})
			if err != nil {
				b.Fatal(err)
			}
			target := staticDN("uid=alice,dc=example,dc=com")
			want := len(database) + len(global)
			b.ReportAllocs()
			for b.Loop() {
				if got := policy.rulesFor(target, nil); len(got) != want {
					b.Fatalf("rulesFor returned %d rules, want %d", len(got), want)
				}
			}
		})
	}
}
