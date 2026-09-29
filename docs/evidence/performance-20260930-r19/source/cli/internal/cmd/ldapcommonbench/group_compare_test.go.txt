package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestGroupCompareOptInAndValidation(t *testing.T) {
	wantDefaults := []string{"userBind", "userBindWrong", "nonrootBase", "nonrootEquality", "memberEquality", "groupBase", "nestedMembership"}
	for _, args := range [][]string{nil, {"-stages=all"}} {
		c := testOptions(t, args...)
		if !slices.Equal(c.Stages, wantDefaults) {
			t.Fatalf("default stages changed: %v", c.Stages)
		}
		if got := benchmarks(c, buildFixture(c, "defaults", "password")); len(got) != 10 {
			t.Fatalf("default benchmark count = %d, want 10", len(got))
		}
	}
	stages := []string{"groupCompareTrueFirst", "groupCompareTrueLast", "groupCompareFalse"}
	for _, stage := range stages {
		for _, pool := range []bool{false, true} {
			args := []string{"-stages=" + stage}
			if pool {
				args = append(args, "-people=ou=people,dc=fixture", "-entries=992")
			}
			c := testOptions(t, args...)
			f := buildFixture(c, "compare", "password")
			if !slices.Equal(c.Stages, []string{stage}) || !needsGroups(c) || f.direct != 2 || len(f.groups) != 5 {
				t.Fatalf("Compare-only stage must create the existing group fixture: %s/pool=%t", stage, pool)
			}
			wantUsers, wantPool, wantEntries := 1000, 0, 1006
			if pool {
				wantUsers, wantPool, wantEntries = 8, 992, 14
			}
			if len(f.users) != wantUsers || len(f.pool) != wantPool || len(f.entries) != wantEntries {
				t.Fatalf("unexpected Compare fixture sizes: users=%d pool=%d entries=%d", len(f.users), len(f.pool), len(f.entries))
			}
			got := benchmarks(c, f)
			if len(got) != 2 {
				t.Fatalf("%s: want one benchmark per group size, got %d", stage, len(got))
			}
			for i, b := range got {
				if b.root || b.user != f.users[0] || b.group != f.groups[i] || len(b.group.GetAttributeValues("member")) != c.GroupSizes[i] {
					t.Fatalf("%s must use groupBase's member account and direct groups", stage)
				}
			}
		}
		for _, extra := range [][]string{
			{"-stages=" + stage + "," + stage},
			{"-stages=all," + stage},
			{"-setup-disposable=false"},
			{"-group-sizes=7"},
			{"-group-sizes=10,10"},
			{"-people=ou=people,dc=fixture", "-entries=991"},
		} {
			args := append(testArgs(), "-stages="+stage)
			if _, err := parseOptions(append(args, extra...), testLookup, io.Discard); err == nil {
				t.Fatalf("expected rejection for %s: %v", stage, extra)
			}
		}
	}
	c := testOptions(t, "-stages=groupCompareTrueLast,base,rootBind,groupCompareFalse,groupCompareTrueFirst")
	if !slices.Equal(c.Stages, []string{"groupCompareTrueLast", "nonrootBase", "rootBind", "groupCompareFalse", "groupCompareTrueFirst"}) {
		t.Fatalf("mixed stage order/alias changed: %v", c.Stages)
	}
}

func TestGroupCompareRequestsIdentityRotationAndSamples(t *testing.T) {
	for _, pool := range []bool{false, true} {
		args := []string{"-n=4", "-repeats=2", "-stages=groupCompareTrueFirst,groupCompareTrueLast,groupCompareFalse",
			"-endpoint=native=ldap://localhost:2389", "-endpoint=before=ldap://localhost:3389"}
		if pool {
			args = append(args, "-people=ou=people,dc=fixture", "-uid=scale-000777")
		}
		c := testOptions(t, args...)
		f := buildFixture(c, "compare", "password")
		for _, b := range benchmarks(c, f) {
			t.Run(fmt.Sprintf("%s/%d/pool=%t", b.name, len(b.group.GetAttributeValues("member")), pool), func(t *testing.T) {
				methods := map[string]string{
					"groupCompareTrueFirst": "compare_member_true_first",
					"groupCompareTrueLast":  "compare_member_true_last",
					"groupCompareFalse":     "compare_member_false_missing",
				}
				if b.method != methods[b.name] {
					t.Fatalf("unexpected method %q", b.method)
				}
				members := b.group.GetAttributeValues("member")
				want := b.name != "groupCompareFalse"
				value := f.users[0].DN
				if b.name == "groupCompareTrueLast" {
					if pool {
						value = scaleEntry(c, fmt.Sprintf("scale-%06d", len(members)-8)).DN
					} else {
						value = f.users[len(members)-1].DN
					}
				} else if !want {
					value = "uid=ldapbench-absent," + f.runDN
					if slices.ContainsFunc(f.entries, func(e *ldap.Entry) bool { return sameDN(e.DN, value) }) {
						t.Fatal("absent assertion must not name a fixture entry")
					}
				}
				if slices.ContainsFunc(members, func(dn string) bool { return sameDN(dn, value) }) != want {
					t.Fatal("assertion presence differs from expected Compare boolean")
				}
				for repeat := range c.Repeats {
					var order []int
					var conns []client
					calls, checks := make([]int, len(c.Endpoints)), make([]int, len(c.Endpoints))
					for i := range c.Endpoints {
						c.Endpoints[i].root = &fakeClient{bind: func(string, string) error {
							t.Fatal("group Compare must never bind the root connection")
							return nil
						}}
						conn := &fakeClient{}
						conn.bind = func(dn, password string) error {
							if dn != f.users[0].DN || password != f.password {
								t.Fatal("group Compare must bind groupBase's nonroot account")
							}
							return nil
						}
						conn.whoAmI = func() (*ldap.WhoAmIResult, error) {
							if checks[i] != calls[i] {
								t.Fatal("identity must be checked before operations and after each Compare")
							}
							checks[i]++
							return &ldap.WhoAmIResult{AuthzID: "dn:" + strings.ToUpper(conn.dn)}, nil
						}
						conn.compare = func(dn, attribute, gotValue string) (bool, error) {
							if dn != b.group.DN || attribute != "member" || gotValue != value || conn.dn != f.users[0].DN {
								t.Fatalf("unexpected nonroot Compare(%q, %q, %q), identity=%q", dn, attribute, gotValue, conn.dn)
							}
							calls[i]++
							order = append(order, i)
							return want, nil
						}
						conns = append(conns, conn)
					}
					var r report
					if err := measure(t.Context(), c, f, b, repeat, conns, &r); err != nil {
						t.Fatal(err)
					}
					var wantOrder []int
					for iteration := range c.N {
						for offset := range len(conns) {
							wantOrder = append(wantOrder, (iteration+repeat+offset)%len(conns))
						}
					}
					if !slices.Equal(order, wantOrder) || len(r.Samples) != len(c.Endpoints) {
						t.Fatalf("endpoint rotation/sample count mismatch: order=%v samples=%d", order, len(r.Samples))
					}
					for i, row := range r.Samples {
						if row.Endpoint != c.Endpoints[i].Name || row.Stage != b.name || row.Method != b.method || row.RootBindDN != "" ||
							row.Members != len(members) || row.Repeat != repeat+1 || row.Operations != c.N || row.Completed != c.N ||
							row.Requests != c.N || row.VerificationRequests != 2+c.N || len(row.LatencyMS) != c.N || calls[i] != c.N || checks[i] != 1+c.N {
							t.Fatalf("incorrect group Compare sample: %+v", row)
						}
						var total float64
						for _, ms := range row.LatencyMS {
							total += ms
						}
						if total != row.TotalMS {
							t.Fatal("total must sum only this endpoint's timed SDK Compare calls")
						}
					}
				}
			})
		}
	}
}

func TestGroupCompareFailuresKeepPartialCounts(t *testing.T) {
	sdkErr := errors.New("Compare SDK failure")
	for _, stage := range []string{"groupCompareTrueFirst", "groupCompareTrueLast", "groupCompareFalse"} {
		for _, failure := range []string{"boolean", "SDK", "identity", "prepare identity", "permission"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				c := testOptions(t, "-n=3", "-group-sizes=10", "-stages="+stage)
				f := buildFixture(c, "failure", "password")
				calls := 0
				want := stage != "groupCompareFalse"
				conn := &fakeClient{}
				conn.compare = func(string, string, string) (bool, error) {
					calls++
					if calls == 2 {
						switch failure {
						case "boolean":
							return !want, nil
						case "SDK":
							return want, sdkErr
						case "permission":
							return false, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
						}
					}
					return want, nil
				}
				conn.whoAmI = func() (*ldap.WhoAmIResult, error) {
					dn := conn.dn
					if failure == "prepare identity" || (failure == "identity" && calls == 2) {
						dn = c.RootBindDN
					}
					return &ldap.WhoAmIResult{AuthzID: "dn:" + dn}, nil
				}
				var r report
				err := measure(t.Context(), c, f, benchmarks(c, f)[0], 0, []client{conn}, &r)
				if err == nil || (failure == "SDK" && !errors.Is(err, sdkErr)) ||
					(failure == "permission" && !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights)) ||
					(strings.Contains(failure, "identity") && !strings.Contains(err.Error(), "identity")) {
					t.Fatalf("expected %s failure, got %v", failure, err)
				}
				operations, completed, verification := 2, 1, 3
				if failure == "prepare identity" {
					operations, completed, verification = 0, 0, 2
				} else if failure == "identity" {
					verification++
				}
				row := r.Samples[0]
				if row.Operations != operations || row.Requests != operations || calls != operations || row.Completed != completed ||
					len(row.LatencyMS) != completed || row.VerificationRequests != verification || row.RootBindDN != "" {
					t.Fatalf("failure must preserve counts without root retry: %+v", row)
				}
			})
		}
	}
}
