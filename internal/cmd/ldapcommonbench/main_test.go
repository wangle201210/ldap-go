package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func testArgs() []string {
	return []string{"-setup-disposable", "-endpoint=go=ldap://127.0.0.1:1389", "-base=dc=fixture", "-root-bind-dn=cn=admin,dc=fixture", "-root-password-env=ROOT_SECRET"}
}

func testLookup(name string) (string, bool) {
	return "root-test-secret", name == "ROOT_SECRET"
}

func testOptions(t *testing.T, args ...string) options {
	t.Helper()
	c, err := parseOptions(append(testArgs(), args...), testLookup, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOptions(t *testing.T) {
	c := testOptions(t, "-endpoint=native=ldaps://127.0.0.1:1636", "-stages=base,equality", "-n=7", "-repeats=2")
	if len(c.Endpoints) != 2 || c.N != 7 || c.Repeats != 2 || !slices.Equal(c.Stages, []string{"nonrootBase", "nonrootEquality"}) {
		t.Fatalf("unexpected parsed options: %+v", c)
	}
	encoded, err := json.Marshal(c)
	if err != nil || bytes.Contains(encoded, []byte(c.password)) {
		t.Fatal("options must serialize without passwords")
	}
	if one := testOptions(t); len(one.Endpoints) != 1 || !slices.Equal(one.GroupSizes, []int{10, 1000}) {
		t.Fatal("single endpoint and default group sizes must work")
	}
	for _, args := range [][]string{
		{"-setup-disposable=false"}, {"-endpoint=bad"}, {"-endpoint=x=http://localhost"},
		{"-endpoint=x=ldap://user:secret@localhost"}, {"-endpoint=x=ldap://localhost/dc=x"},
		{"-endpoint=x=ldap://localhost/?uid"}, {"-endpoint=x=ldap://localhost/#fragment"},
		{"-endpoint=x=ldap://localhost:65536"}, {"-endpoint=x=ldap://localhost:0"},
		{"-endpoint=go=ldap://localhost:2389"}, {"-endpoint=duplicate=ldap://127.0.0.1:1389"},
		{"-base="}, {"-base=invalid"}, {"-base=cn=config"}, {"-base=cn=database,cn=config"},
		{"-root-bind-dn="}, {"-root-password-env="}, {"-root-password-env=UNKNOWN"},
		{"-root-password=secret"}, {"-stages="}, {"-stages=all,base"}, {"-stages=scan"},
		{"-stages=base,nonrootBase"}, {"-n=0"}, {"-n=100001"}, {"-repeats=0"}, {"-repeats=101"},
		{"-timeout=0"}, {"-timeout=6m"}, {"-group-sizes=7"}, {"-group-sizes=10,10"},
		{"-group-sizes="}, {"-group-sizes=10001"}, {"-people=ou=people,dc=other"},
		{"-people=invalid"}, {"-people=dc=fixture"}, {"-uid=scale-000001"},
		{"-entries=0"}, {"-entries=1000000"}, {"-people=ou=people,dc=fixture", "-entries=100"},
		{"positional"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseOptions(append(testArgs(), args...), testLookup, io.Discard); err == nil {
				t.Fatal("expected argument rejection")
			}
		})
	}
	if _, err := parseOptions(testArgs()[2:], testLookup, io.Discard); err == nil {
		t.Fatal("missing endpoint/opt-in must fail")
	}
	if _, err := parseOptions(testArgs(), func(string) (string, bool) { return "", true }, io.Discard); err == nil {
		t.Fatal("empty root password must fail")
	}
}

func TestFixtureMembersAndCredentials(t *testing.T) {
	c := testOptions(t)
	f := buildFixture(c, "testtoken", "user-test-secret")
	if len(f.users) != 1000 || len(f.groups) != 5 || len(f.entries) != 1006 || len(f.pool) != 0 {
		t.Fatalf("unexpected fixture sizes: users=%d groups=%d entries=%d pool=%d", len(f.users), len(f.groups), len(f.entries), len(f.pool))
	}
	base, _ := ldap.ParseDN(f.runDN)
	known := make(map[string]bool)
	for _, entry := range f.entries {
		dn, err := ldap.ParseDN(entry.DN)
		if err != nil || known[entry.DN] || (!base.EqualFold(dn) && !base.AncestorOfFold(dn)) {
			t.Fatalf("duplicate, invalid or unowned DN %q", entry.DN)
		}
		known[entry.DN] = true
	}
	for i, group := range f.groups {
		members := group.GetAttributeValues("member")
		if i < f.direct && len(members) != c.GroupSizes[i] {
			t.Fatal("group member count differs from requested size")
		}
		seen := make(map[string]bool)
		for _, member := range members {
			if seen[member] || !known[member] {
				t.Fatalf("duplicate or unresolved member %q", member)
			}
			seen[member] = true
		}
	}
	stored := f.users[0].GetAttributeValue("userPassword")
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, "{SSHA}"))
	if err != nil || len(raw) <= sha1.Size || !strings.HasPrefix(stored, "{SSHA}") {
		t.Fatalf("invalid SSHA fixture: %v", err)
	}
	digest := sha1.Sum(append([]byte(f.password), raw[sha1.Size:]...))
	if !bytes.Equal(raw[:sha1.Size], digest[:]) || f.users[1].GetAttributeValue("userPassword") != f.password {
		t.Fatal("SSHA and plaintext Bind accounts must have the generated password")
	}
	b := benchmarks(c, f)
	if b[0].method != "simple_bind_ssha" || b[1].method != "simple_bind_plaintext" || b[0].user.DN == b[1].user.DN {
		t.Fatal("Bind methods must identify separate storage formats/accounts")
	}
	other := buildFixture(c, "othertoken", "other-secret")
	if sameDN(f.runDN, other.runDN) || f.users[0].GetAttributeValue("uid") == other.users[0].GetAttributeValue("uid") {
		t.Fatal("run tokens must isolate both DNs and equality keys")
	}
}

func TestProfileFixtureAndOptionalPool(t *testing.T) {
	c := testOptions(t, "-stages=base,equality")
	f := buildFixture(c, "profile", "password")
	if len(f.entries) != 9 || len(f.users) != 8 || len(f.groups) != 0 || len(f.pool) != 0 {
		t.Fatal("Base/equality selection must omit all group fixtures and pool validation")
	}
	c = testOptions(t, "-people=ou=people,dc=fixture", "-n=100")
	f = buildFixture(c, "seed", "password")
	if len(f.users) != 8 || len(f.pool) != 992 || len(f.entries) != 14 {
		t.Fatal("explicit seed pool should replace only the extra member users")
	}
	if f.pool[0].GetAttributeValue("uid") != "scale-000001" || f.pool[991].GetAttributeValue("uid") != "scale-000992" {
		t.Fatal("pool references must be contiguous and distinct")
	}
	if target(c, f, 0).GetAttributeValue("uid") != "scale-000001" || target(c, f, 99).GetAttributeValue("uid") != "scale-100000" {
		t.Fatal("existing equality sampling must cover both pool boundaries")
	}
	c.UID = "literal*)(uid=*)"
	entry := target(c, f, 23)
	if entry.GetAttributeValue("uid") != c.UID {
		t.Fatal("fixed UID must override sampling")
	}
	if dn, err := ldap.ParseDN(entry.DN); err != nil || dn.RDNs[0].Attributes[0].Value != c.UID {
		t.Fatal("fixed UID must be DN-escaped")
	}
}

func TestExactAssertions(t *testing.T) {
	want := []*ldap.Entry{ldap.NewEntry("cn=group,dc=fixture", map[string][]string{"member": {"uid=one,dc=fixture", "uid=two,dc=fixture"}})}
	valid := &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("CN=GROUP,DC=FIXTURE", map[string][]string{"MEMBER": {"UID=TWO,DC=FIXTURE", "uid=one,dc=fixture"}})}}
	if err := assertEntries(valid, want); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]*ldap.SearchResult{
		"nil":               nil,
		"empty":             {},
		"referral":          {Entries: valid.Entries, Referrals: []string{"ldap://elsewhere"}},
		"duplicate entry":   {Entries: append(slices.Clone(valid.Entries), valid.Entries...)},
		"nil entry":         {Entries: []*ldap.Entry{nil}},
		"wrong DN":          {Entries: []*ldap.Entry{ldap.NewEntry("cn=other,dc=fixture", map[string][]string{"member": want[0].GetAttributeValues("member")})}},
		"missing attribute": {Entries: []*ldap.Entry{ldap.NewEntry(want[0].DN, nil)}},
		"wrong count":       {Entries: []*ldap.Entry{ldap.NewEntry(want[0].DN, map[string][]string{"member": {"uid=one,dc=fixture"}})}},
		"wrong member":      {Entries: []*ldap.Entry{ldap.NewEntry(want[0].DN, map[string][]string{"member": {"uid=one,dc=fixture", "uid=other,dc=fixture"}})}},
		"duplicate member":  {Entries: []*ldap.Entry{ldap.NewEntry(want[0].DN, map[string][]string{"member": {"uid=one,dc=fixture", "UID=ONE,DC=fixture"}})}},
		"invalid DN value":  {Entries: []*ldap.Entry{ldap.NewEntry(want[0].DN, map[string][]string{"member": {"uid=one,dc=fixture", "invalid"}})}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := assertEntries(got, want); err == nil {
				t.Fatal("corrupt result accepted")
			}
		})
	}
	if err := assertValues([]string{"UPPER"}, []string{"upper"}, false); err == nil {
		t.Fatal("ordinary attribute data must be exact")
	}
}

func TestProfileRequestShapes(t *testing.T) {
	for _, pool := range []bool{false, true} {
		args := []string{"-stages=base,equality", "-n=1"}
		if pool {
			args = append(args, "-people=ou=people,dc=fixture", "-uid=literal*)(uid=*)")
		}
		c := testOptions(t, args...)
		f := buildFixture(c, "profile", "password")
		entry := target(c, f, 0)
		for _, b := range benchmarks(c, f) {
			t.Run(fmt.Sprintf("%s/pool=%v", b.name, pool), func(t *testing.T) {
				calls := 0
				conn := &fakeClient{search: func(q *ldap.SearchRequest) (*ldap.SearchResult, error) {
					calls++
					base, scope, filter := entry.DN, ldap.ScopeBaseObject, "(objectClass=*)"
					attrs := []string{"uid", "cn", "sn"}
					if pool {
						attrs = []string{"uid"}
					}
					if b.name == "nonrootEquality" {
						base, scope = c.Base, ldap.ScopeWholeSubtree
						if pool {
							base = c.People
						}
						filter = "(uid=" + ldap.EscapeFilter(entry.GetAttributeValue("uid")) + ")"
					}
					if q.BaseDN != base || q.Scope != scope || q.Filter != filter || !slices.Equal(q.Attributes, attrs) || len(q.Controls) != 0 || q.SizeLimit != 2 || q.DerefAliases != ldap.NeverDerefAliases {
						t.Fatalf("unexpected profile query: %+v", q)
					}
					if _, err := ldap.CompileFilter(q.Filter); err != nil {
						t.Fatalf("invalid escaped filter: %v", err)
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
				}}
				var r report
				if err := measure(t.Context(), c, f, b, 0, []client{conn}, &r); err != nil || calls != 1 || r.Samples[0].Requests != 1 || r.Samples[0].VerificationRequests != 3 {
					t.Fatalf("profile must use one exact request: calls=%d error=%v", calls, err)
				}
			})
		}
	}
}

// No sockets or server implementation: these tests supply SDK replies directly.
type fakeClient struct {
	client
	dn         string
	retainBind bool
	bind       func(string, string) error
	whoAmI     func() (*ldap.WhoAmIResult, error)
	search     func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	compare    func(string, string, string) (bool, error)
	del        func(*ldap.DelRequest) error
}

func (f *fakeClient) Bind(dn, password string) error {
	if f.bind != nil {
		if err := f.bind(dn, password); err != nil {
			return err
		}
	}
	if strings.HasSuffix(password, "-wrong") {
		if !f.retainBind {
			f.dn = ""
		}
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("wrong password"))
	}
	f.dn = dn
	return nil
}

func (f *fakeClient) WhoAmI([]ldap.Control) (*ldap.WhoAmIResult, error) {
	if f.whoAmI != nil {
		return f.whoAmI()
	}
	id := ""
	if f.dn != "" {
		id = "dn:" + f.dn
	}
	return &ldap.WhoAmIResult{AuthzID: id}, nil
}

func (f *fakeClient) Search(q *ldap.SearchRequest) (*ldap.SearchResult, error) { return f.search(q) }
func (f *fakeClient) Del(q *ldap.DelRequest) error                             { return f.del(q) }

func (f *fakeClient) Compare(dn, attribute, value string) (bool, error) {
	return f.compare(dn, attribute, value)
}

func TestTimedClientDelegatesAndCountsCallsIncludingErrors(t *testing.T) {
	query := ldap.NewSearchRequest("dc=fixture", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 2, 0, false, "(objectClass=*)", []string{"uid"}, nil)
	result := &ldap.SearchResult{}
	sdkErr := errors.New("SDK search failure")
	var searchErr error
	conn := &fakeClient{search: func(got *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if got != query {
			t.Fatal("Search must receive the original request")
		}
		return result, searchErr
	}}
	timed := &timedClient{client: conn}
	if err := timed.Bind("uid=user,dc=fixture", "password"); err != nil || conn.dn != "uid=user,dc=fixture" || timed.requests != 1 {
		t.Fatalf("Bind delegation: %v, requests=%d", err, timed.requests)
	}
	if err := timed.Bind(conn.dn, "password-wrong"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || conn.dn != "" || timed.requests != 2 {
		t.Fatalf("failed Bind delegation: %v, requests=%d", err, timed.requests)
	}
	for i, err := range []error{nil, sdkErr} {
		searchErr = err
		got, gotErr := timed.Search(query)
		if got != result || !errors.Is(gotErr, err) || timed.requests != 3+i {
			t.Fatalf("Search changed outcome or count: %p, %v, %d", got, gotErr, timed.requests)
		}
	}
	for i, tc := range []struct {
		result bool
		err    error
	}{{true, nil}, {false, nil}, {false, sdkErr}} {
		conn.compare = func(dn, attribute, value string) (bool, error) {
			if dn != query.BaseDN || attribute != "uid" || value != "ldapbench-absent" {
				t.Fatal("Compare must receive the original arguments")
			}
			return tc.result, tc.err
		}
		got, err := timed.Compare(query.BaseDN, "uid", "ldapbench-absent")
		if got != tc.result || !errors.Is(err, tc.err) || timed.requests != 5+i {
			t.Fatalf("Compare changed outcome or count: %t, %v, %d", got, err, timed.requests)
		}
	}
	elapsed := timed.elapsed
	if elapsed <= 0 {
		t.Fatal("SDK calls must record elapsed time")
	}
	if err := identity(timed, ""); err != nil {
		t.Fatal(err)
	}
	if err := assertEntries(result, []*ldap.Entry{ldap.NewEntry(query.BaseDN, map[string][]string{"uid": {"user"}})}); err == nil {
		t.Fatal("timing must not suppress result assertions")
	}
	if timed.requests != 7 || timed.elapsed != elapsed {
		t.Fatal("WhoAmI and local assertions must not change measured time/counts")
	}
}

func TestRootOptionsAndSampling(t *testing.T) {
	wantDefaults := []string{"userBind", "userBindWrong", "nonrootBase", "nonrootEquality", "memberEquality", "groupBase", "nestedMembership"}
	for _, args := range [][]string{nil, {"-stages=all"}} {
		if c := testOptions(t, args...); !slices.Equal(c.Stages, wantDefaults) {
			t.Fatalf("default stages changed: %v", c.Stages)
		}
	}
	c := testOptions(t, "-stages="+strings.Join(rootStageNames, ","), "-people=ou=people,dc=fixture", "-root-bind-dn=CN=ADMIN,DC=FIXTURE")
	if c.RootBindDN != "CN=ADMIN,DC=FIXTURE" || !slices.Equal(c.Stages, rootStageNames) {
		t.Fatal("root stages and literal client DN must be preserved")
	}
	f := buildFixture(c, "root", "password")
	if len(f.entries) != 9 || len(f.pool) != 0 || needsGroups(c) {
		t.Fatal("root-only selection must keep the disposable OU/eight-user flow without groups")
	}
	testOptions(t, "-stages=rootBind,rootBase")
	for _, args := range [][]string{
		{"-stages=rootEquality"}, {"-stages=rootCompareTrue"}, {"-stages=rootCompareFalse"},
		{"-stages=rootBind,rootBind"}, {"-stages=rootBind", "-setup-disposable=false"},
	} {
		if _, err := parseOptions(append(testArgs(), args...), testLookup, io.Discard); err == nil {
			t.Fatalf("expected rejection: %v", args)
		}
	}
	for _, tc := range []struct {
		n, entries int
		want       []string
	}{
		{4, 100000, []string{"scale-000001", "scale-033334", "scale-066667", "scale-100000", "scale-000001"}},
		{1, 100000, []string{"scale-000001", "scale-000001"}},
		{4, 2, []string{"scale-000001", "scale-000002", "scale-000001", "scale-000002"}},
		{4, 1, []string{"scale-000001", "scale-000001"}},
	} {
		c.N, c.Entries = tc.n, tc.entries
		for i, want := range tc.want {
			if got := sampleUID(c, i); got != want {
				t.Fatalf("N=%d entries=%d iteration=%d: %s, want %s", c.N, c.Entries, i, got, want)
			}
		}
	}
}

func TestRootStagesRequestShapesIdentityAndRotation(t *testing.T) {
	for _, rootDN := range []string{"cn=admin,dc=fixture", "CN=ADMIN,DC=FIXTURE"} {
		c := testOptions(t, "-n=4", "-repeats=2", "-stages="+strings.Join(rootStageNames, ",")+",nonrootBase",
			"-people=ou=people,dc=fixture", "-uid=scale-000007", "-root-bind-dn="+rootDN,
			"-endpoint=native=ldap://localhost:2389", "-endpoint=before=ldap://localhost:3389")
		f := buildFixture(c, "root", "password")
		methods := []string{"simple_bind_root", "base_objectclass_root", "subtree_uid_equality_root", "compare_uid_true_root", "compare_uid_false_root", "search_nonrootBase"}
		for index, b := range benchmarks(c, f) {
			t.Run(rootDN+"/"+b.name, func(t *testing.T) {
				if b.method != methods[index] {
					t.Fatalf("method label = %q, want %q", b.method, methods[index])
				}
				for repeat := range c.Repeats {
					var order []int
					var conns []client
					for i := range c.Endpoints {
						iteration, binds := 0, 0
						conn := &fakeClient{}
						conn.bind = func(dn, password string) error {
							if dn != rootDN || password != c.password {
								t.Fatal("root Bind must send the exact supplied DN and root password")
							}
							if b.name == "rootBind" && binds > 0 {
								order = append(order, i)
							}
							binds++
							return nil
						}
						conn.whoAmI = func() (*ldap.WhoAmIResult, error) {
							return &ldap.WhoAmIResult{AuthzID: "dn:" + strings.ToLower(conn.dn)}, nil
						}
						conn.search = func(q *ldap.SearchRequest) (*ldap.SearchResult, error) {
							order = append(order, i)
							uid := []string{"scale-000001", "scale-033334", "scale-066667", "scale-100000"}[iteration]
							iteration++
							base, scope, filter, attrs := c.Base, ldap.ScopeBaseObject, "(objectClass=*)", []string{"objectClass"}
							entry := ldap.NewEntry(strings.ToUpper(c.Base), map[string][]string{"OBJECTCLASS": {"top", "domain"}})
							if b.name == "rootEquality" {
								base, scope, filter, attrs = c.People, ldap.ScopeWholeSubtree, "(uid="+uid+")", []string{"uid"}
								entry = scaleEntry(c, uid)
							}
							if q.BaseDN != base || q.Scope != scope || q.Filter != filter || !slices.Equal(q.Attributes, attrs) ||
								q.SizeLimit != 2 || q.TimeLimit != 0 || q.TypesOnly || q.DerefAliases != ldap.NeverDerefAliases || len(q.Controls) != 0 {
								t.Fatalf("root request differs from fast-probe SDK call: %+v", q)
							}
							return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
						}
						conn.compare = func(dn, attribute, value string) (bool, error) {
							order = append(order, i)
							uid := []string{"scale-000001", "scale-033334", "scale-066667", "scale-100000"}[iteration]
							iteration++
							want := uid
							if b.name == "rootCompareFalse" {
								want = "ldapbench-absent"
							}
							if dn != "uid="+uid+","+c.People || attribute != "uid" || value != want {
								t.Fatalf("unexpected Compare(%q, %q, %q)", dn, attribute, value)
							}
							return b.name == "rootCompareTrue", nil
						}
						c.Endpoints[i].root = conn
						conns = append(conns, &fakeClient{
							bind: func(dn, password string) error {
								if b.root || dn != f.users[0].DN || password != f.password {
									t.Fatal("root stage used nonroot connection or nonroot credentials changed")
								}
								return nil
							},
							search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
								order = append(order, i)
								return &ldap.SearchResult{Entries: []*ldap.Entry{target(c, f, 0)}}, nil
							},
						})
					}
					var r report
					if err := measure(t.Context(), c, f, b, repeat, conns, &r); err != nil {
						t.Fatal(err)
					}
					var want []int
					for iteration := range c.N {
						for offset := range len(conns) {
							want = append(want, (iteration+repeat+offset)%len(conns))
						}
					}
					if !slices.Equal(order, want) {
						t.Fatalf("request rotation = %v, want %v", order, want)
					}
					for i, row := range r.Samples {
						wantDN := ""
						if b.root {
							wantDN = rootDN
						}
						if row.Endpoint != c.Endpoints[i].Name || row.Stage != b.name || row.Method != b.method || row.RootBindDN != wantDN || row.Repeat != repeat+1 ||
							row.Members != 0 || row.Operations != c.N || row.Completed != c.N || row.Requests != c.N || row.VerificationRequests != 2+c.N || len(row.LatencyMS) != c.N {
							t.Fatalf("incorrect root/nonroot sample or verification counts: %+v", row)
						}
						var total float64
						for _, ms := range row.LatencyMS {
							total += ms
						}
						if total != row.TotalMS {
							t.Fatal("samples must contain only this endpoint's timed SDK calls")
						}
					}
				}
			})
		}
	}
}

func TestRootStageFailuresKeepPartialCounts(t *testing.T) {
	sdkErr := errors.New("SDK failure")
	for _, tc := range []struct {
		name, stage string
		result      *ldap.SearchResult
		err         error
	}{
		{"bind error", "rootBind", nil, sdkErr},
		{"bind identity mismatch", "rootBind", nil, nil},
		{"nil base", "rootBase", nil, nil},
		{"base SDK error", "rootBase", nil, sdkErr},
		{"missing base", "rootBase", &ldap.SearchResult{}, nil},
		{"nil base entry", "rootBase", &ldap.SearchResult{Entries: []*ldap.Entry{nil}}, nil},
		{"base referral", "rootBase", &ldap.SearchResult{Referrals: []string{"ldap://other"}}, nil},
		{"wrong base DN", "rootBase", &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("dc=other", map[string][]string{"objectClass": {"domain"}})}}, nil},
		{"missing objectClass", "rootBase", &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("dc=fixture", nil)}}, nil},
		{"missing UID", "rootEquality", &ldap.SearchResult{}, nil},
		{"compare true mismatch", "rootCompareTrue", nil, nil},
		{"compare false mismatch", "rootCompareFalse", nil, nil},
		{"compare SDK error", "rootCompareTrue", nil, sdkErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testOptions(t, "-n=2", "-stages="+tc.stage, "-people=ou=people,dc=fixture", "-root-bind-dn=CN=ADMIN,DC=FIXTURE")
			f := buildFixture(c, "failure", "password")
			binds := 0
			c.Endpoints[0].root = &fakeClient{
				bind: func(string, string) error {
					binds++
					if binds > 1 {
						return tc.err
					}
					return nil
				},
				whoAmI: func() (*ldap.WhoAmIResult, error) {
					dn := "cn=admin,dc=fixture"
					if binds > 1 {
						dn = "cn=other,dc=fixture"
					}
					return &ldap.WhoAmIResult{AuthzID: "dn:" + dn}, nil
				},
				search:  func(*ldap.SearchRequest) (*ldap.SearchResult, error) { return tc.result, tc.err },
				compare: func(string, string, string) (bool, error) { return tc.stage == "rootCompareFalse", tc.err },
			}
			var r report
			err := measure(t.Context(), c, f, benchmarks(c, f)[0], 0, nil, &r)
			if err == nil || (tc.err != nil && !errors.Is(err, tc.err)) {
				t.Fatalf("expected assertion/SDK failure, got %v", err)
			}
			row := r.Samples[0]
			verification := 2
			if tc.name == "bind identity mismatch" {
				verification++
			}
			if row.Operations != 1 || row.Requests != 1 || row.Completed != 0 || len(row.LatencyMS) != 0 || row.VerificationRequests != verification {
				t.Fatalf("failed root operation must retain partial counts: %+v", row)
			}
		})
	}
}

func fixtureSearch(t *testing.T, f fixture, q *ldap.SearchRequest) (*ldap.SearchResult, error) {
	t.Helper()
	var entries []*ldap.Entry
	switch {
	case q.Scope == ldap.ScopeBaseObject:
		for _, entry := range f.entries {
			if sameDN(entry.DN, q.BaseDN) {
				entries = append(entries, project(entry, q.Attributes...))
			}
		}
	case strings.HasPrefix(q.Filter, "(uid="):
		for _, entry := range f.users {
			if q.Filter == "(uid="+ldap.EscapeFilter(entry.GetAttributeValue("uid"))+")" {
				entries = append(entries, project(entry, q.Attributes...))
			}
		}
	case strings.HasPrefix(q.Filter, "(member="):
		if !sameDN(q.BaseDN, f.runDN) || q.Scope != ldap.ScopeWholeSubtree || !slices.Equal(q.Attributes, []string{"cn"}) {
			t.Fatal("membership query changed scope or projection")
		}
		for _, group := range f.groups {
			for _, member := range group.GetAttributeValues("member") {
				key, _ := valuesKey(member, true)
				if q.Filter == "(member="+ldap.EscapeFilter(key)+")" {
					entries = append(entries, project(group, q.Attributes...))
				}
			}
		}
	default:
		t.Fatalf("unexpected query %q", q.Filter)
	}
	// LDAP sets need not preserve insertion order.
	slices.Reverse(entries)
	return &ldap.SearchResult{Entries: entries}, nil
}

func TestTraversalCycleAndRequestRotation(t *testing.T) {
	c := testOptions(t, "-n=8", "-repeats=2", "-group-sizes=10", "-stages=nestedMembership", "-endpoint=native=ldap://localhost:2389", "-endpoint=before=ldap://localhost:3389")
	f := buildFixture(c, "cycle", "password")
	var order []int
	var conns []client
	for i := range c.Endpoints {
		conns = append(conns, &fakeClient{search: func(q *ldap.SearchRequest) (*ldap.SearchResult, error) {
			order = append(order, i)
			return fixtureSearch(t, f, q)
		}})
	}
	var r report
	for repeat := range c.Repeats {
		if err := measure(t.Context(), c, f, benchmarks(c, f)[0], repeat, conns, &r); err != nil {
			t.Fatal(err)
		}
	}
	// First three users reach all four groups (5 requests); others reach one (2).
	for _, row := range r.Samples {
		if row.Operations != 8 || row.Completed != 8 || row.Requests != 25 || len(row.LatencyMS) != 8 || row.VerificationRequests != 27 {
			t.Fatalf("unexpected counters: %+v", row)
		}
		var total float64
		for _, ms := range row.LatencyMS {
			total += ms
		}
		if diff := total - row.TotalMS; diff < -0.000001 || diff > 0.000001 {
			t.Fatal("nested samples must sum request time without interleaved endpoint waits")
		}
	}
	var want []int
	for repeat := range c.Repeats {
		for iteration := range c.N {
			steps := 2
			if iteration%8 < 3 {
				steps = 5
			}
			for step := range steps {
				for offset := range len(conns) {
					want = append(want, (iteration+repeat+step+offset)%len(conns))
				}
			}
		}
	}
	if !slices.Equal(order, want) {
		t.Fatalf("endpoint request rotation = %v, want %v", order, want)
	}
}

func TestStagesBindingStateAndPartialFailures(t *testing.T) {
	c := testOptions(t, "-n=2", "-group-sizes=10")
	f := buildFixture(c, "stages", "password")
	for _, b := range benchmarks(c, f) {
		t.Run(b.name+"/"+b.method, func(t *testing.T) {
			conn := &fakeClient{search: func(q *ldap.SearchRequest) (*ldap.SearchResult, error) { return fixtureSearch(t, f, q) }}
			var r report
			if err := measure(t.Context(), c, f, b, 0, []client{conn}, &r); err != nil {
				t.Fatal(err)
			}
			row := r.Samples[0]
			if row.Completed != c.N || len(row.LatencyMS) != c.N {
				t.Fatalf("incomplete samples: %+v", row)
			}
			if b.name == "userBindWrong" && (conn.dn != "" || row.VerificationRequests != 2+3*c.N) {
				t.Fatal("wrong Bind must start authenticated and finish anonymous on every request")
			}
		})
	}
	c.Stages = []string{"userBindWrong"}
	var r report
	err := measure(t.Context(), c, f, benchmarks(c, f)[0], 0, []client{&fakeClient{retainBind: true}}, &r)
	if err == nil || !strings.Contains(err.Error(), "identity") || r.Samples[0].Completed != 0 || r.Samples[0].Requests != 1 {
		t.Fatalf("retained credentials must fail with partial counts: %v", err)
	}
	c.Stages = []string{"memberEquality"}
	r = report{}
	err = measure(t.Context(), c, f, benchmarks(c, f)[0], 0, []client{&fakeClient{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) { return &ldap.SearchResult{}, nil }}}, &r)
	if err == nil || r.Samples[0].Completed != 0 || r.Samples[0].Requests != 1 {
		t.Fatalf("missing groups must fail immediately: %v", err)
	}
}

func TestCleanupOwnershipOrderAndFailures(t *testing.T) {
	c := testOptions(t, "-stages=base")
	f := buildFixture(c, "cleanup", "password")
	dns := []string{f.runDN, f.users[0].DN, f.users[1].DN}
	for _, failure := range []string{"", "ownership", "delete", "absence"} {
		t.Run(failure, func(t *testing.T) {
			var deleted []string
			conn := &fakeClient{
				search: func(q *ldap.SearchRequest) (*ldap.SearchResult, error) {
					if q.Attributes[0] == "description" {
						entry := project(f.entries[0], "description")
						if failure == "ownership" {
							entry = ldap.NewEntry(f.runDN, map[string][]string{"description": {"another-owner"}})
						}
						return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
					}
					if failure == "absence" {
						return &ldap.SearchResult{}, nil
					}
					return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
				},
				del: func(q *ldap.DelRequest) error {
					deleted = append(deleted, q.DN)
					if q.DN == f.users[1].DN {
						return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("uncommitted Add"))
					}
					if failure == "delete" && q.DN == f.users[0].DN {
						return errors.New("delete failed")
					}
					return nil
				},
			}
			err := cleanup(conn, f, dns)
			if (err != nil) != (failure != "") {
				t.Fatalf("cleanup error = %v", err)
			}
			if failure == "ownership" {
				if len(deleted) != 0 {
					t.Fatal("unowned fixture must never be deleted")
				}
			} else if !slices.Equal(deleted, []string{f.users[1].DN, f.users[0].DN, f.runDN}) {
				t.Fatalf("cleanup must continue and delete children before OU: %v", deleted)
			}
		})
	}
}

func TestExecuteExitAndJSONWithoutNetworking(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		args []string
		code int
	}{
		{nil, 2},
		{append(testArgs(), "-stages=base,equality"), 1},
		{[]string{"-help"}, 0},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			var out bytes.Buffer
			if code := execute(ctx, tc.args, testLookup, &out, io.Discard); code != tc.code {
				t.Fatalf("exit = %d, want %d", code, tc.code)
			}
			if tc.code == 0 {
				return
			}
			var r report
			if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Error == "" || len(r.Samples) != 0 || r.SetupAdds != 0 {
				t.Fatalf("unexpected failure report: %s (%v)", out.Bytes(), err)
			}
			if bytes.Contains(out.Bytes(), []byte("root-test-secret")) {
				t.Fatal("failure JSON contains credentials")
			}
		})
	}
}
