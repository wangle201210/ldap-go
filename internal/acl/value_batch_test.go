package acl

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestPolicyCanBatchValuesProof(t *testing.T) {
	t.Parallel()

	var absent *Policy
	if absent.CanBatchValues() {
		t.Fatal("nil policy is not a batching proof")
	}
	if !DefaultPolicy().CanBatchValues() || !(&Policy{
		databases: []databaseRules{{Suffix: staticDN("dc=example,dc=com")}},
	}).CanBatchValues() {
		t.Fatal("empty rules should permit batching")
	}

	for _, test := range []struct {
		name string
		raw  string
		want bool
	}{
		{"any", `to * by * read`, true},
		{"anonymous", `to * by anonymous auth`, true},
		{"users", `to * by users read`, true},
		{"self", `to * by self read`, true},
		{"real self", `to * by realself read`, true},
		{"DN", `to * by dn.subtree="dc=example,dc=com" read`, true},
		{"real DN", `to * by realdn.exact="uid=alice,dc=example,dc=com" read`, true},
		{"peer", `to * by peername.ip="192.0.2.1" read`, true},
		{"socket", `to * by sockname="IP=192.0.2.1:389" read`, true},
		{"domain", `to * by domain.subtree="example.com" read`, true},
		{"URL", `to * by sockurl="ldap://localhost:389" read`, true},
		{"SSF", `to * by ssf=128 tls_ssf=128 read`, true},
		{"DN captures", `to dn.regex="^uid=([^,]+),dc=example,dc=com$" by dn.exact,expand="uid=$1,dc=example,dc=com" read`, true},
		{"attribute selectors", `to attrs=@person,+,!person,-cn by * read`, true},
		{"value exact", `to attrs=cn val=alice by * read`, false},
		{"value regex", `to attrs=cn val.regex="^(.*)$" by dn.exact,expand="uid=${v1},dc=example,dc=com" read`, false},
		{"value DN subtree", `to attrs=owner val.subtree="dc=example,dc=com" by * read`, false},
		{"filter", `to filter="(objectClass=*)" by * read`, false},
		{"self value", `to attrs=owner by * selfwrite`, false},
		{"real self value", `to attrs=owner by * realselfwrite`, false},
		{"DN attribute", `to * by dnattr=owner read`, false},
		{"real DN attribute", `to * by realdnattr=owner read`, false},
		{"group", `to * by group="cn=readers,dc=example,dc=com" read`, false},
		{"dynamic group", `to * by group/groupOfURLs/memberURL="cn=readers,dc=example,dc=com" read`, false},
		{"set", `to * by set="user & this" read`, false},
		{"ACI", `to * by aci read`, false},
		{"dynacl", `to * by dynacl/aci read`, false},
		{"later clause", `to * by * read stop by set="user & this" read`, false},
		{"later conjunct", `to * by anonymous group="cn=readers,dc=example,dc=com" read`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, placement := range []string{"global", "database", "other database"} {
				t.Run(placement, func(t *testing.T) {
					// The candidate follows an unconditional stop. The proof must
					// still inspect it, including in an unrelated database.
					allow := mustRule(t, `{0}to * by * read`)
					candidate := mustRule(t, test.raw)
					candidate.Order = 1
					global := []Rule{allow}
					databases := map[string][]Rule{"dc=example,dc=com": {allow}}
					switch placement {
					case "global":
						global = append(global, candidate)
					case "database":
						databases["dc=example,dc=com"] = append(databases["dc=example,dc=com"], candidate)
					case "other database":
						databases["dc=other,dc=com"] = []Rule{allow, candidate}
					}
					policy, err := NewPolicy(global, databases)
					if err != nil {
						t.Fatal(err)
					}
					if got := policy.CanBatchValues(); got != test.want {
						t.Fatalf("CanBatchValues() = %t, want %t", got, test.want)
					}
				})
			}
		})
	}
	for _, kind := range []WhoKind{WhoSSF + 1, 255} {
		policy := &Policy{global: []Rule{{By: []ByClause{{Who: []WhoMatcher{{Kind: WhoAny}, {Kind: kind}}}}}}}
		if policy.CanBatchValues() {
			t.Fatalf("unknown matcher kind %d accepted", kind)
		}
	}
}

func TestPolicyCanBatchValuesObservesMutations(t *testing.T) {
	t.Parallel()

	for _, database := range []bool{false, true} {
		t.Run(fmt.Sprintf("database=%t", database), func(t *testing.T) {
			source := []Rule{mustRule(t, `to * by users read`)}
			global := source
			var databases map[string][]Rule
			if database {
				global = nil
				databases = map[string][]Rule{"dc=example,dc=com": source}
			}
			policy, err := NewPolicy(global, databases)
			if err != nil {
				t.Fatal(err)
			}
			check := func(want bool) {
				t.Helper()
				if got := policy.CanBatchValues(); got != want {
					t.Fatalf("CanBatchValues() after mutation = %t, want %t", got, want)
				}
			}
			check(true)
			// These nested slices remain shared with NewPolicy's caller.
			source[0].By[0].Grant.SelfValue = true
			check(false)
			source[0].By[0].Grant.SelfValue = false
			check(true)
			source[0].By[0].Grant.RealSelfValue = true
			check(false)
			source[0].By[0].Grant.RealSelfValue = false
			source[0].By[0].Who[0].Kind = WhoGroup
			check(false)
			source[0].By[0].Who[0].Kind = WhoUsers
			check(true)

			rules := policy.global
			if database {
				rules = policy.databases[0].Rules
			}
			rules[0].Target.Value = &ValueSelector{}
			check(false)
			rules[0].Target.Value = nil
			check(true)
			rules[0].Target.Filter = &directory.Filter{}
			check(false)
			rules[0].Target.Filter = nil
			check(true)
		})
	}
}

func TestPolicyCanBatchValuesDecisionParity(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	const alice = "uid=alice,dc=example,dc=com"
	const bob = "uid=bob,dc=example,dc=com"
	for _, test := range []struct {
		name  string
		rules []string
		who   Subject
		dn    string
		want  bool
	}{
		{"default", nil, Subject{}, alice, true},
		{"default config", nil, Subject{}, "cn=config", false},
		{"default root DSE", nil, Subject{}, "", true},
		{"deny", []string{`to * by * none`}, Subject{DN: alice}, alice, false},
		{"anonymous", []string{`to * by anonymous read`}, Subject{}, alice, true},
		{"users", []string{`to * by users read`}, Subject{DN: alice}, alice, true},
		{"users mismatch", []string{`to * by users read`}, Subject{}, alice, false},
		{"self", []string{`to * by self read`}, Subject{DN: alice}, alice, true},
		{"self mismatch", []string{`to * by self read`}, Subject{DN: bob}, alice, false},
		{"real self", []string{`to * by realself read`}, Subject{DN: bob, RealDN: alice}, alice, true},
		{"self level", []string{`to * by self.level{1} read`}, Subject{DN: alice}, "dc=example,dc=com", true},
		{"DN", []string{`to * by dn.exact="` + alice + `" read`}, Subject{DN: alice}, bob, true},
		{"real DN", []string{`to * by realdn.exact="` + alice + `" read`}, Subject{DN: bob, RealDN: alice}, bob, true},
		{"peer", []string{`to * by peername.ip="192.0.2.1" read`}, Subject{PeerName: "IP=192.0.2.1:1234"}, alice, true},
		{"socket", []string{`to * by sockname="IP=192.0.2.1:389" read`}, Subject{SockName: "IP=192.0.2.1:389"}, alice, true},
		{"domain", []string{`to * by domain.subtree="example.com" read`}, Subject{Domain: "client.example.com"}, alice, true},
		{"URL", []string{`to * by sockurl="ldap://localhost:389" read`}, Subject{SockURL: "ldap://localhost:389"}, alice, true},
		{"SSF", []string{`to * by ssf=128 tls_ssf=128 read`}, Subject{SSF: 128, TLSSSF: 128}, alice, true},
		{"SSF conjunction", []string{`to * by ssf=128 tls_ssf=128 read`}, Subject{SSF: 128}, alice, false},
		{"DN captures", []string{`to dn.regex="^uid=([^,]+),dc=example,dc=com$" by dn.exact,expand="uid=$1,dc=example,dc=com" read`}, Subject{DN: alice}, alice, true},
		{"DN regex expansion", []string{`to dn.regex="^uid=([^,]+),dc=example,dc=com$" by dn.regex="^uid=$1,dc=example,dc=com$$" read`}, Subject{DN: alice}, alice, true},
		{"connection expansion", []string{`to dn.regex="^uid=([^,]+),dc=example,dc=com$" by domain.exact,expand="$1.example.com" read`}, Subject{Domain: "alice.example.com"}, alice, true},
		{"missing value capture", []string{`to * by dn.exact,expand="uid=${v1},dc=example,dc=com" read`}, Subject{DN: alice}, alice, false},
		{"invalid expansion", []string{`to dn.regex="^uid=([^,]+),.*$" by dn.exact,expand="$1" read`}, Subject{DN: alice}, alice, false},
		{"malformed subject", []string{`to * by self read`}, Subject{DN: "cn=broken,"}, alice, false},
		{"malformed target", []string{`to * by * read`}, Subject{}, "cn=broken,", false},
		{"set add remove identity", []string{`to * by * =rs continue by * -r continue by * +r continue by *`}, Subject{}, alice, true},
		{"remove read", []string{`to * by * =rs continue by * -r stop`}, Subject{}, alice, false},
		{"continue implicit deny", []string{`to * by * read continue`}, Subject{}, alice, false},
		{"break implicit deny", []string{`to * by * read break`}, Subject{}, alice, false},
		{"break retains grant", []string{`{0}to * by * =s break`, `{1}to * by * +r stop`}, Subject{}, alice, true},
		{"sorted stop", []string{`{1}to * by * read`, `{0}to * by * none`}, Subject{}, alice, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var rules []Rule
			for _, raw := range test.rules {
				rules = append(rules, mustRule(t, raw))
			}
			policy, err := NewPolicy(rules, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, aware := range []bool{false, true} {
				target := Target{Entry: directory.Entry{DN: test.dn}, Attribute: "owner", DNValued: true}
				if aware {
					target.Schema = registry
					target.DNNormalizer = registry
				}
				assertValueBatchDecisions(t, policy, test.who, target, Read, test.want)
			}
		})
	}
}

func TestPolicyCanBatchValuesDatabaseOrdering(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy([]Rule{mustRule(t, `to * by * +r stop`)}, map[string][]Rule{
		"dc=example,dc=com": {mustRule(t, `to * by * none stop`)},
		"ou=people,dc=example,dc=com": {
			mustRule(t, `{1}to * by * break`),
			mustRule(t, `{0}to * by self =s break`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const alice = "uid=alice,ou=people,dc=example,dc=com"
	for _, dn := range []string{alice, "uid=bob,dc=example,dc=com", "uid=bob,dc=other,dc=com"} {
		target := Target{Entry: directory.Entry{DN: dn}, Attribute: "cn"}
		assertValueBatchDecisions(t, policy, Subject{DN: alice}, target, Read, dn != "uid=bob,dc=example,dc=com")
		assertValueBatchDecisions(t, policy, Subject{DN: alice}, target, Search, dn == alice)
	}
}

func TestPolicyCanBatchValuesModesAndControls(t *testing.T) {
	t.Parallel()

	for _, mode := range []grantMode{grantSet, grantAdd, grantRemove, grantIdentity} {
		for _, control := range []Control{ControlStop, ControlContinue, ControlBreak} {
			t.Run(fmt.Sprintf("mode=%d/control=%d", mode, control), func(t *testing.T) {
				policy, err := NewPolicy([]Rule{{By: []ByClause{{
					Who:     []WhoMatcher{{Kind: WhoAny}},
					Grant:   Grant{Mode: mode, Privileges: ReadLevel},
					Control: control,
				}}}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				target := Target{Entry: testEntry(), Attribute: "cn"}
				for _, required := range []Privilege{0, Read, Write, Read | Write, Manage} {
					want := control == ControlStop && (required == 0 ||
						((mode == grantSet || mode == grantAdd) && ReadLevel&required == required))
					assertValueBatchDecisions(t, policy, Subject{}, target, required, want)
				}
			})
		}
	}
}

type valueBatchForbiddenReader struct{ t *testing.T }

func (reader valueBatchForbiddenReader) Get(directory.DN) (directory.Entry, error) {
	reader.t.Helper()
	reader.t.Fatal("batchable policy called EntryReader.Get")
	return directory.Entry{}, nil
}

func assertValueBatchDecisions(t *testing.T, policy *Policy, subject Subject, target Target, required Privilege, want bool) {
	t.Helper()
	if !policy.CanBatchValues() {
		t.Fatal("value-independent policy rejected")
	}
	values := [][]byte{[]byte("uid=alice,dc=example,dc=com"), nil, {}, []byte("cn=broken,"), {0xff, 0x00}, []byte("other")}
	reader := valueBatchForbiddenReader{t: t}
	target.Value = values[0]
	first := policy.Allowed(subject, target, required, reader)
	if first != want {
		t.Fatalf("Allowed() for first value = %t, want %t (schema=%t, required=%b)", first, want, target.Schema != nil, required)
	}
	for _, value := range values {
		target.Value = value
		if got := policy.Allowed(subject, target, required, reader); got != first {
			t.Fatalf("Allowed(%q) = %t, first-value decision = %t", value, got, first)
		}
	}
}
