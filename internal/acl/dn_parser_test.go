package acl

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

// Only this wrapper opts in; embedding Registry alone must preserve callbacks.
type cachedACLDNNormalizer struct {
	*schema.Registry
}

func (normalizer cachedACLDNNormalizer) ParseDNIdentity(raw string) (directory.DN, error) {
	return normalizer.NormalizeDNCached(raw)
}

var _ DNIdentityParser = cachedACLDNNormalizer{}

type recordingACLDNNormalizer struct {
	*schema.Registry
	calls        []string
	normalizeErr error
	nameErr      error
}

func (normalizer *recordingACLDNNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	normalizer.calls = append(normalizer.calls, "normalize:"+attribute+"="+string(value))
	if normalizer.normalizeErr != nil {
		return "", nil, normalizer.normalizeErr
	}
	return normalizer.Registry.NormalizeDNAttribute(attribute, value)
}

func (normalizer *recordingACLDNNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	normalizer.calls = append(normalizer.calls, "name:"+attribute)
	if normalizer.nameErr != nil {
		return "", normalizer.nameErr
	}
	return normalizer.Registry.CanonicalDNAttributeName(attribute)
}

type stubACLDNParser struct {
	directory.DNAttributeNormalizer
	parse func(string) (directory.DN, error)
}

func (parser stubACLDNParser) ParseDNIdentity(raw string) (directory.DN, error) {
	return parser.parse(raw)
}

func assertACLDNResult(t *testing.T, got directory.DN, gotErr error, want directory.DN, wantErr error) {
	t.Helper()
	if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) ||
		reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) {
		t.Fatalf("DN = %q (%q), %v; want %q (%q), %v",
			got.String(), got.Key(), gotErr, want.String(), want.Key(), wantErr)
	}
}

func TestACLDNParserNilNormalizer(t *testing.T) {
	for _, raw := range []string{"", " ", "CN=Alice+UID=ALICE,DC=Example", `cn=Smith\, Alice`, "broken"} {
		want, wantErr := directory.ParseDN(raw)
		got, gotErr := parseACLDN(raw, nil)
		assertACLDNResult(t, got, gotErr, want, wantErr)
	}
	registry := mustACIRegistry(t)
	aware, err := registry.NormalizeDN("UID=Alice,DC=Example")
	if err != nil {
		t.Fatal(err)
	}
	for _, dn := range []directory.DN{{}, mustACIDN(t, ""), mustACIDN(t, "CN=Alice"), aware} {
		got, err := normalizeACLDN(dn, nil)
		assertACLDNResult(t, got, err, dn, nil)
	}
}

func TestACLDNParserUnoptedCallbacks(t *testing.T) {
	registry := mustACIRegistry(t)
	if _, ok := any(registry).(DNIdentityParser); ok {
		t.Fatal("Registry must not opt all ACL callers into full-DN parsing")
	}
	normalizer := &recordingACLDNNormalizer{Registry: registry}
	if _, ok := any(normalizer).(DNIdentityParser); ok {
		t.Fatal("embedding Registry unexpectedly opted a custom normalizer in")
	}
	sentinel := errors.New("custom callback failure")
	for _, failure := range []string{"none", "normalize", "name"} {
		t.Run(failure, func(t *testing.T) {
			normalizer.normalizeErr, normalizer.nameErr = nil, nil
			if failure == "normalize" {
				normalizer.normalizeErr = sentinel
			} else if failure == "name" {
				normalizer.nameErr = sentinel
			}
			for _, raw := range []string{
				"", "UID=Alice+CN=Primary,DC=Example", "unknownName=x,member=bad",
				"member=bad,unknownName=x", "cn=x+cn=y", "unknownName=x,broken",
			} {
				for range 2 {
					normalizer.calls = nil
					want, wantErr := directory.ParseDNWithNormalizer(raw, normalizer)
					wantCalls := slices.Clone(normalizer.calls)
					normalizer.calls = nil
					got, gotErr := parseACLDN(raw, normalizer)
					assertACLDNResult(t, got, gotErr, want, wantErr)
					if !slices.Equal(normalizer.calls, wantCalls) ||
						errors.Is(gotErr, sentinel) != errors.Is(wantErr, sentinel) {
						t.Fatalf("parse %q: calls = %v, want %v; error = %v", raw, normalizer.calls, wantCalls, gotErr)
					}
					dn, err := directory.ParseDN(raw)
					if err != nil {
						continue
					}
					normalizer.calls = nil
					want, wantErr = directory.ParseDNWithNormalizer(dn.String(), normalizer)
					wantCalls = slices.Clone(normalizer.calls)
					normalizer.calls = nil
					got, gotErr = normalizeACLDN(dn, normalizer)
					assertACLDNResult(t, got, gotErr, want, wantErr)
					if !slices.Equal(normalizer.calls, wantCalls) ||
						errors.Is(gotErr, sentinel) != errors.Is(wantErr, sentinel) {
						t.Fatalf("normalize %q: calls = %v, want %v; error = %v", raw, normalizer.calls, wantCalls, gotErr)
					}
				}
			}
		})
	}
}

func TestACLDNParserDelegatesOnce(t *testing.T) {
	normalizer := &recordingACLDNNormalizer{Registry: mustACIRegistry(t)}
	want, err := directory.ParseDNWithNormalizer("UID=Alice,DC=Example", normalizer)
	if err != nil {
		t.Fatal(err)
	}
	normalizer.calls = nil
	sentinel := errors.New("full-DN parser failure")
	for _, wantErr := range []error{nil, sentinel} {
		var inputs []string
		parser := stubACLDNParser{
			DNAttributeNormalizer: normalizer,
			parse: func(raw string) (directory.DN, error) {
				inputs = append(inputs, raw)
				return want, wantErr
			},
		}
		// Invalid syntax must reach the opted-in parser without pre-parsing.
		for _, raw := range []string{"", "UID=Alice,DC=Example", "broken"} {
			for range 2 {
				inputs = nil
				got, gotErr := parseACLDN(raw, parser)
				assertACLDNResult(t, got, gotErr, want, wantErr)
				// Exact error identity also rules out wrapping or retrying the error.
				if gotErr != wantErr || !slices.Equal(inputs, []string{raw}) || len(normalizer.calls) != 0 {
					t.Fatalf("parse delegated incorrectly: inputs=%v callbacks=%v error=%v", inputs, normalizer.calls, gotErr)
				}
			}
		}
		for _, dn := range []directory.DN{{}, mustACIDN(t, "UID=Alice,DC=Example"), want} {
			inputs = nil
			got, gotErr := normalizeACLDN(dn, parser)
			assertACLDNResult(t, got, gotErr, want, wantErr)
			if gotErr != wantErr || !slices.Equal(inputs, []string{dn.String()}) || len(normalizer.calls) != 0 {
				t.Fatalf("normalize delegated incorrectly: inputs=%v callbacks=%v error=%v", inputs, normalizer.calls, gotErr)
			}
		}
	}
}

func newACLDNParserRegistry(t testing.TB) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.990.1 NAME ( 'aclExactName' 'aclExactAlias' ) EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.990.2 NAME ( 'aclFoldName' 'aclFoldAlias' ) EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func TestACLDNParserCachedParity(t *testing.T) {
	registry := newACLDNParserRegistry(t)
	parser := cachedACLDNNormalizer{registry}
	for _, raw := range []string{
		"", " ", "CN=Alice", "2.5.4.3=Alice",
		"aclExactAlias=Alice+aclFoldAlias=PRIMARY TEAM,DC=Example",
		"1.3.6.1.4.1.99999.990.2=primary team+aclExactName=Alice,dc=example",
		"aclExactName=alice,dc=example", `cn=Smith\, Alice+uid=ALICE,dc=example`,
		`cn=\c3\a9\+\00,dc=example`, "cn=\u00c9quipe,dc=example",
		"cn=E\u0301quipe,dc=example", "member=cn\\=Alice,dc=example",
		"broken", `cn=bad\zz`, "unknownName=x,broken", "unknownName=x,member=bad",
		"member=bad,unknownName=x", "jpegPhoto=x", "cn=x+cn=y",
		"aclExactName=x+aclExactAlias=y", "aclExactName=x+aclExactAlias=y,broken",
	} {
		t.Run(raw, func(t *testing.T) {
			want, wantErr := directory.ParseDNWithNormalizer(raw, registry)
			for range 2 {
				got, gotErr := parseACLDN(raw, parser)
				assertACLDNResult(t, got, gotErr, want, wantErr)
			}
			dn, err := directory.ParseDN(raw)
			if err != nil {
				return
			}
			want, wantErr = directory.ParseDNWithNormalizer(dn.String(), registry)
			for range 2 {
				got, gotErr := normalizeACLDN(dn, parser)
				assertACLDNResult(t, got, gotErr, want, wantErr)
			}
		})
	}
}

func newACLDNParserFixture(t testing.TB) (*schema.Registry, Target, aciMapReader) {
	t.Helper()
	registry := newACLDNParserRegistry(t)
	target := aciTarget(registry)
	target.Entry.DN = "uid=Alice,ou=People,dc=Example,dc=Com"
	target.Entry.ReplaceValues("owner", bytes("invalid", "userid=ALICE,ou=people,dc=example,dc=com"))
	reader := aciMapReader{}
	for _, entry := range []directory.Entry{
		target.Entry,
		{DN: "ou=people,dc=example,dc=com"},
		{
			DN: "cn=alice-readers,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfNames")},
				{Description: "member", Values: bytes("invalid", target.Entry.DN)},
			},
		},
		{
			DN: "cn=unique,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfUniqueNames")},
				{Description: "uniqueMember", Values: bytes(target.Entry.DN)},
			},
		},
		{
			DN: "cn=uid-bound,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfUniqueNames")},
				{Description: "uniqueMember", Values: bytes(target.Entry.DN + "#'101'B")},
			},
		},
		{
			DN: "cn=dynamic,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfURLs")},
				{Description: "memberURL", Values: bytes("ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)")},
			},
		},
	} {
		dn, err := registry.NormalizeDN(entry.DN)
		if err != nil {
			t.Fatal(err)
		}
		reader[dn.Key()] = entry
	}
	return registry, target, reader
}

func assertACLDNParserAllowed(t *testing.T, registry *schema.Registry, policy *Policy, subject Subject, target Target, required Privilege, reader EntryReader, want bool) {
	t.Helper()
	for iteration := range 3 {
		target.DNNormalizer = registry
		uncached := policy.Allowed(subject, target, required, reader)
		target.DNNormalizer = cachedACLDNNormalizer{registry}
		cached := policy.Allowed(subject, target, required, reader)
		if uncached != want || cached != uncached {
			t.Fatalf("Allowed iteration %d: cached=%v uncached=%v want=%v", iteration, cached, uncached, want)
		}
	}
}

func TestACLDNParserAllowedParity(t *testing.T) {
	registry, target, reader := newACLDNParserFixture(t)
	const alice = "userid=ALICE,ou=people,dc=example,dc=com"
	const bob = "uid=bob,ou=people,dc=example,dc=com"
	const exact = "aclExactName=Alice+aclFoldName=Primary Team,dc=example,dc=com"
	const equivalent = "1.3.6.1.4.1.99999.990.2=PRIMARY TEAM+aclExactAlias=Alice,DC=EXAMPLE,DC=COM"
	for _, test := range []struct {
		name      string
		rule      string
		subject   string
		targetDN  string
		attribute string
		value     string
		required  Privilege
		aci       []string
		want      bool
	}{
		{name: "target exact alias", rule: `to dn.exact="` + alice + `" by * read`, want: true},
		{name: "target subtree", rule: `to dn.subtree="OU=PEOPLE,DC=EXAMPLE,DC=COM" by * read`, want: true},
		{name: "target outside subtree", rule: `to dn.subtree="ou=groups,dc=example,dc=com" by * read`},
		{name: "self", rule: `to * by self read`, subject: alice, want: true},
		{name: "self mismatch", rule: `to * by self read`, subject: bob},
		{name: "self multi AVA aliases", rule: `to * by self read`, subject: equivalent, targetDN: exact, want: true},
		{name: "self exact case mismatch", rule: `to * by self read`, subject: "aclExactName=alice+aclFoldName=Primary Team,dc=example,dc=com", targetDN: exact},
		{name: "self escaped Unicode", rule: `to * by self read`, subject: `cn=\c3\a9quipe\, Paris+uid=ALICE,dc=example`, targetDN: "uid=alice+cn=\u00c9quipe\\, Paris,dc=example", want: true},
		{name: "self parent", rule: `to * by self.level{1} read`, subject: alice, targetDN: "ou=people,dc=example,dc=com", want: true},
		{name: "subject exact", rule: `to * by dn.exact="` + equivalent + `" read`, subject: exact, want: true},
		{name: "subject subtree", rule: `to * by dn.subtree="ou=people,dc=example,dc=com" read`, subject: alice, want: true},
		{name: "DN attribute", rule: `to * by dnattr=owner read`, subject: alice, want: true},
		{name: "DN attribute mismatch", rule: `to * by dnattr=owner read`, subject: bob},
		{name: "self value", rule: `to attrs=owner by users selfwrite`, subject: alice, attribute: "owner", value: target.Entry.DN, required: Write, want: true},
		{name: "self value mismatch", rule: `to attrs=owner by users selfwrite`, subject: bob, attribute: "owner", value: target.Entry.DN, required: Write},
		{name: "DN value selector", rule: `to attrs=owner val.exact="` + alice + `" by * read`, attribute: "owner", value: target.Entry.DN, want: true},
		{name: "DN value subtree", rule: `to attrs=owner val.subtree="ou=people,dc=example,dc=com" by * read`, attribute: "owner", value: alice, want: true},
		{name: "invalid DN value", rule: `to attrs=owner val.exact="` + alice + `" by * read`, attribute: "owner", value: "invalid"},
		{name: "static group", rule: `to * by group="cn=alice-readers,ou=groups,dc=example,dc=com" read`, subject: alice, want: true},
		{name: "static nonmember", rule: `to * by group="cn=alice-readers,ou=groups,dc=example,dc=com" read`, subject: bob},
		{name: "unique member", rule: `to * by group/groupOfUniqueNames/uniqueMember="cn=unique,ou=groups,dc=example,dc=com" read`, subject: alice, want: true},
		{name: "unique member UID mismatch", rule: `to * by group/groupOfUniqueNames/uniqueMember="cn=uid-bound,ou=groups,dc=example,dc=com" read`, subject: alice},
		{name: "dynamic group", rule: `to * by group/groupOfURLs/memberURL="cn=dynamic,ou=groups,dc=example,dc=com" read`, subject: alice, want: true},
		{name: "DN expansion", rule: `to dn.regex="^uid=([^,]+),ou=people,dc=example,dc=com$" by dn.exact,expand="userid=$1,ou=people,dc=example,dc=com" read`, subject: alice, want: true},
		{name: "value expansion", rule: `to attrs=mail val.regex="^([^@]+)@example[.]com$" by dn.exact,expand="uid=${v1},ou=people,dc=example,dc=com" read`, subject: alice, attribute: "mail", value: "alice@example.com", want: true},
		{name: "regex expansion", rule: `to dn.regex="^uid=([^,]+),ou=people,dc=example,dc=com$" by dn.regex="^uid=$1,ou=people,dc=example,dc=com$$" read`, subject: alice, want: true},
		{name: "group expansion", rule: `to dn.regex="^uid=([^,]+),ou=people,dc=example,dc=com$" by group.expand="cn=$1-readers,ou=groups,dc=example,dc=com" read`, subject: alice, want: true},
		{name: "invalid expansion", rule: `to dn.regex="^uid=([^,]+),.*$" by dn.exact,expand="$1" read`, subject: alice},
		{name: "set chase", rule: `to * by set="[cn=alice-readers,ou=groups,dc=example,dc=com]/member & user" read`, subject: alice, want: true},
		{name: "set nonmember", rule: `to * by set="[cn=alice-readers,ou=groups,dc=example,dc=com]/member & user" read`, subject: bob},
		{name: "set target attribute", rule: `to * by set="this/owner & user" read`, subject: alice, want: true},
		{name: "set parent", rule: `to * by set="this/-1 & [OU=PEOPLE,DC=EXAMPLE,DC=COM]" read`, want: true},
		{name: "set expansion", rule: `to dn.regex="^uid=([^,]+),ou=people,dc=example,dc=com$" by set.expand="[userid=$1,ou=people,dc=example,dc=com] & user" read`, subject: alice, want: true},
		{name: "ACI public", rule: `to * by dynacl/aci write`, aci: []string{"0#entry#grant;r;cn#public#"}, want: true},
		{name: "ACI deny", rule: `to * by dynacl/aci write`, aci: []string{"0#entry#grant;r;cn#public#", "1#entry#deny;r;cn#public#"}},
		{name: "ACI access id", rule: `to * by dynacl/aci write`, subject: bob, aci: []string{"0#entry#grant;r;cn#access-id#" + bob}, want: true},
		{name: "ACI set", rule: `to * by dynacl/aci write`, subject: bob, aci: []string{"0#entry#grant;r;cn#set#[" + bob + "] & user"}, want: true},
		{name: "invalid target", rule: `to * by * read`, targetDN: "broken"},
		{name: "undefined naming attribute", rule: `to * by * read`, targetDN: "unknownName=alice"},
		{name: "invalid subject", rule: `to * by self read`, subject: "broken"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := policy.Validate(registry); err != nil {
				t.Fatal(err)
			}
			candidate := target
			candidate.Entry = target.Entry.Clone()
			if test.targetDN != "" {
				candidate.Entry.DN = test.targetDN
			}
			if test.attribute != "" {
				candidate.Attribute = test.attribute
				candidate.Value = []byte(test.value)
			}
			if test.aci != nil {
				candidate.Entry.ReplaceValues("OpenLDAPaci", bytes(test.aci...))
			}
			required := test.required
			if required == 0 {
				required = Read
			}
			assertACLDNParserAllowed(t, registry, policy, Subject{DN: test.subject}, candidate, required, reader, test.want)
		})
	}
}

func TestACLDNParserSuffixAndRuleOrder(t *testing.T) {
	registry, target, reader := newACLDNParserFixture(t)
	policy, err := NewPolicy([]Rule{mustRule(t, `to * by users +s`)}, map[string][]Rule{
		"DC=EXAMPLE,DC=COM": {mustRule(t, `to * by * none`)},
		"OU=PEOPLE,DC=EXAMPLE,DC=COM": {
			mustRule(t, `{2}to * by * none`),
			mustRule(t, `{1}to * by dn.exact="uid=bob,ou=people,dc=example,dc=com" break by * none`),
			mustRule(t, `{0}to * by self =s continue by group="cn=alice-readers,ou=groups,dc=example,dc=com" +r stop by * break`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertACLDNParserAllowed(t, registry, policy, Subject{DN: target.Entry.DN}, target, Read, reader, true)
	bob := Subject{DN: "uid=bob,ou=people,dc=example,dc=com"}
	assertACLDNParserAllowed(t, registry, policy, bob, target, Search, reader, false)
	// Removing the final database rule lets break continue into the global ACL.
	policy, err = NewPolicy([]Rule{mustRule(t, `to * by users +s`)}, map[string][]Rule{
		"OU=PEOPLE,DC=EXAMPLE,DC=COM": {mustRule(t, `to * by self read by * break`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertACLDNParserAllowed(t, registry, policy, bob, target, Search, reader, true)
	assertACLDNParserAllowed(t, registry, policy, bob, target, Read, reader, false)
	assertACLDNParserAllowed(t, registry, policy, Subject{}, target, Read, reader, false)
}

func TestACLDNParserObservesSchemaChanges(t *testing.T) {
	for _, selection := range []string{"self", "target", "suffix"} {
		t.Run(selection, func(t *testing.T) {
			registry, target, reader := newACLDNParserFixture(t)
			subject := Subject{DN: "uid=alice,ou=people,dc=example,dc=com"}
			global := []Rule{mustRule(t, `to * by self read`)}
			var databases map[string][]Rule
			if selection == "target" {
				global = []Rule{mustRule(t, `to dn.exact="`+subject.DN+`" by * read`)}
			} else if selection == "suffix" {
				global = []Rule{mustRule(t, `to * by * none`)}
				databases = map[string][]Rule{subject.DN: {mustRule(t, `to * by * read`)}}
			}
			policy, err := NewPolicy(global, databases)
			if err != nil {
				t.Fatal(err)
			}
			assertACLDNParserAllowed(t, registry, policy, subject, target, Read, reader, true)
			attribute, _ := registry.AttributeType("uid")
			for _, equality := range []string{"caseExactMatch", "caseIgnoreMatch"} {
				attribute.Equality = equality
				if err := registry.UpsertAttributeType(attribute); err != nil {
					t.Fatal(err)
				}
				assertACLDNParserAllowed(t, registry, policy, subject, target, Read, reader, equality == "caseIgnoreMatch")
			}
		})
	}
}

func TestACLDNParserObservesGroupAndACIChanges(t *testing.T) {
	for _, rule := range []string{
		`to * by group="cn=alice-readers,ou=groups,dc=example,dc=com" read`,
		`to * by set="[cn=alice-readers,ou=groups,dc=example,dc=com]/member & user" read`,
	} {
		t.Run(rule, func(t *testing.T) {
			registry, target, reader := newACLDNParserFixture(t)
			policy, err := NewPolicy([]Rule{mustRule(t, rule)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{DN: target.Entry.DN}
			groupDN, err := registry.NormalizeDN("cn=alice-readers,ou=groups,dc=example,dc=com")
			if err != nil {
				t.Fatal(err)
			}
			group := reader[groupDN.Key()].Clone()
			assertACLDNParserAllowed(t, registry, policy, subject, target, Read, reader, true)
			for _, member := range []string{"uid=bob,dc=example,dc=com", subject.DN} {
				group.ReplaceValues("member", bytes(member))
				reader[groupDN.Key()] = group.Clone()
				assertACLDNParserAllowed(t, registry, policy, subject, target, Read, reader, member == subject.DN)
			}
			delete(reader, groupDN.Key())
			assertACLDNParserAllowed(t, registry, policy, subject, target, Read, reader, false)
		})
	}
	t.Run("inherited ACI", func(t *testing.T) {
		registry, target, reader := newACLDNParserFixture(t)
		policy, err := NewPolicy([]Rule{mustRule(t, `to * by dynacl/aci write`)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		parentDN, err := registry.NormalizeDN("ou=people,dc=example,dc=com")
		if err != nil {
			t.Fatal(err)
		}
		parent := reader[parentDN.Key()].Clone()
		for _, permission := range []string{"grant", "deny", "grant"} {
			parent.ReplaceValues("OpenLDAPaci", bytes("0#subtree#"+permission+";r;cn#public#"))
			reader[parentDN.Key()] = parent.Clone()
			assertACLDNParserAllowed(t, registry, policy, Subject{}, target, Read, reader, permission == "grant")
		}
	})
}

func TestACLDNParserObservesNewAttribute(t *testing.T) {
	registry := newACLDNParserRegistry(t)
	target := Target{Entry: directory.Entry{DN: "newName=Alice"}, Schema: registry}
	policy, err := NewPolicy([]Rule{mustRule(t, `to * by self read`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{DN: "newAlias=ALICE"}
	assertACLDNParserAllowed(t, registry, policy, subject, target, Read, nil, false)
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.3.6.1.4.1.99999.990.3 NAME ( 'newName' 'newAlias' ) EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	); err != nil {
		t.Fatal(err)
	}
	assertACLDNParserAllowed(t, registry, policy, subject, target, Read, nil, true)
	attribute, _ := registry.AttributeType("newName")
	attribute.Names = []string{"newName"}
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	assertACLDNParserAllowed(t, registry, policy, subject, target, Read, nil, false)
}

func TestACLDNParserResultOwnership(t *testing.T) {
	registry := newACLDNParserRegistry(t)
	parser := cachedACLDNNormalizer{registry}
	const raw = "aclExactAlias=Alice+uid=ALICE,dc=Example,dc=Com"
	want, err := directory.ParseDNWithNormalizer(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	dn, err := parseACLDN(raw, parser)
	if err != nil {
		t.Fatal(err)
	}
	parent, ok := dn.Parent()
	if !ok {
		t.Fatal("missing parent")
	}
	wantParent, _ := want.Parent()
	for _, shared := range []directory.DN{dn, parent} {
		values := shared.RDNValues()
		for i := range values {
			values[i].Type = "changed"
			clear(values[i].Value)
		}
	}
	got, err := parseACLDN(raw, parser)
	assertACLDNResult(t, got, err, want, nil)
	attribute, _ := registry.AttributeType("aclExactName")
	attribute.Equality = "caseIgnoreMatch"
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	got, err = parseACLDN(raw, parser)
	if err != nil || got.Equal(want) {
		t.Fatalf("schema mutation retained old identity: %v", err)
	}
	assertACLDNResult(t, dn, nil, want, nil)
	assertACLDNResult(t, parent, nil, wantParent, nil)
}
