package acl

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseOrderedOpenLDAPACL(t *testing.T) {
	t.Parallel()

	rule, err := ParseRule(
		`{2}to dn.subtree="dc=example,dc=com" attrs=mail,entry ` +
			`by self write by users read by * none`,
	)
	if err != nil {
		t.Fatalf("ParseRule(): %v", err)
	}
	if rule.Order != 2 ||
		rule.Target.DN.Style != DNSubtree ||
		len(rule.Target.Attributes) != 2 ||
		len(rule.By) != 3 ||
		rule.By[0].Grant.Privileges != WriteLevel ||
		rule.By[1].Grant.Privileges != ReadLevel {
		t.Fatalf("rule = %#v", rule)
	}
}

func TestParseGranularWritePrivilegesAndImplicitIdentity(t *testing.T) {
	t.Parallel()

	rule := mustRule(t, `{0}to * by users =az`)
	if rule.By[0].Grant.Privileges != Write {
		t.Fatalf("=az privileges = %b, want %b", rule.By[0].Grant.Privileges, Write)
	}

	policy, err := NewPolicy([]Rule{
		mustRule(t, `{0}to * by users =a continue by users`),
	}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	target := Target{Entry: testEntry(), Attribute: "mail"}
	subject := Subject{DN: "uid=alice,dc=example,dc=com"}
	if !policy.Allowed(subject, target, WriteAdd, nil) {
		t.Fatal("implicit +0 clause discarded the accumulated add privilege")
	}
	if policy.Allowed(subject, target, WriteDelete, nil) {
		t.Fatal("add privilege unexpectedly included delete")
	}
}

func TestSelfValueGrantRequiresDNSyntax(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy([]Rule{
		mustRule(t, `{0}to attrs=owner by users selfwrite by * none`),
	}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	subject := Subject{DN: "uid=alice,dc=example,dc=com"}
	target := Target{
		Entry:     testEntry(),
		Attribute: "owner",
		Value:     []byte(subject.DN),
	}
	if policy.Allowed(subject, target, Write, nil) {
		t.Fatal("selfwrite allowed a non-DN syntax attribute")
	}
	target.DNValued = true
	if !policy.Allowed(subject, target, Write, nil) {
		t.Fatal("selfwrite denied the subject DN on a DN syntax attribute")
	}
}

func TestPolicyEvaluatesOrderingScopesAndSubjects(t *testing.T) {
	t.Parallel()

	passwordRule := mustRule(t,
		"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
	)
	entryRule := mustRule(t,
		"{1}to dn.subtree=\"dc=example,dc=com\" by self write by users read by * none",
	)
	policy, err := NewPolicy(nil, map[string][]Rule{
		"dc=example,dc=com": {passwordRule, entryRule},
	})
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	entry := testEntry()

	if !policy.Allowed(
		Subject{},
		Target{Entry: entry, Attribute: "userPassword"},
		Auth,
		nil,
	) {
		t.Fatal("anonymous authentication access denied")
	}
	if policy.Allowed(
		Subject{},
		Target{Entry: entry, Attribute: "userPassword"},
		Read,
		nil,
	) {
		t.Fatal("anonymous password read allowed")
	}
	if !policy.Allowed(
		Subject{DN: entry.DN},
		Target{Entry: entry, Attribute: "mail"},
		Write,
		nil,
	) {
		t.Fatal("self write denied")
	}
	if !policy.Allowed(
		Subject{DN: "uid=bob,dc=example,dc=com"},
		Target{Entry: entry, Attribute: "mail"},
		Read,
		nil,
	) {
		t.Fatal("authenticated read denied")
	}
}

func TestPolicyContinueBreakAndGroups(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	group := directory.Entry{
		DN: "cn=readers,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: bytes("groupOfNames")},
			{Description: "member", Values: bytes("uid=alice,dc=example,dc=com")},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(group, false)
	}); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	policy, err := NewPolicy(
		[]Rule{
			mustRule(t, `{0}to * by users =s continue `+
				`by group.exact="cn=readers,dc=example,dc=com" +r stop`),
		},
		nil,
	)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}

	err = store.View(context.Background(), func(reader storage.Reader) error {
		target := Target{Entry: testEntry(), Attribute: "cn"}
		if !policy.Allowed(
			Subject{DN: "uid=alice,dc=example,dc=com"},
			target,
			Read,
			reader,
		) {
			t.Fatal("group member read denied")
		}
		if policy.Allowed(
			Subject{DN: "uid=bob,dc=example,dc=com"},
			target,
			Search,
			reader,
		) {
			t.Fatal("continue without later match did not hit implicit deny")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
}

func TestPolicyBreakContinuesWithFollowingRule(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy(
		[]Rule{
			mustRule(t, `{0}to * by users +s`),
		},
		map[string][]Rule{
			"dc=example,dc=com": {
				mustRule(t, `{0}to * by dn.exact="uid=replicator,dc=example,dc=com" read by * break`),
			},
		},
	)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	target := Target{Entry: testEntry(), Attribute: "cn"}
	if !policy.Allowed(
		Subject{DN: "uid=alice,dc=example,dc=com"},
		target,
		Search,
		nil,
	) {
		t.Fatal("break did not continue into global rule")
	}
	if policy.Allowed(
		Subject{DN: "uid=alice,dc=example,dc=com"},
		target,
		Read,
		nil,
	) {
		t.Fatal("global search grant unexpectedly included read")
	}
}

func TestLoadOpenLDAPACLConfig(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	config := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: bytes("{1}mdb")},
			{Description: "olcSuffix", Values: bytes("dc=example,dc=com")},
			{
				Description: "olcAccess",
				Values: bytes(
					"{1}to * by users read by * none",
					"{0}to attrs=userPassword by self write by anonymous auth by * none",
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(config, false)
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	policy, result, err := LoadOpenLDAPConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.RuleSets != 1 || result.Rules != 2 {
		t.Fatalf("LoadResult = %#v", result)
	}
	if policy.Allowed(
		Subject{DN: "uid=bob,dc=example,dc=com"},
		Target{Entry: testEntry(), Attribute: "userPassword"},
		Read,
		nil,
	) {
		t.Fatal("ordered password rule was not evaluated first")
	}
}

func TestLoadOpenLDAPAddContentACL(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	config := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: bytes("{1}mdb")},
			{Description: "olcSuffix", Values: bytes("dc=example,dc=com")},
			{Description: "olcAddContentAcl", Values: bytes("TRUE")},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(config, false)
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	policy, result, err := LoadOpenLDAPConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.RuleSets != 0 || result.Rules != 0 {
		t.Fatalf("LoadResult = %#v", result)
	}
	dn, err := directory.ParseDN("uid=alice,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if !policy.RequiresAddContentACL(dn) {
		t.Fatal("olcAddContentAcl TRUE was not loaded")
	}
}

func TestLoadOpenLDAPACLIgnoresAttributesOutsideConfigTree(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "olcAccess",
				Values:      bytes(`{0}to filter="(uid=*)" by * manage`),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed entry: %v", err)
	}

	_, result, err := LoadOpenLDAPConfig(context.Background(), store)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.RuleSets != 0 || result.Rules != 0 {
		t.Fatalf("LoadResult = %#v", result)
	}
}

func TestLoadOpenLDAPACLRejectsUnsupportedConfigSyntax(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: bytes("{1}mdb")},
			{Description: "olcSuffix", Values: bytes("dc=example,dc=com")},
			{
				Description: "olcAccess",
				Values:      bytes(`{0}to * by dynacl/custom=example manage`),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	if _, _, err := LoadOpenLDAPConfig(context.Background(), store); err == nil {
		t.Fatal("unsupported ACL syntax was accepted")
	}
}

func TestACLTargetFilterValueAndObjectClassSelectors(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entry := testEntry()
	entry.Attributes = append(entry.Attributes,
		directory.Attribute{Description: "uid", Values: bytes("alice")},
		directory.Attribute{
			Description: "owner",
			Values:      bytes("uid=alice,ou=people,dc=example,dc=com"),
		},
	)
	targetDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}

	tests := []struct {
		name      string
		rule      string
		attribute string
		value     []byte
		want      bool
	}{
		{
			name:      "entry filter",
			rule:      `to filter="(&(uid=alice)(objectClass=person))" by * read`,
			attribute: "mail",
			value:     []byte("alice@example.com"),
			want:      true,
		},
		{
			name:      "entry filter mismatch",
			rule:      `to filter="(uid=bob)" by * read`,
			attribute: "mail",
			value:     []byte("alice@example.com"),
		},
		{
			name:      "object class inherited attribute",
			rule:      `to attrs=@person by * read`,
			attribute: "cn",
			value:     []byte("Alice"),
			want:      true,
		},
		{
			name:      "object class excluded attribute",
			rule:      `to attrs=!person by * read`,
			attribute: "mail",
			value:     []byte("alice@example.com"),
			want:      true,
		},
		{
			name:      "object class exclusion rejects allowed attribute",
			rule:      `to attrs=!person by * read`,
			attribute: "cn",
			value:     []byte("Alice"),
		},
		{
			name:      "extensible object attribute set",
			rule:      `to attrs=@extensibleObject by * read`,
			attribute: "entry",
			want:      true,
		},
		{
			name:      "all user attributes excludes operational",
			rule:      `to attrs=* by * read`,
			attribute: "createTimestamp",
		},
		{
			name:      "all operational attributes",
			rule:      `to attrs=+ by * read`,
			attribute: "createTimestamp",
			want:      true,
		},
		{
			name:      "equality value uses attribute matching rule",
			rule:      `to attrs=cn val=" alice " by * read`,
			attribute: "cn",
			value:     []byte("Alice"),
			want:      true,
		},
		{
			name:      "explicit rule sees equality-normalized value",
			rule:      `to attrs=cn val/caseExactMatch="alice" by * read`,
			attribute: "cn",
			value:     []byte("Alice"),
			want:      true,
		},
		{
			name:      "explicit rule does not see original casing",
			rule:      `to attrs=cn val/caseExactMatch="Alice" by * read`,
			attribute: "cn",
			value:     []byte("Alice"),
		},
		{
			name:      "regular expression value",
			rule:      `to attrs=mail val.regex="^alice@.*\.com$" by * read`,
			attribute: "mail",
			value:     []byte("Alice@Example.COM"),
			want:      true,
		},
		{
			name:      "DN subtree value",
			rule:      `to attrs=owner val.subtree="ou=people,dc=example,dc=com" by * read`,
			attribute: "owner",
			value:     []byte("uid=alice,ou=people,dc=example,dc=com"),
			want:      true,
		},
		{
			name:      "value rule does not match attribute-level check",
			rule:      `to attrs=mail val="alice@example.com" by * read`,
			attribute: "mail",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := mustRule(t, test.rule)
			target := Target{
				Entry:     entry,
				Attribute: test.attribute,
				Value:     test.value,
				DNValued:  registry.IsDNValued(test.attribute),
				Schema:    registry,
			}
			if got := matchesTarget(rule.Target, target, targetDN); got != test.want {
				t.Fatalf("matchesTarget() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestACLTargetSelectorSchemaValidation(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	tests := []struct {
		name    string
		rule    string
		wantErr bool
	}{
		{name: "filter", rule: `to filter="(uid=*)" by * read`},
		{name: "object class", rule: `to attrs=@inetOrgPerson by * read`},
		{name: "deprecated bare object class", rule: `to attrs=inetOrgPerson by * read`},
		{name: "DN value scope", rule: `to attrs=owner val.children="dc=example,dc=com" by * read`},
		{name: "unknown object class", rule: `to attrs=@missingClass by * read`, wantErr: true},
		{name: "proxied undefined attribute", rule: `to attrs=missingAttribute by * read`},
		{name: "non-DN value scope", rule: `to attrs=mail val.subtree="dc=example,dc=com" by * read`, wantErr: true},
		{name: "missing equality rule", rule: `to attrs=jpegPhoto val=photo by * read`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
			if err != nil {
				t.Fatalf("NewPolicy(): %v", err)
			}
			err = policy.Validate(registry)
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestACLDNAndGroupExpansion(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	group := directory.Entry{
		DN: "cn=alice-readers,ou=groups,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: bytes("groupOfNames")},
			{Description: "cn", Values: bytes("alice-readers")},
			{Description: "member", Values: bytes("uid=alice,ou=people,dc=example,dc=com")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(group, false)
	}); err != nil {
		t.Fatalf("seed expanded group: %v", err)
	}
	target := Target{
		Entry: directory.Entry{
			DN: "uid=alice,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("inetOrgPerson")},
				{Description: "uid", Values: bytes("alice")},
				{Description: "mail", Values: bytes("alice@example.com")},
			},
		},
		Attribute: "mail",
		Value:     []byte("alice@example.com"),
		Schema:    registry,
	}
	subject := Subject{DN: "uid=alice,ou=people,dc=example,dc=com"}
	rules := []string{
		`to dn.regex="^uid=([^,]+),ou=people,dc=example,dc=com$" by dn.exact,expand="uid=$1,ou=people,dc=example,dc=com" read`,
		`to attrs=mail val.regex="^([^@]+)@example[.]com$" by dn.exact,expand="uid=${v1},ou=people,dc=example,dc=com" read`,
		`to dn.regex="^uid=([^,]+),ou=people,dc=example,dc=com$" by dn.regex="^uid=$1,ou=people,dc=example,dc=com$$" read`,
		`to dn.regex="^uid=([^,]+),ou=people,dc=example,dc=com$" by group.expand="cn=$1-readers,ou=groups,dc=example,dc=com" read`,
	}
	for _, rawRule := range rules {
		policy, err := NewPolicy([]Rule{mustRule(t, rawRule)}, nil)
		if err != nil {
			t.Fatalf("NewPolicy(%q): %v", rawRule, err)
		}
		if err := policy.Validate(registry); err != nil {
			t.Fatalf("Validate(%q): %v", rawRule, err)
		}
		if err := store.View(context.Background(), func(reader storage.Reader) error {
			if !policy.Allowed(subject, target, Read, reader) {
				t.Errorf("expanded ACL denied rule %q", rawRule)
			}
			return nil
		}); err != nil {
			t.Fatalf("View(): %v", err)
		}
	}
}

func TestACLSubjectDNAndSelfLevels(t *testing.T) {
	t.Parallel()

	target := Target{
		Entry:     directory.Entry{DN: "ou=people,dc=example,dc=com"},
		Attribute: "entry",
	}
	tests := []struct {
		name    string
		rule    string
		subject string
		target  string
		want    bool
	}{
		{
			name:    "self parent",
			rule:    `to * by self.level{1} read`,
			subject: "uid=alice,ou=people,dc=example,dc=com",
			want:    true,
		},
		{
			name:    "self child",
			rule:    `to * by self.level{-1} read`,
			subject: "uid=alice,ou=people,dc=example,dc=com",
			target:  "ou=address book,uid=alice,ou=people,dc=example,dc=com",
			want:    true,
		},
		{
			name:    "self level out of range",
			rule:    `to * by self.level{9} read`,
			subject: "uid=alice,ou=people,dc=example,dc=com",
		},
		{
			name:    "DN grandparent",
			rule:    `to * by dn.level{2}="dc=example,dc=com" read`,
			subject: "uid=alice,ou=people,dc=example,dc=com",
			want:    true,
		},
		{
			name:    "DN exact level zero",
			rule:    `to * by dn.level{0}="uid=alice,ou=people,dc=example,dc=com" read`,
			subject: "uid=alice,ou=people,dc=example,dc=com",
			want:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := target.Entry
			if test.target != "" {
				entry.DN = test.target
			}
			policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
			if err != nil {
				t.Fatalf("NewPolicy(): %v", err)
			}
			got := policy.Allowed(
				Subject{DN: test.subject},
				Target{Entry: entry, Attribute: target.Attribute},
				Read,
				nil,
			)
			if got != test.want {
				t.Errorf("Allowed() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestACLRejectsInvalidDNLevels(t *testing.T) {
	t.Parallel()

	for _, rule := range []string{
		`to * by self.level{} read`,
		`to * by self.level{x} read`,
		`to * by dn.level{-1}="dc=example,dc=com" read`,
		`to * by dn.level{1="dc=example,dc=com" read`,
	} {
		if _, err := ParseRule(rule); err == nil {
			t.Errorf("ParseRule(%q) succeeded", rule)
		}
	}
}

func TestACLRealIdentitySelectors(t *testing.T) {
	t.Parallel()

	target := Target{
		Entry: directory.Entry{
			DN: "uid=proxy,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "manager", Values: bytes("uid=admin,dc=example,dc=com")},
			},
		},
		Attribute: "manager",
		Value:     []byte("uid=admin,dc=example,dc=com"),
		DNValued:  true,
	}
	subject := Subject{
		DN:     "uid=proxy,ou=people,dc=example,dc=com",
		RealDN: "uid=admin,dc=example,dc=com",
	}
	tests := []struct {
		name string
		rule string
		want bool
	}{
		{name: "authorization self", rule: `to * by self read`, want: true},
		{name: "authentication self differs", rule: `to * by realself read`},
		{name: "authentication user", rule: `to * by realusers read`, want: true},
		{name: "authentication DN", rule: `to * by realdn.exact="uid=admin,dc=example,dc=com" read`, want: true},
		{name: "authorization DN differs", rule: `to * by dn.exact="uid=admin,dc=example,dc=com" read`},
		{name: "authentication DN attribute", rule: `to * by realdnattr=manager read`, want: true},
		{name: "authorization DN attribute differs", rule: `to * by dnattr=manager read`},
		{name: "authentication self value", rule: `to attrs=manager by * realselfwrite`, want: true},
		{name: "authorization self value differs", rule: `to attrs=manager by * selfwrite`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
			if err != nil {
				t.Fatalf("NewPolicy(): %v", err)
			}
			got := policy.Allowed(subject, target, Read, nil)
			if strings.Contains(test.rule, "write") {
				got = policy.Allowed(subject, target, WriteAdd, nil)
			}
			if got != test.want {
				t.Errorf("Allowed() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestACLConnectionAndSSFSelectors(t *testing.T) {
	t.Parallel()

	target := Target{
		Entry:     directory.Entry{DN: "uid=alice,dc=example,dc=com"},
		Attribute: "entry",
	}
	subject := Subject{
		PeerName:     "IP=192.0.2.27:38900",
		SockName:     "IP=192.0.2.10:389",
		Domain:       "client.example.com",
		SockURL:      "ldap://192.0.2.10:389",
		SSF:          256,
		TransportSSF: 0,
		TLSSSF:       256,
		SASLSSF:      0,
	}
	tests := []struct {
		name string
		rule string
		want bool
	}{
		{name: "peer exact", rule: `to * by peername="IP=192.0.2.27:38900" read`, want: true},
		{name: "peer regex", rule: `to * by peername.regex="^IP=192[.]0[.]2[.]27:[0-9]+$" read`, want: true},
		{name: "peer IPv4 mask", rule: `to * by peername.ip="192.0.2.0%255.255.255.0" read`, want: true},
		{name: "peer IPv4 port mismatch", rule: `to * by peername.ip="192.0.2.0%255.255.255.0{389}" read`},
		{name: "socket exact", rule: `to * by sockname="IP=192.0.2.10:389" read`, want: true},
		{name: "domain subtree", rule: `to * by domain.subtree="example.com" read`, want: true},
		{name: "domain boundary", rule: `to * by domain.subtree="ample.com" read`},
		{name: "listener URL", rule: `to * by sockurl="ldap://192.0.2.10:389" read`, want: true},
		{name: "overall SSF", rule: `to * by ssf=128 read`, want: true},
		{name: "transport SSF", rule: `to * by transport_ssf=1 read`},
		{name: "TLS SSF", rule: `to * by tls_ssf=128 read`, want: true},
		{name: "SASL SSF", rule: `to * by sasl_ssf=1 read`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
			if err != nil {
				t.Fatalf("NewPolicy(): %v", err)
			}
			if got := policy.Allowed(subject, target, Read, nil); got != test.want {
				t.Errorf("Allowed() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestACLConnectionExpansionAndIPv6(t *testing.T) {
	t.Parallel()

	target := Target{
		Entry:     directory.Entry{DN: "uid=alice,dc=example,dc=com"},
		Attribute: "entry",
	}
	tests := []struct {
		rule    string
		subject Subject
	}{
		{
			rule:    `to dn.regex="^uid=([^,]+),dc=example,dc=com$" by domain.exact,expand="$1.example.com" read`,
			subject: Subject{Domain: "alice.example.com"},
		},
		{
			rule:    `to * by peername.ipv6="2001:db8::%ffff:ffff:ffff:ffff::{443}" read`,
			subject: Subject{PeerName: "IP=[2001:db8::42]:443"},
		},
		{
			rule:    `to * by peername.path="/var/run/ldap.sock" read`,
			subject: Subject{PeerName: "PATH=/var/run/ldap.sock"},
		},
	}
	for _, test := range tests {
		policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
		if err != nil {
			t.Fatalf("NewPolicy(): %v", err)
		}
		if !policy.Allowed(test.subject, target, Read, nil) {
			t.Errorf("expanded connection ACL denied rule %q", test.rule)
		}
	}
}

func TestACLSetExpressions(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	entries := []directory.Entry{
		{
			DN: aliceDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("inetOrgPerson")},
				{Description: "uid", Values: bytes("alice")},
				{Description: "cn", Values: bytes("Alice")},
				{Description: "sn", Values: bytes("Alice")},
				{Description: "manager", Values: bytes("uid=admin,dc=example,dc=com")},
			},
		},
		{
			DN: "cn=readers,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfNames")},
				{Description: "cn", Values: bytes("readers")},
				{Description: "member", Values: bytes(aliceDN)},
			},
		},
		{
			DN: "cn=outer,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfNames")},
				{Description: "cn", Values: bytes("outer")},
				{Description: "member", Values: bytes("cn=readers,ou=groups,dc=example,dc=com")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed set entries: %v", err)
	}
	target := Target{Entry: entries[0], Attribute: "cn", Value: []byte("Alice"), Schema: registry}
	tests := []struct {
		name    string
		rule    string
		subject string
		want    bool
	}{
		{
			name:    "attribute chase",
			rule:    `to * by set="[cn=readers,ou=groups,dc=example,dc=com]/member & user" read`,
			subject: aliceDN,
			want:    true,
		},
		{
			name:    "recursive chase",
			rule:    `to * by set="[cn=outer,ou=groups,dc=example,dc=com]/member* & user" read`,
			subject: aliceDN,
			want:    true,
		},
		{
			name:    "target attribute",
			rule:    `to * by set="this/manager & user" read`,
			subject: "uid=admin,dc=example,dc=com",
			want:    true,
		},
		{
			name: "parent",
			rule: `to * by set="this/-1 & [ou=people,dc=example,dc=com]" read`,
			want: true,
		},
		{
			name: "concatenation",
			rule: `to * by set="[uid=]+[alice] & [uid=alice]" read`,
			want: true,
		},
		{
			name:    "local LDAP URL",
			rule:    `to * by set="[ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)]/entryDN & user" read`,
			subject: aliceDN,
			want:    true,
		},
		{
			name:    "member mismatch",
			rule:    `to * by set="[cn=readers,ou=groups,dc=example,dc=com]/member & user" read`,
			subject: "uid=bob,ou=people,dc=example,dc=com",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
			if err != nil {
				t.Fatalf("NewPolicy(): %v", err)
			}
			if err := store.View(context.Background(), func(reader storage.Reader) error {
				got := policy.Allowed(Subject{DN: test.subject}, target, Read, reader)
				if got != test.want {
					t.Errorf("Allowed() = %v, want %v", got, test.want)
				}
				return nil
			}); err != nil {
				t.Fatalf("View(): %v", err)
			}
		})
	}
}

func TestACLStaticAndDynamicGroups(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	bobDN := "uid=bob,ou=people,dc=example,dc=com"
	alice := directory.Entry{
		DN: aliceDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: bytes("inetOrgPerson")},
			{Description: "uid", Values: bytes("alice")},
			{Description: "cn", Values: bytes("Alice")},
			{Description: "sn", Values: bytes("Alice")},
		},
	}
	entries := []directory.Entry{
		alice,
		{
			DN: "cn=unique,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfUniqueNames")},
				{Description: "cn", Values: bytes("unique")},
				{Description: "uniqueMember", Values: bytes(aliceDN)},
			},
		},
		{
			DN: "cn=uid-bound,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfUniqueNames")},
				{Description: "cn", Values: bytes("uid-bound")},
				{Description: "uniqueMember", Values: bytes(aliceDN + "#'101'B")},
			},
		},
		{
			DN: "cn=dynamic,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfURLs")},
				{Description: "cn", Values: bytes("dynamic")},
				{
					Description: "memberURL",
					Values: bytes(
						"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)",
					),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ACL groups: %v", err)
	}
	target := Target{Entry: alice, Attribute: "cn", Value: []byte("Alice"), Schema: registry}
	tests := []struct {
		name    string
		rule    string
		subject string
		want    bool
	}{
		{
			name:    "unique member",
			rule:    `to * by group/groupOfUniqueNames/uniqueMember="cn=unique,ou=groups,dc=example,dc=com" read`,
			subject: aliceDN,
			want:    true,
		},
		{
			name:    "optional UID does not match bare subject DN",
			rule:    `to * by group/groupOfUniqueNames/uniqueMember="cn=uid-bound,ou=groups,dc=example,dc=com" read`,
			subject: aliceDN,
		},
		{
			name:    "dynamic URL member",
			rule:    `to * by group/groupOfURLs/memberURL="cn=dynamic,ou=groups,dc=example,dc=com" read`,
			subject: aliceDN,
			want:    true,
		},
		{
			name:    "dynamic URL filter mismatch",
			rule:    `to * by group/groupOfURLs/memberURL="cn=dynamic,ou=groups,dc=example,dc=com" read`,
			subject: bobDN,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewPolicy([]Rule{mustRule(t, test.rule)}, nil)
			if err != nil {
				t.Fatalf("NewPolicy(): %v", err)
			}
			if err := policy.Validate(registry); err != nil {
				t.Fatalf("Validate(): %v", err)
			}
			if err := store.View(context.Background(), func(reader storage.Reader) error {
				got := policy.Allowed(Subject{DN: test.subject}, target, Read, reader)
				if got != test.want {
					t.Errorf("Allowed() = %v, want %v", got, test.want)
				}
				return nil
			}); err != nil {
				t.Fatalf("View(): %v", err)
			}
		})
	}
}

func TestDefaultPolicyMatchesOpenLDAPReadDefault(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy()
	target := Target{Entry: testEntry(), Attribute: "cn"}
	if !policy.Allowed(Subject{}, target, Read, nil) {
		t.Fatal("default read denied")
	}
	if policy.Allowed(Subject{}, target, Write, nil) {
		t.Fatal("default write allowed")
	}
	target.Entry.DN = "olcDatabase={1}mdb,cn=config"
	if policy.Allowed(Subject{}, target, Read, nil) {
		t.Fatal("cn=config backend default read allowed")
	}
}

func mustRule(t *testing.T, value string) Rule {
	t.Helper()
	rule, err := ParseRule(value)
	if err != nil {
		t.Fatalf("ParseRule(%q): %v", value, err)
	}
	return rule
}

func testEntry() directory.Entry {
	return directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: bytes("inetOrgPerson")},
			{Description: "cn", Values: bytes("Alice")},
			{Description: "mail", Values: bytes("alice@example.com")},
			{Description: "userPassword", Values: bytes("secret")},
		},
	}
}

func bytes(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = []byte(values[i])
	}
	return result
}
