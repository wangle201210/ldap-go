package acl

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
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
				Values:      bytes(`{0}to filter="(uid=*)" by * manage`),
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
