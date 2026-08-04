package acl

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type aciMapReader map[string]directory.Entry

func (reader aciMapReader) Get(dn directory.DN) (directory.Entry, error) {
	entry, ok := reader[dn.Key()]
	if !ok {
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	return entry.Clone(), nil
}

func TestACIDynamicMaskAndScopes(t *testing.T) {
	t.Parallel()

	registry := mustACIRegistry(t)
	target := aciTarget(registry)
	parentDN := mustACIDN(t, "ou=people,dc=example,dc=com")
	rootDN := mustACIDN(t, "dc=example,dc=com")
	reader := aciMapReader{
		parentDN.Key(): {
			DN: parentDN.String(),
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("organizationalUnit")},
				{Description: "ou", Values: bytes("people")},
			},
		},
		rootDN.Key(): {
			DN: rootDN.String(),
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("domain")},
				{Description: "dc", Values: bytes("example")},
			},
		},
	}

	t.Run("entry grant and deny", func(t *testing.T) {
		candidate := target
		candidate.Entry = candidate.Entry.Clone()
		candidate.Entry.Attributes = append(candidate.Entry.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values: bytes(
				"0#entry#grant;r;cn#public#",
				"1#entry#deny;r;cn#public#",
			),
		})
		if aciAllowed(t, candidate, Subject{}, Read, reader, "write") {
			t.Fatal("same-level ACI deny did not override grant")
		}
	})

	t.Run("permission pairs stay independent", func(t *testing.T) {
		candidate := target
		candidate.Entry = candidate.Entry.Clone()
		candidate.Entry.Attributes = append(candidate.Entry.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values:      bytes("0#entry#grant;s;cn;r;mail#public#"),
		})
		if !aciAllowed(t, candidate, Subject{}, Search, reader, "write") {
			t.Fatal("search right for cn was denied")
		}
		if aciAllowed(t, candidate, Subject{}, Read, reader, "write") {
			t.Fatal("read right for mail leaked to cn")
		}
		candidate.Attribute = "mail"
		candidate.Value = []byte("alice@example.com")
		if !aciAllowed(t, candidate, Subject{}, Read, reader, "write") {
			t.Fatal("read right for mail was denied")
		}
	})

	t.Run("static clause caps dynamic grant", func(t *testing.T) {
		candidate := target
		candidate.Entry = candidate.Entry.Clone()
		candidate.Entry.Attributes = append(candidate.Entry.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values:      bytes("0#entry#grant;w;cn#public#"),
		})
		if aciAllowed(t, candidate, Subject{}, WriteAdd, reader, "read") {
			t.Fatal("ACI grant exceeded by-clause static read cap")
		}
	})

	t.Run("attribute value prefix", func(t *testing.T) {
		candidate := target
		candidate.Attribute = "mail"
		candidate.Value = []byte("Allowed@example.com")
		candidate.Entry = candidate.Entry.Clone()
		candidate.Entry.Attributes = append(candidate.Entry.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values:      bytes("0#entry#grant;r;mail=allowed*#public#"),
		})
		if !aciAllowed(t, candidate, Subject{}, Read, reader, "write") {
			t.Fatal("matching ACI value prefix was denied")
		}
		candidate.Value = []byte("hidden@example.com")
		if aciAllowed(t, candidate, Subject{}, Read, reader, "write") {
			t.Fatal("nonmatching ACI value prefix was allowed")
		}
	})

	t.Run("parent subtree", func(t *testing.T) {
		local := cloneACIReader(reader)
		parent := local[parentDN.Key()]
		parent.Attributes = append(parent.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values:      bytes("0#subtree#grant;r;cn#public#"),
		})
		local[parentDN.Key()] = parent
		if !aciAllowed(t, target, Subject{}, Read, local, "write") {
			t.Fatal("parent subtree ACI was not inherited")
		}
	})

	t.Run("entry scope is not inherited", func(t *testing.T) {
		local := cloneACIReader(reader)
		parent := local[parentDN.Key()]
		parent.Attributes = append(parent.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values:      bytes("0#entry#grant;r;cn#public#"),
		})
		local[parentDN.Key()] = parent
		if aciAllowed(t, target, Subject{}, Read, local, "write") {
			t.Fatal("parent entry-scope ACI was inherited")
		}
	})

	t.Run("closest matching parent stops traversal", func(t *testing.T) {
		local := cloneACIReader(reader)
		parent := local[parentDN.Key()]
		parent.Attributes = append(parent.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values:      bytes("0#children#deny;r;cn#public#"),
		})
		local[parentDN.Key()] = parent
		root := local[rootDN.Key()]
		root.Attributes = append(root.Attributes, directory.Attribute{
			Description: "OpenLDAPaci",
			Values:      bytes("0#subtree#grant;r;cn#public#"),
		})
		local[rootDN.Key()] = root
		if aciAllowed(t, target, Subject{}, Read, local, "write") {
			t.Fatal("ancestor grant bypassed a closer parent deny")
		}
	})
}

func TestACISubjectTypes(t *testing.T) {
	t.Parallel()

	registry := mustACIRegistry(t)
	target := aciTarget(registry)
	aliceDN := target.Entry.DN
	bobDN := "uid=bob,ou=people,dc=example,dc=com"
	groupDN := "cn=readers,ou=groups,dc=example,dc=com"
	roleDN := "cn=operators,ou=groups,dc=example,dc=com"
	setDN := "cn=acl-set,ou=groups,dc=example,dc=com"
	reader := aciMapReader{}
	for _, entry := range []directory.Entry{
		target.Entry,
		{
			DN: groupDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("groupOfNames")},
				{Description: "cn", Values: bytes("readers")},
				{Description: "member", Values: bytes(bobDN)},
			},
		},
		{
			DN: roleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("organizationalRole")},
				{Description: "cn", Values: bytes("operators")},
				{Description: "roleOccupant", Values: bytes(bobDN)},
			},
		},
		{
			DN: setDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("extensibleObject")},
				{Description: "cn", Values: bytes("acl-set")},
				{Description: "template", Values: bytes("[" + bobDN + "] & user")},
			},
		},
	} {
		dn := mustACIDN(t, entry.DN)
		reader[dn.Key()] = entry
	}

	tests := []struct {
		name    string
		aci     string
		subject string
		want    bool
	}{
		{name: "public anonymous", aci: "0#entry#grant;r;cn#public#", want: true},
		{name: "users authenticated", aci: "0#entry#grant;r;cn#users#", subject: bobDN, want: true},
		{name: "users anonymous", aci: "0#entry#grant;r;cn#users#"},
		{name: "self", aci: "0#entry#grant;r;cn#self#", subject: aliceDN, want: true},
		{name: "access id", aci: "0#entry#grant;r;cn#access-id#" + bobDN, subject: bobDN, want: true},
		{name: "subtree", aci: "0#entry#grant;r;cn#subtree#ou=people,dc=example,dc=com", subject: bobDN, want: true},
		{name: "children", aci: "0#entry#grant;r;cn#children#ou=people,dc=example,dc=com", subject: bobDN, want: true},
		{name: "children excludes base", aci: "0#entry#grant;r;cn#children#ou=people,dc=example,dc=com", subject: "ou=people,dc=example,dc=com"},
		{name: "onelevel OpenLDAP semantics", aci: "0#entry#grant;r;cn#onelevel#uid=placeholder,ou=people,dc=example,dc=com", subject: "ou=people,dc=example,dc=com", want: true},
		{name: "dnattr", aci: "0#entry#grant;r;cn#dnattr#owner", subject: bobDN, want: true},
		{name: "group", aci: "0#entry#grant;r;cn#group#" + groupDN, subject: bobDN, want: true},
		{name: "role", aci: "0#entry#grant;r;cn#role#" + roleDN, subject: bobDN, want: true},
		{name: "set", aci: "0#entry#grant;r;cn#set#[" + bobDN + "] & user", subject: bobDN, want: true},
		{name: "set ref", aci: "0#entry#grant;r;cn#set-ref#" + setDN + "/template", subject: bobDN, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := target
			candidate.Entry = candidate.Entry.Clone()
			candidate.Entry.Attributes = append(candidate.Entry.Attributes, directory.Attribute{
				Description: "OpenLDAPaci",
				Values:      bytes(test.aci),
			})
			got := aciAllowed(t, candidate, Subject{DN: test.subject}, Read, reader, "write")
			if got != test.want {
				t.Fatalf("Allowed() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestACIParserAndCustomAttributeValidation(t *testing.T) {
	t.Parallel()

	defaultRule := mustRule(t, "to * by dynacl/aci write")
	if len(defaultRule.By) != 1 || len(defaultRule.By[0].Who) != 1 ||
		defaultRule.By[0].Who[0].Kind != WhoACI ||
		defaultRule.By[0].Who[0].ACIAttribute != "OpenLDAPaci" {
		t.Fatalf("default ACI matcher = %#v", defaultRule.By)
	}
	customRule := mustRule(t, "to * by dynacl/aci=customACI write")
	registry := mustACIRegistry(t)
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.3.6.1.4.1.99999.1 NAME 'customACI' EQUALITY OpenLDAPaciMatch " +
			"SYNTAX " + schema.SyntaxOpenLDAPACI + " )",
	); err != nil {
		t.Fatalf("register custom ACI attribute: %v", err)
	}
	policy, err := NewPolicy([]Rule{customRule}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	if err := policy.Validate(registry); err != nil {
		t.Fatalf("Validate(custom ACI): %v", err)
	}

	wrongRule := mustRule(t, "to * by dynacl/aci=description write")
	wrongPolicy, err := NewPolicy([]Rule{wrongRule}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(wrong): %v", err)
	}
	if err := wrongPolicy.Validate(registry); err == nil {
		t.Fatal("ACI matcher accepted a Directory String attribute")
	}
}

func aciAllowed(
	t *testing.T,
	target Target,
	subject Subject,
	required Privilege,
	reader EntryReader,
	cap string,
) bool {
	t.Helper()
	policy, err := NewPolicy([]Rule{mustRule(t, fmt.Sprintf("to * by dynacl/aci %s", cap))}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	if err := policy.Validate(target.Schema); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	return policy.Allowed(subject, target, required, reader)
}

func aciTarget(registry *schema.Registry) Target {
	return Target{
		Entry: directory.Entry{
			DN: "uid=alice,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: bytes("inetOrgPerson")},
				{Description: "uid", Values: bytes("alice")},
				{Description: "cn", Values: bytes("Alice")},
				{Description: "sn", Values: bytes("Alice")},
				{Description: "mail", Values: bytes("alice@example.com")},
				{Description: "owner", Values: bytes("uid=bob,ou=people,dc=example,dc=com")},
			},
		},
		Attribute: "cn",
		Value:     []byte("Alice"),
		Schema:    registry,
	}
}

func mustACIRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	return registry
}

func mustACIDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func cloneACIReader(reader aciMapReader) aciMapReader {
	result := make(aciMapReader, len(reader))
	for key, entry := range reader {
		result[key] = entry.Clone()
	}
	return result
}
