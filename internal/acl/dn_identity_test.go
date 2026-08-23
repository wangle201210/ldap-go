package acl

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestPolicySchemaAwareDNIdentity(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.990.1 NAME ( 'aclExactName' 'aclExactAlias' ) EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.990.2 NAME ( 'aclFoldName' 'aclFoldAlias' ) EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(): %v", err)
		}
	}

	entry := directory.Entry{
		DN: "aclExactName=Alice+aclFoldName=Primary Team,dc=example,dc=com",
	}
	equivalent := "1.3.6.1.4.1.99999.990.2=PRIMARY TEAM+" +
		"aclExactAlias=Alice,DC=EXAMPLE,DC=COM"
	distinct := "aclExactName=alice+aclFoldName=Primary Team,dc=example,dc=com"
	target := Target{
		Entry:        entry,
		Attribute:    "mail",
		Schema:       registry,
		DNNormalizer: registry,
	}

	self, err := NewPolicy([]Rule{
		mustRule(t, "{0}to * by self write by * none"),
	}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(self): %v", err)
	}
	if !self.Allowed(Subject{DN: equivalent}, target, Write, nil) {
		t.Fatal("schema-equivalent self was denied")
	}
	if self.Allowed(Subject{DN: distinct}, target, Write, nil) {
		t.Fatal("caseExact-distinct sibling matched self")
	}

	explicit, err := NewPolicy([]Rule{
		mustRule(t, `{0}to * by dn.exact="`+equivalent+`" read by * none`),
	}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(dn.exact): %v", err)
	}
	if !explicit.Allowed(Subject{DN: entry.DN}, target, Read, nil) {
		t.Fatal("schema-equivalent dn.exact subject was denied")
	}

	selfValue, err := NewPolicy([]Rule{
		mustRule(t, "{0}to attrs=owner by users selfwrite by * none"),
	}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(selfwrite): %v", err)
	}
	valueTarget := target
	valueTarget.Attribute = "owner"
	valueTarget.Value = []byte(equivalent)
	valueTarget.DNValued = true
	if !selfValue.Allowed(Subject{DN: entry.DN}, valueTarget, Write, nil) {
		t.Fatal("schema-equivalent selfwrite value was denied")
	}
}
