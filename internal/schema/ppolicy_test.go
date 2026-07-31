package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestBuiltinPasswordPolicySchema(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	changed, ok := registry.AttributeType("pwdChangedTime")
	if !ok ||
		changed.OID != "1.3.6.1.4.1.42.2.27.8.1.16" ||
		!changed.SingleValue ||
		!changed.NoUserModification ||
		changed.Usage != UsageDirectoryOperation {
		t.Fatalf("pwdChangedTime = %#v, found %t", changed, ok)
	}
	temporaryLock, ok := registry.AttributeType(
		"1.3.6.1.4.1.42.2.27.8.1.33",
	)
	if !ok ||
		temporaryLock.Name() != "pwdAccountTmpLockoutEnd" ||
		!temporaryLock.NoUserModification {
		t.Fatalf(
			"pwdAccountTmpLockoutEnd = %#v, found %t",
			temporaryLock,
			ok,
		)
	}
	policy, ok := registry.ObjectClass("pwdPolicy")
	if !ok ||
		policy.OID != "1.3.6.1.4.1.42.2.27.8.2.1" ||
		policy.Kind != ObjectClassAuxiliary {
		t.Fatalf("pwdPolicy = %#v, found %t", policy, ok)
	}

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      [][]byte{[]byte("inetOrgPerson")},
			},
			{Description: "uid", Values: [][]byte{[]byte("alice")}},
			{Description: "cn", Values: [][]byte{[]byte("Alice")}},
			{Description: "sn", Values: [][]byte{[]byte("Example")}},
			{
				Description: "pwdAccountLockedTime",
				Values:      [][]byte{[]byte("000001010000Z")},
			},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(permanent lock sentinel): %v", err)
	}
}
