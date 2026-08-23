package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestDNIdentityRetcodeMatchedDN(t *testing.T) {
	registry := dnIdentityOverlayScopeRegistry(t)
	parent := mustDNIdentityOverlayScopeDN(
		t,
		registry,
		"scopeExactName=Retcodes,dc=example,dc=com",
	)
	item, err := parseRetcodeItem(
		[]string{
			"cn=failure",
			"53",
			`matched=1.3.6.1.4.1.99999.917.2=\20REMOTE\20\20TENANT\20,DC=EXAMPLE,DC=COM`,
		},
		parent,
		registry,
	)
	if err != nil {
		t.Fatalf("parseRetcodeItem(): %v", err)
	}
	if got, want := item.matchedDN,
		`scopeFoldName=\ REMOTE  TENANT\ ,dc=EXAMPLE,dc=COM`; got != want {
		t.Fatalf("configured matched DN = %q, want %q", got, want)
	}

	directoryItem, applies := retcodeItemFromDirectoryEntry(
		&runtimeState{schema: registry},
		directory.Entry{
			DN: "cn=failure," + parent.String(),
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("errAbsObject")},
				{Description: "errCode", Values: stringValues("53")},
				{Description: "errOp", Values: stringValues("search")},
				{
					Description: "errMatchedDN",
					Values: stringValues(
						"1.3.6.1.4.1.99999.917.1=Tenant,dc=example,dc=com",
					),
				},
			},
		},
		retcodeOperationSearch,
	)
	if !applies || directoryItem.code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf("directory retcode item = %#v, applies=%t", directoryItem, applies)
	}
	if got, want := directoryItem.matchedDN,
		"scopeExactName=Tenant,dc=example,dc=com"; got != want {
		t.Fatalf("directory matched DN = %q, want %q", got, want)
	}
}
