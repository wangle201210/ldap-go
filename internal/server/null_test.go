package server

import (
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPNullBackendMatchesOpenLDAPSemantics(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedNullConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	got := observeNullReference(t, "ldap://"+address)
	want := expectedNullReferenceResult()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("null backend behavior = %#v, want %#v", got, want)
	}
}

func expectedNullReferenceResult() nullReferenceResult {
	entry := "dc=null,dc=example|" +
		"dc=null;entrydn=dc=null,dc=example;" +
		"objectclass=extensibleObject;subschemasubentry=cn=Subschema"
	return nullReferenceResult{
		searches: []nullReferenceSearch{
			{
				base:       "dc=null,dc=example",
				scope:      ldap.ScopeBaseObject,
				filter:     "(objectClass=*)",
				resultCode: ldap.LDAPResultSuccess,
				entries:    []string{entry},
			},
			{
				base:       "dc=null,dc=example",
				scope:      ldap.ScopeSingleLevel,
				filter:     "(objectClass=*)",
				resultCode: ldap.LDAPResultSuccess,
				entries:    []string{entry},
			},
			{
				base:       "dc=null,dc=example",
				scope:      ldap.ScopeWholeSubtree,
				filter:     "(objectClass=domain)",
				resultCode: ldap.LDAPResultSuccess,
				entries:    []string{entry},
			},
			{
				base:       "uid=child,dc=null,dc=example",
				scope:      ldap.ScopeBaseObject,
				filter:     "(dc=missing)",
				resultCode: ldap.LDAPResultSuccess,
				entries:    []string{entry},
			},
			{
				base:       "dc=empty,dc=example",
				scope:      ldap.ScopeBaseObject,
				filter:     "(objectClass=*)",
				resultCode: ldap.LDAPResultSuccess,
			},
		},
		bindAllowedCode:   ldap.LDAPResultSuccess,
		bindDeniedCode:    ldap.LDAPResultInvalidCredentials,
		rootBindCode:      ldap.LDAPResultSuccess,
		writeCodes:        []uint16{0, 0, 0, 0},
		compareValue:      false,
		compareCode:       ldap.LDAPResultSuccess,
		assertSearchCode:  ldap.LDAPResultAssertionFailed,
		assertModifyCode:  ldap.LDAPResultAssertionFailed,
		pagedEntries:      []string{"dc=null,dc=example"},
		pagedControlFound: true,
		typesOnlyEntries: []string{
			"dc=",
			"entrydn=",
			"objectclass=",
			"subschemasubentry=",
		},
		readControlShapes: []string{
			preReadControlOID + "|uid=missing,dc=null,dc=example|entrydn,subschemasubentry",
			postReadControlOID + "|uid=missing,dc=null,dc=example|entrydn,subschemasubentry",
		},
		noOpCodes: []uint16{
			uint16(ldapwire.ResultNoOperation),
			uint16(ldapwire.ResultNoOperation),
			uint16(ldapwire.ResultNoOperation),
			uint16(ldapwire.ResultNoOperation),
		},
		emptyAddCode: ldap.LDAPResultProtocolError,
	}
}
