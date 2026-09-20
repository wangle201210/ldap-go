package server

import (
	"fmt"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestRetcodePasswordModifyOrdinaryEntry(t *testing.T) {
	address := startRetcodePasswordModifyTestServer(t, []string{"to * by * read"})
	conn := dialAndBindRawLDAP(t, address, "cn=admin,dc=example,dc=com", "secret")
	defer conn.Close()
	value := ldapwire.EncodePasswordModifyRequestValue(ldapwire.PasswordModifyRequestValue{
		UserIdentity: []byte("uid=alice,ou=people,dc=example,dc=com"), HasUserIdentity: true,
		OldPassword: []byte("secret"), HasOldPassword: true,
		NewPassword: []byte("replacement"), HasNewPassword: true,
	})
	response := sendRawLDAPOperation(t, conn, 2, rawExtendedRequest(passwordModifyOID, value, true))
	assertRetcodeWireResponse(t, response, 2, ldapwire.ApplicationExtendedResponse, ldap.LDAPResultSuccess)
	response = sendRawLDAPOperation(t, conn, 3, rawExtendedRequest(whoAmIOID, nil, false))
	assertRetcodeWireResponse(t, response, 3, ldapwire.ApplicationExtendedResponse, ldap.LDAPResultSuccess)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "replacement"); err != nil {
		t.Fatal(err)
	}
}

func TestRetcodePasswordModifyTransactionAtomicity(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure=%t", fail), func(t *testing.T) {
			entries := make([]directory.Entry, 2)
			for i, operation := range []string{"extended", "modify"} {
				entries[i] = directory.Entry{DN: fmt.Sprintf("cn=Transaction-%d,ou=people,dc=example,dc=com", i), Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("errObject", "extensibleObject")},
					{Description: "cn", Values: stringValues(fmt.Sprintf("Transaction-%d", i))},
					{Description: "errCode", Values: stringValues("53")},
					{Description: "errOp", Values: stringValues(operation)},
					{Description: "userPassword", Values: stringValues("old-secret")},
				}}
			}
			address := startRetcodePasswordModifyTestServer(t, []string{"to * by * read"}, entries...)
			conn := dialAndBindRawLDAP(t, address, "cn=admin,dc=example,dc=com", "secret")
			defer conn.Close()
			identifier := startRawLDAPTransaction(t, conn, 2)
			count := 1
			if fail {
				count = 2
			}
			for i := 0; i < count; i++ {
				value := ldapwire.EncodePasswordModifyRequestValue(ldapwire.PasswordModifyRequestValue{
					UserIdentity: []byte(entries[i].DN), HasUserIdentity: true,
					OldPassword: []byte("old-secret"), HasOldPassword: true,
					NewPassword: []byte("replacement"), HasNewPassword: true,
				})
				response := sendRawLDAPOperation(t, conn, int64(3+i), rawExtendedRequest(passwordModifyOID, value, true), rawTransactionSpecificationControl(identifier, true, true))
				assertRetcodeWireResponse(t, response, int64(3+i), ldapwire.ApplicationExtendedResponse, ldap.LDAPResultSuccess)
			}
			response := endRawLDAPTransaction(t, conn, 5, true, identifier)
			code := uint16(ldap.LDAPResultSuccess)
			if fail {
				code = ldap.LDAPResultUnwillingToPerform
			}
			assertRetcodeWireResponse(t, response, 5, ldapwire.ApplicationExtendedResponse, code)
			if fail {
				value, present := rawExtendedResponseValue(response)
				result, err := ldapwire.DecodeTransactionEndResponseValue(value)
				if !present || err != nil || !result.HasFailedMessageID || result.FailedMessageID != 4 {
					t.Fatalf("failed transaction result=%+v present=%t err=%v", result, present, err)
				}
			}
			response = sendRawLDAPOperation(t, conn, 6, rawExtendedRequest(whoAmIOID, nil, false))
			assertRetcodeWireResponse(t, response, 6, ldapwire.ApplicationExtendedResponse, ldap.LDAPResultSuccess)
			client := bindOverlayReferenceClient(t, "ldap://"+address, "secret")
			defer client.Close()
			for i, entry := range entries {
				result, err := client.Search(ldap.NewSearchRequest(entry.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"userPassword"}, []ldap.Control{ldap.NewControlManageDsaIT(true)}))
				if err != nil || len(result.Entries) != 1 {
					t.Fatalf("read password: result=%+v err=%v", result, err)
				}
				want := "old-secret"
				if !fail && i == 0 {
					want = "replacement"
				}
				if !auth.VerifyPassword(result.Entries[0].GetRawAttributeValue("userPassword"), []byte(want)) {
					t.Fatalf("entry %s has incorrect committed password", entry.DN)
				}
			}
		})
	}
}
