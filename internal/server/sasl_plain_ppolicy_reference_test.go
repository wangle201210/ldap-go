package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Native OpenLDAP 2.6.13 uses a SASL auxprop Search to obtain the directory
// password, bypassing the ppolicy Bind callback. Simple Bind is the positive
// control: the same accounts and policy must reject locked/expired passwords
// and record failures. This does not cover external SASL password checkers.
func TestOpenLDAP2613SASLPlainPasswordPolicyBoundary(t *testing.T) {
	tools := requireSASLCBindingOpenLDAP(t)
	policy := []directory.Attribute{
		{Description: "pwdLockout", Values: stringValues("TRUE")},
		{Description: "pwdLockoutDuration", Values: stringValues("0")},
		{Description: "pwdMaxFailure", Values: stringValues("2")},
		{Description: "pwdMaxRecordedFailure", Values: stringValues("3")},
		{Description: "pwdMaxAge", Values: stringValues("60")},
		{Description: "pwdGraceAuthNLimit", Values: stringValues("0")},
	}
	users := []struct{ uid, state string }{
		{"plain-healthy", ""},
		{"plain-locked", "pwdAccountLockedTime"},
		{"plain-expired", "pwdChangedTime"},
		{"plain-counter", ""},
	}
	var fixture strings.Builder
	fmt.Fprintf(&fixture, "\ndn: ou=policies,dc=example,dc=com\nobjectClass: organizationalUnit\nou: policies\n\ndn: %s\nobjectClass: device\nobjectClass: pwdPolicy\ncn: default\npwdAttribute: 2.5.4.35\n", passwordPolicyDN)
	for _, attribute := range policy {
		fmt.Fprintf(&fixture, "%s: %s\n", attribute.Description, attribute.Values[0])
	}
	for _, user := range users {
		fmt.Fprintf(&fixture, "\ndn: uid=%s,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: User\nuserPassword: secret\n", user.uid, user.uid, user.uid)
		if user.state != "" {
			fmt.Fprintf(&fixture, "%s: 20000101000000Z\n", user.state)
		}
	}

	// Permit PLAIN only on this disposable loopback fixture. Real deployments
	// must protect password-bearing authentication with TLS.
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil,
		`sasl-secprops none
sasl-auxprops slapd
authz-regexp "^uid=([^,]+),.*cn=auth$" "uid=$1,ou=people,dc=example,dc=com"`,
		`access to attrs=userPassword by self =xw by anonymous auth by * none
access to * by self write by anonymous auth by users read by * none
overlay ppolicy
ppolicy_default "cn=default,ou=policies,dc=example,dc=com"
ppolicy_use_lockout`, fixture.String())
	if !t.Run("OpenLDAP-2.6.13", func(t *testing.T) {
		checkSASLPlainPasswordPolicyBoundary(t, trimLDAPURI(uri))
	}) {
		stop()
		t.Fatal("native reference did not establish the expected boundary")
	}
	stop()

	t.Run("ldap-go", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedPasswordPolicyDirectory(t, store, policy, []directory.Attribute{
			{Description: "olcPPolicyUseLockout", Values: stringValues("TRUE")},
		})
		seedSASLConfiguration(t, store, "none", `{0}^uid=([^,]+),.*cn=auth$ uid=$1,ou=people,dc=example,dc=com`)
		setPasswordPolicyEntryValues(t, store, "olcDatabase={1}mdb,cn=config", map[string][][]byte{
			"olcAccess": stringValues(
				"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
				"{1}to * by self write by anonymous auth by users read by * none",
			),
		})
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			for _, user := range users {
				entry := directory.Entry{
					DN: "uid=" + user.uid + ",ou=people,dc=example,dc=com",
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("inetOrgPerson")},
						{Description: "uid", Values: stringValues(user.uid)},
						{Description: "cn", Values: stringValues(user.uid)},
						{Description: "sn", Values: stringValues("User")},
						{Description: "userPassword", Values: stringValues("secret")},
					},
				}
				if user.state != "" {
					entry.ReplaceValues(user.state, stringValues("20000101000000Z"))
				}
				if err := writer.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		address, stop := startServer(t, store, Config{
			RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("secret"),
		})
		defer stop()
		checkSASLPlainPasswordPolicyBoundary(t, address)
	})
}

func checkSASLPlainPasswordPolicyBoundary(t *testing.T, address string) {
	t.Helper()
	admin, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	admin.SetTimeout(3 * time.Second)
	if err := admin.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	state := func(t *testing.T, uid string, wantFailures int, wantLocked bool) {
		t.Helper()
		result, err := admin.Search(ldap.NewSearchRequest(
			"uid="+uid+",ou=people,dc=example,dc=com", ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 1, 2, false, "(objectClass=*)",
			[]string{"pwdFailureTime", "pwdAccountLockedTime"}, nil))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("read policy state: %v, %v", result, err)
		}
		failures := len(result.Entries[0].GetAttributeValues("pwdFailureTime"))
		locked := result.Entries[0].GetAttributeValue("pwdAccountLockedTime") != ""
		if failures != wantFailures || locked != wantLocked {
			t.Fatalf("%s failures=%d locked=%t; want %d, %t", uid, failures, locked, wantFailures, wantLocked)
		}
	}
	bind := func(t *testing.T, plain bool, uid, password string, wantCode int64) {
		t.Helper()
		connection, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		dn := "uid=" + uid + ",ou=people,dc=example,dc=com"
		var request *ber.Packet
		if plain {
			request = rawSASLBindRequest("PLAIN", []byte("\x00"+uid+"\x00"+password))
		} else {
			request = rawSimpleBindRequestVersion(3, dn, password)
		}
		response := sendRawLDAPOperation(t, connection, 1, request,
			rawControlWithoutValue(passwordPolicyControlOID))
		if len(response.Children) < 2 {
			t.Fatal("malformed Bind response")
		}
		code := rawLDAPResultCode(t, response.Children[1])
		if code != wantCode {
			t.Fatalf("%s PLAIN=%t code=%d; want %d; response=%x", uid, plain, code, wantCode, response.Bytes())
		}
		control, hasControl := rawLDAPResponseControls(response)[passwordPolicyControlOID]
		if plain && hasControl {
			t.Fatalf("PLAIN unexpectedly returned ppolicy control: %x", control)
		}
		if !plain && wantCode == ldap.LDAPResultInvalidCredentials && password == "secret" {
			decoded, ok := decodeOpenLDAPPasswordPolicyTimingControl(control)
			wantError := int64(1) // accountLocked
			if uid == "plain-expired" {
				wantError = 0 // passwordExpired
			}
			if !hasControl || !ok || decoded.errorCode != wantError {
				t.Fatalf("Simple Bind policy error=%x; want %d", control, wantError)
			}
		}
		if code == ldap.LDAPResultSuccess {
			client := ldap.NewConn(connection, false)
			client.Start()
			defer client.Close()
			identity, err := client.WhoAmI(nil)
			if err != nil || identity.AuthzID != "dn:"+dn {
				t.Fatalf("WhoAmI = %v, %v; want dn:%s", identity, err, dn)
			}
		}
	}
	t.Run("healthy-mapped-identity", func(t *testing.T) {
		bind(t, false, "plain-healthy", "secret", ldap.LDAPResultSuccess)
		bind(t, true, "plain-healthy", "secret", ldap.LDAPResultSuccess)
	})
	for _, uid := range []string{"plain-locked", "plain-expired"} {
		t.Run(uid, func(t *testing.T) {
			bind(t, false, uid, "secret", ldap.LDAPResultInvalidCredentials)
			bind(t, true, uid, "secret", ldap.LDAPResultSuccess)
			bind(t, false, uid, "secret", ldap.LDAPResultInvalidCredentials)
			t.Log("Simple Bind rejects with ppolicy error; mapped PLAIN succeeds without ppolicy control")
		})
	}
	t.Run("failure-count-and-lockout", func(t *testing.T) {
		const uid = "plain-counter"
		state(t, uid, 0, false)
		for range 3 {
			bind(t, true, uid, "wrong", ldap.LDAPResultInvalidCredentials)
			state(t, uid, 0, false)
		}
		bind(t, true, uid, "secret", ldap.LDAPResultSuccess)
		for count := 1; count <= 2; count++ {
			bind(t, false, uid, "wrong", ldap.LDAPResultInvalidCredentials)
			state(t, uid, count, count == 2)
		}
		bind(t, false, uid, "secret", ldap.LDAPResultInvalidCredentials)
		bind(t, true, uid, "secret", ldap.LDAPResultSuccess)
		state(t, uid, 2, true)
		t.Log("three bad PLAIN binds record no failures; two bad Simple binds lock the account; PLAIN still succeeds and preserves lockout state")
	})
}
