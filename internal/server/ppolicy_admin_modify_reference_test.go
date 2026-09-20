package server

import (
	"reflect"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPasswordPolicyAdministratorDeleteAdd(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, []directory.Attribute{
		{Description: "pwdSafeModify", Values: stringValues("TRUE")},
	}, nil)
	setPasswordPolicyEntryValues(t, store, "olcDatabase={1}mdb,cn=config", map[string][][]byte{
		"olcAccess": stringValues(
			"{0}to attrs=userPassword by self write by anonymous auth by * none",
			"{1}to * by self write by * read",
		),
	})
	address, stop := startServer(t, store, Config{
		RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("secret"),
	})
	defer stop()
	checkPasswordPolicyAdministratorDeleteAdd(t, "ldap://"+address)
}

func TestOpenLDAPReferencePasswordPolicyAdministratorDeleteAdd(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil, "",
		`access to attrs=userPassword by self write by anonymous auth by * none
access to * by self write by * read
overlay ppolicy
ppolicy_default "cn=default,ou=policies,dc=example,dc=com"`,
		`
dn: ou=policies,dc=example,dc=com
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,dc=example,dc=com
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: 2.5.4.35
pwdSafeModify: TRUE
`)
	defer stop()
	checkPasswordPolicyAdministratorDeleteAdd(t, uri)
}

func checkPasswordPolicyAdministratorDeleteAdd(t *testing.T, uri string) {
	t.Helper()
	const oldHash = "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ="
	admin, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	admin.SetTimeout(3 * time.Second)
	if err := admin.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		self     bool
		oldValue string
		wantCode uint16
	}{
		{"admin-hash", false, oldHash, ldap.LDAPResultSuccess},
		{"admin-cleartext", false, "secret", ldap.LDAPResultNoSuchAttribute},
		{"self-cleartext", true, "secret", ldap.LDAPResultSuccess},
		{"self-hash", true, oldHash, ldap.LDAPResultUnwillingToPerform},
	} {
		t.Run(test.name, func(t *testing.T) {
			dn := "uid=" + test.name + ",ou=people,dc=example,dc=com"
			add := ldap.NewAddRequest(dn, nil)
			add.Attribute("objectClass", []string{"inetOrgPerson"})
			add.Attribute("uid", []string{test.name})
			add.Attribute("cn", []string{test.name})
			add.Attribute("sn", []string{"Test"})
			add.Attribute("userPassword", []string{oldHash})
			if err := admin.Add(add); err != nil {
				t.Fatal(err)
			}
			connection := admin
			if test.self {
				connection, err = ldap.DialURL(uri)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				connection.SetTimeout(3 * time.Second)
				if err := connection.Bind(dn, "secret"); err != nil {
					t.Fatal(err)
				}
			}
			modify := ldap.NewModifyRequest(dn, []ldap.Control{ldap.NewControlBeheraPasswordPolicy()})
			modify.Delete("userPassword", []string{test.oldValue})
			modify.Add("userPassword", []string{"replacement-password"})
			err := connection.Modify(modify)
			if (test.wantCode == ldap.LDAPResultSuccess && err != nil) ||
				(test.wantCode != ldap.LDAPResultSuccess && !ldap.IsErrorWithCode(err, test.wantCode)) {
				t.Errorf("Modify = %v; want result %d", err, test.wantCode)
			}
			result, err := admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject,
				ldap.NeverDerefAliases, 1, 2, false, "(objectClass=*)",
				[]string{"userPassword", "pwdChangedTime"}, nil))
			if err != nil || len(result.Entries) != 1 {
				t.Fatalf("read final password: %v, %v", result, err)
			}
			wantPassword := oldHash
			if test.wantCode == ldap.LDAPResultSuccess {
				wantPassword = "replacement-password"
			}
			if got := result.Entries[0].GetAttributeValues("userPassword"); !reflect.DeepEqual(got, []string{wantPassword}) {
				t.Errorf("stored password = %q; want %q", got, wantPassword)
			}
			changed := result.Entries[0].GetAttributeValue("pwdChangedTime") != ""
			if changed != (test.wantCode == ldap.LDAPResultSuccess) {
				t.Errorf("pwdChangedTime present = %t; want %t", changed, test.wantCode == ldap.LDAPResultSuccess)
			}
		})
	}
}
