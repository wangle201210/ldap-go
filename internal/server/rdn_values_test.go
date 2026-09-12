package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestRDNAttributeModifyFormattingAndRollback(t *testing.T) {
	client, err := ldap.DialURL(syntaxPublicationGoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	const dn = "cn=rdn-modify,dc=example,dc=com"
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"person", "syntaxRefValues"})
	add.Attribute("cn", []string{"rdn-modify"})
	add.Attribute("sn", []string{"Example"})
	add.Attribute("syntaxRefRDN", []string{`CN="a,b",dc=ignored`})
	if err := client.Add(add); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"syntaxRefRDN", "description"}, nil))
		if err != nil || len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("syntaxRefRDN") != want {
			t.Fatalf("RDN readback: %+v %v, want %q", result, err, want)
		}
		if result.Entries[0].GetAttributeValue("description") != "" {
			t.Fatal("rejected modification committed unrelated attribute")
		}
	}
	check(`cn=a\2Cb`)
	modify := ldap.NewModifyRequest(dn, nil)
	modify.Replace("syntaxRefRDN", []string{`2.5.4.3=Alice,dc=ignored`})
	if err := client.Modify(modify); err != nil {
		t.Fatal(err)
	}
	check("cn=Alice")
	modify = ldap.NewModifyRequest(dn, nil)
	modify.Replace("description", []string{"must-roll-back"})
	modify.Replace("syntaxRefRDN", []string{"noSuchAttribute=Alice"})
	if err := client.Modify(modify); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidAttributeSyntax) {
		t.Fatalf("unknown naming attribute: %v", err)
	}
	check("cn=Alice")
}
