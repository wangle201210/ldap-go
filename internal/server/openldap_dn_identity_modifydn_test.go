package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestOpenLDAPReferenceDNIdentityModifyDNPrettyForm(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		`attributetype ( 1.3.6.1.4.1.99999.915.1 NAME 'exactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.915.2 NAME 'foldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectclass ( 1.3.6.1.4.1.99999.915.3 NAME 'dnIdentityModifyDNEntry' SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName ) )`,
		"",
		`
dn: exactName=Alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityModifyDNEntry
cn: Exact Upper
exactName: Alice

dn: exactName=alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityModifyDNEntry
cn: Exact Lower
exactName: alice

dn: foldName=Alice Smith,dc=example,dc=com
objectClass: top
objectClass: dnIdentityModifyDNEntry
cn: Folded Name
foldName: Alice Smith
`,
	)
	defer stop()

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(root): %v", err)
	}

	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		"exactName=Alice,dc=example,dc=com",
		"ExAcTnAmE=Upper Renamed",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(caseExact): %v", err)
	}
	assertOpenLDAPDNIdentityModifyDNPrettyForm(
		t,
		client,
		"Exact Upper",
		"exactName=Upper Renamed,dc=example,dc=com",
	)

	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		"foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
		"FoLdNaMe=Renamed User",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(caseIgnore equivalent source): %v", err)
	}
	assertOpenLDAPDNIdentityModifyDNPrettyForm(
		t,
		client,
		"Folded Name",
		"foldName=Renamed User,dc=example,dc=com",
	)
}

func assertOpenLDAPDNIdentityModifyDNPrettyForm(
	t *testing.T,
	client *ldap.Conn,
	commonName,
	wantDN string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(cn="+ldap.EscapeFilter(commonName)+")",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(cn=%q): %v", commonName, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(cn=%q) returned %d entries, want 1", commonName, len(result.Entries))
	}
	if got := result.Entries[0].DN; got != wantDN {
		t.Fatalf("OpenLDAP entry DN = %q, want %q", got, wantDN)
	}
}
