package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceFilterAbsentAttributeAssertions(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	native, stopNative := startOpenLDAPReferenceServer(t, tools, nil)
	t.Cleanup(stopNative)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	local, stopLocal := startServer(t, store, Config{
		RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("secret"),
	})
	t.Cleanup(stopLocal)
	clients := make([]*ldap.Conn, 0, 2)
	for _, uri := range []string{native, "ldap://" + local} {
		client, err := ldap.DialURL(uri)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
	}
	for _, assertion := range []string{
		"(unknownFilterAttribute=value)", "(unknownFilterAttribute=*)",
		"(cn>=A)", "(jpegPhoto=value)", "(userPassword=*secret*)",
		"(createTimestamp=not-a-time)", "(cn:1.2.3:=value)",
		"(cn;unknownOption=value)", "(cn=Absent)",
		"(cn=*)", "(cn~=Absent)", "(cn;lang-en=Absent)", "(cn;lang-=Absent)",
		"(cn:caseIgnoreMatch:=Absent)", "(createTimestamp=20260920000000Z)",
		"(attributeTypes=cn)", "(objectClasses=person)", "(matchingRules=caseIgnoreMatch)",
		"(dITStructureRules=1)", "(certificateRevocationList=*)", "(certificateRevocationList;binary=*)",
	} {
		for _, filter := range []string{assertion, "(!" + assertion + ")", "(|" + assertion + "(ou=people))", "(&" + assertion + "(ou=people))"} {
			t.Run(filter, func(t *testing.T) {
				counts := make([]int, 2)
				for i, client := range clients {
					result, err := client.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"1.1"}, nil))
					if err != nil {
						t.Fatalf("endpoint %d: %v", i, err)
					}
					counts[i] = len(result.Entries)
				}
				if counts[0] != counts[1] {
					t.Errorf("OpenLDAP=%d ldap-go=%d", counts[0], counts[1])
				}
			})
		}
	}
}
