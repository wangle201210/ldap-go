package server

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceRelayBackend(t *testing.T) {
	tools := requireOpenLDAPRelayReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`overlay sssvlv
database relay
suffix "dc=virtual,dc=test"
relay "dc=example,dc=com"
overlay rwm
rwm-suffixmassage "dc=example,dc=com"
rwm-map objectClass groupOfNames groupOfUniqueNames
rwm-map attribute member uniqueMember`,
		`
dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

dn: cn=staff,ou=groups,dc=example,dc=com
objectClass: groupOfUniqueNames
cn: staff
uniqueMember: uid=alice,ou=people,dc=example,dc=com
`,
	)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedRelayConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{})
	defer stopLDAPGo()

	want := runRelayReferenceScenario(t, openLDAPURI)
	got := runRelayReferenceScenario(t, "ldap://"+ldapGoAddress)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("relay scenario = %#v, want OpenLDAP %#v", got, want)
	}
}

func requireOpenLDAPRelayReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if err != nil {
		t.Skipf("inspect OpenLDAP backends and overlays: %v", err)
	}
	features := strings.ToLower(string(output))
	for _, feature := range []string{"relay", "rwm", "sssvlv"} {
		if !strings.Contains(features, "    "+feature+"\n") {
			t.Skipf(
				"the selected OpenLDAP slapd was not built with %s support",
				feature,
			)
		}
	}
	return tools
}

type relayReferenceResult struct {
	searchDN    string
	compare     bool
	directDN    string
	directMail  string
	virtualBind bool
	groupClass  string
	groupMember string
	sortedDNs   string
}

func runRelayReferenceScenario(t *testing.T, uri string) relayReferenceResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=virtual,dc=test", "secret"); err != nil {
		t.Fatalf("Bind(relay root, %s): %v", uri, err)
	}

	search, err := client.Search(ldap.NewSearchRequest(
		"dc=virtual,dc=test",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(search.Entries) != 1 {
		t.Fatalf("Search(relay, %s) entries=%d err=%v", uri, len(search.Entries), err)
	}
	sorted, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=virtual,dc=test",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=*)",
		[]string{"uid"},
		[]ldap.Control{newSortControl(ldap.SortKey{
			AttributeType: "uid",
			MatchingRule:  "caseIgnoreOrderingMatch",
		})},
	))
	if err != nil {
		t.Fatalf("Search(sorted relay, %s): %v", uri, err)
	}
	sortedDNs := make([]string, len(sorted.Entries))
	for index := range sorted.Entries {
		sortedDNs[index] = sorted.Entries[index].DN
	}
	groupSearch, err := client.Search(ldap.NewSearchRequest(
		"cn=staff,ou=groups,dc=virtual,dc=test",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=groupOfNames)",
		[]string{"objectClass", "member"},
		nil,
	))
	if err != nil || len(groupSearch.Entries) != 1 {
		t.Fatalf(
			"Search(mapped group, %s) entries=%d err=%v",
			uri,
			len(groupSearch.Entries),
			err,
		)
	}

	add := ldap.NewAddRequest("uid=relay-diff,ou=people,dc=virtual,dc=test", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"relay-diff"})
	add.Attribute("cn", []string{"Relay Differential"})
	add.Attribute("sn", []string{"Differential"})
	add.Attribute("userPassword", []string{"relay-secret"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(relay, %s): %v", uri, err)
	}
	modify := ldap.NewModifyRequest(
		"uid=relay-diff,ou=people,dc=virtual,dc=test",
		nil,
	)
	modify.Replace("mail", []string{"relay-diff@example.com"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(relay, %s): %v", uri, err)
	}
	matched, err := client.Compare(
		"uid=relay-diff,ou=people,dc=virtual,dc=test",
		"mail",
		"relay-diff@example.com",
	)
	if err != nil {
		t.Fatalf("Compare(relay, %s): %v", uri, err)
	}
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		"uid=relay-diff,ou=people,dc=virtual,dc=test",
		"uid=relay-renamed",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(relay, %s): %v", uri, err)
	}

	user, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(user, %s): %v", uri, err)
	}
	virtualBind := user.Bind(
		"uid=relay-renamed,ou=people,dc=virtual,dc=test",
		"relay-secret",
	) == nil
	_ = user.Close()

	direct, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(direct, %s): %v", uri, err)
	}
	defer direct.Close()
	if err := direct.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(direct root, %s): %v", uri, err)
	}
	directSearch, err := direct.Search(ldap.NewSearchRequest(
		"uid=relay-renamed,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"mail"},
		nil,
	))
	if err != nil || len(directSearch.Entries) != 1 {
		t.Fatalf(
			"Search(direct, %s) entries=%d err=%v",
			uri,
			len(directSearch.Entries),
			err,
		)
	}

	if err := client.Del(ldap.NewDelRequest(
		"uid=relay-renamed,ou=people,dc=virtual,dc=test",
		nil,
	)); err != nil {
		t.Fatalf("Delete(relay, %s): %v", uri, err)
	}
	return relayReferenceResult{
		searchDN:    search.Entries[0].DN,
		compare:     matched,
		directDN:    directSearch.Entries[0].DN,
		directMail:  directSearch.Entries[0].GetAttributeValue("mail"),
		virtualBind: virtualBind,
		groupClass:  groupSearch.Entries[0].GetAttributeValue("objectClass"),
		groupMember: groupSearch.Entries[0].GetAttributeValue("member"),
		sortedDNs:   strings.Join(sortedDNs, "|"),
	}
}
