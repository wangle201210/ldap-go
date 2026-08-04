package server

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	aclReferenceAliceDN = "uid=acl-alice,ou=people,dc=example,dc=com"
	aclReferenceBobDN   = "uid=acl-bob,ou=people,dc=example,dc=com"
	aclReferenceCarolDN = "uid=acl-carol,ou=people,dc=example,dc=com"
)

type aclReferenceEntry struct {
	dn     string
	values []string
}

type aclReferenceOutcome struct {
	entries      []aclReferenceEntry
	compareCodes []uint16
}

type aclExpansionReferenceOutcome struct {
	values map[string][]string
}

type aclConnectionLevelOutcome struct {
	anonymousCode    uint16
	anonymousEntries int
	levelCode        uint16
	levelEntries     int
	dnLevelValues    []string
}

type aclACIReferenceOutcome struct {
	aliceValues []string
	bobCode     uint16
	bobEntries  int
}

func TestOpenLDAPReferenceACLTargetSelectors(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	rules := aclReferenceRules()
	openLDAPConfig := make([]string, len(rules))
	for index, rule := range rules {
		openLDAPConfig[index] = "access " + rule
	}
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		strings.Join(openLDAPConfig, "\n"),
		"",
	)
	defer stopOpenLDAP()
	openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAPRoot.Close()
	addACLReferenceFixtures(t, openLDAPRoot)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGoURI := "ldap://" + address
	ldapGoRoot := bindOverlayReferenceClient(t, ldapGoURI, "admin-secret")
	defer ldapGoRoot.Close()
	addACLReferenceFixtures(t, ldapGoRoot)
	configClient, err := ldap.DialURL(ldapGoURI)
	if err != nil {
		t.Fatalf("DialURL(ldap-go config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(ldap-go config): %v", err)
	}
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	orderedRules := make([]string, len(rules))
	for index, rule := range rules {
		orderedRules[index] = fmt.Sprintf("{%d}%s", index, rule)
	}
	modify.Replace("olcAccess", orderedRules)
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("Modify(ldap-go ACL target selectors): %v", err)
	}

	openLDAP := dialAnonymousACLReferenceClient(t, openLDAPURI)
	defer openLDAP.Close()
	ldapGo := dialAnonymousACLReferenceClient(t, ldapGoURI)
	defer ldapGo.Close()
	openLDAPOutcome := runACLTargetReferenceScenario(t, openLDAP)
	ldapGoOutcome := runACLTargetReferenceScenario(t, ldapGo)
	if !reflect.DeepEqual(ldapGoOutcome, openLDAPOutcome) {
		t.Fatalf(
			"ACL target selector mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
			openLDAPOutcome,
			ldapGoOutcome,
		)
	}
}

func TestOpenLDAPReferenceACLDNExpansionAndGroups(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	rules := aclExpansionReferenceRules()
	openLDAPConfig := make([]string, len(rules))
	for index, rule := range rules {
		openLDAPConfig[index] = "access " + rule
	}
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"include "+tools.schemaDir+"/dyngroup.schema",
		strings.Join(openLDAPConfig, "\n"),
		"",
	)
	defer stopOpenLDAP()
	openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAPRoot.Close()
	addACLReferenceFixtures(t, openLDAPRoot)
	addACLExpansionGroupFixtures(t, openLDAPRoot)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGoURI := "ldap://" + address
	ldapGoRoot := bindOverlayReferenceClient(t, ldapGoURI, "admin-secret")
	defer ldapGoRoot.Close()
	addACLReferenceFixtures(t, ldapGoRoot)
	addACLExpansionGroupFixtures(t, ldapGoRoot)
	configClient, err := ldap.DialURL(ldapGoURI)
	if err != nil {
		t.Fatalf("DialURL(ldap-go config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(ldap-go config): %v", err)
	}
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	orderedRules := make([]string, len(rules))
	for index, rule := range rules {
		orderedRules[index] = fmt.Sprintf("{%d}%s", index, rule)
	}
	modify.Replace("olcAccess", orderedRules)
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("Modify(ldap-go expansion ACL): %v", err)
	}

	openLDAPAlice := dialBoundACLReferenceClient(
		t,
		openLDAPURI,
		aclReferenceAliceDN,
		"alice-secret",
	)
	defer openLDAPAlice.Close()
	ldapGoAlice := dialBoundACLReferenceClient(
		t,
		ldapGoURI,
		aclReferenceAliceDN,
		"alice-secret",
	)
	defer ldapGoAlice.Close()
	openLDAPBob := dialBoundACLReferenceClient(
		t,
		openLDAPURI,
		aclReferenceBobDN,
		"bob-secret",
	)
	defer openLDAPBob.Close()
	ldapGoBob := dialBoundACLReferenceClient(
		t,
		ldapGoURI,
		aclReferenceBobDN,
		"bob-secret",
	)
	defer ldapGoBob.Close()

	openLDAPOutcome := runACLExpansionReferenceScenario(t, openLDAPAlice, openLDAPBob)
	ldapGoOutcome := runACLExpansionReferenceScenario(t, ldapGoAlice, ldapGoBob)
	if !reflect.DeepEqual(ldapGoOutcome, openLDAPOutcome) {
		t.Fatalf(
			"ACL expansion/group mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
			openLDAPOutcome,
			ldapGoOutcome,
		)
	}
}

func TestOpenLDAPReferenceACLConnectionAndLevels(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	rules := []string{
		`to attrs=userPassword by anonymous auth by * none`,
		`to dn.base="ou=people,dc=example,dc=com" by self.level{1} read by * none`,
		`to attrs=entry,objectClass by users read by * none`,
		`to dn.base="` + aclReferenceAliceDN + `" attrs=cn by dn.level{1}="ou=people,dc=example,dc=com" read by * none`,
		`to dn.base="dc=example,dc=com" by peername.ip=127.0.0.0%255.0.0.0 read by * none`,
		`to * by * none`,
	}
	openLDAPConfig := make([]string, len(rules))
	for index, rule := range rules {
		openLDAPConfig[index] = "access " + rule
	}
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		strings.Join(openLDAPConfig, "\n"),
		"",
	)
	defer stopOpenLDAP()
	openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAPRoot.Close()
	addACLReferenceFixtures(t, openLDAPRoot)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGoURI := "ldap://" + address
	ldapGoRoot := bindOverlayReferenceClient(t, ldapGoURI, "admin-secret")
	defer ldapGoRoot.Close()
	addACLReferenceFixtures(t, ldapGoRoot)
	configClient, err := ldap.DialURL(ldapGoURI)
	if err != nil {
		t.Fatalf("DialURL(ldap-go config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(ldap-go config): %v", err)
	}
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	orderedRules := make([]string, len(rules))
	for index, rule := range rules {
		orderedRules[index] = fmt.Sprintf("{%d}%s", index, rule)
	}
	modify.Replace("olcAccess", orderedRules)
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("Modify(ldap-go connection/level ACL): %v", err)
	}

	openLDAPOutcome := runACLConnectionLevelScenario(t, openLDAPURI)
	ldapGoOutcome := runACLConnectionLevelScenario(t, ldapGoURI)
	if !reflect.DeepEqual(ldapGoOutcome, openLDAPOutcome) {
		t.Fatalf(
			"ACL connection/level mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
			openLDAPOutcome,
			ldapGoOutcome,
		)
	}
}

func TestOpenLDAPReferenceACI(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	requireOpenLDAPACIReference(t, tools)
	rules := []string{
		`to attrs=userPassword by anonymous auth by * none`,
		`to * by dynacl/aci write`,
	}
	openLDAPConfig := make([]string, len(rules))
	for index, rule := range rules {
		openLDAPConfig[index] = "access " + rule
	}
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		strings.Join(openLDAPConfig, "\n"),
		"",
	)
	defer stopOpenLDAP()
	openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAPRoot.Close()
	addACLReferenceFixtures(t, openLDAPRoot)
	addACIGroupFixture(t, openLDAPRoot)
	addACIReferenceValues(t, openLDAPRoot)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGoURI := "ldap://" + address
	ldapGoRoot := bindOverlayReferenceClient(t, ldapGoURI, "admin-secret")
	defer ldapGoRoot.Close()
	addACLReferenceFixtures(t, ldapGoRoot)
	addACIGroupFixture(t, ldapGoRoot)
	addACIReferenceValues(t, ldapGoRoot)
	configClient, err := ldap.DialURL(ldapGoURI)
	if err != nil {
		t.Fatalf("DialURL(ldap-go config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(ldap-go config): %v", err)
	}
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	orderedRules := make([]string, len(rules))
	for index, rule := range rules {
		orderedRules[index] = fmt.Sprintf("{%d}%s", index, rule)
	}
	modify.Replace("olcAccess", orderedRules)
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("Modify(ldap-go ACI ACL): %v", err)
	}

	openLDAPOutcome := runACIReferenceScenario(t, openLDAPURI)
	ldapGoOutcome := runACIReferenceScenario(t, ldapGoURI)
	if !reflect.DeepEqual(ldapGoOutcome, openLDAPOutcome) {
		t.Fatalf(
			"ACI mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
			openLDAPOutcome,
			ldapGoOutcome,
		)
	}
}

func aclReferenceRules() []string {
	return []string{
		`to attrs=entry by * read`,
		`to attrs=objectClass,uid by * search`,
		`to filter="(uid=acl-alice)" attrs=cn val.regex="^Allowed CN$" by * read`,
		`to filter="(uid=acl-alice)" attrs=sn val=" alice " by * read`,
		`to filter="(uid=acl-alice)" attrs=mail val/caseExactIA5Match="Allowed@Example.COM" by * read`,
		`to filter="(uid=acl-alice)" attrs=seeAlso val.subtree="ou=people,dc=example,dc=com" by * read`,
		`to filter="(uid=acl-bob)" attrs=@person by * read`,
		`to filter="(uid=acl-carol)" attrs=!person by * read`,
		`to * by * none`,
	}
}

func aclExpansionReferenceRules() []string {
	return []string{
		`to attrs=userPassword by anonymous auth by * none`,
		`to attrs=entry by users read`,
		`to attrs=objectClass,uid by users search`,
		`to dn.regex="^uid=(acl-alice),ou=people,dc=example,dc=com$" attrs=cn by dn.exact,expand="uid=$1,ou=people,dc=example,dc=com" read`,
		`to dn.base="uid=acl-bob,ou=people,dc=example,dc=com" attrs=description val.regex="^owner:([^ ]+)$" by dn.exact,expand="uid=${v1},ou=people,dc=example,dc=com" read`,
		`to dn.regex="^uid=(acl-carol),ou=people,dc=example,dc=com$" attrs=mail by group.expand="cn=$1-readers,ou=groups,dc=example,dc=com" read`,
		`to dn.base="uid=acl-alice,ou=people,dc=example,dc=com" attrs=sn by group/groupOfUniqueNames/uniqueMember.exact="cn=unique,ou=groups,dc=example,dc=com" read`,
		`to dn.base="uid=acl-alice,ou=people,dc=example,dc=com" attrs=mail by group/groupOfURLs/memberURL.exact="cn=dynamic,ou=groups,dc=example,dc=com" read`,
		`to dn.base="uid=acl-alice,ou=people,dc=example,dc=com" attrs=telephoneNumber by set="[cn=unique,ou=groups,dc=example,dc=com]/uniqueMember & user" read`,
		`to * by * none`,
	}
}

func addACLReferenceFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	entries := []struct {
		dn         string
		attributes map[string][]string
	}{
		{
			dn: aclReferenceAliceDN,
			attributes: map[string][]string{
				"objectClass": {"inetOrgPerson"},
				"uid":         {"acl-alice"},
				"cn":          {"Allowed CN", "Hidden CN"},
				"sn":          {"ALICE", "Hidden Surname"},
				"mail":        {"Allowed@Example.COM", "hidden@example.com"},
				"seeAlso": {
					"uid=owner,ou=people,dc=example,dc=com",
					"uid=owner,ou=archive,dc=example,dc=com",
				},
				"description":     {"hidden description"},
				"telephoneNumber": {"+1 555 0100"},
				"userPassword":    {"alice-secret"},
			},
		},
		{
			dn: aclReferenceBobDN,
			attributes: map[string][]string{
				"objectClass":  {"inetOrgPerson"},
				"uid":          {"acl-bob"},
				"cn":           {"Bob Visible"},
				"sn":           {"Bob"},
				"mail":         {"bob-hidden@example.com"},
				"description":  {"Bob Description", "owner:acl-alice"},
				"userPassword": {"bob-secret"},
			},
		},
		{
			dn: aclReferenceCarolDN,
			attributes: map[string][]string{
				"objectClass":  {"inetOrgPerson"},
				"uid":          {"acl-carol"},
				"cn":           {"Carol Hidden"},
				"sn":           {"Carol"},
				"mail":         {"carol-visible@example.com"},
				"description":  {"Carol Hidden Description"},
				"userPassword": {"carol-secret"},
			},
		},
	}
	for _, entry := range entries {
		request := ldap.NewAddRequest(entry.dn, nil)
		for attribute, values := range entry.attributes {
			request.Attribute(attribute, values)
		}
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(%s): %v", entry.dn, err)
		}
	}
}

func addACLExpansionGroupFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	entries := []struct {
		dn         string
		attributes map[string][]string
	}{
		{
			dn: "ou=groups,dc=example,dc=com",
			attributes: map[string][]string{
				"objectClass": {"organizationalUnit"},
				"ou":          {"groups"},
			},
		},
		{
			dn: "cn=acl-carol-readers,ou=groups,dc=example,dc=com",
			attributes: map[string][]string{
				"objectClass": {"groupOfNames"},
				"cn":          {"acl-carol-readers"},
				"member":      {aclReferenceAliceDN},
			},
		},
		{
			dn: "cn=unique,ou=groups,dc=example,dc=com",
			attributes: map[string][]string{
				"objectClass":  {"groupOfUniqueNames"},
				"cn":           {"unique"},
				"uniqueMember": {aclReferenceAliceDN},
			},
		},
		{
			dn: "cn=dynamic,ou=groups,dc=example,dc=com",
			attributes: map[string][]string{
				"objectClass": {"groupOfURLs"},
				"cn":          {"dynamic"},
				"memberURL": {
					"ldap:///ou=people,dc=example,dc=com??sub?(uid=acl-alice)",
				},
			},
		},
	}
	for _, entry := range entries {
		request := ldap.NewAddRequest(entry.dn, nil)
		for attribute, values := range entry.attributes {
			request.Attribute(attribute, values)
		}
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(%s): %v", entry.dn, err)
		}
	}
}

func addACIReferenceValues(t *testing.T, client *ldap.Conn) {
	t.Helper()
	root := ldap.NewModifyRequest("dc=example,dc=com", nil)
	root.Add("OpenLDAPaci", []string{
		"0#subtree#grant;d,s,r;[all]#group#" +
			"cn=acl-carol-readers,ou=groups,dc=example,dc=com",
	})
	if err := client.Modify(root); err != nil {
		t.Fatalf("Modify(root OpenLDAPaci): %v", err)
	}
	alice := ldap.NewModifyRequest(aclReferenceAliceDN, nil)
	alice.Add("OpenLDAPaci", []string{
		"0#entry#deny;r;mail#users#",
	})
	if err := client.Modify(alice); err != nil {
		t.Fatalf("Modify(alice OpenLDAPaci): %v", err)
	}
}

func addACIGroupFixture(t *testing.T, client *ldap.Conn) {
	t.Helper()
	organizationalUnit := ldap.NewAddRequest("ou=groups,dc=example,dc=com", nil)
	organizationalUnit.Attribute("objectClass", []string{"organizationalUnit"})
	organizationalUnit.Attribute("ou", []string{"groups"})
	if err := client.Add(organizationalUnit); err != nil {
		t.Fatalf("Add(ACI groups OU): %v", err)
	}
	group := ldap.NewAddRequest(
		"cn=acl-carol-readers,ou=groups,dc=example,dc=com",
		nil,
	)
	group.Attribute("objectClass", []string{"groupOfNames"})
	group.Attribute("cn", []string{"acl-carol-readers"})
	group.Attribute("member", []string{aclReferenceAliceDN})
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(ACI group): %v", err)
	}
}

func dialAnonymousACLReferenceClient(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	return client
}

func dialBoundACLReferenceClient(
	t *testing.T,
	uri,
	dn,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s, %s): %v", uri, dn, err)
	}
	return client
}

func runACLTargetReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) aclReferenceOutcome {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(uid=acl-alice)(uid=acl-bob)(uid=acl-carol))",
		[]string{"cn", "sn", "mail", "seeAlso", "description"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(ACL target selectors): %v", err)
	}
	outcome := aclReferenceOutcome{}
	for _, entry := range result.Entries {
		flattened := make([]string, 0)
		for _, attribute := range entry.Attributes {
			for _, value := range attribute.Values {
				flattened = append(flattened, attribute.Name+"="+value)
			}
		}
		sort.Strings(flattened)
		outcome.entries = append(outcome.entries, aclReferenceEntry{
			dn:     strings.ToLower(entry.DN),
			values: flattened,
		})
	}
	sort.Slice(outcome.entries, func(i, j int) bool {
		return outcome.entries[i].dn < outcome.entries[j].dn
	})
	outcome.compareCodes = []uint16{
		overlayCompareResultCode(t, client, aclReferenceAliceDN, "cn", "Allowed CN"),
		overlayCompareResultCode(t, client, aclReferenceAliceDN, "cn", "Hidden CN"),
		overlayCompareResultCode(t, client, aclReferenceCarolDN, "mail", "carol-visible@example.com"),
	}
	return outcome
}

func runACLExpansionReferenceScenario(
	t *testing.T,
	alice,
	bob *ldap.Conn,
) aclExpansionReferenceOutcome {
	t.Helper()
	outcome := aclExpansionReferenceOutcome{values: make(map[string][]string)}
	queries := []struct {
		name      string
		client    *ldap.Conn
		dn        string
		attribute string
	}{
		{name: "dn-expand", client: alice, dn: aclReferenceAliceDN, attribute: "cn"},
		{name: "value-expand", client: alice, dn: aclReferenceBobDN, attribute: "description"},
		{name: "group-expand", client: alice, dn: aclReferenceCarolDN, attribute: "mail"},
		{name: "unique-member", client: alice, dn: aclReferenceAliceDN, attribute: "sn"},
		{name: "dynamic-group", client: alice, dn: aclReferenceAliceDN, attribute: "mail"},
		{name: "set-member", client: alice, dn: aclReferenceAliceDN, attribute: "telephoneNumber"},
		{name: "other-user", client: bob, dn: aclReferenceAliceDN, attribute: "cn"},
	}
	for _, query := range queries {
		result, err := query.client.Search(ldap.NewSearchRequest(
			query.dn,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{query.attribute},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(%s): %v", query.name, err)
		}
		var values []string
		if len(result.Entries) == 1 {
			values = result.Entries[0].GetAttributeValues(query.attribute)
		}
		sort.Strings(values)
		outcome.values[query.name] = values
	}
	return outcome
}

func runACLConnectionLevelScenario(
	t *testing.T,
	uri string,
) aclConnectionLevelOutcome {
	t.Helper()
	outcome := aclConnectionLevelOutcome{}
	anonymous := dialAnonymousACLReferenceClient(t, uri)
	defer anonymous.Close()
	result, err := anonymous.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	outcome.anonymousCode = monitorLDAPResultCode(err)
	if result != nil {
		outcome.anonymousEntries = len(result.Entries)
	}

	alice := dialBoundACLReferenceClient(
		t,
		uri,
		aclReferenceAliceDN,
		"alice-secret",
	)
	defer alice.Close()
	result, err = alice.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"ou"},
		nil,
	))
	outcome.levelCode = monitorLDAPResultCode(err)
	if result != nil {
		outcome.levelEntries = len(result.Entries)
	}
	result, err = alice.Search(ldap.NewSearchRequest(
		aclReferenceAliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	if err == nil && len(result.Entries) == 1 {
		outcome.dnLevelValues = result.Entries[0].GetAttributeValues("cn")
		sort.Strings(outcome.dnLevelValues)
	}
	return outcome
}

func runACIReferenceScenario(t *testing.T, uri string) aclACIReferenceOutcome {
	t.Helper()
	alice := dialBoundACLReferenceClient(
		t,
		uri,
		aclReferenceAliceDN,
		"alice-secret",
	)
	defer alice.Close()
	result, err := alice.Search(ldap.NewSearchRequest(
		aclReferenceAliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", "cn", "mail"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(ACI as Alice): %v", err)
	}
	outcome := aclACIReferenceOutcome{}
	if len(result.Entries) == 1 {
		for _, attribute := range result.Entries[0].Attributes {
			for _, value := range attribute.Values {
				outcome.aliceValues = append(
					outcome.aliceValues,
					strings.ToLower(attribute.Name)+"="+value,
				)
			}
		}
		sort.Strings(outcome.aliceValues)
	}

	bob := dialBoundACLReferenceClient(
		t,
		uri,
		aclReferenceBobDN,
		"bob-secret",
	)
	defer bob.Close()
	result, err = bob.Search(ldap.NewSearchRequest(
		aclReferenceAliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	outcome.bobCode = monitorLDAPResultCode(err)
	if result != nil {
		outcome.bobEntries = len(result.Entries)
	}
	return outcome
}
