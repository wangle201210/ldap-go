package server

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type openLDAPMetaRuleSearchObservation struct {
	code    uint16
	entries []string
}

type openLDAPMetaRuleOutcome struct {
	includeSelected openLDAPMetaRuleSearchObservation
	includeRejected openLDAPMetaRuleSearchObservation
	filterSelected  openLDAPMetaRuleSearchObservation
	filterRejected  openLDAPMetaRuleSearchObservation
	excludeSelected openLDAPMetaRuleSearchObservation
	excludeRejected openLDAPMetaRuleSearchObservation
}

func TestOpenLDAPReferenceMetaSearchTargetRules(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	run := func(t *testing.T, ldapGo bool) openLDAPMetaRuleOutcome {
		t.Helper()
		providerOne, stopProviderOne := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-one",
			"provider-one",
		)
		defer stopProviderOne()
		providerTwo, stopProviderTwo := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-two",
			"provider-two",
		)
		defer stopProviderTwo()
		seedOpenLDAPMetaRuleProvider(t, providerOne)

		var proxyURI string
		var stop func()
		if ldapGo {
			proxyURI, stop = startLDAPGoMetaRuleFixture(t, providerOne, providerTwo)
		} else {
			proxyURI, stop = startOpenLDAPMetaRuleProxy(
				t,
				tools,
				providerOne,
				providerTwo,
			)
		}
		defer stop()

		return observeOpenLDAPMetaRules(t, proxyURI)
	}

	reference := run(t, false)
	assertOpenLDAPMetaRuleFixture(t, reference)
	if t.Failed() {
		return
	}

	got := run(t, true)
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf(
			"ldap-go back-meta Search target rules differ from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			got,
		)
	}
}

func seedOpenLDAPMetaRuleProvider(t *testing.T, providerURI string) {
	t.Helper()
	client, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("dial back-meta rule provider: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind back-meta rule provider: %v", err)
	}
	request := ldap.NewAddRequest("ou=outside,dc=example,dc=com", nil)
	request.Attribute("objectClass", []string{"organizationalUnit"})
	request.Attribute("ou", []string{"outside"})
	if err := client.Add(request); err != nil {
		t.Fatalf("seed back-meta rule provider %s: %v", request.DN, err)
	}
}

func startOpenLDAPMetaRuleProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerOne string,
	providerTwo string,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
subtree-include "dn.subtree:ou=people,%s"
filter "object[Cc]lass"
filter "description=provider-one"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"

uri "%s/%s"
suffixmassage "%s" "ou=people,dc=example,dc=com"
subtree-exclude "dn.subtree:uid=route-two,%s"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerOne,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerTwo,
		openLDAPMetaSpecificBase,
		openLDAPMetaSpecificBase,
		openLDAPMetaSpecificBase,
	)
	return startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", configuration, "")
}

func startLDAPGoMetaRuleFixture(
	t *testing.T,
	providerOne string,
	providerTwo string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaRuleConfiguration(t, store, providerOne, providerTwo)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaRuleConfiguration(
	t *testing.T,
	store storage.Store,
	providerOne string,
	providerTwo string,
) {
	t.Helper()
	databaseDN := "olcDatabase={1}meta,cn=config"
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}meta")},
				{Description: "olcSuffix", Values: stringValues(openLDAPMetaBaseDN)},
				{Description: "olcRootDN", Values: stringValues("cn=admin," + openLDAPMetaBaseDN)},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbNretries", Values: stringValues("1")},
			},
		},
		{
			DN: "olcMetaSub={0}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(providerOne + "/" + openLDAPMetaBaseDN)},
				{Description: "olcDbRewrite", Values: stringValues(
					"suffixmassage \"" + openLDAPMetaBaseDN + "\" \"dc=example,dc=com\"",
				)},
				{Description: "olcDbSubtreeInclude", Values: stringValues(
					"dn.subtree:ou=people," + openLDAPMetaBaseDN,
				)},
				{Description: "olcDbFilter", Values: stringValues(
					"object[Cc]lass",
					"description=provider-one",
				)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
				)},
				{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
			},
		},
		{
			DN: "olcMetaSub={1}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{1}uri")},
				{Description: "olcDbURI", Values: stringValues(providerTwo + "/" + openLDAPMetaSpecificBase)},
				{Description: "olcDbRewrite", Values: stringValues(
					"suffixmassage \"" + openLDAPMetaSpecificBase + "\" \"ou=people,dc=example,dc=com\"",
				)},
				{Description: "olcDbSubtreeExclude", Values: stringValues(
					"dn.subtree:uid=route-two," + openLDAPMetaSpecificBase,
				)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
				)},
				{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta rule configuration: %v", err)
	}
}

func observeOpenLDAPMetaRules(t *testing.T, proxyURI string) openLDAPMetaRuleOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta rule fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta rule fixture: %v", err)
	}

	return openLDAPMetaRuleOutcome{
		includeSelected: searchOpenLDAPMetaRule(
			t,
			client,
			"uid=route-one,ou=people,"+openLDAPMetaBaseDN,
			"(objectClass=*)",
		),
		includeRejected: searchOpenLDAPMetaRule(
			t,
			client,
			"ou=outside,"+openLDAPMetaBaseDN,
			"(objectClass=*)",
		),
		filterSelected: searchOpenLDAPMetaRule(
			t,
			client,
			"uid=route-one,ou=people,"+openLDAPMetaBaseDN,
			"(description=provider-one)",
		),
		filterRejected: searchOpenLDAPMetaRule(
			t,
			client,
			"uid=route-one,ou=people,"+openLDAPMetaBaseDN,
			"(sn=Route)",
		),
		excludeSelected: searchOpenLDAPMetaRule(
			t,
			client,
			"uid=alice,"+openLDAPMetaSpecificBase,
			"(objectClass=*)",
		),
		excludeRejected: searchOpenLDAPMetaRule(
			t,
			client,
			"uid=route-two,"+openLDAPMetaSpecificBase,
			"(objectClass=*)",
		),
	}
}

func searchOpenLDAPMetaRule(
	t *testing.T,
	client *ldap.Conn,
	baseDN string,
	filter string,
) openLDAPMetaRuleSearchObservation {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"description"},
		nil,
	))
	observation := openLDAPMetaRuleSearchObservation{code: monitorLDAPResultCode(err)}
	if result != nil {
		for _, entry := range result.Entries {
			observation.entries = append(
				observation.entries,
				entry.DN+"|"+entry.GetAttributeValue("description"),
			)
		}
		sort.Strings(observation.entries)
	}
	return observation
}

func assertOpenLDAPMetaRuleFixture(t *testing.T, got openLDAPMetaRuleOutcome) {
	t.Helper()
	assertSelected := func(
		name string,
		observation openLDAPMetaRuleSearchObservation,
		wantEntry string,
	) {
		t.Helper()
		if observation.code != ldap.LDAPResultSuccess ||
			len(observation.entries) != 1 || observation.entries[0] != wantEntry {
			t.Errorf("OpenLDAP %s rule fixture was not selected: %#v", name, observation)
		}
	}
	assertRejected := func(name string, observation openLDAPMetaRuleSearchObservation) {
		t.Helper()
		if observation.code != ldap.LDAPResultNoSuchObject || len(observation.entries) != 0 {
			t.Errorf("OpenLDAP %s rule fixture was not rejected: %#v", name, observation)
		}
	}

	assertSelected(
		"olcDbSubtreeInclude match",
		got.includeSelected,
		"uid=route-one,ou=people,"+openLDAPMetaBaseDN+"|provider-one",
	)
	assertRejected("olcDbSubtreeInclude miss", got.includeRejected)
	assertSelected(
		"olcDbFilter match",
		got.filterSelected,
		"uid=route-one,ou=people,"+openLDAPMetaBaseDN+"|provider-one",
	)
	assertRejected("olcDbFilter miss", got.filterRejected)
	assertSelected(
		"olcDbSubtreeExclude miss",
		got.excludeSelected,
		"uid=alice,"+openLDAPMetaSpecificBase+"|",
	)
	assertRejected("olcDbSubtreeExclude match", got.excludeRejected)
}
