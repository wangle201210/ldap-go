package server

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaACLVisibleDN = "uid=route-one,ou=people," + openLDAPMetaBaseDN
	openLDAPMetaACLHiddenDN  = "uid=route-two," + openLDAPMetaSpecificBase
	openLDAPMetaACLPassword  = "route-one-secret"
)

type openLDAPMetaACLSearchObservation struct {
	code        uint16
	entries     int
	dn          string
	attributes  []string
	uid         string
	cn          string
	sn          string
	description string
}

type openLDAPMetaACLProviderObservation struct {
	description string
	sn          string
}

type openLDAPMetaACLOutcome struct {
	visibleSearch openLDAPMetaACLSearchObservation
	hiddenSearch  openLDAPMetaACLSearchObservation
	subtreeCode   uint16
	subtreeRoutes []string

	ordinaryAttributeCompare openLDAPMetaCompareObservation
	filteredAttributeCompare openLDAPMetaCompareObservation
	hiddenEntryCompare       openLDAPMetaCompareObservation

	bindCode                    uint16
	filteredAttributeModifyCode uint16
	ordinaryAttributeModifyCode uint16
	providerAfter               openLDAPMetaACLProviderObservation
}

func TestOpenLDAPReferenceMetaParentACL(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	var reference openLDAPMetaACLOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
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
		seedOpenLDAPMetaACLPassword(t, providerOne)

		proxyURI, stopProxy := startOpenLDAPMetaACLProxy(
			t,
			tools,
			providerOne,
			providerTwo,
		)
		defer stopProxy()

		reference = observeOpenLDAPMetaParentACL(t, proxyURI, providerOne)
		assertOpenLDAPMetaACLFixture(t, reference)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
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
		seedOpenLDAPMetaACLPassword(t, providerOne)

		proxyURI, stopProxy := startLDAPGoMetaACLFixture(
			t,
			providerOne,
			providerTwo,
		)
		defer stopProxy()

		got := observeOpenLDAPMetaParentACL(t, proxyURI, providerOne)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go meta-parent olcAccess differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func openLDAPMetaACLRules() []string {
	return []string{
		`to dn.exact="` + openLDAPMetaACLHiddenDN + `" by * none`,
		`to attrs=description by * none`,
		`to * by * write`,
	}
}

func startOpenLDAPMetaACLProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerOne string,
	providerTwo string,
) (string, func()) {
	t.Helper()
	rules := openLDAPMetaACLRules()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access %s
access %s
access %s
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"

uri "%s/%s"
suffixmassage "%s" "ou=people,dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		rules[0],
		rules[1],
		rules[2],
		providerOne,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerTwo,
		openLDAPMetaSpecificBase,
		openLDAPMetaSpecificBase,
	)
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		configuration,
		"",
	)
}

func startLDAPGoMetaACLFixture(
	t *testing.T,
	providerOne string,
	providerTwo string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaReferenceConfiguration(t, store, "", providerOne, providerTwo)

	databaseDN, err := directory.ParseDN("olcDatabase={1}meta,cn=config")
	if err != nil {
		t.Fatalf("parse ldap-go meta ACL database DN: %v", err)
	}
	rules := openLDAPMetaACLRules()
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		entry, getErr := writer.Get(databaseDN)
		if getErr != nil {
			return getErr
		}
		entry.ReplaceValues("olcAccess", stringValues(
			"{0}"+rules[0],
			"{1}"+rules[1],
			"{2}"+rules[2],
		))
		return writer.Put(entry, true)
	})
	if err != nil {
		t.Fatalf("seed ldap-go meta parent olcAccess: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func observeOpenLDAPMetaParentACL(
	t *testing.T,
	proxyURI string,
	providerOneURI string,
) openLDAPMetaACLOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta ACL fixture %s: %v", proxyURI, err)
	}
	defer client.Close()

	outcome := openLDAPMetaACLOutcome{
		visibleSearch: observeOpenLDAPMetaACLSearch(t, client, openLDAPMetaACLVisibleDN),
		hiddenSearch:  observeOpenLDAPMetaACLSearch(t, client, openLDAPMetaACLHiddenDN),
	}
	outcome.subtreeCode, outcome.subtreeRoutes = observeOpenLDAPMetaACLSubtree(t, client)
	outcome.ordinaryAttributeCompare = compareOpenLDAPMetaEntry(
		client,
		openLDAPMetaACLVisibleDN,
		"cn",
		"route-one",
	)
	outcome.filteredAttributeCompare = compareOpenLDAPMetaEntry(
		client,
		openLDAPMetaACLVisibleDN,
		"description",
		"provider-one",
	)
	outcome.hiddenEntryCompare = compareOpenLDAPMetaEntry(
		client,
		openLDAPMetaACLHiddenDN,
		"cn",
		"route-two",
	)
	outcome.bindCode = monitorLDAPResultCode(client.Bind(
		openLDAPMetaACLVisibleDN,
		openLDAPMetaACLPassword,
	))

	filteredModify := ldap.NewModifyRequest(openLDAPMetaACLVisibleDN, nil)
	filteredModify.Replace("description", []string{"acl-filtered-write"})
	outcome.filteredAttributeModifyCode = monitorLDAPResultCode(
		client.Modify(filteredModify),
	)

	ordinaryModify := ldap.NewModifyRequest(openLDAPMetaACLVisibleDN, nil)
	ordinaryModify.Replace("sn", []string{"acl-ordinary-write"})
	outcome.ordinaryAttributeModifyCode = monitorLDAPResultCode(
		client.Modify(ordinaryModify),
	)
	outcome.providerAfter = observeOpenLDAPMetaACLProvider(t, providerOneURI)
	return outcome
}

func seedOpenLDAPMetaACLPassword(t *testing.T, providerURI string) {
	t.Helper()
	client, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("dial back-meta ACL provider %s: %v", providerURI, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind back-meta ACL provider %s: %v", providerURI, err)
	}
	request := ldap.NewModifyRequest(
		"uid=route-one,ou=people,dc=example,dc=com",
		nil,
	)
	request.Replace("userPassword", []string{openLDAPMetaACLPassword})
	if err := client.Modify(request); err != nil {
		t.Fatalf("seed back-meta ACL user password: %v", err)
	}
}

func observeOpenLDAPMetaACLSearch(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) openLDAPMetaACLSearchObservation {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", "cn", "sn", "description"},
		nil,
	))
	observation := openLDAPMetaACLSearchObservation{code: monitorLDAPResultCode(err)}
	if result == nil {
		return observation
	}
	observation.entries = len(result.Entries)
	if len(result.Entries) == 0 {
		return observation
	}
	entry := result.Entries[0]
	observation.dn = strings.ToLower(entry.DN)
	observation.uid = entry.GetAttributeValue("uid")
	observation.cn = entry.GetAttributeValue("cn")
	observation.sn = entry.GetAttributeValue("sn")
	observation.description = entry.GetAttributeValue("description")
	for _, attribute := range entry.Attributes {
		observation.attributes = append(
			observation.attributes,
			strings.ToLower(attribute.Name),
		)
	}
	sort.Strings(observation.attributes)
	return observation
}

func observeOpenLDAPMetaACLSubtree(
	t *testing.T,
	client *ldap.Conn,
) (uint16, []string) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		openLDAPMetaBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", "description"},
		nil,
	))
	code := monitorLDAPResultCode(err)
	if result == nil {
		return code, nil
	}
	var routes []string
	for _, entry := range result.Entries {
		dn := strings.ToLower(entry.DN)
		if dn != openLDAPMetaACLVisibleDN && dn != openLDAPMetaACLHiddenDN {
			continue
		}
		routes = append(routes, fmt.Sprintf(
			"%s|uid=%s|description=%s",
			dn,
			entry.GetAttributeValue("uid"),
			entry.GetAttributeValue("description"),
		))
	}
	sort.Strings(routes)
	return code, routes
}

func observeOpenLDAPMetaACLProvider(
	t *testing.T,
	providerURI string,
) openLDAPMetaACLProviderObservation {
	t.Helper()
	client, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("dial back-meta ACL provider %s: %v", providerURI, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind back-meta ACL provider %s: %v", providerURI, err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"uid=route-one,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"description", "sn"},
		nil,
	))
	if err != nil {
		t.Fatalf("read back-meta ACL provider entry: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("back-meta ACL provider returned %d entries, want 1", len(result.Entries))
	}
	return openLDAPMetaACLProviderObservation{
		description: result.Entries[0].GetAttributeValue("description"),
		sn:          result.Entries[0].GetAttributeValue("sn"),
	}
}

func assertOpenLDAPMetaACLFixture(t *testing.T, got openLDAPMetaACLOutcome) {
	t.Helper()
	want := openLDAPMetaACLOutcome{
		visibleSearch: openLDAPMetaACLSearchObservation{
			code:       ldap.LDAPResultSuccess,
			entries:    1,
			dn:         openLDAPMetaACLVisibleDN,
			attributes: []string{"cn", "sn", "uid"},
			uid:        "route-one",
			cn:         "route-one",
			sn:         "Route",
		},
		hiddenSearch: openLDAPMetaACLSearchObservation{
			code: ldap.LDAPResultSuccess,
		},
		subtreeCode: ldap.LDAPResultSuccess,
		subtreeRoutes: []string{
			openLDAPMetaACLVisibleDN + "|uid=route-one|description=",
		},
		ordinaryAttributeCompare: openLDAPMetaCompareObservation{
			matched: true,
			code:    ldap.LDAPResultSuccess,
		},
		filteredAttributeCompare: openLDAPMetaCompareObservation{
			matched: true,
			code:    ldap.LDAPResultSuccess,
		},
		hiddenEntryCompare: openLDAPMetaCompareObservation{
			matched: true,
			code:    ldap.LDAPResultSuccess,
		},
		bindCode:                    ldap.LDAPResultSuccess,
		filteredAttributeModifyCode: ldap.LDAPResultSuccess,
		ordinaryAttributeModifyCode: ldap.LDAPResultSuccess,
		providerAfter: openLDAPMetaACLProviderObservation{
			description: "acl-filtered-write",
			sn:          "acl-ordinary-write",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP 2.6.13 meta-parent olcAccess fixture drifted:\n got: %#v\nwant: %#v",
			got,
			want,
		)
	}
}
