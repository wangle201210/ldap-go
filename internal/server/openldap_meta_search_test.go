package server

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

type openLDAPMetaUnionOutcome struct {
	code        uint16
	entries     []string
	limitedCode uint16
	limitedN    int
}

func TestOpenLDAPReferenceMetaSearchUnion(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	run := func(t *testing.T, ldapGo bool) openLDAPMetaUnionOutcome {
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
		var proxyURI string
		var stop func()
		if ldapGo {
			proxyURI, stop = startLDAPGoMetaReferenceFixture(t, "", providerOne, providerTwo)
		} else {
			proxyURI, stop = startOpenLDAPMetaUnionProxy(
				t,
				tools,
				providerOne,
				providerTwo,
			)
		}
		defer stop()
		return observeOpenLDAPMetaUnion(t, proxyURI)
	}

	reference := run(t, false)
	if !metaUnionHasEntry(reference.entries, "uid=route-one,ou=people,"+openLDAPMetaBaseDN) ||
		!metaUnionHasEntry(reference.entries, "uid=route-two,"+openLDAPMetaSpecificBase) {
		t.Fatalf("OpenLDAP back-meta union fixture did not query both targets: %#v", reference)
	}
	got := run(t, true)
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf(
			"ldap-go back-meta Search union differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			got,
		)
	}
}

func observeOpenLDAPMetaUnion(t *testing.T, proxyURI string) openLDAPMetaUnionOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta union fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta union fixture: %v", err)
	}
	search, err := client.Search(ldap.NewSearchRequest(
		openLDAPMetaBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	outcome := openLDAPMetaUnionOutcome{code: monitorLDAPResultCode(err)}
	if search != nil {
		for _, entry := range search.Entries {
			outcome.entries = append(
				outcome.entries,
				entry.DN+"|"+entry.GetAttributeValue("description"),
			)
		}
		sort.Strings(outcome.entries)
	}
	limited, limitedErr := client.Search(ldap.NewSearchRequest(
		openLDAPMetaBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	outcome.limitedCode = monitorLDAPResultCode(limitedErr)
	if limited != nil {
		outcome.limitedN = len(limited.Entries)
	}
	return outcome
}

func startOpenLDAPMetaUnionProxy(
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
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"

uri "%s/%s"
suffixmassage "%s" "ou=people,dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerOne,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerTwo,
		openLDAPMetaSpecificBase,
		openLDAPMetaSpecificBase,
	)
	return startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", configuration, "")
}

func metaUnionHasEntry(entries []string, dn string) bool {
	for _, entry := range entries {
		if len(entry) >= len(dn) && entry[:len(dn)] == dn {
			return true
		}
	}
	return false
}
