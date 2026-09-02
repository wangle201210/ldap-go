package server

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type openLDAPMetaACLDependencyObservation struct {
	code        uint16
	entries     int
	attributes  []string
	description string
}

func TestOpenLDAPReferenceMetaACLUnrequestedTargetFilterAttribute(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)
	providerURI, stopProvider := startOpenLDAPMetaProvider(
		t,
		tools,
		"route-one",
		"classified",
	)
	defer stopProvider()

	openLDAPURI, stopOpenLDAP := startOpenLDAPMetaACLDependencyProxy(
		t,
		tools,
		providerURI,
	)
	defer stopOpenLDAP()
	reference := observeOpenLDAPMetaACLDependency(t, openLDAPURI)
	want := openLDAPMetaACLDependencyObservation{
		code:    ldap.LDAPResultSuccess,
		entries: 1,
	}
	if !reflect.DeepEqual(reference, want) {
		t.Fatalf("OpenLDAP 2.6.13 extra_attrs ACL fixture = %#v, want %#v", reference, want)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaReferenceConfiguration(t, store, "", providerURI, providerURI)
	setMetaACLRulesAtDN(t, store, "olcDatabase={1}meta,cn=config", []string{
		`to filter="(sn=Route)" attrs=description by * none`,
		`to * by * read`,
	})
	address, stopLDAPGo := startServer(t, store, Config{})
	defer stopLDAPGo()
	got := observeOpenLDAPMetaACLDependency(t, "ldap://"+address)
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf(
			"ldap-go unrequested target-filter ACL differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			got,
		)
	}
}

func startOpenLDAPMetaACLDependencyProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to filter="(sn=Route)" attrs=description by * none
access to * by * read
extra_attrs sn
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
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

func observeOpenLDAPMetaACLDependency(
	t *testing.T,
	proxyURI string,
) openLDAPMetaACLDependencyObservation {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta ACL dependency fixture: %v", err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		openLDAPMetaACLVisibleDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	observation := openLDAPMetaACLDependencyObservation{
		code: monitorLDAPResultCode(err),
	}
	if result == nil {
		return observation
	}
	observation.entries = len(result.Entries)
	if len(result.Entries) != 1 {
		return observation
	}
	observation.description = result.Entries[0].GetAttributeValue("description")
	for _, attribute := range result.Entries[0].Attributes {
		observation.attributes = append(observation.attributes, attribute.Name)
	}
	sort.Strings(observation.attributes)
	return observation
}
