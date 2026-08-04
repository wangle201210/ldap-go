package server

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaDNCacheUID              = "dncache-shared"
	openLDAPMetaDNCacheProviderOne      = "dncache-provider-one"
	openLDAPMetaDNCacheProviderTwo      = "dncache-provider-two"
	openLDAPMetaDNCacheImmediateValue   = "dncache-immediate"
	openLDAPMetaDNCacheAfterWindowValue = "dncache-after-window"
	openLDAPMetaDNCacheTTL              = "1s"
	openLDAPMetaDNCacheExpiryWindow     = 2300 * time.Millisecond
)

type openLDAPMetaDNCacheOutcome struct {
	primeCode             uint16
	primeEntries          []string
	providerOneAfterHide  openLDAPMetaSearchObservation
	providerTwoBefore     openLDAPMetaSearchObservation
	immediateModifyCode   uint16
	afterWindowModifyCode uint16
	providerOneFinal      openLDAPMetaSearchObservation
	providerTwoFinal      openLDAPMetaSearchObservation
}

func TestOpenLDAPReferenceMetaDNCacheTTL(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []struct {
		name string
		ttl  string
		want openLDAPMetaDNCacheOutcome
	}{
		{
			name: "disabled",
			ttl:  "disabled",
			want: openLDAPMetaDNCacheExpectedOutcome(
				ldap.LDAPResultSuccess,
				ldap.LDAPResultSuccess,
				openLDAPMetaDNCacheAfterWindowValue,
			),
		},
		{
			name: "finite TTL",
			ttl:  openLDAPMetaDNCacheTTL,
			want: openLDAPMetaDNCacheExpectedOutcome(
				ldap.LDAPResultNoSuchObject,
				ldap.LDAPResultSuccess,
				openLDAPMetaDNCacheAfterWindowValue,
			),
		},
		{
			name: "forever",
			ttl:  "forever",
			want: openLDAPMetaDNCacheExpectedOutcome(
				ldap.LDAPResultNoSuchObject,
				ldap.LDAPResultNoSuchObject,
				openLDAPMetaDNCacheProviderTwo,
			),
		},
	}

	reference := make(map[string]openLDAPMetaDNCacheOutcome, len(tests))
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got := runOpenLDAPMetaDNCacheScenario(t, tools, false, test.ttl)
				if !reflect.DeepEqual(got, test.want) {
					t.Fatalf(
						"OpenLDAP 2.6.13 back-meta olcDbDnCacheTtl fixture drifted:\n got: %#v\nwant: %#v",
						got,
						test.want,
					)
				}
				reference[test.name] = got
			})
		}
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go comparison", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got := runOpenLDAPMetaDNCacheScenario(t, tools, true, test.ttl)
				if !reflect.DeepEqual(got, reference[test.name]) {
					t.Fatalf(
						"ldap-go back-meta olcDbDnCacheTtl differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
						reference[test.name],
						got,
					)
				}
			})
		}
	})
}

func openLDAPMetaDNCacheExpectedOutcome(
	immediateCode uint16,
	afterWindowCode uint16,
	providerTwoDescription string,
) openLDAPMetaDNCacheOutcome {
	remoteDN := openLDAPMetaDNCacheRemoteDN()
	return openLDAPMetaDNCacheOutcome{
		primeCode: ldap.LDAPResultSuccess,
		primeEntries: []string{
			openLDAPMetaDNCacheLocalDN() + "|" + openLDAPMetaDNCacheProviderOne,
		},
		providerOneAfterHide: openLDAPMetaSearchObservation{
			code: ldap.LDAPResultNoSuchObject,
		},
		providerTwoBefore: openLDAPMetaSearchObservation{
			code:        ldap.LDAPResultSuccess,
			dn:          remoteDN,
			description: openLDAPMetaDNCacheProviderTwo,
		},
		immediateModifyCode:   immediateCode,
		afterWindowModifyCode: afterWindowCode,
		providerOneFinal: openLDAPMetaSearchObservation{
			code: ldap.LDAPResultNoSuchObject,
		},
		providerTwoFinal: openLDAPMetaSearchObservation{
			code:        ldap.LDAPResultSuccess,
			dn:          remoteDN,
			description: providerTwoDescription,
		},
	}
}

func runOpenLDAPMetaDNCacheScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
	ttl string,
) openLDAPMetaDNCacheOutcome {
	t.Helper()
	providerOne, stopProviderOne := startOpenLDAPMetaProvider(
		t,
		tools,
		"dncache-route-one",
		"dncache-route-one",
	)
	defer stopProviderOne()
	providerTwo, stopProviderTwo := startOpenLDAPMetaProvider(
		t,
		tools,
		"dncache-route-two",
		"dncache-route-two",
	)
	defer stopProviderTwo()
	seedOpenLDAPMetaDNCacheProviders(t, providerOne, providerTwo)

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaDNCacheFixture(
			t,
			providerOne,
			providerTwo,
			ttl,
		)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaDNCacheProxy(
			t,
			tools,
			providerOne,
			providerTwo,
			ttl,
		)
	}
	defer stopProxy()

	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta DN cache fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta DN cache fixture: %v", err)
	}

	outcome := observeOpenLDAPMetaDNCachePrime(t, client)
	deleteOpenLDAPMetaDNCacheProviderEntry(t, providerOne)
	outcome.providerOneAfterHide = searchOpenLDAPMetaURI(
		t,
		providerOne,
		openLDAPMetaDNCacheRemoteDN(),
	)
	outcome.providerTwoBefore = searchOpenLDAPMetaURI(
		t,
		providerTwo,
		openLDAPMetaDNCacheRemoteDN(),
	)
	outcome.immediateModifyCode = modifyOpenLDAPMetaDNCacheEntry(
		client,
		openLDAPMetaDNCacheImmediateValue,
	)

	time.Sleep(openLDAPMetaDNCacheExpiryWindow)
	outcome.afterWindowModifyCode = modifyOpenLDAPMetaDNCacheEntry(
		client,
		openLDAPMetaDNCacheAfterWindowValue,
	)
	outcome.providerOneFinal = searchOpenLDAPMetaURI(
		t,
		providerOne,
		openLDAPMetaDNCacheRemoteDN(),
	)
	outcome.providerTwoFinal = searchOpenLDAPMetaURI(
		t,
		providerTwo,
		openLDAPMetaDNCacheRemoteDN(),
	)
	return outcome
}

func seedOpenLDAPMetaDNCacheProviders(
	t *testing.T,
	providerOne string,
	providerTwo string,
) {
	t.Helper()
	for _, provider := range []struct {
		uri         string
		description string
	}{
		{uri: providerOne, description: openLDAPMetaDNCacheProviderOne},
		{uri: providerTwo, description: openLDAPMetaDNCacheProviderTwo},
	} {
		client, err := ldap.DialURL(provider.uri)
		if err != nil {
			t.Fatalf("dial back-meta DN cache provider: %v", err)
		}
		if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
			client.Close()
			t.Fatalf("bind back-meta DN cache provider: %v", err)
		}
		request := metaCandidateUserAdd(
			openLDAPMetaDNCacheRemoteDN(),
			openLDAPMetaDNCacheUID,
			provider.description,
			"dncache-secret",
		)
		if err := client.Add(request); err != nil {
			client.Close()
			t.Fatalf("seed back-meta DN cache provider: %v", err)
		}
		client.Close()
	}
}

func startOpenLDAPMetaDNCacheProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerOne string,
	providerTwo string,
	ttl string,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
dncache-ttl %s
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		ttl,
		providerOne,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerTwo,
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

func startLDAPGoMetaDNCacheFixture(
	t *testing.T,
	providerOne string,
	providerTwo string,
	ttl string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaDNCacheConfiguration(t, store, providerOne, providerTwo, ttl)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaDNCacheConfiguration(
	t *testing.T,
	store storage.Store,
	providerOne string,
	providerTwo string,
	ttl string,
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
				{Description: "olcDbDnCacheTtl", Values: stringValues(ttl)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbNretries", Values: stringValues("1")},
			},
		},
		openLDAPMetaOnErrTargetEntry(databaseDN, 0, providerOne),
		openLDAPMetaOnErrTargetEntry(databaseDN, 1, providerTwo),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta DN cache configuration: %v", err)
	}
}

func observeOpenLDAPMetaDNCachePrime(
	t *testing.T,
	client *ldap.Conn,
) openLDAPMetaDNCacheOutcome {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		openLDAPMetaDNCacheLocalDN(),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description="+openLDAPMetaDNCacheProviderOne+")",
		[]string{"description"},
		nil,
	))
	outcome := openLDAPMetaDNCacheOutcome{primeCode: monitorLDAPResultCode(err)}
	if result != nil {
		for _, entry := range result.Entries {
			outcome.primeEntries = append(
				outcome.primeEntries,
				strings.ToLower(entry.DN)+"|"+entry.GetAttributeValue("description"),
			)
		}
	}
	if outcome.primeEntries == nil {
		outcome.primeEntries = []string{}
	}
	sort.Strings(outcome.primeEntries)
	return outcome
}

func deleteOpenLDAPMetaDNCacheProviderEntry(t *testing.T, providerURI string) {
	t.Helper()
	client, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("dial provider to hide DN cache entry: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind provider to hide DN cache entry: %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(openLDAPMetaDNCacheRemoteDN(), nil)); err != nil {
		t.Fatalf("hide cached entry from first provider: %v", err)
	}
}

func modifyOpenLDAPMetaDNCacheEntry(client *ldap.Conn, description string) uint16 {
	request := ldap.NewModifyRequest(openLDAPMetaDNCacheLocalDN(), nil)
	request.Replace("description", []string{description})
	return monitorLDAPResultCode(client.Modify(request))
}

func openLDAPMetaDNCacheLocalDN() string {
	return "uid=" + openLDAPMetaDNCacheUID + ",ou=people," + openLDAPMetaBaseDN
}

func openLDAPMetaDNCacheRemoteDN() string {
	return "uid=" + openLDAPMetaDNCacheUID + ",ou=people,dc=example,dc=com"
}
