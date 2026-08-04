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

const (
	openLDAPMetaOnErrUID         = "onerr-live"
	openLDAPMetaOnErrDescription = "onerr-provider"
)

type openLDAPMetaOnErrOutcome struct {
	code    uint16
	entries []string
}

func TestOpenLDAPReferenceMetaOnErr(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []struct {
		name      string
		mode      string
		deadFirst bool
		want      openLDAPMetaOnErrOutcome
	}{
		{
			name:      "continue/dead-first",
			mode:      "continue",
			deadFirst: true,
			want:      openLDAPMetaOnErrSuccessOutcome(),
		},
		{
			name: "continue/dead-last",
			mode: "continue",
			want: openLDAPMetaOnErrSuccessOutcome(),
		},
		{
			name:      "report/dead-first",
			mode:      "report",
			deadFirst: true,
			want: openLDAPMetaOnErrOutcome{
				code:    ldap.LDAPResultUnavailable,
				entries: openLDAPMetaOnErrEntries(),
			},
		},
		{
			name: "report/dead-last",
			mode: "report",
			want: openLDAPMetaOnErrOutcome{
				code:    ldap.LDAPResultUnavailable,
				entries: openLDAPMetaOnErrEntries(),
			},
		},
		{
			name:      "stop/dead-first",
			mode:      "stop",
			deadFirst: true,
			want: openLDAPMetaOnErrOutcome{
				code:    ldap.LDAPResultUnavailable,
				entries: []string{},
			},
		},
		{
			name: "stop/dead-last",
			mode: "stop",
			want: openLDAPMetaOnErrOutcome{
				code:    ldap.LDAPResultUnavailable,
				entries: []string{},
			},
		},
	}

	reference := make(map[string]openLDAPMetaOnErrOutcome, len(tests))
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got := runOpenLDAPMetaOnErrScenario(
					t,
					tools,
					false,
					test.mode,
					test.deadFirst,
				)
				if !reflect.DeepEqual(got, test.want) {
					t.Fatalf(
						"OpenLDAP 2.6.13 back-meta onerr fixture drifted:\n got: %#v\nwant: %#v",
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
				got := runOpenLDAPMetaOnErrScenario(
					t,
					tools,
					true,
					test.mode,
					test.deadFirst,
				)
				if !reflect.DeepEqual(got, reference[test.name]) {
					t.Fatalf(
						"ldap-go back-meta olcDbOnErr differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
						reference[test.name],
						got,
					)
				}
			})
		}
	})
}

func openLDAPMetaOnErrSuccessOutcome() openLDAPMetaOnErrOutcome {
	return openLDAPMetaOnErrOutcome{
		code:    ldap.LDAPResultSuccess,
		entries: openLDAPMetaOnErrEntries(),
	}
}

func openLDAPMetaOnErrEntries() []string {
	return []string{
		"uid=" + openLDAPMetaOnErrUID + ",ou=people," + openLDAPMetaBaseDN +
			"|" + openLDAPMetaOnErrDescription,
	}
}

func runOpenLDAPMetaOnErrScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
	mode string,
	deadFirst bool,
) openLDAPMetaOnErrOutcome {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaOnErrUID,
		openLDAPMetaOnErrDescription,
	)
	defer stopProvider()
	deadURI := reserveClosedOpenLDAPMetaURI(t)

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaOnErrFixture(
			t,
			deadURI,
			providerURI,
			mode,
			deadFirst,
		)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaOnErrProxy(
			t,
			tools,
			deadURI,
			providerURI,
			mode,
			deadFirst,
		)
	}
	defer stopProxy()
	return observeOpenLDAPMetaOnErr(t, proxyURI)
}

func startOpenLDAPMetaOnErrProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	deadURI string,
	providerURI string,
	mode string,
	deadFirst bool,
) (string, func()) {
	t.Helper()
	deadTarget := openLDAPMetaOnErrTargetConfig(deadURI)
	liveTarget := openLDAPMetaOnErrTargetConfig(providerURI)
	first, second := liveTarget, deadTarget
	if deadFirst {
		first, second = deadTarget, liveTarget
	}
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no
onerr %s

%s

%s`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		mode,
		first,
		second,
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

func openLDAPMetaOnErrTargetConfig(uri string) string {
	return fmt.Sprintf(`uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		uri,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
	)
}

func startLDAPGoMetaOnErrFixture(
	t *testing.T,
	deadURI string,
	providerURI string,
	mode string,
	deadFirst bool,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaOnErrConfiguration(
		t,
		store,
		deadURI,
		providerURI,
		mode,
		deadFirst,
	)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaOnErrConfiguration(
	t *testing.T,
	store storage.Store,
	deadURI string,
	providerURI string,
	mode string,
	deadFirst bool,
) {
	t.Helper()
	databaseDN := "olcDatabase={1}meta,cn=config"
	firstURI, secondURI := providerURI, deadURI
	if deadFirst {
		firstURI, secondURI = deadURI, providerURI
	}
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
				{Description: "olcDbOnErr", Values: stringValues(mode)},
			},
		},
		openLDAPMetaOnErrTargetEntry(databaseDN, 0, firstURI),
		openLDAPMetaOnErrTargetEntry(databaseDN, 1, secondURI),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta olcDbOnErr configuration: %v", err)
	}
}

func openLDAPMetaOnErrTargetEntry(
	databaseDN string,
	order int,
	uri string,
) directory.Entry {
	orderedName := fmt.Sprintf("{%d}uri", order)
	return directory.Entry{
		DN: "olcMetaSub=" + orderedName + "," + databaseDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
			{Description: "olcMetaSub", Values: stringValues(orderedName)},
			{Description: "olcDbURI", Values: stringValues(uri + "/" + openLDAPMetaBaseDN)},
			{Description: "olcDbRewrite", Values: stringValues(
				"suffixmassage \"" + openLDAPMetaBaseDN + "\" \"dc=example,dc=com\"",
			)},
			{Description: "olcDbIDAssertBind", Values: stringValues(
				`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
			)},
			{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
		},
	}
}

func observeOpenLDAPMetaOnErr(
	t *testing.T,
	proxyURI string,
) openLDAPMetaOnErrOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta olcDbOnErr fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta olcDbOnErr fixture: %v", err)
	}
	result, searchErr := client.Search(ldap.NewSearchRequest(
		openLDAPMetaBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid="+openLDAPMetaOnErrUID+")",
		[]string{"description"},
		nil,
	))
	outcome := openLDAPMetaOnErrOutcome{code: monitorLDAPResultCode(searchErr)}
	if result != nil {
		for _, entry := range result.Entries {
			outcome.entries = append(
				outcome.entries,
				entry.DN+"|"+entry.GetAttributeValue("description"),
			)
		}
	}
	if outcome.entries == nil {
		outcome.entries = []string{}
	}
	sort.Strings(outcome.entries)
	return outcome
}
