package server

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultSearchBaseFrontendDN = "olcDatabase={-1}frontend,cn=config"
	defaultSearchBaseRootDN     = "dc=example,dc=com"
	defaultSearchBasePeopleDN   = "ou=people," + defaultSearchBaseRootDN
)

type defaultSearchBaseReferencePair struct {
	referenceData   *ldap.Conn
	referenceConfig *ldap.Conn
	localData       *ldap.Conn
	localConfig     *ldap.Conn
	localStore      storage.Store
}

type defaultSearchBaseSearchResult struct {
	code      uint16
	matchedDN string
	dns       []string
}

func TestOpenLDAPReferenceDefaultSearchBasePlacementAndSearch(t *testing.T) {
	pair := startDefaultSearchBaseReferencePair(t, true)

	t.Run("configuration is on frontend and DN is normalized", func(t *testing.T) {
		const wantKey = "dc=example,dc=com"
		wantPretty := []string{"dc=Example,dc=COM"}
		referenceFrontend := readDefaultSearchBaseConfigValues(
			t,
			pair.referenceConfig,
			defaultSearchBaseFrontendDN,
		)
		assertDefaultSearchBaseConfigValues(t, "OpenLDAP frontend", referenceFrontend, wantKey)
		if !slices.Equal(referenceFrontend, wantPretty) {
			t.Fatalf(
				"OpenLDAP fixture error: normalized frontend value = %q, want %q",
				referenceFrontend,
				wantPretty,
			)
		}
		referenceGlobal := readDefaultSearchBaseConfigValues(t, pair.referenceConfig, "cn=config")
		if len(referenceGlobal) != 0 {
			t.Fatalf("OpenLDAP fixture error: cn=config olcDefaultSearchBase = %q, want absent", referenceGlobal)
		}

		localFrontend := readDefaultSearchBaseConfigValues(
			t,
			pair.localConfig,
			defaultSearchBaseFrontendDN,
		)
		assertDefaultSearchBaseConfigValues(t, "ldap-go frontend", localFrontend, wantKey)
		if !slices.Equal(localFrontend, referenceFrontend) {
			t.Errorf(
				"ldap-go implementation gap: normalized frontend value = %q, OpenLDAP = %q",
				localFrontend,
				referenceFrontend,
			)
		}
		storedFrontend := readStoredEntry(t, pair.localStore, defaultSearchBaseFrontendDN)
		storedValues := defaultSearchBaseByteValuesToStrings(
			storedFrontend.Values("olcDefaultSearchBase"),
		)
		if !slices.Equal(storedValues, referenceFrontend) {
			t.Errorf(
				"ldap-go implementation gap: stored normalized frontend value = %q, OpenLDAP = %q",
				storedValues,
				referenceFrontend,
			)
		}
		localGlobal := readDefaultSearchBaseConfigValues(t, pair.localConfig, "cn=config")
		if len(localGlobal) != 0 {
			t.Errorf("ldap-go implementation gap: cn=config olcDefaultSearchBase = %q, want absent", localGlobal)
		}
	})

	for _, test := range []struct {
		name  string
		scope int
		want  []string
	}{
		{
			name:  "empty base base scope remains Root DSE",
			scope: ldap.ScopeBaseObject,
			want:  []string{""},
		},
		{
			name:  "empty base one-level scope is rewritten",
			scope: ldap.ScopeSingleLevel,
			want: []string{
				"ou=archive," + defaultSearchBaseRootDN,
				defaultSearchBasePeopleDN,
			},
		},
		{
			name:  "empty base subtree scope is rewritten",
			scope: ldap.ScopeWholeSubtree,
			want: []string{
				defaultSearchBaseRootDN,
				"ou=archive," + defaultSearchBaseRootDN,
				defaultSearchBasePeopleDN,
				"uid=alice," + defaultSearchBasePeopleDN,
				"uid=bob," + defaultSearchBasePeopleDN,
				"uid=carol," + defaultSearchBasePeopleDN,
			},
		},
		{
			name:  "empty base children scope is rewritten",
			scope: ldap.ScopeChildren,
			want: []string{
				"ou=archive," + defaultSearchBaseRootDN,
				defaultSearchBasePeopleDN,
				"uid=alice," + defaultSearchBasePeopleDN,
				"uid=bob," + defaultSearchBasePeopleDN,
				"uid=carol," + defaultSearchBasePeopleDN,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference := observeDefaultSearchBaseSearch(t, pair.referenceData, test.scope)
			assertDefaultSearchBaseSearch(
				t,
				"OpenLDAP fixture",
				reference,
				ldap.LDAPResultSuccess,
				"",
				test.want,
			)
			local := observeDefaultSearchBaseSearch(t, pair.localData, test.scope)
			assertDefaultSearchBaseEquivalent(t, reference, local)
		})
	}
}

func TestOpenLDAPReferenceDefaultSearchBaseUnsetChildren(t *testing.T) {
	pair := startDefaultSearchBaseReferencePair(t, false)
	reference := observeDefaultSearchBaseSearch(t, pair.referenceData, ldap.ScopeChildren)
	assertDefaultSearchBaseSearch(
		t,
		"OpenLDAP fixture",
		reference,
		ldap.LDAPResultNoSuchObject,
		"",
		nil,
	)
	local := observeDefaultSearchBaseSearch(t, pair.localData, ldap.ScopeChildren)
	assertDefaultSearchBaseEquivalent(t, reference, local)
}

func TestOpenLDAPReferenceDefaultSearchBaseOnlineLifecycle(t *testing.T) {
	t.Run("missing target is reported before the online-only constraint", func(t *testing.T) {
		pair := startDefaultSearchBaseReferencePair(t, false)
		runDefaultSearchBaseModifyDifferential(
			t,
			pair,
			ldap.LDAPResultNoSuchObject,
			func() *ldap.ModifyRequest {
				request := ldap.NewModifyRequest("cn=missing,cn=config", nil)
				request.Add("olcDefaultSearchBase", []string{defaultSearchBaseRootDN})
				return request
			},
		)
		assertDefaultSearchBasePairState(t, pair, "")
	})

	t.Run("add is rejected and absent state rolls back", func(t *testing.T) {
		pair := startDefaultSearchBaseReferencePair(t, false)
		runDefaultSearchBaseModifyDifferential(
			t,
			pair,
			ldap.LDAPResultConstraintViolation,
			func() *ldap.ModifyRequest {
				request := ldap.NewModifyRequest(defaultSearchBaseFrontendDN, nil)
				request.Add("olcDefaultSearchBase", []string{"DC=Example, DC=COM"})
				return request
			},
		)
		assertDefaultSearchBasePairState(t, pair, "")
	})

	t.Run("replace is rejected and configured state rolls back", func(t *testing.T) {
		pair := startDefaultSearchBaseReferencePair(t, true)
		runDefaultSearchBaseModifyDifferential(
			t,
			pair,
			ldap.LDAPResultConstraintViolation,
			func() *ldap.ModifyRequest {
				request := ldap.NewModifyRequest(defaultSearchBaseFrontendDN, nil)
				request.Replace("olcDefaultSearchBase", []string{"OU=People, DC=Example, DC=COM"})
				return request
			},
		)
		assertDefaultSearchBasePairState(t, pair, "dc=example,dc=com")
		reference := observeDefaultSearchBaseSearch(t, pair.referenceData, ldap.ScopeChildren)
		assertDefaultSearchBaseSearch(
			t,
			"OpenLDAP after rejected replace",
			reference,
			ldap.LDAPResultSuccess,
			"",
			[]string{
				"ou=archive," + defaultSearchBaseRootDN,
				defaultSearchBasePeopleDN,
				"uid=alice," + defaultSearchBasePeopleDN,
				"uid=bob," + defaultSearchBasePeopleDN,
				"uid=carol," + defaultSearchBasePeopleDN,
			},
		)
		assertDefaultSearchBaseEquivalent(
			t,
			reference,
			observeDefaultSearchBaseSearch(t, pair.localData, ldap.ScopeChildren),
		)
	})

	t.Run("delete succeeds", func(t *testing.T) {
		pair := startDefaultSearchBaseReferencePair(t, true)
		runDefaultSearchBaseModifyDifferential(
			t,
			pair,
			ldap.LDAPResultSuccess,
			func() *ldap.ModifyRequest {
				request := ldap.NewModifyRequest(defaultSearchBaseFrontendDN, nil)
				request.Delete("olcDefaultSearchBase", nil)
				return request
			},
		)
		assertDefaultSearchBasePairState(t, pair, "")
		reference := observeDefaultSearchBaseSearch(t, pair.referenceData, ldap.ScopeChildren)
		assertDefaultSearchBaseSearch(
			t,
			"OpenLDAP after delete",
			reference,
			ldap.LDAPResultNoSuchObject,
			"",
			nil,
		)
		assertDefaultSearchBaseEquivalent(
			t,
			reference,
			observeDefaultSearchBaseSearch(t, pair.localData, ldap.ScopeChildren),
		)
	})

	t.Run("invalid multivalue add rolls back absent state", func(t *testing.T) {
		pair := startDefaultSearchBaseReferencePair(t, false)
		runDefaultSearchBaseModifyDifferential(
			t,
			pair,
			ldap.LDAPResultConstraintViolation,
			func() *ldap.ModifyRequest {
				request := ldap.NewModifyRequest(defaultSearchBaseFrontendDN, nil)
				request.Add("olcDefaultSearchBase", []string{
					defaultSearchBaseRootDN,
					defaultSearchBasePeopleDN,
				})
				return request
			},
		)
		assertDefaultSearchBasePairState(t, pair, "")
	})

	t.Run("invalid multivalue replace rolls back configured state", func(t *testing.T) {
		pair := startDefaultSearchBaseReferencePair(t, true)
		runDefaultSearchBaseModifyDifferential(
			t,
			pair,
			ldap.LDAPResultConstraintViolation,
			func() *ldap.ModifyRequest {
				request := ldap.NewModifyRequest(defaultSearchBaseFrontendDN, nil)
				request.Replace("olcDefaultSearchBase", []string{
					defaultSearchBaseRootDN,
					defaultSearchBasePeopleDN,
				})
				return request
			},
		)
		assertDefaultSearchBasePairState(t, pair, "dc=example,dc=com")
	})
}

func runDefaultSearchBaseModifyDifferential(
	t *testing.T,
	pair defaultSearchBaseReferencePair,
	wantCode uint16,
	makeRequest func() *ldap.ModifyRequest,
) {
	t.Helper()
	referenceErr := pair.referenceConfig.Modify(makeRequest())
	referenceCode := defaultSearchBaseResultCode(referenceErr)
	if referenceCode != wantCode {
		t.Fatalf(
			"OpenLDAP fixture error: Modify result = %d (%v), want %d",
			referenceCode,
			referenceErr,
			wantCode,
		)
	}
	localErr := pair.localConfig.Modify(makeRequest())
	localCode := defaultSearchBaseResultCode(localErr)
	if localCode != referenceCode {
		t.Errorf(
			"ldap-go implementation gap: Modify result = %d (%v), OpenLDAP = %d (%v)",
			localCode,
			localErr,
			referenceCode,
			referenceErr,
		)
	}
}

func assertDefaultSearchBasePairState(
	t *testing.T,
	pair defaultSearchBaseReferencePair,
	wantKey string,
) {
	t.Helper()
	reference := readDefaultSearchBaseConfigValues(
		t,
		pair.referenceConfig,
		defaultSearchBaseFrontendDN,
	)
	assertDefaultSearchBaseConfigValues(t, "OpenLDAP fixture frontend", reference, wantKey)
	local := readDefaultSearchBaseConfigValues(
		t,
		pair.localConfig,
		defaultSearchBaseFrontendDN,
	)
	assertDefaultSearchBaseConfigValues(t, "ldap-go frontend", local, wantKey)
	stored := readStoredEntry(t, pair.localStore, defaultSearchBaseFrontendDN)
	assertDefaultSearchBaseConfigValues(
		t,
		"ldap-go stored frontend",
		defaultSearchBaseByteValuesToStrings(stored.Values("olcDefaultSearchBase")),
		wantKey,
	)
}

func startDefaultSearchBaseReferencePair(
	t *testing.T,
	configured bool,
) defaultSearchBaseReferencePair {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	requireOpenLDAPDefaultSearchBaseVersion(t, tools)
	globalConfig := `database config
rootdn "cn=config"
rootpw config-secret
access to * by * manage`
	if configured {
		globalConfig = `defaultSearchBase "DC=Example, DC=COM"
` + globalConfig
	}
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		globalConfig,
		"access to * by * read",
		`
dn: ou=archive,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: archive
`,
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedDefaultSearchBaseReferenceLocalEntries(t, store, configured)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin," + defaultSearchBaseRootDN,
		RootPassword: []byte("admin-secret"),
	})
	t.Cleanup(stopLocal)

	return defaultSearchBaseReferencePair{
		referenceData: bindDefaultSearchBaseClient(
			t,
			referenceURI,
			"cn=admin,"+defaultSearchBaseRootDN,
			"secret",
		),
		referenceConfig: bindDefaultSearchBaseClient(
			t,
			referenceURI,
			"cn=config",
			"config-secret",
		),
		localData: bindDefaultSearchBaseClient(
			t,
			"ldap://"+localAddress,
			"cn=admin,"+defaultSearchBaseRootDN,
			"admin-secret",
		),
		localConfig: bindDefaultSearchBaseClient(
			t,
			"ldap://"+localAddress,
			"cn=config",
			"config-secret",
		),
		localStore: store,
	}
}

func requireOpenLDAPDefaultSearchBaseVersion(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	output, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil {
		t.Fatalf("read OpenLDAP reference version: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), "OpenLDAP: slapd 2.6.13 ") {
		t.Fatalf(
			"default-search-base differential test requires OpenLDAP slapd 2.6.13, got: %s",
			strings.TrimSpace(string(output)),
		)
	}
}

func seedDefaultSearchBaseReferenceLocalEntries(
	t *testing.T,
	store storage.Store,
	configured bool,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{
				DN: "uid=bob," + defaultSearchBasePeopleDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("bob")},
					{Description: "cn", Values: stringValues("Bob")},
					{Description: "sn", Values: stringValues("Bob")},
				},
			},
			{
				DN: "uid=carol," + defaultSearchBasePeopleDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("carol")},
					{Description: "cn", Values: stringValues("Carol")},
					{Description: "sn", Values: stringValues("Carol")},
				},
			},
			{
				DN: defaultSearchBaseFrontendDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
					{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				},
			},
		}
		if configured {
			entries[2].Attributes = append(entries[2].Attributes, directory.Attribute{
				Description: "olcDefaultSearchBase",
				Values:      stringValues("DC=Example, DC=COM"),
			})
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ldap-go default-search-base reference fixture: %v", err)
	}
}

func bindDefaultSearchBaseClient(
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
	t.Cleanup(func() { client.Close() })
	if err := client.Bind(dn, password); err != nil {
		t.Fatalf("Bind(%s): %v", dn, err)
	}
	return client
}

func readDefaultSearchBaseConfigValues(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcDefaultSearchBase"},
		nil,
	))
	if err != nil {
		t.Fatalf("read %s olcDefaultSearchBase: %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("read %s: got %d entries, want 1", dn, len(result.Entries))
	}
	return result.Entries[0].GetAttributeValues("olcDefaultSearchBase")
}

func assertDefaultSearchBaseConfigValues(
	t *testing.T,
	label string,
	values []string,
	wantKey string,
) {
	t.Helper()
	if wantKey == "" {
		if len(values) != 0 {
			t.Errorf("%s olcDefaultSearchBase = %q, want absent", label, values)
		}
		return
	}
	if len(values) != 1 {
		t.Errorf("%s olcDefaultSearchBase = %q, want one value", label, values)
		return
	}
	dn, err := directory.ParseDN(values[0])
	if err != nil {
		t.Errorf("%s olcDefaultSearchBase %q is not a DN: %v", label, values[0], err)
		return
	}
	if dn.Key() != wantKey {
		t.Errorf("%s normalized olcDefaultSearchBase = %q, want %q", label, dn.Key(), wantKey)
	}
}

func observeDefaultSearchBaseSearch(
	t *testing.T,
	client *ldap.Conn,
	scope int,
) defaultSearchBaseSearchResult {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	observation := defaultSearchBaseSearchResult{code: ldap.LDAPResultSuccess}
	if result != nil {
		observation.dns = make([]string, len(result.Entries))
		for index, entry := range result.Entries {
			observation.dns[index] = entry.DN
		}
		slices.Sort(observation.dns)
	}
	if err == nil {
		return observation
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("Search(scope=%d): %v", scope, err)
	}
	observation.code = ldapErr.ResultCode
	observation.matchedDN = ldapErr.MatchedDN
	return observation
}

func assertDefaultSearchBaseSearch(
	t *testing.T,
	label string,
	got defaultSearchBaseSearchResult,
	wantCode uint16,
	wantMatchedDN string,
	wantDNs []string,
) {
	t.Helper()
	wantDNs = slices.Clone(wantDNs)
	slices.Sort(wantDNs)
	if got.code != wantCode ||
		!strings.EqualFold(got.matchedDN, wantMatchedDN) ||
		!slices.Equal(got.dns, wantDNs) {
		t.Fatalf(
			"%s Search = {code:%d matchedDN:%q dns:%q}, want {code:%d matchedDN:%q dns:%q}",
			label,
			got.code,
			got.matchedDN,
			got.dns,
			wantCode,
			wantMatchedDN,
			wantDNs,
		)
	}
}

func assertDefaultSearchBaseEquivalent(
	t *testing.T,
	reference,
	local defaultSearchBaseSearchResult,
) {
	t.Helper()
	if reference.code != local.code ||
		!strings.EqualFold(reference.matchedDN, local.matchedDN) ||
		!slices.Equal(reference.dns, local.dns) {
		t.Errorf(
			"ldap-go implementation gap: Search = {code:%d matchedDN:%q dns:%q}, OpenLDAP = {code:%d matchedDN:%q dns:%q}",
			local.code,
			local.matchedDN,
			local.dns,
			reference.code,
			reference.matchedDN,
			reference.dns,
		)
	}
}

func defaultSearchBaseResultCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode
	}
	return ldap.LDAPResultOther
}

func defaultSearchBaseByteValuesToStrings(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}
