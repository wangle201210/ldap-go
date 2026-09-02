package server

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type ldapBackendACLSearchCounter struct {
	searches atomic.Int64
}

func (counter *ldapBackendACLSearchCounter) Record(event audit.Event) error {
	if event.Operation == "search" {
		counter.searches.Add(1)
	}
	return nil
}

func TestLDAPBackendLocalACLOnlineLifecycle(t *testing.T) {
	providerURI, stopProvider := startLDAPBackendACLProvider(t)
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxyURI(t, proxyStore, providerURI)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	data := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
	defer data.Close()
	configuration := dialLDAPBackendClient(t, proxyAddress)
	defer configuration.Close()
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind back-ldap configuration root: %v", err)
	}

	assertLDAPBackendDescriptionValues(
		t,
		data,
		[]string{"classified", "public"},
	)

	valueRules := []string{
		`{0}to attrs=description val.regex="^classified$" by * none`,
		`{1}to * by * write`,
	}
	add := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
	add.Add("olcAccess", valueRules)
	if err := configuration.Modify(add); err != nil {
		t.Fatalf("online Add(olcAccess): %v", err)
	}
	assertLDAPBackendStoredACL(t, proxyStore, valueRules)
	assertLDAPBackendDescriptionValues(t, data, []string{"public"})

	hiddenRules := []string{
		`{0}to dn.exact="` + ldapBackendTestUserDN + `" by * none`,
		`{1}to * by * write`,
	}
	replace := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
	replace.Replace("olcAccess", hiddenRules)
	if err := configuration.Modify(replace); err != nil {
		t.Fatalf("online Replace(olcAccess): %v", err)
	}
	assertLDAPBackendStoredACL(t, proxyStore, hiddenRules)
	assertLDAPBackendSearchEntryCount(t, data, 0)

	invalid := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
	invalid.Replace("olcAccess", []string{"{0}not-an-access-rule"})
	assertLDAPResultCode(
		t,
		configuration.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	assertLDAPBackendStoredACL(t, proxyStore, hiddenRules)
	assertLDAPBackendSearchEntryCount(t, data, 0)

	remove := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
	remove.Delete("olcAccess", nil)
	if err := configuration.Modify(remove); err != nil {
		t.Fatalf("online Delete(olcAccess): %v", err)
	}
	assertLDAPBackendStoredACL(t, proxyStore, nil)
	assertLDAPBackendDescriptionValues(
		t,
		data,
		[]string{"classified", "public"},
	)
}

func TestLDAPBackendACLPolicySourcesAndUpstreamSearchCount(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*testing.T, storage.Store) *acl.Policy
		want      []string
	}{
		{
			name: "no ACL fast path",
			configure: func(*testing.T, storage.Store) *acl.Policy {
				return nil
			},
			want: []string{"classified", "public"},
		},
		{
			name: "database olcAccess",
			configure: func(t *testing.T, store storage.Store) *acl.Policy {
				setLDAPBackendACLConfiguration(t, store, []string{
					`{0}to attrs=description val.regex="^classified$" by * none`,
					`{1}to * by * write`,
				})
				return nil
			},
			want: []string{"public"},
		},
		{
			name: "global olcAccess",
			configure: func(t *testing.T, store storage.Store) *acl.Policy {
				setLDAPBackendGlobalACLConfiguration(t, store, []string{
					`{0}to attrs=description val.regex="^classified$" by * none`,
					`{1}to * by * write`,
				})
				return nil
			},
			want: []string{"public"},
		},
		{
			name: "Config AccessPolicy",
			configure: func(t *testing.T, _ storage.Store) *acl.Policy {
				return newLDAPBackendExplicitAccessPolicy(t)
			},
			want: []string{"public"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			counter := &ldapBackendACLSearchCounter{}
			providerURI, stopProvider := startLDAPBackendACLProviderWithAudit(t, counter)
			defer stopProvider()

			proxyStore := storage.NewMemory()
			t.Cleanup(func() { _ = proxyStore.Close() })
			seedLDAPBackendProxyURI(t, proxyStore, providerURI)
			policy := test.configure(t, proxyStore)
			proxyAddress, stopProxy := startServer(t, proxyStore, Config{
				AccessPolicy: policy,
			})
			defer stopProxy()

			client := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
			defer client.Close()
			before := counter.searches.Load()
			assertLDAPBackendSubtreeDescriptionValues(t, client, test.want)
			if got := counter.searches.Load() - before; got != 1 {
				t.Fatalf("provider Search round trips = %d, want 1", got)
			}
		})
	}
}

func TestLDAPBackendLocalACLIdentityContext(t *testing.T) {
	providerURI, stopProvider := startLDAPBackendACLProvider(t)
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxyURI(t, proxyStore, providerURI)
	setLDAPBackendACLConfiguration(t, proxyStore, []string{
		`{0}to * by dn.exact="` + ldapBackendTestUserDN +
			`" none by dn.exact="cn=config" none by * read`,
	})
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	user := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
	defer user.Close()
	assertLDAPBackendSearchEntryCount(t, user, 0)

	root := dialLDAPBackendClient(t, proxyAddress)
	defer root.Close()
	if err := root.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("bind back-ldap database root: %v", err)
	}
	assertLDAPBackendSearchEntryCount(t, root, 1)
	proxied, err := root.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		[]ldap.Control{proxyAuthorizationControl("dn:"+ldapBackendTestUserDN, true)},
	))
	if err != nil {
		t.Fatalf("ProxyAuthz Search through back-ldap ACL: %v", err)
	}
	if len(proxied.Entries) != 0 {
		t.Fatalf("ProxyAuthz Search entries = %d, want 0 for effective identity", len(proxied.Entries))
	}

	configuration := dialLDAPBackendClient(t, proxyAddress)
	defer configuration.Close()
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind configuration root: %v", err)
	}
	assertLDAPBackendSearchEntryCount(t, configuration, 0)
}

func TestLDAPBackendLocalACLWithPcache(t *testing.T) {
	counter := &ldapBackendACLSearchCounter{}
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	if err := providerStore.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "ou=pcache-referral," + ldapBackendTestPeopleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("referral", "extensibleObject")},
				{Description: "ou", Values: stringValues("pcache-referral")},
				{Description: "ref", Values: stringValues("ldap://remote.example/dc=remote,dc=test")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed pcache ACL referral: %v", err)
	}
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
		AuditSink:    counter,
	})
	providerRunning := true
	defer func() {
		if providerRunning {
			stopProvider()
		}
	}()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	if err := proxyStore.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(testPcacheOverlayForDatabase(ldapBackendTestDatabaseDN), false)
	}); err != nil {
		t.Fatalf("add pcache overlay for back-ldap ACL: %v", err)
	}
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
	defer client.Close()
	configuration := dialLDAPBackendClient(t, proxyAddress)
	defer configuration.Close()
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind pcache ACL configuration root: %v", err)
	}
	search := func() *ldap.SearchResult {
		result, err := client.Search(ldap.NewSearchRequest(
			ldapBackendTestPeopleDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(sn=Proxy)",
			[]string{"uid", "cn", "sn"},
			nil,
		))
		if err != nil {
			t.Fatalf("pcache back-ldap ACL Search: %v", err)
		}
		return result
	}
	result := search()
	if len(result.Entries) != 2 || len(result.Referrals) != 1 {
		t.Fatalf("pcache response before back-ldap ACL = %#v", result)
	}
	if got := counter.searches.Load(); got != 1 {
		t.Fatalf("provider Searches before ACL = %d, want 1", got)
	}

	addACL := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
	addACL.Add("olcAccess", []string{
		`{0}to dn.exact="uid=bob,` + ldapBackendTestPeopleDN + `" by * none`,
		`{1}to * by * read`,
	})
	if err := configuration.Modify(addACL); err != nil {
		t.Fatalf("add back-ldap ACL over populated pcache: %v", err)
	}
	result = search()
	if len(result.Entries) != 1 ||
		!strings.EqualFold(result.Entries[0].DN, ldapBackendTestUserDN) ||
		len(result.Referrals) != 1 {
		t.Fatalf("pcache miss after back-ldap ACL change = %#v", result)
	}
	if got := counter.searches.Load(); got != 2 {
		t.Fatalf("provider Searches after ACL cache-key change = %d, want 2", got)
	}

	stopProvider()
	providerRunning = false
	result = search()
	if len(result.Entries) != 1 ||
		!strings.EqualFold(result.Entries[0].DN, ldapBackendTestUserDN) ||
		len(result.Referrals) != 1 {
		t.Fatalf("pcache hit with back-ldap ACL = %#v", result)
	}
	if got := counter.searches.Load(); got != 2 {
		t.Fatalf("provider Searches after offline ACL cache hit = %d, want 2", got)
	}
}

func TestLDAPBackendLocalACLPagingSortingAndReferral(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	if err := providerStore.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
				{Description: "olcOverlay", Values: stringValues("{1}sssvlv")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed provider sssvlv overlay: %v", err)
	}
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	setLDAPBackendACLConfiguration(t, proxyStore, []string{
		`{0}to dn.exact="uid=bob,` + ldapBackendTestPeopleDN + `" by * none`,
		`{1}to * by * read`,
	})
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
	defer client.Close()
	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	page := ldap.NewControlPaging(1)
	result, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		[]ldap.Control{sortControl, page},
	))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "alice" {
		t.Fatalf("sorted paged back-ldap ACL Search = %#v, %v", result, err)
	}
	assertSortResult(t, result, ldap.ControlServerSideSortingCodeSuccess)
	responsePage, ok := ldap.FindControl(
		result.Controls,
		ldap.ControlTypePaging,
	).(*ldap.ControlPaging)
	if !ok || len(responsePage.Cookie) == 0 {
		t.Fatalf("back-ldap ACL paging response = %#v", result.Controls)
	}

	continuation := ldap.NewControlPaging(1)
	continuation.SetCookie(responsePage.Cookie)
	_, err = client.Search(ldap.NewSearchRequest(
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		[]ldap.Control{newSortControl(ldap.SortKey{
			AttributeType: "cn",
			MatchingRule:  "caseIgnoreOrderingMatch",
		}), continuation},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)

	proxyReferral := ldapBackendReferralObservation(
		t,
		client,
		"ou=referral,"+ldapBackendTestSuffix,
	)
	provider := bindLDAPBackendUser(t, providerAddress, ldapBackendTestUserPassword)
	defer provider.Close()
	directReferral := ldapBackendReferralObservation(
		t,
		provider,
		"ou=referral,"+ldapBackendTestSuffix,
	)
	if !reflect.DeepEqual(proxyReferral, directReferral) {
		t.Fatalf("back-ldap ACL referral = %#v, want %#v", proxyReferral, directReferral)
	}
}

func TestLDAPBackendLocalACLGroupLookupAndFailure(t *testing.T) {
	const groupDN = "cn=readers," + ldapBackendTestPeopleDN
	for _, test := range []struct {
		name         string
		aclPassword  string
		wantCode     uint16
		wantEntries  int
		wantSearches int64
	}{
		{
			name:         "ACL bind resolves group",
			aclPassword:  ldapBackendTestAdminSecret,
			wantCode:     ldap.LDAPResultSuccess,
			wantEntries:  1,
			wantSearches: 2,
		},
		{
			name:         "ACL bind failure is reported",
			aclPassword:  "wrong-acl-password",
			wantCode:     ldap.LDAPResultUnavailable,
			wantSearches: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			counter := &ldapBackendACLSearchCounter{}
			providerStore := storage.NewMemory()
			t.Cleanup(func() { _ = providerStore.Close() })
			seedLDAPBackendProvider(t, providerStore)
			if err := providerStore.Update(context.Background(), func(writer storage.Writer) error {
				return writer.Put(directory.Entry{
					DN: groupDN,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("groupOfNames")},
						{Description: "cn", Values: stringValues("readers")},
						{Description: "member", Values: stringValues(ldapBackendTestUserDN)},
					},
				}, false)
			}); err != nil {
				t.Fatalf("seed back-ldap ACL group: %v", err)
			}
			providerAddress, stopProvider := startServer(t, providerStore, Config{
				RootDN:       ldapBackendTestAdminDN,
				RootPassword: []byte(ldapBackendTestAdminSecret),
				AuditSink:    counter,
			})
			defer stopProvider()

			proxyStore := storage.NewMemory()
			t.Cleanup(func() { _ = proxyStore.Close() })
			seedLDAPBackendProxy(t, proxyStore, providerAddress)
			setLDAPBackendACLConfiguration(t, proxyStore, []string{
				`{0}to * by group.exact="` + groupDN + `" read by * none`,
			})
			databaseDN, err := directory.ParseDN(ldapBackendTestDatabaseDN)
			if err != nil {
				t.Fatalf("parse back-ldap database DN: %v", err)
			}
			if err := proxyStore.Update(context.Background(), func(writer storage.Writer) error {
				entry, err := writer.Get(databaseDN)
				if err != nil {
					return err
				}
				entry.ReplaceValues("olcDbACLBind", stringValues(
					`bindmethod=simple binddn="`+ldapBackendTestAdminDN+
						`" credentials="`+test.aclPassword+`"`,
				))
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatalf("configure back-ldap ACL bind: %v", err)
			}
			proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
			defer stopProxy()

			client := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
			defer client.Close()
			before := counter.searches.Load()
			result, searchErr := client.Search(ldap.NewSearchRequest(
				ldapBackendTestUserDN,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				1,
				0,
				false,
				"(objectClass=*)",
				[]string{"uid"},
				nil,
			))
			if code := monitorLDAPResultCode(searchErr); code != test.wantCode {
				t.Fatalf("group ACL Search result = %d, want %d: %v", code, test.wantCode, searchErr)
			}
			if searchErr == nil && len(result.Entries) != test.wantEntries {
				t.Fatalf("group ACL Search entries = %d, want %d", len(result.Entries), test.wantEntries)
			}
			if got := counter.searches.Load() - before; got != test.wantSearches {
				t.Fatalf("group ACL provider Search round trips = %d, want %d", got, test.wantSearches)
			}
		})
	}
}

func assertLDAPBackendSubtreeDescriptionValues(
	t *testing.T,
	client *ldap.Conn,
	want []string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"description"},
		nil,
	))
	if err != nil {
		t.Fatalf("subtree Search(description): %v", err)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("subtree Search(description) entries = %d, want 2", len(result.Entries))
	}
	for _, entry := range result.Entries {
		if !strings.EqualFold(entry.DN, ldapBackendTestUserDN) {
			continue
		}
		got := append([]string(nil), entry.GetAttributeValues("description")...)
		sort.Strings(got)
		want = append([]string(nil), want...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("subtree Search(description) values = %q, want %q", got, want)
		}
		return
	}
	t.Fatalf("subtree Search omitted %s", ldapBackendTestUserDN)
}

func setLDAPBackendACLConfiguration(
	t *testing.T,
	store storage.Store,
	rules []string,
) {
	t.Helper()
	dn, err := directory.ParseDN(ldapBackendTestDatabaseDN)
	if err != nil {
		t.Fatalf("parse back-ldap database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(rules...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure back-ldap database olcAccess: %v", err)
	}
}

func setLDAPBackendGlobalACLConfiguration(
	t *testing.T,
	store storage.Store,
	rules []string,
) {
	t.Helper()
	dn, err := directory.ParseDN("cn=config")
	if err != nil {
		t.Fatalf("parse global configuration DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(rules...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure global olcAccess: %v", err)
	}
}

func newLDAPBackendExplicitAccessPolicy(t *testing.T) *acl.Policy {
	t.Helper()
	var rules []acl.Rule
	for _, raw := range []string{
		`to attrs=description val.regex="^classified$" by * none`,
		`to * by * write`,
	} {
		rule, err := acl.ParseRule(raw)
		if err != nil {
			t.Fatalf("parse explicit back-ldap ACL %q: %v", raw, err)
		}
		rules = append(rules, rule)
	}
	policy, err := acl.NewPolicy(nil, map[string][]acl.Rule{
		ldapBackendTestSuffix: rules,
	})
	if err != nil {
		t.Fatalf("build explicit back-ldap AccessPolicy: %v", err)
	}
	return policy
}

func assertLDAPBackendDescriptionValues(
	t *testing.T,
	client *ldap.Conn,
	want []string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(description): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(description) entries = %d, want 1", len(result.Entries))
	}
	got := append([]string(nil), result.Entries[0].GetAttributeValues("description")...)
	sort.Strings(got)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Search(description) values = %q, want %q", got, want)
	}
}

func assertLDAPBackendSearchEntryCount(
	t *testing.T,
	client *ldap.Conn,
	want int,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(entry visibility): %v", err)
	}
	if len(result.Entries) != want {
		t.Fatalf("Search(entry visibility) entries = %d, want %d", len(result.Entries), want)
	}
}

func assertLDAPBackendStoredACL(
	t *testing.T,
	store storage.Store,
	want []string,
) {
	t.Helper()
	dn, err := directory.ParseDN(ldapBackendTestDatabaseDN)
	if err != nil {
		t.Fatalf("parse back-ldap database DN: %v", err)
	}
	var got []string
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.Get(dn)
		if err != nil {
			return err
		}
		for _, value := range entry.Values("olcAccess") {
			got = append(got, string(value))
		}
		return nil
	}); err != nil {
		t.Fatalf("read stored back-ldap olcAccess: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stored back-ldap olcAccess = %q, want %q", got, want)
	}
}
