package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	ldapBackendRWMLocalSuffix    = "dc=virtual,dc=test"
	ldapBackendRWMLocalPeopleDN  = "ou=people," + ldapBackendRWMLocalSuffix
	ldapBackendRWMLocalAliceDN   = "uid=alice," + ldapBackendRWMLocalPeopleDN
	ldapBackendRWMLocalBobDN     = "uid=bob," + ldapBackendRWMLocalPeopleDN
	ldapBackendRWMLocalGroupDN   = "cn=staff," + ldapBackendRWMLocalPeopleDN
	ldapBackendRWMRemoteGroupDN  = "cn=staff," + ldapBackendTestPeopleDN
	ldapBackendRWMLocalRefDN     = "ou=rwm-referral," + ldapBackendRWMLocalPeopleDN
	ldapBackendRWMRemoteRefDN    = "ou=rwm-referral," + ldapBackendTestPeopleDN
	ldapBackendRWMLocalRootDN    = "cn=proxy-root," + ldapBackendRWMLocalSuffix
	ldapBackendRWMOverlayDN      = "olcOverlay={0}rwm," + ldapBackendTestDatabaseDN
	ldapBackendRWMUpdatedSecret  = "proxy-secret-rwm-updated"
	ldapBackendRWMInitialDisplay = "Initial RWM group"
	ldapBackendRWMUpdatedDisplay = "Updated RWM group"
)

type ldapBackendRWMOutcome struct {
	searchDN               string
	objectClasses          []string
	members                []string
	owners                 []string
	referrals              []string
	descriptions           []string
	filterEntries          int
	compareMatched         bool
	compareCode            uint16
	pagingResponse         bool
	missingCode            uint16
	missingMatchedDN       string
	modifyCode             uint16
	transactionCode        uint16
	transactionPreserved   bool
	modifyDNCode           uint16
	passwordModifyCode     uint16
	postPasswordSearchCode uint16
	oldPasswordCode        uint16
	newPasswordCode        uint16
	providerDN             string
	providerObjectClasses  []string
	providerMembers        []string
	providerOwners         []string
	providerReferrals      []string
	providerDisplays       []string
	deleteCode             uint16
	providerDeleteCode     uint16
}

func TestLDAPBackendRWMOperations(t *testing.T) {
	providerURI, stopProvider := startLDAPBackendRWMProvider(t)
	defer stopProvider()
	proxyURI, _, stopProxy := startLDAPBackendRWMProxy(t, providerURI, true)
	defer stopProxy()

	got := observeLDAPBackendRWM(t, proxyURI, providerURI, true, true)
	want := ldapBackendRWMExpectedOutcome(true, true)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("direct back-ldap RWM outcome:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestLDAPBackendRWMOnlineConfigurationRollback(t *testing.T) {
	providerURI, stopProvider := startLDAPBackendRWMProvider(t)
	defer stopProvider()
	proxyURI, proxyStore, stopProxy := startLDAPBackendRWMProxy(t, providerURI, false)
	defer stopProxy()

	config := dialLDAPBackendRWMClient(t, proxyURI)
	defer config.Close()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind cn=config: %v", err)
	}
	request := ldap.NewAddRequest(ldapBackendRWMOverlayDN, nil)
	request.Attribute("objectClass", []string{"olcOverlayConfig", "olcRwmConfig"})
	request.Attribute("olcOverlay", []string{"{0}rwm"})
	request.Attribute("olcRwmRewrite", []string{ldapBackendRWMSuffixDirective()})
	request.Attribute("olcRwmMap", ldapBackendRWMMapDirectives())
	if err := config.Add(request); err != nil {
		t.Fatalf("add direct back-ldap RWM overlay online: %v", err)
	}

	assertLDAPBackendRWMLocalSearch(t, proxyURI)
	modify := ldap.NewModifyRequest(ldapBackendRWMOverlayDN, nil)
	modify.Replace("olcRwmRewrite", []string{"{0}rewriteContext default"})
	err := config.Modify(modify)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "unsupported rewrite directive") {
		t.Fatalf("invalid online RWM Modify error = %v", err)
	}
	assertLDAPBackendRWMLocalSearch(t, proxyURI)

	dn, parseErr := directory.ParseDN(ldapBackendRWMOverlayDN)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if err := proxyStore.View(t.Context(), func(reader storage.Reader) error {
		entry, err := reader.Get(dn)
		if err != nil {
			return err
		}
		values := entry.Values("olcRwmRewrite")
		if len(values) != 1 || string(values[0]) != ldapBackendRWMSuffixDirective() {
			return fmt.Errorf("persisted olcRwmRewrite = %q", values)
		}
		return nil
	}); err != nil {
		t.Fatalf("invalid RWM Modify was not rolled back: %v", err)
	}
}

func TestLDAPBackendRWMNoConfigurationFastPath(t *testing.T) {
	controlValue := []byte{0x01, 0x02, 0x03}
	message := ldapwire.Message{
		ID: 17,
		Request: ldapwire.SearchRequest{
			BaseDN:     ldapBackendTestSuffix,
			Attributes: []string{"cn", "sn"},
		},
		Controls: []ldapwire.Control{{
			OID:      "1.2.3.4",
			Value:    controlValue,
			HasValue: true,
		}},
	}
	mapped, err := mapLDAPBackendRequestToRemote(nil, message)
	if err != nil || !reflect.DeepEqual(mapped, message) {
		t.Fatalf("nil RWM request mapping = %#v, %v", mapped, err)
	}
	if &mapped.Controls[0].Value[0] != &message.Controls[0].Value[0] {
		t.Fatal("nil RWM request fast path cloned controls")
	}

	attempt := chainAttempt{
		result:      ldapwire.Result{Code: ldapwire.ResultSuccess},
		hasResult:   true,
		localResult: &ldapwire.Result{Code: ldapwire.ResultReferral},
	}
	mappedAttempt, err := mapLDAPBackendAttemptToLocal(nil, attempt)
	if err != nil || mappedAttempt.localResult != attempt.localResult {
		t.Fatalf("nil RWM response mapping = %#v, %v", mappedAttempt, err)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if _, mapErr := mapLDAPBackendRequestToRemote(nil, message); mapErr != nil {
			panic(mapErr)
		}
		if _, mapErr := mapLDAPBackendAttemptToLocal(nil, attempt); mapErr != nil {
			panic(mapErr)
		}
	}); allocations != 0 {
		t.Fatalf("nil RWM request/response fast path allocations = %v, want 0", allocations)
	}
}

func TestOpenLDAPReferenceLDAPBackendRWM(t *testing.T) {
	tools := requireOpenLDAPLDAPBackendReferenceTools(t)
	assertOpenLDAPLDAPBackendRWMSource(t)

	providerURI, stopProvider := startLDAPBackendRWMProvider(t)
	referenceURI, stopReference := startOpenLDAPBackendRWMProxy(
		t,
		tools,
		providerURI,
	)
	reference := observeLDAPBackendRWM(t, referenceURI, providerURI, false, false)
	stopReference()
	stopProvider()

	providerURI, stopProvider = startLDAPBackendRWMProvider(t)
	defer stopProvider()
	implementationURI, _, stopImplementation := startLDAPBackendRWMProxy(
		t,
		providerURI,
		true,
	)
	defer stopImplementation()
	implementation := observeLDAPBackendRWM(
		t,
		implementationURI,
		providerURI,
		false,
		false,
	)
	if !reflect.DeepEqual(implementation, reference) {
		t.Fatalf(
			"direct back-ldap RWM differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}
	want := ldapBackendRWMExpectedOutcome(false, false)
	if !reflect.DeepEqual(reference, want) {
		t.Fatalf("OpenLDAP 2.6.13 RWM fixture drifted:\n got: %#v\nwant: %#v", reference, want)
	}
}

func observeLDAPBackendRWM(
	t *testing.T,
	proxyURI,
	providerURI string,
	includeOptionalUID,
	checkTransaction bool,
) ldapBackendRWMOutcome {
	t.Helper()
	client := dialLDAPBackendRWMClient(t, proxyURI)
	defer client.Close()
	if err := client.Bind(ldapBackendRWMLocalAliceDN, ldapBackendTestUserPassword); err != nil {
		t.Fatalf("bind mapped back-ldap user at %s: %v", proxyURI, err)
	}

	members := []string{ldapBackendRWMLocalAliceDN}
	assertedMember := ldapBackendRWMLocalAliceDN
	if includeOptionalUID {
		assertedMember = ldapBackendRWMLocalBobDN + "#'0101'B"
		members = append(members, assertedMember)
	}
	add := ldap.NewAddRequest(ldapBackendRWMLocalGroupDN, nil)
	add.Attribute("objectClass", []string{"top", "groupOfNames", "extensibleObject"})
	add.Attribute("cn", []string{"staff"})
	add.Attribute("member", members)
	add.Attribute("owner", []string{ldapBackendRWMLocalAliceDN})
	add.Attribute("description", []string{ldapBackendRWMInitialDisplay})
	if err := client.Add(add); err != nil {
		t.Fatalf("add mapped group through %s: %v", proxyURI, err)
	}

	filter := "(&(objectClass=groupOfNames)(member=" +
		ldap.EscapeFilter(assertedMember) + ")(description=" +
		ldap.EscapeFilter(ldapBackendRWMInitialDisplay) + "))"
	search, err := client.Search(ldap.NewSearchRequest(
		ldapBackendRWMLocalPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"objectClass", "member", "owner", "description"},
		nil,
	))
	if err != nil || len(search.Entries) != 1 {
		t.Fatalf("search mapped group through %s = %#v, %v", proxyURI, search, err)
	}
	entry := search.Entries[0]
	outcome := ldapBackendRWMOutcome{
		searchDN:      entry.DN,
		objectClasses: sortedLDAPBackendRWMValues(entry.GetAttributeValues("objectClass")),
		members:       sortedLDAPBackendRWMValues(entry.GetAttributeValues("member")),
		owners:        sortedLDAPBackendRWMValues(entry.GetAttributeValues("owner")),
		descriptions:  sortedLDAPBackendRWMValues(entry.GetAttributeValues("description")),
		filterEntries: len(search.Entries),
	}
	referralModify := ldap.NewModifyRequest(ldapBackendRWMLocalRefDN, nil)
	referralModify.Replace("ref", []string{"ldap://provider/" + ldapBackendRWMLocalBobDN})
	referralModify.Controls = []ldap.Control{ldap.NewControlString(
		manageDsaITControlOID,
		true,
		"",
	)}
	if err := client.Modify(referralModify); err != nil {
		t.Fatalf("modify mapped referral URL through %s: %v", proxyURI, err)
	}
	referralEntry := searchLDAPBackendRWMManagedEntry(
		t,
		client,
		ldapBackendRWMLocalRefDN,
		[]string{"ref"},
	)
	outcome.referrals = sortedLDAPBackendRWMValues(
		referralEntry.GetAttributeValues("ref"),
	)
	outcome.compareMatched, err = client.Compare(
		ldapBackendRWMLocalGroupDN,
		"member",
		assertedMember,
	)
	outcome.compareCode = monitorLDAPResultCode(err)

	pagedRequest := ldap.NewSearchRequest(
		ldapBackendRWMLocalPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=groupOfNames)",
		[]string{"cn"},
		[]ldap.Control{ldap.NewControlPaging(1)},
	)
	paged, pagedErr := client.Search(pagedRequest)
	if pagedErr != nil || len(paged.Entries) != 1 {
		t.Fatalf("paged mapped Search through %s = %#v, %v", proxyURI, paged, pagedErr)
	}
	outcome.pagingResponse = ldap.FindControl(
		paged.Controls,
		ldap.ControlTypePaging,
	) != nil

	missingDN := "uid=missing," + ldapBackendRWMLocalPeopleDN
	_, err = client.Search(ldap.NewSearchRequest(
		missingDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	outcome.missingCode = monitorLDAPResultCode(err)
	var missing *ldap.Error
	if errors.As(err, &missing) {
		outcome.missingMatchedDN = missing.MatchedDN
	}

	modify := ldap.NewModifyRequest(ldapBackendRWMLocalGroupDN, nil)
	modify.Replace("description", []string{ldapBackendRWMUpdatedDisplay})
	outcome.modifyCode = monitorLDAPResultCode(client.Modify(modify))
	if checkTransaction {
		transaction := ldap.NewModifyRequest(ldapBackendRWMLocalGroupDN, nil)
		transaction.Replace("description", []string{"must not commit"})
		transaction.Controls = []ldap.Control{ldap.NewControlString(
			transactionSpecificationControlOID,
			true,
			"not-a-live-transaction",
		)}
		outcome.transactionCode = monitorLDAPResultCode(client.Modify(transaction))
		verification := searchLDAPBackendRWMEntry(
			t,
			client,
			ldapBackendRWMLocalGroupDN,
			[]string{"description"},
		)
		outcome.transactionPreserved = verification.GetAttributeValue("description") ==
			ldapBackendRWMUpdatedDisplay
	}

	renamedLocalDN := "cn=renamed," + ldapBackendRWMLocalPeopleDN
	renamedRemoteDN := "cn=renamed," + ldapBackendTestPeopleDN
	outcome.modifyDNCode = monitorLDAPResultCode(client.ModifyDN(
		ldap.NewModifyDNRequest(
			ldapBackendRWMLocalGroupDN,
			"cn=renamed",
			true,
			ldapBackendRWMLocalPeopleDN,
		),
	))
	outcome.passwordModifyCode = monitorLDAPResultCode(func() error {
		_, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
			ldapBackendRWMLocalAliceDN,
			ldapBackendTestUserPassword,
			ldapBackendRWMUpdatedSecret,
		))
		return err
	}())
	_, err = client.Search(ldap.NewSearchRequest(
		renamedLocalDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=groupOfNames)",
		[]string{"cn"},
		nil,
	))
	outcome.postPasswordSearchCode = monitorLDAPResultCode(err)
	outcome.oldPasswordCode = ldapBackendRWMBindCode(
		t,
		proxyURI,
		ldapBackendTestUserPassword,
	)
	outcome.newPasswordCode = ldapBackendRWMBindCode(
		t,
		proxyURI,
		ldapBackendRWMUpdatedSecret,
	)

	provider := dialLDAPBackendRWMClient(t, providerURI)
	defer provider.Close()
	if err := provider.Bind(ldapBackendTestAdminDN, ldapBackendTestAdminSecret); err != nil {
		t.Fatalf("bind RWM provider root: %v", err)
	}
	providerEntry := searchLDAPBackendRWMEntry(
		t,
		provider,
		renamedRemoteDN,
		[]string{"objectClass", "uniqueMember", "owner", "businessCategory"},
	)
	outcome.providerDN = providerEntry.DN
	outcome.providerObjectClasses = sortedLDAPBackendRWMValues(
		providerEntry.GetAttributeValues("objectClass"),
	)
	outcome.providerMembers = sortedLDAPBackendRWMValues(
		providerEntry.GetAttributeValues("uniqueMember"),
	)
	outcome.providerOwners = sortedLDAPBackendRWMValues(
		providerEntry.GetAttributeValues("owner"),
	)
	providerReferral := searchLDAPBackendRWMManagedEntry(
		t,
		provider,
		ldapBackendRWMRemoteRefDN,
		[]string{"ref"},
	)
	outcome.providerReferrals = sortedLDAPBackendRWMValues(
		providerReferral.GetAttributeValues("ref"),
	)
	outcome.providerDisplays = sortedLDAPBackendRWMValues(
		providerEntry.GetAttributeValues("businessCategory"),
	)

	outcome.deleteCode = monitorLDAPResultCode(client.Del(
		ldap.NewDelRequest(renamedLocalDN, nil),
	))
	_, err = provider.Search(ldap.NewSearchRequest(
		renamedRemoteDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	outcome.providerDeleteCode = monitorLDAPResultCode(err)
	return outcome
}

func ldapBackendRWMExpectedOutcome(
	includeOptionalUID,
	checkTransaction bool,
) ldapBackendRWMOutcome {
	localMembers := []string{ldapBackendRWMLocalAliceDN}
	remoteMembers := []string{ldapBackendTestUserDN}
	if includeOptionalUID {
		localMembers = append(localMembers, ldapBackendRWMLocalBobDN+"#'0101'B")
		remoteMembers = append(
			remoteMembers,
			"uid=bob,"+ldapBackendTestPeopleDN+"#'0101'B",
		)
	}
	outcome := ldapBackendRWMOutcome{
		searchDN:               ldapBackendRWMLocalGroupDN,
		objectClasses:          sortedLDAPBackendRWMValues([]string{"top", "groupOfNames", "extensibleObject"}),
		members:                sortedLDAPBackendRWMValues(localMembers),
		owners:                 []string{ldapBackendRWMLocalAliceDN},
		referrals:              []string{"ldap://provider/" + ldapBackendRWMLocalBobDN},
		descriptions:           []string{ldapBackendRWMInitialDisplay},
		filterEntries:          1,
		compareMatched:         true,
		compareCode:            ldap.LDAPResultSuccess,
		pagingResponse:         true,
		missingCode:            ldap.LDAPResultNoSuchObject,
		missingMatchedDN:       ldapBackendRWMLocalPeopleDN,
		modifyCode:             ldap.LDAPResultSuccess,
		modifyDNCode:           ldap.LDAPResultSuccess,
		passwordModifyCode:     ldap.LDAPResultSuccess,
		postPasswordSearchCode: ldap.LDAPResultSuccess,
		oldPasswordCode:        ldap.LDAPResultInvalidCredentials,
		newPasswordCode:        ldap.LDAPResultSuccess,
		providerDN:             "cn=renamed," + ldapBackendTestPeopleDN,
		providerObjectClasses:  sortedLDAPBackendRWMValues([]string{"top", "groupOfUniqueNames", "extensibleObject"}),
		providerMembers:        sortedLDAPBackendRWMValues(remoteMembers),
		providerOwners:         []string{ldapBackendTestUserDN},
		providerReferrals:      []string{"ldap://provider/" + ldapBackendRWMLocalBobDN},
		providerDisplays:       []string{ldapBackendRWMUpdatedDisplay},
		deleteCode:             ldap.LDAPResultSuccess,
		providerDeleteCode:     ldap.LDAPResultNoSuchObject,
	}
	if checkTransaction {
		outcome.transactionCode = ldap.LDAPResultUnwillingToPerform
		outcome.transactionPreserved = true
	}
	return outcome
}

func startLDAPBackendRWMProvider(t *testing.T) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPBackendProvider(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: ldapBackendRWMRemoteRefDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("referral", "extensibleObject")},
				{Description: "ou", Values: stringValues("rwm-referral")},
				{Description: "ref", Values: stringValues("ldap://provider/" + ldapBackendTestUserDN)},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed RWM provider referral: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	return "ldap://" + address, stop
}

func startLDAPBackendRWMProxy(
	t *testing.T,
	providerURI string,
	withRWM bool,
) (string, storage.Store, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPBackendRWMProxy(t, store, providerURI, withRWM)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, store, stop
}

func seedLDAPBackendRWMProxy(
	t *testing.T,
	store storage.Store,
	providerURI string,
	withRWM bool,
) {
	t.Helper()
	database := ldapBackendDatabaseEntry(
		"{1}ldap",
		ldapBackendRWMLocalSuffix,
		providerURI,
	)
	database.ReplaceValues("olcRootDN", stringValues(ldapBackendRWMLocalRootDN))
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
				{Description: "olcAccess", Values: stringValues("{0}to * by * none")},
			},
		},
		database,
	}
	if withRWM {
		entries = append(entries, ldapBackendRWMOverlayEntry())
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{ldapBackendRWMLocalSuffix, "cn=config"})
	}); err != nil {
		t.Fatalf("seed direct back-ldap RWM proxy: %v", err)
	}
}

func ldapBackendRWMOverlayEntry() directory.Entry {
	return directory.Entry{
		DN: ldapBackendRWMOverlayDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcRwmConfig")},
			{Description: "olcOverlay", Values: stringValues("{0}rwm")},
			{Description: "olcRwmRewrite", Values: stringValues(ldapBackendRWMSuffixDirective())},
			{Description: "olcRwmMap", Values: stringValues(ldapBackendRWMMapDirectives()...)},
		},
	}
}

func ldapBackendRWMSuffixDirective() string {
	return `{0}rwm-suffixmassage "` + ldapBackendRWMLocalSuffix + `" "` +
		ldapBackendTestSuffix + `"`
}

func ldapBackendRWMMapDirectives() []string {
	return []string{
		"{0}objectClass groupOfNames groupOfUniqueNames",
		"{1}attribute member uniqueMember",
		"{2}attribute description businessCategory",
	}
}

func assertLDAPBackendRWMLocalSearch(t *testing.T, proxyURI string) {
	t.Helper()
	client := dialLDAPBackendRWMClient(t, proxyURI)
	defer client.Close()
	if err := client.Bind(ldapBackendRWMLocalAliceDN, ldapBackendTestUserPassword); err != nil {
		t.Fatalf("bind through online direct RWM: %v", err)
	}
	entry := searchLDAPBackendRWMEntry(
		t,
		client,
		ldapBackendRWMLocalAliceDN,
		[]string{"uid"},
	)
	if entry.DN != ldapBackendRWMLocalAliceDN || entry.GetAttributeValue("uid") != "alice" {
		t.Fatalf("online direct RWM Search entry = %#v", entry)
	}
}

func searchLDAPBackendRWMEntry(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attributes,
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search(%s) = %#v, %v", dn, result, err)
	}
	return result.Entries[0]
}

func searchLDAPBackendRWMManagedEntry(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attributes,
		[]ldap.Control{ldap.NewControlString(manageDsaITControlOID, true, "")},
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("managed Search(%s) = %#v, %v", dn, result, err)
	}
	return result.Entries[0]
}

func dialLDAPBackendRWMClient(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial %s: %v", uri, err)
	}
	return client
}

func ldapBackendRWMBindCode(t *testing.T, uri, password string) uint16 {
	t.Helper()
	client := dialLDAPBackendRWMClient(t, uri)
	defer client.Close()
	return monitorLDAPResultCode(client.Bind(ldapBackendRWMLocalAliceDN, password))
}

func sortedLDAPBackendRWMValues(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
