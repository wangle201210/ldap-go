package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPBackendReferralHopLimit(t *testing.T) {
	providers := startLDAPBackendReferralProviders(t, openLDAPDefaultReferralHopLimit+1)

	withinLimit := startLDAPBackendReferralProxy(t, providers[1])
	got := observeLDAPBackendReferralSearch(t, "ldap://"+withinLimit)
	if got.code != ldap.LDAPResultSuccess || got.entryDN != ldapBackendTestUserDN {
		t.Fatalf("five referral hops = %#v, want successful final entry", got)
	}

	overLimit := startLDAPBackendReferralProxy(t, providers[0])
	got = observeLDAPBackendReferralSearch(t, "ldap://"+overLimit)
	if got.code != ldap.LDAPResultLoopDetect || got.entryDN != "" {
		t.Fatalf("six referral hops = %#v, want loopDetect", got)
	}
}

func TestLDAPBackendSearchReferenceHopLimit(t *testing.T) {
	providers := startLDAPBackendSearchReferenceProviders(
		t,
		openLDAPDefaultReferralHopLimit+1,
	)

	withinLimit := startLDAPBackendReferralProxy(t, providers[1])
	got := observeLDAPBackendReferralSearchRequest(
		t,
		"ldap://"+withinLimit,
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
	)
	if got.code != ldap.LDAPResultSuccess {
		t.Fatalf("five search-reference hops = %#v, want success", got)
	}

	overLimit := startLDAPBackendReferralProxy(t, providers[0])
	got = observeLDAPBackendReferralSearchRequest(
		t,
		"ldap://"+overLimit,
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
	)
	if got.code != ldap.LDAPResultLoopDetect {
		t.Fatalf("six search-reference hops = %#v, want loopDetect", got)
	}
}

func TestMetaBackendReferralHopLimit(t *testing.T) {
	providers := startLDAPBackendReferralProviders(t, openLDAPDefaultReferralHopLimit+1)

	withinLimit := startMetaBackendReferralProxy(t, providers[1])
	got := observeLDAPBackendReferralSearch(t, "ldap://"+withinLimit)
	if got.code != ldap.LDAPResultSuccess || got.entryDN != ldapBackendTestUserDN {
		t.Fatalf("back-meta five referral hops = %#v, want successful final entry", got)
	}

	overLimit := startMetaBackendReferralProxy(t, providers[0])
	got = observeLDAPBackendReferralSearch(t, "ldap://"+overLimit)
	if got.code != ldap.LDAPResultLoopDetect || got.entryDN != "" {
		t.Fatalf("back-meta six referral hops = %#v, want loopDetect", got)
	}
}

func TestMetaBackendSearchReferenceHopLimit(t *testing.T) {
	providers := startLDAPBackendSearchReferenceProviders(
		t,
		openLDAPDefaultReferralHopLimit+1,
	)

	withinLimit := startMetaBackendReferralProxy(t, providers[1])
	got := observeLDAPBackendReferralSearchRequest(
		t,
		"ldap://"+withinLimit,
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
	)
	if got.code != ldap.LDAPResultSuccess {
		t.Fatalf("back-meta five search-reference hops = %#v, want success", got)
	}

	overLimit := startMetaBackendReferralProxy(t, providers[0])
	got = observeLDAPBackendReferralSearchRequest(
		t,
		"ldap://"+overLimit,
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
	)
	if got.code != ldap.LDAPResultSuccess {
		t.Fatalf("back-meta continue after partial search-reference result = %#v, want success", got)
	}

	reportLimit := startMetaBackendReferralProxy(t, providers[0], "report")
	got = observeLDAPBackendReferralSearchRequest(
		t,
		"ldap://"+reportLimit,
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
	)
	if got.code != ldap.LDAPResultLoopDetect {
		t.Fatalf("back-meta report after search-reference hop limit = %#v, want loopDetect", got)
	}
}

func TestOpenLDAPReferenceLDAPBackendReferralHopLimit(t *testing.T) {
	_ = requireOpenLDAPLDAPBackendReferenceTools(t)
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("referral limit reference requires a verified OpenLDAP build")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != "d172686d3d270bc961b78f3ff00d7019c8dfb094" {
		t.Fatalf("OpenLDAP reference commit = %q", got)
	}
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	files := map[string][]string{
		filepath.Join("libraries", "libldap", "ldap-int.h"): {
			"#define LDAP_DEFAULT_REFHOPLIMIT 5",
		},
		filepath.Join("libraries", "libldap", "request.c"): {
			"lr->lr_parentcnt >= ld->ld_refhoplimit",
			"ld->ld_errno = LDAP_REFERRAL_LIMIT_EXCEEDED",
		},
		filepath.Join("servers", "slapd", "result.c"): {
			"case LDAP_REFERRAL_LIMIT_EXCEEDED:",
			"return LDAP_LOOP_DETECT;",
		},
	}
	for relativePath, anchors := range files {
		contents, err := os.ReadFile(filepath.Join(sourceRoot, relativePath))
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", relativePath, err)
		}
		for _, anchor := range anchors {
			if !strings.Contains(string(contents), anchor) {
				t.Fatalf("pinned OpenLDAP source %s lacks %q", relativePath, anchor)
			}
		}
	}
}

type ldapBackendReferralSearchObservation struct {
	code       uint16
	entryDN    string
	diagnostic string
}

func observeLDAPBackendReferralSearch(
	t *testing.T,
	uri string,
) ldapBackendReferralSearchObservation {
	t.Helper()
	return observeLDAPBackendReferralSearchRequest(
		t,
		uri,
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
	)
}

func observeLDAPBackendReferralSearchRequest(
	t *testing.T,
	uri string,
	baseDN string,
	scope int,
) ldapBackendReferralSearchObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	client.SetTimeout(10 * time.Second)

	result, err := client.Search(ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	observation := ldapBackendReferralSearchObservation{code: ldap.LDAPResultSuccess}
	if result != nil && len(result.Entries) > 0 {
		observation.entryDN = result.Entries[0].DN
	}
	if err == nil {
		return observation
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("Search(%s): %v", uri, err)
	}
	observation.code = ldapError.ResultCode
	if ldapError.Err != nil {
		observation.diagnostic = ldapError.Err.Error()
	}
	return observation
}

func startLDAPBackendReferralProviders(t *testing.T, referrals int) []string {
	t.Helper()
	return startLDAPBackendReferralProvidersWithTarget(
		t,
		referrals,
		ldapBackendTestUserDN,
	)
}

func startLDAPBackendSearchReferenceProviders(
	t *testing.T,
	referrals int,
) []string {
	t.Helper()
	return startLDAPBackendReferralProvidersWithTarget(
		t,
		referrals,
		ldapBackendTestPeopleDN+"??sub",
	)
}

func startLDAPBackendReferralProvidersWithTarget(
	t *testing.T,
	referrals int,
	referralTarget string,
) []string {
	t.Helper()
	addresses := make([]string, referrals+1)
	nextAddress := ""
	for index := referrals; index >= 0; index-- {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedLDAPBackendProvider(t, store)
		if nextAddress != "" {
			replaceLDAPBackendUserWithReferral(
				t,
				store,
				nextAddress,
				referralTarget,
			)
		}
		address, stop := startServer(t, store, Config{
			RootDN:       ldapBackendTestAdminDN,
			RootPassword: []byte(ldapBackendTestAdminSecret),
		})
		t.Cleanup(stop)
		addresses[index] = address
		nextAddress = address
	}
	return addresses
}

func replaceLDAPBackendUserWithReferral(
	t *testing.T,
	store storage.Store,
	nextAddress string,
	referralTarget string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: ldapBackendTestUserDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("referral", "extensibleObject")},
			{Description: "uid", Values: stringValues("alice")},
			{
				Description: "ref",
				Values: stringValues(
					"ldap://" + nextAddress + "/" + referralTarget,
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("replace provider user with referral: %v", err)
	}
}

func startLDAPBackendReferralProxy(t *testing.T, providerAddress string) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPBackendProxy(t, store, providerAddress)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(ldapBackendTestDatabaseDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbChaseReferrals", stringValues("TRUE"))
		entry.ReplaceValues("olcDbIDAssertBind", nil)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("enable proxy referral chasing: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	return address
}

func startMetaBackendReferralProxy(
	t *testing.T,
	providerAddress string,
	onError ...string,
) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	databaseDN := "olcDatabase={1}meta,cn=config"
	metaDatabase := directory.Entry{
		DN: databaseDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
			{Description: "olcDatabase", Values: stringValues("{1}meta")},
			{Description: "olcSuffix", Values: stringValues(ldapBackendTestSuffix)},
			{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
		},
	}
	if len(onError) > 0 {
		metaDatabase.ReplaceValues("olcDbOnErr", stringValues(onError[0]))
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
		metaDatabase,
		{
			DN: "olcMetaSub={0}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(fmt.Sprintf(
					`"ldap://%s/%s"`,
					providerAddress,
					ldapBackendTestSuffix,
				))},
				{Description: "olcDbChaseReferrals", Values: stringValues("TRUE")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{ldapBackendTestSuffix, "cn=config"})
	}); err != nil {
		t.Fatalf("seed back-meta referral proxy: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	return address
}
