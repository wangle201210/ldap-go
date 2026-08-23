package server

import (
	"context"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const asyncMetaTestDatabaseDN = "olcDatabase={1}asyncmeta,cn=config"

func TestAsyncMetaMultiTargetSearchAndReloadRollback(t *testing.T) {
	providerOneAddress, stopProviderOne := startAsyncMetaTestProvider(t, "async-one")
	defer stopProviderOne()
	providerTwoAddress, stopProviderTwo := startAsyncMetaTestProvider(t, "async-two")
	defer stopProviderTwo()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedAsyncMetaTestProxy(t, store, providerOneAddress, providerTwoAddress)
	assertAsyncMetaRuntimeConfiguration(t, store, 2)

	proxyAddress, stopProxy := startServer(t, store, Config{})
	defer stopProxy()
	client := dialLDAPBackendClient(t, proxyAddress)
	defer client.Close()
	if err := client.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("Bind(asyncmeta root): %v", err)
	}
	assertAsyncMetaSearchUnion(t, client)

	config := dialLDAPBackendClient(t, proxyAddress)
	defer config.Close()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	reload := ldap.NewModifyRequest(asyncMetaTestDatabaseDN, nil)
	reload.Replace("olcDbMaxPendingOps", []string{"3"})
	if err := config.Modify(reload); err != nil {
		t.Fatalf("reload asyncmeta max pending operations: %v", err)
	}
	assertAsyncMetaRuntimeConfiguration(t, store, 3)
	assertAsyncMetaSearchUnion(t, client)

	invalid := ldap.NewModifyRequest(asyncMetaTestDatabaseDN, nil)
	invalid.Replace("olcDbMaxPendingOps", []string{"-1"})
	assertLDAPResultCode(t, config.Modify(invalid), ldap.LDAPResultConstraintViolation)
	assertAsyncMetaRuntimeConfiguration(t, store, 3)
	assertAsyncMetaSearchUnion(t, client)
}

func TestAsyncMetaPendingLimitReturnsBusy(t *testing.T) {
	configuration := &asyncMetaBackendRuntimeConfiguration{
		meta:                 &metaBackendRuntimeConfiguration{},
		maxPendingOperations: 1,
		maxTargetConnections: 2,
		scheduler:            newAsyncMetaScheduler(2),
	}
	first := configuration.acquire()
	second := configuration.acquire()
	if first == nil || second == nil || first.connection == second.connection {
		t.Fatalf("asyncmeta metaconn leases = %#v, %#v", first, second)
	}
	if lease := configuration.acquire(); lease != nil {
		lease.release()
		t.Fatal("round-robin selected a full metaconn without returning busy")
	}
	first.release()
	if lease := configuration.acquire(); lease != nil {
		lease.release()
		t.Fatal("round-robin skipped the next full metaconn")
	}
	recovered := configuration.acquire()
	if recovered == nil || recovered.connection != first.connection {
		t.Fatalf("asyncmeta released metaconn was not reusable: %#v", recovered)
	}
	recovered.release()
	second.release()
}

func TestAsyncMetaTimeoutsAreTargetScopedAndCountPartialResponses(t *testing.T) {
	configuration := &asyncMetaBackendRuntimeConfiguration{
		maxPendingOperations: 2,
		scheduler:            newAsyncMetaScheduler(2),
	}
	first := configuration.acquire()
	second := configuration.acquire()
	if first == nil || second == nil || first.connection == second.connection {
		t.Fatalf("asyncmeta leases = %#v and %#v", first, second)
	}
	defer first.release()
	defer second.release()
	const target = "olcAsyncMetaSub={0}uri"
	if retired := first.observeTarget(target, 1, true, true); len(retired) != 0 {
		t.Fatalf("first partial timeout retired owners %q", retired)
	}
	retired := second.observeTarget(target, 1, true, true)
	if len(retired) != 2 {
		t.Fatalf("shared target timeout retired owners %q, want both metaconns", retired)
	}
	for connection := 0; connection < 2; connection++ {
		want := asyncMetaDerivedTransportOwner(target, connection, 0)
		found := false
		for _, owner := range retired {
			if owner == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("retired owners %q do not include %q", retired, want)
		}
	}
	if got, want := first.transportOwner(target),
		asyncMetaDerivedTransportOwner(target, first.connection, 1); got != want {
		t.Fatalf("target transport owner after retirement = %q, want %q", got, want)
	}

	if retired := first.observeTarget(target, 1, true, false); len(retired) != 0 {
		t.Fatalf("timeout before success retired owners %q", retired)
	}
	if retired := second.observeTarget(target, 1, false, true); len(retired) != 0 {
		t.Fatalf("successful response retired owners %q", retired)
	}
	configuration.scheduler.mu.Lock()
	remaining := configuration.scheduler.targets[target].consecutiveTimeouts
	configuration.scheduler.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("successful target response left %d consecutive timeouts", remaining)
	}
}

func startAsyncMetaTestProvider(t *testing.T, uid string) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPBackendProvider(t, store)
	entry := directory.Entry{
		DN: "uid=" + uid + "," + ldapBackendTestPeopleDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(uid)},
			{Description: "sn", Values: stringValues("Asyncmeta")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed asyncmeta provider %q: %v", uid, err)
	}
	return startServer(t, store, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
}

func seedAsyncMetaTestProxy(
	t *testing.T,
	store storage.Store,
	providerOneAddress string,
	providerTwoAddress string,
) {
	t.Helper()
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
			DN: asyncMetaTestDatabaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcAsyncMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}asyncmeta")},
				{Description: "olcSuffix", Values: stringValues(ldapBackendTestSuffix)},
				{Description: "olcRootDN", Values: stringValues(ldapBackendTestLocalRootDN)},
				{Description: "olcRootPW", Values: stringValues(ldapBackendTestLocalRootPW)},
				{Description: "olcDbMaxPendingOps", Values: stringValues("2")},
				{Description: "olcDbMaxTargetConns", Values: stringValues("4")},
				{Description: "olcDbOnErr", Values: stringValues("report")},
			},
		},
		asyncMetaTestTarget(0, providerOneAddress),
		asyncMetaTestTarget(1, providerTwoAddress),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{ldapBackendTestSuffix, "cn=config"})
	}); err != nil {
		t.Fatalf("seed asyncmeta proxy: %v", err)
	}
}

func asyncMetaTestTarget(order int, providerAddress string) directory.Entry {
	marker := "{" + string(rune('0'+order)) + "}uri"
	return directory.Entry{
		DN: "olcAsyncMetaSub=" + marker + "," + asyncMetaTestDatabaseDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcAsyncMetaTargetConfig")},
			{Description: "olcAsyncMetaSub", Values: stringValues(marker)},
			{Description: "olcDbURI", Values: stringValues(
				"ldap://" + providerAddress + "/" + ldapBackendTestSuffix,
			)},
			{Description: "olcDbIDAssertBind", Values: stringValues(
				`bindmethod=simple binddn="` + ldapBackendTestAdminDN +
					`" credentials="` + ldapBackendTestAdminSecret + `" mode=none`,
			)},
			{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
		},
	}
}

func assertAsyncMetaSearchUnion(t *testing.T, client *ldap.Conn) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestSuffix,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(uid=async-one)(uid=async-two))",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("asyncmeta multi-target Search: %v", err)
	}
	got := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		got = append(got, entry.GetAttributeValue("uid"))
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "async-one" || got[1] != "async-two" {
		t.Fatalf("asyncmeta multi-target Search UIDs = %v", got)
	}
}

func assertAsyncMetaRuntimeConfiguration(
	t *testing.T,
	store storage.Store,
	wantPending int,
) {
	t.Helper()
	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("load asyncmeta runtime: %v", err)
	}
	for index := range databases {
		database := &databases[index]
		if !isAsyncMetaBackendDatabase(*database) {
			continue
		}
		configuration := database.asyncMetaBackend
		if configuration == nil || configuration.meta == nil ||
			database.metaBackend != configuration.meta {
			t.Fatalf("asyncmeta runtime sharing = %#v", configuration)
		}
		if configuration.maxPendingOperations != wantPending ||
			configuration.maxTargetConnections != 4 ||
			configuration.scheduler == nil ||
			len(configuration.scheduler.connections) != 4 ||
			len(configuration.meta.targets) != 2 {
			t.Fatalf("asyncmeta runtime = %#v", configuration)
		}
		for _, target := range configuration.meta.targets {
			for _, remote := range target.ldapBackend.remotes {
				if remote.connectionPoolMax != 1 {
					t.Fatalf("asyncmeta metaconn target pool maximum = %d, want 1", remote.connectionPoolMax)
				}
			}
		}
		return
	}
	t.Fatal("asyncmeta runtime database was not loaded")
}
