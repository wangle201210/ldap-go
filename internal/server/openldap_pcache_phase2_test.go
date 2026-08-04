package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type pcachePhaseTwoProxyConfig struct {
	maxEntries       int
	entryLimit       int
	consistencyCheck int
	ttl              string
	negativeTTL      string
	limitTTL         string
	ttr              string
	maxQueries       int
	offline          bool
	persist          bool
	cacheDirectory   string
}

type pcachePhaseTwoProxyFactory func(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	config pcachePhaseTwoProxyConfig,
) (string, func(), error)

type pcachePhaseTwoTTRResult struct {
	startupError string
	initial      pcachePhaseOneSearch
	referenced   pcachePhaseOneSearch
	refreshed    pcachePhaseOneSearch
}

type pcachePhaseTwoOfflineResult struct {
	startupError string
	initial      pcachePhaseOneSearch
	offlineStale pcachePhaseOneSearch
	onlineReload pcachePhaseOneSearch
	onlineFinal  pcachePhaseOneSearch
}

type pcachePhaseTwoLRUResult struct {
	startupError string
	a            pcachePhaseOneSearch
	b            pcachePhaseOneSearch
	c            pcachePhaseOneSearch
	d            pcachePhaseOneSearch
}

type pcachePhaseTwoWritesResult struct {
	startupError  string
	modifiedStale pcachePhaseOneSearch
	addedStale    pcachePhaseOneSearch
	deletedStale  pcachePhaseOneSearch
	modifiedFinal pcachePhaseOneSearch
	addedFinal    pcachePhaseOneSearch
	deletedFinal  pcachePhaseOneSearch
}

type pcachePhaseTwoOutcome struct {
	ttr        pcachePhaseTwoTTRResult
	offline    pcachePhaseTwoOfflineResult
	maxEntries pcachePhaseTwoLRUResult
	maxQueries pcachePhaseTwoLRUResult
	writes     pcachePhaseTwoWritesResult
}

func TestOpenLDAPReferencePcachePhaseTwo(t *testing.T) {
	tools := requireOpenLDAPPcacheReferenceTools(t)
	assertPinnedOpenLDAPPcacheReference(t, tools)
	assertOpenLDAPPcachePhaseTwoAnchors(t)

	var reference pcachePhaseTwoOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		t.Run("TTR positive refresh to negative", func(t *testing.T) {
			reference.ttr = observePcachePhaseTwoTTR(t, tools, startOpenLDAPPcachePhaseTwoProxy)
			assertPcachePhaseTwoTTR(t, reference.ttr)
		})
		t.Run("offline pauses expiry and online resumes it", func(t *testing.T) {
			reference.offline = observePcachePhaseTwoOffline(t, tools, startOpenLDAPPcachePhaseTwoProxy)
			assertPcachePhaseTwoOffline(t, reference.offline)
		})
		t.Run("max entries strict boundary and LRU", func(t *testing.T) {
			reference.maxEntries = observePcachePhaseTwoLRU(t, tools, startOpenLDAPPcachePhaseTwoProxy, 2, 10)
			assertPcachePhaseTwoMaxEntriesLRU(t, reference.maxEntries)
		})
		t.Run("pcacheMaxQueries boundary keeps existing queries", func(t *testing.T) {
			reference.maxQueries = observePcachePhaseTwoLRU(t, tools, startOpenLDAPPcachePhaseTwoProxy, 10, 2)
			assertPcachePhaseTwoMaxQueries(t, reference.maxQueries)
		})
		t.Run("proxy writes remain stale until TTL", func(t *testing.T) {
			reference.writes = observePcachePhaseTwoWrites(t, tools, startOpenLDAPPcachePhaseTwoProxy)
			assertPcachePhaseTwoWrites(t, reference.writes)
		})
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		got := observePcachePhaseTwo(t, tools, startLDAPGoPcachePhaseTwoProxy)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go pcache Phase 2 is not implemented or differs from OpenLDAP 2.6.13:\n%s",
				firstPcachePhaseTwoDifference(reference, got),
			)
		}
	})
}

func assertOpenLDAPPcachePhaseTwoAnchors(t *testing.T) {
	t.Helper()
	source := os.Getenv("OPENLDAP_SOURCE")
	assertOpenLDAPPcacheFile(
		t,
		filepath.Join(source, "servers", "slapd", "overlays", "pcache.c"),
		openLDAPPcacheSourceSHA256,
		[]string{
			"if ( query->refresh_time && query->refresh_time < op->o_time )",
			"refresh_query( op, query, on, templ );",
			"/* Don't expire anything when we're offline */",
			"if (cm->num_cached_queries >= cm->max_queries)",
			"while ( cm->cur_entries > (cm->max_entries) )",
		},
	)
}

func observePcachePhaseTwo(
	t *testing.T,
	tools openLDAPReferenceTools,
	startProxy pcachePhaseTwoProxyFactory,
) pcachePhaseTwoOutcome {
	t.Helper()
	return pcachePhaseTwoOutcome{
		ttr:        observePcachePhaseTwoTTR(t, tools, startProxy),
		offline:    observePcachePhaseTwoOffline(t, tools, startProxy),
		maxEntries: observePcachePhaseTwoLRU(t, tools, startProxy, 2, 10),
		maxQueries: observePcachePhaseTwoLRU(t, tools, startProxy, 10, 2),
		writes:     observePcachePhaseTwoWrites(t, tools, startProxy),
	}
}

func observePcachePhaseTwoTTR(
	t *testing.T,
	tools openLDAPReferenceTools,
	startProxy pcachePhaseTwoProxyFactory,
) pcachePhaseTwoTTRResult {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPReferenceServer(t, tools, nil)
	provider := bindOverlayReferenceClient(t, providerURI, "secret")
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{{
		uid: "refresh", cn: "Refresh Me", sn: "Refresh",
	}})
	proxyURI, stopProxy, err := startProxy(t, tools, providerURI, pcachePhaseTwoProxyConfig{
		maxEntries: 10, entryLimit: 10, consistencyCheck: 1,
		ttl: "20", negativeTTL: "20", limitTTL: "20", ttr: "2",
		maxQueries: 10,
	})
	if err != nil {
		provider.Close()
		stopProvider()
		return pcachePhaseTwoTTRResult{startupError: err.Error()}
	}
	defer stopProxy()
	defer stopProvider()
	defer provider.Close()

	proxy := bindPcachePhaseOneClient(t, proxyURI)
	defer proxy.Close()
	result := pcachePhaseTwoTTRResult{}
	result.initial = searchPcachePhaseOne(t, proxy, "(sn=Refresh)", false, nil)
	result.referenced = searchPcachePhaseOne(t, proxy, "(sn=Refresh)", false, nil)
	if err := provider.Del(ldap.NewDelRequest("uid=refresh,"+pcachePhaseOneBaseDN, nil)); err != nil {
		t.Fatalf("delete TTR provider entry: %v", err)
	}
	result.refreshed = waitForPcachePhaseTwoSearch(t, proxy, "(sn=Refresh)", 12*time.Second, func(search pcachePhaseOneSearch) bool {
		return search.code == ldap.LDAPResultSuccess && search.transportErr == "" && len(search.entries) == 0
	})
	return result
}

func observePcachePhaseTwoOffline(
	t *testing.T,
	tools openLDAPReferenceTools,
	startProxy pcachePhaseTwoProxyFactory,
) pcachePhaseTwoOfflineResult {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPReferenceServer(t, tools, nil)
	provider := bindOverlayReferenceClient(t, providerURI, "secret")
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{{
		uid: "offline", cn: "Offline Entry", sn: "Offline",
	}})
	cacheDirectory := filepath.Join(t.TempDir(), "persistent-cache")
	proxyURI, stopProxy, err := startProxy(t, tools, providerURI, pcachePhaseTwoProxyConfig{
		maxEntries: 10, entryLimit: 10, consistencyCheck: 2,
		ttl: "2", negativeTTL: "2", limitTTL: "2",
		maxQueries: 10, offline: true, persist: true,
		cacheDirectory: cacheDirectory,
	})
	if err != nil {
		provider.Close()
		stopProvider()
		return pcachePhaseTwoOfflineResult{startupError: err.Error()}
	}
	proxy := bindPcachePhaseOneClient(t, proxyURI)
	result := pcachePhaseTwoOfflineResult{}
	result.initial = searchPcachePhaseOne(t, proxy, "(sn=Offline)", false, nil)
	provider.Close()
	stopProvider()
	time.Sleep(4 * time.Second)
	result.offlineStale = searchPcachePhaseOne(t, proxy, "(sn=Offline)", false, nil)
	proxy.Close()
	stopProxy()

	proxyURI, stopOnlineProxy, err := startProxy(t, tools, providerURI, pcachePhaseTwoProxyConfig{
		maxEntries: 10, entryLimit: 10, consistencyCheck: 2,
		ttl: "2", negativeTTL: "2", limitTTL: "2",
		maxQueries: 10, persist: true,
		cacheDirectory: cacheDirectory,
	})
	if err != nil {
		return pcachePhaseTwoOfflineResult{startupError: "restart online: " + err.Error()}
	}
	defer stopOnlineProxy()
	proxy = bindPcachePhaseOneClient(t, proxyURI)
	defer proxy.Close()
	result.onlineReload = searchPcachePhaseOne(t, proxy, "(sn=Offline)", false, nil)
	result.onlineFinal = waitForPcachePhaseTwoSearch(t, proxy, "(sn=Offline)", 12*time.Second, func(search pcachePhaseOneSearch) bool {
		return search.code == ldap.LDAPResultUnavailable && search.transportErr == ""
	})
	return result
}

func observePcachePhaseTwoLRU(
	t *testing.T,
	tools openLDAPReferenceTools,
	startProxy pcachePhaseTwoProxyFactory,
	maxEntries,
	maxQueries int,
) pcachePhaseTwoLRUResult {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPReferenceServer(t, tools, nil)
	provider := bindOverlayReferenceClient(t, providerURI, "secret")
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{
		{uid: "lru-a", cn: "LRU A", sn: "LRUA"},
		{uid: "lru-b", cn: "LRU B", sn: "LRUB"},
		{uid: "lru-c", cn: "LRU C", sn: "LRUC"},
		{uid: "lru-d", cn: "LRU D", sn: "LRUD"},
	})
	proxyURI, stopProxy, err := startProxy(t, tools, providerURI, pcachePhaseTwoProxyConfig{
		maxEntries: maxEntries, entryLimit: 2, consistencyCheck: 1,
		ttl: "30", negativeTTL: "30", limitTTL: "30",
		maxQueries: maxQueries,
	})
	if err != nil {
		provider.Close()
		stopProvider()
		return pcachePhaseTwoLRUResult{startupError: err.Error()}
	}
	defer stopProxy()

	proxy := bindPcachePhaseOneClient(t, proxyURI)
	defer proxy.Close()
	searchPcachePhaseOne(t, proxy, "(sn=LRUA)", false, nil)
	searchPcachePhaseOne(t, proxy, "(sn=LRUB)", false, nil)
	searchPcachePhaseOne(t, proxy, "(sn=LRUA)", false, nil)
	searchPcachePhaseOne(t, proxy, "(sn=LRUC)", false, nil)
	searchPcachePhaseOne(t, proxy, "(sn=LRUD)", false, nil)
	provider.Close()
	stopProvider()
	return pcachePhaseTwoLRUResult{
		a: searchPcachePhaseOne(t, proxy, "(sn=LRUA)", false, nil),
		b: searchPcachePhaseOne(t, proxy, "(sn=LRUB)", false, nil),
		c: searchPcachePhaseOne(t, proxy, "(sn=LRUC)", false, nil),
		d: searchPcachePhaseOne(t, proxy, "(sn=LRUD)", false, nil),
	}
}

func observePcachePhaseTwoWrites(
	t *testing.T,
	tools openLDAPReferenceTools,
	startProxy pcachePhaseTwoProxyFactory,
) pcachePhaseTwoWritesResult {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPReferenceServer(t, tools, nil)
	provider := bindOverlayReferenceClient(t, providerURI, "secret")
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{
		{uid: "modified", cn: "Before Modify", sn: "Modified"},
		{uid: "deleted", cn: "Before Delete", sn: "Deleted"},
	})
	proxyURI, stopProxy, err := startProxy(t, tools, providerURI, pcachePhaseTwoProxyConfig{
		maxEntries: 20, entryLimit: 10, consistencyCheck: 1,
		ttl: "3", negativeTTL: "3", limitTTL: "3",
		maxQueries: 20,
	})
	if err != nil {
		provider.Close()
		stopProvider()
		return pcachePhaseTwoWritesResult{startupError: err.Error()}
	}
	defer stopProxy()
	defer stopProvider()
	defer provider.Close()

	proxy := bindPcachePhaseOneClient(t, proxyURI)
	defer proxy.Close()
	searchPcachePhaseOne(t, proxy, "(sn=Modified)", false, nil)
	searchPcachePhaseOne(t, proxy, "(sn=Added)", false, nil)
	searchPcachePhaseOne(t, proxy, "(sn=Deleted)", false, nil)

	modify := ldap.NewModifyRequest("uid=modified,"+pcachePhaseOneBaseDN, nil)
	modify.Replace("cn", []string{"After Modify"})
	if err := proxy.Modify(modify); err != nil {
		t.Fatalf("modify provider through pcache proxy: %v", err)
	}
	add := ldap.NewAddRequest("uid=added,"+pcachePhaseOneBaseDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"added"})
	add.Attribute("cn", []string{"After Add"})
	add.Attribute("sn", []string{"Added"})
	if err := proxy.Add(add); err != nil {
		t.Fatalf("add provider entry through pcache proxy: %v", err)
	}
	if err := proxy.Del(ldap.NewDelRequest("uid=deleted,"+pcachePhaseOneBaseDN, nil)); err != nil {
		t.Fatalf("delete provider entry through pcache proxy: %v", err)
	}

	result := pcachePhaseTwoWritesResult{
		modifiedStale: searchPcachePhaseOne(t, proxy, "(sn=Modified)", false, nil),
		addedStale:    searchPcachePhaseOne(t, proxy, "(sn=Added)", false, nil),
		deletedStale:  searchPcachePhaseOne(t, proxy, "(sn=Deleted)", false, nil),
	}
	deadline := time.Now().Add(14 * time.Second)
	for {
		result.modifiedFinal = searchPcachePhaseOne(t, proxy, "(sn=Modified)", false, nil)
		result.addedFinal = searchPcachePhaseOne(t, proxy, "(sn=Added)", false, nil)
		result.deletedFinal = searchPcachePhaseOne(t, proxy, "(sn=Deleted)", false, nil)
		if pcachePhaseTwoSearchHasCN(result.modifiedFinal, "After Modify") &&
			pcachePhaseTwoSearchHasCN(result.addedFinal, "After Add") &&
			result.deletedFinal.code == ldap.LDAPResultSuccess &&
			len(result.deletedFinal.entries) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pcache stale write results did not expire before %s: %#v", deadline, result)
		}
		time.Sleep(150 * time.Millisecond)
	}
	return result
}

func waitForPcachePhaseTwoSearch(
	t *testing.T,
	client *ldap.Conn,
	filter string,
	timeout time.Duration,
	done func(pcachePhaseOneSearch) bool,
) pcachePhaseOneSearch {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last pcachePhaseOneSearch
	for {
		last = searchPcachePhaseOne(t, client, filter, false, nil)
		if done(last) {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("pcache condition for %s did not converge before %s; last=%#v", filter, deadline, last)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func assertPcachePhaseTwoTTR(t *testing.T, got pcachePhaseTwoTTRResult) {
	t.Helper()
	if got.startupError != "" {
		t.Fatal(got.startupError)
	}
	wantEntry := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "refresh", cn: "Refresh Me", sn: "Refresh"}}, false)
	wantEmpty := pcachePhaseOneSearch{code: ldap.LDAPResultSuccess}
	if !reflect.DeepEqual(got.initial, wantEntry) || !reflect.DeepEqual(got.referenced, wantEntry) || !reflect.DeepEqual(got.refreshed, wantEmpty) {
		t.Fatalf("OpenLDAP TTR behavior drifted: got=%#v", got)
	}
}

func assertPcachePhaseTwoOffline(t *testing.T, got pcachePhaseTwoOfflineResult) {
	t.Helper()
	if got.startupError != "" {
		t.Fatal(got.startupError)
	}
	wantEntry := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "offline", cn: "Offline Entry", sn: "Offline"}}, false)
	wantUnavailable := pcachePhaseOneSearch{code: ldap.LDAPResultUnavailable}
	if !reflect.DeepEqual(got.initial, wantEntry) ||
		!reflect.DeepEqual(got.offlineStale, wantEntry) ||
		!reflect.DeepEqual(got.onlineReload, wantUnavailable) ||
		!reflect.DeepEqual(got.onlineFinal, wantUnavailable) {
		t.Fatalf("OpenLDAP offline behavior drifted: got=%#v", got)
	}
}

func assertPcachePhaseTwoMaxEntriesLRU(t *testing.T, got pcachePhaseTwoLRUResult) {
	t.Helper()
	if got.startupError != "" {
		t.Fatal(got.startupError)
	}
	wantA := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "lru-a", cn: "LRU A", sn: "LRUA"}}, false)
	wantB := pcachePhaseOneSearch{code: ldap.LDAPResultUnavailable}
	wantC := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "lru-c", cn: "LRU C", sn: "LRUC"}}, false)
	wantD := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "lru-d", cn: "LRU D", sn: "LRUD"}}, false)
	if !reflect.DeepEqual(got.a, wantA) || !reflect.DeepEqual(got.b, wantB) || !reflect.DeepEqual(got.c, wantC) || !reflect.DeepEqual(got.d, wantD) {
		t.Fatalf("OpenLDAP pcache max entries LRU behavior drifted: got=%#v", got)
	}
}

func assertPcachePhaseTwoMaxQueries(t *testing.T, got pcachePhaseTwoLRUResult) {
	t.Helper()
	if got.startupError != "" {
		t.Fatal(got.startupError)
	}
	wantA := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "lru-a", cn: "LRU A", sn: "LRUA"}}, false)
	wantB := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "lru-b", cn: "LRU B", sn: "LRUB"}}, false)
	wantUnavailable := pcachePhaseOneSearch{code: ldap.LDAPResultUnavailable}
	if !reflect.DeepEqual(got.a, wantA) || !reflect.DeepEqual(got.b, wantB) || !reflect.DeepEqual(got.c, wantUnavailable) || !reflect.DeepEqual(got.d, wantUnavailable) {
		t.Fatalf("OpenLDAP pcache max queries boundary behavior drifted: got=%#v", got)
	}
}

func assertPcachePhaseTwoWrites(t *testing.T, got pcachePhaseTwoWritesResult) {
	t.Helper()
	if got.startupError != "" {
		t.Fatal(got.startupError)
	}
	wantModifiedStale := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "modified", cn: "Before Modify", sn: "Modified"}}, false)
	wantDeletedStale := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "deleted", cn: "Before Delete", sn: "Deleted"}}, false)
	wantEmpty := pcachePhaseOneSearch{code: ldap.LDAPResultSuccess}
	wantModifiedFinal := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "modified", cn: "After Modify", sn: "Modified"}}, false)
	wantAddedFinal := expectedPcachePhaseOneSearch([]pcachePhaseOnePerson{{uid: "added", cn: "After Add", sn: "Added"}}, false)
	if !reflect.DeepEqual(got.modifiedStale, wantModifiedStale) ||
		!reflect.DeepEqual(got.addedStale, wantEmpty) ||
		!reflect.DeepEqual(got.deletedStale, wantDeletedStale) ||
		!reflect.DeepEqual(got.modifiedFinal, wantModifiedFinal) ||
		!reflect.DeepEqual(got.addedFinal, wantAddedFinal) ||
		!reflect.DeepEqual(got.deletedFinal, wantEmpty) {
		t.Fatalf("OpenLDAP stale write behavior drifted: got=%#v", got)
	}
}

func pcachePhaseTwoSearchHasCN(search pcachePhaseOneSearch, want string) bool {
	if search.code != ldap.LDAPResultSuccess || search.transportErr != "" || len(search.entries) != 1 {
		return false
	}
	for _, attribute := range search.entries[0].attributes {
		if attribute.name == "cn" && len(attribute.values) == 1 && attribute.values[0] == want {
			return true
		}
	}
	return false
}

func firstPcachePhaseTwoDifference(want, got pcachePhaseTwoOutcome) string {
	comparisons := []struct {
		name      string
		want, got any
	}{
		{"TTR", want.ttr, got.ttr},
		{"offline", want.offline, got.offline},
		{"max entries LRU", want.maxEntries, got.maxEntries},
		{"max queries boundary", want.maxQueries, got.maxQueries},
		{"stale writes", want.writes, got.writes},
	}
	for _, comparison := range comparisons {
		if !reflect.DeepEqual(comparison.want, comparison.got) {
			return fmt.Sprintf("%s:\nOpenLDAP: %#v\nldap-go:  %#v", comparison.name, comparison.want, comparison.got)
		}
	}
	return "outcomes differ in an unclassified field"
}

func startOpenLDAPPcachePhaseTwoProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	config pcachePhaseTwoProxyConfig,
) (string, func(), error) {
	t.Helper()
	root := t.TempDir()
	cacheDirectory := config.cacheDirectory
	if cacheDirectory == "" {
		cacheDirectory = filepath.Join(root, "cache")
	}
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		return "", nil, fmt.Errorf("create pcache Phase 2 MDB directory: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("reserve pcache Phase 2 proxy port: %w", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", nil, fmt.Errorf("release pcache Phase 2 proxy port: %w", err)
	}
	uri := "ldap://" + address
	var options strings.Builder
	if config.maxQueries > 0 {
		fmt.Fprintf(&options, "pcacheMaxQueries %d\n", config.maxQueries)
	}
	if config.offline {
		options.WriteString("pcacheOffline TRUE\n")
	}
	if config.persist {
		options.WriteString("pcachePersist TRUE\n")
	}
	configuration := fmt.Sprintf(
		`include %s
include %s
include %s
pidfile %s
argsfile %s

database config
rootdn "cn=config"
rootpw config-secret

database ldap
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
uri %s
network-timeout 1
chase-referrals FALSE
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"

overlay pcache
pcache mdb %d 1 %d %d
pcacheAttrset 0 uid cn sn
pcacheTemplate (sn=) 0 %s %s %s %s
%sdirectory %s
dbnosync
index objectClass,sn,pcacheQueryid eq
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		providerURI,
		config.maxEntries,
		config.entryLimit,
		config.consistencyCheck,
		config.ttl,
		config.negativeTTL,
		config.limitTTL,
		config.ttr,
		options.String(),
		cacheDirectory,
	)
	configPath := filepath.Join(root, "slapd.conf")
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		return "", nil, fmt.Errorf("write pcache Phase 2 configuration: %w", err)
	}
	check := exec.Command(tools.slapd, "-Ttest", "-u", "-f", configPath)
	if output, err := check.CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("validate pcache Phase 2 configuration: %w\n%s\nconfiguration:\n%s", err, output, configuration)
	}

	var logs bytes.Buffer
	debugLevel := os.Getenv(openLDAPSlapdDebugEnv)
	if debugLevel == "" {
		debugLevel = "0"
	}
	command := exec.Command(tools.slapd, "-f", configPath, "-h", uri, "-d", debugLevel)
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		return "", nil, fmt.Errorf("start OpenLDAP pcache Phase 2 proxy: %w", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if command.Process != nil {
				_ = command.Process.Signal(os.Interrupt)
			}
			select {
			case <-waitDone:
			case <-time.After(5 * time.Second):
				if command.Process != nil {
					_ = command.Process.Kill()
				}
				<-waitDone
			}
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case waitErr := <-waitDone:
			return "", nil, fmt.Errorf("OpenLDAP pcache Phase 2 proxy exited during startup: %v\n%s", waitErr, openLDAPReferenceLogTail(logs.Bytes()))
		default:
		}
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			stop()
			return "", nil, fmt.Errorf("OpenLDAP pcache Phase 2 proxy did not start: %v\n%s", dialErr, openLDAPReferenceLogTail(logs.Bytes()))
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Cleanup(stop)
	return uri, stop, nil
}

func startLDAPGoPcachePhaseTwoProxy(
	t *testing.T,
	_ openLDAPReferenceTools,
	providerURI string,
	config pcachePhaseTwoProxyConfig,
) (string, func(), error) {
	t.Helper()
	store := storage.NewMemory()
	if err := seedLDAPGoPcachePhaseTwoConfiguration(store, providerURI, config); err != nil {
		_ = store.Close()
		return "", nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = store.Close()
		return "", nil, err
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		_ = store.Close()
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("ldap-go pcache Phase 2 proxy did not stop")
			}
			_ = store.Close()
		})
	}
	t.Cleanup(stop)
	return "ldap://" + listener.Addr().String(), stop, nil
}

func seedLDAPGoPcachePhaseTwoConfiguration(
	store storage.Store,
	providerURI string,
	config pcachePhaseTwoProxyConfig,
) error {
	databaseDN := "olcDatabase={1}ldap,cn=config"
	template := fmt.Sprintf("(sn=) 0 %s %s %s", config.ttl, config.negativeTTL, config.limitTTL)
	if config.ttr != "" {
		template += " " + config.ttr
	}
	overlayAttributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcPcacheConfig")},
		{Description: "olcOverlay", Values: stringValues("{0}pcache")},
		{Description: "olcPcache", Values: stringValues(fmt.Sprintf("mdb %d 1 %d %d", config.maxEntries, config.entryLimit, config.consistencyCheck))},
		{Description: "olcPcacheAttrset", Values: stringValues("0 uid cn sn")},
		{Description: "olcPcacheTemplate", Values: stringValues(template)},
	}
	if config.maxQueries > 0 {
		overlayAttributes = append(overlayAttributes, directory.Attribute{Description: "olcPcacheMaxQueries", Values: stringValues(fmt.Sprint(config.maxQueries))})
	}
	if config.offline {
		overlayAttributes = append(overlayAttributes, directory.Attribute{Description: "olcPcacheOffline", Values: stringValues("TRUE")})
	}
	if config.persist {
		overlayAttributes = append(overlayAttributes, directory.Attribute{Description: "olcPcachePersist", Values: stringValues("TRUE")})
	}
	entries := []directory.Entry{
		{DN: "cn=config", Attributes: []directory.Attribute{{Description: "objectClass", Values: stringValues("olcGlobal")}, {Description: "cn", Values: stringValues("config")}}},
		{DN: "olcDatabase={0}config,cn=config", Attributes: []directory.Attribute{{Description: "objectClass", Values: stringValues("olcDatabaseConfig")}, {Description: "olcDatabase", Values: stringValues("{0}config")}, {Description: "olcRootDN", Values: stringValues("cn=config")}, {Description: "olcRootPW", Values: stringValues("config-secret")}}},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}ldap")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=example,dc=com")},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcDbURI", Values: stringValues(providerURI)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbChaseReferrals", Values: stringValues("FALSE")},
				{
					Description: "olcDbIDAssertBind",
					Values: stringValues(
						`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials="secret" mode=none`,
					),
				},
				{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
			},
		},
		{DN: "olcOverlay={0}pcache," + databaseDN, Attributes: overlayAttributes},
	}
	return store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	})
}
