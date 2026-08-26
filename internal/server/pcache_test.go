package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type pcacheTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *pcacheTestClock) current() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *pcacheTestClock) advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

func TestLoadPcacheRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	overlay := testPcacheOverlay()
	overlay.ReplaceValues("olcPcacheTemplate", stringValues("(sn=) 0 30 20 10 5"))
	overlay.Attributes = append(overlay.Attributes,
		directory.Attribute{
			Description: "olcPcacheMaxQueries",
			Values:      stringValues("25"),
		},
		directory.Attribute{
			Description: "olcPcacheOffline",
			Values:      stringValues("TRUE"),
		},
		directory.Attribute{
			Description: "olcPcachePersist",
			Values:      stringValues("TRUE"),
		},
		directory.Attribute{
			Description: "olcPcachePosition",
			Values:      stringValues("HEAD"),
		},
		directory.Attribute{
			Description: "olcPcacheValidate",
			Values:      stringValues("TRUE"),
		},
	)
	configuration, err := loadPcacheRuntimeConfiguration(overlay)
	if err != nil {
		t.Fatalf("loadPcacheRuntimeConfiguration(): %v", err)
	}
	if configuration.maxEntries != 100 || configuration.maxQueries != 25 ||
		configuration.entryLimit != 10 || !configuration.offline ||
		!configuration.persist ||
		configuration.position != pcacheResponseHead || !configuration.validate ||
		configuration.consistencyPeriod != time.Second ||
		len(configuration.attributeSets) != 1 ||
		len(configuration.templates) != 1 ||
		configuration.templates[0].ttl != 30*time.Second ||
		configuration.templates[0].negativeTTL != 20*time.Second ||
		configuration.templates[0].limitTTL != 10*time.Second ||
		configuration.templates[0].ttr != 5*time.Second {
		t.Fatalf("pcache configuration = %#v", configuration)
	}

	legacy := testPcacheOverlay()
	legacy.ReplaceValues("olcPcache", nil)
	legacy.ReplaceValues("olcPcacheAttrset", nil)
	legacy.ReplaceValues("olcPcacheTemplate", nil)
	legacy.Attributes = append(legacy.Attributes,
		directory.Attribute{
			Description: "olcProxyCache",
			Values:      stringValues("mdb 100 1 10 1"),
		},
		directory.Attribute{
			Description: "olcProxyAttrset",
			Values:      stringValues("{0}0 uid cn sn"),
		},
		directory.Attribute{
			Description: "olcProxyCacheTemplate",
			Values:      stringValues("{0}(sn=) 0 30 20 10"),
		},
		directory.Attribute{
			Description: "olcProxyCacheQueries",
			Values:      stringValues("12"),
		},
		directory.Attribute{
			Description: "olcProxySaveQueries",
			Values:      stringValues("TRUE"),
		},
		directory.Attribute{
			Description: "olcProxyCheckCacheability",
			Values:      stringValues("TRUE"),
		},
	)
	legacyConfiguration, err := loadPcacheRuntimeConfiguration(legacy)
	if err != nil {
		t.Fatalf("legacy pcache aliases: %v", err)
	}
	if legacyConfiguration.maxQueries != 12 || !legacyConfiguration.persist ||
		!legacyConfiguration.validate {
		t.Fatalf("legacy pcache Phase 2 configuration = %#v", legacyConfiguration)
	}
	defaults, err := loadPcacheRuntimeConfiguration(testPcacheOverlay())
	if err != nil {
		t.Fatalf("default pcache configuration: %v", err)
	}
	if defaults.maxQueries != pcacheDefaultMaxQueries || defaults.offline ||
		defaults.persist || defaults.validate || defaults.position != pcacheResponseTail {
		t.Fatalf("default pcache Phase 2 configuration = %#v", defaults)
	}

	invalid := []struct {
		name      string
		attribute string
		values    []string
		contains  string
	}{
		{"unsupported backend", "olcPcache", []string{"memory 100 1 10 1"}, "unsupported"},
		{"entry limit", "olcPcache", []string{"mdb 10 1 11 1"}, "entry limit"},
		{"missing attrset", "olcPcacheAttrset", nil, "configures 0 pcache attrsets"},
		{"duplicate attrset", "olcPcacheAttrset", []string{"0 uid", "0 cn"}, "duplicate"},
		{"duplicate template", "olcPcacheTemplate", []string{"{0}(sn=) 0 30", "{1}(sn=) 0 60"}, "duplicate"},
		{"invalid TTR", "olcPcacheTemplate", []string{"(sn=) 0 30 20 10 invalid"}, "TTR"},
		{"invalid max queries", "olcPcacheMaxQueries", []string{"0"}, "positive"},
		{"invalid persist", "olcPcachePersist", []string{"sometimes"}, "invalid value"},
		{"invalid validate", "olcPcacheValidate", []string{"sometimes"}, "invalid value"},
		{"invalid position", "olcPcachePosition", []string{"middle"}, "unknown specifier"},
		{"duplicate position", "olcPcachePosition", []string{"head", "tail"}, "single-valued"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			entry := testPcacheOverlay()
			entry.ReplaceValues(test.attribute, stringValues(test.values...))
			_, err := loadPcacheRuntimeConfiguration(entry)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("configuration error = %v, want substring %q", err, test.contains)
			}
		})
	}

	aliases := testPcacheOverlay()
	aliases.Attributes = append(aliases.Attributes,
		directory.Attribute{
			Description: "olcPcacheValidate",
			Values:      stringValues("TRUE"),
		},
		directory.Attribute{
			Description: "olcProxyCheckCacheability",
			Values:      stringValues("TRUE"),
		},
	)
	if _, err := loadPcacheRuntimeConfiguration(aliases); err == nil ||
		!strings.Contains(err.Error(), "both olcPcacheValidate and alias") {
		t.Fatalf("validate alias collision error = %v", err)
	}
}

func TestPcacheTemplateMatchingAndCacheKey(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	configuration, err := loadPcacheRuntimeConfiguration(testPcacheOverlay())
	if err != nil {
		t.Fatalf("loadPcacheRuntimeConfiguration(): %v", err)
	}
	server := &Server{}
	runtime := &runtimeState{schema: registry}
	filter, err := ldapwire.CompileFilter("(sn=Cached)")
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	request := ldapwire.SearchRequest{
		BaseDN:     "OU=People,DC=Example,DC=Com",
		Scope:      directory.ScopeWholeSubtree,
		Filter:     filter,
		Attributes: []string{"uid", "cn"},
	}
	first, ok := server.matchPcacheRequest(runtime, configuration, request)
	if !ok || first.attrset.index != 0 {
		t.Fatalf("matchPcacheRequest() = %#v, %v", first, ok)
	}
	request.BaseDN = "ou=people,dc=example,dc=com"
	second, ok := server.matchPcacheRequest(runtime, configuration, request)
	if !ok || first.key != second.key {
		t.Fatalf("normalized cache keys = %q, %q", first.key, second.key)
	}
	request.Attributes = []string{"mail"}
	if _, ok := server.matchPcacheRequest(runtime, configuration, request); ok {
		t.Fatal("attrset answered an attribute it does not contain")
	}
	for _, selector := range []string{"@person", "@extensibleObject"} {
		request.Attributes = expandObjectClassAttributeSelection(
			runtime.schema,
			[]string{selector},
		)
		if _, ok := server.matchPcacheRequest(runtime, configuration, request); ok {
			t.Errorf("incomplete attrset answered %s", selector)
		}
	}
	other, err := ldapwire.CompileFilter("(cn=Cached)")
	if err != nil {
		t.Fatalf("CompileFilter(other): %v", err)
	}
	request.Filter = other
	request.Attributes = []string{"cn"}
	if _, ok := server.matchPcacheRequest(runtime, configuration, request); ok {
		t.Fatal("sn template matched a cn filter")
	}
}

func TestPcacheStateConcurrentLifecycle(t *testing.T) {
	t.Parallel()

	state := newPcacheState()
	now := state.epoch.Add(100 * time.Millisecond)
	response := pcacheSearchResponse{
		items:  []pcacheSearchItem{{entry: &directory.Entry{DN: "uid=a,dc=example"}}},
		result: ldapwire.Result{Code: ldapwire.ResultSuccess},
	}
	policy := pcacheRefreshPolicy{
		positiveTTL:       time.Second,
		negativeTTL:       time.Second,
		consistencyPeriod: time.Second,
		entryLimit:        10,
	}
	state.commit(
		"key",
		response,
		ldapwire.Message{},
		pcacheRemoteContext{},
		now,
		policy,
		10,
		100,
		false,
	)
	if _, found, _ := state.lookup("key", now.Add(500*time.Millisecond), false); !found {
		t.Fatal("fresh pcache query was not found")
	}

	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				key := fmt.Sprintf("worker-%d", worker)
				state.commit(
					key,
					response,
					ldapwire.Message{},
					pcacheRemoteContext{},
					now,
					policy,
					100,
					100,
					false,
				)
				_, _, _ = state.lookup(
					key,
					now.Add(time.Duration(iteration)*time.Millisecond),
					false,
				)
			}
		}(worker)
	}
	wait.Wait()
	if _, found, _ := state.lookup("key", now.Add(3*time.Second), false); found {
		t.Fatal("expired pcache query remained visible")
	}
}

func TestPcacheStatePhaseTwoLRUAndMaxQueries(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	state := newPcacheStateWithClock(func() time.Time { return now })
	policy := pcacheRefreshPolicy{
		positiveTTL: time.Minute,
		negativeTTL: time.Minute,
		entryLimit:  2,
	}
	commit := func(key string) {
		t.Helper()
		if !state.commit(
			key,
			pcacheStateTestResponse("uid="+key+",dc=example"),
			ldapwire.Message{},
			pcacheRemoteContext{},
			now,
			policy,
			2,
			10,
			false,
		) {
			t.Fatalf("commit(%q) was rejected", key)
		}
	}
	commit("A")
	commit("B")
	if _, found, _ := state.lookup("A", now, false); !found {
		t.Fatal("LRU touch query A was not found")
	}
	commit("C")
	commit("D")
	for _, test := range []struct {
		key  string
		want bool
	}{
		{"A", true},
		{"B", false},
		{"C", true},
		{"D", true},
	} {
		_, found, _ := state.lookup(test.key, now, false)
		if found != test.want {
			t.Fatalf("lookup(%q) found = %v, want %v", test.key, found, test.want)
		}
	}
	state.mu.Lock()
	entries, queries := state.entries, len(state.queries)
	state.mu.Unlock()
	if entries != 3 || queries != 3 {
		t.Fatalf("strict-boundary cache has %d entries/%d queries, want 3/3", entries, queries)
	}

	limited := newPcacheStateWithClock(func() time.Time { return now })
	for _, key := range []string{"A", "B"} {
		if !limited.commit(
			key,
			pcacheStateTestResponse("uid="+key+",dc=example"),
			ldapwire.Message{},
			pcacheRemoteContext{},
			now,
			policy,
			10,
			2,
			false,
		) {
			t.Fatalf("maxQueries commit(%q) was rejected", key)
		}
	}
	if limited.commit(
		"C",
		pcacheStateTestResponse("uid=C,dc=example"),
		ldapwire.Message{},
		pcacheRemoteContext{},
		now,
		policy,
		10,
		2,
		false,
	) {
		t.Fatal("maxQueries accepted a third query")
	}
	for _, key := range []string{"A", "B"} {
		if _, found, _ := limited.lookup(key, now, false); !found {
			t.Fatalf("maxQueries discarded existing query %q", key)
		}
	}
}

func TestPcacheStatePhaseTwoOfflineAndNoRestore(t *testing.T) {
	t.Parallel()

	clock := &pcacheTestClock{now: time.Unix(1_700_000_000, 0)}
	state := newPcacheStateWithClock(clock.current)
	policy := pcacheRefreshPolicy{
		positiveTTL: time.Second,
		negativeTTL: time.Second,
		ttr:         500 * time.Millisecond,
		entryLimit:  1,
	}
	if !state.commit(
		"offline",
		pcacheStateTestResponse("uid=offline,dc=example"),
		ldapwire.Message{},
		pcacheRemoteContext{},
		clock.current(),
		policy,
		10,
		10,
		true,
	) {
		t.Fatal("offline query was not cached")
	}
	clock.advance(time.Hour)
	if _, found, refresh := state.lookup("offline", clock.current(), true); !found || refresh != nil {
		t.Fatalf("offline stale lookup = found %v, refresh %#v", found, refresh)
	}

	fresh := newPcacheStateWithClock(clock.current)
	if _, found, _ := fresh.lookup("offline", clock.current(), false); found {
		t.Fatal("fresh state restored a query despite observed no-restore persist compatibility")
	}
	if _, found, _ := state.lookup("offline", clock.current(), false); found {
		t.Fatal("online lookup retained an expired offline query")
	}
}

func TestPcacheStatePhaseTwoRefreshLeaseAndDeepCopy(t *testing.T) {
	t.Parallel()

	clock := &pcacheTestClock{now: time.Unix(1_700_000_000, 0)}
	state := newPcacheStateWithClock(clock.current)
	filter, err := ldapwire.CompileFilter("(sn=Cached)")
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	replay := ldapwire.Message{
		ID: 17,
		Request: ldapwire.SearchRequest{
			BaseDN:     "dc=example",
			Scope:      directory.ScopeWholeSubtree,
			Filter:     filter,
			Attributes: []string{"uid", "cn", "sn"},
		},
		Controls: []ldapwire.Control{{OID: "1.2.3", HasValue: true, Value: []byte("value")}},
	}
	policy := pcacheRefreshPolicy{
		positiveTTL: time.Minute,
		negativeTTL: time.Minute,
		ttr:         2 * time.Second,
		entryLimit:  10,
	}
	remoteCredentials := []byte("secret")
	if !state.commit(
		"refresh",
		pcacheStateTestResponse("uid=refresh,dc=example"),
		replay,
		pcacheRemoteContext{bindCredentials: remoteCredentials},
		clock.current(),
		policy,
		10,
		10,
		false,
	) {
		t.Fatal("refresh query was not cached")
	}
	request := replay.Request.(ldapwire.SearchRequest)
	request.Attributes[0] = "mail"
	request.Filter.Assertion[0] = 'X'
	replay.Controls[0].Value[0] = 'X'
	remoteCredentials[0] = 'X'

	clock.advance(3 * time.Second)
	_, found, refresh := state.lookup("refresh", clock.current(), false)
	if !found || refresh == nil {
		t.Fatalf("due TTR lookup = found %v, refresh %#v", found, refresh)
	}
	refreshRequest := refresh.replay.Request.(ldapwire.SearchRequest)
	if refreshRequest.Attributes[0] != "uid" || string(refreshRequest.Filter.Assertion) != "Cached" ||
		string(refresh.replay.Controls[0].Value) != "value" ||
		string(refresh.remote.bindCredentials) != "secret" {
		t.Fatalf("replay was not deeply copied: %#v", refresh.replay)
	}
	if _, _, duplicate := state.lookup("refresh", clock.current(), false); duplicate != nil {
		t.Fatal("concurrent lookup acquired a duplicate refresh lease")
	}
	empty := pcacheSearchResponse{result: ldapwire.Result{Code: ldapwire.ResultSuccess}}
	if !state.completeRefresh(*refresh, empty, clock.current()) {
		t.Fatal("refresh completion was rejected")
	}
	response, found, next := state.lookup("refresh", clock.current(), false)
	if !found || response.entryCount() != 0 || next != nil {
		t.Fatalf("refreshed negative query = %#v, found %v, next %#v", response, found, next)
	}
	clock.advance(3 * time.Second)
	_, _, refresh = state.lookup("refresh", clock.current(), false)
	if refresh == nil {
		t.Fatal("negative query did not become refreshable again")
	}
	state.abortRefresh(*refresh, clock.current())
	if _, found, retry := state.lookup("refresh", clock.current(), false); !found || retry != nil {
		t.Fatalf("failed refresh did not retain deterministic stale state: found %v, retry %#v", found, retry)
	}
}

func TestReusePcacheStates(t *testing.T) {
	t.Parallel()

	oldConfiguration, err := loadPcacheRuntimeConfiguration(testPcacheOverlay())
	if err != nil {
		t.Fatalf("old configuration: %v", err)
	}
	newConfiguration, err := loadPcacheRuntimeConfiguration(testPcacheOverlay())
	if err != nil {
		t.Fatalf("new configuration: %v", err)
	}
	previous := &runtimeState{databases: []runtimeDatabase{{pcache: &oldConfiguration}}}
	next := &runtimeState{databases: []runtimeDatabase{{pcache: &newConfiguration}}}
	reusePcacheStates(previous, next)
	if next.databases[0].pcache.state != oldConfiguration.state {
		t.Fatal("equivalent reload did not preserve pcache state")
	}

	changedEntry := testPcacheOverlay()
	changedEntry.ReplaceValues("olcPcacheTemplate", stringValues("(sn=) 0 60 20 10"))
	changed, err := loadPcacheRuntimeConfiguration(changedEntry)
	if err != nil {
		t.Fatalf("changed configuration: %v", err)
	}
	changedRuntime := &runtimeState{databases: []runtimeDatabase{{pcache: &changed}}}
	reusePcacheStates(previous, changedRuntime)
	if changedRuntime.databases[0].pcache.state == oldConfiguration.state {
		t.Fatal("semantic configuration change reused stale pcache state")
	}

	phaseTwoEntry := testPcacheOverlay()
	phaseTwoEntry.Attributes = append(
		phaseTwoEntry.Attributes,
		directory.Attribute{
			Description: "olcPcacheMaxQueries",
			Values:      stringValues("50"),
		},
		directory.Attribute{
			Description: "olcPcachePersist",
			Values:      stringValues("TRUE"),
		},
	)
	phaseTwo, err := loadPcacheRuntimeConfiguration(phaseTwoEntry)
	if err != nil {
		t.Fatalf("Phase 2 configuration: %v", err)
	}
	phaseTwoRuntime := &runtimeState{databases: []runtimeDatabase{{pcache: &phaseTwo}}}
	reusePcacheStates(previous, phaseTwoRuntime)
	if phaseTwoRuntime.databases[0].pcache.state == oldConfiguration.state ||
		phaseTwo.fingerprint == oldConfiguration.fingerprint {
		t.Fatal("Phase 2 lifecycle settings were omitted from the configuration fingerprint")
	}
}

func TestPcacheLDAPBackendIntegration(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
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
		t.Fatalf("add pcache overlay: %v", err)
	}
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := dialLDAPBackendClient(t, proxyAddress)
	defer client.Close()
	if err := client.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("Bind(proxy root): %v", err)
	}
	search := func(typesOnly bool) *ldap.SearchResult {
		result, err := client.Search(ldap.NewSearchRequest(
			ldapBackendTestPeopleDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			typesOnly,
			"(sn=Proxy)",
			[]string{"uid", "cn", "sn"},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(typesOnly=%v): %v", typesOnly, err)
		}
		return result
	}
	if result := search(false); len(result.Entries) != 2 {
		t.Fatalf("cache miss entries = %d, want 2", len(result.Entries))
	}
	stopProvider()
	providerRunning = false
	result := search(true)
	if len(result.Entries) != 2 {
		t.Fatalf("cache hit entries = %d, want 2", len(result.Entries))
	}
	for _, entry := range result.Entries {
		for _, attribute := range entry.Attributes {
			if len(attribute.ByteValues) != 0 {
				t.Fatalf("types-only cache hit returned values: %#v", entry)
			}
		}
	}
}

func testPcacheOverlay() directory.Entry {
	return testPcacheOverlayForDatabase("olcDatabase={1}ldap,cn=config")
}

func testPcacheOverlayForDatabase(databaseDN string) directory.Entry {
	return directory.Entry{
		DN: "olcOverlay={0}pcache," + databaseDN,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("olcOverlayConfig", "olcPcacheConfig"),
			},
			{Description: "olcOverlay", Values: stringValues("{0}pcache")},
			{Description: "olcPcache", Values: stringValues("mdb 100 1 10 1")},
			{Description: "olcPcacheAttrset", Values: stringValues("0 uid cn sn")},
			{
				Description: "olcPcacheTemplate",
				Values:      stringValues("(sn=) 0 30 20 10"),
			},
		},
	}
}

func pcacheStateTestResponse(dn string) pcacheSearchResponse {
	return pcacheSearchResponse{
		items:  []pcacheSearchItem{{entry: &directory.Entry{DN: dn}}},
		result: ldapwire.Result{Code: ldapwire.ResultSuccess},
	}
}
