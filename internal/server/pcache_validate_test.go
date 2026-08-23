package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPcacheValidateResponseCacheability(t *testing.T) {
	t.Parallel()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	filter := pcacheValidateFilter(t, "(sn=Cached)")
	matching := pcacheValidateResponse(directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("alice")},
			{Description: "cn", Values: stringValues("Alice")},
			{Description: "sn", Values: stringValues("Cached")},
		},
	})
	if !pcacheResponseCacheable(registry, filter, matching, true) {
		t.Fatal("matching provider response was not cacheable with validation")
	}

	mismatching := clonePcacheSearchResponse(matching)
	mismatching.items[0].entry.ReplaceValues("sn", stringValues("Changed"))
	if pcacheResponseCacheable(registry, filter, mismatching, true) {
		t.Fatal("mismatching provider response was cacheable with validation")
	}
	if !pcacheResponseCacheable(registry, filter, mismatching, false) {
		t.Fatal("disabled validation re-evaluated the provider response filter")
	}

	malformed := clonePcacheSearchResponse(matching)
	malformed.items[0].entry.Attributes = append(
		malformed.items[0].entry.Attributes,
		directory.Attribute{Description: "description"},
	)
	if pcacheResponseCacheable(registry, filter, malformed, false) {
		t.Fatal("attribute without values was cacheable with validation disabled")
	}

	unknownRule := pcacheValidateFilter(t, "(sn:1.3.6.1.4.1.99999.404:=Cached)")
	if pcacheResponseCacheable(registry, unknownRule, matching, true) {
		t.Fatal("unknown matching rule was cacheable")
	}
}

func TestPcacheValidateDNAttributes(t *testing.T) {
	t.Parallel()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entry := directory.Entry{
		DN: "uid=Alice,ou=People,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "cn", Values: stringValues("Alice")},
			{Description: "sn", Values: stringValues("Cached")},
		},
	}
	response := pcacheValidateResponse(entry)
	if !pcacheResponseCacheable(
		registry,
		pcacheValidateFilter(t, "(uid:dn:caseIgnoreMatch:=alice)"),
		response,
		true,
	) {
		t.Fatal("DN attribute extensible filter did not match the entry DN")
	}
	if pcacheResponseCacheable(
		registry,
		pcacheValidateFilter(t, "(&(uid=alice)(uid:dn:caseIgnoreMatch:=alice))"),
		response,
		true,
	) {
		t.Fatal("DN AVA leaked into a non-dnAttributes filter child")
	}
}

func TestPcacheValidateLookupInvalidatesAtomically(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	state := newPcacheStateWithClock(func() time.Time { return now })
	response := pcacheValidateResponse(directory.Entry{
		DN: "uid=invalid,dc=example",
		Attributes: []directory.Attribute{
			{Description: "sn", Values: stringValues("Changed")},
		},
	})
	if !state.commit(
		"invalid",
		response,
		ldapwire.Message{},
		pcacheRemoteContext{bindCredentials: []byte("secret")},
		now,
		pcacheRefreshPolicy{positiveTTL: time.Minute, entryLimit: 1},
		10,
		10,
		false,
	) {
		t.Fatal("commit invalid fixture failed")
	}

	const workers = 32
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, found, refresh := state.lookupValidated(
				"invalid",
				now,
				false,
				func(pcacheSearchResponse) bool { return false },
			); found || refresh != nil {
				t.Errorf("invalid query remained visible: found=%v refresh=%#v", found, refresh)
			}
		}()
	}
	wait.Wait()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.entries != 0 || len(state.queries) != 0 {
		t.Fatalf("invalidated cache state = %d entries/%d queries", state.entries, len(state.queries))
	}
}

func TestPcacheValidateAndPositionReloadFingerprint(t *testing.T) {
	t.Parallel()
	load := func(validate, position string) pcacheRuntimeConfiguration {
		t.Helper()
		overlay := testPcacheOverlay()
		if validate != "" {
			overlay.Attributes = append(overlay.Attributes, directory.Attribute{
				Description: "olcPcacheValidate",
				Values:      stringValues(validate),
			})
		}
		if position != "" {
			overlay.Attributes = append(overlay.Attributes, directory.Attribute{
				Description: "olcPcachePosition",
				Values:      stringValues(position),
			})
		}
		configuration, err := loadPcacheRuntimeConfiguration(overlay)
		if err != nil {
			t.Fatalf("loadPcacheRuntimeConfiguration(): %v", err)
		}
		return configuration
	}

	previousConfiguration := load("TRUE", "head")
	previous := &runtimeState{databases: []runtimeDatabase{{pcache: &previousConfiguration}}}
	unchangedConfiguration := load("TRUE", "HEAD")
	unchanged := &runtimeState{databases: []runtimeDatabase{{pcache: &unchangedConfiguration}}}
	reusePcacheStates(previous, unchanged)
	if unchangedConfiguration.state != previousConfiguration.state {
		t.Fatal("equivalent validate/position reload discarded cache state")
	}

	for _, test := range []struct {
		name     string
		validate string
		position string
	}{
		{name: "validation changed", validate: "FALSE", position: "head"},
		{name: "position changed", validate: "TRUE", position: "tail"},
	} {
		t.Run(test.name, func(t *testing.T) {
			nextConfiguration := load(test.validate, test.position)
			nextState := nextConfiguration.state
			next := &runtimeState{databases: []runtimeDatabase{{pcache: &nextConfiguration}}}
			reusePcacheStates(previous, next)
			if nextConfiguration.state != nextState || nextConfiguration.state == previousConfiguration.state {
				t.Fatal("semantic pcache reload reused stale cache state")
			}
		})
	}
}

func TestPcachePositionIsEquivalentWithoutAnOverlayCallbackChain(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"head", "tail"} {
		overlay := testPcacheOverlay()
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcPcachePosition",
			Values:      stringValues(raw),
		})
		configuration, err := loadPcacheRuntimeConfiguration(overlay)
		if err != nil {
			t.Fatalf("load position %s: %v", raw, err)
		}
		if configuration.position.String() != raw {
			t.Fatalf("position = %s, want %s", configuration.position, raw)
		}
	}

	// runtime database loading rejects every database-local overlay except
	// pcache on delegated back-ldap databases, and delegated operations run
	// before local Search projections. There is consequently no response
	// callback between pcache and the provider whose output head/tail could
	// reorder in this supported topology.
}

func TestPcacheValidatePositionPinnedOpenLDAPSourceAnchors(t *testing.T) {
	sources := []string{os.Getenv("OPENLDAP_SOURCE")}
	if sources[0] == "" {
		sources = []string{
			"/private/tmp/ldap-go-openldap-source-2.6.13",
			"/private/tmp/ldap-go-openldap-source-2.6.13-full",
		}
	}
	var path string
	for _, source := range sources {
		candidate := filepath.Join(source, "servers", "slapd", "overlays", "pcache.c")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
			break
		}
	}
	if path == "" {
		t.Skip("pinned OpenLDAP pcache.c unavailable")
	}
	assertOpenLDAPPcacheFile(t, path, openLDAPPcacheSourceSHA256, []string{
		"cm->check_cacheability && test_filter( op, rs->sr_entry, si->query.filter ) != LDAP_COMPARE_TRUE",
		`{ "pcachePosition", "head|tail(default)",`,
		`{ "pcacheValidate", "TRUE|FALSE",`,
		"cm->response_cb = PCACHE_RESPONSE_CB_HEAD;",
		"cm->response_cb = PCACHE_RESPONSE_CB_TAIL;",
		"cb->sc_next = op->o_callback;",
		"for ( pcb = &op->o_callback; *pcb; pcb = &(*pcb)->sc_next );",
		`{ "pcache-", "private database args",`,
	})
}

func pcacheValidateFilter(t *testing.T, value string) directory.Filter {
	t.Helper()
	filter, err := ldapwire.CompileFilter(value)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", value, err)
	}
	return filter
}

func pcacheValidateResponse(entry directory.Entry) pcacheSearchResponse {
	return pcacheSearchResponse{
		items:  []pcacheSearchItem{{entry: &entry}},
		result: ldapwire.Result{Code: ldapwire.ResultSuccess},
	}
}

func TestPcacheValidateClearsCredentialMaterialOnInvalidation(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	credentials := []byte("secret")
	state := newPcacheStateWithClock(func() time.Time { return now })
	if !state.commit(
		"credentials",
		pcacheValidateResponse(directory.Entry{
			DN:         "uid=invalid,dc=example",
			Attributes: []directory.Attribute{{Description: "sn", Values: stringValues("Changed")}},
		}),
		ldapwire.Message{},
		pcacheRemoteContext{bindCredentials: credentials},
		now,
		pcacheRefreshPolicy{positiveTTL: time.Minute, entryLimit: 1},
		10,
		10,
		false,
	) {
		t.Fatal("commit credential fixture failed")
	}
	stored := state.queries["credentials"].remote.bindCredentials
	state.lookupValidated(
		"credentials",
		now,
		false,
		func(pcacheSearchResponse) bool { return false },
	)
	if bytes.Count(stored, []byte{0}) != len(stored) {
		t.Fatal("query invalidation retained remote Bind credentials")
	}
}

func TestPcacheValidateProviderChangeInvalidatesRefresh(t *testing.T) {
	provider := startPcacheValidateProvider(t)
	provider.set(
		pcacheValidateProviderEntry("Cached"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
	proxy, client, _, stopProxy := startPcacheValidateProxy(
		t,
		provider.address(),
		"30 20 10 1",
		true,
		"tail",
	)
	defer stopProxy()
	defer client.Close()
	clock := installPcacheValidateClock(t, proxy)

	if got := pcacheValidateSearch(t, client); got != "Cached" {
		t.Fatalf("initial provider result = %q", got)
	}
	clock.advance(2 * time.Second)
	provider.set(
		pcacheValidateProviderEntry("Changed"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
	if got := pcacheValidateSearch(t, client); got != "Changed" {
		t.Fatalf("invalid refresh provider result = %q", got)
	}
	database := pcacheValidateRuntimeDatabase(t, proxy)
	database.pcache.state.mu.Lock()
	queries := len(database.pcache.state.queries)
	database.pcache.state.mu.Unlock()
	if queries != 0 {
		t.Fatalf("invalid refresh retained %d cached queries", queries)
	}

	provider.set(directory.Entry{}, ldapwire.ResultError(
		ldapwire.ResultUnavailable,
		"provider unavailable",
	))
	_, err := client.Search(pcacheValidateSearchRequest())
	if ldapBackendResultCode(err) != ldap.LDAPResultUnavailable {
		t.Fatalf("post-invalidation Search() = %v", err)
	}
}

func TestPcacheValidateProviderErrorRetainsFreshCache(t *testing.T) {
	provider := startPcacheValidateProvider(t)
	provider.set(
		pcacheValidateProviderEntry("Cached"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
	proxy, client, _, stopProxy := startPcacheValidateProxy(
		t,
		provider.address(),
		"30 20 10 1",
		true,
		"head",
	)
	defer stopProxy()
	defer client.Close()
	clock := installPcacheValidateClock(t, proxy)
	if got := pcacheValidateSearch(t, client); got != "Cached" {
		t.Fatalf("initial provider result = %q", got)
	}

	clock.advance(2 * time.Second)
	provider.set(directory.Entry{}, ldapwire.ResultError(
		ldapwire.ResultUnavailable,
		"provider unavailable",
	))
	if got := pcacheValidateSearch(t, client); got != "Cached" {
		t.Fatalf("provider error did not preserve cached result: %q", got)
	}
	database := pcacheValidateRuntimeDatabase(t, proxy)
	database.pcache.state.mu.Lock()
	queries := len(database.pcache.state.queries)
	database.pcache.state.mu.Unlock()
	if queries != 1 {
		t.Fatalf("provider error retained %d queries, want 1", queries)
	}
}

func TestPcacheValidateExpiredResponseIsNotRecached(t *testing.T) {
	provider := startPcacheValidateProvider(t)
	provider.set(
		pcacheValidateProviderEntry("Cached"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
	proxy, client, _, stopProxy := startPcacheValidateProxy(
		t,
		provider.address(),
		"2 2 1",
		true,
		"tail",
	)
	defer stopProxy()
	defer client.Close()
	clock := installPcacheValidateClock(t, proxy)
	if got := pcacheValidateSearch(t, client); got != "Cached" {
		t.Fatalf("initial provider result = %q", got)
	}

	clock.advance(3 * time.Second)
	provider.set(
		pcacheValidateProviderEntry("Changed"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
	if got := pcacheValidateSearch(t, client); got != "Changed" {
		t.Fatalf("expired provider result = %q", got)
	}
	provider.set(directory.Entry{}, ldapwire.ResultError(
		ldapwire.ResultUnavailable,
		"provider unavailable",
	))
	_, err := client.Search(pcacheValidateSearchRequest())
	if ldapBackendResultCode(err) != ldap.LDAPResultUnavailable {
		t.Fatalf("invalid expired response was cached: %v", err)
	}
}

func TestPcacheValidateOnlineReloadInvalidatesState(t *testing.T) {
	provider := startPcacheValidateProvider(t)
	provider.set(
		pcacheValidateProviderEntry("Cached"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
	proxy, client, address, stopProxy := startPcacheValidateProxy(
		t,
		provider.address(),
		"30 20 10",
		true,
		"head",
	)
	defer stopProxy()
	defer client.Close()
	if got := pcacheValidateSearch(t, client); got != "Cached" {
		t.Fatalf("initial provider result = %q", got)
	}
	oldState := pcacheValidateRuntimeDatabase(t, proxy).pcache.state

	configClient := dialLDAPBackendClient(t, address)
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	modify := ldap.NewModifyRequest(
		testPcacheOverlayForDatabase(ldapBackendTestDatabaseDN).DN,
		nil,
	)
	modify.Replace("olcPcacheValidate", []string{"FALSE"})
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("Modify(olcPcacheValidate): %v", err)
	}
	newState := pcacheValidateRuntimeDatabase(t, proxy).pcache.state
	if newState == oldState {
		t.Fatal("validation reload reused the old cache state")
	}

	provider.set(directory.Entry{}, ldapwire.ResultError(
		ldapwire.ResultUnavailable,
		"provider unavailable",
	))
	_, err := client.Search(pcacheValidateSearchRequest())
	if ldapBackendResultCode(err) != ldap.LDAPResultUnavailable {
		t.Fatalf("reload retained old cached response: %v", err)
	}
}

func TestPcachePrivateOperationsRemainExplicitlyRejected(t *testing.T) {
	provider := startPcacheValidateProvider(t)
	provider.set(
		pcacheValidateProviderEntry("Cached"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
	_, client, _, stopProxy := startPcacheValidateProxy(
		t,
		provider.address(),
		"30 20 10",
		true,
		"tail",
	)
	defer stopProxy()
	defer client.Close()

	privateSearch := pcacheValidateSearchRequest()
	privateSearch.Controls = []ldap.Control{
		ldap.NewControlString(pcachePrivateDBControl, true, ""),
	}
	_, err := client.Search(privateSearch)
	if code := ldapBackendResultCode(err); code != ldap.LDAPResultUnavailableCriticalExtension {
		t.Fatalf("private DB control result = %d (%v)", code, err)
	}
	if searches := provider.searches.Load(); searches != 0 {
		t.Fatalf("private DB control reached provider in %d Searches", searches)
	}

	const queryDeleteOID = "1.3.6.1.4.1.4203.666.11.9.6.1"
	_, err = client.Extended(ldap.NewExtendedRequest(queryDeleteOID, nil))
	if code := ldapBackendResultCode(err); code != ldap.LDAPResultProtocolError {
		t.Fatalf("query-delete result = %d (%v)", code, err)
	}
}

type pcacheValidateProvider struct {
	listener    net.Listener
	mu          sync.RWMutex
	entry       directory.Entry
	result      ldapwire.Result
	connections map[net.Conn]struct{}
	searches    atomic.Int64
	done        chan struct{}
	wait        sync.WaitGroup
}

func startPcacheValidateProvider(t *testing.T) *pcacheValidateProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(provider): %v", err)
	}
	provider := &pcacheValidateProvider{
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
		done:        make(chan struct{}),
	}
	provider.wait.Add(1)
	go provider.serve()
	t.Cleanup(provider.close)
	return provider
}

func (provider *pcacheValidateProvider) address() string {
	return provider.listener.Addr().String()
}

func (provider *pcacheValidateProvider) set(
	entry directory.Entry,
	result ldapwire.Result,
) {
	provider.mu.Lock()
	provider.entry = entry.Clone()
	provider.result = result
	provider.mu.Unlock()
}

func (provider *pcacheValidateProvider) serve() {
	defer provider.wait.Done()
	defer close(provider.done)
	for {
		connection, err := provider.listener.Accept()
		if err != nil {
			return
		}
		provider.mu.Lock()
		provider.connections[connection] = struct{}{}
		provider.mu.Unlock()
		provider.wait.Add(1)
		go provider.handle(connection)
	}
}

func (provider *pcacheValidateProvider) handle(connection net.Conn) {
	defer provider.wait.Done()
	defer func() {
		provider.mu.Lock()
		delete(provider.connections, connection)
		provider.mu.Unlock()
		_ = connection.Close()
	}()
	for {
		message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			return
		}
		switch message.Request.(type) {
		case ldapwire.BindRequest:
			err = ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			))
		case ldapwire.SearchRequest:
			provider.searches.Add(1)
			provider.mu.RLock()
			entry := provider.entry.Clone()
			result := provider.result
			provider.mu.RUnlock()
			if result.Code == ldapwire.ResultSuccess && entry.DN != "" {
				err = ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
					message.ID,
					entry,
					nil,
				))
			}
			if err == nil {
				err = ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
					message.ID,
					result,
					nil,
				))
			}
		case ldapwire.UnbindRequest:
			return
		default:
			err = fmt.Errorf("unsupported provider request %T", message.Request)
		}
		if err != nil {
			return
		}
	}
}

func (provider *pcacheValidateProvider) close() {
	if provider == nil {
		return
	}
	_ = provider.listener.Close()
	<-provider.done
	provider.mu.Lock()
	for connection := range provider.connections {
		_ = connection.Close()
	}
	provider.mu.Unlock()
	provider.wait.Wait()
}

func startPcacheValidateProxy(
	t *testing.T,
	providerAddress,
	templateTimes string,
	validate bool,
	position string,
) (*Server, *ldap.Conn, string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPBackendProxy(t, store, providerAddress)
	overlay := testPcacheOverlayForDatabase(ldapBackendTestDatabaseDN)
	overlay.ReplaceValues(
		"olcPcacheTemplate",
		stringValues("(sn=) 0 "+templateTimes),
	)
	overlay.Attributes = append(overlay.Attributes,
		directory.Attribute{
			Description: "olcPcacheValidate",
			Values:      stringValues(fmt.Sprintf("%t", validate)),
		},
		directory.Attribute{
			Description: "olcPcachePosition",
			Values:      stringValues(position),
		},
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(overlay, false)
	}); err != nil {
		t.Fatalf("store pcache overlay: %v", err)
	}
	proxy, address, stop := startPcacheBindWireServer(t, store)
	client := dialLDAPBackendClient(t, address)
	if err := client.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		client.Close()
		stop()
		t.Fatalf("Bind(proxy root): %v", err)
	}
	return proxy, client, address, stop
}

func installPcacheValidateClock(t *testing.T, server *Server) *pcacheTestClock {
	t.Helper()
	database := pcacheValidateRuntimeDatabase(t, server)
	clock := &pcacheTestClock{now: database.pcache.state.epoch}
	database.pcache.state.clock = clock.current
	return clock
}

func pcacheValidateRuntimeDatabase(t *testing.T, server *Server) *runtimeDatabase {
	t.Helper()
	runtime := server.runtime.Load()
	if runtime == nil || runtime.schema == nil {
		t.Fatal("pcache runtime is unavailable")
	}
	dn, err := runtime.schema.NormalizeDN(ldapBackendTestUserDN)
	if err != nil {
		t.Fatalf("NormalizeDN(): %v", err)
	}
	database := databaseForDN(runtime, dn)
	if database == nil || database.pcache == nil {
		t.Fatal("pcache runtime database is unavailable")
	}
	return database
}

func pcacheValidateProviderEntry(sn string) directory.Entry {
	return directory.Entry{
		DN: ldapBackendTestUserDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("alice")},
			{Description: "cn", Values: stringValues("Alice")},
			{Description: "sn", Values: stringValues(sn)},
		},
	}
}

func pcacheValidateSearchRequest() *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(sn=Cached)",
		[]string{"uid", "cn", "sn"},
		nil,
	)
}

func pcacheValidateSearch(t *testing.T, client *ldap.Conn) string {
	t.Helper()
	result, err := client.Search(pcacheValidateSearchRequest())
	if err != nil {
		t.Fatalf("Search(): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search() entries = %d, want 1", len(result.Entries))
	}
	return result.Entries[0].GetAttributeValue("sn")
}
