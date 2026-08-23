package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadPcacheBindRuntimeConfiguration(t *testing.T) {
	t.Parallel()
	overlay := testPcacheOverlay()
	overlay.Attributes = append(overlay.Attributes, directory.Attribute{
		Description: "olcPcacheBind",
		Values: stringValues(
			`{0}(sn=) 0 5 sub "ou=people,dc=example,dc=com"`,
		),
	})
	configuration, err := loadPcacheRuntimeConfiguration(overlay)
	if err != nil {
		t.Fatalf("loadPcacheRuntimeConfiguration(): %v", err)
	}
	if len(configuration.binds) != 1 {
		t.Fatalf("Bind configurations = %#v", configuration.binds)
	}
	bind := configuration.binds[0]
	if bind.attrset != 0 || bind.ttl != 5*time.Second ||
		bind.scope != directory.ScopeWholeSubtree ||
		bind.baseDN != "ou=people,dc=example,dc=com" {
		t.Fatalf("Bind configuration = %#v", bind)
	}

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"arguments", `(sn=) 0 5 sub`, "requires filter"},
		{"unsafe OR", `(|(sn=)(uid=)) 0 5 sub dc=example,dc=com`, "safe subset"},
		{"no placeholder", `(sn=Smith) 0 5 sub dc=example,dc=com`, "safe subset"},
		{"attrset", `(sn=) 2 5 sub dc=example,dc=com`, "out of range"},
		{"template", `(uid=) 0 5 sub dc=example,dc=com`, "no matching"},
		{"zero TTR", `(sn=) 0 0 sub dc=example,dc=com`, "positive"},
		{"scope", `(sn=) 0 5 nearby dc=example,dc=com`, "unknown Bind scope"},
		{"base", `(sn=) 0 5 sub dc=example,`, "base DN"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := testPcacheOverlay()
			candidate.Attributes = append(candidate.Attributes, directory.Attribute{
				Description: "olcPcacheBind",
				Values:      stringValues(test.value),
			})
			_, err := loadPcacheRuntimeConfiguration(candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("configuration error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPcacheBindVerifierTTLAndOffline(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	state := newPcacheStateWithClock(func() time.Time { return now })
	password := []byte("pcache-bind-secret")
	if !state.rememberBind("uid=alice", password, now, time.Second, 10, 10) {
		t.Fatal("rememberBind() rejected a valid credential")
	}
	cached := state.binds["uid=alice"]
	if bytes.Contains(cached.passwordHash, password) ||
		!auth.VerifyPassword(cached.passwordHash, password) {
		t.Fatalf("cached verifier is unsafe or invalid: %q", cached.passwordHash)
	}
	if !state.lookupBind("uid=alice", password, now, false) {
		t.Fatal("correct password did not hit Bind cache")
	}
	if state.lookupBind("uid=alice", []byte("wrong-password"), now, false) {
		t.Fatal("wrong password hit Bind cache")
	}
	if !state.lookupBind("uid=alice", password, now.Add(2*time.Second), true) {
		t.Fatal("offline mode did not retain an expired Bind verifier")
	}
	if state.lookupBind("uid=alice", password, now.Add(2*time.Second), false) {
		t.Fatal("online mode accepted an expired Bind verifier")
	}
	if len(state.binds) != 0 || state.entries != 0 {
		t.Fatalf("expired Bind state = %d records, %d entries", len(state.binds), state.entries)
	}
}

func TestPcacheBindLimitsAndConcurrentVerification(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_100, 0)
	state := newPcacheStateWithClock(func() time.Time { return now })
	if !state.rememberBind("uid=one", []byte("one"), now, time.Minute, 1, 2) ||
		!state.rememberBind("uid=two", []byte("two"), now, time.Minute, 1, 2) {
		t.Fatal("OpenLDAP strict-boundary maxEntries setup failed")
	}
	if !state.lookupBind("uid=one", []byte("one"), now, false) ||
		!state.lookupBind("uid=two", []byte("two"), now, false) {
		t.Fatal("strict-boundary maxEntries did not retain max+1 Binds")
	}
	if state.rememberBind("uid=three", []byte("three"), now, time.Minute, 10, 1) {
		t.Fatal("maxQueries accepted an additional Bind")
	}

	const workers = 12
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			password := []byte("two")
			want := true
			if worker%2 != 0 {
				password = []byte("wrong")
				want = false
			}
			if got := state.lookupBind("uid=two", password, now, false); got != want {
				t.Errorf("worker %d lookup = %t, want %t", worker, got, want)
			}
		}(worker)
	}
	wait.Wait()
}

func TestPcacheBindReloadClearsVerifiers(t *testing.T) {
	t.Parallel()
	entry := pcacheBindTestOverlay("5")
	previousConfiguration, err := loadPcacheRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("load previous configuration: %v", err)
	}
	nextConfiguration, err := loadPcacheRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("load next configuration: %v", err)
	}
	now := previousConfiguration.state.clock()
	if !previousConfiguration.state.rememberBind(
		"uid=alice",
		[]byte("secret"),
		now,
		time.Minute,
		10,
		10,
	) {
		t.Fatal("rememberBind() failed")
	}
	storedHash := previousConfiguration.state.binds["uid=alice"].passwordHash
	previous := &runtimeState{databases: []runtimeDatabase{{pcache: &previousConfiguration}}}
	next := &runtimeState{databases: []runtimeDatabase{{pcache: &nextConfiguration}}}
	reusePcacheStates(previous, next)
	if nextConfiguration.state != previousConfiguration.state ||
		len(nextConfiguration.state.binds) != 1 {
		t.Fatal("candidate runtime mutated the active Bind cache")
	}
	if bytes.Count(storedHash, []byte{0}) == len(storedHash) {
		t.Fatal("candidate runtime erased the active credential verifier")
	}
	clearPcacheBindStates(previous)
	clearPcacheBindStates(next)
	if len(nextConfiguration.state.binds) != 0 {
		t.Fatal("activated configuration retained Bind cache records")
	}
	if bytes.Count(storedHash, []byte{0}) != len(storedHash) {
		t.Fatal("configuration reload did not erase the credential verifier")
	}

	for _, test := range []struct {
		name string
		next *pcacheRuntimeConfiguration
	}{
		{name: "changed", next: func() *pcacheRuntimeConfiguration {
			changed, loadErr := loadPcacheRuntimeConfiguration(pcacheBindTestOverlay("6"))
			if loadErr != nil {
				t.Fatalf("load changed configuration: %v", loadErr)
			}
			return &changed
		}()},
		{name: "removed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			old, loadErr := loadPcacheRuntimeConfiguration(entry)
			if loadErr != nil {
				t.Fatalf("load old configuration: %v", loadErr)
			}
			if !old.state.rememberBind(
				"uid=alice",
				[]byte("secret"),
				old.state.clock(),
				time.Minute,
				10,
				10,
			) {
				t.Fatal("rememberBind() failed")
			}
			oldRuntime := &runtimeState{databases: []runtimeDatabase{{pcache: &old}}}
			newRuntime := &runtimeState{}
			if test.next != nil {
				newRuntime.databases = []runtimeDatabase{{pcache: test.next}}
			}
			reusePcacheStates(oldRuntime, newRuntime)
			if len(old.state.binds) != 1 {
				t.Fatal("candidate runtime mutated old Bind verifiers")
			}
			if test.next != nil && test.next.state == old.state {
				t.Fatal("changed configuration reused old pcache state")
			}
			clearPcacheBindStates(oldRuntime)
			clearPcacheBindStates(newRuntime)
			if len(old.state.binds) != 0 {
				t.Fatal("activation retained old Bind verifiers")
			}
		})
	}
}

func TestPcacheBindDNIdentityAndConnectionState(t *testing.T) {
	t.Parallel()
	registry := dnIdentityCacheRegistry(t)
	configuration, err := loadPcacheRuntimeConfiguration(
		pcacheBindTestOverlay("5"),
	)
	if err != nil {
		t.Fatalf("loadPcacheRuntimeConfiguration(): %v", err)
	}
	runtime := &runtimeState{schema: registry}
	upper, err := registry.NormalizeDN("UID=Alice,OU=People,DC=Example,DC=Com")
	if err != nil {
		t.Fatalf("NormalizeDN(upper): %v", err)
	}
	lower, err := registry.NormalizeDN("uid= alice ,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("NormalizeDN(lower): %v", err)
	}
	_, upperKey, upperOK := matchPcacheBindRequest(runtime, configuration, upper)
	_, lowerKey, lowerOK := matchPcacheBindRequest(runtime, configuration, lower)
	if !upperOK || !lowerOK || upperKey != lowerKey {
		t.Fatalf("schema-aware Bind keys = %q (%t), %q (%t)", upperKey, upperOK, lowerKey, lowerOK)
	}
	state := &connectionState{bindCredentials: []byte("old")}
	pcacheEstablishBindIdentity(state, upper, []byte("new-secret"))
	if state.boundDN != upper.String() || state.bindCredentialDN != upper.String() ||
		state.authMechanism != "SIMPLE" || string(state.bindCredentials) != "new-secret" {
		t.Fatalf("cached Bind connection identity = %#v", state)
	}
}

func TestPcacheBindRealLDAPBackendProvider(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
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

			proxyStore := pcacheBindTestStore(t, backend)
			seedLDAPBackendProxy(t, proxyStore, providerAddress)
			if err := proxyStore.Update(context.Background(), func(writer storage.Writer) error {
				return writer.Put(pcacheBindProviderOverlay("2"), false)
			}); err != nil {
				t.Fatalf("seed pcache Bind overlay: %v", err)
			}
			proxy, err := New(Config{Store: proxyStore})
			if err != nil {
				t.Fatalf("New(proxy): %v", err)
			}
			runtime := proxy.runtime.Load()
			database := databaseForDNString(t, runtime, ldapBackendTestUserDN)
			clock := &pcacheTestClock{now: time.Unix(1_800_000_200, 0)}
			database.pcache.state.clock = clock.current
			database.pcache.state.epoch = clock.current()

			if code := invokePcacheBind(
				t,
				proxy,
				runtime,
				ldapBackendTestUserDN,
				"wrong-password",
			); code != int(ldapwire.ResultInvalidCredentials) {
				t.Fatalf("provider wrong-password Bind result = %d", code)
			}
			if len(database.pcache.state.binds) != 0 {
				t.Fatal("failed provider Bind created a cached verifier")
			}
			if code := invokePcacheBind(
				t,
				proxy,
				runtime,
				ldapBackendTestUserDN,
				ldapBackendTestUserPassword,
			); code != int(ldapwire.ResultSuccess) {
				t.Fatalf("provider-backed Bind result = %d", code)
			}
			cached := database.pcache.state.binds
			if len(cached) != 1 {
				t.Fatalf("cached Bind count = %d", len(cached))
			}
			for _, bind := range cached {
				if bytes.Contains(bind.passwordHash, []byte(ldapBackendTestUserPassword)) {
					t.Fatal("Bind cache retained plaintext credentials")
				}
			}

			stopProvider()
			providerRunning = false
			if code := invokePcacheBind(
				t,
				proxy,
				runtime,
				strings.ToUpper(ldapBackendTestUserDN),
				ldapBackendTestUserPassword,
			); code != int(ldapwire.ResultSuccess) {
				t.Fatalf("provider-outage cache hit result = %d", code)
			}
			if code := invokePcacheBind(
				t,
				proxy,
				runtime,
				ldapBackendTestUserDN,
				"wrong-password",
			); code != int(ldapwire.ResultUnavailable) {
				t.Fatalf("wrong-password outage result = %d, want unavailable", code)
			}

			clock.advance(3 * time.Second)
			database.pcache.offline = true
			if code := invokePcacheBind(
				t,
				proxy,
				runtime,
				ldapBackendTestUserDN,
				ldapBackendTestUserPassword,
			); code != int(ldapwire.ResultSuccess) {
				t.Fatalf("offline expired cache hit result = %d", code)
			}
			database.pcache.offline = false
			if code := invokePcacheBind(
				t,
				proxy,
				runtime,
				ldapBackendTestUserDN,
				ldapBackendTestUserPassword,
			); code != int(ldapwire.ResultUnavailable) {
				t.Fatalf("online expired cache result = %d, want unavailable", code)
			}
		})
	}
}

func TestPcacheBindProductionWireProviderOutageAndTTL(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
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

			proxyStore := pcacheBindTestStore(t, backend)
			seedLDAPBackendProxy(t, proxyStore, providerAddress)
			if err := proxyStore.Update(context.Background(), func(writer storage.Writer) error {
				return writer.Put(pcacheBindProviderOverlay("2"), false)
			}); err != nil {
				t.Fatalf("seed pcache Bind overlay: %v", err)
			}
			proxy, proxyAddress, stopProxy := startPcacheBindWireServer(t, proxyStore)
			defer stopProxy()
			runtime := proxy.runtime.Load()
			database := databaseForDNString(t, runtime, ldapBackendTestUserDN)
			clock := &pcacheTestClock{now: time.Unix(1_800_000_300, 0)}
			database.pcache.state.clock = clock.current
			database.pcache.state.epoch = clock.current()

			mixedCaseDN := "UID=Alice,OU=People,DC=Proxy,DC=Test"
			first := dialLDAPBackendClient(t, proxyAddress)
			if err := first.Bind(mixedCaseDN, ldapBackendTestUserPassword); err != nil {
				first.Close()
				t.Fatalf("initial wire Bind: %v", err)
			}
			first.Close()
			if len(database.pcache.state.binds) != 1 {
				t.Fatalf("initial wire Bind cached %d verifiers", len(database.pcache.state.binds))
			}

			cached := dialLDAPBackendClient(t, proxyAddress)
			if err := cached.Bind(mixedCaseDN, ldapBackendTestUserPassword); err != nil {
				cached.Close()
				t.Fatalf("second wire Bind: %v", err)
			}
			identity, err := cached.WhoAmI(nil)
			if err != nil {
				cached.Close()
				t.Fatalf("cached Bind WhoAmI: %v", err)
			}
			canonical, err := runtime.schema.NormalizeDN(mixedCaseDN)
			if err != nil {
				cached.Close()
				t.Fatalf("NormalizeDN(%q): %v", mixedCaseDN, err)
			}
			if identity.AuthzID != "dn:"+canonical.String() {
				cached.Close()
				t.Fatalf("cached Bind WhoAmI = %q, want %q", identity.AuthzID, "dn:"+canonical.String())
			}
			cached.Close()

			stopProvider()
			providerRunning = false
			if code := pcacheBindWireResultCode(
				t,
				proxyAddress,
				ldapBackendTestUserDN,
				ldapBackendTestUserPassword,
			); code != ldap.LDAPResultSuccess {
				t.Fatalf("provider-outage wire cache hit = %d", code)
			}
			if code := pcacheBindWireResultCode(
				t,
				proxyAddress,
				ldapBackendTestUserDN,
				"wrong-password",
			); code == ldap.LDAPResultSuccess {
				t.Fatal("wrong password hit production Bind cache")
			}

			clock.advance(3 * time.Second)
			if code := pcacheBindWireResultCode(
				t,
				proxyAddress,
				ldapBackendTestUserDN,
				ldapBackendTestUserPassword,
			); code == ldap.LDAPResultSuccess {
				t.Fatal("expired production Bind cache returned success")
			}
		})
	}
}

func TestPcacheBindProductionWireReloadClearsCache(t *testing.T) {
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
	overlay := pcacheBindProviderOverlay("30")
	if err := proxyStore.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(overlay, false)
	}); err != nil {
		t.Fatalf("seed pcache Bind overlay: %v", err)
	}
	proxy, proxyAddress, stopProxy := startPcacheBindWireServer(t, proxyStore)
	defer stopProxy()

	if code := pcacheBindWireResultCode(
		t,
		proxyAddress,
		ldapBackendTestUserDN,
		ldapBackendTestUserPassword,
	); code != ldap.LDAPResultSuccess {
		t.Fatalf("initial Bind result = %d", code)
	}
	oldDatabase := databaseForDNString(t, proxy.runtime.Load(), ldapBackendTestUserDN)
	if len(oldDatabase.pcache.state.binds) != 1 {
		t.Fatal("initial wire Bind did not populate cache")
	}

	configClient := dialLDAPBackendClient(t, proxyAddress)
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		configClient.Close()
		t.Fatalf("Bind(cn=config): %v", err)
	}
	invalid := ldap.NewModifyRequest(overlay.DN, nil)
	invalid.Replace("olcPcacheMaxQueries", []string{"0"})
	if err := configClient.Modify(invalid); err == nil {
		configClient.Close()
		t.Fatal("invalid pcache configuration was accepted")
	}
	afterFailure := databaseForDNString(t, proxy.runtime.Load(), ldapBackendTestUserDN)
	if afterFailure.pcache.state != oldDatabase.pcache.state ||
		len(oldDatabase.pcache.state.binds) != 1 {
		configClient.Close()
		t.Fatal("failed configuration reload mutated active Bind cache")
	}
	modify := ldap.NewModifyRequest(overlay.DN, nil)
	modify.Add("olcPcacheMaxQueries", []string{"9999"})
	if err := configClient.Modify(modify); err != nil {
		configClient.Close()
		t.Fatalf("reload pcache configuration: %v", err)
	}
	configClient.Close()
	newDatabase := databaseForDNString(t, proxy.runtime.Load(), ldapBackendTestUserDN)
	if newDatabase.pcache.state == oldDatabase.pcache.state ||
		len(oldDatabase.pcache.state.binds) != 0 ||
		len(newDatabase.pcache.state.binds) != 0 {
		t.Fatal("production configuration reload retained Bind cache")
	}

	stopProvider()
	providerRunning = false
	if code := pcacheBindWireResultCode(
		t,
		proxyAddress,
		ldapBackendTestUserDN,
		ldapBackendTestUserPassword,
	); code == ldap.LDAPResultSuccess {
		t.Fatal("Bind succeeded from cache after configuration reload")
	}
}

func TestPcacheBindProductionWireCaseExactIsolation(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	dnIdentityBindEntryImport(t, providerStore, "0", dnIdentityBindEntryConfigLDIF, true)
	dnIdentityBindEntryImport(t, providerStore, "1", dnIdentityBindEntryUpperContentLDIF, false)
	dnIdentityBindEntryImport(t, providerStore, "2", dnIdentityBindEntryLowerContentLDIF, false)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	providerRunning := true
	defer func() {
		if providerRunning {
			stopProvider()
		}
	}()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedPcacheBindCaseExactProxy(t, proxyStore, providerAddress)
	_, proxyAddress, stopProxy := startPcacheBindWireServer(t, proxyStore)
	defer stopProxy()

	if code := pcacheBindWireResultCode(
		t,
		proxyAddress,
		dnIdentityBindEntryUpperUser,
		"upper-user-secret",
	); code != ldap.LDAPResultSuccess {
		t.Fatalf("caseExact upper Bind result = %d", code)
	}
	if code := pcacheBindWireResultCode(
		t,
		proxyAddress,
		dnIdentityBindEntryLowerUser,
		"upper-user-secret",
	); code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("caseExact sibling wrong-password result = %d", code)
	}

	stopProvider()
	providerRunning = false
	if code := pcacheBindWireResultCode(
		t,
		proxyAddress,
		dnIdentityBindEntryUpperUser,
		"upper-user-secret",
	); code != ldap.LDAPResultSuccess {
		t.Fatalf("caseExact cached upper Bind result = %d", code)
	}
	if code := pcacheBindWireResultCode(
		t,
		proxyAddress,
		dnIdentityBindEntryLowerUser,
		"upper-user-secret",
	); code == ldap.LDAPResultSuccess {
		t.Fatal("caseExact sibling reused another DN's Bind cache")
	}
}

func TestPcacheBindPinnedOpenLDAPSourceAnchors(t *testing.T) {
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
		"static int\npcache_op_bind(",
		"pc_setpw( &op2, &op->orb_cred, cm )",
		"op->o_time < pbi->bi_cq->bindref_time",
		"cm->cc_paused & PCACHE_CC_OFFLINE",
		`{ "pcacheBind", "filter> <attrset-index> <TTR> <scope> <base"`,
	})
}

func pcacheBindTestOverlay(ttl string) directory.Entry {
	overlay := testPcacheOverlay()
	overlay.Attributes = append(overlay.Attributes, directory.Attribute{
		Description: "olcPcacheBind",
		Values: stringValues(
			`(sn=) 0 ` + ttl + ` sub "ou=people,dc=example,dc=com"`,
		),
	})
	return overlay
}

func pcacheBindProviderOverlay(ttl string) directory.Entry {
	overlay := testPcacheOverlayForDatabase(ldapBackendTestDatabaseDN)
	overlay.ReplaceValues("olcPcacheAttrset", stringValues("0 uid cn sn"))
	overlay.ReplaceValues("olcPcacheTemplate", stringValues("(uid=) 0 30 20 10"))
	overlay.Attributes = append(overlay.Attributes, directory.Attribute{
		Description: "olcPcacheBind",
		Values: stringValues(
			`(uid=) 0 ` + ttl + ` sub "` + ldapBackendTestPeopleDN + `"`,
		),
	})
	return overlay
}

func pcacheBindTestStore(t *testing.T, backend string) storage.Store {
	t.Helper()
	if backend == "memory" {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "pcache-bind.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func startPcacheBindWireServer(
	t *testing.T,
	store storage.Store,
) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve(): %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("pcache Bind wire server did not stop")
			}
		})
	}
	return instance, listener.Addr().String(), stop
}

func pcacheBindWireResultCode(
	t *testing.T,
	address,
	dn,
	password string,
) uint16 {
	t.Helper()
	client := dialLDAPBackendClient(t, address)
	defer client.Close()
	return ldapBackendResultCode(client.Bind(dn, password))
}

func seedPcacheBindCaseExactProxy(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	configuration := fmt.Sprintf(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}bindentrydn,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}bindentrydn
olcAttributeTypes: ( 1.3.6.1.4.1.99999.950.1 NAME ( 'bindExactName' 'bindExactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.950.2 NAME ( 'bindFoldName' 'bindFoldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.950.3 NAME 'bindIdentityEntry' SUP top STRUCTURAL MUST cn MAY ( sn $ userPassword $ bindExactName $ bindFoldName ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}ldap,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}ldap
olcSuffix: %s
olcRootDN: cn=proxy-root,%s
olcRootPW: proxy-root-secret
olcDbURI: ldap://%s
olcDbNetworkTimeout: 1s
olcDbChaseReferrals: FALSE
olcDbProxyWhoAmI: TRUE
olcDbIDAssertBind: bindmethod=simple binddn="%s" credentials="upper-root-secret" mode=none
olcDbIDAssertAuthzFrom: *

dn: olcOverlay={0}pcache,olcDatabase={1}ldap,cn=config
objectClass: olcOverlayConfig
objectClass: olcPcacheConfig
olcOverlay: {0}pcache
olcPcache: mdb 100 1 10 1
olcPcacheAttrset: 0 bindExactName bindFoldName cn sn
olcPcacheTemplate: (bindExactName=) 0 30 20 10
olcPcacheBind: (bindExactName=) 0 30 sub "ou=people,%s"

`, dnIdentityBindEntryUpperBase, dnIdentityBindEntryUpperBase,
		providerAddress, dnIdentityBindEntryUpperRoot, dnIdentityBindEntryUpperBase)
	dnIdentityBindEntryImport(t, store, "0", configuration, true)
}

func databaseForDNString(
	t *testing.T,
	runtime *runtimeState,
	value string,
) *runtimeDatabase {
	t.Helper()
	dn, err := runtime.schema.NormalizeDN(value)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", value, err)
	}
	database := databaseForDN(runtime, dn)
	if database == nil || database.pcache == nil {
		t.Fatalf("pcache database for %q was not loaded", value)
	}
	return database
}

func invokePcacheBind(
	t *testing.T,
	server *Server,
	runtime *runtimeState,
	dn,
	password string,
) int {
	t.Helper()
	requestDN, err := runtime.schema.NormalizeDN(dn)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", dn, err)
	}
	request := ldapwire.BindRequest{
		Version: 3,
		Name:    dn,
		Authentication: ldapwire.Authentication{
			Simple: []byte(password),
		},
	}
	message := ldapwire.Message{ID: 1, Request: request}
	connection := &pcacheBindCaptureConnection{}
	state := &connectionState{
		connectionID:   1,
		runtime:        runtime,
		metaTransports: newMetaTransportCache(time.Now),
	}
	handled, err := server.tryPcacheBind(
		context.Background(),
		connection,
		state,
		message,
		request,
		requestDN,
	)
	if err != nil {
		t.Fatalf("tryPcacheBind(): %v", err)
	}
	if !handled {
		t.Fatal("tryPcacheBind() did not handle configured Bind")
	}
	code, ok := auditLDAPResultCode(connection.Bytes())
	if !ok {
		t.Fatalf("decode Bind response: %x", connection.Bytes())
	}
	if code == int(ldapwire.ResultSuccess) &&
		(state.boundDN != requestDN.String() || state.authMechanism != "SIMPLE") {
		t.Fatalf("successful Bind identity = %#v", state)
	}
	state.metaTransports.close()
	clear(state.bindCredentials)
	return code
}

type pcacheBindCaptureConnection struct {
	bytes.Buffer
}

func (*pcacheBindCaptureConnection) Read([]byte) (int, error)         { return 0, os.ErrClosed }
func (*pcacheBindCaptureConnection) Close() error                     { return nil }
func (*pcacheBindCaptureConnection) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*pcacheBindCaptureConnection) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*pcacheBindCaptureConnection) SetDeadline(time.Time) error      { return nil }
func (*pcacheBindCaptureConnection) SetReadDeadline(time.Time) error  { return nil }
func (*pcacheBindCaptureConnection) SetWriteDeadline(time.Time) error { return nil }
