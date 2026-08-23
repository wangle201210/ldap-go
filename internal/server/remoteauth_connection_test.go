package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRemoteAuthConnectionsAreOneShotAndFailuresAreEvicted(t *testing.T) {
	clientClosed := make(chan int, 2)
	address, provider := startPBindTestProvider(
		t,
		func(attempt int, connection net.Conn) error {
			messageID, err := readPBindTestRequest(connection)
			if err != nil {
				return err
			}
			if attempt == 1 {
				return nil
			}
			if err := writePBindTestResponse(
				connection,
				messageID,
				ldapwire.ResultSuccess,
			); err != nil {
				return err
			}
			buffer := make([]byte, 1)
			if _, err := connection.Read(buffer); err == nil {
				return errors.New("bound connection remained reusable")
			}
			clientClosed <- attempt
			return nil
		},
	)
	manager := newRemoteAuthConnectionManager(2, time.Second)
	configuration := remoteAuthConnectionTestConfiguration(
		manager,
	)
	providerURI := "ldap://" + address
	request := remoteAuthConnectionTestRequest("one-shot-secret")
	defer clear(request.Authentication.Simple)

	if _, err := executeRemoteAuthBind(
		t.Context(), configuration, "realm-a", providerURI, request,
	); err == nil {
		t.Fatal("connection failure unexpectedly returned a Bind result")
	}
	result, err := executeRemoteAuthBind(
		t.Context(), configuration, "realm-a", providerURI, request,
	)
	if err != nil || result.Code != ldapwire.ResultSuccess {
		t.Fatalf("Bind after failed connection = %#v, %v", result, err)
	}
	result, err = executeRemoteAuthBind(
		t.Context(), configuration, "realm-a", providerURI, request,
	)
	if err != nil || result.Code != ldapwire.ResultSuccess {
		t.Fatalf("second successful Bind = %#v, %v", result, err)
	}
	provider.waitForAttempts(t, 3)
	if got := provider.accepted.Load(); got != 3 {
		t.Fatalf("accepted connections = %d, want a fresh connection per Bind", got)
	}
	for range 2 {
		select {
		case <-clientClosed:
		case <-time.After(time.Second):
			t.Fatal("remoteauth did not close a successfully bound connection")
		}
	}
	manager.mu.Lock()
	idleGroups := len(manager.groups)
	manager.mu.Unlock()
	if idleGroups != 0 {
		t.Fatalf("idle remoteauth groups = %d, want zero", idleGroups)
	}
}

func TestRemoteAuthConnectionManagerBoundsAndIsolatesAttempts(t *testing.T) {
	manager := newRemoteAuthConnectionManager(1, time.Second)
	release, err := manager.acquire(t.Context(), "realm-a", "ldap://provider-a")
	if err != nil {
		t.Fatalf("acquire first attempt: %v", err)
	}
	defer release()

	blockedContext, cancelBlocked := context.WithCancel(t.Context())
	blocked := make(chan error, 1)
	go func() {
		_, acquireErr := manager.acquire(
			blockedContext,
			"realm-a",
			"ldap://provider-a",
		)
		blocked <- acquireErr
	}()
	select {
	case err := <-blocked:
		t.Fatalf("same group bypassed concurrency limit: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	for _, group := range []struct {
		realm    string
		provider string
	}{
		{realm: "realm-b", provider: "ldap://provider-a"},
		{realm: "realm-a", provider: "ldap://provider-b"},
	} {
		groupRelease, acquireErr := manager.acquire(
			t.Context(),
			group.realm,
			group.provider,
		)
		if acquireErr != nil {
			t.Fatalf("independent group %v: %v", group, acquireErr)
		}
		groupRelease()
	}
	otherTLSConfiguration := newRemoteAuthConnectionManager(1, time.Second)
	otherRelease, err := otherTLSConfiguration.acquire(
		t.Context(),
		"realm-a",
		"ldap://provider-a",
	)
	if err != nil {
		t.Fatalf("independent TLS configuration: %v", err)
	}
	otherRelease()

	cancelBlocked()
	if err := <-blocked; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
}

func TestRemoteAuthBoundsActualProviderConcurrency(t *testing.T) {
	const (
		limit   = 2
		callers = 6
	)
	releaseProvider := make(chan struct{})
	started := make(chan struct{}, callers)
	var active, maximum atomic.Int32
	address, provider := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			messageID, err := readPBindTestRequest(connection)
			if err != nil {
				return err
			}
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			started <- struct{}{}
			<-releaseProvider
			active.Add(-1)
			return writePBindTestResponse(
				connection,
				messageID,
				ldapwire.ResultSuccess,
			)
		},
	)
	configuration := remoteAuthConnectionTestConfiguration(
		newRemoteAuthConnectionManager(limit, 2*time.Second),
	)
	providerURI := "ldap://" + address
	results := make(chan error, callers)
	for range callers {
		go func() {
			request := remoteAuthConnectionTestRequest("secret")
			defer clear(request.Authentication.Simple)
			result, err := executeRemoteAuthBind(
				t.Context(),
				configuration,
				"realm-a",
				providerURI,
				request,
			)
			if err == nil && result.Code != ldapwire.ResultSuccess {
				err = errors.New("provider returned a non-success result")
			}
			results <- err
		}()
	}
	for range limit {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("provider concurrency limit was not filled")
		}
	}
	time.Sleep(40 * time.Millisecond)
	if got := provider.accepted.Load(); got != limit {
		t.Fatalf("connections before release = %d, want %d", got, limit)
	}
	close(releaseProvider)
	for range callers {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent remoteauth Bind: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out draining remoteauth attempts")
		}
	}
	provider.waitForAttempts(t, callers)
	if got := maximum.Load(); got > limit {
		t.Fatalf("maximum provider concurrency = %d, want <= %d", got, limit)
	}
}

func TestRemoteAuthCancellationLifetimeAndRuntimeRetirement(t *testing.T) {
	requestReceived := make(chan struct{}, 2)
	address, _ := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			if _, err := readPBindTestRequest(connection); err != nil {
				return err
			}
			requestReceived <- struct{}{}
			buffer := make([]byte, 1)
			_, _ = connection.Read(buffer)
			return nil
		},
	)
	providerURI := "ldap://" + address

	t.Run("request cancellation", func(t *testing.T) {
		configuration := remoteAuthConnectionTestConfiguration(
			newRemoteAuthConnectionManager(1, time.Second),
		)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			request := remoteAuthConnectionTestRequest("cancel-secret")
			defer clear(request.Authentication.Simple)
			_, err := executeRemoteAuthBind(
				ctx, configuration, "realm-a", providerURI, request,
			)
			result <- err
		}()
		<-requestReceived
		cancel()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("canceled Bind returned without error")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled Bind did not close its connection")
		}
	})

	t.Run("maximum lifetime", func(t *testing.T) {
		configuration := remoteAuthConnectionTestConfiguration(
			newRemoteAuthConnectionManager(1, 50*time.Millisecond),
		)
		request := remoteAuthConnectionTestRequest("lifetime-secret")
		defer clear(request.Authentication.Simple)
		startedAt := time.Now()
		_, err := executeRemoteAuthBind(
			t.Context(), configuration, "realm-a", providerURI, request,
		)
		if err == nil {
			t.Fatal("maximum connection lifetime was not enforced")
		}
		if elapsed := time.Since(startedAt); elapsed > time.Second {
			t.Fatalf("maximum lifetime elapsed = %v", elapsed)
		}
	})

	t.Run("online reload retires old configuration", func(t *testing.T) {
		suffix, err := directory.ParseDN("dc=example,dc=com")
		if err != nil {
			t.Fatalf("parse suffix: %v", err)
		}
		oldManager := newRemoteAuthConnectionManager(1, time.Second)
		newManager := newRemoteAuthConnectionManager(1, time.Second)
		instance := &Server{}
		instance.runtime.Store(&runtimeState{databases: []runtimeDatabase{{
			suffixes: []directory.DN{suffix},
			remoteAuth: &remoteAuthRuntimeConfiguration{
				connections: oldManager,
			},
		}}})
		stop := watchRemoteAuthRuntime(
			t.Context(),
			oldManager,
			func() bool {
				return instance.remoteAuthConfigurationCurrent(suffix, oldManager)
			},
		)
		defer stop()
		attemptContext, cancelAttempt := oldManager.attemptContext(t.Context())
		defer cancelAttempt()
		instance.runtime.Store(&runtimeState{databases: []runtimeDatabase{{
			suffixes: []directory.DN{suffix},
			remoteAuth: &remoteAuthRuntimeConfiguration{
				connections: newManager,
			},
		}}})
		select {
		case <-attemptContext.Done():
		case <-time.After(time.Second):
			t.Fatal("runtime reload did not retire the old remoteauth attempts")
		}
		if newManager.lifecycle.Err() != nil {
			t.Fatal("runtime reload retired the replacement configuration")
		}
	})
}

func TestRemoteAuthRetryClassification(t *testing.T) {
	for _, test := range []struct {
		name         string
		result       *ldapwire.ResultCode
		wantAttempts int
	}{
		{name: "transport failure is not retried", wantAttempts: 1},
		{
			name: "nonterminal Bind result is retried",
			result: func() *ldapwire.ResultCode {
				code := ldapwire.ResultUnavailable
				return &code
			}(),
			wantAttempts: 4,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerAddress, provider := startPBindTestProvider(
				t,
				func(_ int, connection net.Conn) error {
					messageID, err := readPBindTestRequest(connection)
					if err != nil {
						return err
					}
					if test.result == nil {
						return nil
					}
					return writePBindTestResponse(connection, messageID, *test.result)
				},
			)
			instance, runtime, database, dn := newRemoteAuthDirectTestServer(
				t,
				providerAddress,
				3,
			)
			handled, result, _ := instance.remoteAuthSimpleBind(
				t.Context(),
				runtime,
				database,
				dn,
				[]byte("secret"),
			)
			if !handled || result.Code == ldapwire.ResultSuccess {
				t.Fatalf("remoteauth result = handled %t, %#v", handled, result)
			}
			provider.waitForAttempts(t, test.wantAttempts)
			time.Sleep(50 * time.Millisecond)
			if got := int(provider.accepted.Load()); got != test.wantAttempts {
				t.Fatalf("provider attempts = %d, want %d", got, test.wantAttempts)
			}
		})
	}
}

func TestRemoteAuthRejectsSuccessFromRetiredRuntime(t *testing.T) {
	requestReceived := make(chan struct{})
	releaseProvider := make(chan struct{})
	providerAddress, _ := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			messageID, err := readPBindTestRequest(connection)
			if err != nil {
				return err
			}
			close(requestReceived)
			<-releaseProvider
			_ = writePBindTestResponse(connection, messageID, ldapwire.ResultSuccess)
			return nil
		},
	)
	instance, runtime, database, dn := newRemoteAuthDirectTestServer(
		t,
		providerAddress,
		0,
	)
	database.remoteAuth.storeOnSuccess = true
	done := make(chan ldapwire.Result, 1)
	go func() {
		_, result, _ := instance.remoteAuthSimpleBind(
			t.Context(), runtime, database, dn, []byte("secret"),
		)
		done <- result
	}()
	<-requestReceived
	retired := *instance.runtime.Load()
	retired.databases = append([]runtimeDatabase(nil), retired.databases...)
	for index := range retired.databases {
		retired.databases[index].remoteAuth = nil
	}
	instance.runtime.Store(&retired)
	close(releaseProvider)
	if result := <-done; result.Code != ldapwire.ResultOperationsError {
		t.Fatalf("retired remoteauth result = %#v", result)
	}
	if values := readStoredEntry(t, instance.config.Store, dn.String()).Values("userPassword"); len(values) != 0 {
		t.Fatalf("retired remoteauth stored a local password: %q", values)
	}
}

func TestRemoteAuthStoreOnSuccessRuntimeCommitGate(t *testing.T) {
	providerAddress, _ := startPBindTestProvider(
		t,
		func(_ int, connection net.Conn) error {
			_, _ = connection.Read(make([]byte, 1))
			return nil
		},
	)

	t.Run("retired runtime cannot write", func(t *testing.T) {
		instance, runtime, database, dn := newRemoteAuthDirectTestServer(
			t,
			providerAddress,
			0,
		)
		manager := database.remoteAuth.connections
		instance.runtimeActivationMu.Lock()
		stored := make(chan bool, 1)
		go func() {
			stored <- instance.storeRemoteAuthPassword(
				t.Context(), runtime, database, dn, []byte("retired-secret"), manager,
			)
		}()
		retired := remoteAuthRetiredRuntime(runtime)
		instance.runtime.Store(retired)
		instance.runtimeActivationMu.Unlock()
		if accepted := <-stored; accepted {
			t.Fatal("retired remoteauth configuration passed the password commit gate")
		}
		if values := readStoredEntry(t, instance.config.Store, dn.String()).Values("userPassword"); len(values) != 0 {
			t.Fatalf("retired commit gate wrote userPassword: %q", values)
		}
	})

	t.Run("runtime activation waits for password commit", func(t *testing.T) {
		instance, runtime, database, dn := newRemoteAuthDirectTestServer(
			t,
			providerAddress,
			0,
		)
		blocking := &remoteAuthCommitGateStore{
			Store:   instance.config.Store,
			started: make(chan struct{}),
			release: make(chan struct{}),
		}
		blocking.enabled.Store(true)
		instance.config.Store = blocking
		defer blocking.unblock()

		stored := make(chan bool, 1)
		go func() {
			stored <- instance.storeRemoteAuthPassword(
				t.Context(),
				runtime,
				database,
				dn,
				[]byte("committed-secret"),
				database.remoteAuth.connections,
			)
		}()
		select {
		case <-blocking.started:
		case <-time.After(time.Second):
			t.Fatal("remoteauth password write did not reach the commit gate")
		}

		activated := make(chan struct{})
		go func() {
			instance.activateRuntime(remoteAuthRetiredRuntime(runtime))
			close(activated)
		}()
		select {
		case <-activated:
			t.Fatal("runtime activation crossed an in-flight remoteauth password commit")
		case <-time.After(30 * time.Millisecond):
		}
		blocking.unblock()
		if accepted := <-stored; !accepted {
			t.Fatal("current remoteauth configuration was rejected by the commit gate")
		}
		select {
		case <-activated:
		case <-time.After(time.Second):
			t.Fatal("runtime activation did not resume after password commit")
		}
		if values := readStoredEntry(t, instance.config.Store, dn.String()).Values("userPassword"); len(values) != 1 {
			t.Fatalf("committed remoteauth password values = %q", values)
		}
	})
}

func remoteAuthRetiredRuntime(runtime *runtimeState) *runtimeState {
	retired := *runtime
	retired.revision = runtime.revision + 1
	retired.databases = append([]runtimeDatabase(nil), runtime.databases...)
	for index := range retired.databases {
		retired.databases[index].remoteAuth = nil
	}
	return &retired
}

type remoteAuthCommitGateStore struct {
	storage.Store
	enabled atomic.Bool
	started chan struct{}
	release chan struct{}
	start   sync.Once
	done    sync.Once
}

func (store *remoteAuthCommitGateStore) Update(
	ctx context.Context,
	fn func(storage.Writer) error,
) error {
	if store.enabled.Load() {
		store.start.Do(func() { close(store.started) })
		select {
		case <-store.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return store.Store.Update(ctx, fn)
}

func (store *remoteAuthCommitGateStore) unblock() {
	store.done.Do(func() { close(store.release) })
}

func newRemoteAuthDirectTestServer(
	t *testing.T,
	providerAddress string,
	retryCount int,
) (*Server, *runtimeState, runtimeDatabase, directory.DN) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedRemoteAuthConfiguration(t, store, providerAddress, false)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(
			"olcOverlay={0}remoteauth,olcDatabase={1}mdb,cn=config",
		)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"olcRemoteAuthRetryCount",
			stringValues(fmt.Sprint(retryCount)),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	runtime := instance.runtime.Load()
	dn, err := parseRuntimeConnectionDN(
		runtime,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForDN(runtime, dn)
	if database == nil || database.remoteAuth == nil {
		t.Fatal("remoteauth runtime configuration is missing")
	}
	return instance, runtime, *database, dn
}

func TestOpenLDAPRemoteAuthConnectionLifecycleSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	contents, err := os.ReadFile(filepath.Join(
		sourceRoot,
		"servers",
		"slapd",
		"overlays",
		"remoteauth.c",
	))
	if err != nil {
		t.Fatalf("read pinned OpenLDAP remoteauth.c: %v", err)
	}
	for _, contract := range []string{
		"ldap_initialize( &ld, ldap_url )",
		"ldap_sasl_bind_s( ld, dn.bv_val, LDAP_SASL_SIMPLE",
		"if ( ld ) ldap_unbind_ext_s( ld, NULL, NULL )",
	} {
		if !strings.Contains(string(contents), contract) {
			t.Fatalf("pinned OpenLDAP remoteauth.c lacks %q", contract)
		}
	}
	slapHeader, err := os.ReadFile(filepath.Join(
		sourceRoot,
		"servers",
		"slapd",
		"slap.h",
	))
	if err != nil {
		t.Fatalf("read pinned OpenLDAP slap.h: %v", err)
	}
	if !strings.Contains(
		string(slapHeader),
		"#define SLAP_MAX_WORKER_THREADS\t\t(16)",
	) {
		t.Fatal("pinned OpenLDAP default worker concurrency changed")
	}
}

func remoteAuthConnectionTestConfiguration(
	manager *remoteAuthConnectionManager,
) remoteAuthRuntimeConfiguration {
	return remoteAuthRuntimeConfiguration{
		connection: syncConsumerConfig{
			networkTimeout:   time.Second,
			operationTimeout: time.Second,
		},
		pins:        make(map[string]remoteAuthTLSPin),
		connections: manager,
	}
}

func remoteAuthConnectionTestRequest(password string) ldapwire.BindRequest {
	return ldapwire.BindRequest{
		Version: 3,
		Name:    "uid=alice,ou=people,dc=example,dc=com",
		Authentication: ldapwire.Authentication{
			Simple: []byte(password),
		},
	}
}
