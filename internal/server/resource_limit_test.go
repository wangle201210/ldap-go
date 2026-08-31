package server

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestResourceLimiterBoundsAndCancelsWaiters(t *testing.T) {
	limiter := newResourceLimiter(2)
	for range 2 {
		if !limiter.acquire(context.Background()) {
			t.Fatal("initial limiter slot was unavailable")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan bool, 1)
	go func() { waiting <- limiter.acquire(ctx) }()
	deadline := time.Now().Add(time.Second)
	for limiter.waiting.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("limiter waiter was not published")
		}
		time.Sleep(time.Millisecond)
	}
	if limiter.active.Load() != 2 || limiter.limit() != 2 {
		t.Fatalf("limiter state = active:%d limit:%d", limiter.active.Load(), limiter.limit())
	}
	cancel()
	if <-waiting {
		t.Fatal("canceled limiter waiter acquired a slot")
	}
	limiter.release()
	limiter.release()
	if limiter.active.Load() != 0 || limiter.waiting.Load() != 0 {
		t.Fatalf("limiter leaked state: active=%d waiting=%d", limiter.active.Load(), limiter.waiting.Load())
	}
}

func TestResourceByteLimiterBoundsAndRecovers(t *testing.T) {
	t.Parallel()

	limiter := newResourceByteLimiter(10)
	if !limiter.tryAcquire(6) || limiter.tryAcquire(5) {
		t.Fatal("byte limiter did not enforce its maximum")
	}
	if limiter.active.Load() != 6 || limiter.rejected.Load() != 1 {
		t.Fatalf("byte limiter active=%d rejected=%d", limiter.active.Load(), limiter.rejected.Load())
	}
	limiter.release(6)
	if !limiter.tryAcquire(10) {
		t.Fatal("byte limiter did not recover capacity")
	}
	limiter.release(10)
	if limiter.active.Load() != 0 || limiter.limit() != 10 {
		t.Fatalf("byte limiter final active=%d limit=%d", limiter.active.Load(), limiter.limit())
	}
}

func TestServerGlobalConnectionLimitRejectsAndRecovers(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:          store,
		MaxConnections: 1,
		RootDN:         "cn=admin,dc=example,dc=com",
		RootPassword:   []byte("secret"),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	waitForServerConnectionCount(t, instance, 1)
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	if err := second.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		first.Close()
		second.Close()
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := second.Read(buffer); err == nil {
		first.Close()
		second.Close()
		t.Fatal("connection above the global limit remained open")
	}
	second.Close()
	if instance.rejectedConnections.Load() != 1 {
		first.Close()
		t.Fatalf("rejected connections = %d", instance.rejectedConnections.Load())
	}
	first.Close()
	waitForServerConnectionCount(t, instance, 0)

	client, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind after connection capacity recovered: %v", err)
	}
}

func TestServerGlobalHandshakeLimit(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	transport := &resourceLimitSecureTransport{
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
	instance, err := New(Config{
		Store:                   store,
		SecureTransport:         transport,
		MaxConcurrentHandshakes: 2,
		SecureHandshakeTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 5
	connections := make([]net.Conn, 0, attempts*2)
	results := make(chan error, attempts)
	for range attempts {
		client, server := net.Pipe()
		connections = append(connections, client, server)
		go func() {
			_, err := instance.secureHandshake(context.Background(), server)
			results <- err
		}()
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range 2 {
		select {
		case <-transport.entered:
		case <-time.After(time.Second):
			t.Fatal("handshake did not enter available slots")
		}
	}
	select {
	case <-transport.entered:
		t.Fatal("third handshake exceeded the global limit")
	case <-time.After(50 * time.Millisecond):
	}
	close(transport.release)
	for range attempts {
		if err := <-results; err != nil {
			t.Fatalf("bounded handshake: %v", err)
		}
	}
	if transport.maximum.Load() != 2 || instance.handshakeLimiter.active.Load() != 0 {
		t.Fatalf("handshake maximum=%d active=%d", transport.maximum.Load(), instance.handshakeLimiter.active.Load())
	}
}

func TestServerGlobalOperationLimit(t *testing.T) {
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	seedDirectory(t, base)
	store := newResourceLimitStore(base)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:                   store,
		MaxConcurrentOperations: 2,
		RootDN:                  "cn=admin,dc=example,dc=com",
		RootPassword:            []byte("secret"),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		store.unblock()
		<-done
	})
	clients := make([]*ldap.Conn, 4)
	for index := range clients {
		client, err := ldap.DialURL("ldap://" + listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
			client.Close()
			t.Fatal(err)
		}
		clients[index] = client
		defer client.Close()
	}
	store.enable()
	results := make(chan error, len(clients))
	for _, client := range clients {
		go func() {
			_, err := client.Search(ldap.NewSearchRequest(
				"dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"dc"},
				nil,
			))
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-store.entered:
		case <-time.After(time.Second):
			t.Fatal("operation did not enter available global slot")
		}
	}
	select {
	case <-store.entered:
		t.Fatal("third operation exceeded the global limit")
	case <-time.After(50 * time.Millisecond):
	}
	if instance.operationLimiter.active.Load() != 2 ||
		instance.operationLimiter.waiting.Load() != 2 {
		t.Fatalf(
			"operation limiter active=%d waiting=%d",
			instance.operationLimiter.active.Load(),
			instance.operationLimiter.waiting.Load(),
		)
	}
	store.unblock()
	for range clients {
		if err := <-results; err != nil {
			t.Fatalf("bounded Search: %v", err)
		}
	}
	if store.maximum.Load() != 2 || instance.operationLimiter.active.Load() != 0 {
		t.Fatalf("operation maximum=%d active=%d", store.maximum.Load(), instance.operationLimiter.active.Load())
	}
}

func TestServerPerConnectionOperationLimit(t *testing.T) {
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	seedDirectory(t, base)
	store := newResourceLimitStore(base)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:                      store,
		MaxConcurrentOperations:    16,
		MaxOperationsPerConnection: 2,
		RootDN:                     "cn=admin,dc=example,dc=com",
		RootPassword:               []byte("secret"),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		store.unblock()
		<-done
	})
	client, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	store.enable()
	results := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := client.Search(ldap.NewSearchRequest(
				"dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"dc"},
				nil,
			))
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-store.entered:
		case <-time.After(time.Second):
			t.Fatal("same-connection Search did not enter an available slot")
		}
	}
	select {
	case <-store.entered:
		t.Fatal("third same-connection Search exceeded its connection limit")
	case <-time.After(50 * time.Millisecond):
	}
	store.unblock()
	for range 3 {
		if err := <-results; err != nil {
			t.Fatalf("same-connection Search: %v", err)
		}
	}
	if store.maximum.Load() != 2 {
		t.Fatalf("same-connection maximum = %d, want 2", store.maximum.Load())
	}
}

func TestFiniteSearchResponseByteLimit(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:                 "cn=admin,dc=example,dc=com",
		RootPassword:           []byte("secret"),
		MaxSearchResponseBytes: 32,
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*", "+"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultAdminLimitExceeded)
	who, err := client.WhoAmI(nil)
	if err != nil || who.AuthzID != "dn:cn=admin,dc=example,dc=com" {
		t.Fatalf("Who Am I after response limit = %#v, %v", who, err)
	}
}

func TestSearchResponsePDULimit(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:                 "cn=admin,dc=example,dc=com",
		RootPassword:           []byte("secret"),
		MaxResponsePDUBytes:    32,
		MaxSearchResponseBytes: 1 << 20,
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*", "+"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultAdminLimitExceeded)
	if _, err := client.WhoAmI(nil); err != nil {
		t.Fatalf("Who Am I after PDU limit: %v", err)
	}
}

func TestProcessSearchMemoryLimit(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:               "cn=admin,dc=example,dc=com",
		RootPassword:         []byte("secret"),
		MaxSearchMemoryBytes: 1,
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultAdminLimitExceeded)
	who, err := client.WhoAmI(nil)
	if err != nil || who.AuthzID != "dn:cn=admin,dc=example,dc=com" {
		t.Fatalf("Who Am I after search memory limit = %#v, %v", who, err)
	}
}

func TestPersistentSyncIsExemptFromFiniteResponseByteLimit(t *testing.T) {
	t.Parallel()

	message := ldapwire.Message{
		ID:      1,
		Request: ldapwire.SearchRequest{},
		Controls: []ldapwire.Control{{
			OID:      syncRequestControlOID,
			HasValue: true,
			Value: ldapwire.EncodeSyncRequestValue(ldapwire.SyncRequestValue{
				Mode: ldapwire.SyncRefreshAndPersist,
			}),
		}},
	}
	operation := newTrackedOperation(context.Background(), message)
	server := &Server{config: Config{MaxSearchResponseBytes: 32}}
	if got := server.searchResponseByteLimit(&queuedOperation{
		message:   message,
		operation: operation,
	}); got != 0 {
		t.Fatalf("persistent Sync response limit = %d, want unlimited", got)
	}
	server.config.MaxResponsePDUBytes = 16
	if got := server.searchResponsePDULimit(&queuedOperation{
		message:   message,
		operation: operation,
	}); got != 16 {
		t.Fatalf("persistent Sync PDU limit = %d, want 16", got)
	}
}

func TestWhoAmIRunsBesideBlockedSameConnectionSearch(t *testing.T) {
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	seedDirectory(t, base)
	store := newResourceLimitStore(base)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:                      store,
		MaxOperationsPerConnection: 2,
		RootDN:                     "cn=admin,dc=example,dc=com",
		RootPassword:               []byte("secret"),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		store.unblock()
		<-done
	})
	client, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	store.enable()
	searchDone := make(chan error, 1)
	go func() {
		_, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		))
		searchDone <- err
	}()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("Search did not enter storage")
	}
	whoDone := make(chan error, 1)
	go func() {
		response, err := client.WhoAmI(nil)
		if err == nil && response.AuthzID != "dn:cn=admin,dc=example,dc=com" {
			err = errors.New("Who Am I returned the wrong authorization identity")
		}
		whoDone <- err
	}()
	select {
	case err := <-whoDone:
		if err != nil {
			t.Fatalf("Who Am I: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Who Am I was blocked behind Search")
	}
	store.unblock()
	if err := <-searchDone; err != nil {
		t.Fatalf("Search(): %v", err)
	}
}

func TestBindAbandonsActiveSameConnectionSearch(t *testing.T) {
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	seedDirectory(t, base)
	store := newResourceLimitStore(base)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:                      store,
		MaxOperationsPerConnection: 2,
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		store.unblock()
		<-done
	})
	client, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	store.enable()
	searchDone := make(chan error, 1)
	go func() {
		_, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		))
		searchDone <- err
	}()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("Search did not enter storage")
	}
	bindDone := make(chan error, 1)
	go func() {
		bindDone <- client.Bind(
			"uid=alice,ou=people,dc=example,dc=com",
			"secret",
		)
	}()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("Bind remained queued behind the abandoned Search")
	}
	store.unblock()
	select {
	case err := <-bindDone:
		if err != nil {
			client.Close()
			t.Fatalf("Bind(): %v", err)
		}
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("Bind did not complete after Search cancellation")
	}
	client.Close()
	select {
	case <-searchDone:
	case <-time.After(time.Second):
		t.Fatal("abandoned Search did not terminate when the connection closed")
	}
}

func TestNewResourceLimitDefaultsAndValidation(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(config *Config) { config.MaxConnections = -1 },
		func(config *Config) { config.MaxConcurrentOperations = -1 },
		func(config *Config) { config.MaxConcurrentHandshakes = -1 },
		func(config *Config) { config.MaxSearchCandidates = -1 },
		func(config *Config) { config.MaxSearchCandidateBytes = -1 },
		func(config *Config) { config.MaxSearchResponseBytes = -1 },
		func(config *Config) { config.MaxOperationsPerConnection = -1 },
		func(config *Config) { config.MaxPendingBytesPerConnection = -1 },
		func(config *Config) { config.MaxPendingOperationBytes = -1 },
		func(config *Config) { config.MaxSearchMemoryBytes = -1 },
		func(config *Config) { config.MaxResponsePDUBytes = -1 },
		func(config *Config) { config.MaxInFlightResponseBytes = -1 },
	} {
		store := storage.NewMemory()
		config := Config{Store: store}
		mutate(&config)
		if _, err := New(config); err == nil {
			store.Close()
			t.Fatal("negative resource limit was accepted")
		}
		store.Close()
	}
	store := storage.NewMemory()
	defer store.Close()
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if instance.config.MaxConnections != defaultMaxConnections ||
		instance.operationLimiter.limit() != defaultMaxConcurrentOperations ||
		instance.handshakeLimiter.limit() != defaultMaxConcurrentHandshakes ||
		instance.config.MaxSearchCandidates != defaultMaxSearchCandidates ||
		instance.config.MaxSearchCandidateBytes != defaultMaxSearchCandidateBytes ||
		instance.config.MaxSearchResponseBytes != defaultMaxSearchResponseBytes ||
		instance.config.MaxOperationsPerConnection != defaultMaxOperationsPerConnection ||
		instance.config.MaxPendingBytesPerConnection != defaultMaxPendingBytesPerConnection ||
		instance.pendingByteLimiter.limit() != defaultMaxPendingOperationBytes ||
		instance.searchMemoryLimiter.limit() != defaultMaxSearchMemoryBytes ||
		instance.config.MaxResponsePDUBytes != defaultMaxResponsePDUBytes ||
		instance.responseByteLimiter.limit() != defaultMaxInFlightResponseBytes {
		t.Fatalf("resource defaults = %#v", instance.config)
	}
	entries := instance.monitorEntries(instance.runtime.Load())
	for dn, want := range map[string][]string{
		"cn=Connections,cn=Monitor": {"maxConnections=4096", "rejectedConnections=0"},
		"cn=Threads,cn=Monitor": {
			"maxConcurrentOperations=256", "activeOperations=0",
			"maxOperationsPerConnection=8",
			"maxPendingBytesPerConnection=67108864",
			"maxPendingOperationBytes=268435456",
			"activePendingOperationBytes=0",
			"maxSearchCandidates=100000", "maxSearchCandidateBytes=67108864",
			"maxSearchResponseBytes=134217728",
			"maxSearchMemoryBytes=536870912",
			"activeSearchMemoryBytes=0",
			"maxResponsePDUBytes=16777216",
			"maxInFlightResponseBytes=268435456",
			"activeInFlightResponseBytes=0",
		},
	} {
		entry := monitorEntryByDN(entries, dn)
		if entry == nil {
			t.Fatalf("monitor entry %s is missing", dn)
		}
		values := byteValuesToStrings(entry.Values("monitoredInfo"))
		for _, value := range want {
			if !slices.Contains(values, value) {
				t.Fatalf("%s monitoredInfo = %q, missing %q", dn, values, value)
			}
		}
	}
}

type resourceLimitSecureTransport struct {
	entered chan struct{}
	release chan struct{}
	active  atomic.Int64
	maximum atomic.Int64
}

func (transport *resourceLimitSecureTransport) ServerHandshake(
	ctx context.Context,
	connection net.Conn,
) (net.Conn, error) {
	active := transport.active.Add(1)
	for {
		maximum := transport.maximum.Load()
		if active <= maximum || transport.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	defer transport.active.Add(-1)
	transport.entered <- struct{}{}
	select {
	case <-transport.release:
		return connection, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type resourceLimitStore struct {
	storage.Store
	enabled atomic.Bool
	active  atomic.Int64
	maximum atomic.Int64
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newResourceLimitStore(store storage.Store) *resourceLimitStore {
	return &resourceLimitStore{
		Store:   store,
		entered: make(chan struct{}, 16),
		release: make(chan struct{}),
	}
}

func (store *resourceLimitStore) enable()  { store.enabled.Store(true) }
func (store *resourceLimitStore) unblock() { store.once.Do(func() { close(store.release) }) }

func (store *resourceLimitStore) View(
	ctx context.Context,
	fn func(storage.Reader) error,
) error {
	if store.enabled.Load() {
		active := store.active.Add(1)
		for {
			maximum := store.maximum.Load()
			if active <= maximum || store.maximum.CompareAndSwap(maximum, active) {
				break
			}
		}
		store.entered <- struct{}{}
		select {
		case <-store.release:
		case <-ctx.Done():
			store.active.Add(-1)
			return ctx.Err()
		}
		store.active.Add(-1)
	}
	return store.Store.View(ctx, fn)
}

func waitForServerConnectionCount(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		server.mu.Lock()
		got := len(server.connections)
		server.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server connections = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func monitorEntryByDN(entries []directory.Entry, dn string) *directory.Entry {
	for index := range entries {
		if strings.EqualFold(entries[index].DN, dn) {
			return &entries[index]
		}
	}
	return nil
}
