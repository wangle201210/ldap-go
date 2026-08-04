package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestServeGracefulShutdownCompletesInFlightWrite(t *testing.T) {
	t.Parallel()

	baseStore := storage.NewMemory()
	t.Cleanup(func() { _ = baseStore.Close() })
	seedDirectory(t, baseStore)
	store := newShutdownBlockingStore(baseStore)
	instance, address, cancel, done := startShutdownTestServer(
		t,
		store,
		2*time.Second,
	)
	_ = instance

	client := dialLDAPRoot(t, address)
	defer client.Close()
	gate := store.blockNextUpdate()
	addDone := make(chan error, 1)
	go func() {
		addDone <- client.Add(newPersonAddRequest("graceful"))
	}()
	gate.wait(t)

	cancel()
	select {
	case err := <-done:
		t.Fatalf("Serve() returned before the write completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	gate.unblock()
	if err := <-addDone; err != nil {
		t.Fatalf("in-flight Add(): %v", err)
	}
	if err := waitShutdownResult(t, done); err != nil {
		t.Fatalf("Serve(): %v", err)
	}

	dn, err := directory.ParseDN(
		"uid=graceful,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := baseStore.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	}); err != nil {
		t.Fatalf("read committed graceful Add: %v", err)
	}
}

func TestServeGracefulShutdownForcesTimedOutWrite(t *testing.T) {
	t.Parallel()

	baseStore := storage.NewMemory()
	t.Cleanup(func() { _ = baseStore.Close() })
	seedDirectory(t, baseStore)
	store := newShutdownBlockingStore(baseStore)
	_, address, cancel, done := startShutdownTestServer(
		t,
		store,
		50*time.Millisecond,
	)

	client := dialLDAPRoot(t, address)
	defer client.Close()
	gate := store.blockNextUpdate()
	addDone := make(chan error, 1)
	go func() {
		addDone <- client.Add(newPersonAddRequest("timed-out"))
	}()
	gate.wait(t)
	cancel()

	serveErr := waitShutdownResult(t, done)
	if !errors.Is(serveErr, ErrShutdownTimeout) {
		t.Fatalf("Serve() error = %v, want ErrShutdownTimeout", serveErr)
	}
	if err := <-addDone; err == nil {
		t.Fatal("timed-out Add unexpectedly succeeded")
	}
	gate.unblock()

	dn, err := directory.ParseDN(
		"uid=timed-out,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	err = baseStore.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("timed-out Add lookup error = %v, want entry not found", err)
	}
}

func TestServeGracefulShutdownAbandonsPersistentSync(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	_, address, cancel, done := startShutdownTestServer(
		t,
		store,
		500*time.Millisecond,
	)

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
	)
	for {
		message := readRawSyncMessage(t, connection, 2)
		if message.entry != nil {
			continue
		}
		if message.info != nil &&
			message.info.Kind == ldapwire.SyncInfoRefreshPresent &&
			message.info.RefreshDone {
			break
		}
		t.Fatalf("unexpected persistent refresh response = %#v", message)
	}

	cancel()
	if err := waitShutdownResult(t, done); err != nil {
		t.Fatalf("Serve(): %v", err)
	}
}

func TestNewRejectsNegativeShutdownTimeout(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := New(Config{
		Store:           store,
		ShutdownTimeout: -time.Second,
	}); err == nil {
		t.Fatal("New() accepted a negative shutdown timeout")
	}
}

func startShutdownTestServer(
	t *testing.T,
	store storage.Store,
	shutdownTimeout time.Duration,
) (*Server, string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := New(Config{
		Store:           store,
		RootDN:          syncTestRootDN,
		RootPassword:    []byte(syncTestRootPassword),
		ShutdownTimeout: shutdownTimeout,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	return instance, listener.Addr().String(), cancel, done
}

func waitShutdownResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish shutdown")
		return nil
	}
}

type shutdownWriteGate struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	claimed bool
}

func (gate *shutdownWriteGate) wait(t *testing.T) {
	t.Helper()
	select {
	case <-gate.started:
	case <-time.After(2 * time.Second):
		t.Fatal("write did not reach the storage gate")
	}
}

func (gate *shutdownWriteGate) unblock() {
	gate.once.Do(func() {
		close(gate.release)
	})
}

type shutdownBlockingStore struct {
	storage.Store

	mu   sync.Mutex
	gate *shutdownWriteGate
}

func newShutdownBlockingStore(store storage.Store) *shutdownBlockingStore {
	return &shutdownBlockingStore{Store: store}
}

func (store *shutdownBlockingStore) blockNextUpdate() *shutdownWriteGate {
	store.mu.Lock()
	defer store.mu.Unlock()
	gate := &shutdownWriteGate{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	store.gate = gate
	return gate
}

func (store *shutdownBlockingStore) Update(
	ctx context.Context,
	fn func(storage.Writer) error,
) error {
	store.mu.Lock()
	gate := store.gate
	if gate == nil || gate.claimed {
		store.mu.Unlock()
		return store.Store.Update(ctx, fn)
	}
	gate.claimed = true
	close(gate.started)
	store.mu.Unlock()

	select {
	case <-gate.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	store.mu.Lock()
	if store.gate == gate {
		store.gate = nil
	}
	store.mu.Unlock()
	return store.Store.Update(ctx, fn)
}
