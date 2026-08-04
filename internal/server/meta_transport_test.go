package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetaTransportCacheReuseAndExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newMetaTransportCache(func() time.Time { return now })
	client, peer := net.Pipe()
	defer peer.Close()
	transport := &syncConsumerTransport{connection: client, context: context.Background()}
	remote := chainRemoteConfiguration{idleTimeout: 2 * time.Second}

	cache.release("key", remote, transport, true)
	if got := cache.acquire("key", remote); got != transport {
		t.Fatalf("cached transport = %p, want %p", got, transport)
	}
	cache.release("key", remote, transport, true)
	now = now.Add(2 * time.Second)
	if got := cache.acquire("key", remote); got != nil {
		t.Fatalf("expired transport = %p", got)
	}
	cache.close()
}

func TestMetaTransportCacheTemporaryConnectionUsesIdlePrimary(t *testing.T) {
	cache := newMetaTransportCache(time.Now)
	primaryClient, primaryPeer := net.Pipe()
	defer primaryPeer.Close()
	primary := &syncConsumerTransport{
		connection: primaryClient,
		context:    context.Background(),
	}
	remote := chainRemoteConfiguration{useTemporary: true}
	cache.release("key", remote, primary, true)
	if got := cache.acquire("key", remote); got != primary {
		t.Fatalf("cached primary transport = %p, want %p", got, primary)
	}

	temporaryClient, temporaryPeer := net.Pipe()
	temporary := &syncConsumerTransport{
		connection: temporaryClient,
		context:    context.Background(),
	}
	cache.release("key", remote, temporary, true)
	_ = temporaryPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := temporaryPeer.Read([]byte{0}); err == nil {
		t.Fatal("busy-primary temporary transport peer did not observe close")
	}
	_ = temporaryPeer.Close()

	cache.release("key", remote, primary, true)
	if got := cache.acquire("key", remote); got != primary {
		t.Fatalf("released primary transport = %p, want %p", got, primary)
	}
	cache.release("key", remote, primary, true)
	cache.close()
}

func TestMetaTransportCacheConfigureOwnersRetiresIdleTransport(t *testing.T) {
	cache := newMetaTransportCache(time.Now)
	transport, connection := newMetaCacheTestTransport()
	remote := defaultChainRemoteConfiguration()
	active := map[string]struct{}{"generation-1": {}}

	cache.releaseOwned("key", "generation-1", remote, transport, true)
	cache.configureOwners(active)
	delete(active, "generation-1")
	active["generation-2"] = struct{}{}
	if got := cache.acquireOwned("key", "generation-1", remote); got != transport {
		t.Fatalf("transport after caller mutated active map = %p, want %p", got, transport)
	}
	cache.releaseOwned("key", "generation-1", remote, transport, true)

	cache.configureOwners(map[string]struct{}{"generation-2": {}})
	assertMetaCacheConnectionClosed(t, connection)
	if got := cache.acquireOwned("key", "generation-1", remote); got != nil {
		t.Fatalf("retired owner acquired transport %p", got)
	}
	cache.mu.Lock()
	entryCount := len(cache.entries)
	activeCount := len(cache.activeOwners)
	cache.mu.Unlock()
	if entryCount != 0 {
		t.Fatalf("entries after idle retirement = %d, want 0", entryCount)
	}
	if activeCount != 1 {
		t.Fatalf("active owners after replacement = %d, want 1", activeCount)
	}
}

func TestMetaTransportCacheFirstEmptyOwnerConfigurationEnablesPolicy(t *testing.T) {
	cache := newMetaTransportCache(time.Now)
	cache.configureOwners(nil)
	transport, connection := newMetaCacheTestTransport()
	cache.releaseOwned(
		"key",
		"generation-1",
		defaultChainRemoteConfiguration(),
		transport,
		true,
	)
	assertMetaCacheConnectionClosed(t, connection)
	if calls := connection.closeCalls.Load(); calls != 1 {
		t.Fatalf("transport close calls = %d, want 1", calls)
	}
	cache.mu.Lock()
	configured := cache.ownersConfigured
	entryCount := len(cache.entries)
	cache.mu.Unlock()
	if !configured || entryCount != 0 {
		t.Fatalf(
			"empty owner policy state = (configured %t, entries %d), want true, 0",
			configured,
			entryCount,
		)
	}
}

func TestMetaTransportCacheRetiresInUseTransportOnFinalRelease(t *testing.T) {
	cache := newMetaTransportCache(time.Now)
	remote := defaultChainRemoteConfiguration()
	cache.configureOwners(map[string]struct{}{"generation-1": {}})
	transport, connection := newMetaCacheTestTransport()
	cache.releaseOwned("key", "generation-1", remote, transport, true)
	if got := cache.acquireOwned("key", "generation-1", remote); got != transport {
		t.Fatalf("acquired transport = %p, want %p", got, transport)
	}

	cache.configureOwners(map[string]struct{}{"generation-2": {}})
	assertMetaCacheConnectionOpen(t, connection)
	cache.mu.Lock()
	entry := cache.entries["key"]
	cache.mu.Unlock()
	if entry == nil || !entry.retired || !entry.inUse {
		t.Fatalf("retired in-use entry = %#v", entry)
	}
	if got := cache.acquireOwned("key", "generation-1", remote); got != nil {
		t.Fatalf("late retired-owner acquire = %p, want nil", got)
	}

	lateTransport, lateConnection := newMetaCacheTestTransport()
	cache.releaseOwned("late", "generation-1", remote, lateTransport, true)
	assertMetaCacheConnectionClosed(t, lateConnection)

	cache.releaseOwned("key", "generation-1", remote, transport, true)
	assertMetaCacheConnectionClosed(t, connection)
	if calls := connection.closeCalls.Load(); calls != 1 {
		t.Fatalf("retired transport close calls = %d, want 1", calls)
	}
	cache.mu.Lock()
	_, exists := cache.entries["key"]
	cache.mu.Unlock()
	if exists {
		t.Fatal("retired in-use entry remains after final release")
	}

	current, currentConnection := newMetaCacheTestTransport()
	cache.releaseOwned("key", "generation-2", remote, current, true)
	assertMetaCacheConnectionOpen(t, currentConnection)
	if got := cache.acquireOwned("key", "generation-2", remote); got != current {
		t.Fatalf("current owner acquired transport = %p, want %p", got, current)
	}
	cache.releaseOwned("key", "generation-2", remote, current, true)
	cache.close()
	assertMetaCacheConnectionClosed(t, currentConnection)
}

func TestMetaTransportCacheRejectsOpenCompletedAfterOwnerRetirement(t *testing.T) {
	cache := newMetaTransportCache(time.Now)
	remote := defaultChainRemoteConfiguration()
	cache.configureOwners(map[string]struct{}{"generation-1": {}})
	if got := cache.acquireOwned("key", "generation-1", remote); got != nil {
		t.Fatalf("initial empty acquire = %p, want nil", got)
	}

	cache.configureOwners(map[string]struct{}{"generation-2": {}})
	opened, connection := newMetaCacheTestTransport()
	cache.releaseOwned("key", "generation-1", remote, opened, true)
	assertMetaCacheConnectionClosed(t, connection)
	cache.mu.Lock()
	entryCount := len(cache.entries)
	cache.mu.Unlock()
	if entryCount != 0 {
		t.Fatalf("entries after late open completed = %d, want 0", entryCount)
	}
}

func TestMetaTransportCacheCloseAndOwnerLifecycleConcurrent(t *testing.T) {
	cache := newMetaTransportCache(time.Now)
	remote := defaultChainRemoteConfiguration()
	const (
		workers    = 8
		iterations = 300
	)
	owners := []string{"generation-1", "generation-2"}
	cache.configureOwners(map[string]struct{}{
		owners[0]: {},
		owners[1]: {},
	})

	start := make(chan struct{})
	progress := make(chan struct{}, workers)
	var wait sync.WaitGroup
	var connectionsMu sync.Mutex
	var connections []*metaCacheTestConnection
	newTransport := func() *syncConsumerTransport {
		transport, connection := newMetaCacheTestTransport()
		connectionsMu.Lock()
		connections = append(connections, connection)
		connectionsMu.Unlock()
		return transport
	}

	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				owner := owners[(worker+iteration)%len(owners)]
				transport := cache.acquireOwned("shared", owner, remote)
				if transport == nil {
					transport = newTransport()
				}
				cache.releaseOwned("shared", owner, remote, transport, true)
				if iteration == 20 {
					progress <- struct{}{}
				}
			}
		}()
	}

	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		for iteration := 0; iteration < iterations; iteration++ {
			owner := owners[iteration%len(owners)]
			cache.configureOwners(map[string]struct{}{owner: {}})
		}
	}()
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		for range workers {
			<-progress
		}
		cache.close()
	}()

	close(start)
	wait.Wait()
	cache.close()
	cache.mu.Lock()
	entryCount := len(cache.entries)
	closed := cache.closed
	cache.mu.Unlock()
	if !closed || entryCount != 0 {
		t.Fatalf("closed cache state = (closed %t, entries %d), want true, 0", closed, entryCount)
	}
	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	for index, connection := range connections {
		select {
		case <-connection.closed:
		default:
			t.Fatalf("transport connection %d remains open", index)
		}
	}
}

func TestMetaTransportKeyIncludesCredentials(t *testing.T) {
	first := defaultChainRemoteConfiguration()
	first.endpointKey = "ldap://provider"
	first.uri = "ldap://provider"
	first.bind.bindMethod = "simple"
	first.bind.bindDN = "cn=proxy,dc=example,dc=com"
	first.bind.credentials = []byte("first")
	second := first.clone()
	second.bind.credentials = []byte("second")
	if metaTransportKey("target", first) == metaTransportKey("target", second) {
		t.Fatal("transport cache key does not include credentials")
	}
}

type metaCacheTestConnection struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newMetaCacheTestTransport() (*syncConsumerTransport, *metaCacheTestConnection) {
	connection := &metaCacheTestConnection{closed: make(chan struct{})}
	return &syncConsumerTransport{
		connection: connection,
		context:    context.Background(),
	}, connection
}

func (connection *metaCacheTestConnection) Read([]byte) (int, error) {
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *metaCacheTestConnection) Write(encoded []byte) (int, error) {
	select {
	case <-connection.closed:
		return 0, net.ErrClosed
	default:
		return len(encoded), nil
	}
}

func (connection *metaCacheTestConnection) Close() error {
	connection.closeCalls.Add(1)
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*metaCacheTestConnection) LocalAddr() net.Addr {
	return metaCacheTestAddress("local")
}

func (*metaCacheTestConnection) RemoteAddr() net.Addr {
	return metaCacheTestAddress("remote")
}

func (*metaCacheTestConnection) SetDeadline(time.Time) error      { return nil }
func (*metaCacheTestConnection) SetReadDeadline(time.Time) error  { return nil }
func (*metaCacheTestConnection) SetWriteDeadline(time.Time) error { return nil }

type metaCacheTestAddress string

func (address metaCacheTestAddress) Network() string { return "test" }
func (address metaCacheTestAddress) String() string  { return string(address) }

func assertMetaCacheConnectionOpen(t *testing.T, connection *metaCacheTestConnection) {
	t.Helper()
	select {
	case <-connection.closed:
		t.Fatal("transport connection is closed, want open")
	default:
	}
}

func assertMetaCacheConnectionClosed(t *testing.T, connection *metaCacheTestConnection) {
	t.Helper()
	select {
	case <-connection.closed:
	default:
		t.Fatal("transport connection is open, want closed")
	}
}
