package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetaTransportPoolCapacityAndBusyReuse(t *testing.T) {
	pool := newMetaTransportPool(nil)
	remote := chainRemoteConfiguration{}
	first, firstConnection := newMetaPoolTestTransport()
	second, secondConnection := newMetaPoolTestTransport()

	transport, firstLease, err := pool.acquire(
		context.Background(), "target", remote, 2, false,
	)
	if err != nil {
		t.Fatalf("reserve first transport: %v", err)
	}
	if transport != nil || firstLease == nil || !firstLease.reserved {
		t.Fatalf("first reservation = (%p, %#v)", transport, firstLease)
	}
	if !pool.publish(firstLease, first) {
		t.Fatal("publish first transport = false")
	}

	transport, secondLease, err := pool.acquire(
		context.Background(), "target", remote, 2, false,
	)
	if err != nil {
		t.Fatalf("reserve second transport: %v", err)
	}
	if transport != nil || secondLease == nil || !secondLease.reserved {
		t.Fatalf("second reservation = (%p, %#v)", transport, secondLease)
	}
	if !pool.publish(secondLease, second) {
		t.Fatal("publish second transport = false")
	}

	busy, busyLease, err := pool.acquire(
		context.Background(), "target", remote, 2, false,
	)
	if err != nil {
		t.Fatalf("acquire at capacity: %v", err)
	}
	if busy != first {
		t.Fatalf("busy transport = %p, want first %p", busy, first)
	}
	if busyLease == nil || busyLease.entry != firstLease.entry {
		t.Fatalf("busy lease = %#v, want first pool entry", busyLease)
	}

	pool.mu.Lock()
	group := pool.groups["target"]
	entryCount, opening := len(group.entries), group.opening
	firstReferences := firstLease.entry.references
	pool.mu.Unlock()
	if entryCount != 2 || opening != 0 {
		t.Fatalf("pool state = %d entries, %d opening; want 2, 0", entryCount, opening)
	}
	if firstReferences != 2 {
		t.Fatalf("busy transport references = %d, want 2", firstReferences)
	}

	pool.release(busyLease, remote, busy, true)
	pool.release(firstLease, remote, first, true)
	pool.release(secondLease, remote, second, true)
	assertMetaPoolConnectionOpen(t, firstConnection)
	assertMetaPoolConnectionOpen(t, secondConnection)
	pool.close()
	assertMetaPoolConnectionClosed(t, firstConnection)
	assertMetaPoolConnectionClosed(t, secondConnection)
}

func TestMetaTransportPoolTemporaryTransportIsNotPooled(t *testing.T) {
	pool := newMetaTransportPool(nil)
	remote := chainRemoteConfiguration{}
	primary, primaryConnection := newMetaPoolTestTransport()

	_, primaryLease, err := pool.acquire(
		context.Background(), "target", remote, 1, false,
	)
	if err != nil {
		t.Fatalf("reserve primary transport: %v", err)
	}
	if !pool.publish(primaryLease, primary) {
		t.Fatal("publish primary transport = false")
	}

	transport, temporaryLease, err := pool.acquire(
		context.Background(), "target", remote, 1, true,
	)
	if err != nil {
		t.Fatalf("acquire temporary transport: %v", err)
	}
	if transport != nil || temporaryLease == nil || !temporaryLease.temporary {
		t.Fatalf("temporary reservation = (%p, %#v)", transport, temporaryLease)
	}
	temporary, temporaryConnection := newMetaPoolTestTransport()
	pool.release(temporaryLease, remote, temporary, true)
	assertMetaPoolConnectionClosed(t, temporaryConnection)

	pool.release(primaryLease, remote, primary, true)
	reused, reusedLease, err := pool.acquire(
		context.Background(), "target", remote, 1, false,
	)
	if err != nil {
		t.Fatalf("reacquire primary transport: %v", err)
	}
	if reused != primary {
		t.Fatalf("reused transport = %p, want primary %p", reused, primary)
	}
	pool.mu.Lock()
	entryCount := len(pool.groups["target"].entries)
	pool.mu.Unlock()
	if entryCount != 1 {
		t.Fatalf("pooled transport count = %d, want 1", entryCount)
	}
	pool.release(reusedLease, remote, reused, true)
	pool.close()
	assertMetaPoolConnectionClosed(t, primaryConnection)
}

func TestMetaTransportPoolExpiresIdleAndTTLTransports(t *testing.T) {
	t.Run("idle timeout", func(t *testing.T) {
		now := time.Unix(100, 0)
		pool := newMetaTransportPool(func() time.Time { return now })
		remote := chainRemoteConfiguration{idleTimeout: 2 * time.Second}
		transport, connection := newMetaPoolTestTransport()

		_, lease, err := pool.acquire(
			context.Background(), "target", remote, 1, false,
		)
		if err != nil {
			t.Fatalf("reserve transport: %v", err)
		}
		if !pool.publish(lease, transport) {
			t.Fatal("publish transport = false")
		}
		pool.release(lease, remote, transport, true)
		now = now.Add(remote.idleTimeout)

		got, replacement, err := pool.acquire(
			context.Background(), "target", remote, 1, false,
		)
		if err != nil {
			t.Fatalf("acquire after idle timeout: %v", err)
		}
		if got != nil || replacement == nil || !replacement.reserved {
			t.Fatalf("idle replacement = (%p, %#v)", got, replacement)
		}
		assertMetaPoolConnectionClosed(t, connection)
		pool.abort(replacement)
		pool.close()
	})

	t.Run("connection TTL", func(t *testing.T) {
		now := time.Unix(200, 0)
		pool := newMetaTransportPool(func() time.Time { return now })
		remote := chainRemoteConfiguration{
			idleTimeout:   time.Hour,
			connectionTTL: 3 * time.Second,
		}
		transport, connection := newMetaPoolTestTransport()

		_, lease, err := pool.acquire(
			context.Background(), "target", remote, 1, false,
		)
		if err != nil {
			t.Fatalf("reserve transport: %v", err)
		}
		if !pool.publish(lease, transport) {
			t.Fatal("publish transport = false")
		}
		now = now.Add(time.Second)
		pool.release(lease, remote, transport, true)
		now = now.Add(2 * time.Second)

		got, replacement, err := pool.acquire(
			context.Background(), "target", remote, 1, false,
		)
		if err != nil {
			t.Fatalf("acquire after connection TTL: %v", err)
		}
		if got != nil || replacement == nil || !replacement.reserved {
			t.Fatalf("TTL replacement = (%p, %#v)", got, replacement)
		}
		assertMetaPoolConnectionClosed(t, connection)
		pool.abort(replacement)
		pool.close()
	})
}

func TestMetaTransportPoolContextAndCloseWakeWaiters(t *testing.T) {
	t.Run("context cancellation", func(t *testing.T) {
		pool := newMetaTransportPool(nil)
		remote := chainRemoteConfiguration{}
		_, opening, err := pool.acquire(
			context.Background(), "target", remote, 1, false,
		)
		if err != nil {
			t.Fatalf("reserve opening transport: %v", err)
		}

		ctx := newMetaPoolObservedContext()
		result := make(chan metaPoolAcquireResult, 1)
		go func() {
			transport, lease, acquireErr := pool.acquire(
				ctx, "target", remote, 1, false,
			)
			result <- metaPoolAcquireResult{transport, lease, acquireErr}
		}()
		awaitMetaPoolSignal(t, ctx.observed, "waiter entering context select")
		select {
		case completed := <-result:
			t.Fatalf("waiting acquire completed before cancellation: %#v", completed)
		default:
		}
		ctx.cancel()
		completed := awaitMetaPoolAcquireResult(t, result)
		if !errors.Is(completed.err, context.Canceled) {
			t.Fatalf("waiting acquire error = %v, want context.Canceled", completed.err)
		}
		if completed.transport != nil || completed.lease != nil {
			t.Fatalf("canceled acquire = (%p, %#v)", completed.transport, completed.lease)
		}
		pool.abort(opening)
		pool.close()
	})

	t.Run("pool close", func(t *testing.T) {
		pool := newMetaTransportPool(nil)
		remote := chainRemoteConfiguration{}
		_, _, err := pool.acquire(
			context.Background(), "target", remote, 1, false,
		)
		if err != nil {
			t.Fatalf("reserve opening transport: %v", err)
		}

		ctx := newMetaPoolObservedContext()
		result := make(chan metaPoolAcquireResult, 1)
		go func() {
			transport, lease, acquireErr := pool.acquire(
				ctx, "target", remote, 1, false,
			)
			result <- metaPoolAcquireResult{transport, lease, acquireErr}
		}()
		awaitMetaPoolSignal(t, ctx.observed, "waiter entering context select")
		pool.close()
		completed := awaitMetaPoolAcquireResult(t, result)
		if completed.err == nil || completed.err.Error() != "back-meta transport pool is closed" {
			t.Fatalf("acquire after close error = %v", completed.err)
		}
		if completed.transport != nil || completed.lease != nil {
			t.Fatalf("closed-pool acquire = (%p, %#v)", completed.transport, completed.lease)
		}
	})

	t.Run("close pooled transport", func(t *testing.T) {
		pool := newMetaTransportPool(nil)
		remote := chainRemoteConfiguration{}
		transport, connection := newMetaPoolTestTransport()
		_, lease, err := pool.acquire(
			context.Background(), "target", remote, 1, false,
		)
		if err != nil {
			t.Fatalf("reserve transport: %v", err)
		}
		if !pool.publish(lease, transport) {
			t.Fatal("publish transport = false")
		}
		pool.close()
		assertMetaPoolConnectionClosed(t, connection)
		pool.release(lease, remote, transport, true)
	})
}

func TestMetaTransportPoolRetiresConfigurationOwners(t *testing.T) {
	pool := newMetaTransportPool(nil)
	t.Cleanup(pool.close)
	remote := defaultChainRemoteConfiguration()
	const (
		key      = "retired-key"
		owner    = "target-generation-1"
		newOwner = "target-generation-2"
	)
	pool.configureOwners(map[string]struct{}{owner: {}})

	transport, connection := newMetaPoolTestTransport()
	pooled, firstLease, err := pool.acquireOwned(
		context.Background(), key, owner, remote, 1, false,
	)
	if err != nil || pooled != nil || firstLease == nil || !firstLease.reserved {
		t.Fatalf("initial reservation = (%p, %#v, %v)", pooled, firstLease, err)
	}
	if !pool.publish(firstLease, transport) {
		t.Fatal("publish initial transport = false")
	}
	pooled, secondLease, err := pool.acquireOwned(
		context.Background(), key, owner, remote, 1, false,
	)
	if err != nil || pooled != transport || secondLease == nil {
		t.Fatalf("shared acquire = (%p, %#v, %v)", pooled, secondLease, err)
	}

	pool.configureOwners(map[string]struct{}{newOwner: {}})
	assertMetaPoolConnectionOpen(t, connection)
	pool.release(firstLease, remote, transport, true)
	assertMetaPoolConnectionOpen(t, connection)

	retiredTransport, retiredLease, err := pool.acquireOwned(
		context.Background(), key, owner, remote, 1, false,
	)
	if err != nil || retiredTransport != nil || retiredLease == nil ||
		!retiredLease.temporary {
		t.Fatalf("retired acquire = (%p, %#v, %v)", retiredTransport, retiredLease, err)
	}

	pool.release(secondLease, remote, transport, true)
	assertMetaPoolConnectionClosed(t, connection)
	pool.mu.Lock()
	_, oldGroupExists := pool.groups[key]
	pool.mu.Unlock()
	if oldGroupExists {
		t.Fatal("retired pool group still exists after its final release")
	}

	newTransport, newConnection := newMetaPoolTestTransport()
	pooled, newLease, err := pool.acquireOwned(
		context.Background(), key, newOwner, remote, 1, false,
	)
	if err != nil || pooled != nil || newLease == nil || !newLease.reserved {
		t.Fatalf("new owner reservation = (%p, %#v, %v)", pooled, newLease, err)
	}
	if !pool.publish(newLease, newTransport) {
		t.Fatal("publish new owner transport = false")
	}
	pool.release(newLease, remote, newTransport, true)
	assertMetaPoolConnectionOpen(t, newConnection)
}

func TestMetaTransportPoolRejectsPublishForRetiredOwner(t *testing.T) {
	pool := newMetaTransportPool(nil)
	t.Cleanup(pool.close)
	remote := defaultChainRemoteConfiguration()
	const owner = "retired-opening-owner"
	pool.configureOwners(map[string]struct{}{owner: {}})

	_, lease, err := pool.acquireOwned(
		context.Background(), "retired-opening-key", owner, remote, 1, false,
	)
	if err != nil || lease == nil || !lease.reserved {
		t.Fatalf("opening reservation = (%#v, %v)", lease, err)
	}
	pool.configureOwners(nil)
	transport, connection := newMetaPoolTestTransport()
	if pool.publish(lease, transport) {
		t.Fatal("publish for retired owner = true")
	}
	pool.mu.Lock()
	_, groupExists := pool.groups["retired-opening-key"]
	pool.mu.Unlock()
	if groupExists {
		t.Fatal("retired opening group still exists after rejected publish")
	}
	pool.release(lease, remote, transport, true)
	assertMetaPoolConnectionClosed(t, connection)
}

func TestMetaTransportPoolConfigureOwnersClosesIdleEntriesImmediately(t *testing.T) {
	pool := newMetaTransportPool(nil)
	t.Cleanup(pool.close)
	remote := defaultChainRemoteConfiguration()
	const owner = "idle-owner"
	pool.configureOwners(map[string]struct{}{owner: {}})

	transport, connection := newMetaPoolTestTransport()
	_, lease, err := pool.acquireOwned(
		context.Background(), "idle-key", owner, remote, 1, false,
	)
	if err != nil || lease == nil || !lease.reserved {
		t.Fatalf("idle reservation = (%#v, %v)", lease, err)
	}
	if !pool.publish(lease, transport) {
		t.Fatal("publish idle transport = false")
	}
	pool.release(lease, remote, transport, true)
	assertMetaPoolConnectionOpen(t, connection)

	pool.configureOwners(nil)
	assertMetaPoolConnectionClosed(t, connection)
	pool.mu.Lock()
	groupCount := len(pool.groups)
	pool.mu.Unlock()
	if groupCount != 0 {
		t.Fatalf("pool groups after idle retirement = %d, want 0", groupCount)
	}
}

func TestMetaTransportPoolConfiguredOwnersRemainBounded(t *testing.T) {
	pool := newMetaTransportPool(nil)
	t.Cleanup(pool.close)
	remote := defaultChainRemoteConfiguration()
	const generations = 128

	var previousOwner string
	var previousConnection *metaPoolTestConnection
	for generation := 0; generation < generations; generation++ {
		owner := fmt.Sprintf("owner-generation-%d", generation)
		key := fmt.Sprintf("key-generation-%d", generation)
		pool.configureOwners(map[string]struct{}{owner: {}})
		if previousConnection != nil {
			assertMetaPoolConnectionClosed(t, previousConnection)
			stale, staleLease, err := pool.acquireOwned(
				context.Background(), "stale-key", previousOwner, remote, 1, false,
			)
			if err != nil || stale != nil || staleLease == nil || !staleLease.temporary {
				t.Fatalf(
					"generation %d stale acquire = (%p, %#v, %v)",
					generation, stale, staleLease, err,
				)
			}
		}

		pool.mu.Lock()
		activeCount := len(pool.activeOwners)
		_, ownerActive := pool.activeOwners[owner]
		configured := pool.ownersConfigured
		pool.mu.Unlock()
		if !configured || activeCount != 1 || !ownerActive {
			t.Fatalf(
				"generation %d active owners = (%t, %d, %t), want (true, 1, true)",
				generation, configured, activeCount, ownerActive,
			)
		}

		transport, connection := newMetaPoolTestTransport()
		_, lease, err := pool.acquireOwned(
			context.Background(), key, owner, remote, 1, false,
		)
		if err != nil || lease == nil || !lease.reserved {
			t.Fatalf("generation %d reservation = (%#v, %v)", generation, lease, err)
		}
		if !pool.publish(lease, transport) {
			t.Fatalf("generation %d publish = false", generation)
		}
		pool.release(lease, remote, transport, true)
		previousOwner = owner
		previousConnection = connection
	}

	pool.configureOwners(nil)
	assertMetaPoolConnectionClosed(t, previousConnection)
	pool.mu.Lock()
	activeCount := len(pool.activeOwners)
	groupCount := len(pool.groups)
	pool.mu.Unlock()
	if activeCount != 0 || groupCount != 0 {
		t.Fatalf("final pool state = %d owners, %d groups; want 0, 0", activeCount, groupCount)
	}
}

type metaPoolAcquireResult struct {
	transport *syncConsumerTransport
	lease     *metaTransportPoolLease
	err       error
}

type metaPoolObservedContext struct {
	context.Context
	done        chan struct{}
	observed    chan struct{}
	observeOnce sync.Once
	cancelOnce  sync.Once
	canceled    atomic.Bool
}

func newMetaPoolObservedContext() *metaPoolObservedContext {
	return &metaPoolObservedContext{
		Context:  context.Background(),
		done:     make(chan struct{}),
		observed: make(chan struct{}),
	}
}

func (ctx *metaPoolObservedContext) Done() <-chan struct{} {
	ctx.observeOnce.Do(func() { close(ctx.observed) })
	return ctx.done
}

func (ctx *metaPoolObservedContext) Err() error {
	if ctx.canceled.Load() {
		return context.Canceled
	}
	return nil
}

func (ctx *metaPoolObservedContext) cancel() {
	ctx.cancelOnce.Do(func() {
		ctx.canceled.Store(true)
		close(ctx.done)
	})
}

type metaPoolTestConnection struct {
	closed chan struct{}
	once   sync.Once
}

func newMetaPoolTestTransport() (*syncConsumerTransport, *metaPoolTestConnection) {
	connection := &metaPoolTestConnection{closed: make(chan struct{})}
	return &syncConsumerTransport{
		connection: connection,
		context:    context.Background(),
	}, connection
}

func (connection *metaPoolTestConnection) Read([]byte) (int, error) {
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *metaPoolTestConnection) Write(encoded []byte) (int, error) {
	select {
	case <-connection.closed:
		return 0, net.ErrClosed
	default:
		return len(encoded), nil
	}
}

func (connection *metaPoolTestConnection) Close() error {
	connection.once.Do(func() { close(connection.closed) })
	return nil
}

func (*metaPoolTestConnection) LocalAddr() net.Addr              { return metaPoolTestAddress("local") }
func (*metaPoolTestConnection) RemoteAddr() net.Addr             { return metaPoolTestAddress("remote") }
func (*metaPoolTestConnection) SetDeadline(time.Time) error      { return nil }
func (*metaPoolTestConnection) SetReadDeadline(time.Time) error  { return nil }
func (*metaPoolTestConnection) SetWriteDeadline(time.Time) error { return nil }

type metaPoolTestAddress string

func (address metaPoolTestAddress) Network() string { return "test" }
func (address metaPoolTestAddress) String() string  { return string(address) }

func assertMetaPoolConnectionOpen(t *testing.T, connection *metaPoolTestConnection) {
	t.Helper()
	select {
	case <-connection.closed:
		t.Fatal("transport connection is closed, want open")
	default:
	}
}

func assertMetaPoolConnectionClosed(t *testing.T, connection *metaPoolTestConnection) {
	t.Helper()
	select {
	case <-connection.closed:
	default:
		t.Fatal("transport connection is open, want closed")
	}
}

func awaitMetaPoolSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitMetaPoolAcquireResult(
	t *testing.T,
	result <-chan metaPoolAcquireResult,
) metaPoolAcquireResult {
	t.Helper()
	select {
	case completed := <-result:
		return completed
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pool acquire")
		return metaPoolAcquireResult{}
	}
}
