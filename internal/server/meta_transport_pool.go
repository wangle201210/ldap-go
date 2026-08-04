package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type metaTransportPoolEntry struct {
	transport  *syncConsumerTransport
	created    time.Time
	lastUsed   time.Time
	references int
	closed     bool
	retired    bool
}

type metaTransportPoolGroup struct {
	owner   string
	entries []*metaTransportPoolEntry
	opening int
	retired bool
}

type metaTransportPool struct {
	mu               sync.Mutex
	groups           map[string]*metaTransportPoolGroup
	activeOwners     map[string]struct{}
	ownersConfigured bool
	changed          chan struct{}
	clock            func() time.Time
	closed           bool
}

type metaTransportPoolLease struct {
	pool      *metaTransportPool
	key       string
	entry     *metaTransportPoolEntry
	reserved  bool
	temporary bool
	settled   bool
}

type metaTransportPoolWriteOutcome struct {
	requestSent bool
	reusable    bool
}

func newMetaTransportPool(clock func() time.Time) *metaTransportPool {
	if clock == nil {
		clock = time.Now
	}
	return &metaTransportPool{
		groups:       make(map[string]*metaTransportPoolGroup),
		activeOwners: make(map[string]struct{}),
		changed:      make(chan struct{}),
		clock:        clock,
	}
}

func (pool *metaTransportPool) acquire(
	ctx context.Context,
	key string,
	remote chainRemoteConfiguration,
	maximum int,
	useTemporary bool,
) (*syncConsumerTransport, *metaTransportPoolLease, error) {
	return pool.acquireOwned(ctx, key, key, remote, maximum, useTemporary)
}

func (pool *metaTransportPool) acquireOwned(
	ctx context.Context,
	key string,
	owner string,
	remote chainRemoteConfiguration,
	maximum int,
	useTemporary bool,
) (*syncConsumerTransport, *metaTransportPoolLease, error) {
	if pool == nil || key == "" {
		return nil, &metaTransportPoolLease{temporary: true}, nil
	}
	if owner == "" {
		owner = key
	}
	if maximum < 1 {
		maximum = 1
	}
	for {
		now := pool.clock()
		var stale []*syncConsumerTransport
		pool.mu.Lock()
		if pool.closed {
			pool.mu.Unlock()
			return nil, nil, errors.New("back-meta transport pool is closed")
		}
		if !pool.ownerActiveLocked(owner) {
			pool.mu.Unlock()
			return nil, &metaTransportPoolLease{
				pool:      pool,
				key:       key,
				temporary: true,
			}, nil
		}
		group := pool.groups[key]
		if group == nil {
			group = &metaTransportPoolGroup{owner: owner}
			pool.groups[key] = group
		} else if group.owner != owner {
			pool.mu.Unlock()
			return nil, nil, errors.New("back-meta transport pool key owner mismatch")
		} else if group.retired {
			pool.mu.Unlock()
			return nil, &metaTransportPoolLease{
				pool:      pool,
				key:       key,
				temporary: true,
			}, nil
		}
		kept := group.entries[:0]
		for _, entry := range group.entries {
			if entry.references == 0 &&
				(entry.retired || metaPoolTransportExpired(entry, remote, now)) {
				entry.closed = true
				stale = append(stale, entry.transport)
				continue
			}
			kept = append(kept, entry)
		}
		group.entries = kept
		if len(stale) > 0 {
			pool.signalLocked()
			pool.mu.Unlock()
			closeMetaPoolTransports(stale)
			continue
		}
		for _, entry := range group.entries {
			if entry.references == 0 && !entry.closed && !entry.retired {
				entry.references++
				lease := &metaTransportPoolLease{
					pool:  pool,
					key:   key,
					entry: entry,
				}
				pool.mu.Unlock()
				return entry.transport, lease, nil
			}
		}
		if len(group.entries)+group.opening < maximum {
			group.opening++
			lease := &metaTransportPoolLease{
				pool:     pool,
				key:      key,
				reserved: true,
			}
			pool.mu.Unlock()
			return nil, lease, nil
		}
		if useTemporary {
			lease := &metaTransportPoolLease{
				pool:      pool,
				key:       key,
				temporary: true,
			}
			pool.mu.Unlock()
			return nil, lease, nil
		}
		for _, entry := range group.entries {
			if !entry.closed && !entry.retired {
				entry.references++
				lease := &metaTransportPoolLease{
					pool:  pool,
					key:   key,
					entry: entry,
				}
				pool.mu.Unlock()
				return entry.transport, lease, nil
			}
		}
		changed := pool.changed
		pool.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-changed:
		}
	}
}

func (pool *metaTransportPool) publish(
	lease *metaTransportPoolLease,
	transport *syncConsumerTransport,
) bool {
	if pool == nil || lease == nil || !lease.reserved || transport == nil {
		return false
	}
	now := pool.clock()
	pool.mu.Lock()
	if lease.settled {
		pool.mu.Unlock()
		return false
	}
	lease.reserved = false
	lease.settled = true
	group := pool.groups[lease.key]
	if group != nil && group.opening > 0 {
		group.opening--
	}
	if pool.closed || group == nil || group.retired ||
		!pool.ownerActiveLocked(group.owner) {
		lease.temporary = true
		pool.removeEmptyGroupLocked(lease.key, group)
		pool.signalLocked()
		pool.mu.Unlock()
		return false
	}
	entry := &metaTransportPoolEntry{
		transport:  transport,
		created:    now,
		lastUsed:   now,
		references: 1,
	}
	group.entries = append(group.entries, entry)
	lease.entry = entry
	pool.signalLocked()
	pool.mu.Unlock()
	return true
}

func (pool *metaTransportPool) abort(lease *metaTransportPoolLease) {
	if pool == nil || lease == nil || !lease.reserved {
		return
	}
	pool.mu.Lock()
	if !lease.settled {
		lease.settled = true
		lease.reserved = false
		if group := pool.groups[lease.key]; group != nil && group.opening > 0 {
			group.opening--
			pool.removeEmptyGroupLocked(lease.key, group)
		}
		pool.signalLocked()
	}
	pool.mu.Unlock()
}

func (pool *metaTransportPool) release(
	lease *metaTransportPoolLease,
	remote chainRemoteConfiguration,
	transport *syncConsumerTransport,
	reusable bool,
) {
	if transport == nil {
		pool.abort(lease)
		return
	}
	if pool == nil || lease == nil || lease.temporary || lease.entry == nil {
		pool.abort(lease)
		_ = transport.close()
		return
	}
	now := pool.clock()
	closeTransport := false
	pool.mu.Lock()
	entry := lease.entry
	if entry.references > 0 {
		entry.references--
	}
	if entry.retired && entry.references == 0 && !entry.closed {
		entry.closed = true
		pool.removeEntryLocked(lease.key, entry)
		closeTransport = true
	} else if reusable && !entry.closed {
		entry.lastUsed = now
	} else if !entry.closed {
		entry.closed = true
		pool.removeEntryLocked(lease.key, entry)
		closeTransport = true
	}
	pool.signalLocked()
	pool.mu.Unlock()
	if closeTransport {
		_ = transport.close()
	}
}

func (pool *metaTransportPool) configureOwners(active map[string]struct{}) {
	if pool == nil {
		return
	}
	configured := make(map[string]struct{}, len(active))
	for owner := range active {
		if owner != "" {
			configured[owner] = struct{}{}
		}
	}
	var transports []*syncConsumerTransport
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return
	}
	pool.activeOwners = configured
	pool.ownersConfigured = true
	transports = pool.retireGroupsLocked(func(owner string) bool {
		_, active := configured[owner]
		return !active
	})
	pool.signalLocked()
	pool.mu.Unlock()
	closeMetaPoolTransports(transports)
}

func (pool *metaTransportPool) retireGroupsLocked(
	retire func(owner string) bool,
) []*syncConsumerTransport {
	var transports []*syncConsumerTransport
	for key, group := range pool.groups {
		if group == nil {
			delete(pool.groups, key)
			continue
		}
		if !retire(group.owner) {
			continue
		}
		group.retired = true
		kept := group.entries[:0]
		for _, entry := range group.entries {
			entry.retired = true
			if entry.references == 0 && !entry.closed {
				entry.closed = true
				transports = append(transports, entry.transport)
				continue
			}
			kept = append(kept, entry)
		}
		group.entries = kept
		if len(group.entries) == 0 && group.opening == 0 {
			delete(pool.groups, key)
		}
	}
	return transports
}

func (pool *metaTransportPool) removeEntryLocked(
	key string,
	entry *metaTransportPoolEntry,
) {
	group := pool.groups[key]
	if group == nil {
		return
	}
	for index, candidate := range group.entries {
		if candidate == entry {
			group.entries = append(group.entries[:index], group.entries[index+1:]...)
			break
		}
	}
	pool.removeEmptyGroupLocked(key, group)
}

func (pool *metaTransportPool) removeEmptyGroupLocked(
	key string,
	group *metaTransportPoolGroup,
) {
	if group != nil && len(group.entries) == 0 && group.opening == 0 &&
		pool.groups[key] == group {
		delete(pool.groups, key)
	}
}

func (pool *metaTransportPool) ownerActiveLocked(owner string) bool {
	if !pool.ownersConfigured {
		return true
	}
	_, active := pool.activeOwners[owner]
	return active
}

func writeMetaTransportPoolPacket(
	ctx context.Context,
	transport *syncConsumerTransport,
	encoded []byte,
) (metaTransportPoolWriteOutcome, error) {
	outcome := metaTransportPoolWriteOutcome{reusable: true}
	if transport == nil {
		outcome.reusable = false
		return outcome, errors.New("write pooled LDAP request: nil transport")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := lockMetaTransportPoolWriter(ctx, &transport.writeMu); err != nil {
		return outcome, err
	}
	defer transport.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return outcome, err
	}

	connection := transport.currentConnection()
	if connection == nil {
		outcome.reusable = false
		return outcome, errors.New("write pooled LDAP request: nil connection")
	}
	deadline := time.Time{}
	if configured, ok := ctx.Deadline(); ok {
		deadline = configured
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		outcome.reusable = false
		return outcome, fmt.Errorf("set pooled LDAP write deadline: %w", err)
	}

	interruptDone := make(chan struct{})
	var interruptErr error
	stopInterrupt := context.AfterFunc(ctx, func() {
		interruptErr = connection.SetWriteDeadline(time.Now())
		if interruptErr != nil {
			_ = connection.Close()
		}
		close(interruptDone)
	})

	written := 0
	var writeErr error
	for written < len(encoded) {
		count, err := connection.Write(encoded[written:])
		if count < 0 || count > len(encoded)-written {
			writeErr = fmt.Errorf("write LDAP request: invalid write count %d", count)
			break
		}
		written += count
		if err != nil {
			writeErr = fmt.Errorf("write LDAP request: %w", err)
			break
		}
		if count == 0 {
			writeErr = fmt.Errorf("write LDAP request: %w", io.ErrShortWrite)
			break
		}
	}
	if written == len(encoded) {
		outcome.requestSent = true
	}
	if !stopInterrupt() {
		<-interruptDone
	}
	clearErr := connection.SetWriteDeadline(time.Time{})

	var cleanupErr error
	if interruptErr != nil {
		cleanupErr = errors.Join(
			cleanupErr,
			fmt.Errorf("interrupt pooled LDAP write: %w", interruptErr),
		)
	}
	if clearErr != nil {
		cleanupErr = errors.Join(
			cleanupErr,
			fmt.Errorf("clear pooled LDAP write deadline: %w", clearErr),
		)
	}
	if writeErr == nil && cleanupErr == nil {
		return outcome, nil
	}
	if writeErr == nil {
		outcome.reusable = false
		return outcome, cleanupErr
	}

	interrupted := ctx.Err() != nil || metaTransportPoolWriteTimedOut(writeErr)
	outcome.reusable = written == 0 && interrupted && cleanupErr == nil
	if ctxErr := ctx.Err(); ctxErr != nil && written == 0 {
		writeErr = errors.Join(ctxErr, writeErr)
	}
	return outcome, errors.Join(writeErr, cleanupErr)
}

func lockMetaTransportPoolWriter(ctx context.Context, mutex *sync.Mutex) error {
	if mutex.TryLock() {
		return nil
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if mutex.TryLock() {
				return nil
			}
		}
	}
}

func metaTransportPoolWriteTimedOut(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func (pool *metaTransportPool) close() {
	if pool == nil {
		return
	}
	var transports []*syncConsumerTransport
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return
	}
	pool.closed = true
	for _, group := range pool.groups {
		for _, entry := range group.entries {
			if !entry.closed {
				entry.closed = true
				transports = append(transports, entry.transport)
			}
		}
	}
	pool.groups = make(map[string]*metaTransportPoolGroup)
	pool.activeOwners = make(map[string]struct{})
	pool.ownersConfigured = false
	pool.signalLocked()
	pool.mu.Unlock()
	closeMetaPoolTransports(transports)
}

func (pool *metaTransportPool) signalLocked() {
	close(pool.changed)
	pool.changed = make(chan struct{})
}

func metaPoolTransportExpired(
	entry *metaTransportPoolEntry,
	remote chainRemoteConfiguration,
	now time.Time,
) bool {
	if entry == nil || entry.transport == nil || entry.closed {
		return true
	}
	if remote.connectionTTL > 0 && !entry.created.Add(remote.connectionTTL).After(now) {
		return true
	}
	return remote.idleTimeout > 0 && !entry.lastUsed.Add(remote.idleTimeout).After(now)
}

func closeMetaPoolTransports(transports []*syncConsumerTransport) {
	for _, transport := range transports {
		if transport != nil {
			_ = transport.close()
		}
	}
}
