package server

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const asyncMetaTransportOwnerMarker = "\x00async-metaconn="

type metaTransportCacheEntry struct {
	transport *syncConsumerTransport
	owner     string
	created   time.Time
	lastUsed  time.Time
	inUse     bool
	retired   bool
	closed    bool
}

type metaTransportCache struct {
	mu               sync.Mutex
	entries          map[string]*metaTransportCacheEntry
	activeOwners     map[string]struct{}
	ownersConfigured bool
	closed           bool
	clock            func() time.Time
}

func newMetaTransportCache(clock func() time.Time) *metaTransportCache {
	if clock == nil {
		clock = time.Now
	}
	return &metaTransportCache{
		entries:      make(map[string]*metaTransportCacheEntry),
		activeOwners: make(map[string]struct{}),
		clock:        clock,
	}
}

func (cache *metaTransportCache) acquire(
	key string,
	remote chainRemoteConfiguration,
) *syncConsumerTransport {
	return cache.acquireOwned(key, key, remote)
}

func (cache *metaTransportCache) acquireOwned(
	key string,
	owner string,
	remote chainRemoteConfiguration,
) *syncConsumerTransport {
	if cache == nil || key == "" {
		return nil
	}
	if owner == "" {
		owner = key
	}
	now := cache.clock()
	var stale *syncConsumerTransport
	cache.mu.Lock()
	if cache.closed || !cache.ownerActiveLocked(owner) {
		cache.mu.Unlock()
		return nil
	}
	entry := cache.entries[key]
	if entry != nil && !entry.inUse &&
		(entry.owner != owner || entry.retired ||
			metaTransportExpired(entry, remote, now)) {
		delete(cache.entries, key)
		entry.retired = true
		if !entry.closed {
			entry.closed = true
			stale = entry.transport
		}
		entry = nil
	}
	if entry != nil && entry.owner == owner && !entry.retired &&
		!entry.closed && !entry.inUse {
		entry.inUse = true
		cache.mu.Unlock()
		closeMetaTransportCacheTransport(stale)
		return entry.transport
	}
	cache.mu.Unlock()
	closeMetaTransportCacheTransport(stale)
	return nil
}

func (cache *metaTransportCache) release(
	key string,
	remote chainRemoteConfiguration,
	transport *syncConsumerTransport,
	healthy bool,
) {
	cache.releaseOwned(key, key, remote, transport, healthy)
}

func (cache *metaTransportCache) releaseOwned(
	key string,
	owner string,
	remote chainRemoteConfiguration,
	transport *syncConsumerTransport,
	healthy bool,
) {
	if transport == nil {
		return
	}
	if cache == nil || key == "" {
		_ = transport.close()
		return
	}
	if owner == "" {
		owner = key
	}
	now := cache.clock()
	closeTransport := false
	cache.mu.Lock()
	entry := cache.entries[key]
	switch {
	case !healthy:
		if entry != nil && entry.transport == transport {
			delete(cache.entries, key)
			entry.inUse = false
			entry.retired = true
			if !entry.closed {
				entry.closed = true
				closeTransport = true
			}
		} else {
			closeTransport = true
		}
	case cache.closed || !cache.ownerActiveLocked(owner):
		if entry != nil && entry.transport == transport {
			delete(cache.entries, key)
			entry.inUse = false
			entry.retired = true
			if !entry.closed {
				entry.closed = true
				closeTransport = true
			}
		} else {
			closeTransport = true
		}
	case entry == nil:
		cache.entries[key] = &metaTransportCacheEntry{
			transport: transport,
			owner:     owner,
			created:   now,
			lastUsed:  now,
		}
	case entry.transport == transport:
		entry.inUse = false
		if entry.owner != owner || entry.retired || entry.closed {
			delete(cache.entries, key)
			entry.retired = true
			if !entry.closed {
				entry.closed = true
				closeTransport = true
			}
		} else {
			entry.lastUsed = now
		}
	default:
		closeTransport = true
	}
	cache.mu.Unlock()
	if closeTransport {
		_ = transport.close()
	}
}

func (cache *metaTransportCache) remove(key string, transport *syncConsumerTransport) {
	if cache == nil || key == "" {
		return
	}
	cache.mu.Lock()
	entry := cache.entries[key]
	if entry != nil && (transport == nil || entry.transport == transport) {
		delete(cache.entries, key)
		entry.retired = true
	}
	cache.mu.Unlock()
}

func (cache *metaTransportCache) resetOwner(owner string) {
	if cache == nil || owner == "" {
		return
	}
	var stale []*syncConsumerTransport
	cache.mu.Lock()
	for key, entry := range cache.entries {
		if entry == nil || entry.owner != owner {
			continue
		}
		delete(cache.entries, key)
		entry.inUse = false
		entry.retired = true
		if !entry.closed {
			entry.closed = true
			stale = append(stale, entry.transport)
		}
	}
	cache.mu.Unlock()
	closeMetaTransportCacheTransports(stale)
}

func (cache *metaTransportCache) configureOwners(active map[string]struct{}) {
	if cache == nil {
		return
	}
	owners := make(map[string]struct{}, len(active))
	for owner := range active {
		owners[owner] = struct{}{}
	}

	var stale []*syncConsumerTransport
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		return
	}
	cache.ownersConfigured = true
	cache.activeOwners = owners
	for key, entry := range cache.entries {
		if entry == nil {
			delete(cache.entries, key)
			continue
		}
		if _, active := owners[metaTransportLifecycleOwner(entry.owner)]; active {
			continue
		}
		entry.retired = true
		if entry.inUse {
			continue
		}
		delete(cache.entries, key)
		if !entry.closed {
			entry.closed = true
			stale = append(stale, entry.transport)
		}
	}
	cache.mu.Unlock()
	closeMetaTransportCacheTransports(stale)
}

func (cache *metaTransportCache) close() {
	if cache == nil {
		return
	}
	var stale []*syncConsumerTransport
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		return
	}
	cache.closed = true
	cache.ownersConfigured = true
	cache.activeOwners = make(map[string]struct{})
	for key, entry := range cache.entries {
		if entry == nil {
			delete(cache.entries, key)
			continue
		}
		entry.retired = true
		if !entry.closed {
			entry.closed = true
			stale = append(stale, entry.transport)
		}
		if !entry.inUse {
			delete(cache.entries, key)
		}
	}
	cache.mu.Unlock()
	closeMetaTransportCacheTransports(stale)
}

func (cache *metaTransportCache) ownerActiveLocked(owner string) bool {
	if !cache.ownersConfigured {
		return true
	}
	_, active := cache.activeOwners[metaTransportLifecycleOwner(owner)]
	return active
}

func metaTransportLifecycleOwner(owner string) string {
	if index := strings.Index(owner, asyncMetaTransportOwnerMarker); index >= 0 {
		return owner[:index]
	}
	return owner
}

func closeMetaTransportCacheTransports(transports []*syncConsumerTransport) {
	for _, transport := range transports {
		closeMetaTransportCacheTransport(transport)
	}
}

func closeMetaTransportCacheTransport(transport *syncConsumerTransport) {
	if transport != nil {
		_ = transport.close()
	}
}

func metaTransportExpired(
	entry *metaTransportCacheEntry,
	remote chainRemoteConfiguration,
	now time.Time,
) bool {
	if entry == nil || entry.transport == nil || entry.retired || entry.closed {
		return true
	}
	if remote.connectionTTL > 0 && !entry.created.Add(remote.connectionTTL).After(now) {
		return true
	}
	return remote.idleTimeout > 0 && !entry.lastUsed.Add(remote.idleTimeout).After(now)
}

func metaTransportKey(targetKey string, remote chainRemoteConfiguration) string {
	hash := sha256.New()
	for _, value := range []string{
		targetKey,
		remote.endpointKey,
		remote.uri,
		remote.bind.bindMethod,
		remote.bind.bindDN,
		remote.bind.saslMechanism,
		remote.bind.authenticationID,
		remote.bind.authorizationID,
		remote.bind.realm,
		remote.startTLSMode,
		fmt.Sprint(remote.protocolVersion),
	} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	_, _ = hash.Write(remote.bind.credentials)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func chainRequestTimeout(
	remote chainRemoteConfiguration,
	request ldapwire.Request,
) time.Duration {
	if timeout, found := remote.operationTimeouts[request.ApplicationTag()]; found {
		return timeout
	}
	return 0
}
