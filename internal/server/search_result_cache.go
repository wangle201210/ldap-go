package server

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const searchResultCacheMaximumEntries = 16384

const searchBaseCacheMaximumEntries = 64

type searchBaseCache struct {
	mu      sync.Mutex
	entries map[searchBaseCacheKey]directory.Entry
}

type searchBaseCacheKey struct {
	partition string
	dnKey     string
	revision  uint64
}

func newSearchBaseCache() *searchBaseCache {
	return &searchBaseCache{entries: make(map[searchBaseCacheKey]directory.Entry)}
}

func (cache *searchBaseCache) get(
	partition string,
	dn directory.DN,
	revision uint64,
) (directory.Entry, bool) {
	if cache == nil {
		return directory.Entry{}, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, found := cache.entries[searchBaseCacheKey{
		partition: partition,
		dnKey:     dn.Key(),
		revision:  revision,
	}]
	return entry, found
}

func (cache *searchBaseCache) put(
	partition string,
	dn directory.DN,
	revision uint64,
	entry directory.Entry,
) {
	if cache == nil {
		return
	}
	key := searchBaseCacheKey{partition: partition, dnKey: dn.Key(), revision: revision}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) >= searchBaseCacheMaximumEntries {
		clear(cache.entries)
	}
	cache.entries[key] = entry.Clone()
}

type searchResultCache struct {
	mu      sync.Mutex
	entries map[searchResultCacheKey]searchResultCacheEntry
	bytes   int64
	maximum int64
}

type searchResultCacheKey struct {
	fingerprint [sha256.Size]byte
	revision    uint64
}

type searchResultCacheEntry struct {
	entries []directory.Entry
	bytes   int64
}

func newSearchResultCache(maximum int64) *searchResultCache {
	return &searchResultCache{
		entries: make(map[searchResultCacheKey]searchResultCacheEntry),
		maximum: maximum,
	}
}

func (cache *searchResultCache) get(
	fingerprint [sha256.Size]byte,
	revision uint64,
) ([]directory.Entry, bool) {
	if cache == nil {
		return nil, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, found := cache.entries[searchResultCacheKey{
		fingerprint: fingerprint,
		revision:    revision,
	}]
	if !found {
		return nil, false
	}
	return append([]directory.Entry(nil), entry.entries...), true
}

func (cache *searchResultCache) put(
	fingerprint [sha256.Size]byte,
	revision uint64,
	entries []directory.Entry,
) {
	if cache == nil {
		return
	}
	retained := int64(64)
	cloned := make([]directory.Entry, len(entries))
	for index := range entries {
		cloned[index] = entries[index].Clone()
		retained += searchResultCacheEntryBytes(cloned[index])
	}
	if retained > cache.maximum {
		return
	}
	key := searchResultCacheKey{fingerprint: fingerprint, revision: revision}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if previous, found := cache.entries[key]; found {
		cache.bytes -= previous.bytes
	}
	if cache.bytes+retained > cache.maximum ||
		len(cache.entries) >= searchResultCacheMaximumEntries {
		clear(cache.entries)
		cache.bytes = 0
	}
	cache.entries[key] = searchResultCacheEntry{entries: cloned, bytes: retained}
	cache.bytes += retained
}

func searchResultCacheEntryBytes(entry directory.Entry) int64 {
	retained := int64(len(entry.DN) + 64)
	for _, attribute := range entry.Attributes {
		retained += int64(len(attribute.Description) + 32)
		for _, value := range attribute.Values {
			retained += int64(len(value) + 24)
		}
	}
	return retained
}

func (server *Server) rootEqualitySearchCacheFingerprint(
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	controls []ldapwire.Control,
) ([sha256.Size]byte, bool) {
	if server == nil || state == nil || state.runtime == nil ||
		state.runtime.searchResults == nil || len(controls) != 0 ||
		request.SizeLimit != 0 || request.TimeLimit != 0 ||
		len(database.searchSizeLimits) != 0 ||
		request.DerefAliases != 0 || request.Filter.Kind != directory.FilterEquality ||
		request.Filter.Attribute == "" ||
		!pagedSnapshotAttributesCacheable(state.runtime.schema, request.Attributes) ||
		!databaseSearchResultCacheSafe(state.runtime, database) ||
		!server.isDatabaseRoot(state.runtime, database, state.boundDN) {
		return [sha256.Size]byte{}, false
	}
	if state.runtime.schema.IsOperational(request.Filter.Attribute) ||
		state.runtime.schema.IsCollective(request.Filter.Attribute) ||
		state.runtime.schema.IsDNValued(request.Filter.Attribute) {
		return [sha256.Size]byte{}, false
	}
	indexSchema, ok := database.dnNormalizer.(storage.EqualityIndexSchema)
	if !ok {
		return [sha256.Size]byte{}, false
	}
	_, equality, _, err := indexSchema.ResolveEqualityIndexAttribute(
		request.Filter.Attribute,
	)
	if err != nil || !equality {
		return [sha256.Size]byte{}, false
	}
	return rootEqualitySearchFingerprint(state.boundDN, request), true
}

func rootEqualitySearchFingerprint(
	boundDN string,
	request ldapwire.SearchRequest,
) [sha256.Size]byte {
	var buffer [512]byte
	encoded := buffer[:0]
	encoded = append(encoded, "ldap-go:root-equality-search:v1"...)
	encoded = appendSearchFingerprintField(encoded, []byte(boundDN))
	encoded = appendSearchFingerprintField(encoded, []byte(request.BaseDN))
	encoded = binary.AppendVarint(encoded, int64(request.Scope))
	encoded = binary.AppendVarint(encoded, int64(request.DerefAliases))
	encoded = binary.AppendVarint(encoded, int64(request.SizeLimit))
	encoded = binary.AppendVarint(encoded, int64(request.TimeLimit))
	if request.TypesOnly {
		encoded = append(encoded, 1)
	} else {
		encoded = append(encoded, 0)
	}
	encoded = append(encoded, byte(request.Filter.Kind))
	encoded = appendSearchFingerprintField(encoded, []byte(request.Filter.Attribute))
	encoded = appendSearchFingerprintField(encoded, request.Filter.Assertion)
	encoded = binary.AppendUvarint(encoded, uint64(len(request.Attributes)))
	for _, attribute := range request.Attributes {
		encoded = appendSearchFingerprintField(encoded, []byte(attribute))
	}
	return sha256.Sum256(encoded)
}

func appendSearchFingerprintField(destination, value []byte) []byte {
	destination = binary.AppendUvarint(destination, uint64(len(value)))
	return append(destination, value...)
}

func databaseSearchResultCacheSafe(
	runtime *runtimeState,
	database runtimeDatabase,
) bool {
	return runtime != nil && !runtime.features.searchPreDispatch &&
		runtime.frontendRestrictions == 0 && database.restrictions == 0 &&
		database.frontendRestrictions == 0 &&
		databaseUsesLocalContentStorage(database) &&
		!databaseSearchCandidatesAreDelegated(runtime, database) &&
		unindexedValueCacheSafe(database) && database.relay == nil &&
		!database.lastBind && !database.lastBindOverlay &&
		!database.allOperationalAttrs && !database.syncProvider &&
		!database.nopsOverlay && database.dds == nil && database.ppolicy == nil &&
		database.pbind == nil && database.remoteAuth == nil && database.homedir == nil &&
		database.otp == nil && len(database.totpPasswords) == 0 &&
		database.autoca == nil && database.constraint == nil && database.seqmod == nil &&
		!database.deref && database.unique == nil && database.valueSort == nil &&
		database.accesslog == nil && database.auditlog == nil &&
		len(database.retcodes) == 0 && len(database.memberOf) == 0 &&
		len(database.refint) == 0
}
