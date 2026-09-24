package schema

import (
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	maxCachedDNs     = 128
	maxCachedDNInput = 1024
	maxCachedDNDepth = 32
	maxCachedDNBytes = 1 << 20
)

type normalizedDNCache struct {
	mu         sync.Mutex
	entries    map[string]normalizedDNCacheEntry
	bytes      int
	generation uint64
}

type normalizedDNCacheEntry struct {
	dn         directory.DN
	normalized string
}

func (entry normalizedDNCacheEntry) normalizedString() string {
	if entry.normalized != "" {
		return entry.normalized
	}
	// Inputs rejected by the cache's input/depth limits are rendered only
	// when a text consumer needs them. Empty DNs also take this cheap path.
	return entry.dn.NormalizedString()
}

// NormalizeDNCached is an opt-in, bounded cache of successful NormalizeDN
// results. Attribute definitions, including externally shared Names slices,
// must remain immutable except through registry mutation methods. Those
// methods invalidate cached results; direct alias slice edits do not.
// NormalizeDN remains uncached for callers that cannot meet this contract.
func (registry *Registry) NormalizeDNCached(value string) (directory.DN, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	entry, err := registry.normalizeDNCachedLocked(value)
	return entry.dn, err
}

// The caller holds Registry.mu through lookup, parsing and publication. Schema
// definitions (including Names slices shared by registry APIs) must be treated
// as immutable; registry mutation methods advance preparedNames.generation.
func (registry *Registry) normalizeDNCachedLocked(value string) (normalizedDNCacheEntry, error) {
	cache := &registry.dnCache
	cache.mu.Lock()
	if cache.generation != registry.preparedNames.generation {
		cache.entries = nil
		cache.bytes = 0
		cache.generation = registry.preparedNames.generation
	}
	if len(value) > maxCachedDNInput {
		cache.mu.Unlock()
		dn, err := registry.normalizeDNLocked(value)
		return normalizedDNCacheEntry{dn: dn}, err
	}
	if dn, ok := cache.entries[value]; ok {
		cache.mu.Unlock()
		return dn, nil
	}
	cache.mu.Unlock()

	// Own the input before parsing: both the map key and parsed substrings must
	// not keep an arbitrarily large caller-owned backing string alive.
	value = strings.Clone(value)
	// Recursive DN-valued matching uses normalizeDNLocked and bypasses this
	// cache. Never hold the cache mutex while running the parser or matcher.
	dn, err := registry.normalizeDNLocked(value)
	entry := normalizedDNCacheEntry{dn: dn}
	if err != nil || dn.Depth() > maxCachedDNDepth {
		return entry, err
	}
	entry.normalized = dn.NormalizedString()
	retained := estimatedDNCacheBytes(value, entry)
	if retained > maxCachedDNBytes {
		return entry, nil
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cached, ok := cache.entries[value]; ok {
		return cached, nil
	}
	// Match the prepared-name cache's clear-on-limit policy. Returned DNs are
	// immutable through their public API and remain valid after eviction.
	if len(cache.entries) >= maxCachedDNs || retained > maxCachedDNBytes-cache.bytes {
		cache.entries = nil
		cache.bytes = 0
	}
	if cache.entries == nil {
		cache.entries = make(map[string]normalizedDNCacheEntry)
	}
	cache.entries[value] = entry
	cache.bytes += retained
	return entry, nil
}

func estimatedDNCacheBytes(value string, entry normalizedDNCacheEntry) int {
	// Allow for map slots, the DN, parsed RDN/AVA objects, nested slice headers,
	// spare capacity and allocator rounding. Every AVA requires an '=' in the
	// input; escaped '=' bytes only overestimate that count. Charge multiple
	// copies of input, identity and rendered strings to cover retained values,
	// identity RDN buffers, the retained normalized text and normalization/schema-
	// name expansion. The entry's string header fits in the fixed allowance.
	// This is a conservative estimate, not an exact Go heap measurement.
	dn := entry.dn
	return 512 + 512*dn.Depth() + 256*strings.Count(value, "=") +
		4*(len(value)+len(dn.Key())+len(dn.String())+len(entry.normalized))
}
