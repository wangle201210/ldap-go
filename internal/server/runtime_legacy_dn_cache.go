package server

import (
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	maxRuntimeLegacyDNs     = 128
	maxRuntimeLegacyDNInput = 1024
	maxRuntimeLegacyDNDepth = 32
	maxRuntimeLegacyDNBytes = 1 << 20
)

// Only syntax parsing is shared. Routing, schema normalization and root/ACL
// decisions still execute against the caller's runtime on every invocation.
type runtimeLegacyDNCache struct {
	mu      sync.Mutex
	entries map[string]directory.DN
	bytes   int
}

func newRuntimeLegacyDNCache() *runtimeLegacyDNCache {
	return &runtimeLegacyDNCache{}
}

func (cache *runtimeLegacyDNCache) parse(raw string) (directory.DN, error) {
	if cache == nil || len(raw) > maxRuntimeLegacyDNInput {
		return directory.ParseDN(raw)
	}
	cache.mu.Lock()
	dn, found := cache.entries[raw]
	cache.mu.Unlock()
	if found {
		return dn, nil
	}
	raw = strings.Clone(raw)
	dn, err := directory.ParseDN(raw)
	if err != nil || dn.Depth() > maxRuntimeLegacyDNDepth {
		return dn, err
	}
	// Charge conservatively for parsed RDN/AVA objects, strings and map storage.
	retained := 512 + 512*dn.Depth() + 256*strings.Count(raw, "=") +
		4*(len(raw)+len(dn.Key())+len(dn.String()))
	if retained > maxRuntimeLegacyDNBytes {
		return dn, nil
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if previous, ok := cache.entries[raw]; ok {
		return previous, nil
	}
	if len(cache.entries) >= maxRuntimeLegacyDNs || retained > maxRuntimeLegacyDNBytes-cache.bytes {
		cache.entries = nil
		cache.bytes = 0
	}
	if cache.entries == nil {
		cache.entries = make(map[string]directory.DN)
	}
	cache.entries[raw] = dn
	cache.bytes += retained
	return dn, nil
}
