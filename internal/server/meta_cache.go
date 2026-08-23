package server

import (
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type metaDNRouteCacheEntry struct {
	targetKey string
	updated   time.Time
}

type metaDNRouteCache struct {
	mu      sync.Mutex
	entries map[string]metaDNRouteCacheEntry
	clock   func() time.Time
}

func newMetaDNRouteCache(clock func() time.Time) *metaDNRouteCache {
	if clock == nil {
		clock = time.Now
	}
	return &metaDNRouteCache{
		entries: make(map[string]metaDNRouteCacheEntry),
		clock:   clock,
	}
}

func (cache *metaDNRouteCache) lookup(
	configuration *metaBackendRuntimeConfiguration,
	dn directory.DN,
) string {
	if cache == nil || configuration == nil || configuration.dnCacheTTL == 0 {
		return ""
	}
	key, ok := metaDNRouteCacheKey(configuration, dn)
	if !ok {
		return ""
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, found := cache.entries[key]
	if !found {
		return ""
	}
	if configuration.dnCacheTTL > 0 &&
		!entry.updated.Add(configuration.dnCacheTTL).After(cache.clock()) {
		delete(cache.entries, key)
		return ""
	}
	return entry.targetKey
}

func (cache *metaDNRouteCache) store(
	configuration *metaBackendRuntimeConfiguration,
	dn directory.DN,
	targetKey string,
) {
	if cache == nil || configuration == nil || configuration.dnCacheTTL == 0 ||
		targetKey == "" {
		return
	}
	entry := metaDNRouteCacheEntry{targetKey: targetKey}
	if configuration.dnCacheTTL > 0 {
		entry.updated = cache.clock()
	}
	key, ok := metaDNRouteCacheKey(configuration, dn)
	if !ok {
		return
	}
	cache.mu.Lock()
	cache.entries[key] = entry
	cache.mu.Unlock()
}

func (cache *metaDNRouteCache) remove(
	configuration *metaBackendRuntimeConfiguration,
	dn directory.DN,
) {
	if cache == nil || configuration == nil {
		return
	}
	key, ok := metaDNRouteCacheKey(configuration, dn)
	if !ok {
		return
	}
	cache.mu.Lock()
	delete(cache.entries, key)
	cache.mu.Unlock()
}

func metaDNRouteCacheKey(
	configuration *metaBackendRuntimeConfiguration,
	dn directory.DN,
) (string, bool) {
	normalized, err := configuration.normalizeDN(dn)
	if err != nil {
		return "", false
	}
	return configuration.configDNKey + "\x00" + normalized.Key(), true
}

func (server *Server) cacheMetaSearchEntries(
	configuration *metaBackendRuntimeConfiguration,
	target metaBackendTargetRuntimeConfiguration,
	packets []*ber.Packet,
) {
	for _, packet := range packets {
		dn, ok := metaSearchEntryDN(packet)
		if !ok {
			continue
		}
		server.metaRoutes.store(configuration, dn, target.configDNKey)
	}
}

func metaSearchEntryDN(packet *ber.Packet) (directory.DN, bool) {
	if packet == nil || len(packet.Children) < 2 {
		return directory.DN{}, false
	}
	operation := packet.Children[1]
	if operation == nil || uint64(operation.Tag) != ldapwire.ApplicationSearchResultEntry ||
		len(operation.Children) == 0 {
		return directory.DN{}, false
	}
	raw, err := syncConsumerPacketBytes(operation.Children[0])
	if err != nil {
		return directory.DN{}, false
	}
	dn, err := directory.ParseDN(string(raw))
	return dn, err == nil
}

func (server *Server) updateMetaRouteAfterOperation(
	database runtimeDatabase,
	target metaBackendTargetRuntimeConfiguration,
	targetDN directory.DN,
	request ldapwire.Request,
) {
	switch value := request.(type) {
	case ldapwire.AddRequest:
		server.metaRoutes.store(database.metaBackend, targetDN, target.configDNKey)
	case ldapwire.DeleteRequest:
		server.metaRoutes.remove(database.metaBackend, targetDN)
	case ldapwire.ModifyDNRequest:
		server.metaRoutes.remove(database.metaBackend, targetDN)
		if destination, ok := metaModifyDNDestinationWithNormalizer(
			targetDN,
			value,
			database.metaBackend.dnNormalizer,
		); ok {
			server.metaRoutes.store(database.metaBackend, destination, target.configDNKey)
		}
	}
}

func metaModifyDNDestination(
	source directory.DN,
	request ldapwire.ModifyDNRequest,
) (directory.DN, bool) {
	return metaModifyDNDestinationWithNormalizer(source, request, nil)
}

func metaModifyDNDestinationWithNormalizer(
	source directory.DN,
	request ldapwire.ModifyDNRequest,
	normalizer directory.DNAttributeNormalizer,
) (directory.DN, bool) {
	source, err := parseRuntimeDN(source.String(), normalizer)
	if err != nil {
		return directory.DN{}, false
	}
	parent, ok := source.Parent()
	if !ok {
		return directory.DN{}, false
	}
	if request.HasNewSuperior {
		parent, err = parseRuntimeDN(request.NewSuperior, normalizer)
		if err != nil {
			return directory.DN{}, false
		}
	}
	raw := request.NewRDN
	if parent.Depth() > 0 {
		raw += "," + parent.String()
	}
	destination, err := parseRuntimeDN(raw, normalizer)
	return destination, err == nil
}
