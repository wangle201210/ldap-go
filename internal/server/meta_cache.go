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
	key := metaDNRouteCacheKey(configuration.configDNKey, dn)
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
	cache.mu.Lock()
	cache.entries[metaDNRouteCacheKey(configuration.configDNKey, dn)] = entry
	cache.mu.Unlock()
}

func (cache *metaDNRouteCache) remove(databaseKey string, dn directory.DN) {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	delete(cache.entries, metaDNRouteCacheKey(databaseKey, dn))
	cache.mu.Unlock()
}

func metaDNRouteCacheKey(databaseKey string, dn directory.DN) string {
	return databaseKey + "\x00" + dn.Key()
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
		server.metaRoutes.remove(database.configDNKey, targetDN)
	case ldapwire.ModifyDNRequest:
		server.metaRoutes.remove(database.configDNKey, targetDN)
		if destination, ok := metaModifyDNDestination(targetDN, value); ok {
			server.metaRoutes.store(database.metaBackend, destination, target.configDNKey)
		}
	}
}

func metaModifyDNDestination(
	source directory.DN,
	request ldapwire.ModifyDNRequest,
) (directory.DN, bool) {
	parent, ok := source.Parent()
	if !ok {
		return directory.DN{}, false
	}
	if request.HasNewSuperior {
		var err error
		parent, err = directory.ParseDN(request.NewSuperior)
		if err != nil {
			return directory.DN{}, false
		}
	}
	raw := request.NewRDN
	if parent.Depth() > 0 {
		raw += "," + parent.String()
	}
	destination, err := directory.ParseDN(raw)
	return destination, err == nil
}
