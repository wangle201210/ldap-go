package server

import (
	"bytes"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const (
	compareDNPrefixMaxRecords = 64
	compareDNPrefixMaxBytes   = 8 << 20
	compareDNPrefixMetadata   = 64 << 10
	compareDNPrefixReserve    = 1 << 20
	compareDNPrefixMaxToken   = 256 << 10
	compareDNPrefixMaxDN      = 1024
	compareDNPrefixMinValues  = 32
)

// Each runtime owns one cache for its schema lifetime. Keys are hints only:
// schema checks token ownership, generation and each current raw value. This
// container owns no entries, assertions, comparison results or authorization.
type compareDNPrefixCache struct {
	mu       sync.Mutex
	records  map[compareDNPrefixKey]*compareDNPrefixRecord
	live     int // Includes fixed metadata and retired records with borrowers.
	reserved int
}

type compareDNPrefixKey struct {
	dn          string
	description string
}

type compareDNPrefixRecord struct {
	token *schema.DNComparisonPrefix
	cost  int
	refs  int // One map owner, if present, plus active callers.
}

// A lease is local to one call and must not be copied after acquisition.
type compareDNPrefixLease struct {
	record   *compareDNPrefixRecord
	reserved int
}

func newCompareDNPrefixCache() *compareDNPrefixCache {
	return &compareDNPrefixCache{
		records: make(map[compareDNPrefixKey]*compareDNPrefixRecord, compareDNPrefixMaxRecords),
		live:    compareDNPrefixMetadata,
	}
}

func (cache *compareDNPrefixCache) compare(registry *schema.Registry, entry directory.Entry, description string, assertion []byte) (bool, bool, error) {
	if cache == nil || !compareDNPrefixEligible(entry, description) {
		return registry.CompareEntryAttributeCachedDN(entry, description, assertion)
	}
	// Raw equality only selects the original comparator; it never proves a
	// match. This keeps its cheap first-value path and all earlier errors.
	for _, attribute := range entry.Attributes {
		if attribute.Description == "member" {
			if len(attribute.Values) > 0 && bytes.Equal(attribute.Values[0], assertion) {
				return registry.CompareEntryAttributeCachedDN(entry, description, assertion)
			}
			break
		}
	}
	key := compareDNPrefixKey{dn: entry.DN, description: description}
	lease, ok := cache.acquire(key)
	if !ok {
		return registry.CompareEntryAttributeCachedDN(entry, description, assertion)
	}
	defer cache.release(&lease)

	var previous *schema.DNComparisonPrefix
	if lease.record != nil {
		previous = lease.record.token
	}
	present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, description, assertion, previous)
	cache.publish(key, &lease, next)
	return present, matched, err
}

func compareDNPrefixEligible(entry directory.Entry, description string) bool {
	if description != "member" || entry.DN == "" || len(entry.DN) > compareDNPrefixMaxDN {
		return false
	}
	for _, attribute := range entry.Attributes {
		if attribute.Description == "member" && len(attribute.Values) >= compareDNPrefixMinValues {
			return true
		}
	}
	return false
}

func (cache *compareDNPrefixCache) acquire(key compareDNPrefixKey) (compareDNPrefixLease, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	lease := compareDNPrefixLease{record: cache.records[key]}
	if lease.record != nil {
		lease.record.refs++
	}
	for key, record := range cache.records {
		if cache.live+cache.reserved+compareDNPrefixReserve <= compareDNPrefixMaxBytes {
			break
		}
		// Pin the acquired record before eviction; borrowed tokens remain live.
		if record.refs == 1 {
			delete(cache.records, key)
			cache.drop(record)
		}
	}
	if cache.live+cache.reserved+compareDNPrefixReserve > compareDNPrefixMaxBytes {
		cache.drop(lease.record)
		return compareDNPrefixLease{}, false
	}
	lease.reserved = compareDNPrefixReserve
	cache.reserved += lease.reserved
	return lease, true
}

func (cache *compareDNPrefixCache) publish(key compareDNPrefixKey, lease *compareDNPrefixLease, next *schema.DNComparisonPrefix) {
	if next == nil {
		return
	}
	retained := next.RetainedBytes()
	if retained <= 0 || retained > compareDNPrefixMaxToken {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.records[key] != lease.record || lease.record != nil && lease.record.token == next {
		return
	}
	if lease.record == nil && len(cache.records) >= compareDNPrefixMaxRecords {
		return
	}
	cost := retained + 512 + 4*(len(key.dn)+len(key.description))
	if cost > lease.reserved {
		return
	}
	key = compareDNPrefixKey{dn: strings.Clone(key.dn), description: strings.Clone(key.description)}
	record := &compareDNPrefixRecord{token: next, cost: cost, refs: 1}
	cache.records[key] = record
	// Convert the construction reservation, retaining the remainder until the
	// caller returns. Replaced records stay charged until their last release.
	cache.reserved -= cost
	lease.reserved -= cost
	cache.live += cost
	cache.drop(lease.record)
}

func (cache *compareDNPrefixCache) release(lease *compareDNPrefixLease) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.reserved -= lease.reserved
	lease.reserved = 0
	cache.drop(lease.record)
	lease.record = nil
}

// drop removes one ownership reference while holding cache.mu.
func (cache *compareDNPrefixCache) drop(record *compareDNPrefixRecord) {
	if record == nil {
		return
	}
	record.refs--
	if record.refs == 0 {
		cache.live -= record.cost
		record.token = nil
	}
}
