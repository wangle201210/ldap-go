package server

import (
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type unindexedValueCache struct {
	mu      sync.Mutex
	entries map[string]unindexedValueCacheEntry
	bytes   int64
	maximum int64
}

type unindexedValueCacheEntry struct {
	revision uint64
	values   map[string]struct{}
	bytes    int64
}

func newUnindexedValueCache(maximum int64) *unindexedValueCache {
	return &unindexedValueCache{
		entries: make(map[string]unindexedValueCacheEntry),
		maximum: maximum,
	}
}

func (cache *unindexedValueCache) definitelyAbsent(
	registry *schema.Registry,
	database runtimeDatabase,
	reader storage.Reader,
	filter directory.Filter,
) (bool, bool, error) {
	if cache == nil || registry == nil || filter.Kind != directory.FilterEquality ||
		filter.Attribute == "" || registry.IsOperational(filter.Attribute) ||
		registry.IsCollective(filter.Attribute) || registry.IsDNValued(filter.Attribute) ||
		!unindexedValueCacheSafe(database) {
		return false, false, nil
	}
	if registry.AttributeDescriptionSubtype(filter.Attribute, "objectClass") {
		return false, false, nil
	}
	revision, ok := storage.ReaderSnapshotRevision(reader)
	if !ok {
		return false, false, nil
	}
	attributeType, ok := registry.AttributeType(filter.Attribute)
	if !ok {
		return false, false, nil
	}
	assertion, err := registry.NormalizeEqualityAssertion(filter.Attribute, filter.Assertion)
	if err != nil {
		return false, false, nil
	}
	key := database.partition + "\x00" + strings.ToLower(attributeType.OID)
	cache.mu.Lock()
	cached, found := cache.entries[key]
	if found && cached.revision == revision {
		_, present := cached.values[string(assertion)]
		cache.mu.Unlock()
		return !present, true, nil
	}
	cache.mu.Unlock()

	values := make(map[string]struct{})
	var retained int64
	hasReferral := false
	err = reader.ForEach(func(entry directory.Entry) error {
		if registry.EntryHasObjectClass(entry, "referral") {
			hasReferral = true
		}
		for _, value := range registry.AttributeValues(entry, filter.Attribute) {
			normalized, normalizeErr := registry.NormalizeEqualityValue(filter.Attribute, value)
			if normalizeErr != nil {
				return errUnindexedValueCacheUnsupported
			}
			term := string(normalized)
			if _, exists := values[term]; exists {
				continue
			}
			retained += int64(len(term) + 32)
			if retained > cache.maximum {
				return errUnindexedValueCacheLimit
			}
			values[term] = struct{}{}
		}
		return nil
	})
	if err != nil {
		if err == errUnindexedValueCacheLimit || err == errUnindexedValueCacheUnsupported {
			return false, false, nil
		}
		return false, false, err
	}
	if hasReferral {
		return false, false, nil
	}
	cache.mu.Lock()
	if previous, exists := cache.entries[key]; exists {
		cache.bytes -= previous.bytes
	}
	if cache.bytes+retained > cache.maximum || len(cache.entries) >= 64 {
		clear(cache.entries)
		cache.bytes = 0
	}
	cache.entries[key] = unindexedValueCacheEntry{
		revision: revision,
		values:   values,
		bytes:    retained,
	}
	cache.bytes += retained
	_, present := values[string(assertion)]
	cache.mu.Unlock()
	return !present, true, nil
}

func unindexedValueCacheSafe(database runtimeDatabase) bool {
	return database.sqlBackend == nil && database.rwm == nil &&
		database.translucent == nil && database.collect == nil &&
		database.dynlist == nil && database.dyngroup == nil &&
		len(database.nestGroups) == 0
}

type unindexedValueCacheLimitError struct{}

func (unindexedValueCacheLimitError) Error() string {
	return "unindexed value cache limit exceeded"
}

var errUnindexedValueCacheLimit error = unindexedValueCacheLimitError{}

type unindexedValueCacheUnsupportedError struct{}

func (unindexedValueCacheUnsupportedError) Error() string {
	return "unindexed value cache cannot normalize stored value"
}

var errUnindexedValueCacheUnsupported error = unindexedValueCacheUnsupportedError{}
