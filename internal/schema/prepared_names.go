package schema

import (
	"strings"
	"sync"
)

const (
	maxPreparedNamePlans = 16
	maxPreparedNameBytes = 1 << 20
)

type preparedAttributeNameCache struct {
	mu    sync.Mutex
	plans map[*AttributeType]preparedAttributeNames
	bytes int
}

// Schema writers hold Registry.mu first, matching the preparation lock order.
// Published maps are never changed, including on invalidation or eviction.
func (cache *preparedAttributeNameCache) clear() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.plans = nil
	cache.bytes = 0
}

// Both matching and nonmatching known names are recorded. This avoids folding
// common camel-case descriptions on every row without caching arbitrary input.
type preparedAttributeNames map[string]bool

// The caller holds the registry read lock; the result is immutable thereafter.
func (registry *Registry) prepareAttributeNames(target *AttributeType) preparedAttributeNames {
	cache := &registry.preparedNames
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if names := cache.plans[target]; names != nil {
		return names
	}
	names := make(preparedAttributeNames, len(registry.attributes))
	for key, candidate := range registry.attributes {
		selected := registry.attributeTypeSubtype(candidate, target, make(map[string]bool))
		names[key] = selected
		for _, spelling := range candidate.Names {
			if schemaKey(spelling) == key {
				names[spelling] = selected
			}
		}
	}
	// Names refer to strings already owned by the schema. Charge conservatively
	// for map slots and cap both the number of targets and estimated table bytes.
	retained := 128 + len(names)*64
	if retained <= maxPreparedNameBytes {
		if len(cache.plans) >= maxPreparedNamePlans || retained > maxPreparedNameBytes-cache.bytes {
			cache.plans = nil
			cache.bytes = 0
		}
		if cache.plans == nil {
			cache.plans = make(map[*AttributeType]preparedAttributeNames)
		}
		cache.plans[target] = names
		cache.bytes += retained
	}
	return names
}

func (names preparedAttributeNames) match(description string) bool {
	description, _, _ = strings.Cut(description, ";")
	matched, known := names[description]
	if !known {
		matched = names[schemaKey(description)]
	}
	return matched
}
