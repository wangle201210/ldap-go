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
	mu         sync.Mutex
	plans      map[*AttributeType]preparedAttributeNames
	bytes      int
	generation uint64 // Also protected by Registry.mu; eviction does not change it.
}

// Schema writers hold Registry.mu first, matching the preparation lock order.
// Published maps are never changed, including on invalidation or eviction.
func (cache *preparedAttributeNameCache) clear() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.plans = nil
	cache.bytes = 0
	cache.generation++
}

type preparedAttributeRole uint8

const (
	preparedAttributeTarget preparedAttributeRole = 1 << iota
	preparedAttributeObjectClass
)

// Both matching and nonmatching known names are recorded. This avoids folding
// common camel-case descriptions on every row without caching arbitrary input.
type preparedAttributeNames map[string]preparedAttributeRole

// The caller holds the registry read lock; the result is immutable thereafter.
func (registry *Registry) prepareAttributeNames(target *AttributeType) preparedAttributeNames {
	cache := &registry.preparedNames
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if names := cache.plans[target]; names != nil {
		return names
	}
	names := make(preparedAttributeNames, len(registry.attributes))
	objectClass := registry.attributes[schemaKey("objectClass")]
	for key, candidate := range registry.attributes {
		var roles preparedAttributeRole
		if registry.attributeTypeSubtype(candidate, target, make(map[string]bool)) {
			roles |= preparedAttributeTarget
		}
		if target == objectClass {
			if roles&preparedAttributeTarget != 0 {
				roles |= preparedAttributeObjectClass
			}
		} else if objectClass != nil && registry.attributeTypeSubtype(candidate, objectClass, make(map[string]bool)) {
			roles |= preparedAttributeObjectClass
		}
		names[key] = roles
		for _, spelling := range candidate.Names {
			if schemaKey(spelling) == key {
				names[spelling] = roles
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
	return names.roles(description)&preparedAttributeTarget != 0
}

func (names preparedAttributeNames) roles(description string) preparedAttributeRole {
	description, _, _ = strings.Cut(description, ";")
	roles, known := names[description]
	if !known {
		roles = names[schemaKey(description)]
	}
	return roles
}
