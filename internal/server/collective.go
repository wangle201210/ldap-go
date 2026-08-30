package server

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const excludeAllCollectiveAttributesOID = "2.5.18.0"

const (
	autonomousAreaOID                  = "2.5.23.1"
	collectiveAttributeSpecificAreaOID = "2.5.23.5"
	collectiveAttributeInnerAreaOID    = "2.5.23.6"
)

type collectiveAdministrativeRole uint8

const (
	collectiveAdministrativeRoleAutonomous collectiveAdministrativeRole = 1 << iota
	collectiveAdministrativeRoleSpecific
	collectiveAdministrativeRoleInner
)

type collectiveAttributePlan struct {
	registry      *schema.Registry
	specificAreas []directory.DN
	sources       []collectiveAttributeSource
}

type collectiveAttributePlanCache struct {
	registry   *schema.Registry
	plans      map[string]*collectiveAttributePlan
	shared     *collectiveAttributePlanSharedCache
	generation uint64
}

type collectiveAttributePlanSharedCache struct {
	mu         sync.Mutex
	plans      map[string]collectiveAttributePlanSharedEntry
	generation uint64
}

type collectiveAttributePlanSharedEntry struct {
	generation uint64
	plan       *collectiveAttributePlan
}

type collectiveAttributeSource struct {
	dn                  directory.DN
	administrativePoint directory.DN
	specificArea        directory.DN
	specification       schema.SubtreeSpecification
	attributes          []collectiveSourceAttribute
}

type collectiveAdministrativePoint struct {
	dn    directory.DN
	roles collectiveAdministrativeRole
}

type collectiveSourceAttribute struct {
	description string
	oid         string
	key         string
	values      [][]byte
}

type collectiveDerivedAttribute struct {
	description string
	values      [][]byte
}

func newCollectiveAttributePlanCache(
	registry *schema.Registry,
	shared ...*collectiveAttributePlanSharedCache,
) *collectiveAttributePlanCache {
	cache := &collectiveAttributePlanCache{
		registry: registry,
		plans:    make(map[string]*collectiveAttributePlan),
	}
	if len(shared) != 0 {
		cache.shared = shared[0]
		if cache.shared != nil {
			cache.shared.mu.Lock()
			cache.generation = cache.shared.generation
			cache.shared.mu.Unlock()
		}
	}
	return cache
}

func (cache *collectiveAttributePlanSharedCache) invalidate() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	cache.generation++
	clear(cache.plans)
	cache.mu.Unlock()
}

func collectiveStorageChangesAffectPlan(
	registry *schema.Registry,
	changes []homedirStorageChange,
) bool {
	if registry == nil {
		return false
	}
	for _, change := range changes {
		for _, entry := range []*directory.Entry{change.before, change.after} {
			if entry == nil {
				continue
			}
			if len(registry.AttributeValues(*entry, "administrativeRole")) != 0 ||
				registry.EntryHasObjectClass(*entry, "subentry") ||
				registry.EntryHasObjectClass(*entry, "collectiveAttributeSubentry") {
				return true
			}
			for _, attribute := range entry.Attributes {
				if registry.IsCollective(attribute.Description) {
					return true
				}
			}
		}
	}
	return false
}

func newCollectiveAttributePlanSharedCache() *collectiveAttributePlanSharedCache {
	return &collectiveAttributePlanSharedCache{
		plans: make(map[string]collectiveAttributePlanSharedEntry),
	}
}

func (cache *collectiveAttributePlanCache) apply(
	partition string,
	reader storage.Reader,
	entry directory.Entry,
) (directory.Entry, error) {
	plan, err := cache.plan(partition, reader)
	if err != nil {
		return directory.Entry{}, err
	}
	return plan.apply(entry)
}

func (cache *collectiveAttributePlanCache) plan(
	partition string,
	reader storage.Reader,
) (*collectiveAttributePlan, error) {
	cacheKey, planReader, _ := collectiveAttributePlanReader(partition, reader)
	plan := cache.plans[cacheKey]
	if plan == nil {
		reusable := cache.shared != nil && !strings.HasPrefix(cacheKey, "sql:")
		if reusable {
			cache.shared.mu.Lock()
			shared := cache.shared.plans[cacheKey]
			if cache.generation != cache.shared.generation {
				cache.shared.mu.Unlock()
				var err error
				plan, err = buildCollectiveAttributePlan(cache.registry, planReader)
				if err != nil {
					return nil, err
				}
			} else {
				if shared.plan != nil && shared.generation == cache.generation {
					plan = shared.plan
				} else {
					var err error
					plan, err = buildCollectiveAttributePlan(cache.registry, planReader)
					if err != nil {
						cache.shared.mu.Unlock()
						return nil, err
					}
					cache.shared.plans[cacheKey] = collectiveAttributePlanSharedEntry{
						generation: cache.generation,
						plan:       plan,
					}
				}
				cache.shared.mu.Unlock()
			}
		} else {
			var err error
			plan, err = buildCollectiveAttributePlan(cache.registry, planReader)
			if err != nil {
				return nil, err
			}
		}
		cache.plans[cacheKey] = plan
	}
	return plan, nil
}

func runtimeCollectiveAttributePlan(
	runtime *runtimeState,
	partition string,
	reader storage.Reader,
) (*collectiveAttributePlan, error) {
	if runtime == nil {
		return buildCollectiveAttributePlan(nil, reader)
	}
	return newCollectiveAttributePlanCache(
		runtime.schema,
		runtime.collectivePlans,
	).plan(partition, reader)
}

type collectiveAttributePlanReaderProvider interface {
	collectiveAttributePlanReader() (string, storage.Reader)
}

func collectiveAttributePlanReader(
	partition string,
	reader storage.Reader,
) (string, storage.Reader, bool) {
	if provider, ok := reader.(collectiveAttributePlanReaderProvider); ok {
		if cacheKey, planReader := provider.collectiveAttributePlanReader(); cacheKey != "" && planReader != nil {
			return cacheKey, planReader, true
		}
	}
	if mapped, ok := reader.(*rwmStorageReader); ok {
		cacheKey, planReader, changed := collectiveAttributePlanReader(partition, mapped.Reader)
		if changed {
			return cacheKey, &rwmStorageReader{
				Reader:        planReader,
				configuration: mapped.configuration,
			}, true
		}
		return cacheKey, reader, false
	}
	return partition, reader, false
}

func withCollectiveAttributes(
	registry *schema.Registry,
	reader storage.Reader,
	entry directory.Entry,
) (directory.Entry, error) {
	plan, err := buildCollectiveAttributePlan(registry, reader)
	if err != nil {
		return directory.Entry{}, err
	}
	return plan.apply(entry)
}

func buildCollectiveAttributePlan(
	registry *schema.Registry,
	reader storage.Reader,
) (*collectiveAttributePlan, error) {
	plan := &collectiveAttributePlan{registry: registry}
	if registry == nil || !registry.HasCollectiveAttributeTypes() {
		return plan, nil
	}

	var (
		administrativePoints []collectiveAdministrativePoint
		candidateSources     []collectiveAttributeSource
	)
	if err := reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse collective administration DN %q: %w", entry.DN, err)
		}
		dn, err = storage.NormalizeReaderDN(reader, dn)
		if err != nil {
			return fmt.Errorf("normalize collective administration DN %q: %w", entry.DN, err)
		}
		roles := collectiveAdministrativeRoles(registry, entry)
		if roles != 0 {
			administrativePoints = append(administrativePoints, collectiveAdministrativePoint{
				dn:    dn,
				roles: roles,
			})
		}

		if !registry.EntryHasObjectClass(entry, "collectiveAttributeSubentry") ||
			!registry.EntryHasObjectClass(entry, "subentry") {
			return nil
		}
		values := registry.AttributeValues(entry, "subtreeSpecification")
		if len(values) != 1 {
			return nil
		}
		specification, err := schema.ParseSubtreeSpecification(string(values[0]))
		if err != nil {
			// Imported OpenLDAP data can contain values accepted by slapd's
			// UTF-8-only validator. Such a source remains readable but cannot
			// safely define a collection.
			return nil
		}
		administrativePoint, ok := dn.Parent()
		if !ok {
			return nil
		}
		source := collectiveAttributeSource{
			dn:                  dn,
			administrativePoint: administrativePoint,
			specification:       specification,
		}
		for _, attribute := range entry.Attributes {
			if !registry.IsCollective(attribute.Description) {
				continue
			}
			attributeType, ok := registry.AttributeType(attribute.Description)
			if !ok {
				continue
			}
			source.attributes = append(source.attributes, collectiveSourceAttribute{
				description: canonicalCollectiveDescription(
					attributeType.Name(),
					attribute.Description,
				),
				oid:    attributeType.OID,
				key:    collectiveAttributeKey(attributeType.OID, attribute.Description),
				values: cloneCollectiveValues(attribute.Values),
			})
		}
		candidateSources = append(candidateSources, source)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan collective attribute subentries: %w", err)
	}

	for _, point := range administrativePoints {
		if point.roles&(collectiveAdministrativeRoleAutonomous|
			collectiveAdministrativeRoleSpecific) != 0 {
			plan.specificAreas = append(plan.specificAreas, point.dn)
		}
	}
	sort.SliceStable(plan.specificAreas, func(left, right int) bool {
		return plan.specificAreas[left].Depth() > plan.specificAreas[right].Depth()
	})
	for _, source := range candidateSources {
		point, ok := collectiveAdministrativePointAt(
			administrativePoints,
			source.administrativePoint,
		)
		if !ok {
			continue
		}
		switch {
		case point.roles&(collectiveAdministrativeRoleAutonomous|
			collectiveAdministrativeRoleSpecific) != 0:
			source.specificArea = point.dn
		case point.roles&collectiveAdministrativeRoleInner != 0:
			var found bool
			source.specificArea, found = closestCollectiveSpecificArea(
				plan.specificAreas,
				point.dn,
				false,
			)
			if !found {
				continue
			}
		default:
			continue
		}
		plan.sources = append(plan.sources, source)
	}

	type orderedSource struct {
		source collectiveAttributeSource
		key    string
	}
	ordered := make([]orderedSource, len(plan.sources))
	for index, source := range plan.sources {
		key, err := storage.ReaderDNOrderKey(reader, source.dn)
		if err != nil {
			return nil, fmt.Errorf(
				"order collective attribute subentry DN %q: %w",
				source.dn.String(),
				err,
			)
		}
		ordered[index] = orderedSource{source: source, key: key}
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].key < ordered[right].key
	})
	for index := range ordered {
		plan.sources[index] = ordered[index].source
	}
	return plan, nil
}

func (plan *collectiveAttributePlan) apply(entry directory.Entry) (directory.Entry, error) {
	if plan == nil || plan.registry == nil ||
		len(plan.sources) == 0 ||
		plan.registry.EntryHasObjectClass(entry, "subentry") {
		return entry, nil
	}
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, fmt.Errorf("parse collective attribute target DN %q: %w", entry.DN, err)
	}
	entryDN, err = plan.registry.NormalizeDN(entryDN.String())
	if err != nil {
		return directory.Entry{}, fmt.Errorf(
			"normalize collective attribute target DN %q: %w",
			entry.DN,
			err,
		)
	}

	result := directory.Entry{DN: entry.DN}
	for _, attribute := range entry.Attributes {
		if plan.registry.IsCollective(attribute.Description) ||
			plan.registry.AttributeDescriptionSubtype(
				attribute.Description,
				"collectiveAttributeSubentries",
			) {
			continue
		}
		result.Attributes = append(result.Attributes, directory.Attribute{
			Description: attribute.Description,
			Values:      cloneCollectiveValues(attribute.Values),
		})
	}

	excludeAll, excludedOIDs := collectiveExclusions(plan.registry, entry)
	derived := make(map[string]*collectiveDerivedAttribute)
	var sourceDNs [][]byte
	targetSpecificArea, inCollectiveArea := closestCollectiveSpecificArea(
		plan.specificAreas,
		entryDN,
		true,
	)
	for _, source := range plan.sources {
		if !inCollectiveArea || !source.specificArea.Equal(targetSpecificArea) {
			continue
		}
		matches, err := plan.registry.SubtreeSpecificationMatches(
			source.specification,
			source.administrativePoint,
			entryDN,
			entry,
		)
		if err != nil {
			return directory.Entry{}, err
		}
		if !matches {
			continue
		}
		sourceDNs = append(sourceDNs, []byte(source.dn.String()))
		if excludeAll {
			continue
		}
		for _, attribute := range source.attributes {
			if _, excluded := excludedOIDs[strings.ToLower(attribute.oid)]; excluded {
				continue
			}
			target := derived[attribute.key]
			if target == nil {
				target = &collectiveDerivedAttribute{
					description: attribute.description,
				}
				derived[attribute.key] = target
			}
			for _, value := range attribute.values {
				if collectiveValueExists(
					plan.registry,
					target.description,
					target.values,
					value,
				) {
					continue
				}
				target.values = append(target.values, bytes.Clone(value))
			}
		}
	}

	keys := make([]string, 0, len(derived))
	for key := range derived {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		attribute := derived[key]
		if len(attribute.values) == 0 {
			continue
		}
		result.Attributes = append(result.Attributes, directory.Attribute{
			Description: attribute.description,
			Values:      cloneCollectiveValues(attribute.values),
		})
	}
	if len(sourceDNs) > 0 {
		result.Attributes = append(result.Attributes, directory.Attribute{
			Description: "collectiveAttributeSubentries",
			Values:      sourceDNs,
		})
	}
	return result, nil
}

func collectiveAdministrativeRoles(
	registry *schema.Registry,
	entry directory.Entry,
) collectiveAdministrativeRole {
	var roles collectiveAdministrativeRole
	for _, value := range registry.AttributeValues(entry, "administrativeRole") {
		switch strings.ToLower(strings.TrimSpace(string(value))) {
		case autonomousAreaOID, "autonomousarea":
			roles |= collectiveAdministrativeRoleAutonomous
		case collectiveAttributeSpecificAreaOID, "collectiveattributespecificarea":
			roles |= collectiveAdministrativeRoleSpecific
		case collectiveAttributeInnerAreaOID, "collectiveattributeinnerarea":
			roles |= collectiveAdministrativeRoleInner
		}
	}
	return roles
}

func collectiveAdministrativePointAt(
	points []collectiveAdministrativePoint,
	dn directory.DN,
) (collectiveAdministrativePoint, bool) {
	for _, point := range points {
		if point.dn.Equal(dn) {
			return point, true
		}
	}
	return collectiveAdministrativePoint{}, false
}

func closestCollectiveSpecificArea(
	areas []directory.DN,
	dn directory.DN,
	includeSelf bool,
) (directory.DN, bool) {
	for _, area := range areas {
		if includeSelf && area.Equal(dn) || area.AncestorOf(dn) {
			return area, true
		}
	}
	return directory.DN{}, false
}

func collectiveExclusions(
	registry *schema.Registry,
	entry directory.Entry,
) (bool, map[string]struct{}) {
	excluded := make(map[string]struct{})
	for _, value := range registry.AttributeValues(entry, "collectiveExclusions") {
		identifier := string(value)
		if strings.EqualFold(identifier, "excludeAllCollectiveAttributes") ||
			identifier == excludeAllCollectiveAttributesOID {
			return true, excluded
		}
		attributeType, ok := registry.AttributeType(identifier)
		if ok {
			excluded[strings.ToLower(attributeType.OID)] = struct{}{}
		}
	}
	return false, excluded
}

func collectiveValueExists(
	registry *schema.Registry,
	description string,
	existing [][]byte,
	candidate []byte,
) bool {
	for _, value := range existing {
		comparison, err := registry.Compare(description, "", value, candidate)
		if err == nil && comparison == 0 {
			return true
		}
		if err != nil && bytes.Equal(value, candidate) {
			return true
		}
	}
	return false
}

func collectiveAttributeKey(oid, description string) string {
	parts := strings.Split(description, ";")
	options := make([]string, 0, len(parts)-1)
	for _, option := range parts[1:] {
		options = append(options, strings.ToLower(option))
	}
	sort.Strings(options)
	return strings.ToLower(oid) + ";" + strings.Join(options, ";")
}

func canonicalCollectiveDescription(name, source string) string {
	if index := strings.IndexByte(source, ';'); index >= 0 {
		return name + source[index:]
	}
	return name
}

func cloneCollectiveValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}
