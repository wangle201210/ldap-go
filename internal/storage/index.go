package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const equalityIndexFormatVersion = 2

// EqualityIndexFormatVersion is persisted with each index configuration. It is
// exported so database-specific schema adapters can request the current term
// format without duplicating its version number.
const EqualityIndexFormatVersion = equalityIndexFormatVersion

const (
	substringIndexNGramSize = 3
	substringIndexAnchorMax = 8
	substringIndexMaxNGrams = 256
)

func equalityIndexPostingKindConfigured(definition EqualityIndexAttribute, kind byte) bool {
	switch kind {
	case equalityIndexPresence:
		return definition.Presence
	case equalityIndexValue:
		return definition.Equality
	case equalityIndexSubstringInitial:
		return definition.SubstringInitial
	case equalityIndexSubstringAny, equalityIndexSubstringOverflow:
		return definition.SubstringAny
	case equalityIndexSubstringFinal:
		return definition.SubstringFinal
	case equalityIndexOrdering:
		return definition.Ordering
	case equalityIndexApproximate:
		return definition.Approximate
	default:
		return false
	}
}

// EqualityIndexAttribute identifies one equality index by canonical attribute
// OID and effective equality matching rule. The matching rule is part of the
// persisted configuration fingerprint so schema changes cannot reuse stale
// postings.
type EqualityIndexAttribute struct {
	Attribute        string `json:"attribute"`
	EqualityRule     string `json:"equalityRule,omitempty"`
	ApproximateRule  string `json:"approximateRule,omitempty"`
	SubstringRule    string `json:"substringRule,omitempty"`
	OrderingRule     string `json:"orderingRule,omitempty"`
	Equality         bool   `json:"equality,omitempty"`
	Presence         bool   `json:"presence,omitempty"`
	Approximate      bool   `json:"approximate,omitempty"`
	SubstringInitial bool   `json:"substringInitial,omitempty"`
	SubstringAny     bool   `json:"substringAny,omitempty"`
	SubstringFinal   bool   `json:"substringFinal,omitempty"`
	Ordering         bool   `json:"ordering,omitempty"`
	NoTags           bool   `json:"noTags,omitempty"`
	NoSubtypes       bool   `json:"noSubtypes,omitempty"`
}

// EqualityIndexConfig is the storage-neutral representation of olcDbIndex eq
// configuration for one database partition.
type EqualityIndexConfig struct {
	Version    int                      `json:"version"`
	Attributes []EqualityIndexAttribute `json:"attributes"`
}

// EqualityIndexSchema supplies database-specific schema operations without
// coupling storage to the schema package.
type EqualityIndexSchema interface {
	EqualityIndexConfiguration() EqualityIndexConfig
	ResolveEqualityIndexAttribute(description string) (canonical string, equality, presence bool, err error)
	NormalizeEqualityIndexAssertion(description string, value []byte) ([]byte, error)
	EqualityIndexValues(entry directory.Entry, canonicalAttribute string) ([][]byte, error)
	ResolveSubstringIndexAttribute(description string) (canonical string, initial, any, final bool, err error)
	NormalizeSubstringIndexAssertion(description string, value directory.Substring) (directory.Substring, error)
	SubstringIndexValues(entry directory.Entry, canonicalAttribute string) ([][]byte, error)
	ResolveOrderingIndexAttribute(description string) (canonical string, ordering bool, err error)
	NormalizeOrderingIndexAssertion(description string, value []byte) ([]byte, error)
	OrderingIndexValues(entry directory.Entry, canonicalAttribute string) ([][]byte, error)
	ResolveApproximateIndexAttribute(description string) (canonical string, approximate, equalityFallback bool, err error)
	ApproximateIndexAssertionTerms(description string, value []byte) (terms [][]byte, usable bool, err error)
	ApproximateIndexValues(entry directory.Entry, canonicalAttribute string) ([][]byte, error)
}

type equalityIndexStorageReader interface {
	equalityIndexConfig(partition string) (EqualityIndexConfig, bool, error)
	equalityIndexPostings(
		partition,
		attribute string,
		kind byte,
		value []byte,
	) ([]string, error)
	equalityIndexOrderingPostings(partition, attribute string, assertion []byte, greaterOrEqual bool) ([]string, error)
	equalityIndexEntries(keys []string) ([]directory.Entry, error)
}

type equalityIndexStorageWriter interface {
	equalityIndexStorageReader
	putInWithEqualityIndexes(
		partition string,
		entry directory.Entry,
		dn directory.DN,
		replace bool,
		schema EqualityIndexSchema,
	) error
	deleteInWithEqualityIndexes(
		partition string,
		dn directory.DN,
		schema EqualityIndexSchema,
	) error
	rebuildEqualityIndexes(partition string, schema EqualityIndexSchema) error
}

type selectiveEqualityIndexStorageWriter interface {
	rebuildSelectedEqualityIndexes(
		partition string,
		schema EqualityIndexSchema,
		attributes []string,
	) error
}

type equalityIndexCandidatePlanner interface {
	planEqualityIndexCandidates(directory.Filter) ([]directory.Entry, bool, error)
}

// EqualityIndexValidationCache lets an immutable schema adapter retain the
// result of comparing its expected index configuration with one storage
// snapshot. A new storage revision always forces validation again.
type EqualityIndexValidationCache interface {
	EqualityIndexValidation(partition string, revision uint64) (current, known bool)
	StoreEqualityIndexValidation(partition string, revision uint64, current bool)
}

// DNIdentityHintResolver resolves a stored physical identity through a
// runtime-owned bounded cache.
type DNIdentityHintResolver interface {
	ResolveDNIdentityHint(entry directory.Entry, identity string) (directory.Entry, error)
}

// ForEachFilterCandidate visits an index-reduced candidate set when the reader
// has a complete compatible equality index. planned=false means the caller
// must perform its normal full scan. Every returned entry still requires scope,
// filter, ACL, and overlay evaluation by the server.
func ForEachFilterCandidate(
	reader Reader,
	filter directory.Filter,
	fn func(directory.Entry) error,
) (planned bool, candidates int, err error) {
	planner, ok := reader.(equalityIndexCandidatePlanner)
	if !ok {
		return false, 0, nil
	}
	entries, planned, err := planner.planEqualityIndexCandidates(filter)
	if err != nil || !planned {
		return planned, 0, err
	}
	for _, entry := range entries {
		if err := fn(entry); err != nil {
			return true, candidates, err
		}
		candidates++
	}
	return true, candidates, nil
}

// RebuildEqualityIndexes rebuilds one partition's configured equality indexes
// inside the caller's write transaction.
func RebuildEqualityIndexes(
	writer Writer,
	partition string,
	schema EqualityIndexSchema,
) error {
	writer = maintenanceWriter(writer)
	indexed, ok := writer.(equalityIndexStorageWriter)
	if !ok {
		return errors.New("writer does not support equality indexes")
	}
	return indexed.rebuildEqualityIndexes(partition, schema)
}

// RebuildSelectedEqualityIndexes replaces postings for configured canonical
// attributes while preserving every other attribute index. A stale or missing
// persisted configuration triggers a complete rebuild so partial publication
// can never make an incompatible index authoritative.
func RebuildSelectedEqualityIndexes(
	writer Writer,
	partition string,
	schema EqualityIndexSchema,
	attributes []string,
) error {
	if len(attributes) == 0 {
		return RebuildEqualityIndexes(writer, partition, schema)
	}
	writer = maintenanceWriter(writer)
	indexed, ok := writer.(selectiveEqualityIndexStorageWriter)
	if !ok {
		return errors.New("writer does not support selective equality index rebuilds")
	}
	return indexed.rebuildSelectedEqualityIndexes(partition, schema, attributes)
}

// EnsureEqualityIndexes creates or refreshes one partition's indexes only when
// the persisted configuration does not match the requested schema.
func EnsureEqualityIndexes(
	writer Writer,
	partition string,
	schema EqualityIndexSchema,
) error {
	if normalizer, ok := schema.(directory.DNAttributeNormalizer); ok {
		if err := ensureSchemaAwareDNIdentities(writer, partition, normalizer); err != nil {
			return err
		}
	}
	writer = maintenanceWriter(writer)
	indexed, ok := writer.(equalityIndexStorageWriter)
	if !ok {
		return errors.New("writer does not support equality indexes")
	}
	current, present, err := indexed.equalityIndexConfig(partition)
	if err != nil {
		return err
	}
	want, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil {
		return err
	}
	if present {
		current, err = normalizeEqualityIndexConfig(current)
		if err == nil && equalityIndexConfigsEqual(current, want) {
			return nil
		}
	}
	return indexed.rebuildEqualityIndexes(partition, schema)
}

// EqualityIndexesCurrent reports whether one partition's persisted DN identity
// marker and equality-index configuration match the requested schema. It only
// reads fixed-size metadata and index configuration; it never scans entries or
// starts a write transaction.
func EqualityIndexesCurrent(
	reader Reader,
	partition string,
	schema EqualityIndexSchema,
) (bool, error) {
	reader = maintenanceReader(reader)
	if normalizer, ok := schema.(directory.DNAttributeNormalizer); ok && normalizer != nil {
		marker, err := reader.Metadata(schemaAwareDNMigrationMetadataKey(partition))
		switch {
		case errors.Is(err, ErrMetadataNotFound):
			return false, nil
		case err != nil:
			return false, err
		case len(marker) != 1 || int(marker[0]) != schemaAwareDNIdentityFormatVersion:
			return false, fmt.Errorf(
				"partition %q has unsupported DN identity format marker %x",
				partition,
				marker,
			)
		}
	}
	indexed, ok := reader.(equalityIndexStorageReader)
	if !ok {
		return false, nil
	}
	current, present, err := indexed.equalityIndexConfig(partition)
	if err != nil || !present {
		return false, err
	}
	want, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil {
		return false, err
	}
	current, err = normalizeEqualityIndexConfig(current)
	if err != nil {
		return false, nil
	}
	return equalityIndexConfigsEqual(current, want), nil
}

func putPartitionEntryWithEqualityIndexes(
	writer Writer,
	partition string,
	entry directory.Entry,
	dn directory.DN,
	replace bool,
	normalizer directory.DNAttributeNormalizer,
) (bool, error) {
	schema, ok := normalizer.(EqualityIndexSchema)
	if !ok {
		return false, nil
	}
	observers := maintenanceMutationObservers(writer)
	backend := maintenanceWriter(writer)
	indexed, ok := backend.(equalityIndexStorageWriter)
	if !ok {
		return false, nil
	}
	var before *directory.Entry
	existing, err := backend.GetIn(partition, dn)
	if err == nil {
		before = &existing
	} else if !errors.Is(err, ErrEntryNotFound) {
		return true, err
	}
	if err := indexed.putInWithEqualityIndexes(
		partition,
		entry,
		dn,
		replace,
		schema,
	); err != nil {
		return true, err
	}
	after := entry.Clone()
	return true, observeMaintenanceMutation(observers, partition, before, &after)
}

func deletePartitionEntryWithEqualityIndexes(
	writer Writer,
	partition string,
	dn directory.DN,
	normalizer directory.DNAttributeNormalizer,
) (bool, error) {
	schema, ok := normalizer.(EqualityIndexSchema)
	if !ok {
		return false, nil
	}
	observers := maintenanceMutationObservers(writer)
	backend := maintenanceWriter(writer)
	indexed, ok := backend.(equalityIndexStorageWriter)
	if !ok {
		return false, nil
	}
	before, err := backend.GetIn(partition, dn)
	if err != nil {
		return true, err
	}
	if err := indexed.deleteInWithEqualityIndexes(partition, dn, schema); err != nil {
		return true, err
	}
	return true, observeMaintenanceMutation(observers, partition, &before, nil)
}

func (reader schemaAwarePartitionReader) planEqualityIndexCandidates(
	filter directory.Filter,
) ([]directory.Entry, bool, error) {
	schema, ok := reader.normalizer.(EqualityIndexSchema)
	if !ok {
		return nil, false, nil
	}
	indexed, ok := maintenanceReader(reader.Reader).(equalityIndexStorageReader)
	if !ok {
		return nil, false, nil
	}
	revision, hasRevision := ReaderSnapshotRevision(reader.Reader)
	validationCache, cacheable := schema.(EqualityIndexValidationCache)
	if hasRevision && cacheable {
		if current, known := validationCache.EqualityIndexValidation(
			reader.partition,
			revision,
		); known {
			if !current {
				return nil, false, nil
			}
			return reader.planCurrentEqualityIndexCandidates(indexed, schema, filter)
		}
	}
	want, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil || len(want.Attributes) == 0 {
		return nil, false, err
	}
	stored, present, err := indexed.equalityIndexConfig(reader.partition)
	if err != nil || !present {
		if err == nil && hasRevision && cacheable {
			validationCache.StoreEqualityIndexValidation(reader.partition, revision, false)
		}
		return nil, false, err
	}
	stored, err = normalizeEqualityIndexConfig(stored)
	if err != nil {
		return nil, false, nil
	}
	if !equalityIndexConfigsEqual(stored, want) {
		if hasRevision && cacheable {
			validationCache.StoreEqualityIndexValidation(reader.partition, revision, false)
		}
		return nil, false, nil
	}
	if hasRevision && cacheable {
		validationCache.StoreEqualityIndexValidation(reader.partition, revision, true)
	}
	return reader.planCurrentEqualityIndexCandidates(indexed, schema, filter)
}

func (reader schemaAwarePartitionReader) planCurrentEqualityIndexCandidates(
	indexed equalityIndexStorageReader,
	schema EqualityIndexSchema,
	filter directory.Filter,
) ([]directory.Entry, bool, error) {
	keys, planned, err := planEqualityIndexFilter(
		indexed,
		reader.partition,
		schema,
		filter,
	)
	if err != nil || !planned {
		return nil, planned, err
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	entries, err := indexed.equalityIndexEntries(ordered)
	if err == nil {
		if resolver, ok := schema.(DNIdentityHintResolver); ok {
			for index := range entries {
				identity, present := entries[index].DNIdentity()
				if !present {
					continue
				}
				entries[index], err = resolver.ResolveDNIdentityHint(entries[index], identity)
				if err != nil {
					return nil, false, err
				}
			}
		}
	}
	return entries, true, err
}

func planEqualityIndexFilter(
	reader equalityIndexStorageReader,
	partition string,
	schema EqualityIndexSchema,
	filter directory.Filter,
) (map[string]struct{}, bool, error) {
	switch filter.Kind {
	case directory.FilterEquality:
		attribute, equality, _, err := schema.ResolveEqualityIndexAttribute(filter.Attribute)
		if err != nil || !equality {
			return nil, false, err
		}
		normalized, err := schema.NormalizeEqualityIndexAssertion(
			filter.Attribute,
			filter.Assertion,
		)
		if err != nil {
			return nil, false, err
		}
		keys, err := reader.equalityIndexPostings(
			partition,
			attribute,
			equalityIndexValue,
			normalized,
		)
		return stringSet(keys), true, err
	case directory.FilterApprox:
		attribute, approximate, equalityFallback, err := schema.ResolveApproximateIndexAttribute(
			filter.Attribute,
		)
		if err != nil || !approximate && !equalityFallback {
			return nil, false, err
		}
		if equalityFallback {
			normalized, err := schema.NormalizeEqualityIndexAssertion(filter.Attribute, filter.Assertion)
			if err != nil {
				return nil, false, err
			}
			keys, err := reader.equalityIndexPostings(
				partition, attribute, equalityIndexValue, normalized,
			)
			return stringSet(keys), true, err
		}
		terms, usable, err := schema.ApproximateIndexAssertionTerms(filter.Attribute, filter.Assertion)
		if err != nil || !usable {
			return nil, false, err
		}
		if len(terms) == 0 {
			return map[string]struct{}{}, true, nil
		}
		var result map[string]struct{}
		for _, term := range uniqueIndexValues(terms) {
			keys, err := reader.equalityIndexPostings(
				partition, attribute, equalityIndexApproximate, term,
			)
			if err != nil {
				return nil, false, err
			}
			candidate := stringSet(keys)
			if result == nil {
				result = candidate
			} else {
				intersectStringSets(result, candidate)
			}
		}
		return result, true, nil
	case directory.FilterPresent:
		attribute, _, presence, err := schema.ResolveEqualityIndexAttribute(filter.Attribute)
		if err != nil || !presence {
			return nil, false, err
		}
		keys, err := reader.equalityIndexPostings(
			partition,
			attribute,
			equalityIndexPresence,
			nil,
		)
		return stringSet(keys), true, err
	case directory.FilterSubstrings:
		attribute, initial, any, final, err := schema.ResolveSubstringIndexAttribute(
			filter.Attribute,
		)
		if err != nil || !initial && !any && !final {
			return nil, false, err
		}
		normalized, err := schema.NormalizeSubstringIndexAssertion(
			filter.Attribute,
			filter.Substring,
		)
		if err != nil {
			return nil, false, err
		}
		constraints := substringIndexFilterConstraints(normalized, initial, any, final)
		if len(constraints) == 0 {
			return nil, false, nil
		}
		var result map[string]struct{}
		for _, constraint := range constraints {
			keys, err := reader.equalityIndexPostings(
				partition,
				attribute,
				constraint.kind,
				constraint.value,
			)
			if err != nil {
				return nil, false, err
			}
			candidate := stringSet(keys)
			if constraint.includeOverflow {
				overflow, err := reader.equalityIndexPostings(
					partition,
					attribute,
					equalityIndexSubstringOverflow,
					nil,
				)
				if err != nil {
					return nil, false, err
				}
				for key := range stringSet(overflow) {
					candidate[key] = struct{}{}
				}
			}
			if result == nil {
				result = candidate
				continue
			}
			intersectStringSets(result, candidate)
		}
		return result, true, nil
	case directory.FilterGreaterOrEqual, directory.FilterLessOrEqual:
		attribute, ordering, err := schema.ResolveOrderingIndexAttribute(filter.Attribute)
		if err != nil || !ordering {
			return nil, false, err
		}
		normalized, err := schema.NormalizeOrderingIndexAssertion(
			filter.Attribute,
			filter.Assertion,
		)
		if err != nil {
			return nil, false, err
		}
		keys, err := reader.equalityIndexOrderingPostings(
			partition,
			attribute,
			normalized,
			filter.Kind == directory.FilterGreaterOrEqual,
		)
		return stringSet(keys), true, err
	case directory.FilterAnd:
		var result map[string]struct{}
		plannedAny := false
		for _, child := range filter.Children {
			childKeys, planned, err := planEqualityIndexFilter(
				reader,
				partition,
				schema,
				child,
			)
			if err != nil {
				return nil, false, err
			}
			if !planned {
				continue
			}
			if !plannedAny {
				result = childKeys
				plannedAny = true
				continue
			}
			for key := range result {
				if _, ok := childKeys[key]; !ok {
					delete(result, key)
				}
			}
		}
		return result, plannedAny, nil
	case directory.FilterOr:
		result := make(map[string]struct{})
		for _, child := range filter.Children {
			childKeys, planned, err := planEqualityIndexFilter(
				reader,
				partition,
				schema,
				child,
			)
			if err != nil {
				return nil, false, err
			}
			if !planned {
				return nil, false, nil
			}
			for key := range childKeys {
				result[key] = struct{}{}
			}
		}
		return result, true, nil
	default:
		return nil, false, nil
	}
}

func intersectStringSets(left, right map[string]struct{}) {
	for key := range left {
		if _, ok := right[key]; !ok {
			delete(left, key)
		}
	}
}

type substringIndexConstraint struct {
	kind            byte
	value           []byte
	includeOverflow bool
}

func substringIndexFilterConstraints(
	value directory.Substring,
	initial,
	any,
	final bool,
) []substringIndexConstraint {
	var constraints []substringIndexConstraint
	if initial && value.Initial != nil && len(value.Initial) > 0 {
		length := min(len(value.Initial), substringIndexAnchorMax)
		constraints = append(constraints, substringIndexConstraint{
			kind:  equalityIndexSubstringInitial,
			value: bytes.Clone(value.Initial[:length]),
		})
	}
	if any {
		for _, part := range value.Any {
			if len(part) < substringIndexNGramSize {
				continue
			}
			for _, gram := range boundedQueryNGrams(part) {
				constraints = append(constraints, substringIndexConstraint{
					kind:            equalityIndexSubstringAny,
					value:           gram,
					includeOverflow: true,
				})
			}
		}
	}
	if final && value.Final != nil && len(value.Final) > 0 {
		length := min(len(value.Final), substringIndexAnchorMax)
		constraints = append(constraints, substringIndexConstraint{
			kind:  equalityIndexSubstringFinal,
			value: bytes.Clone(value.Final[len(value.Final)-length:]),
		})
	}
	return constraints
}

// A bounded sample is sufficient here: every selected gram is a necessary
// condition, while final filter evaluation removes false positives.
func boundedQueryNGrams(value []byte) [][]byte {
	count := len(value) - substringIndexNGramSize + 1
	if count <= 0 {
		return nil
	}
	const maxQueryGrams = 8
	selected := min(count, maxQueryGrams)
	result := make([][]byte, 0, selected)
	seen := make(map[string]struct{}, selected)
	for index := 0; index < selected; index++ {
		position := 0
		if selected > 1 {
			position = index * (count - 1) / (selected - 1)
		}
		gram := bytes.Clone(value[position : position+substringIndexNGramSize])
		if _, duplicate := seen[string(gram)]; duplicate {
			continue
		}
		seen[string(gram)] = struct{}{}
		result = append(result, gram)
	}
	return result
}

func normalizeEqualityIndexConfig(
	config EqualityIndexConfig,
) (EqualityIndexConfig, error) {
	if config.Version == 0 {
		config.Version = equalityIndexFormatVersion
	}
	if config.Version != equalityIndexFormatVersion {
		return EqualityIndexConfig{}, fmt.Errorf(
			"unsupported equality index format version %d",
			config.Version,
		)
	}
	byAttribute := make(map[string]EqualityIndexAttribute, len(config.Attributes))
	for _, attribute := range config.Attributes {
		attribute.Attribute = strings.ToLower(strings.TrimSpace(attribute.Attribute))
		attribute.EqualityRule = strings.ToLower(strings.TrimSpace(attribute.EqualityRule))
		attribute.ApproximateRule = strings.ToLower(strings.TrimSpace(attribute.ApproximateRule))
		attribute.SubstringRule = strings.ToLower(strings.TrimSpace(attribute.SubstringRule))
		attribute.OrderingRule = strings.ToLower(strings.TrimSpace(attribute.OrderingRule))
		hasSubstring := attribute.SubstringInitial || attribute.SubstringAny || attribute.SubstringFinal
		if attribute.Attribute == "" ||
			(attribute.Equality && attribute.EqualityRule == "") ||
			(attribute.Approximate && attribute.ApproximateRule == "") ||
			(hasSubstring && attribute.SubstringRule == "") ||
			(attribute.Ordering && attribute.OrderingRule == "") ||
			(!attribute.Equality && !attribute.Presence && !attribute.Approximate &&
				!hasSubstring && !attribute.Ordering && !attribute.NoTags && !attribute.NoSubtypes) {
			return EqualityIndexConfig{}, errors.New(
				"index attribute, enabled mode, and matching rules are required",
			)
		}
		if existing, ok := byAttribute[attribute.Attribute]; ok {
			if rulesConflict(existing.EqualityRule, attribute.EqualityRule) ||
				rulesConflict(existing.ApproximateRule, attribute.ApproximateRule) ||
				rulesConflict(existing.SubstringRule, attribute.SubstringRule) ||
				rulesConflict(existing.OrderingRule, attribute.OrderingRule) {
				return EqualityIndexConfig{}, fmt.Errorf(
					"attribute %q has conflicting index rules",
					attribute.Attribute,
				)
			}
			if attribute.EqualityRule == "" {
				attribute.EqualityRule = existing.EqualityRule
			}
			if attribute.ApproximateRule == "" {
				attribute.ApproximateRule = existing.ApproximateRule
			}
			if attribute.SubstringRule == "" {
				attribute.SubstringRule = existing.SubstringRule
			}
			if attribute.OrderingRule == "" {
				attribute.OrderingRule = existing.OrderingRule
			}
			attribute.Equality = attribute.Equality || existing.Equality
			attribute.Presence = attribute.Presence || existing.Presence
			attribute.Approximate = attribute.Approximate || existing.Approximate
			attribute.SubstringInitial = attribute.SubstringInitial || existing.SubstringInitial
			attribute.SubstringAny = attribute.SubstringAny || existing.SubstringAny
			attribute.SubstringFinal = attribute.SubstringFinal || existing.SubstringFinal
			attribute.Ordering = attribute.Ordering || existing.Ordering
			attribute.NoTags = attribute.NoTags || existing.NoTags
			attribute.NoSubtypes = attribute.NoSubtypes || existing.NoSubtypes
		}
		byAttribute[attribute.Attribute] = attribute
	}
	config.Attributes = config.Attributes[:0]
	for _, attribute := range byAttribute {
		config.Attributes = append(config.Attributes, attribute)
	}
	sort.Slice(config.Attributes, func(left, right int) bool {
		return config.Attributes[left].Attribute < config.Attributes[right].Attribute
	})
	return config, nil
}

func selectedEqualityIndexConfig(
	config EqualityIndexConfig,
	attributes []string,
) (EqualityIndexConfig, error) {
	config, err := normalizeEqualityIndexConfig(config)
	if err != nil {
		return EqualityIndexConfig{}, err
	}
	selected := EqualityIndexConfig{Version: config.Version}
	seen := make(map[string]struct{}, len(attributes))
	for _, raw := range attributes {
		attribute := strings.ToLower(strings.TrimSpace(raw))
		if attribute == "" {
			return EqualityIndexConfig{}, errors.New("selected index attribute must not be empty")
		}
		if _, duplicate := seen[attribute]; duplicate {
			continue
		}
		definition, found := equalityIndexAttributeDefinition(config, attribute)
		if !found {
			return EqualityIndexConfig{}, fmt.Errorf("no index configured for attribute %q", raw)
		}
		seen[attribute] = struct{}{}
		selected.Attributes = append(selected.Attributes, definition)
	}
	if len(selected.Attributes) == 0 {
		return EqualityIndexConfig{}, errors.New("at least one index attribute is required")
	}
	sort.Slice(selected.Attributes, func(left, right int) bool {
		return selected.Attributes[left].Attribute < selected.Attributes[right].Attribute
	})
	return selected, nil
}

func equalityIndexAttributePrefix(partition, attribute string) []byte {
	result := []byte{equalityIndexFormatVersion}
	result = appendLengthPrefixed(result, []byte(partition))
	return appendLengthPrefixed(result, []byte(attribute))
}

func rulesConflict(left, right string) bool {
	return left != "" && right != "" && left != right
}

func equalityIndexConfigsEqual(left, right EqualityIndexConfig) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func equalityIndexConfigFingerprint(config EqualityIndexConfig) (string, error) {
	config, err := normalizeEqualityIndexConfig(config)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func equalityIndexAttributeConfigured(config EqualityIndexConfig, attribute string) bool {
	index := sort.Search(len(config.Attributes), func(index int) bool {
		return config.Attributes[index].Attribute >= attribute
	})
	return index < len(config.Attributes) &&
		config.Attributes[index].Attribute == attribute
}

func equalityIndexAttributeDefinition(
	config EqualityIndexConfig,
	attribute string,
) (EqualityIndexAttribute, bool) {
	index := sort.Search(len(config.Attributes), func(index int) bool {
		return config.Attributes[index].Attribute >= attribute
	})
	if index >= len(config.Attributes) ||
		config.Attributes[index].Attribute != attribute {
		return EqualityIndexAttribute{}, false
	}
	return config.Attributes[index], true
}

type equalityIndexAttributeTerms struct {
	present     bool
	equality    [][]byte
	approximate [][]byte
	substring   [][]byte
	ordering    [][]byte
}

func equalityIndexEntryTerms(
	schema EqualityIndexSchema,
	config EqualityIndexConfig,
	entry directory.Entry,
) (map[string]equalityIndexAttributeTerms, error) {
	terms := make(map[string]equalityIndexAttributeTerms, len(config.Attributes))
	for _, attribute := range config.Attributes {
		var result equalityIndexAttributeTerms
		if attribute.Equality || attribute.Presence {
			values, err := schema.EqualityIndexValues(entry, attribute.Attribute)
			if err != nil {
				return nil, fmt.Errorf("normalize entry %q equality index %s: %w", entry.DN, attribute.Attribute, err)
			}
			result.present = len(values) > 0
			result.equality = uniqueIndexValues(values)
		}
		if attribute.Approximate {
			values, err := schema.ApproximateIndexValues(entry, attribute.Attribute)
			if err != nil {
				return nil, fmt.Errorf("normalize entry %q approximate index %s: %w", entry.DN, attribute.Attribute, err)
			}
			result.present = result.present || len(values) > 0
			result.approximate = uniqueIndexValues(values)
		}
		if attribute.SubstringInitial || attribute.SubstringAny || attribute.SubstringFinal {
			values, err := schema.SubstringIndexValues(entry, attribute.Attribute)
			if err != nil {
				return nil, fmt.Errorf("normalize entry %q substring index %s: %w", entry.DN, attribute.Attribute, err)
			}
			result.present = result.present || len(values) > 0
			result.substring = uniqueIndexValues(values)
		}
		if attribute.Ordering {
			values, err := schema.OrderingIndexValues(entry, attribute.Attribute)
			if err != nil {
				return nil, fmt.Errorf("normalize entry %q ordering index %s: %w", entry.DN, attribute.Attribute, err)
			}
			result.present = result.present || len(values) > 0
			result.ordering = uniqueIndexValues(values)
		}
		terms[attribute.Attribute] = result
	}
	return terms, nil
}

func equalityIndexEntriesHaveSameTerms(
	schema EqualityIndexSchema,
	config EqualityIndexConfig,
	left, right directory.Entry,
) (bool, error) {
	leftTerms, err := equalityIndexEntryTerms(schema, config, left)
	if err != nil {
		return false, err
	}
	rightTerms, err := equalityIndexEntryTerms(schema, config, right)
	if err != nil {
		return false, err
	}
	for _, definition := range config.Attributes {
		leftSet := make(map[string]struct{})
		for _, term := range equalityIndexTermsForAttribute(
			definition,
			leftTerms[definition.Attribute],
		) {
			leftSet[string(append([]byte{term.kind}, term.value...))] = struct{}{}
		}
		rightValues := equalityIndexTermsForAttribute(
			definition,
			rightTerms[definition.Attribute],
		)
		if len(leftSet) != len(rightValues) {
			return false, nil
		}
		for _, term := range rightValues {
			if _, ok := leftSet[string(append([]byte{term.kind}, term.value...))]; !ok {
				return false, nil
			}
		}
	}
	return true, nil
}

func uniqueIndexValues(values [][]byte) [][]byte {
	result := make([][]byte, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[string(value)]; duplicate {
			continue
		}
		seen[string(value)] = struct{}{}
		result = append(result, bytes.Clone(value))
	}
	return result
}

type equalityIndexTerm struct {
	kind  byte
	value []byte
}

func equalityIndexTermsForAttribute(
	definition EqualityIndexAttribute,
	values equalityIndexAttributeTerms,
) []equalityIndexTerm {
	var result []equalityIndexTerm
	if definition.Presence && values.present {
		result = append(result, equalityIndexTerm{kind: equalityIndexPresence})
	}
	if definition.Equality {
		for _, value := range values.equality {
			result = append(result, equalityIndexTerm{kind: equalityIndexValue, value: value})
		}
	}
	if definition.Approximate {
		for _, value := range values.approximate {
			result = append(result, equalityIndexTerm{kind: equalityIndexApproximate, value: value})
		}
	}
	if definition.SubstringInitial || definition.SubstringAny || definition.SubstringFinal {
		seen := make(map[string]struct{})
		for _, value := range values.substring {
			for _, term := range substringIndexValueTerms(value, definition) {
				key := string(append([]byte{term.kind}, term.value...))
				if _, duplicate := seen[key]; duplicate {
					continue
				}
				seen[key] = struct{}{}
				result = append(result, term)
			}
		}
	}
	if definition.Ordering {
		for _, value := range values.ordering {
			result = append(result, equalityIndexTerm{kind: equalityIndexOrdering, value: value})
		}
	}
	return result
}

func substringIndexValueTerms(
	value []byte,
	definition EqualityIndexAttribute,
) []equalityIndexTerm {
	var result []equalityIndexTerm
	if definition.SubstringInitial {
		for length := 1; length <= min(len(value), substringIndexAnchorMax); length++ {
			result = append(result, equalityIndexTerm{kind: equalityIndexSubstringInitial, value: bytes.Clone(value[:length])})
		}
	}
	if definition.SubstringFinal {
		for length := 1; length <= min(len(value), substringIndexAnchorMax); length++ {
			result = append(result, equalityIndexTerm{kind: equalityIndexSubstringFinal, value: bytes.Clone(value[len(value)-length:])})
		}
	}
	if !definition.SubstringAny || len(value) < substringIndexNGramSize {
		return result
	}
	seen := make(map[string]struct{})
	for position := 0; position+substringIndexNGramSize <= len(value); position++ {
		gram := value[position : position+substringIndexNGramSize]
		if _, duplicate := seen[string(gram)]; duplicate {
			continue
		}
		if len(seen) >= substringIndexMaxNGrams {
			result = append(result, equalityIndexTerm{kind: equalityIndexSubstringOverflow})
			return result
		}
		seen[string(gram)] = struct{}{}
		result = append(result, equalityIndexTerm{kind: equalityIndexSubstringAny, value: bytes.Clone(gram)})
	}
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

const (
	equalityIndexPresence          byte = 0
	equalityIndexValue             byte = 1
	equalityIndexSubstringInitial  byte = 2
	equalityIndexSubstringAny      byte = 3
	equalityIndexSubstringFinal    byte = 4
	equalityIndexSubstringOverflow byte = 5
	equalityIndexOrdering          byte = 6
	equalityIndexApproximate       byte = 7
)

func equalityIndexPostingPrefix(
	partition,
	attribute string,
	kind byte,
	value []byte,
) []byte {
	result := equalityIndexAttributeKindPrefix(partition, attribute, kind)
	switch kind {
	case equalityIndexPresence, equalityIndexSubstringOverflow:
		return result
	case equalityIndexOrdering:
		return appendOrderPreservingValue(result, value)
	default:
		return appendLengthPrefixed(result, value)
	}
}

func equalityIndexAttributeKindPrefix(partition, attribute string, kind byte) []byte {
	result := []byte{equalityIndexFormatVersion}
	result = appendLengthPrefixed(result, []byte(partition))
	result = appendLengthPrefixed(result, []byte(attribute))
	return append(result, kind)
}

func equalityIndexPostingKey(
	partition,
	attribute string,
	kind byte,
	value []byte,
	entryKey string,
) []byte {
	return append(
		equalityIndexPostingPrefix(partition, attribute, kind, value),
		[]byte(entryKey)...,
	)
}

func decodeEqualityIndexPostingKey(
	key []byte,
) (partition, attribute string, kind byte, value []byte, entryKey string, err error) {
	if len(key) == 0 || key[0] != equalityIndexFormatVersion {
		return "", "", 0, nil, "", errors.New("invalid equality index key version")
	}
	position := 1
	partitionBytes, next, err := readLengthPrefixed(key, position)
	if err != nil {
		return "", "", 0, nil, "", err
	}
	position = next
	attributeBytes, next, err := readLengthPrefixed(key, position)
	if err != nil {
		return "", "", 0, nil, "", err
	}
	position = next
	if position >= len(key) {
		return "", "", 0, nil, "", errors.New("truncated equality index key")
	}
	kind = key[position]
	position++
	switch kind {
	case equalityIndexPresence, equalityIndexSubstringOverflow:
	case equalityIndexValue, equalityIndexSubstringInitial,
		equalityIndexSubstringAny, equalityIndexSubstringFinal,
		equalityIndexApproximate:
		value, position, err = readLengthPrefixed(key, position)
		if err != nil {
			return "", "", 0, nil, "", err
		}
	case equalityIndexOrdering:
		value, position, err = readOrderPreservingValue(key, position)
		if err != nil {
			return "", "", 0, nil, "", err
		}
	default:
		return "", "", 0, nil, "", fmt.Errorf("invalid equality index key kind %d", kind)
	}
	if position >= len(key) {
		return "", "", 0, nil, "", errors.New("equality index key has no entry key")
	}
	return string(partitionBytes), string(attributeBytes), kind, bytes.Clone(value), string(key[position:]), nil
}

func appendOrderPreservingValue(destination, value []byte) []byte {
	for _, octet := range value {
		destination = append(destination, 1, octet)
	}
	return append(destination, 0)
}

func readOrderPreservingValue(value []byte, position int) ([]byte, int, error) {
	var result []byte
	for position < len(value) {
		switch value[position] {
		case 0:
			return result, position + 1, nil
		case 1:
			if position+1 >= len(value) {
				return nil, position, errors.New("truncated ordering index value")
			}
			result = append(result, value[position+1])
			position += 2
		default:
			return nil, position, errors.New("invalid ordering index value escape")
		}
	}
	return nil, position, errors.New("unterminated ordering index value")
}

func appendLengthPrefixed(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func readLengthPrefixed(value []byte, position int) ([]byte, int, error) {
	if position < 0 || len(value)-position < 4 {
		return nil, position, errors.New("truncated equality index key length")
	}
	length := int(binary.BigEndian.Uint32(value[position : position+4]))
	position += 4
	if length < 0 || len(value)-position < length {
		return nil, position, errors.New("truncated equality index key value")
	}
	return value[position : position+length], position + length, nil
}
