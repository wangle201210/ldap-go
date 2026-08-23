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

const equalityIndexFormatVersion = 1

// EqualityIndexAttribute identifies one equality index by canonical attribute
// OID and effective equality matching rule. The matching rule is part of the
// persisted configuration fingerprint so schema changes cannot reuse stale
// postings.
type EqualityIndexAttribute struct {
	Attribute    string `json:"attribute"`
	EqualityRule string `json:"equalityRule"`
	Equality     bool   `json:"equality"`
	Presence     bool   `json:"presence"`
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
}

type equalityIndexStorageReader interface {
	equalityIndexConfig(partition string) (EqualityIndexConfig, bool, error)
	equalityIndexPostings(
		partition,
		attribute string,
		value []byte,
		presence bool,
	) ([]string, error)
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

type equalityIndexCandidatePlanner interface {
	planEqualityIndexCandidates(directory.Filter) ([]directory.Entry, bool, error)
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
	indexed, ok := writer.(equalityIndexStorageWriter)
	if !ok {
		return errors.New("writer does not support equality indexes")
	}
	return indexed.rebuildEqualityIndexes(partition, schema)
}

// EnsureEqualityIndexes creates or refreshes one partition's indexes only when
// the persisted configuration does not match the requested schema.
func EnsureEqualityIndexes(
	writer Writer,
	partition string,
	schema EqualityIndexSchema,
) error {
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
		if err != nil {
			return err
		}
	}
	if present && equalityIndexConfigsEqual(current, want) {
		return nil
	}
	return indexed.rebuildEqualityIndexes(partition, schema)
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
	indexed, ok := writer.(equalityIndexStorageWriter)
	if !ok {
		return false, nil
	}
	return true, indexed.putInWithEqualityIndexes(
		partition,
		entry,
		dn,
		replace,
		schema,
	)
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
	indexed, ok := writer.(equalityIndexStorageWriter)
	if !ok {
		return false, nil
	}
	return true, indexed.deleteInWithEqualityIndexes(partition, dn, schema)
}

func (reader schemaAwarePartitionReader) planEqualityIndexCandidates(
	filter directory.Filter,
) ([]directory.Entry, bool, error) {
	schema, ok := reader.normalizer.(EqualityIndexSchema)
	if !ok {
		return nil, false, nil
	}
	indexed, ok := reader.Reader.(equalityIndexStorageReader)
	if !ok {
		return nil, false, nil
	}
	want, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil || len(want.Attributes) == 0 {
		return nil, false, err
	}
	stored, present, err := indexed.equalityIndexConfig(reader.partition)
	if err != nil || !present {
		return nil, false, err
	}
	stored, err = normalizeEqualityIndexConfig(stored)
	if err != nil {
		return nil, false, err
	}
	if !equalityIndexConfigsEqual(stored, want) {
		return nil, false, nil
	}

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
			normalized,
			false,
		)
		return stringSet(keys), true, err
	case directory.FilterPresent:
		attribute, _, presence, err := schema.ResolveEqualityIndexAttribute(filter.Attribute)
		if err != nil || !presence {
			return nil, false, err
		}
		keys, err := reader.equalityIndexPostings(
			partition,
			attribute,
			nil,
			true,
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
		if attribute.Attribute == "" ||
			(attribute.Equality && attribute.EqualityRule == "") ||
			(!attribute.Equality && !attribute.Presence) {
			return EqualityIndexConfig{}, errors.New(
				"equality index attribute, mode, and equality rule are required",
			)
		}
		if existing, ok := byAttribute[attribute.Attribute]; ok {
			if existing.EqualityRule != attribute.EqualityRule {
				return EqualityIndexConfig{}, fmt.Errorf(
					"attribute %q has conflicting equality index rules",
					attribute.Attribute,
				)
			}
			attribute.Equality = attribute.Equality || existing.Equality
			attribute.Presence = attribute.Presence || existing.Presence
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

func equalityIndexEntryTerms(
	schema EqualityIndexSchema,
	config EqualityIndexConfig,
	entry directory.Entry,
) (map[string][][]byte, error) {
	terms := make(map[string][][]byte, len(config.Attributes))
	for _, attribute := range config.Attributes {
		values, err := schema.EqualityIndexValues(entry, attribute.Attribute)
		if err != nil {
			return nil, fmt.Errorf(
				"normalize entry %q equality index %s: %w",
				entry.DN,
				attribute.Attribute,
				err,
			)
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			key := string(value)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			terms[attribute.Attribute] = append(
				terms[attribute.Attribute],
				bytes.Clone(value),
			)
		}
	}
	return terms, nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

const (
	equalityIndexPresence byte = 0
	equalityIndexValue    byte = 1
)

func equalityIndexPostingPrefix(
	partition,
	attribute string,
	value []byte,
	presence bool,
) []byte {
	result := []byte{equalityIndexFormatVersion}
	result = appendLengthPrefixed(result, []byte(partition))
	result = appendLengthPrefixed(result, []byte(attribute))
	if presence {
		result = append(result, equalityIndexPresence)
		return result
	}
	result = append(result, equalityIndexValue)
	return appendLengthPrefixed(result, value)
}

func equalityIndexPostingKey(
	partition,
	attribute string,
	value []byte,
	presence bool,
	entryKey string,
) []byte {
	return append(
		equalityIndexPostingPrefix(partition, attribute, value, presence),
		[]byte(entryKey)...,
	)
}

func decodeEqualityIndexPostingKey(
	key []byte,
) (partition, attribute string, value []byte, presence bool, entryKey string, err error) {
	if len(key) == 0 || key[0] != equalityIndexFormatVersion {
		return "", "", nil, false, "", errors.New("invalid equality index key version")
	}
	position := 1
	partitionBytes, next, err := readLengthPrefixed(key, position)
	if err != nil {
		return "", "", nil, false, "", err
	}
	position = next
	attributeBytes, next, err := readLengthPrefixed(key, position)
	if err != nil {
		return "", "", nil, false, "", err
	}
	position = next
	if position >= len(key) {
		return "", "", nil, false, "", errors.New("truncated equality index key")
	}
	kind := key[position]
	position++
	switch kind {
	case equalityIndexPresence:
		presence = true
	case equalityIndexValue:
		value, position, err = readLengthPrefixed(key, position)
		if err != nil {
			return "", "", nil, false, "", err
		}
	default:
		return "", "", nil, false, "", fmt.Errorf("invalid equality index key kind %d", kind)
	}
	if position >= len(key) {
		return "", "", nil, false, "", errors.New("equality index key has no entry key")
	}
	return string(partitionBytes), string(attributeBytes), bytes.Clone(value), presence, string(key[position:]), nil
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
