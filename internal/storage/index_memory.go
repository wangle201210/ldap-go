package storage

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func cloneEqualityIndexConfigs(
	source map[string]EqualityIndexConfig,
) map[string]EqualityIndexConfig {
	result := make(map[string]EqualityIndexConfig, len(source))
	for partition, config := range source {
		config.Attributes = append(
			[]EqualityIndexAttribute(nil),
			config.Attributes...,
		)
		result[partition] = config
	}
	return result
}

func cloneEqualityIndexPostings(
	source map[string]map[string]map[string]struct{},
) map[string]map[string]map[string]struct{} {
	result := make(map[string]map[string]map[string]struct{}, len(source))
	for partition, terms := range source {
		clonedTerms := make(map[string]map[string]struct{}, len(terms))
		for term, keys := range terms {
			clonedKeys := make(map[string]struct{}, len(keys))
			for key := range keys {
				clonedKeys[key] = struct{}{}
			}
			clonedTerms[term] = clonedKeys
		}
		result[partition] = clonedTerms
	}
	return result
}

func (tx *memoryTx) equalityIndexConfig(
	partition string,
) (EqualityIndexConfig, bool, error) {
	if err := tx.ctx.Err(); err != nil {
		return EqualityIndexConfig{}, false, err
	}
	config, ok := tx.equalityIndexConfigs[partition]
	if !ok {
		return EqualityIndexConfig{}, false, nil
	}
	config.Attributes = append(
		[]EqualityIndexAttribute(nil),
		config.Attributes...,
	)
	return config, true, nil
}

func (tx *memoryTx) equalityIndexPostings(
	partition,
	attribute string,
	kind byte,
	value []byte,
) ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	term := string(equalityIndexPostingPrefix(
		partition,
		attribute,
		kind,
		value,
	))
	keys := tx.equalityPostings[partition][term]
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

func (tx *memoryTx) equalityIndexOrderingPostings(
	partition,
	attribute string,
	assertion []byte,
	greaterOrEqual bool,
) ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	prefix := equalityIndexAttributeKindPrefix(partition, attribute, equalityIndexOrdering)
	keys := make(map[string]struct{})
	for term, postings := range tx.equalityPostings[partition] {
		if !strings.HasPrefix(term, string(prefix)) {
			continue
		}
		value, position, err := readOrderPreservingValue([]byte(term), len(prefix))
		if err != nil || position != len(term) {
			if err == nil {
				err = errors.New("ordering index term has trailing data")
			}
			return nil, err
		}
		comparison := bytes.Compare(value, assertion)
		if greaterOrEqual && comparison < 0 || !greaterOrEqual && comparison > 0 {
			continue
		}
		for key := range postings {
			keys[key] = struct{}{}
		}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

func (tx *memoryTx) equalityIndexEntries(
	partition string,
	references []string,
	schema EqualityIndexSchema,
) ([]directory.Entry, error) {
	entries := make([]directory.Entry, 0, len(references))
	for _, reference := range references {
		if err := tx.ctx.Err(); err != nil {
			return nil, err
		}
		dn, err := resolveEqualityIndexDNReference(schema, reference)
		if err != nil {
			return nil, fmt.Errorf("resolve equality index DN reference %q: %w", reference, err)
		}
		key := partitionedEntryKey(partition, dn.Key())
		entry, ok := tx.entries[key]
		if !ok {
			legacy, legacyErr := directory.ParseDN(reference)
			if legacyErr != nil {
				return nil, legacyErr
			}
			legacyKey := partitionedEntryKey(partition, legacy.Key())
			if legacyKey != key {
				key = legacyKey
				entry, ok = tx.entries[key]
			}
		}
		if !ok {
			return nil, fmt.Errorf(
				"equality index references missing entry key %q",
				key,
			)
		}
		if err := tx.validateEntry(key, entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry.Clone().WithNormalizedDNHint(
			dn,
			dn.LegacyKey()+"\x00"+dn.Key(),
		))
	}
	return entries, nil
}

func (tx *memoryTx) putInWithEqualityIndexes(
	partition string,
	entry directory.Entry,
	dn directory.DN,
	replace bool,
	schema EqualityIndexSchema,
) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	config, err := tx.ensureEqualityIndexes(partition, schema)
	if err != nil {
		return err
	}
	existingKeys, err := tx.schemaAwareEntryKeys(partition, dn, schema)
	if err != nil {
		return err
	}
	if len(existingKeys) > 0 && !replace {
		return ErrEntryExists
	}
	for _, key := range existingKeys {
		if err := tx.removeEqualityIndexEntry(
			partition,
			key,
			tx.entries[key],
			schema,
			config,
		); err != nil {
			return err
		}
		delete(tx.entries, key)
		delete(tx.dnIdentities, key)
		delete(tx.dnSources, key)
	}
	if err := tx.putInWithDN(
		partition,
		entry.WithoutDNIdentity(),
		dn,
		dn.Key(),
		false,
	); err != nil {
		return err
	}
	key := partitionedEntryKey(partition, dn.Key())
	return tx.addEqualityIndexEntry(partition, key, entry, schema, config)
}

func (tx *memoryTx) deleteInWithEqualityIndexes(
	partition string,
	dn directory.DN,
	schema EqualityIndexSchema,
) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	config, err := tx.ensureEqualityIndexes(partition, schema)
	if err != nil {
		return err
	}
	keys, err := tx.schemaAwareEntryKeys(partition, dn, schema)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return ErrEntryNotFound
	}
	key := keys[0]
	if err := tx.removeEqualityIndexEntry(
		partition,
		key,
		tx.entries[key],
		schema,
		config,
	); err != nil {
		return err
	}
	delete(tx.entries, key)
	delete(tx.dnIdentities, key)
	delete(tx.dnSources, key)
	return nil
}

func (tx *memoryTx) rebuildEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	config, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil {
		return err
	}
	return tx.buildEqualityIndexes(partition, schema, config)
}

func (tx *memoryTx) rebuildSelectedEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
	attributes []string,
) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	want, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil {
		return err
	}
	selected, err := selectedEqualityIndexConfig(want, attributes)
	if err != nil {
		return err
	}
	current, present := tx.equalityIndexConfigs[partition]
	if present {
		current, err = normalizeEqualityIndexConfig(current)
	}
	if !present || err != nil || !equalityIndexConfigsEqual(current, want) {
		return tx.buildEqualityIndexes(partition, schema, want)
	}
	postings := tx.equalityPostings[partition]
	for _, definition := range selected.Attributes {
		prefix := string(equalityIndexAttributePrefix(partition, definition.Attribute))
		for term := range postings {
			if strings.HasPrefix(term, prefix) {
				delete(postings, term)
			}
		}
	}
	keys := make([]string, 0)
	for key := range tx.entries {
		entryPartition, _ := splitPartitionedEntryKey(key)
		if entryPartition == partition {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := tx.addEqualityIndexEntry(
			partition, key, tx.entries[key], schema, selected,
		); err != nil {
			return err
		}
	}
	return nil
}

func (tx *memoryTx) ensureEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
) (EqualityIndexConfig, error) {
	config, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil {
		return EqualityIndexConfig{}, err
	}
	current, ok := tx.equalityIndexConfigs[partition]
	if ok && equalityIndexConfigsEqual(current, config) {
		return config, nil
	}
	return config, tx.buildEqualityIndexes(partition, schema, config)
}

func (tx *memoryTx) buildEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
	config EqualityIndexConfig,
) error {
	tx.equalityIndexConfigs[partition] = config
	tx.equalityPostings[partition] = make(map[string]map[string]struct{})
	keys := make([]string, 0)
	for key := range tx.entries {
		entryPartition, _ := splitPartitionedEntryKey(key)
		if entryPartition == partition {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := tx.addEqualityIndexEntry(
			partition,
			key,
			tx.entries[key],
			schema,
			config,
		); err != nil {
			return err
		}
	}
	return nil
}

func (tx *memoryTx) schemaAwareEntryKeys(
	partition string,
	dn directory.DN,
	schema EqualityIndexSchema,
) ([]string, error) {
	if _, ok := schema.(directory.DNAttributeNormalizer); !ok {
		return nil, errors.New("equality index schema cannot normalize DNs")
	}
	key := partitionedEntryKey(partition, dn.Key())
	entry, ok := tx.entries[key]
	if !ok {
		return nil, nil
	}
	if err := tx.validateEntry(key, entry); err != nil {
		return nil, err
	}
	return []string{key}, nil
}

func (tx *memoryTx) addEqualityIndexEntry(
	partition,
	_ string,
	entry directory.Entry,
	schema EqualityIndexSchema,
	config EqualityIndexConfig,
) error {
	terms, err := equalityIndexEntryTerms(schema, config, entry)
	if err != nil {
		return err
	}
	postings := tx.equalityPostings[partition]
	for attribute, values := range terms {
		definition, _ := equalityIndexAttributeDefinition(config, attribute)
		for _, term := range equalityIndexTermsForAttribute(definition, values) {
			addMemoryEqualityPosting(postings, partition, attribute, term.kind, term.value, entry.DN)
		}
	}
	return nil
}

func (tx *memoryTx) removeEqualityIndexEntry(
	partition,
	_ string,
	entry directory.Entry,
	schema EqualityIndexSchema,
	config EqualityIndexConfig,
) error {
	terms, err := equalityIndexEntryTerms(schema, config, entry)
	if err != nil {
		return err
	}
	postings := tx.equalityPostings[partition]
	for attribute, values := range terms {
		definition, _ := equalityIndexAttributeDefinition(config, attribute)
		for _, term := range equalityIndexTermsForAttribute(definition, values) {
			deleteMemoryEqualityPosting(postings, partition, attribute, term.kind, term.value, entry.DN)
		}
	}
	return nil
}

func (tx *memoryTx) invalidateEqualityIndexes(partition string) {
	delete(tx.equalityIndexConfigs, partition)
	delete(tx.equalityPostings, partition)
}

func addMemoryEqualityPosting(
	postings map[string]map[string]struct{},
	partition,
	attribute string,
	kind byte,
	value []byte,
	entryKey string,
) {
	term := string(equalityIndexPostingPrefix(partition, attribute, kind, value))
	if postings[term] == nil {
		postings[term] = make(map[string]struct{})
	}
	postings[term][entryKey] = struct{}{}
}

func deleteMemoryEqualityPosting(
	postings map[string]map[string]struct{},
	partition,
	attribute string,
	kind byte,
	value []byte,
	entryKey string,
) {
	term := string(equalityIndexPostingPrefix(partition, attribute, kind, value))
	delete(postings[term], entryKey)
	if len(postings[term]) == 0 {
		delete(postings, term)
	}
}

var _ equalityIndexStorageWriter = (*memoryTx)(nil)
var _ selectiveEqualityIndexStorageWriter = (*memoryTx)(nil)
