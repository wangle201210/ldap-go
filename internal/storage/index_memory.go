package storage

import (
	"errors"
	"fmt"
	"sort"

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
	value []byte,
	presence bool,
) ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	term := string(equalityIndexPostingPrefix(
		partition,
		attribute,
		value,
		presence,
	))
	keys := tx.equalityPostings[partition][term]
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

func (tx *memoryTx) equalityIndexEntries(
	keys []string,
) ([]directory.Entry, error) {
	entries := make([]directory.Entry, 0, len(keys))
	for _, key := range keys {
		if err := tx.ctx.Err(); err != nil {
			return nil, err
		}
		entry, ok := tx.entries[key]
		if !ok {
			return nil, fmt.Errorf(
				"equality index references missing entry key %q",
				key,
			)
		}
		if err := tx.validateEntry(key, entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry.Clone())
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
	normalizer, ok := schema.(directory.DNAttributeNormalizer)
	if !ok {
		return nil, errors.New("equality index schema cannot normalize DNs")
	}
	var keys []string
	for key, entry := range tx.entries {
		entryPartition, _ := splitPartitionedEntryKey(key)
		if entryPartition != partition {
			continue
		}
		candidate, err := directory.ParseDNWithNormalizer(entry.DN, normalizer)
		if err != nil {
			return nil, err
		}
		if candidate.Equal(dn) {
			keys = append(keys, key)
		}
	}
	if len(keys) > 1 {
		return nil, ErrEntryAmbiguous
	}
	return keys, nil
}

func (tx *memoryTx) addEqualityIndexEntry(
	partition,
	entryKey string,
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
		if len(values) == 0 {
			continue
		}
		if definition.Presence {
			addMemoryEqualityPosting(postings, partition, attribute, nil, true, entryKey)
		}
		if definition.Equality {
			for _, value := range values {
				addMemoryEqualityPosting(postings, partition, attribute, value, false, entryKey)
			}
		}
	}
	return nil
}

func (tx *memoryTx) removeEqualityIndexEntry(
	partition,
	entryKey string,
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
		if len(values) == 0 {
			continue
		}
		if definition.Presence {
			deleteMemoryEqualityPosting(postings, partition, attribute, nil, true, entryKey)
		}
		if definition.Equality {
			for _, value := range values {
				deleteMemoryEqualityPosting(postings, partition, attribute, value, false, entryKey)
			}
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
	value []byte,
	presence bool,
	entryKey string,
) {
	term := string(equalityIndexPostingPrefix(partition, attribute, value, presence))
	if postings[term] == nil {
		postings[term] = make(map[string]struct{})
	}
	postings[term][entryKey] = struct{}{}
}

func deleteMemoryEqualityPosting(
	postings map[string]map[string]struct{},
	partition,
	attribute string,
	value []byte,
	presence bool,
	entryKey string,
) {
	term := string(equalityIndexPostingPrefix(partition, attribute, value, presence))
	delete(postings[term], entryKey)
	if len(postings[term]) == 0 {
		delete(postings, term)
	}
}

var _ equalityIndexStorageWriter = (*memoryTx)(nil)
