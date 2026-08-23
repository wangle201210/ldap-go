package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func (tx *boltTx) equalityIndexConfig(
	partition string,
) (EqualityIndexConfig, bool, error) {
	if err := tx.ctx.Err(); err != nil {
		return EqualityIndexConfig{}, false, err
	}
	if tx.equalityIndexConfigs == nil {
		return EqualityIndexConfig{}, false, nil
	}
	encoded := tx.equalityIndexConfigs.Get([]byte(partition))
	if encoded == nil {
		return EqualityIndexConfig{}, false, nil
	}
	var config EqualityIndexConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		return EqualityIndexConfig{}, false, fmt.Errorf(
			"decode equality index configuration for partition %q: %w",
			partition,
			err,
		)
	}
	return config, true, nil
}

func (tx *boltTx) equalityIndexPostings(
	partition,
	attribute string,
	kind byte,
	value []byte,
) ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	if tx.equalityIndexes == nil {
		return nil, nil
	}
	prefix := equalityIndexPostingPrefix(
		partition,
		attribute,
		kind,
		value,
	)
	var result []string
	cursor := tx.equalityIndexes.Cursor()
	for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return nil, err
		}
		if len(key) == len(prefix) {
			return nil, errors.New("equality index posting has no entry key")
		}
		result = append(result, string(key[len(prefix):]))
	}
	return result, nil
}

func (tx *boltTx) equalityIndexOrderingPostings(
	partition,
	attribute string,
	assertion []byte,
	greaterOrEqual bool,
) ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	if tx.equalityIndexes == nil {
		return nil, nil
	}
	prefix := equalityIndexAttributeKindPrefix(partition, attribute, equalityIndexOrdering)
	start := prefix
	if greaterOrEqual {
		start = equalityIndexPostingPrefix(partition, attribute, equalityIndexOrdering, assertion)
	}
	keys := make(map[string]struct{})
	cursor := tx.equalityIndexes.Cursor()
	for key, _ := cursor.Seek(start); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return nil, err
		}
		_, _, kind, value, entryKey, err := decodeEqualityIndexPostingKey(key)
		if err != nil {
			return nil, err
		}
		if kind != equalityIndexOrdering {
			return nil, errors.New("ordering index range contains another posting kind")
		}
		comparison := bytes.Compare(value, assertion)
		if greaterOrEqual {
			if comparison < 0 {
				continue
			}
		} else if comparison > 0 {
			break
		}
		keys[entryKey] = struct{}{}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

func (tx *boltTx) equalityIndexEntries(
	keys []string,
) ([]directory.Entry, error) {
	entries := make([]directory.Entry, 0, len(keys))
	for _, key := range keys {
		if err := tx.ctx.Err(); err != nil {
			return nil, err
		}
		value := tx.entries.Get([]byte(key))
		if value == nil {
			return nil, fmt.Errorf(
				"equality index references missing entry key %q",
				key,
			)
		}
		_, entryKey := splitPartitionedEntryKey(key)
		entry, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (tx *boltTx) putInWithEqualityIndexes(
	partition string,
	entry directory.Entry,
	dn directory.DN,
	replace bool,
	schema EqualityIndexSchema,
) error {
	if !tx.tx.Writable() {
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
		value := tx.entries.Get([]byte(key))
		_, entryKey := splitPartitionedEntryKey(key)
		existing, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return err
		}
		if err := tx.removeEqualityIndexEntry(
			partition,
			key,
			existing,
			schema,
			config,
		); err != nil {
			return err
		}
		if err := tx.entries.Delete([]byte(key)); err != nil {
			return err
		}
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

func (tx *boltTx) deleteInWithEqualityIndexes(
	partition string,
	dn directory.DN,
	schema EqualityIndexSchema,
) error {
	if !tx.tx.Writable() {
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
	value := tx.entries.Get([]byte(key))
	_, entryKey := splitPartitionedEntryKey(key)
	entry, err := decodeAndValidateEntry(entryKey, value)
	if err != nil {
		return err
	}
	if err := tx.removeEqualityIndexEntry(
		partition,
		key,
		entry,
		schema,
		config,
	); err != nil {
		return err
	}
	return tx.entries.Delete([]byte(key))
}

func (tx *boltTx) rebuildEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	config, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil {
		return err
	}
	return tx.buildEqualityIndexes(partition, schema, config)
}

func (tx *boltTx) ensureEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
) (EqualityIndexConfig, error) {
	config, err := normalizeEqualityIndexConfig(schema.EqualityIndexConfiguration())
	if err != nil {
		return EqualityIndexConfig{}, err
	}
	current, ok, err := tx.equalityIndexConfig(partition)
	if err != nil {
		return EqualityIndexConfig{}, err
	}
	if ok {
		current, err = normalizeEqualityIndexConfig(current)
		if err != nil {
			return EqualityIndexConfig{}, err
		}
	}
	if ok && equalityIndexConfigsEqual(current, config) {
		return config, nil
	}
	return config, tx.buildEqualityIndexes(partition, schema, config)
}

func (tx *boltTx) buildEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
	config EqualityIndexConfig,
) error {
	if err := tx.ensureEqualityIndexBuckets(); err != nil {
		return err
	}
	if err := tx.clearEqualityIndexPostings(partition); err != nil {
		return err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if err := tx.equalityIndexConfigs.Put([]byte(partition), encoded); err != nil {
		return err
	}
	return tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entryPartition, entryKey := splitPartitionedEntryKey(string(key))
		if entryPartition != partition {
			return nil
		}
		entry, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return err
		}
		return tx.addEqualityIndexEntry(
			partition,
			string(key),
			entry,
			schema,
			config,
		)
	})
}

func (tx *boltTx) schemaAwareEntryKeys(
	partition string,
	dn directory.DN,
	schema EqualityIndexSchema,
) ([]string, error) {
	normalizer, ok := schema.(directory.DNAttributeNormalizer)
	if !ok {
		return nil, errors.New("equality index schema cannot normalize DNs")
	}
	var keys []string
	err := tx.entries.ForEach(func(key, value []byte) error {
		entryPartition, entryKey := splitPartitionedEntryKey(string(key))
		if entryPartition != partition {
			return nil
		}
		entry, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return err
		}
		candidate, err := directory.ParseDNWithNormalizer(entry.DN, normalizer)
		if err != nil {
			return err
		}
		if candidate.Equal(dn) {
			keys = append(keys, string(key))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(keys) > 1 {
		return nil, ErrEntryAmbiguous
	}
	return keys, nil
}

func (tx *boltTx) addEqualityIndexEntry(
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
	for attribute, values := range terms {
		definition, _ := equalityIndexAttributeDefinition(config, attribute)
		for _, term := range equalityIndexTermsForAttribute(definition, values) {
			if err := tx.equalityIndexes.Put(
				equalityIndexPostingKey(partition, attribute, term.kind, term.value, entryKey),
				[]byte{1},
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (tx *boltTx) removeEqualityIndexEntry(
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
	for attribute, values := range terms {
		definition, _ := equalityIndexAttributeDefinition(config, attribute)
		for _, term := range equalityIndexTermsForAttribute(definition, values) {
			if err := tx.equalityIndexes.Delete(
				equalityIndexPostingKey(partition, attribute, term.kind, term.value, entryKey),
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (tx *boltTx) invalidateEqualityIndexes(partition string) error {
	if tx.equalityIndexConfigs == nil || tx.equalityIndexes == nil {
		return nil
	}
	if err := tx.equalityIndexConfigs.Delete([]byte(partition)); err != nil {
		return err
	}
	return tx.clearEqualityIndexPostings(partition)
}

func (tx *boltTx) clearEqualityIndexPostings(partition string) error {
	if tx.equalityIndexes == nil {
		return nil
	}
	prefix := equalityIndexPartitionPrefix(partition)
	cursor := tx.equalityIndexes.Cursor()
	var keys [][]byte
	for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		keys = append(keys, bytes.Clone(key))
	}
	for _, key := range keys {
		if err := tx.equalityIndexes.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func (tx *boltTx) ensureEqualityIndexBuckets() error {
	if tx.equalityIndexes == nil {
		bucket, err := tx.tx.CreateBucketIfNotExists(equalityIndexBucket)
		if err != nil {
			return err
		}
		tx.equalityIndexes = bucket
	}
	if tx.equalityIndexConfigs == nil {
		bucket, err := tx.tx.CreateBucketIfNotExists(equalityIndexConfigBucket)
		if err != nil {
			return err
		}
		tx.equalityIndexConfigs = bucket
	}
	return nil
}

func equalityIndexPartitionPrefix(partition string) []byte {
	result := []byte{equalityIndexFormatVersion}
	return appendLengthPrefixed(result, []byte(partition))
}

var _ equalityIndexStorageWriter = (*boltTx)(nil)
