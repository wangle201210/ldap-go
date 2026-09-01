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
		_, _, kind, value, entryReference, err := decodeEqualityIndexPostingKey(key)
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
		keys[entryReference] = struct{}{}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

func (tx *boltTx) equalityIndexEntries(
	partition string,
	references []string,
	schema EqualityIndexSchema,
) ([]directory.Entry, error) {
	entries := make([]directory.Entry, 0, len(references))
	ready, err := tx.schemaAwareDNIdentityReady(partition)
	if err != nil {
		return nil, err
	}
	for _, entryID := range references {
		if err := tx.ctx.Err(); err != nil {
			return nil, err
		}
		if len(entryID) != equalityIndexEntryIDSize || tx.equalityIndexRefs == nil {
			return nil, errors.New("equality index entry reference is invalid")
		}
		encodedReference := tx.equalityIndexRefs.Get([]byte(entryID))
		if encodedReference == nil {
			return nil, fmt.Errorf("equality index references missing entry ID %x", entryID)
		}
		referencePartition, locator, err := decodeEqualityIndexEntryReference(encodedReference)
		if err != nil {
			return nil, err
		}
		if referencePartition != partition {
			return nil, fmt.Errorf(
				"equality index entry ID %x crosses partitions %q and %q",
				entryID,
				referencePartition,
				partition,
			)
		}
		var dn directory.DN
		physicalEntryKey := ""
		if isSchemaAwareDNKey(locator) {
			physicalEntryKey = partitionedEntryKey(partition, locator)
		}
		key := physicalEntryKey
		if key == "" {
			dn, err = resolveEqualityIndexDNReference(schema, locator)
			if err != nil {
				return nil, fmt.Errorf("resolve equality index DN reference %q: %w", locator, err)
			}
			key = partitionedEntryKey(partition, dn.Key())
		}
		value := tx.entries.Get([]byte(key))
		if value == nil && physicalEntryKey == "" {
			legacy, legacyErr := directory.ParseDN(locator)
			if legacyErr != nil {
				return nil, legacyErr
			}
			legacyKey := partitionedEntryKey(partition, legacy.Key())
			if legacyKey != key {
				key = legacyKey
				value = tx.entries.Get([]byte(key))
			}
		}
		if value == nil {
			return nil, fmt.Errorf(
				"equality index references missing entry key %q",
				key,
			)
		}
		_, entryKey := splitPartitionedEntryKey(key)
		var entry directory.Entry
		if ready && isSchemaAwareDNKey(entryKey) {
			stored, decodeErr := decodeStoredEntry(value)
			if decodeErr != nil {
				return nil, decodeErr
			}
			entry = stored.Entry
		} else {
			var decodeErr error
			entry, decodeErr = decodeAndValidateEntry(entryKey, value)
			if decodeErr != nil {
				return nil, decodeErr
			}
		}
		if physicalEntryKey == "" {
			entry = entry.WithNormalizedDNHint(
				dn,
				dn.LegacyKey()+"\x00"+dn.Key(),
			)
		} else if ready && isSchemaAwareDNKey(entryKey) {
			entry = entry.WithDNIdentityKey(entryKey)
		} else {
			dn, err = directory.ParseDNWithIdentityKey(entry.DN, entryKey)
			if err != nil {
				return nil, err
			}
			entry = entry.WithNormalizedDNHint(
				dn,
				dn.LegacyKey()+"\x00"+dn.Key(),
			)
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
	if len(existingKeys) == 1 && existingKeys[0] == partitionedEntryKey(partition, dn.Key()) {
		value := tx.entries.Get([]byte(existingKeys[0]))
		_, entryKey := splitPartitionedEntryKey(existingKeys[0])
		existing, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return err
		}
		same, err := equalityIndexEntriesHaveSameTerms(schema, config, existing, entry)
		if err != nil {
			return err
		}
		if same {
			return tx.putInWithDN(
				partition,
				entry.WithoutDNIdentity(),
				dn,
				dn.Key(),
				true,
			)
		}
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

func (tx *boltTx) rebuildSelectedEqualityIndexes(
	partition string,
	schema EqualityIndexSchema,
	attributes []string,
) error {
	if !tx.tx.Writable() {
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
	current, present, err := tx.equalityIndexConfig(partition)
	if err != nil {
		return err
	}
	if present {
		current, err = normalizeEqualityIndexConfig(current)
	}
	if !present || err != nil || !equalityIndexConfigsEqual(current, want) {
		return tx.buildEqualityIndexes(partition, schema, want)
	}
	if err := tx.ensureEqualityIndexBuckets(); err != nil {
		return err
	}
	for _, definition := range selected.Attributes {
		prefix := equalityIndexAttributePrefix(partition, definition.Attribute)
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
			partition, string(key), entry, schema, selected,
		)
	})
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
		if err == nil && equalityIndexConfigsEqual(current, config) {
			return config, nil
		}
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
	if err := tx.validateEqualityIndexTokens(partition, config); err != nil {
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

func (tx *boltTx) validateEqualityIndexTokens(
	partition string,
	config EqualityIndexConfig,
) error {
	partitionTokens := make(map[string]string)
	attributeTokens := make(map[string]string)
	register := func(candidatePartition string, candidate EqualityIndexConfig) error {
		partitionToken := string(appendEqualityIndexToken(
			nil,
			"partition",
			candidatePartition,
			equalityIndexTokenSize,
		))
		if previous, found := partitionTokens[partitionToken]; found && previous != candidatePartition {
			return fmt.Errorf(
				"equality index partition token collision between %q and %q",
				previous,
				candidatePartition,
			)
		}
		partitionTokens[partitionToken] = candidatePartition
		for _, definition := range candidate.Attributes {
			attributeToken := string(appendEqualityIndexToken(
				nil,
				"attribute",
				definition.Attribute,
				equalityIndexTokenSize,
			))
			if previous, found := attributeTokens[attributeToken]; found &&
				previous != definition.Attribute {
				return fmt.Errorf(
					"equality index attribute token collision between %q and %q",
					previous,
					definition.Attribute,
				)
			}
			attributeTokens[attributeToken] = definition.Attribute
		}
		return nil
	}
	if tx.equalityIndexConfigs != nil {
		if err := tx.equalityIndexConfigs.ForEach(func(key, value []byte) error {
			if string(key) == partition {
				return nil
			}
			var existing EqualityIndexConfig
			if err := json.Unmarshal(value, &existing); err != nil {
				return err
			}
			existing, err := normalizeEqualityIndexConfig(existing)
			if err != nil {
				return err
			}
			return register(string(key), existing)
		}); err != nil {
			return err
		}
	}
	return register(partition, config)
}

func (tx *boltTx) schemaAwareEntryKeys(
	partition string,
	dn directory.DN,
	schema EqualityIndexSchema,
) ([]string, error) {
	if _, ok := schema.(directory.DNAttributeNormalizer); !ok {
		return nil, errors.New("equality index schema cannot normalize DNs")
	}
	key := partitionedEntryKey(partition, dn.Key())
	value := tx.entries.Get([]byte(key))
	if value == nil {
		return nil, nil
	}
	if _, err := decodeAndValidateEntry(dn.Key(), value); err != nil {
		return nil, err
	}
	return []string{key}, nil
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
	entryID := ""
	for attribute, values := range terms {
		definition, _ := equalityIndexAttributeDefinition(config, attribute)
		for _, term := range equalityIndexTermsForAttribute(definition, values) {
			if entryID == "" {
				entryID, err = tx.putEqualityIndexEntryReference(partition, entryKey, entry.DN)
				if err != nil {
					return err
				}
			}
			if err := tx.equalityIndexes.Put(
				equalityIndexPostingKey(partition, attribute, term.kind, term.value, entryID),
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
	entryID := string(equalityIndexEntryID(partition, entryKey))
	hadPosting := false
	for attribute, values := range terms {
		definition, _ := equalityIndexAttributeDefinition(config, attribute)
		for _, term := range equalityIndexTermsForAttribute(definition, values) {
			hadPosting = true
			if err := tx.equalityIndexes.Delete(
				equalityIndexPostingKey(partition, attribute, term.kind, term.value, entryID),
			); err != nil {
				return err
			}
		}
	}
	if hadPosting && tx.equalityIndexRefs != nil {
		return tx.equalityIndexRefs.Delete([]byte(entryID))
	}
	return nil
}

func (tx *boltTx) putEqualityIndexEntryReference(
	partition,
	entryKey,
	reference string,
) (string, error) {
	if tx.equalityIndexRefs == nil {
		return "", errors.New("equality index reference bucket is missing")
	}
	entryID := equalityIndexEntryID(partition, entryKey)
	_, physicalKey := splitPartitionedEntryKey(entryKey)
	encoded := encodeEqualityIndexEntryReference(partition, physicalKey)
	if existing := tx.equalityIndexRefs.Get(entryID); existing != nil &&
		!bytes.Equal(existing, encoded) {
		existingPartition, existingLocator, decodeErr :=
			decodeEqualityIndexEntryReference(existing)
		if decodeErr != nil || existingPartition != partition ||
			(existingLocator != reference && existingLocator != physicalKey) {
			return "", fmt.Errorf(
				"equality index entry ID collision %x between %q and %q",
				entryID,
				existing,
				encoded,
			)
		}
	}
	if err := tx.equalityIndexRefs.Put(entryID, encoded); err != nil {
		return "", err
	}
	return string(entryID), nil
}

func equalityIndexEntryID(partition, entryKey string) []byte {
	return appendEqualityIndexToken(nil, "entry\x00"+partition, entryKey, equalityIndexEntryIDSize)
}

func encodeEqualityIndexEntryReference(partition, locator string) []byte {
	encoded := appendLengthPrefixed(nil, []byte(partition))
	return appendLengthPrefixed(encoded, []byte(locator))
}

func decodeEqualityIndexEntryReference(encoded []byte) (string, string, error) {
	partition, position, err := readLengthPrefixed(encoded, 0)
	if err != nil {
		return "", "", err
	}
	locator, position, err := readLengthPrefixed(encoded, position)
	if err != nil {
		return "", "", err
	}
	if position != len(encoded) {
		return "", "", errors.New("equality index entry reference has trailing data")
	}
	return string(partition), string(locator), nil
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
	if tx.equalityIndexRefs == nil {
		return nil
	}
	keys = keys[:0]
	if err := tx.equalityIndexRefs.ForEach(func(key, value []byte) error {
		referencePartition, _, err := decodeEqualityIndexEntryReference(value)
		if err != nil {
			return err
		}
		if referencePartition == partition {
			keys = append(keys, bytes.Clone(key))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, key := range keys {
		if err := tx.equalityIndexRefs.Delete(key); err != nil {
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
	if tx.equalityIndexRefs == nil {
		bucket, err := tx.tx.CreateBucketIfNotExists(equalityIndexRefBucket)
		if err != nil {
			return err
		}
		tx.equalityIndexRefs = bucket
	}
	tx.applyFillPercent()
	return nil
}

func equalityIndexPartitionPrefix(partition string) []byte {
	result := []byte{equalityIndexFormatVersion}
	return appendEqualityIndexToken(result, "partition", partition, equalityIndexTokenSize)
}

var _ equalityIndexStorageWriter = (*boltTx)(nil)
var _ selectiveEqualityIndexStorageWriter = (*boltTx)(nil)
