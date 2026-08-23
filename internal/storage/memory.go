package storage

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type Memory struct {
	mu             sync.RWMutex
	entries        map[string]directory.Entry
	dnIdentities   map[string]string
	dnSources      map[string]string
	namingContexts []string
	metadata       map[string][]byte
	closed         bool
}

func NewMemory() *Memory {
	return &Memory{
		entries:      make(map[string]directory.Entry),
		dnIdentities: make(map[string]string),
		dnSources:    make(map[string]string),
		metadata:     make(map[string][]byte),
	}
}

func (store *Memory) View(ctx context.Context, fn func(Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return context.Canceled
	}
	return fn(&memoryTx{
		ctx:            ctx,
		entries:        store.entries,
		dnIdentities:   store.dnIdentities,
		dnSources:      store.dnSources,
		namingContexts: store.namingContexts,
		metadata:       store.metadata,
		readOnly:       true,
	})
}

func (store *Memory) Update(ctx context.Context, fn func(Writer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return context.Canceled
	}

	tx := &memoryTx{
		ctx:            ctx,
		entries:        cloneEntryMap(store.entries),
		dnIdentities:   cloneStringMap(store.dnIdentities),
		dnSources:      cloneStringMap(store.dnSources),
		namingContexts: append([]string(nil), store.namingContexts...),
		metadata:       cloneMetadataMap(store.metadata),
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	store.entries = tx.entries
	store.dnIdentities = tx.dnIdentities
	store.dnSources = tx.dnSources
	store.namingContexts = tx.namingContexts
	store.metadata = tx.metadata
	return nil
}

func (store *Memory) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closed = true
	store.entries = nil
	store.dnIdentities = nil
	store.dnSources = nil
	store.namingContexts = nil
	store.metadata = nil
	return nil
}

type memoryTx struct {
	ctx            context.Context
	entries        map[string]directory.Entry
	dnIdentities   map[string]string
	dnSources      map[string]string
	namingContexts []string
	metadata       map[string][]byte
	readOnly       bool
}

func (tx *memoryTx) Get(dn directory.DN) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	var result directory.Entry
	found := false
	for key, entry := range tx.entries {
		_, entryDN := splitPartitionedEntryKey(key)
		directIdentity := entryDN == dn.Key()
		if !directIdentity && !entryMatchesDisplayDN(entry, dn) {
			continue
		}
		if err := tx.validateEntry(key, entry); err != nil {
			return directory.Entry{}, err
		}
		if entryDN == dn.Key() {
			if err := validateDirectIdentityLookup(entryDN, dn); err != nil {
				return directory.Entry{}, err
			}
		}
		if found {
			return directory.Entry{}, ErrEntryAmbiguous
		}
		result = entry
		found = true
	}
	if !found {
		return directory.Entry{}, ErrEntryNotFound
	}
	return result.Clone(), nil
}

func (tx *memoryTx) GetIn(partition string, dn directory.DN) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	key := partitionedEntryKey(partition, dn.Key())
	entry, ok := tx.entries[key]
	var directKey string
	var directEntry directory.Entry
	if ok {
		if err := tx.validateEntry(key, entry); err != nil {
			return directory.Entry{}, err
		}
		if err := validateDirectIdentityLookup(dn.Key(), dn); err != nil {
			return directory.Entry{}, err
		}
		directKey = key
		directEntry = entry
	}
	match := directEntry
	matchKey := directKey
	for key, candidate := range tx.entries {
		if key == directKey {
			continue
		}
		entryPartition, _ := splitPartitionedEntryKey(key)
		if entryPartition != partition || !entryMatchesDisplayDN(candidate, dn) {
			continue
		}
		if err := tx.validateEntry(key, candidate); err != nil {
			return directory.Entry{}, err
		}
		if matchKey != "" {
			return directory.Entry{}, ErrEntryAmbiguous
		}
		match = candidate
		matchKey = key
	}
	if matchKey == "" {
		return directory.Entry{}, ErrEntryNotFound
	}
	return match.Clone(), nil
}

func (tx *memoryTx) ForEach(fn func(directory.Entry) error) error {
	keys := make([]string, 0, len(tx.entries))
	for key := range tx.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entry := tx.entries[key]
		if err := tx.validateEntry(key, entry); err != nil {
			return err
		}
		if err := fn(entry.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (tx *memoryTx) ForEachIn(
	partition string,
	fn func(directory.Entry) error,
) error {
	keys := make([]string, 0)
	for key := range tx.entries {
		entryPartition, _ := splitPartitionedEntryKey(key)
		if entryPartition == partition {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	for _, key := range keys {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entry := tx.entries[key]
		if err := tx.validateEntry(key, entry); err != nil {
			return err
		}
		if err := fn(entry.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (tx *memoryTx) ForEachPartition(
	fn func(string, directory.Entry) error,
) error {
	keys := make([]string, 0, len(tx.entries))
	for key := range tx.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		partition, _ := splitPartitionedEntryKey(key)
		entry := tx.entries[key]
		if err := tx.validateEntry(key, entry); err != nil {
			return err
		}
		if err := fn(partition, entry.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (tx *memoryTx) NamingContexts() ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	return append([]string(nil), tx.namingContexts...), nil
}

func (tx *memoryTx) Metadata(key string) ([]byte, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	value, ok := tx.metadata[key]
	if !ok {
		return nil, ErrMetadataNotFound
	}
	return bytes.Clone(value), nil
}

func (tx *memoryTx) Put(entry directory.Entry, replace bool) error {
	return tx.PutIn("", entry, replace)
}

func (tx *memoryTx) PutIn(
	partition string,
	entry directory.Entry,
	replace bool,
) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	identity := dn.Key()
	if normalized, ok := entry.DNIdentity(); ok {
		if err := requireTrustedDNIdentityWrite(partition, entry, normalized); err != nil {
			return err
		}
		identity = normalized
	}
	if err := dn.ValidateIdentityKey(identity); err != nil {
		return fmt.Errorf("entry %q DN identity: %w", entry.DN, err)
	}
	return tx.putInWithDN(partition, entry.WithoutDNIdentity(), dn, identity, replace)
}

func (tx *memoryTx) putInWithDN(
	partition string,
	entry directory.Entry,
	entryDN directory.DN,
	identity string,
	replace bool,
) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	key := partitionedEntryKey(partition, identity)
	existingKeys := make(map[string]struct{})
	if _, exists := tx.entries[key]; exists {
		existingKeys[key] = struct{}{}
	}
	for candidateKey, candidate := range tx.entries {
		candidatePartition, _ := splitPartitionedEntryKey(candidateKey)
		if candidatePartition == partition && entryMatchesDisplayDN(candidate, entryDN) {
			existingKeys[candidateKey] = struct{}{}
		}
	}
	if len(existingKeys) > 0 && !replace {
		return ErrEntryExists
	}
	tx.entries[key] = entry.Clone()
	if isSchemaAwareDNKey(identity) {
		tx.dnIdentities[key] = identity
		tx.dnSources[key] = entry.DN
	} else {
		delete(tx.dnIdentities, key)
		delete(tx.dnSources, key)
	}
	for existingKey := range existingKeys {
		if existingKey != key {
			delete(tx.entries, existingKey)
			delete(tx.dnIdentities, existingKey)
			delete(tx.dnSources, existingKey)
		}
	}
	return nil
}

func (tx *memoryTx) Delete(dn directory.DN) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	foundKey := ""
	for key, entry := range tx.entries {
		_, entryDN := splitPartitionedEntryKey(key)
		directIdentity := entryDN == dn.Key()
		if !directIdentity && !entryMatchesDisplayDN(entry, dn) {
			continue
		}
		if err := tx.validateEntry(key, entry); err != nil {
			return err
		}
		if entryDN == dn.Key() {
			if err := validateDirectIdentityLookup(entryDN, dn); err != nil {
				return err
			}
		}
		if foundKey != "" {
			return ErrEntryAmbiguous
		}
		foundKey = key
	}
	if foundKey == "" {
		return ErrEntryNotFound
	}
	delete(tx.entries, foundKey)
	delete(tx.dnIdentities, foundKey)
	delete(tx.dnSources, foundKey)
	return nil
}

func (tx *memoryTx) DeleteIn(partition string, dn directory.DN) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	key := partitionedEntryKey(partition, dn.Key())
	selectedKey := ""
	if entry, exists := tx.entries[key]; exists {
		if err := tx.validateEntry(key, entry); err != nil {
			return err
		}
		if err := validateDirectIdentityLookup(dn.Key(), dn); err != nil {
			return err
		}
		selectedKey = key
	}
	foundKey := selectedKey
	for candidateKey, entry := range tx.entries {
		if candidateKey == selectedKey {
			continue
		}
		entryPartition, _ := splitPartitionedEntryKey(candidateKey)
		if entryPartition != partition || !entryMatchesDisplayDN(entry, dn) {
			continue
		}
		if err := tx.validateEntry(candidateKey, entry); err != nil {
			return err
		}
		if foundKey != "" {
			return ErrEntryAmbiguous
		}
		foundKey = candidateKey
	}
	if foundKey == "" {
		return ErrEntryNotFound
	}
	delete(tx.entries, foundKey)
	delete(tx.dnIdentities, foundKey)
	delete(tx.dnSources, foundKey)
	return nil
}

func (tx *memoryTx) Clear() error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	tx.entries = make(map[string]directory.Entry)
	tx.dnIdentities = make(map[string]string)
	tx.dnSources = make(map[string]string)
	tx.namingContexts = nil
	tx.metadata = make(map[string][]byte)
	return nil
}

func (tx *memoryTx) validateEntry(key string, entry directory.Entry) error {
	_, physicalKey := splitPartitionedEntryKey(key)
	if err := validateStoredEntryIdentity(
		physicalKey,
		entry,
		tx.dnIdentities[key],
		tx.dnSources[key],
	); err != nil {
		return fmt.Errorf("entry key %q: %w", key, err)
	}
	return nil
}

func (tx *memoryTx) validateSchemaAwareDNBindingsIn(
	partition string,
	normalizer directory.DNAttributeNormalizer,
) error {
	for key, entry := range tx.entries {
		entryPartition, physicalKey := splitPartitionedEntryKey(key)
		if entryPartition != partition || !isSchemaAwareDNKey(physicalKey) {
			continue
		}
		if err := tx.validateEntry(key, entry); err != nil {
			return err
		}
		normalized, err := directory.ParseDNWithNormalizer(entry.DN, normalizer)
		if err != nil {
			return fmt.Errorf("entry key %q cannot normalize DN %q: %w", key, entry.DN, err)
		}
		if normalized.Key() != physicalKey {
			return fmt.Errorf(
				"entry key %q does not match schema-normalized DN %q",
				key,
				entry.DN,
			)
		}
	}
	return nil
}

func (tx *memoryTx) SetNamingContexts(contexts []string) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	tx.namingContexts = append([]string(nil), contexts...)
	return nil
}

func (tx *memoryTx) SetMetadata(key string, value []byte) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	tx.metadata[key] = bytes.Clone(value)
	return nil
}

func (tx *memoryTx) DeleteMetadata(key string) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	if _, ok := tx.metadata[key]; !ok {
		return ErrMetadataNotFound
	}
	delete(tx.metadata, key)
	return nil
}

func cloneEntryMap(entries map[string]directory.Entry) map[string]directory.Entry {
	cloned := make(map[string]directory.Entry, len(entries))
	for key, entry := range entries {
		cloned[key] = entry.Clone()
	}
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneMetadataMap(metadata map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(metadata))
	for key, value := range metadata {
		cloned[key] = bytes.Clone(value)
	}
	return cloned
}
