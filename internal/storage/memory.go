package storage

import (
	"context"
	"sort"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type Memory struct {
	mu             sync.RWMutex
	entries        map[string]directory.Entry
	namingContexts []string
	closed         bool
}

func NewMemory() *Memory {
	return &Memory{entries: make(map[string]directory.Entry)}
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
		namingContexts: store.namingContexts,
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
		namingContexts: append([]string(nil), store.namingContexts...),
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	store.entries = tx.entries
	store.namingContexts = tx.namingContexts
	return nil
}

func (store *Memory) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closed = true
	store.entries = nil
	store.namingContexts = nil
	return nil
}

type memoryTx struct {
	ctx            context.Context
	entries        map[string]directory.Entry
	namingContexts []string
	readOnly       bool
}

func (tx *memoryTx) Get(dn directory.DN) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	var result directory.Entry
	found := false
	foundPartition := ""
	for key, entry := range tx.entries {
		partition, entryDN := splitPartitionedEntryKey(key)
		if entryDN != dn.Key() {
			continue
		}
		if found && partition != foundPartition {
			return directory.Entry{}, ErrEntryAmbiguous
		}
		result = entry
		found = true
		foundPartition = partition
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
	entry, ok := tx.entries[partitionedEntryKey(partition, dn.Key())]
	if !ok {
		return directory.Entry{}, ErrEntryNotFound
	}
	return entry.Clone(), nil
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
		if err := fn(tx.entries[key].Clone()); err != nil {
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
		if err := fn(tx.entries[key].Clone()); err != nil {
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
		if err := fn(partition, tx.entries[key].Clone()); err != nil {
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
	key := partitionedEntryKey(partition, dn.Key())
	if _, exists := tx.entries[key]; exists && !replace {
		return ErrEntryExists
	}
	tx.entries[key] = entry.Clone()
	return nil
}

func (tx *memoryTx) Delete(dn directory.DN) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	foundKey := ""
	foundPartition := ""
	for key := range tx.entries {
		partition, entryDN := splitPartitionedEntryKey(key)
		if entryDN != dn.Key() {
			continue
		}
		if foundKey != "" && partition != foundPartition {
			return ErrEntryAmbiguous
		}
		foundKey = key
		foundPartition = partition
	}
	if foundKey == "" {
		return ErrEntryNotFound
	}
	delete(tx.entries, foundKey)
	return nil
}

func (tx *memoryTx) DeleteIn(partition string, dn directory.DN) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	key := partitionedEntryKey(partition, dn.Key())
	if _, exists := tx.entries[key]; !exists {
		return ErrEntryNotFound
	}
	delete(tx.entries, key)
	return nil
}

func (tx *memoryTx) Clear() error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	tx.entries = make(map[string]directory.Entry)
	tx.namingContexts = nil
	return nil
}

func (tx *memoryTx) SetNamingContexts(contexts []string) error {
	if tx.readOnly {
		return errorsReadOnly()
	}
	tx.namingContexts = append([]string(nil), contexts...)
	return nil
}

func cloneEntryMap(entries map[string]directory.Entry) map[string]directory.Entry {
	cloned := make(map[string]directory.Entry, len(entries))
	for key, entry := range entries {
		cloned[key] = entry.Clone()
	}
	return cloned
}
