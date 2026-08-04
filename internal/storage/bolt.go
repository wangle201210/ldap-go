package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

var (
	entriesBucket  = []byte("entries")
	metaBucket     = []byte("metadata")
	contextsKey    = []byte("naming-contexts")
	metadataPrefix = []byte("value:")
)

type Bolt struct {
	db *bolt.DB
}

func OpenBolt(path string) (*Bolt, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	store := &Bolt{db: db}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(entriesBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(metaBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	return store, nil
}

// OpenBoltReadOnly opens an existing ldap-go database without creating or
// modifying the database file, its parent directory, or any buckets.
func OpenBoltReadOnly(path string) (*Bolt, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	db, err := openBoltReadOnly(path)
	if err != nil {
		return nil, err
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(entriesBucket) == nil || tx.Bucket(metaBucket) == nil {
			return errors.New("required entries or metadata bucket is missing")
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("validate database %q: %w", path, err)
	}
	return &Bolt{db: db}, nil
}

func (store *Bolt) View(ctx context.Context, fn func(Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.View(func(tx *bolt.Tx) error {
		return fn(&boltTx{ctx: ctx, tx: tx, entries: tx.Bucket(entriesBucket), meta: tx.Bucket(metaBucket)})
	})
}

func (store *Bolt) Update(ctx context.Context, fn func(Writer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		writer := &boltTx{ctx: ctx, tx: tx, entries: tx.Bucket(entriesBucket), meta: tx.Bucket(metaBucket)}
		if err := fn(writer); err != nil {
			return err
		}
		return ctx.Err()
	})
}

func (store *Bolt) Close() error {
	return store.db.Close()
}

type boltTx struct {
	ctx     context.Context
	tx      *bolt.Tx
	entries *bolt.Bucket
	meta    *bolt.Bucket
}

func (tx *boltTx) Get(dn directory.DN) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	var result directory.Entry
	found := false
	foundPartition := ""
	err := tx.entries.ForEach(func(key, value []byte) error {
		partition, entryDN := splitPartitionedEntryKey(string(key))
		if entryDN != dn.Key() {
			return nil
		}
		if found && partition != foundPartition {
			return ErrEntryAmbiguous
		}
		entry, err := decodeEntry(value)
		if err != nil {
			return err
		}
		result = entry
		found = true
		foundPartition = partition
		return nil
	})
	if err != nil {
		return directory.Entry{}, err
	}
	if !found {
		return directory.Entry{}, ErrEntryNotFound
	}
	return result, nil
}

func (tx *boltTx) GetIn(partition string, dn directory.DN) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	value := tx.entries.Get([]byte(partitionedEntryKey(partition, dn.Key())))
	if value == nil && partition == "" {
		value = tx.entries.Get([]byte(dn.Key()))
	}
	if value == nil {
		return directory.Entry{}, ErrEntryNotFound
	}
	return decodeEntry(value)
}

func (tx *boltTx) ForEach(fn func(directory.Entry) error) error {
	return tx.entries.ForEach(func(_, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entry, err := decodeEntry(value)
		if err != nil {
			return err
		}
		return fn(entry)
	})
}

func (tx *boltTx) ForEachIn(
	partition string,
	fn func(directory.Entry) error,
) error {
	return tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entryPartition, _ := splitPartitionedEntryKey(string(key))
		if entryPartition != partition {
			return nil
		}
		entry, err := decodeEntry(value)
		if err != nil {
			return err
		}
		return fn(entry)
	})
}

func (tx *boltTx) ForEachPartition(
	fn func(string, directory.Entry) error,
) error {
	return tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		partition, _ := splitPartitionedEntryKey(string(key))
		entry, err := decodeEntry(value)
		if err != nil {
			return err
		}
		return fn(partition, entry)
	})
}

func (tx *boltTx) NamingContexts() ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	value := tx.meta.Get(contextsKey)
	if value == nil {
		return nil, nil
	}
	var contexts []string
	if err := json.Unmarshal(value, &contexts); err != nil {
		return nil, fmt.Errorf("decode naming contexts: %w", err)
	}
	return contexts, nil
}

func (tx *boltTx) Metadata(key string) ([]byte, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	value := tx.meta.Get(genericMetadataKey(key))
	if value == nil {
		return nil, ErrMetadataNotFound
	}
	return bytes.Clone(value), nil
}

func (tx *boltTx) Put(entry directory.Entry, replace bool) error {
	return tx.PutIn("", entry, replace)
}

func (tx *boltTx) PutIn(
	partition string,
	entry directory.Entry,
	replace bool,
) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	key := []byte(partitionedEntryKey(partition, dn.Key()))
	existing := tx.entries.Get(key)
	if existing == nil && partition == "" {
		existing = tx.entries.Get([]byte(dn.Key()))
	}
	if existing != nil && !replace {
		return ErrEntryExists
	}
	value, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode entry %q: %w", entry.DN, err)
	}
	if err := tx.entries.Put(key, value); err != nil {
		return err
	}
	if partition == "" {
		return tx.entries.Delete([]byte(dn.Key()))
	}
	return nil
}

func (tx *boltTx) Delete(dn directory.DN) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	found := false
	foundPartition := ""
	err := tx.entries.ForEach(func(key, _ []byte) error {
		partition, entryDN := splitPartitionedEntryKey(string(key))
		if entryDN != dn.Key() {
			return nil
		}
		if found && partition != foundPartition {
			return ErrEntryAmbiguous
		}
		found = true
		foundPartition = partition
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return ErrEntryNotFound
	}
	return tx.DeleteIn(foundPartition, dn)
}

func (tx *boltTx) DeleteIn(partition string, dn directory.DN) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	key := []byte(partitionedEntryKey(partition, dn.Key()))
	legacyKey := []byte(dn.Key())
	exists := tx.entries.Get(key) != nil
	if partition == "" && tx.entries.Get(legacyKey) != nil {
		exists = true
	}
	if !exists {
		return ErrEntryNotFound
	}
	if err := tx.entries.Delete(key); err != nil {
		return err
	}
	if partition == "" {
		return tx.entries.Delete(legacyKey)
	}
	return nil
}

func (tx *boltTx) Clear() error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	if err := tx.tx.DeleteBucket(entriesBucket); err != nil {
		return err
	}
	bucket, err := tx.tx.CreateBucket(entriesBucket)
	if err != nil {
		return err
	}
	tx.entries = bucket
	if err := tx.tx.DeleteBucket(metaBucket); err != nil {
		return err
	}
	meta, err := tx.tx.CreateBucket(metaBucket)
	if err != nil {
		return err
	}
	tx.meta = meta
	return nil
}

func (tx *boltTx) SetNamingContexts(contexts []string) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	value, err := json.Marshal(contexts)
	if err != nil {
		return fmt.Errorf("encode naming contexts: %w", err)
	}
	return tx.meta.Put(contextsKey, value)
}

func (tx *boltTx) SetMetadata(key string, value []byte) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	return tx.meta.Put(genericMetadataKey(key), bytes.Clone(value))
}

func (tx *boltTx) DeleteMetadata(key string) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	encodedKey := genericMetadataKey(key)
	if tx.meta.Get(encodedKey) == nil {
		return ErrMetadataNotFound
	}
	return tx.meta.Delete(encodedKey)
}

func genericMetadataKey(key string) []byte {
	encoded := make([]byte, 0, len(metadataPrefix)+len(key))
	encoded = append(encoded, metadataPrefix...)
	encoded = append(encoded, key...)
	return encoded
}

func decodeEntry(value []byte) (directory.Entry, error) {
	var entry directory.Entry
	if err := json.Unmarshal(value, &entry); err != nil {
		return directory.Entry{}, fmt.Errorf("decode entry: %w", err)
	}
	return entry, nil
}

func errorsReadOnly() error {
	return errors.New("read-only transaction")
}
