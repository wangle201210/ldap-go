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
	entriesBucket             = []byte("entries")
	metaBucket                = []byte("metadata")
	equalityIndexBucket       = []byte("indexes:eq")
	equalityIndexConfigBucket = []byte("indexes:eq:config")
	contextsKey               = []byte("naming-contexts")
	metadataPrefix            = []byte("value:")
)

type Bolt struct {
	db       *bolt.DB
	pathLock *boltPathLock
}

func OpenBolt(path string) (*Bolt, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	pathLock, err := acquireBoltPathLock(path, false)
	if err != nil {
		return nil, fmt.Errorf("lock database path: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		_ = pathLock.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	store := &Bolt{db: db, pathLock: pathLock}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(entriesBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(metaBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(equalityIndexBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(equalityIndexConfigBucket)
		return err
	}); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	return store, nil
}

// OpenBoltReadOnly opens an existing ldap-go database without creating or
// modifying the database file or its buckets. It creates the stable sidecar
// lock file when an older database does not have one yet.
func OpenBoltReadOnly(path string) (*Bolt, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	pathLock, err := acquireBoltPathLock(path, false)
	if err != nil {
		return nil, fmt.Errorf("lock database path: %w", err)
	}
	db, err := openBoltReadOnly(path)
	if err != nil {
		_ = pathLock.Close()
		return nil, err
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(entriesBucket) == nil || tx.Bucket(metaBucket) == nil {
			return errors.New("required entries or metadata bucket is missing")
		}
		return nil
	}); err != nil {
		_ = db.Close()
		_ = pathLock.Close()
		return nil, fmt.Errorf("validate database %q: %w", path, err)
	}
	return &Bolt{db: db, pathLock: pathLock}, nil
}

func (store *Bolt) View(ctx context.Context, fn func(Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.View(func(tx *bolt.Tx) error {
		return fn(newBoltTx(ctx, tx))
	})
}

func (store *Bolt) Update(ctx context.Context, fn func(Writer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		writer := newBoltTx(ctx, tx)
		if err := fn(writer); err != nil {
			return err
		}
		return ctx.Err()
	})
}

// Backup writes a transactionally consistent snapshot of an open bbolt store.
// The read transaction remains pinned while bbolt copies the pages, so callers
// may continue committing writes while the backup is in progress.
func (store *Bolt) Backup(
	ctx context.Context,
	backupPath string,
	replace bool,
) (CheckReport, error) {
	if store == nil || store.db == nil {
		return CheckReport{}, errors.New("database is not open")
	}
	return backupOpenBolt(ctx, store.db, backupPath, replace, osFileSystem{})
}

func (store *Bolt) Close() error {
	if store == nil {
		return nil
	}
	var databaseErr error
	if store.db != nil {
		databaseErr = store.db.Close()
	}
	var lockErr error
	if store.pathLock != nil {
		lockErr = store.pathLock.Close()
	}
	return errors.Join(databaseErr, lockErr)
}

type boltTx struct {
	ctx                  context.Context
	tx                   *bolt.Tx
	entries              *bolt.Bucket
	meta                 *bolt.Bucket
	equalityIndexes      *bolt.Bucket
	equalityIndexConfigs *bolt.Bucket
}

func newBoltTx(ctx context.Context, tx *bolt.Tx) *boltTx {
	return &boltTx{
		ctx:                  ctx,
		tx:                   tx,
		entries:              tx.Bucket(entriesBucket),
		meta:                 tx.Bucket(metaBucket),
		equalityIndexes:      tx.Bucket(equalityIndexBucket),
		equalityIndexConfigs: tx.Bucket(equalityIndexConfigBucket),
	}
}

func (tx *boltTx) Get(dn directory.DN) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	var result directory.Entry
	found := false
	err := tx.entries.ForEach(func(key, value []byte) error {
		_, entryDN := splitPartitionedEntryKey(string(key))
		entry, err := decodeAndValidateEntry(entryDN, value)
		if err != nil {
			return err
		}
		directIdentity := entryDN == dn.Key()
		if !directIdentity && !entryMatchesDisplayDN(entry, dn) {
			return nil
		}
		if entryDN == dn.Key() {
			if err := validateDirectIdentityLookup(entryDN, dn); err != nil {
				return err
			}
		}
		if found {
			return ErrEntryAmbiguous
		}
		result = entry
		found = true
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
	physicalKey := []byte(partitionedEntryKey(partition, dn.Key()))
	value := tx.entries.Get(physicalKey)
	if value == nil && partition == "" {
		physicalKey = []byte(dn.Key())
		value = tx.entries.Get(physicalKey)
	}
	var directKey []byte
	var directEntry directory.Entry
	if value != nil {
		entry, err := decodeAndValidateEntry(dn.Key(), value)
		if err != nil {
			return directory.Entry{}, err
		}
		if err := validateDirectIdentityLookup(dn.Key(), dn); err != nil {
			return directory.Entry{}, err
		}
		directKey = bytes.Clone(physicalKey)
		directEntry = entry
	}
	match := directEntry
	matchKey := directKey
	err := tx.entries.ForEach(func(key, value []byte) error {
		if bytes.Equal(key, directKey) {
			return nil
		}
		entryPartition, entryKey := splitPartitionedEntryKey(string(key))
		if entryPartition != partition {
			return nil
		}
		entry, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return err
		}
		directIdentity := entryKey == dn.Key() && isSchemaAwareDNKey(entryKey)
		if !directIdentity && !entryMatchesDisplayDN(entry, dn) {
			return nil
		}
		if matchKey != nil {
			return ErrEntryAmbiguous
		}
		match = entry
		matchKey = bytes.Clone(key)
		return nil
	})
	if err != nil {
		return directory.Entry{}, err
	}
	if matchKey == nil {
		return directory.Entry{}, ErrEntryNotFound
	}
	return match, nil
}

func (tx *boltTx) ForEach(fn func(directory.Entry) error) error {
	return tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		_, entryKey := splitPartitionedEntryKey(string(key))
		entry, err := decodeAndValidateEntry(entryKey, value)
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
		entryPartition, entryKey := splitPartitionedEntryKey(string(key))
		if entryPartition != partition {
			return nil
		}
		entry, err := decodeAndValidateEntry(entryKey, value)
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
		partition, entryKey := splitPartitionedEntryKey(string(key))
		entry, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return err
		}
		return fn(partition, entry)
	})
}

func (tx *boltTx) validateSchemaAwareDNBindingsIn(
	partition string,
	normalizer directory.DNAttributeNormalizer,
) error {
	return tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entryPartition, physicalKey := splitPartitionedEntryKey(string(key))
		if entryPartition != partition || !isSchemaAwareDNKey(physicalKey) {
			return nil
		}
		entry, err := decodeAndValidateEntry(physicalKey, value)
		if err != nil {
			return fmt.Errorf("entry key %q: %w", key, err)
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
		return nil
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
	if err := tx.putInWithDN(
		partition,
		entry.WithoutDNIdentity(),
		dn,
		identity,
		replace,
	); err != nil {
		return err
	}
	return tx.invalidateEqualityIndexes(partition)
}

func (tx *boltTx) putInWithDN(
	partition string,
	entry directory.Entry,
	entryDN directory.DN,
	identity string,
	replace bool,
) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	key := []byte(partitionedEntryKey(partition, identity))
	existingKeys := make(map[string]struct{})
	if tx.entries.Get(key) != nil {
		existingKeys[string(key)] = struct{}{}
	}
	if !isSchemaAwareDNKey(identity) && partition == "" && tx.entries.Get([]byte(entryDN.Key())) != nil {
		existingKeys[entryDN.Key()] = struct{}{}
	}
	if err := tx.entries.ForEach(func(candidateKey, value []byte) error {
		candidatePartition, candidateEntryKey := splitPartitionedEntryKey(string(candidateKey))
		if candidatePartition != partition {
			return nil
		}
		candidate, err := decodeAndValidateEntry(candidateEntryKey, value)
		if err != nil {
			return err
		}
		if entryMatchesDisplayDN(candidate, entryDN) {
			existingKeys[string(candidateKey)] = struct{}{}
		}
		return nil
	}); err != nil {
		return err
	}
	if len(existingKeys) > 0 && !replace {
		return ErrEntryExists
	}
	storedIdentity := ""
	if isSchemaAwareDNKey(identity) {
		storedIdentity = identity
	}
	value, err := encodeEntry(entry, storedIdentity, entry.DN)
	if err != nil {
		return fmt.Errorf("encode entry %q: %w", entry.DN, err)
	}
	if err := tx.entries.Put(key, value); err != nil {
		return err
	}
	for existingKey := range existingKeys {
		if existingKey == string(key) {
			continue
		}
		if err := tx.entries.Delete([]byte(existingKey)); err != nil {
			return err
		}
	}
	return nil
}

func (tx *boltTx) Delete(dn directory.DN) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	found := false
	foundPartition := ""
	err := tx.entries.ForEach(func(key, value []byte) error {
		partition, entryDN := splitPartitionedEntryKey(string(key))
		entry, err := decodeAndValidateEntry(entryDN, value)
		if err != nil {
			return err
		}
		directIdentity := entryDN == dn.Key()
		if !directIdentity && !entryMatchesDisplayDN(entry, dn) {
			return nil
		}
		if entryDN == dn.Key() {
			if err := validateDirectIdentityLookup(entryDN, dn); err != nil {
				return err
			}
		}
		if found {
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
	var foundKey []byte
	if value := tx.entries.Get(key); value != nil {
		_, err := decodeAndValidateEntry(dn.Key(), value)
		if err != nil {
			return err
		}
		if err := validateDirectIdentityLookup(dn.Key(), dn); err != nil {
			return err
		}
		foundKey = bytes.Clone(key)
	}
	err := tx.entries.ForEach(func(candidateKey, value []byte) error {
		if bytes.Equal(candidateKey, foundKey) {
			return nil
		}
		entryPartition, candidateEntryKey := splitPartitionedEntryKey(string(candidateKey))
		if entryPartition != partition {
			return nil
		}
		entry, err := decodeAndValidateEntry(candidateEntryKey, value)
		if err != nil {
			return err
		}
		if !entryMatchesDisplayDN(entry, dn) {
			return nil
		}
		if foundKey != nil {
			return ErrEntryAmbiguous
		}
		foundKey = bytes.Clone(candidateKey)
		return nil
	})
	if err != nil {
		return err
	}
	if foundKey == nil {
		return ErrEntryNotFound
	}
	if err := tx.entries.Delete(foundKey); err != nil {
		return err
	}
	return tx.invalidateEqualityIndexes(partition)
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
	for _, bucketName := range [][]byte{
		equalityIndexBucket,
		equalityIndexConfigBucket,
	} {
		if tx.tx.Bucket(bucketName) != nil {
			if err := tx.tx.DeleteBucket(bucketName); err != nil {
				return err
			}
		}
	}
	indexes, err := tx.tx.CreateBucket(equalityIndexBucket)
	if err != nil {
		return err
	}
	configs, err := tx.tx.CreateBucket(equalityIndexConfigBucket)
	if err != nil {
		return err
	}
	tx.equalityIndexes = indexes
	tx.equalityIndexConfigs = configs
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

type storedEntry struct {
	directory.Entry
	DNIdentity string `json:"dnIdentity,omitempty"`
	DNSource   string `json:"dnSource,omitempty"`
}

func encodeEntry(entry directory.Entry, identity, source string) ([]byte, error) {
	if identity == "" {
		source = ""
	}
	value, err := json.Marshal(storedEntry{
		Entry:      entry,
		DNIdentity: identity,
		DNSource:   source,
	})
	if err != nil {
		return nil, fmt.Errorf("encode entry %q: %w", entry.DN, err)
	}
	return value, nil
}

func decodeStoredEntry(value []byte) (storedEntry, error) {
	var stored storedEntry
	if err := json.Unmarshal(value, &stored); err != nil {
		return storedEntry{}, fmt.Errorf("decode entry: %w", err)
	}
	return stored, nil
}

func decodeAndValidateEntry(key string, value []byte) (directory.Entry, error) {
	stored, err := decodeStoredEntry(value)
	if err != nil {
		return directory.Entry{}, err
	}
	if err := validateStoredEntryIdentity(
		key,
		stored.Entry,
		stored.DNIdentity,
		stored.DNSource,
	); err != nil {
		return directory.Entry{}, err
	}
	return stored.Entry, nil
}

func errorsReadOnly() error {
	return errors.New("read-only transaction")
}
