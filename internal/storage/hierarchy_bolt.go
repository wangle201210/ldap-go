package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

var hierarchyBucket = []byte("indexes:hierarchy:v1")
var hierarchyManifestKey = []byte{0}

const hierarchyManifestSize = 2 + sha256.Size + 8

type hierarchyManifest struct {
	fingerprint [sha256.Size]byte
	count       uint64
}

func hierarchyPartitionKey(partition string) []byte {
	return append([]byte{0}, partition...)
}

func readHierarchyManifest(rows *bolt.Bucket) (hierarchyManifest, error) {
	var manifest hierarchyManifest
	encoded := rows.Get(hierarchyManifestKey)
	if len(encoded) != hierarchyManifestSize || encoded[0] != 1 || encoded[1] != schemaAwareDNIdentityFormatVersion {
		return manifest, errors.New("hierarchy manifest is missing, malformed, or unsupported")
	}
	copy(manifest.fingerprint[:], encoded[2:2+sha256.Size])
	manifest.count = binary.BigEndian.Uint64(encoded[2+sha256.Size:])
	return manifest, nil
}

func putHierarchyManifest(rows *bolt.Bucket, manifest hierarchyManifest) error {
	encoded := make([]byte, hierarchyManifestSize)
	encoded[0], encoded[1] = 1, schemaAwareDNIdentityFormatVersion
	copy(encoded[2:], manifest.fingerprint[:])
	binary.BigEndian.PutUint64(encoded[2+sha256.Size:], manifest.count)
	return rows.Put(hierarchyManifestKey, encoded)
}

func (tx *boltTx) hierarchyRoot() (*bolt.Bucket, error) {
	root := tx.tx.Bucket(hierarchyBucket)
	if root == nil {
		key, _ := tx.tx.Cursor().Seek(hierarchyBucket)
		if bytes.Equal(key, hierarchyBucket) {
			return nil, errors.New("hierarchy bucket is replaced by a value")
		}
		return nil, nil
	}
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	return root, nil
}

func (tx *boltTx) hierarchyPartition(partition string) (*bolt.Bucket, hierarchyManifest, bool, error) {
	root, err := tx.hierarchyRoot()
	if err != nil || root == nil {
		return nil, hierarchyManifest{}, false, err
	}
	key := hierarchyPartitionKey(partition)
	rows := root.Bucket(key)
	if rows == nil {
		if root.Get(key) != nil {
			return nil, hierarchyManifest{}, false, fmt.Errorf("hierarchy partition %q is replaced by a value", partition)
		}
		return nil, hierarchyManifest{}, false, nil
	}
	manifest, err := readHierarchyManifest(rows)
	if err != nil {
		return nil, hierarchyManifest{}, false, fmt.Errorf("hierarchy partition %q: %w", partition, err)
	}
	return rows, manifest, true, nil
}

func (tx *boltTx) checkHierarchyCount(partition string, manifest hierarchyManifest) error {
	count, err := tx.PartitionEntryCount(partition)
	if err != nil {
		return err
	}
	if count != manifest.count {
		return fmt.Errorf("hierarchy partition %q count is %d, entries count is %d", partition, manifest.count, count)
	}
	return nil
}

// hierarchyPutEntry must run before entries.Put and the entry-count update.
// Ordinary and equality-indexed writes share this hook. An unindexed partition
// stays unindexed until a complete, schema-aware rebuild is possible.
func (tx *boltTx) hierarchyPutEntry(key, value []byte) error {
	partition, identity := splitPartitionedEntryKey(string(key))
	rows, manifest, present, err := tx.hierarchyPartition(partition)
	if err != nil || !present {
		return err
	}
	if err := tx.checkHierarchyCount(partition, manifest); err != nil {
		return err
	}
	if !isSchemaAwareDNKey(identity) {
		return tx.invalidateHierarchyIndex(partition)
	}
	if _, err := decodeNamingContextMetadata(identity, value); err != nil {
		return fmt.Errorf("hierarchy entry %q: %w", key, err)
	}
	path, err := directory.DNHierarchyPath(identity)
	if err != nil {
		return err
	}
	existing := rows.Get(path)
	if tx.entries.Get(key) != nil {
		if !bytes.Equal(existing, key) {
			return fmt.Errorf("hierarchy entry %q has a missing or mismatched mapping", key)
		}
		return nil
	}
	if existing != nil || rows.Bucket(path) != nil {
		return fmt.Errorf("hierarchy entry %q has an unexpected existing mapping", key)
	}
	if manifest.count == math.MaxUint64 {
		return errors.New("hierarchy entry count overflow")
	}
	if tx.fillPercent > 0 {
		rows.FillPercent = tx.fillPercent
	}
	if err := rows.Put(path, bytes.Clone(key)); err != nil {
		return err
	}
	manifest.count++
	return putHierarchyManifest(rows, manifest)
}

// hierarchyDeleteEntry must run before entries.Delete and the count update.
func (tx *boltTx) hierarchyDeleteEntry(key []byte) error {
	partition, identity := splitPartitionedEntryKey(string(key))
	rows, manifest, present, err := tx.hierarchyPartition(partition)
	if err != nil || !present {
		return err
	}
	if err := tx.checkHierarchyCount(partition, manifest); err != nil {
		return err
	}
	if tx.entries.Get(key) == nil {
		return nil
	}
	path, err := directory.DNHierarchyPath(identity)
	if err != nil {
		return err
	}
	if !bytes.Equal(rows.Get(path), key) || manifest.count == 0 {
		return fmt.Errorf("hierarchy entry %q has a missing or mismatched mapping", key)
	}
	if tx.fillPercent > 0 {
		rows.FillPercent = tx.fillPercent
	}
	if err := rows.Delete(path); err != nil {
		return err
	}
	manifest.count--
	return putHierarchyManifest(rows, manifest)
}

func (tx *boltTx) invalidateHierarchyIndex(partition string) error {
	root, err := tx.hierarchyRoot()
	if err != nil || root == nil {
		return err
	}
	if _, _, present, err := tx.hierarchyPartition(partition); err != nil || !present {
		return err
	}
	return root.DeleteBucket(hierarchyPartitionKey(partition))
}

// clearHierarchyIndexes belongs in boltTx.Clear's existing transaction.
func (tx *boltTx) clearHierarchyIndexes() error {
	root, err := tx.hierarchyRoot()
	if err != nil || root == nil {
		return err
	}
	return tx.tx.DeleteBucket(hierarchyBucket)
}

// rebuildHierarchyIndex must run after identity migration's final entry,
// entry-count, and identity-marker writes, even when every key was current.
// Its errors must abort the enclosing transaction. The ready manifest is
// written last, so an interrupted rebuild cannot publish a partial index.
func (tx *boltTx) rebuildHierarchyIndex(partition string, normalizer directory.DNAttributeNormalizer) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	_, _, _, err := tx.hierarchyPartition(partition)
	if err != nil {
		return err
	}
	_, supported := hierarchyFingerprint(normalizer)
	if !supported || !hierarchyPartitionSupported(partition) {
		return tx.invalidateHierarchyIndex(partition)
	}
	return tx.replaceHierarchyIndex(partition, normalizer)
}

func (tx *boltTx) validateHierarchySource(partition string, normalizer directory.DNAttributeNormalizer) (hierarchyManifest, error) {
	fingerprint, _ := hierarchyFingerprint(normalizer)
	manifest := hierarchyManifest{fingerprint: fingerprint}
	if err := requireSchemaAwareDNIdentities(tx, partition); err != nil {
		return manifest, err
	}
	prefix := []byte(partition + "\x00")
	cursor := tx.entries.Cursor()
	for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return manifest, err
		}
		identity := string(key[len(prefix):])
		entry, err := decodeNamingContextMetadata(identity, value)
		if err != nil {
			return manifest, fmt.Errorf("hierarchy entry %q: %w", key, err)
		}
		dn, err := directory.ParseDNWithNormalizer(entry.DN, normalizer)
		if err != nil {
			return manifest, err
		}
		if dn.Key() != identity {
			return manifest, fmt.Errorf("hierarchy entry %q does not match schema-normalized DN", key)
		}
		if _, err := directory.DNHierarchyPath(identity); err != nil {
			return manifest, err
		}
		manifest.count++
	}
	if err := tx.checkHierarchyCount(partition, manifest); err != nil {
		return manifest, err
	}
	return manifest, tx.ctx.Err()
}

func (tx *boltTx) replaceHierarchyIndex(partition string, normalizer directory.DNAttributeNormalizer) error {
	// Validate first, even on explicit repair. No malformed source row may be
	// hidden by replacing a corrupt manifest with a superficially ready one.
	manifest, err := tx.validateHierarchySource(partition, normalizer)
	if err != nil {
		return err
	}
	if tx.tx.Bucket(hierarchyBucket) == nil {
		key, _ := tx.tx.Cursor().Seek(hierarchyBucket)
		if bytes.Equal(key, hierarchyBucket) {
			if err := tx.tx.Cursor().Bucket().Delete(hierarchyBucket); err != nil {
				return err
			}
		}
	}
	root, err := tx.tx.CreateBucketIfNotExists(hierarchyBucket)
	if err != nil {
		return err
	}
	partitionKey := hierarchyPartitionKey(partition)
	if root.Bucket(partitionKey) != nil {
		if err := root.DeleteBucket(partitionKey); err != nil {
			return err
		}
	} else if err := root.Delete(partitionKey); err != nil {
		return err
	}
	rows, err := root.CreateBucket(partitionKey)
	if err != nil {
		return err
	}
	if tx.fillPercent > 0 {
		root.FillPercent, rows.FillPercent = tx.fillPercent, tx.fillPercent
	}
	prefix := []byte(partition + "\x00")
	cursor := tx.entries.Cursor()
	for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		path, err := directory.DNHierarchyPath(string(key[len(prefix):]))
		if err != nil {
			return err
		}
		if rows.Get(path) != nil {
			return fmt.Errorf("hierarchy entry %q has a duplicate path", key)
		}
		if err := rows.Put(path, bytes.Clone(key)); err != nil {
			return err
		}
	}
	if err := tx.setSchemaAwareDNIdentityReady(partition); err != nil {
		return err
	}
	return putHierarchyManifest(rows, manifest)
}

func (tx *boltTx) hierarchyEntry(partition string, path, locator []byte) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	entryPartition, identity := splitPartitionedEntryKey(string(locator))
	if entryPartition != partition || !isSchemaAwareDNKey(identity) {
		return directory.Entry{}, fmt.Errorf("hierarchy partition %q has an invalid locator %q", partition, locator)
	}
	expected, err := directory.DNHierarchyPath(identity)
	if err != nil {
		return directory.Entry{}, err
	}
	if !bytes.Equal(expected, path) {
		return directory.Entry{}, fmt.Errorf("hierarchy entry %q has a mismatched path", locator)
	}
	value := tx.entries.Get(locator)
	if value == nil {
		return directory.Entry{}, fmt.Errorf("hierarchy entry %q is missing", locator)
	}
	entry, err := decodeAndValidateEntry(identity, value)
	if err != nil {
		return directory.Entry{}, err
	}
	dn, err := directory.ParseDNWithIdentityKey(entry.DN, identity)
	if err != nil {
		return directory.Entry{}, err
	}
	return entry.WithNormalizedDNHint(dn, dn.LegacyKey()+"\x00"+identity), nil
}

func (tx *boltTx) validateHierarchyPartition(partition string, rows *bolt.Bucket, manifest hierarchyManifest, normalizer directory.DNAttributeNormalizer) error {
	var count uint64
	prefix := []byte(partition + "\x00")
	cursor := tx.entries.Cursor()
	for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		identity := string(key[len(prefix):])
		entry, err := decodeNamingContextMetadata(identity, value)
		if err != nil {
			return fmt.Errorf("hierarchy entry %q: %w", key, err)
		}
		if normalizer != nil {
			dn, err := directory.ParseDNWithNormalizer(entry.DN, normalizer)
			if err != nil {
				return err
			}
			if dn.Key() != identity {
				return fmt.Errorf("hierarchy entry %q does not match schema-normalized DN", key)
			}
		}
		path, err := directory.DNHierarchyPath(identity)
		if err != nil {
			return err
		}
		if !bytes.Equal(rows.Get(path), key) {
			return fmt.Errorf("hierarchy entry %q has a missing or mismatched mapping", key)
		}
		count++
	}
	if count != manifest.count {
		return fmt.Errorf("hierarchy partition %q count is %d, actual %d", partition, manifest.count, count)
	}
	var indexed uint64
	if err := rows.ForEach(func(path, locator []byte) error {
		if bytes.Equal(path, hierarchyManifestKey) {
			return nil
		}
		if _, err := tx.hierarchyEntry(partition, path, locator); err != nil {
			return err
		}
		indexed++
		return nil
	}); err != nil {
		return err
	}
	if indexed != count {
		return fmt.Errorf("hierarchy partition %q has %d mappings, actual %d", partition, indexed, count)
	}
	return nil
}

func checkBoltHierarchyIndexes(ctx context.Context, raw *bolt.Tx) error {
	tx := newBoltTx(ctx, raw)
	root, err := tx.hierarchyRoot()
	if err != nil || root == nil {
		return err
	}
	return root.ForEach(func(key, value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value != nil || len(key) < 2 || key[0] != 0 || !hierarchyPartitionSupported(string(key[1:])) {
			return fmt.Errorf("invalid hierarchy partition bucket %q", key)
		}
		partition := string(key[1:])
		rows, manifest, _, err := tx.hierarchyPartition(partition)
		if err != nil {
			return err
		}
		marker := tx.meta.Get(boltSchemaAwareDNMigrationMetadataKey(partition))
		if len(marker) != 1 || marker[0] != schemaAwareDNIdentityFormatVersion {
			return fmt.Errorf("hierarchy partition %q is not marked schema-aware", partition)
		}
		return tx.validateHierarchyPartition(partition, rows, manifest, nil)
	})
}
