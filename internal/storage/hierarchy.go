package storage

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// HierarchyIdentityNormalizer opts a deterministic normalizer into bounded
// hierarchy queries. The fingerprint must include all DN matching semantics.
// Implementations must return false for custom or stateful matching rules.
type HierarchyIdentityNormalizer interface {
	HierarchyIdentityFingerprint() ([sha256.Size]byte, bool)
}

// HierarchyReaderProvider is an explicit promise that a decorator preserves
// the underlying partition's entries and DN identities. General maintenance
// access alone does not grant permission to bypass a decorator for queries.
type HierarchyReaderProvider interface {
	HierarchyStorageReader() Reader
}

func hierarchyFingerprint(normalizer directory.DNAttributeNormalizer) ([sha256.Size]byte, bool) {
	provider, ok := normalizer.(HierarchyIdentityNormalizer)
	if !ok {
		return [sha256.Size]byte{}, false
	}
	return provider.HierarchyIdentityFingerprint()
}

func hierarchyPartitionSupported(partition string) bool {
	return partition != "" && partition != OpenLDAPConfigPartition && !strings.ContainsRune(partition, 0)
}

// EnsureHierarchyIndex builds a missing index, or replaces one for an older
// schema, in the caller's transaction. A matching manifest is an O(1) check;
// startup should use ValidateHierarchyIndex before trusting persisted indexes.
func EnsureHierarchyIndex(writer Writer, partition string, normalizer directory.DNAttributeNormalizer) (bool, error) {
	fingerprint, supported := hierarchyFingerprint(normalizer)
	tx, ok := maintenanceWriter(writer).(*boltTx)
	if !ok || !supported || !hierarchyPartitionSupported(partition) {
		return false, nil
	}
	if !tx.tx.Writable() {
		return true, errorsReadOnly()
	}
	_, manifest, present, err := tx.hierarchyPartition(partition)
	if err != nil {
		return true, err
	}
	marker := tx.meta.Get(boltSchemaAwareDNMigrationMetadataKey(partition))
	if present && manifest.fingerprint == fingerprint && len(marker) == 1 && marker[0] == schemaAwareDNIdentityFormatVersion {
		return true, tx.checkHierarchyCount(partition, manifest)
	}
	if err := ensureSchemaAwareDNIdentities(tx, partition, normalizer); err != nil {
		return true, err
	}
	// Identity migration may already have rebuilt the hierarchy in this tx.
	_, manifest, present, err = tx.hierarchyPartition(partition)
	if err != nil {
		return true, err
	}
	marker = tx.meta.Get(boltSchemaAwareDNMigrationMetadataKey(partition))
	if present && manifest.fingerprint == fingerprint && len(marker) == 1 && marker[0] == schemaAwareDNIdentityFormatVersion {
		return true, tx.checkHierarchyCount(partition, manifest)
	}
	return true, tx.rebuildHierarchyIndex(partition, normalizer)
}

// RebuildHierarchyIndex explicitly repairs derived hierarchy state, including
// malformed manifests. It validates all authoritative entries before replacing
// any derived bucket and publishes the complete index atomically in the
// caller's transaction. Every returned error must abort that transaction.
// Identity migration must precede this operation for legacy partitions.
func RebuildHierarchyIndex(writer Writer, partition string, normalizer directory.DNAttributeNormalizer) (bool, error) {
	_, supported := hierarchyFingerprint(normalizer)
	tx, ok := maintenanceWriter(writer).(*boltTx)
	if !ok || !supported || !hierarchyPartitionSupported(partition) {
		return false, nil
	}
	if !tx.tx.Writable() {
		return true, errorsReadOnly()
	}
	return true, tx.replaceHierarchyIndex(partition, normalizer)
}

// ValidateHierarchyIndex verifies both directions of the entry/index mapping
// without changing storage. An absent index or schema mismatch reports ready
// false; malformed manifests and corrupt mappings are errors.
// A read-only database with no usable optional index reports handled false so
// startup can retain scan-based reads without requesting an impossible rebuild.
func ValidateHierarchyIndex(reader Reader, partition string, normalizer directory.DNAttributeNormalizer) (handled, ready bool, err error) {
	fingerprint, supported := hierarchyFingerprint(normalizer)
	tx, ok := maintenanceReader(reader).(*boltTx)
	if !ok || !supported || !hierarchyPartitionSupported(partition) {
		return false, false, nil
	}
	rows, manifest, present, err := tx.hierarchyPartition(partition)
	if err != nil || !present {
		return err != nil || !tx.tx.DB().IsReadOnly(), false, err
	}
	if manifest.fingerprint != fingerprint {
		return !tx.tx.DB().IsReadOnly(), false, nil
	}
	marker := tx.meta.Get(boltSchemaAwareDNMigrationMetadataKey(partition))
	if marker == nil {
		return !tx.tx.DB().IsReadOnly(), false, nil
	}
	if _, err := tx.schemaAwareDNIdentityReady(partition); err != nil {
		return true, false, err
	}
	if err := tx.validateHierarchyPartition(partition, rows, manifest, normalizer); err != nil {
		return true, false, err
	}
	return true, true, nil
}

func hierarchyQuery(reader Reader, base directory.DN) (*boltTx, string, []byte, bool, error) {
	var partition string
	var normalizer directory.DNAttributeNormalizer
	switch scoped := reader.(type) {
	case schemaAwarePartitionWriter:
		partition, normalizer, reader = scoped.partition, scoped.normalizer, scoped.Writer
	case schemaAwarePartitionReader:
		partition, normalizer, reader = scoped.partition, scoped.normalizer, scoped.Reader
	default:
		return nil, "", nil, false, nil
	}
	fingerprint, supported := hierarchyFingerprint(normalizer)
	if !supported || !hierarchyPartitionSupported(partition) {
		return nil, "", nil, false, nil
	}
	for depth := 0; depth < 32; depth++ {
		if tx, ok := reader.(*boltTx); ok {
			rows, manifest, present, err := tx.hierarchyPartition(partition)
			if err != nil {
				return nil, "", nil, true, err
			}
			if !present || manifest.fingerprint != fingerprint {
				return nil, "", nil, false, nil
			}
			marker := tx.meta.Get(boltSchemaAwareDNMigrationMetadataKey(partition))
			if marker == nil {
				return nil, "", nil, false, nil
			}
			if _, err := tx.schemaAwareDNIdentityReady(partition); err != nil {
				return nil, "", nil, true, err
			}
			if err := tx.checkHierarchyCount(partition, manifest); err != nil {
				return nil, "", nil, true, err
			}
			dn, err := directory.ParseDNWithNormalizer(base.String(), normalizer)
			if err != nil {
				return nil, "", nil, true, err
			}
			path, err := directory.DNHierarchyPath(dn.Key())
			if err != nil {
				return nil, "", nil, true, err
			}
			locator := []byte(partitionedEntryKey(partition, dn.Key()))
			if tx.entries.Get(locator) != nil && !bytes.Equal(rows.Get(path), locator) {
				return nil, "", nil, true, fmt.Errorf("hierarchy partition %q is missing base mapping", partition)
			}
			return tx, partition, path, true, nil
		}
		provider, ok := reader.(HierarchyReaderProvider)
		if !ok {
			break
		}
		reader = provider.HierarchyStorageReader()
	}
	return nil, "", nil, false, nil
}

// HasDescendants checks for any strict descendant, including descendants with
// missing intermediate parents. Unsupported readers report handled false.
// It validates encountered rows, not unrelated entries elsewhere in storage.
func HasDescendants(reader Reader, base directory.DN) (handled, found bool, err error) {
	tx, partition, prefix, handled, err := hierarchyQuery(reader, base)
	if err != nil || !handled {
		return handled, false, err
	}
	rows, _, _, err := tx.hierarchyPartition(partition)
	if err != nil {
		return true, false, err
	}
	cursor := rows.Cursor()
	key, locator := cursor.Seek(prefix)
	if bytes.Equal(key, prefix) {
		if _, err := tx.hierarchyEntry(partition, key, locator); err != nil {
			return true, false, err
		}
		key, locator = cursor.Next()
	}
	if key == nil || !bytes.HasPrefix(key, prefix) {
		return true, false, tx.ctx.Err()
	}
	_, err = tx.hierarchyEntry(partition, key, locator)
	return true, err == nil, err
}

// ForEachSubtreeEntry visits the base and all descendants. It owns and validates
// the complete matching set before callbacks and preserves schema-aware
// ForEach's order and DN hints within that set. Callbacks must not mutate the
// transaction. Work and retained entries depend on subtree size, not partition
// size. Unsupported readers return false without invoking the callback.
func ForEachSubtreeEntry(reader Reader, base directory.DN, visit func(directory.Entry) error) (bool, error) {
	tx, partition, prefix, handled, err := hierarchyQuery(reader, base)
	if err != nil || !handled {
		return handled, err
	}
	rows, _, _, err := tx.hierarchyPartition(partition)
	if err != nil {
		return true, err
	}
	type candidate struct {
		entry directory.Entry
		order string
	}
	var entries []candidate
	cursor := rows.Cursor()
	for key, locator := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, locator = cursor.Next() {
		entry, err := tx.hierarchyEntry(partition, key, locator)
		if err != nil {
			return true, err
		}
		dn, _ := entry.NormalizedDNHint()
		entries = append(entries, candidate{entry: entry, order: dn.LegacyKey() + "\x00" + dn.Key()})
	}
	slices.SortStableFunc(entries, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(a.order, b.order), cmp.Compare(a.entry.DN, b.entry.DN))
	})
	for _, candidate := range entries {
		if err := tx.ctx.Err(); err != nil {
			return true, err
		}
		if err := visit(candidate.entry); err != nil {
			return true, err
		}
	}
	return true, tx.ctx.Err()
}
