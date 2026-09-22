package storage

import (
	"bytes"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// ForEachDeleteCandidateDN preserves a schema-aware writer's ForEach validation,
// ordering and DN hints without materializing attribute payloads. All rows are
// decoded and their DN identities checked before the first callback. Callbacks
// may inspect the owned DN metadata only; they must not write to the transaction.
// Unsupported writers return false without callbacks or cancellation checkpoints.
func ForEachDeleteCandidateDN(writer Writer, visit func(directory.Entry) error) (bool, error) {
	scoped, ok := writer.(schemaAwarePartitionWriter)
	if !ok || scoped.partition == "" || strings.IndexByte(scoped.partition, 0) >= 0 {
		return false, nil
	}
	// The existing ready-partition ForEach also uses this maintenance backend,
	// rather than invoking inner decorators' ForEachIn methods.
	tx, ok := maintenanceReader(scoped.Writer).(*boltTx)
	if !ok || !tx.tx.Writable() {
		return false, nil
	}
	marker := tx.meta.Get(boltSchemaAwareDNMigrationMetadataKey(scoped.partition))
	if len(marker) != 1 || int(marker[0]) != schemaAwareDNIdentityFormatVersion {
		return false, nil
	}
	if err := requireSchemaAwareDNIdentities(scoped.Writer, scoped.partition); err != nil {
		return true, err
	}

	type candidate struct {
		entry directory.Entry
		key   string
	}
	var candidates []candidate
	prefix := []byte(scoped.partition + "\x00")
	cursor := tx.entries.Cursor()
	for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return true, err
		}
		entry, err := decodeDeleteDNMetadata(value)
		if err != nil {
			return true, err
		}
		physicalKey := string(key[len(prefix):])
		var orderKey string
		if physicalKey != "" {
			dn, err := directory.ParseDNWithIdentityKey(entry.DN, physicalKey)
			if err != nil {
				return true, err
			}
			orderKey = dn.LegacyKey() + "\x00" + physicalKey
			entry = entry.WithNormalizedDNHint(dn, orderKey)
		} else {
			// Retain ForEach's behavior even for an empty physical identity under
			// a ready marker, including schema normalization and its error order.
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return true, err
			}
			orderKey, err = schemaAwareDNOrderKey(dn, scoped.normalizer)
			if err != nil {
				return true, err
			}
		}
		candidates = append(candidates, candidate{entry: entry, key: orderKey})
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		if candidates[left].key == candidates[right].key {
			return candidates[left].entry.DN < candidates[right].entry.DN
		}
		return candidates[left].key < candidates[right].key
	})
	for _, candidate := range candidates {
		if err := visit(candidate.entry); err != nil {
			return true, err
		}
	}
	return true, nil
}

func decodeDeleteDNMetadata(value []byte) (directory.Entry, error) {
	if !validBinaryCandidateEntry(value) {
		stored, err := decodeStoredEntry(value)
		if err != nil {
			return directory.Entry{}, err
		}
		return directory.Entry{DN: stored.DN}, nil
	}
	// Structural validation covered attributes and V3 flags. Match the physical
	// iterator's decodeStoredEntry contract; binding validation remains at its
	// existing later write/refresh sites rather than gaining earlier precedence.
	remaining := value[len(entryBinaryPrefix):]
	if bytes.HasPrefix(value, entryBinaryV3Prefix) {
		_, remaining, _ = consumeEntryBinaryField(remaining)
	}
	dn, _, _ := consumeEntryBinaryField(remaining)
	return directory.Entry{DN: string(dn)}, nil
}
