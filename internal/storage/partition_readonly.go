package storage

import (
	"bytes"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// ForEachReadOnlyStablePhysicalEntry has ForEachStablePhysicalEntry's order,
// decoding errors and cancellation checkpoints, but entries are read-only and
// valid only within their callback. Retained output must be cloned or selected
// there. DNs, descriptions and identity keys are owned; no parsed DN hint is
// provided. DN identity validation still precedes every callback.
//
// Only read-only Bolt transactions in nonempty schema-aware partitions use this
// path. Unsupported readers return false without visiting entries.
func ForEachReadOnlyStablePhysicalEntry(reader Reader, visit func(directory.Entry) error) (bool, error) {
	scoped, ok := reader.(schemaAwarePartitionReader)
	if !ok || scoped.partition == "" {
		return false, nil
	}
	tx, ok := maintenanceReader(scoped.Reader).(*boltTx)
	if !ok || tx.tx.Writable() {
		return false, nil
	}
	if err := requireSchemaAwareDNIdentities(scoped.Reader, scoped.partition); err != nil {
		return false, err
	}
	var decoder readOnlyCandidateDecoder
	prefix := []byte(scoped.partition + "\x00")
	cursor := tx.entries.Cursor()
	for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return true, err
		}
		identity := string(key[len(prefix):])
		entry, err := decoder.decode(value)
		if err != nil {
			return true, err
		}
		if err := directory.ValidateDNWithIdentityKey(entry.DN, identity); err != nil {
			return true, err
		}
		if err := visit(entry.WithDNIdentityKey(identity)); err != nil {
			return true, err
		}
	}
	return true, nil
}
