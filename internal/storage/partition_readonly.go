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
	return forEachReadOnlyPhysicalEntry(reader, nil, 0, func(entry directory.Entry, _ bool, _ error) error {
		return visit(entry)
	})
}

// ForEachReadOnlyStablePhysicalEntryInScope shares the read-only ownership
// contract above and reuses DN decoding for scope evaluation. Every validated
// row still reaches visit, including rows outside scope. Scope errors are passed
// to visit so callers can retain their deadline/error ordering; DN validation
// errors stop iteration before the callback as before.
func ForEachReadOnlyStablePhysicalEntryInScope(reader Reader, base directory.DN, scope directory.Scope, visit func(directory.Entry, bool, error) error) (bool, error) {
	return forEachReadOnlyPhysicalEntry(reader, &base, scope, visit)
}

func forEachReadOnlyPhysicalEntry(reader Reader, base *directory.DN, scope directory.Scope, visit func(directory.Entry, bool, error) error) (bool, error) {
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
		var inScope bool
		var scopeErr error
		if base == nil {
			err = directory.ValidateDNWithIdentityKey(entry.DN, identity)
		} else {
			inScope, scopeErr, err = directory.ValidateDNIdentityInScope(entry.DN, identity, *base, scope)
		}
		if err != nil {
			return true, err
		}
		if err := visit(entry.WithDNIdentityKey(identity), inScope, scopeErr); err != nil {
			return true, err
		}
	}
	return true, nil
}
