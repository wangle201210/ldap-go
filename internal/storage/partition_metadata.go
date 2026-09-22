package storage

import (
	"bytes"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// EntryMetadataView borrows a row's DN, physical identity and attribute values.
// The view and its attributes are read-only and valid only in the callback.
// Materialize owns the whole entry; ReadOnlyEntry owns only its strings.
type EntryMetadataView struct {
	dn         []byte
	identity   []byte
	attributes []directory.Attribute
}

// Attributes returns callback-scoped, read-only descriptors and values.
func (view EntryMetadataView) Attributes() []directory.Attribute {
	return view.attributes
}

// HasIdentity reports whether the physical key is nonempty, including legacy keys.
func (view EntryMetadataView) HasIdentity() bool {
	return len(view.identity) > 0
}

// ReadOnlyEntry copies DN and identity strings, but borrows attribute descriptors
// and values for the callback, like ForEachReadOnlyStablePhysicalEntry. Retained
// attributes must be cloned or selected before the callback returns.
func (view EntryMetadataView) ReadOnlyEntry() directory.Entry {
	return directory.Entry{DN: string(view.dn), Attributes: view.attributes}.
		WithDNIdentityKey(string(view.identity))
}

// Materialize returns an independent owned entry on every call. ReadOnlyEntry
// copies strings explicitly; Clone copies attribute descriptors and values.
func (view EntryMetadataView) Materialize() directory.Entry {
	return view.ReadOnlyEntry().Clone()
}

func (decoder *readOnlyCandidateDecoder) decodeMetadata(value, identity []byte) (EntryMetadataView, error) {
	dn, attributes, ok := decoder.borrowMetadata(value)
	if !ok {
		// Keep unsupported shapes and all codec errors on the authoritative path.
		stored, err := decodeStoredEntry(value)
		if err != nil {
			return EntryMetadataView{}, err
		}
		dn, attributes = []byte(stored.DN), stored.Attributes
	}
	return EntryMetadataView{dn: dn, identity: identity, attributes: attributes}, nil
}

// ForEachReadOnlyStablePhysicalMetadataInScope has the read-only physical
// iterator's order, codec errors and cancellation checkpoints, but borrows DN
// and identity bytes too. Every validated row reaches visit, including rows
// outside scope. Scope errors are deferred to visit for deadline/error ordering;
// DN validation errors stop iteration before the callback.
// Only read-only Bolt transactions in nonempty schema-aware partitions qualify.
// Unsupported readers return false without visiting any rows.
func ForEachReadOnlyStablePhysicalMetadataInScope(
	reader Reader,
	base directory.DN,
	scope directory.Scope,
	visit func(EntryMetadataView, bool, error) error,
) (bool, error) {
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
		view, err := decoder.decodeMetadata(value, key[len(prefix):])
		if err != nil {
			return true, err
		}
		inScope, scopeErr, err := directory.ValidateDNIdentityInScopeBytes(view.dn, view.identity, base, scope)
		if err != nil {
			return true, err
		}
		if err := visit(view, inScope, scopeErr); err != nil {
			return true, err
		}
	}
	return true, nil
}
