package storage

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// InferNamingContextsMetadataWithNormalizer preserves the full naming-context
// scan and validation while avoiding copies of attributes that inference never
// reads. Only owned DN strings escape the backend iteration.
func InferNamingContextsMetadataWithNormalizer(
	reader Reader,
	normalizer directory.DNAttributeNormalizer,
) ([]string, error) {
	var scan func(func(string, directory.Entry, directory.DN) error) error
	switch backend := reader.(type) {
	case *boltTx:
		scan = backend.forEachNamingContextMetadata
	case *memoryTx:
		scan = backend.forEachNamingContextMetadata
	}
	if scan == nil {
		return InferNamingContextsWithNormalizer(reader, normalizer)
	}
	configurationSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return nil, err
	}
	return inferNamingContexts(func(visit func(directory.Entry, directory.DN) error) error {
		return scan(func(partition string, entry directory.Entry, legacy directory.DN) error {
			dn := legacy
			if partition != OpenLDAPConfigPartition &&
				!configurationSuffix.Equal(legacy) &&
				!configurationSuffix.AncestorOf(legacy) {
				var err error
				dn, err = legacy.NormalizeWith(normalizer)
				if err != nil {
					return err
				}
			}
			return visit(entry, dn)
		})
	})
}

func (tx *boltTx) forEachNamingContextMetadata(
	visit func(string, directory.Entry, directory.DN) error,
) error {
	return tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		partition, identity := splitPartitionedEntryKey(string(key))
		entry, legacy, err := decodeNamingContextMetadataDN(identity, value)
		if err != nil {
			return err
		}
		return visit(partition, entry, legacy)
	})
}

func decodeNamingContextMetadata(
	identity string,
	value []byte,
) (directory.Entry, error) {
	entry, _, err := decodeNamingContextMetadataDN(identity, value)
	return entry, err
}

func decodeNamingContextMetadataDN(
	identity string,
	value []byte,
) (directory.Entry, directory.DN, error) {
	if validBinaryCandidateEntry(value) {
		// The structural validator consumed every field, including attributes
		// and V3 flags, so these header reads cannot fail. No borrowed bytes escape.
		remaining := value[len(entryBinaryPrefix):]
		if bytes.HasPrefix(value, entryBinaryV3Prefix) {
			_, remaining, _ = consumeEntryBinaryField(remaining)
		}
		dn, remaining, _ := consumeEntryBinaryField(remaining)
		binding, remaining, _ := consumeEntryBinaryField(remaining)
		entry := directory.Entry{DN: string(dn)}
		var storedIdentity, storedSource string
		if bytes.HasPrefix(value, entryBinaryV1Prefix) {
			source, _, _ := consumeEntryBinaryField(remaining)
			storedIdentity, storedSource = string(binding), string(source)
			binding = nil
		}
		legacy, err := validateStoredEntryIdentityDN(identity, entry, storedIdentity, storedSource, binding)
		if err != nil {
			return directory.Entry{}, directory.DN{}, err
		}
		return entry, legacy, nil
	}
	// Keep JSON, unknown formats and every decode error on the
	// authoritative path, including its error wrapping and validation order.
	entry, err := decodeAndValidateEntry(identity, value)
	if err != nil {
		return directory.Entry{}, directory.DN{}, err
	}
	legacy, err := directory.ParseDN(entry.DN)
	return directory.Entry{DN: entry.DN}, legacy, err
}

func (tx *memoryTx) forEachNamingContextMetadata(
	visit func(string, directory.Entry, directory.DN) error,
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
		partition, identity := splitPartitionedEntryKey(key)
		entry := tx.entries[key]
		legacy, err := validateStoredEntryIdentityDN(identity, entry, tx.dnIdentities[key], tx.dnSources[key], nil)
		if err != nil {
			return fmt.Errorf("entry key %q: %w", key, err)
		}
		if err := visit(partition, directory.Entry{DN: entry.DN}, legacy); err != nil {
			return err
		}
	}
	return nil
}
