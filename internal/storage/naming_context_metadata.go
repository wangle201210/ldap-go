package storage

import (
	"bytes"
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
	var scan func(func(string, directory.Entry) error) error
	switch backend := reader.(type) {
	case *boltTx:
		scan = backend.forEachNamingContextMetadata
	case *memoryTx:
		scan = backend.forEachNamingContextMetadata
	}
	if scan != nil {
		reader = namingContextMetadataReader{Reader: reader, scan: scan}
	}
	return InferNamingContextsWithNormalizer(reader, normalizer)
}

type namingContextMetadataReader struct {
	Reader
	scan func(func(string, directory.Entry) error) error
}

func (reader namingContextMetadataReader) ForEachPartition(
	visit func(string, directory.Entry) error,
) error {
	return reader.scan(visit)
}

func (tx *boltTx) forEachNamingContextMetadata(
	visit func(string, directory.Entry) error,
) error {
	return tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		partition, identity := splitPartitionedEntryKey(string(key))
		entry, err := decodeNamingContextMetadata(identity, value)
		if err != nil {
			return err
		}
		return visit(partition, entry)
	})
}

func decodeNamingContextMetadata(
	identity string,
	value []byte,
) (directory.Entry, error) {
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
		if err := validateStoredEntryIdentity(identity, entry, storedIdentity, storedSource, binding); err != nil {
			return directory.Entry{}, err
		}
		return entry, nil
	}
	// Keep JSON, unknown formats and every decode error on the
	// authoritative path, including its error wrapping and validation order.
	entry, err := decodeAndValidateEntry(identity, value)
	if err != nil {
		return directory.Entry{}, err
	}
	return directory.Entry{DN: entry.DN}, nil
}

func (tx *memoryTx) forEachNamingContextMetadata(
	visit func(string, directory.Entry) error,
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
		entry := tx.entries[key]
		if err := tx.validateEntry(key, entry); err != nil {
			return err
		}
		if err := visit(partition, directory.Entry{DN: entry.DN}); err != nil {
			return err
		}
	}
	return nil
}
