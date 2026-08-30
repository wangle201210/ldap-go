package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const schemaAwareDNOrderFormatVersion = 1

func schemaAwareDNOrderMetadataKey(partition string) string {
	return "dn-order:v1:" + partition
}

func schemaAwareDNOrderPrefix(partition string) []byte {
	return []byte(partition + "\x00")
}

func boltSchemaAwareDNOrderKey(
	partition string,
	entry directory.Entry,
	identity string,
) ([]byte, error) {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 0, len(partition)+len(dn.Key())+len(identity)+2)
	key = append(key, partition...)
	key = append(key, 0)
	key = append(key, dn.Key()...)
	key = append(key, 0)
	key = append(key, identity...)
	return key, nil
}

func (tx *boltTx) schemaAwareDNOrderReady(partition string) (bool, error) {
	if tx.dnOrder == nil {
		return false, nil
	}
	value := tx.meta.Get(genericMetadataKey(schemaAwareDNOrderMetadataKey(partition)))
	if value == nil {
		return false, nil
	}
	if len(value) != 1 || int(value[0]) != schemaAwareDNOrderFormatVersion {
		return false, fmt.Errorf(
			"partition %q has unsupported DN order format marker %x",
			partition,
			value,
		)
	}
	return true, nil
}

func (tx *boltTx) setSchemaAwareDNOrderReady(partition string) error {
	return tx.meta.Put(
		genericMetadataKey(schemaAwareDNOrderMetadataKey(partition)),
		[]byte{schemaAwareDNOrderFormatVersion},
	)
}

func (tx *boltTx) invalidateSchemaAwareDNOrder(partition string) error {
	if err := tx.clearSchemaAwareDNOrder(partition); err != nil {
		return err
	}
	return tx.meta.Delete(genericMetadataKey(schemaAwareDNOrderMetadataKey(partition)))
}

func (tx *boltTx) clearSchemaAwareDNOrder(partition string) error {
	if tx.dnOrder == nil {
		return nil
	}
	prefix := schemaAwareDNOrderPrefix(partition)
	var keys [][]byte
	cursor := tx.dnOrder.Cursor()
	for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		keys = append(keys, bytes.Clone(key))
	}
	for _, key := range keys {
		if err := tx.dnOrder.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func (tx *boltTx) rebuildSchemaAwareDNOrder(partition string) error {
	if tx.dnOrder == nil {
		return errors.New("schema-aware DN order bucket is missing")
	}
	if err := tx.clearSchemaAwareDNOrder(partition); err != nil {
		return err
	}
	entryPrefix := []byte(partition + "\x00")
	entryCursor := tx.entries.Cursor()
	for key, value := entryCursor.Seek(entryPrefix); key != nil && bytes.HasPrefix(key, entryPrefix); key, value = entryCursor.Next() {
		identity := string(key[len(entryPrefix):])
		if !isSchemaAwareDNKey(identity) {
			return fmt.Errorf("partition %q: %w", partition, ErrDNIdentityMigrationRequired)
		}
		stored, err := decodeStoredEntry(value)
		if err != nil {
			return err
		}
		orderKey, err := boltSchemaAwareDNOrderKey(partition, stored.Entry, identity)
		if err != nil {
			return err
		}
		if err := tx.dnOrder.Put(orderKey, []byte(identity)); err != nil {
			return err
		}
	}
	return tx.setSchemaAwareDNOrderReady(partition)
}

func (tx *boltTx) putSchemaAwareDNOrder(
	partition string,
	entry directory.Entry,
	identity string,
) error {
	ready, err := tx.schemaAwareDNOrderReady(partition)
	if err != nil || !ready {
		return err
	}
	key, err := boltSchemaAwareDNOrderKey(partition, entry, identity)
	if err != nil {
		return err
	}
	return tx.dnOrder.Put(key, []byte(identity))
}

func (tx *boltTx) removeSchemaAwareDNOrder(
	partition string,
	entry directory.Entry,
	identity string,
) error {
	ready, err := tx.schemaAwareDNOrderReady(partition)
	if err != nil || !ready {
		return err
	}
	key, err := boltSchemaAwareDNOrderKey(partition, entry, identity)
	if err != nil {
		return err
	}
	return tx.dnOrder.Delete(key)
}
