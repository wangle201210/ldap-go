package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var ErrPartitionEntryCountUnavailable = errors.New("partition entry count unavailable")

type partitionEntryCounter interface {
	PartitionEntryCount(partition string) (uint64, error)
}

// PartitionEntryCount returns the number of entries visible in partition from
// the reader's current transaction. Native memory and bbolt readers answer in
// constant time without decoding entries.
func PartitionEntryCount(reader Reader, partition string) (uint64, error) {
	for depth := 0; depth < 32 && reader != nil; depth++ {
		if counter, ok := reader.(partitionEntryCounter); ok {
			return counter.PartitionEntryCount(partition)
		}
		provider, ok := reader.(MaintenanceReaderProvider)
		if !ok {
			break
		}
		next := provider.MaintenanceStorageReader()
		if next == nil || next == reader {
			break
		}
		reader = next
	}
	return 0, ErrPartitionEntryCountUnavailable
}

// Reuse the maintenance check's entry traversal; live counter reads stay O(1).
func checkBoltEntryCounts(ctx context.Context, tx *bolt.Tx, actual map[string]uint64) error {
	counts := tx.Bucket(entryCountsBucket)
	if counts == nil {
		key, _ := tx.Cursor().Seek(entryCountsBucket)
		if bytes.Equal(key, entryCountsBucket) {
			return errors.New("entry count bucket is replaced by a value")
		}
		// Legacy files predate this derived bucket. Writable open backfills it.
		return nil
	}
	if err := counts.ForEach(func(key, value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value == nil {
			return fmt.Errorf("entry count bucket contains nested bucket %q", key)
		}
		if len(key) == 0 || key[0] != 0 {
			return fmt.Errorf("invalid entry count key %q", key)
		}
		partition := string(key[1:])
		if len(value) != 8 {
			return fmt.Errorf("partition %q has invalid entry count encoding", partition)
		}
		count := binary.BigEndian.Uint64(value)
		if count == 0 || actual[partition] != count {
			return fmt.Errorf("partition %q entry count is %d, actual %d", partition, count, actual[partition])
		}
		return nil
	}); err != nil {
		return err
	}
	for partition := range actual {
		if err := ctx.Err(); err != nil {
			return err
		}
		if counts.Get(boltEntryCountKey(partition)) == nil {
			return fmt.Errorf("partition %q is missing its entry count", partition)
		}
	}
	return nil
}
