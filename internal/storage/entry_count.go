package storage

import "errors"

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
