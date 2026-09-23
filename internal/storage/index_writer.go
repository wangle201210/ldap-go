package storage

import "github.com/wangle201210/ldap-go/internal/directory"

func (writer schemaAwarePartitionWriter) planEqualityIndexCandidates(
	filter directory.Filter,
) ([]directory.Entry, bool, error) {
	reader := schemaAwarePartitionReader{
		partitionReader: partitionReader{
			Reader:    liveEqualityIndexReader{Reader: writer.Writer},
			partition: writer.partition,
		},
		normalizer:  writer.normalizer,
		allowLegacy: writer.allowLegacy,
	}
	return reader.planEqualityIndexCandidates(filter)
}

// The backend remains live, but its transaction ID cannot identify successive
// index configurations within a write transaction or an aborted transaction.
type liveEqualityIndexReader struct {
	Reader
}

func (liveEqualityIndexReader) StorageSnapshotRevision() (uint64, bool) {
	return 0, false
}

func (reader liveEqualityIndexReader) MaintenanceStorageReader() Reader {
	return reader.Reader
}
