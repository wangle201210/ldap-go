package server

import (
	"crypto/sha256"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (normalizer *databaseEqualityIndexNormalizer) HierarchyIdentityFingerprint() ([sha256.Size]byte, bool) {
	if normalizer == nil {
		return [sha256.Size]byte{}, false
	}
	registry, ok := normalizer.registry.(*schema.Registry)
	if !ok || registry == nil {
		return [sha256.Size]byte{}, false
	}
	return registry.DNIdentityFingerprint(), true
}

func (writer *homedirTrackingWriter) HierarchyStorageReader() storage.Reader {
	return writer.Writer
}

func (writer accessContextWriter) HierarchyStorageReader() storage.Reader {
	return writer.Writer
}

func (reader accessContextReader) HierarchyStorageReader() storage.Reader {
	return reader.Reader
}

func (writer *entryLimitWriter) HierarchyStorageReader() storage.Reader {
	return writer.Writer
}

func (reader storageRevisionReader) HierarchyStorageReader() storage.Reader {
	return reader.Reader
}

// This full validation belongs to managed-store startup, not configuration
// reloads. It catches stale persisted mappings even when schema fingerprints
// match, including databases written by an older binary without index hooks.
func runtimeHierarchyIndexesCurrent(reader storage.Reader, runtime *runtimeState) (bool, error) {
	if runtime == nil || runtime.schema == nil {
		return true, nil
	}
	current := true
	seen := make(map[string]struct{})
	for _, database := range runtime.databases {
		if !databaseUsesLocalContentStorage(database) || database.partition == configurationStoragePartition {
			continue
		}
		if _, duplicate := seen[database.partition]; duplicate {
			continue
		}
		seen[database.partition] = struct{}{}
		normalizer := &databaseEqualityIndexNormalizer{registry: runtime.schema, config: database.equalityIndexes}
		handled, ready, err := storage.ValidateHierarchyIndex(reader, database.partition, normalizer)
		if err != nil {
			return false, fmt.Errorf("validate hierarchy in partition %q: %w", database.partition, err)
		}
		if handled && !ready {
			current = false
		}
	}
	return current, nil
}
