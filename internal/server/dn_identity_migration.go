package server

import (
	"context"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) migrateRuntimeDNIdentities(
	ctx context.Context,
	runtime *runtimeState,
) error {
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		return migrateRuntimeDNIdentitiesInWriter(writer, runtime)
	})
}

func migrateRuntimeDNIdentitiesInWriter(
	writer storage.Writer,
	runtime *runtimeState,
) error {
	if runtime == nil || runtime.schema == nil {
		return nil
	}
	normalizers := make(map[string]directory.DNAttributeNormalizer)
	for _, database := range runtime.databases {
		if !databaseUsesLocalContentStorage(database) ||
			database.partition == configurationStoragePartition {
			continue
		}
		if _, exists := normalizers[database.partition]; exists {
			continue
		}
		normalizers[database.partition] = &databaseEqualityIndexNormalizer{
			registry: runtime.schema,
			config:   database.equalityIndexes,
		}
	}
	for partition, normalizer := range normalizers {
		if _, err := storage.MigrateSchemaAwareDNIdentities(
			writer,
			partition,
			normalizer,
		); err != nil {
			return fmt.Errorf(
				"migrate schema-aware DN identities in partition %q: %w",
				partition,
				err,
			)
		}
	}
	return nil
}
