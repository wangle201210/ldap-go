package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) migrateRuntimeDNIdentities(
	ctx context.Context,
	runtime *runtimeState,
) error {
	current, err := runtimeDNIdentityFingerprintsCurrent(
		ctx,
		server.config.Store,
		runtime,
	)
	if err != nil || current {
		return err
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		return migrateRuntimeDNIdentitiesInWriter(writer, runtime)
	})
}

func runtimeDNIdentityFingerprintsCurrent(
	ctx context.Context,
	store storage.Store,
	runtime *runtimeState,
) (bool, error) {
	if runtime == nil || runtime.schema == nil {
		return true, nil
	}
	fingerprint := runtime.schema.DNIdentityFingerprint()
	partitions := make(map[string]struct{})
	for _, database := range runtime.databases {
		if databaseUsesLocalContentStorage(database) &&
			database.partition != configurationStoragePartition {
			partitions[database.partition] = struct{}{}
		}
	}
	current := true
	err := store.View(ctx, func(reader storage.Reader) error {
		for partition := range partitions {
			stored, err := reader.Metadata(runtimeDNIdentityFingerprintMetadataKey(partition))
			switch {
			case errors.Is(err, storage.ErrMetadataNotFound):
				current = false
			case err != nil:
				return err
			case !bytes.Equal(stored, fingerprint[:]):
				current = false
			}
		}
		return nil
	})
	return current, err
}

func migrateRuntimeDNIdentitiesInWriter(
	writer storage.Writer,
	runtime *runtimeState,
) error {
	if runtime == nil || runtime.schema == nil {
		return nil
	}
	fingerprint := runtime.schema.DNIdentityFingerprint()
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
		metadataKey := runtimeDNIdentityFingerprintMetadataKey(partition)
		stored, err := writer.Metadata(metadataKey)
		switch {
		case err == nil && bytes.Equal(stored, fingerprint[:]):
			continue
		case err != nil && !errors.Is(err, storage.ErrMetadataNotFound):
			return fmt.Errorf(
				"read DN identity schema fingerprint in partition %q: %w",
				partition,
				err,
			)
		}
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
		if err := writer.SetMetadata(metadataKey, fingerprint[:]); err != nil {
			return fmt.Errorf(
				"store DN identity schema fingerprint in partition %q: %w",
				partition,
				err,
			)
		}
	}
	return nil
}

func runtimeDNIdentityFingerprintMetadataKey(partition string) string {
	return "server:dn-identity-schema:v1:" +
		base64.RawURLEncoding.EncodeToString([]byte(partition))
}
