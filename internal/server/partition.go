package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) partitionLegacyConfigurationEntries(ctx context.Context) error {
	var entries []directory.Entry
	if err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		return reader.ForEachIn("", func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf("parse unpartitioned entry DN %q: %w", entry.DN, err)
			}
			if isConfigurationDN(dn) {
				entries = append(entries, entry)
			}
			return nil
		})
	}); err != nil {
		return fmt.Errorf("scan unpartitioned configuration entries: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		for _, entry := range entries {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			existing, err := writer.GetIn(configurationStoragePartition, dn)
			targetAlreadyPresent := err == nil
			switch {
			case err == nil && !existing.Equal(entry):
				return fmt.Errorf(
					"configuration partition already contains a different entry for %q",
					entry.DN,
				)
			case err == nil:
			case errors.Is(err, storage.ErrEntryNotFound):
				if err := writer.PutIn(configurationStoragePartition, entry, false); err != nil {
					return fmt.Errorf("partition configuration entry %q: %w", entry.DN, err)
				}
			default:
				return err
			}
			if err := writer.DeleteIn("", dn); err != nil {
				if targetAlreadyPresent && errors.Is(err, storage.ErrEntryNotFound) {
					continue
				}
				return fmt.Errorf("remove unpartitioned configuration entry %q: %w", entry.DN, err)
			}
		}
		return nil
	})
}

func (server *Server) partitionDefaultEntries(
	ctx context.Context,
	runtime *runtimeState,
) error {
	hasEntries := false
	if err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		return reader.ForEachIn("", func(directory.Entry) error {
			hasEntries = true
			return nil
		})
	}); err != nil {
		return fmt.Errorf("scan unpartitioned entries: %w", err)
	}
	if !hasEntries {
		return nil
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		var entries []directory.Entry
		if err := writer.ForEachIn("", func(entry directory.Entry) error {
			entries = append(entries, entry)
			return nil
		}); err != nil {
			return fmt.Errorf("scan unpartitioned entries: %w", err)
		}

		for _, entry := range entries {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf("parse unpartitioned entry DN %q: %w", entry.DN, err)
			}
			partition, err := partitionForLegacyDN(runtime, dn)
			if err != nil {
				return err
			}
			if partition == "" {
				continue
			}

			existing, err := writer.GetIn(partition, dn)
			switch {
			case err == nil && !existing.Equal(entry):
				return fmt.Errorf(
					"partition %q already contains a different entry for %q",
					partition,
					entry.DN,
				)
			case err == nil:
				if err := writer.DeleteIn("", dn); err != nil &&
					!errors.Is(err, storage.ErrEntryNotFound) {
					return err
				}
				continue
			case !errors.Is(err, storage.ErrEntryNotFound):
				return err
			}
			if err := writer.PutIn(partition, entry, false); err != nil {
				return fmt.Errorf("partition entry %q: %w", entry.DN, err)
			}
			if err := writer.DeleteIn("", dn); err != nil {
				return fmt.Errorf("remove unpartitioned entry %q: %w", entry.DN, err)
			}
		}
		return nil
	})
}

func partitionForLegacyDN(
	runtime *runtimeState,
	dn directory.DN,
) (string, error) {
	if isConfigurationDN(dn) {
		return configurationStoragePartition, nil
	}
	index, err := databaseIndexForLegacyDN(runtime.databases, dn)
	if err != nil {
		return "", fmt.Errorf(
			"cannot partition legacy entry %q; re-import it with an explicit database: %w",
			dn.String(),
			err,
		)
	}
	if index < 0 {
		return "", nil
	}
	return runtime.databases[index].partition, nil
}
