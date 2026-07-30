package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) partitionDefaultEntries(
	ctx context.Context,
	runtime *runtimeState,
) error {
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
				if err := writer.DeleteIn("", dn); err != nil {
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
