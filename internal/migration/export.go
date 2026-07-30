package migration

import (
	"context"
	"fmt"
	"io"
	"sort"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type ExportResult struct {
	Entries int
}

type ExportOptions struct {
	Database string
}

func ExportLDIF(
	ctx context.Context,
	store storage.Store,
	writer io.Writer,
) (ExportResult, error) {
	return ExportLDIFWithOptions(ctx, store, writer, ExportOptions{})
}

func ExportLDIFWithOptions(
	ctx context.Context,
	store storage.Store,
	writer io.Writer,
	options ExportOptions,
) (ExportResult, error) {
	if writer == nil {
		return ExportResult{}, fmt.Errorf("LDIF writer is required")
	}

	var entries []directory.Entry
	err := store.View(ctx, func(tx storage.Reader) error {
		if options.Database != "" {
			target, err := resolveDatabaseTarget(tx, options.Database)
			if err != nil {
				return err
			}
			return tx.ForEachIn(target.partition, func(entry directory.Entry) error {
				entries = append(entries, entry)
				return nil
			})
		}

		seen := make(map[string]string)
		return tx.ForEachPartition(func(partition string, entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if previous, exists := seen[dn.Key()]; exists && previous != partition {
				return fmt.Errorf(
					"DN %q exists in multiple databases; select one database for export",
					entry.DN,
				)
			}
			seen[dn.Key()] = partition
			entries = append(entries, entry)
			return nil
		})
	})
	if err != nil {
		return ExportResult{}, err
	}

	sort.Slice(entries, func(i, j int) bool {
		left, leftErr := directory.ParseDN(entries[i].DN)
		right, rightErr := directory.ParseDN(entries[j].DN)
		if leftErr != nil || rightErr != nil {
			return entries[i].DN < entries[j].DN
		}
		if left.Depth() != right.Depth() {
			return left.Depth() < right.Depth()
		}
		return left.Key() < right.Key()
	})
	for _, entry := range entries {
		if err := ldif.Dump(writer, 76, toLDAPEntry(entry)); err != nil {
			return ExportResult{}, fmt.Errorf("export %q: %w", entry.DN, err)
		}
	}
	return ExportResult{Entries: len(entries)}, nil
}

func toLDAPEntry(source directory.Entry) *ldap.Entry {
	entry := &ldap.Entry{
		DN:         source.DN,
		Attributes: make([]*ldap.EntryAttribute, 0, len(source.Attributes)),
	}
	for _, sourceAttribute := range source.Attributes {
		attribute := &ldap.EntryAttribute{
			Name:       sourceAttribute.Description,
			Values:     make([]string, len(sourceAttribute.Values)),
			ByteValues: make([][]byte, len(sourceAttribute.Values)),
		}
		for i := range sourceAttribute.Values {
			attribute.Values[i] = string(sourceAttribute.Values[i])
			attribute.ByteValues[i] = append([]byte(nil), sourceAttribute.Values[i]...)
		}
		entry.Attributes = append(entry.Attributes, attribute)
	}
	return entry
}
