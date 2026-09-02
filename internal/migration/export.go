package migration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type ExportResult struct {
	Entries int
}

type ExportOptions struct {
	Database              string
	SelectDefaultDatabase bool
	IncludeSubordinates   bool
	Filter                string
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
		matchEntry := func(directory.Entry) (bool, error) { return true, nil }
		if options.Filter != "" {
			filter, err := ldapwire.CompileFilter(options.Filter)
			if err != nil {
				return fmt.Errorf("invalid export filter %q: %w", options.Filter, err)
			}
			registry, err := importedSchemaRegistry(tx, nil)
			if err != nil {
				return err
			}
			matchEntry = func(entry directory.Entry) (bool, error) {
				return filter.MatchWith(entry, registry)
			}
		}
		appendTarget := func(target databaseTarget) error {
			return tx.ForEachIn(target.partition, func(entry directory.Entry) error {
				matched, err := matchEntry(entry)
				if err != nil {
					return fmt.Errorf(
						"evaluate export filter for %q: %w",
						entry.DN,
						err,
					)
				}
				if !matched {
					return nil
				}
				entries = append(entries, entry)
				return nil
			})
		}
		appendSelected := func(target databaseTarget) error {
			if !target.supportsOfflineExport() {
				return fmt.Errorf(
					"OpenLDAP %s backend %q does not support offline entry export",
					target.backend,
					target.name,
				)
			}
			if err := appendTarget(target); err != nil {
				return err
			}
			if !options.IncludeSubordinates {
				return nil
			}
			targets, err := loadDatabaseTargets(tx)
			if err != nil {
				return err
			}
			subordinates, err := glueSubordinateTargets(tx, target, targets)
			if err != nil {
				return err
			}
			for _, subordinate := range subordinates {
				if !subordinate.supportsOfflineExport() {
					continue
				}
				if err := appendTarget(subordinate); err != nil {
					return err
				}
			}
			return nil
		}
		if options.Database != "" {
			target, err := resolveDatabaseTarget(tx, options.Database)
			if err != nil {
				return err
			}
			return appendSelected(target)
		}
		if options.SelectDefaultDatabase {
			target, found, err := resolveDefaultDatabaseTarget(tx)
			if err != nil {
				return fmt.Errorf("resolve default OpenLDAP database: %w", err)
			}
			if found {
				return appendSelected(target)
			}
			return errors.New("no available OpenLDAP content database")
		}

		seen := make(map[string]string)
		return tx.ForEachPartition(func(partition string, entry directory.Entry) error {
			matched, err := matchEntry(entry)
			if err != nil {
				return fmt.Errorf(
					"evaluate export filter for %q: %w",
					entry.DN,
					err,
				)
			}
			if !matched {
				return nil
			}
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
