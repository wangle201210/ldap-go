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

func ExportLDIF(
	ctx context.Context,
	store storage.Store,
	writer io.Writer,
) (ExportResult, error) {
	if writer == nil {
		return ExportResult{}, fmt.Errorf("LDIF writer is required")
	}

	var entries []directory.Entry
	err := store.View(ctx, func(tx storage.Reader) error {
		return tx.ForEach(func(entry directory.Entry) error {
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
