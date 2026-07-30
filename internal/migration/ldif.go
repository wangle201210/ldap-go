package migration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type ImportOptions struct {
	Replace bool
}

type ImportResult struct {
	Entries        int
	NamingContexts []string
}

// ImportLDIF atomically imports content LDIF, including slapcat operational
// attributes. Change records are rejected because they have different
// transaction semantics and are handled by the future ldapmodify-compatible
// command.
func ImportLDIF(
	ctx context.Context,
	store storage.Store,
	reader io.Reader,
	options ImportOptions,
) (ImportResult, error) {
	if reader == nil {
		return ImportResult{}, errors.New("LDIF reader is required")
	}

	var result ImportResult
	err := store.Update(ctx, func(tx storage.Writer) error {
		if options.Replace {
			if err := tx.Clear(); err != nil {
				return fmt.Errorf("clear destination: %w", err)
			}
		}

		document := &ldif.LDIF{}
		for record, parseErr := range ldif.UnmarshalEntries(reader, document) {
			if parseErr != nil {
				return fmt.Errorf("parse LDIF: %w", parseErr)
			}
			if record == nil {
				continue
			}
			if record.Entry == nil {
				return errors.New("LDIF change records are not accepted by content import")
			}

			entry := fromLDAPEntry(record.Entry)
			if err := tx.Put(entry, false); err != nil {
				return fmt.Errorf("import %q: %w", entry.DN, err)
			}
			result.Entries++
		}

		contexts, err := inferNamingContexts(tx)
		if err != nil {
			return err
		}
		if err := tx.SetNamingContexts(contexts); err != nil {
			return fmt.Errorf("store naming contexts: %w", err)
		}
		result.NamingContexts = contexts
		return nil
	})
	if err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

func fromLDAPEntry(source *ldap.Entry) directory.Entry {
	entry := directory.Entry{
		DN:         source.DN,
		Attributes: make([]directory.Attribute, 0, len(source.Attributes)),
	}
	for _, sourceAttribute := range source.Attributes {
		attribute := directory.Attribute{
			Description: sourceAttribute.Name,
			Values:      make([][]byte, len(sourceAttribute.ByteValues)),
		}
		for i := range sourceAttribute.ByteValues {
			attribute.Values[i] = append([]byte(nil), sourceAttribute.ByteValues[i]...)
		}
		entry.Attributes = append(entry.Attributes, attribute)
	}
	return entry
}

func inferNamingContexts(reader storage.Reader) ([]string, error) {
	type namedDN struct {
		dn  directory.DN
		raw string
	}

	entries := make(map[string]namedDN)
	if err := reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		if dn.Depth() == 0 {
			return nil
		}
		entries[dn.Key()] = namedDN{dn: dn, raw: entry.DN}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan imported entries: %w", err)
	}

	contexts := make([]namedDN, 0)
	for _, entry := range entries {
		parent, hasParent := entry.dn.Parent()
		if !hasParent || parent.Depth() == 0 {
			contexts = append(contexts, entry)
			continue
		}
		if _, exists := entries[parent.Key()]; !exists {
			contexts = append(contexts, entry)
		}
	}
	sort.Slice(contexts, func(i, j int) bool {
		return contexts[i].dn.Key() < contexts[j].dn.Key()
	})

	result := make([]string, len(contexts))
	for i := range contexts {
		result[i] = contexts[i].raw
	}
	return result, nil
}
