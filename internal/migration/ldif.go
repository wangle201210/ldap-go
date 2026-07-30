package migration

import (
	"context"
	"errors"
	"fmt"
	"io"

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

		contexts, err := storage.InferNamingContexts(tx)
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
