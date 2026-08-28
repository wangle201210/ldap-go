package server

import (
	"bytes"
	"context"
	"errors"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) applyNopsModify(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
	request ldapwire.ModifyRequest,
) (ldapwire.ModifyRequest, bool, error) {
	if !database.nopsOverlay || len(request.Changes) == 0 {
		return request, false, nil
	}
	var entry directory.Entry
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database, ctx)
		normalized, err := storage.NormalizeReaderDN(tx, dn)
		if err != nil {
			return err
		}
		entry, err = tx.Get(normalized)
		return err
	})
	if errors.Is(err, storage.ErrEntryNotFound) {
		return request, false, nil
	}
	if err != nil {
		return request, false, err
	}

	changes := make([]ldapwire.Modification, 0, len(request.Changes))
	for _, change := range request.Changes {
		if change.Operation == ldapwire.ModificationReplace &&
			len(change.Attribute.Values) > 0 &&
			nopsValuesEqual(
				change.Attribute.Values,
				runtime.schema.AttributeValues(entry, change.Attribute.Description),
			) {
			continue
		}
		changes = append(changes, change)
	}
	request.Changes = changes
	return request, len(changes) == 0, nil
}

func nopsValuesEqual(replacements, stored [][]byte) bool {
	if len(replacements) != len(stored) {
		return false
	}
	found := 0
	for _, replacement := range replacements {
		for _, value := range stored {
			if bytes.Equal(replacement, value) {
				found++
				break
			}
		}
	}
	return found == len(stored)
}
