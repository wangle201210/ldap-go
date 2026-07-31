package server

import (
	"context"
	"errors"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var errSASLCleartextPasswordUnavailable = errors.New(
	"SASL cleartext password is unavailable",
)

func (server *Server) lookupSASLCleartextPassword(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
) ([]byte, error) {
	database := databaseForDN(runtime, authenticationDN)
	if database == nil {
		return nil, errSASLCleartextPasswordUnavailable
	}
	if database.rootDN != nil &&
		database.rootDN.Equal(authenticationDN) &&
		database.rootPasswordSet {
		password, ok := auth.ExtractCleartextPassword(
			database.rootPassword,
		)
		if !ok {
			return nil, errSASLCleartextPasswordUnavailable
		}
		return password, nil
	}

	var password []byte
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := storage.ReaderInPartition(reader, database.partition)
		entry, err := tx.Get(authenticationDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !server.allowed(
			runtime,
			tx,
			"",
			entry,
			"userPassword",
			nil,
			acl.Auth,
		) {
			return nil
		}
		for _, stored := range entry.Values("userPassword") {
			cleartext, ok := auth.ExtractCleartextPassword(stored)
			if !ok {
				continue
			}
			password = cleartext
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if password == nil {
		return nil, errSASLCleartextPasswordUnavailable
	}
	return password, nil
}
