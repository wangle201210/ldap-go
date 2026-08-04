package server

import (
	"context"
	"errors"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
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
	if rootPassword, ok := databaseAuthenticationRoot(
		runtime,
		*database,
		authenticationDN,
	); ok {
		password, ok := auth.ExtractCleartextPassword(
			rootPassword,
		)
		if !ok {
			return nil, errSASLCleartextPasswordUnavailable
		}
		return password, nil
	}
	entry, err := server.lookupSASLCredentialEntry(
		ctx,
		runtime,
		authenticationDN,
		[]string{"userPassword"},
	)
	if errors.Is(err, errSASLCredentialEntryUnavailable) {
		return nil, errSASLCleartextPasswordUnavailable
	}
	if err != nil {
		return nil, err
	}
	defer clearSASLCredentialEntry(&entry)
	for _, stored := range entry.Values("userPassword") {
		password, ok := auth.ExtractCleartextPassword(stored)
		if ok {
			return password, nil
		}
	}
	return nil, errSASLCleartextPasswordUnavailable
}

func (server *Server) authenticateSASLPassword(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
	password []byte,
) (bool, error) {
	if len(password) == 0 {
		return false, nil
	}
	database := databaseForDN(runtime, authenticationDN)
	if database == nil {
		return false, nil
	}
	if rootPassword, ok := databaseAuthenticationRoot(
		runtime,
		*database,
		authenticationDN,
	); ok {
		return auth.VerifyPassword(rootPassword, password), nil
	}
	entry, err := server.lookupSASLCredentialEntry(
		ctx,
		runtime,
		authenticationDN,
		[]string{"userPassword"},
	)
	if errors.Is(err, errSASLCredentialEntryUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer clearSASLCredentialEntry(&entry)
	for _, stored := range entry.Values("userPassword") {
		if auth.VerifyPassword(stored, password) {
			return true, nil
		}
	}
	return false, nil
}
