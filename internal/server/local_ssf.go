package server

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type localSSFSyntaxError struct {
	err error
}

func (failure *localSSFSyntaxError) Error() string {
	return "olcLocalSSF must be a 32-bit integer: " + failure.err.Error()
}

func localSSFConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *localSSFSyntaxError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(
		ldapwire.ResultInvalidAttributeSyntax,
		"invalid cn=config: "+err.Error(),
	), true
}

func loadLocalSSF(reader storage.Reader) (uint32, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return defaultLocalSecurityStrengthFactor, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load olcLocalSSF: %w", err)
	}
	values := entry.Values("olcLocalSSF")
	if len(values) == 0 {
		return defaultLocalSecurityStrengthFactor, nil
	}
	if len(values) != 1 {
		return 0, errors.New("olcLocalSSF must be single-valued")
	}
	value, err := strconv.ParseInt(
		strings.TrimLeft(string(values[0]), " \t\n\v\f\r"),
		0,
		32,
	)
	if err != nil {
		var number *strconv.NumError
		if errors.As(err, &number) && errors.Is(number.Err, strconv.ErrSyntax) {
			return 0, &localSSFSyntaxError{err: err}
		}
		return 0, fmt.Errorf("olcLocalSSF must be a 32-bit integer: %w", err)
	}
	return uint32(int32(value)), nil
}

func (server *Server) connectionTransportSecurityStrength(connection net.Conn) uint32 {
	if provider, ok := connection.(securityStrengthConnection); ok {
		return provider.SecurityStrengthFactor()
	}
	if address := connection.LocalAddr(); address != nil && address.Network() == "unix" {
		if runtime := server.runtime.Load(); runtime != nil {
			return runtime.localSSF
		}
		return defaultLocalSecurityStrengthFactor
	}
	return 0
}
