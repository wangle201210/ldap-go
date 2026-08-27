package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type maxFilterDepthSyntaxError struct {
	err error
}

func (failure *maxFilterDepthSyntaxError) Error() string {
	return "olcMaxFilterDepth must be a 32-bit integer: " + failure.err.Error()
}

func maxFilterDepthConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *maxFilterDepthSyntaxError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(
		ldapwire.ResultInvalidAttributeSyntax,
		"invalid cn=config: "+err.Error(),
	), true
}

func loadMaxFilterDepth(reader storage.Reader) (int, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return ldapwire.DefaultMaxFilterDepth, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load olcMaxFilterDepth: %w", err)
	}
	values := entry.Values("olcMaxFilterDepth")
	if len(values) == 0 {
		return ldapwire.DefaultMaxFilterDepth, nil
	}
	if len(values) != 1 {
		return 0, errors.New("olcMaxFilterDepth must be single-valued")
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(values[0])), 10, 32)
	if err != nil {
		return 0, &maxFilterDepthSyntaxError{err: err}
	}
	return int(value), nil
}

func (server *Server) currentMaxFilterDepth() int {
	if runtime := server.runtime.Load(); runtime != nil {
		return runtime.maxFilterDepth
	}
	return ldapwire.DefaultMaxFilterDepth
}

func assertionFilterExceedsRuntimeDepth(
	controls []ldapwire.Control,
	maxDepth int,
) bool {
	for _, control := range controls {
		if control.OID != assertionControlOID || !control.HasValue || len(control.Value) == 0 {
			continue
		}
		if _, err := ldapwire.DecodeFilterWithMaxDepth(control.Value, maxDepth); errors.Is(
			err,
			ldapwire.ErrFilterTooDeep,
		) {
			return true
		}
	}
	return false
}
