package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const gentleHUPAttribute = "olcGentleHUP"

func loadGentleHUP(reader storage.Reader) (bool, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return false, validateGentleHUPPlacement(reader)
	}
	if err != nil {
		return false, fmt.Errorf("load olcGentleHUP: %w", err)
	}
	enabled, _, err := singleBoolean(entry, gentleHUPAttribute)
	if err != nil {
		return false, err
	}
	if err := validateGentleHUPPlacement(reader); err != nil {
		return false, err
	}
	return enabled, nil
}

func validateGentleHUPPlacement(reader storage.Reader) error {
	return reader.ForEach(func(entry directory.Entry) error {
		if len(entry.Values(gentleHUPAttribute)) == 0 {
			return nil
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse olcGentleHUP entry DN %q: %w", entry.DN, err)
		}
		if !configurationSuffix.Equal(dn) {
			return fmt.Errorf(
				"%s olcGentleHUP is only valid on cn=config",
				entry.DN,
			)
		}
		return nil
	})
}

func validateGentleHUPOnlineChanges(
	entry directory.Entry,
	changes []ldapwire.Modification,
) error {
	touched := false
	for _, change := range changes {
		if strings.EqualFold(
			strings.SplitN(change.Attribute.Description, ";", 2)[0],
			gentleHUPAttribute,
		) {
			touched = true
			break
		}
	}
	if !touched {
		return nil
	}
	if !isGlobalConfigurationEntry(entry.DN) {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"olcGentleHUP is only allowed on cn=config",
		)
	}
	return nil
}

// GentleHUPEnabled reports whether the active runtime enables olcGentleHUP.
func (server *Server) GentleHUPEnabled() bool {
	runtime := server.runtime.Load()
	return runtime != nil && runtime.gentleHUP
}

// BeginGentleShutdown closes admission while preserving existing sessions.
func (server *Server) BeginGentleShutdown(listener net.Listener) bool {
	if listener == nil || !server.GentleHUPEnabled() ||
		!server.gentleDraining.CompareAndSwap(false, true) {
		return false
	}
	if err := listener.Close(); err != nil {
		server.gentleDraining.Store(false)
		return false
	}
	return true
}

func (server *Server) waitForGentleConnectionClose(
	ctx context.Context,
	force context.CancelFunc,
) error {
	done := make(chan struct{})
	go func() {
		server.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		server.draining.Store(true)
		server.beginConnectionDrain()
		return server.waitForConnectionDrain(force)
	}
}

func (server *Server) gentleShutdownRequestResult(
	request ldapwire.Request,
) *ldapwire.Result {
	if !server.gentleDraining.Load() {
		return nil
	}
	write := false
	switch request := request.(type) {
	case ldapwire.AddRequest,
		ldapwire.ModifyRequest,
		ldapwire.DeleteRequest,
		ldapwire.ModifyDNRequest:
		write = true
	case ldapwire.ExtendedRequest:
		write = request.Name == passwordModifyOID || request.Name == dynamicRefreshOID
	}
	if !write {
		return nil
	}
	result := ldapwire.ResultError(
		ldapwire.ResultUnwillingToPerform,
		"operation restricted",
	)
	return &result
}
