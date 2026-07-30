package server

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	startTLSOID       = "1.3.6.1.4.1.1466.20037"
	passwordModifyOID = "1.3.6.1.4.1.4203.1.11.1"
	whoAmIOID         = "1.3.6.1.4.1.4203.1.11.3"
)

func (server *Server) handleExtended(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	if hasUnsupportedCriticalControl(message.Controls) {
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"unsupported critical control",
			),
			nil,
		))
	}
	switch request.Name {
	case startTLSOID:
		return server.handleStartTLS(ctx, connection, state, message, request)
	case passwordModifyOID:
		return server.handlePasswordModify(ctx, connection, state, message, request)
	case whoAmIOID:
		return server.handleWhoAmI(connection, state, message, request)
	default:
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"extended operation is not implemented",
			),
			nil,
		))
	}
}

func (server *Server) handleStartTLS(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	if request.HasValue {
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"no request data expected",
			),
			nil,
		))
	}
	if state.secure {
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultOperationsError,
				"TLS already started",
			),
			nil,
		))
	}
	if server.secureTransport == nil {
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnavailable,
				"TLS is not configured",
			),
			nil,
		))
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeResultResponse(
		message.ID,
		ldapwire.ApplicationExtendedResponse,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		return err
	}

	state.boundDN = ""
	clearSearchSessions(state)
	secured, err := server.secureHandshake(ctx, connection)
	if err != nil {
		return fmt.Errorf("complete StartTLS handshake: %w", err)
	}
	if secured == nil {
		return errors.New("secure transport returned a nil connection")
	}
	state.connection = secured
	state.secure = true
	state.externalDN = externalIdentityDN(secured)
	return nil
}

func (server *Server) handleWhoAmI(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	if request.HasValue {
		return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"no request data expected",
			),
			"",
			nil,
			nil,
		))
	}

	authzID := []byte{}
	if state.boundDN != "" {
		dn, err := directory.ParseDN(state.boundDN)
		if err != nil {
			return fmt.Errorf("normalize bound DN: %w", err)
		}
		authzID = []byte("dn:" + dn.String())
	}
	return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		"",
		authzID,
		nil,
	))
}
