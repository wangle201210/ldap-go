package server

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const startTLSOID = "1.3.6.1.4.1.1466.20037"

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
	if request.Name != startTLSOID {
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
	secured, err := server.secureHandshake(ctx, connection)
	if err != nil {
		return fmt.Errorf("complete StartTLS handshake: %w", err)
	}
	if secured == nil {
		return errors.New("secure transport returned a nil connection")
	}
	state.connection = secured
	state.secure = true
	return nil
}
