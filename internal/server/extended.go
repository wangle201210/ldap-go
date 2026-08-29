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
	cancelOID         = "1.3.6.1.1.8"
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
	if request.Name == pcacheQueryDeleteOID {
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
		return server.handlePcacheQueryDelete(
			ctx,
			connection,
			state,
			message,
			request,
		)
	}
	if request.Name != passwordModifyOID &&
		hasUnsupportedCriticalControl(message.Controls) {
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
		if frontendRestricts(state.runtime, restrictStartTLS) {
			return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
				message.ID,
				ldapwire.ApplicationExtendedResponse,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"operation restricted",
				),
				nil,
			))
		}
		return server.handleStartTLS(ctx, connection, state, message, request)
	case transactionStartOID:
		return server.handleTransactionStart(connection, state, message, request)
	case transactionEndOID:
		return server.handleTransactionEnd(ctx, connection, state, message, request)
	case passwordModifyOID:
		return server.handlePasswordModify(ctx, connection, state, message, request)
	case dynamicRefreshOID:
		return server.handleDynamicRefresh(ctx, connection, state, message, request)
	case whoAmIOID:
		return server.handleWhoAmI(connection, state, message, request)
	default:
		if frontendRestricts(state.runtime, restrictExtended) {
			return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
				message.ID,
				ldapwire.ApplicationExtendedResponse,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"operation restricted",
				),
				nil,
			))
		}
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"unsupported extended operation",
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
	if state.transaction != nil {
		return server.writeLDAPResultResponse(
			connection,
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultOperationsError,
				"cannot start TLS during a transaction",
			),
			"",
			nil,
			nil,
		)
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
	if state.saslSSF > 0 {
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultOperationsError,
				"cannot start TLS after a SASL security layer is installed",
			),
			nil,
		))
	}
	if !state.runtime.disallows.tlsToAnonymous && state.boundDN != "" {
		state.boundDN = ""
		state.authMechanism = ""
		clearBindCredentials(state)
		clearSASLSession(state)
		clearSearchSessions(state)
	}
	if state.runtime.disallows.tlsAuthenticated && state.boundDN != "" {
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			ldapwire.ResultError(
				ldapwire.ResultOperationsError,
				"cannot start TLS after authentication",
			),
			nil,
		))
	}
	if !server.secureTransportAvailable(state.runtime) {
		if referral, ok := globalReferralResult(
			state.runtime,
			nil,
			referralScopeDefault,
		); ok {
			return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
				message.ID,
				ldapwire.ApplicationExtendedResponse,
				referral,
				nil,
			))
		}
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

	clearSearchSessions(state)
	secured, err := server.secureHandshake(ctx, state.connection)
	if err != nil {
		return fmt.Errorf("complete StartTLS handshake: %w", err)
	}
	if secured == nil {
		return errors.New("secure transport returned a nil connection")
	}
	state.connection = secured
	state.secure = true
	state.tlsSSF = connectionSecurityStrength(secured, true)
	state.externalSSF = max(state.transportSSF, state.tlsSSF)
	if tlsIdentity := externalIdentityDN(secured); tlsIdentity != "" {
		state.externalDN = tlsIdentity
	}
	return nil
}

func (server *Server) handleCancel(
	ctx context.Context,
	connection net.Conn,
	operations *operationRegistry,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	var target *trackedOperation

	switch {
	case hasUnsupportedCriticalControl(message.Controls):
		result = ldapwire.ResultError(
			ldapwire.ResultUnavailableCriticalExtension,
			"unsupported critical control",
		)
	case frontendRestricts(server.runtime.Load(), restrictCancel):
		result = ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		)
	case !request.HasValue:
		result = ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"no message ID supplied",
		)
	case len(request.Value) == 0:
		result = ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"empty request data field",
		)
	default:
		targetID, err := ldapwire.DecodeCancelRequestValue(request.Value)
		if err != nil {
			result = ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"message ID parse failed",
			)
			break
		}
		if targetID == message.ID {
			result = ldapwire.ResultError(
				ldapwire.ResultCannotCancel,
				"Cancel operations cannot be canceled",
			)
			break
		}
		target, result = operations.cancel(targetID)
	}

	if result.Code == ldapwire.ResultSuccess && target != nil {
		select {
		case <-target.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
		message.ID,
		result,
		"",
		nil,
		nil,
	))
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
	var database *runtimeDatabase
	if state.boundDN != "" {
		boundDN, err := parseConnectionDN(state, state.boundDN)
		if err != nil {
			return fmt.Errorf("normalize bound DN: %w", err)
		}
		database = databaseForDN(state.runtime, boundDN)
	}
	if result := operationSecurityResult(state, database, policyRead); result != nil {
		return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			message.ID,
			*result,
			"",
			nil,
			nil,
		))
	}
	if database == nil && frontendRestricts(state.runtime, restrictWhoAmI) {
		return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"extended operation restricted",
			),
			"",
			nil,
			nil,
		))
	}
	if state.boundDN != "" {
		if database != nil && databaseRestricts(*database, restrictWhoAmI) {
			return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
				message.ID,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"extended operation restricted",
				),
				"",
				nil,
				nil,
			))
		}
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
