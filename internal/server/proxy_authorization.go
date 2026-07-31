package server

import (
	"context"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const proxyAuthorizationControlOID = "2.16.840.1.113730.3.4.18"

func (server *Server) applyProxyAuthorization(
	ctx context.Context,
	state *connectionState,
	message ldapwire.Message,
) (ldapwire.Message, string, bool, *ldapwire.Result) {
	if !supportsProxyAuthorization(message.Request) {
		return message, "", false, nil
	}

	controlIndex := -1
	var control ldapwire.Control
	for index, candidate := range message.Controls {
		if candidate.OID != proxyAuthorizationControlOID {
			continue
		}
		if controlIndex >= 0 {
			result := ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"proxy authorization control specified multiple times",
			)
			return message, "", false, &result
		}
		controlIndex = index
		control = candidate
		if !control.HasValue {
			result := ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"proxy authorization control value absent",
			)
			return message, "", false, &result
		}
		if state.runtime.disallows.noncriticalProxyAuthorization &&
			!control.Critical {
			result := ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"proxied authorization criticality of FALSE not allowed",
			)
			return message, "", false, &result
		}
	}
	if controlIndex < 0 {
		return message, "", false, nil
	}
	if state.boundDN == "" && !state.runtime.allows.anonymousProxyAuthz {
		result := ldapwire.ResultError(
			ldapwire.ResultProxiedAuthorizationDenied,
			"anonymous proxied authorization not allowed",
		)
		return message, "", false, &result
	}

	authenticationDN, err := directory.ParseDN(state.boundDN)
	if err != nil {
		result := ldapwire.ResultError(
			ldapwire.ResultProxiedAuthorizationDenied,
			"not authorized to assume identity",
		)
		return message, "", false, &result
	}
	authorizationDN, err := server.proxiedAuthorizationDN(
		ctx,
		state.runtime,
		state.authMechanism,
		state.boundDN,
		control.Value,
	)
	if err != nil {
		result := ldapwire.ResultError(
			ldapwire.ResultProxiedAuthorizationDenied,
			"authzId mapping failed",
		)
		return message, "", false, &result
	}
	authorized, err := server.saslAuthorized(
		ctx,
		state.runtime,
		authenticationDN,
		authorizationDN,
	)
	if err != nil || !authorized {
		result := ldapwire.ResultError(
			ldapwire.ResultProxiedAuthorizationDenied,
			"not authorized to assume identity",
		)
		return message, "", false, &result
	}

	message.Controls = withoutControl(message.Controls, controlIndex)
	return message, authorizationDN.String(), true, nil
}

func (server *Server) proxiedAuthorizationDN(
	ctx context.Context,
	runtime *runtimeState,
	mechanism string,
	authenticationDN string,
	value []byte,
) (directory.DN, error) {
	if !utf8.Valid(value) {
		return directory.DN{}, errSASLAuthorizationDenied
	}
	authorizationID := string(value)
	if authorizationID == "" ||
		strings.EqualFold(authorizationID, "anonymous") {
		return directory.ParseDN("")
	}
	switch {
	case strings.HasPrefix(strings.ToLower(authorizationID), "dn:"):
		return directory.ParseDN(authorizationID[3:])
	case strings.HasPrefix(strings.ToLower(authorizationID), "u:"):
		if mechanism == "" {
			mechanism = "AUTHZ"
		}
		return server.saslUserDNAs(
			ctx,
			runtime,
			mechanism,
			authorizationID[2:],
			"",
			authenticationDN,
		)
	default:
		return directory.DN{}, errSASLAuthorizationDenied
	}
}

func supportsProxyAuthorization(request ldapwire.Request) bool {
	switch request := request.(type) {
	case ldapwire.SearchRequest,
		ldapwire.CompareRequest,
		ldapwire.AddRequest,
		ldapwire.ModifyRequest,
		ldapwire.DeleteRequest,
		ldapwire.ModifyDNRequest:
		return true
	case ldapwire.ExtendedRequest:
		switch request.Name {
		case passwordModifyOID, whoAmIOID, dynamicRefreshOID:
			return true
		}
	}
	return false
}

func writeResultForMessage(
	connection net.Conn,
	message ldapwire.Message,
	result ldapwire.Result,
) error {
	switch message.Request.(type) {
	case ldapwire.SearchRequest:
		return ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
			message.ID,
			result,
			nil,
		))
	case ldapwire.ExtendedRequest:
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationExtendedResponse,
			result,
			nil,
		))
	default:
		responseTag, responds := responseTagFor(
			message.Request.ApplicationTag(),
		)
		if !responds {
			return nil
		}
		return ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			responseTag,
			result,
			nil,
		))
	}
}
