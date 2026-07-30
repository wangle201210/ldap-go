package server

import (
	"net"
	"strings"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func (server *Server) handleSASLBind(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	if !strings.EqualFold(request.Authentication.SASLMechanism, "EXTERNAL") {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultAuthMethodNotSupported,
				"requested SASL mechanism is not supported",
			),
			nil,
		))
	}
	if len(request.Authentication.SASLCredentials) != 0 {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"proxy authorization is not supported",
			),
			nil,
		))
	}
	if state.externalDN == "" {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInvalidCredentials, ""),
			nil,
		))
	}

	state.boundDN = state.externalDN
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	))
}
