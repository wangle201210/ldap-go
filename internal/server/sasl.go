package server

import (
	"bytes"
	"context"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/stringprep"
)

func (server *Server) handleSASLBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	mechanism := strings.ToUpper(request.Authentication.SASLMechanism)
	if failure := saslMechanismPolicyFailure(
		state.runtime.sasl.securityProperties,
		mechanism,
		state.externalSSF,
	); failure != nil {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			*failure,
			nil,
		))
	}

	switch mechanism {
	case "EXTERNAL":
		return server.handleSASLExternalBind(
			connection,
			state,
			message,
			request,
		)
	case "PLAIN":
		return server.handleSASLPlainBind(
			ctx,
			connection,
			state,
			message,
			request,
		)
	default:
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultAuthMethodNotSupported,
				"requested SASL mechanism is not supported",
			),
			nil,
		))
	}
}

func (server *Server) handleSASLExternalBind(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
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

func (server *Server) handleSASLPlainBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	authorizationID, authenticationID, password, valid :=
		parseSASLPlainCredentials(
			request.Authentication.SASLCredentials,
		)
	if !valid {
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	preparedAuthenticationID, err := stringprep.SASLprep.Prepare(
		authenticationID,
	)
	if err != nil || preparedAuthenticationID == "" {
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	preparedPassword, err := stringprep.SASLprep.Prepare(password)
	if err != nil {
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	authenticationDN, err := server.saslAuthenticationDN(
		ctx,
		state.runtime,
		"PLAIN",
		preparedAuthenticationID,
	)
	if err != nil {
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	authenticated, err := server.authenticate(
		ctx,
		state.runtime,
		authenticationDN.String(),
		[]byte(preparedPassword),
	)
	if err != nil {
		return err
	}
	if !authenticated {
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	authorizationDN, err := server.resolveSASLAuthorizationDN(
		ctx,
		state.runtime,
		"PLAIN",
		preparedAuthenticationID,
		authenticationDN,
		authorizationID,
	)
	if err != nil {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultInappropriateAuthentication,
				"",
			),
			nil,
		))
	}
	state.boundDN = authorizationDN.String()
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	))
}

func parseSASLPlainCredentials(
	credentials []byte,
) (string, string, string, bool) {
	parts := bytes.Split(credentials, []byte{0})
	if len(parts) != 3 ||
		!utf8.Valid(parts[0]) ||
		!utf8.Valid(parts[1]) ||
		!utf8.Valid(parts[2]) {
		return "", "", "", false
	}
	return string(parts[0]), string(parts[1]), string(parts[2]), true
}

func writeSASLInvalidCredentials(
	connection net.Conn,
	messageID int64,
) error {
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		messageID,
		ldapwire.ResultError(ldapwire.ResultInvalidCredentials, ""),
		nil,
	))
}

type saslMechanismSecurity struct {
	noDictionary    bool
	noPlain         bool
	noActive        bool
	passCredentials bool
	forwardSecrecy  bool
	noAnonymous     bool
}

func saslMechanismPolicyFailure(
	properties saslSecurityProperties,
	mechanism string,
	externalSSF uint32,
) *ldapwire.Result {
	var security saslMechanismSecurity
	switch mechanism {
	case "EXTERNAL":
		security = saslMechanismSecurity{
			noDictionary: true,
			noPlain:      true,
			noAnonymous:  true,
		}
	case "PLAIN":
		security = saslMechanismSecurity{
			passCredentials: true,
			noAnonymous:     true,
		}
	default:
		result := ldapwire.ResultError(
			ldapwire.ResultAuthMethodNotSupported,
			"requested SASL mechanism is not supported",
		)
		return &result
	}

	if properties.minSSF > externalSSF {
		result := ldapwire.ResultError(
			ldapwire.ResultStrongerAuthRequired,
			"SASL security strength requirement is not met",
		)
		return &result
	}
	if properties.noPlain &&
		!security.noPlain &&
		!(externalSSF > 1 && properties.minSSF <= externalSSF) {
		result := ldapwire.ResultError(
			ldapwire.ResultConfidentialityRequired,
			"SASL mechanism requires a protected transport",
		)
		return &result
	}
	if (properties.noDictionary && !security.noDictionary) ||
		(properties.noActive && !security.noActive) ||
		(properties.passCredentials && !security.passCredentials) ||
		(properties.forwardSecrecy && !security.forwardSecrecy) ||
		(properties.noAnonymous && !security.noAnonymous) {
		result := ldapwire.ResultError(
			ldapwire.ResultAuthMethodNotSupported,
			"requested SASL mechanism does not meet security properties",
		)
		return &result
	}
	return nil
}

func supportedSASLMechanisms(state *connectionState) []string {
	var mechanisms []string
	properties := state.runtime.sasl.securityProperties
	if state.externalDN != "" &&
		saslMechanismPolicyFailure(
			properties,
			"EXTERNAL",
			state.externalSSF,
		) == nil {
		mechanisms = append(mechanisms, "EXTERNAL")
	}
	if saslMechanismPolicyFailure(
		properties,
		"PLAIN",
		state.externalSSF,
	) == nil {
		mechanisms = append(mechanisms, "PLAIN")
	}
	return mechanisms
}
