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
	session := state.saslSession
	if session != nil && session.mechanism != mechanism {
		clearSASLSession(state)
		session = nil
	}
	runtime := state.runtime
	if session != nil {
		runtime = session.runtime
	}
	if failure := saslMechanismPolicyFailure(
		runtime.sasl.securityProperties,
		mechanism,
		state.externalSSF,
	); failure != nil {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			*failure,
			nil,
		))
	}

	switch mechanism {
	case "EXTERNAL":
		clearSASLSession(state)
		return server.handleSASLExternalBind(
			connection,
			state,
			message,
			request,
		)
	case "PLAIN":
		if !request.Authentication.HasSASLCredentials {
			if session != nil {
				clearSASLSession(state)
				return writeSASLInvalidCredentials(
					connection,
					message.ID,
				)
			}
			state.saslSession = &serverSASLSession{
				mechanism: mechanism,
				runtime:   runtime,
			}
			return writeSASLChallenge(connection, message.ID, nil)
		}
		clearSASLSession(state)
		return server.handleSASLPlainBind(
			ctx,
			connection,
			state,
			runtime,
			message,
			request,
		)
	case "CRAM-MD5":
		if session == nil {
			if len(request.Authentication.SASLCredentials) != 0 {
				return writeSASLInvalidCredentials(
					connection,
					message.ID,
				)
			}
			var err error
			session, err = startSASLCRAMMD5Session(runtime)
			if err != nil {
				return err
			}
			state.saslSession = session
			return writeSASLChallenge(
				connection,
				message.ID,
				session.cramMD5Challenge,
			)
		}
		if !request.Authentication.HasSASLCredentials {
			clearSASLSession(state)
			return writeSASLInvalidCredentials(connection, message.ID)
		}
		return server.handleSASLCRAMMD5Step(
			ctx,
			connection,
			state,
			session,
			message,
			request,
		)
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512":
		if session == nil {
			session = &serverSASLSession{
				mechanism: mechanism,
				runtime:   runtime,
			}
			state.saslSession = session
			if !request.Authentication.HasSASLCredentials {
				return writeSASLChallenge(connection, message.ID, nil)
			}
		} else if !request.Authentication.HasSASLCredentials {
			clearSASLSession(state)
			return writeSASLInvalidCredentials(connection, message.ID)
		}
		return server.handleSASLSCRAMStep(
			ctx,
			connection,
			state,
			session,
			message,
			request,
		)
	default:
		clearSASLSession(state)
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
	runtime *runtimeState,
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
		runtime,
		"PLAIN",
		preparedAuthenticationID,
	)
	if err != nil {
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	authenticated, err := server.authenticate(
		ctx,
		runtime,
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
		runtime,
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

func writeSASLChallenge(
	connection net.Conn,
	messageID int64,
	challenge []byte,
) error {
	return ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
		challenge,
		true,
		nil,
	))
}

func clearSASLSession(state *connectionState) {
	state.saslSession = nil
}

func (server *Server) rejectOperationDuringSASLBind(
	connection net.Conn,
	message ldapwire.Message,
) error {
	result := ldapwire.ResultError(
		ldapwire.ResultOperationsError,
		"SASL bind in progress",
	)
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
	case "CRAM-MD5":
		security = saslMechanismSecurity{
			noPlain:     true,
			noAnonymous: true,
		}
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512":
		security = saslMechanismSecurity{
			noPlain:     true,
			noActive:    true,
			noAnonymous: true,
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
	if saslMechanismPolicyFailure(
		properties,
		"CRAM-MD5",
		state.externalSSF,
	) == nil {
		mechanisms = append(mechanisms, "CRAM-MD5")
	}
	for _, mechanism := range []string{
		"SCRAM-SHA-512",
		"SCRAM-SHA-256",
		"SCRAM-SHA-1",
	} {
		if saslMechanismPolicyFailure(
			properties,
			mechanism,
			state.externalSSF,
		) == nil {
			mechanisms = append(mechanisms, mechanism)
		}
	}
	return mechanisms
}
