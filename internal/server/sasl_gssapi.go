package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

const (
	serverGSSAPIStageContextEstablished = 1
	serverGSSAPIStageSecurityOffered    = 2
)

func (server *Server) handleSASLGSSAPIStep(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	runtime *runtimeState,
	session *serverSASLSession,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	if session == nil {
		if !request.Authentication.HasSASLCredentials ||
			len(request.Authentication.SASLCredentials) == 0 {
			state.saslSession = &serverSASLSession{
				mechanism: "GSSAPI",
				runtime:   runtime,
			}
			return writeSASLChallenge(connection, message.ID, nil)
		}
		return server.startSASLGSSAPI(
			ctx,
			connection,
			state,
			runtime,
			message,
			request.Authentication.SASLCredentials,
		)
	}
	if session.gssapiSession == nil {
		if !request.Authentication.HasSASLCredentials ||
			len(request.Authentication.SASLCredentials) == 0 {
			clearSASLSession(state)
			return writeSASLInvalidCredentials(connection, message.ID)
		}
		return server.startSASLGSSAPI(
			ctx,
			connection,
			state,
			session.runtime,
			message,
			request.Authentication.SASLCredentials,
		)
	}

	gssapiSession := session.gssapiSession
	switch gssapiSession.stage {
	case serverGSSAPIStageContextEstablished:
		if request.Authentication.HasSASLCredentials &&
			len(request.Authentication.SASLCredentials) != 0 {
			clearSASLSession(state)
			return writeSASLInvalidCredentials(connection, message.ID)
		}
		return server.offerSASLGSSAPISecurity(
			connection,
			state,
			message.ID,
			gssapiSession,
		)
	case serverGSSAPIStageSecurityOffered:
		if !request.Authentication.HasSASLCredentials ||
			len(request.Authentication.SASLCredentials) == 0 {
			clearSASLSession(state)
			return writeSASLInvalidCredentials(connection, message.ID)
		}
		return server.finishSASLGSSAPI(
			ctx,
			connection,
			state,
			message.ID,
			session,
			request.Authentication.SASLCredentials,
		)
	default:
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
}

func (server *Server) startSASLGSSAPI(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	runtime *runtimeState,
	message ldapwire.Message,
	encoded []byte,
) error {
	servicePrincipal := "ldap/" + runtime.sasl.host
	var channelBinding []byte
	if server.config.GSSAPIChannelBinding == saslkrb5.ChannelBindingTLSServerEndpoint {
		channelBinding = connectionTLSChannelBinding(state.connection)
		if len(channelBinding) == 0 {
			server.config.Logger.Debug(
				"SASL GSSAPI AP-REQ rejected",
				"error", "tls-server-end-point channel binding requires TLS",
			)
			clearSASLSession(state)
			return writeSASLInvalidCredentials(connection, message.ID)
		}
	}
	defer clear(channelBinding)
	accepted, err := saslkrb5.AcceptAPReq(
		encoded,
		server.gssapiKeytab,
		servicePrincipal,
		channelBinding,
	)
	if err != nil {
		server.config.Logger.Debug("SASL GSSAPI AP-REQ rejected", "error", err)
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	authenticationDN, err := server.saslUserDN(
		ctx,
		runtime,
		"GSSAPI",
		accepted.User,
		accepted.Realm,
	)
	if err != nil {
		clear(accepted.Key.KeyValue)
		clear(accepted.APRep)
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	state.saslSession = &serverSASLSession{
		mechanism: "GSSAPI",
		runtime:   runtime,
		gssapiSession: &serverGSSAPISession{
			stage:            serverGSSAPIStageContextEstablished,
			context:          accepted,
			authenticationDN: authenticationDN,
		},
	}
	return writeSASLChallenge(connection, message.ID, accepted.APRep)
}

func (server *Server) offerSASLGSSAPISecurity(
	connection net.Conn,
	state *connectionState,
	messageID int64,
	session *serverGSSAPISession,
) error {
	properties := state.saslSession.runtime.sasl.securityProperties
	layers := byte(0)
	if properties.minSSF <= state.externalSSF {
		layers |= saslkrb5.SecurityNone
	}
	if properties.maxBufferSize != 0 &&
		properties.minSSF <= state.externalSSF+1 &&
		properties.maxSSF >= state.externalSSF+1 {
		layers |= saslkrb5.SecurityIntegrity
	}
	keySSF, err := saslkrb5.SecurityStrength(session.context.Key)
	if err != nil {
		clearSASLSession(state)
		return fmt.Errorf("determine SASL GSSAPI context strength: %w", err)
	}
	if properties.maxBufferSize != 0 &&
		properties.minSSF <= state.externalSSF+keySSF &&
		properties.maxSSF >= state.externalSSF+keySSF {
		layers |= saslkrb5.SecurityConfidentiality
	}
	if layers == 0 {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			messageID,
			ldapwire.ResultError(
				ldapwire.ResultStrongerAuthRequired,
				"SASL GSSAPI security strength requirement is not met",
			),
			nil,
		))
	}
	maximum := uint32(0)
	if layers&(saslkrb5.SecurityIntegrity|saslkrb5.SecurityConfidentiality) != 0 {
		maximum = properties.maxBufferSize
	}
	payload := []byte{layers, byte(maximum >> 16), byte(maximum >> 8), byte(maximum)}
	wrapped, err := saslkrb5.Wrap(
		payload,
		session.context.Key,
		true,
		session.context.AcceptorSubkey,
		session.context.SendSequence,
	)
	clear(payload)
	if err != nil {
		clearSASLSession(state)
		return fmt.Errorf("encode SASL GSSAPI security offer: %w", err)
	}
	session.context.SendSequence++
	session.stage = serverGSSAPIStageSecurityOffered
	session.offeredLayers = layers
	session.maximumBuffer = maximum
	err = writeSASLChallenge(connection, messageID, wrapped)
	clear(wrapped)
	return err
}

func (server *Server) finishSASLGSSAPI(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	saslSession *serverSASLSession,
	encoded []byte,
) error {
	session := saslSession.gssapiSession
	payload, err := saslkrb5.Unwrap(
		encoded,
		session.context.Key,
		false,
		session.context.AcceptorSubkey,
		session.context.ReceiveSequence,
	)
	if err != nil {
		server.config.Logger.Debug("SASL GSSAPI security selection rejected", "error", err)
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, messageID)
	}
	session.context.ReceiveSequence++
	selection, maximum, authorizationID, err := saslkrb5.DecodeNegotiation(payload)
	clear(payload)
	if err != nil || selection&session.offeredLayers == 0 ||
		(selection != saslkrb5.SecurityNone && maximum == 0) ||
		strings.IndexByte(authorizationID, 0) >= 0 || !utf8.ValidString(authorizationID) {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, messageID)
	}
	authorizationDN, err := server.resolveSASLAuthorizationDN(
		ctx,
		saslSession.runtime,
		"GSSAPI",
		session.context.Principal,
		session.authenticationDN,
		authorizationID,
	)
	if err != nil {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			messageID,
			ldapwire.ResultError(ldapwire.ResultInappropriateAuthentication, ""),
			nil,
		))
	}
	key := session.context.Key
	key.KeyValue = append([]byte(nil), key.KeyValue...)
	securityState := saslkrb5.SecurityState{
		SendSequence:    session.context.SendSequence,
		ReceiveSequence: session.context.ReceiveSequence,
		AcceptorSubkey:  session.context.AcceptorSubkey,
	}
	peerMaximum := maximum
	localMaximum := session.maximumBuffer
	state.boundDN = authorizationDN.String()
	state.authMechanism = "GSSAPI"
	clearSASLSession(state)
	if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		clear(key.KeyValue)
		return err
	}
	if selection == saslkrb5.SecurityNone {
		clear(key.KeyValue)
		return nil
	}
	if selection != saslkrb5.SecurityIntegrity &&
		selection != saslkrb5.SecurityConfidentiality {
		clear(key.KeyValue)
		return errors.New("unsupported GSSAPI security layer selected")
	}
	var layer net.Conn
	securitySSF := uint32(1)
	if selection == saslkrb5.SecurityConfidentiality {
		securitySSF, err = saslkrb5.SecurityStrength(key)
		if err != nil {
			clear(key.KeyValue)
			return fmt.Errorf("determine SASL GSSAPI security strength: %w", err)
		}
	}
	if selection == saslkrb5.SecurityConfidentiality {
		layer, err = saslkrb5.NewConfidentialityConnection(
			state.connection,
			key,
			true,
			securityState,
			peerMaximum,
			localMaximum,
		)
	} else {
		layer, err = saslkrb5.NewIntegrityConnection(
			state.connection,
			key,
			true,
			securityState,
			peerMaximum,
			localMaximum,
		)
	}
	clear(key.KeyValue)
	if err != nil {
		return fmt.Errorf("install SASL GSSAPI security layer: %w", err)
	}
	state.connection = layer
	state.saslSSF = securitySSF
	return nil
}
