package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const metaBackendTransactionDiagnostic = "meta proxy backend does not support transactions"

func (server *Server) tryMetaBackendOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	targetDN, ok := metaRequestTargetDN(state, message.Request)
	if !ok {
		return false, nil
	}
	database := databaseForDN(state.runtime, targetDN)
	if database == nil || database.metaBackend == nil {
		return false, nil
	}
	if databaseRestricts(*database, requestDatabaseRestriction(message.Request)) {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "operation restricted"),
		)
	}
	if ldapBackendTransactionRequest(message) {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				metaBackendTransactionDiagnostic,
			),
		)
	}
	if request, search := message.Request.(ldapwire.SearchRequest); search {
		return server.tryMetaBackendSearch(
			ctx,
			connection,
			state,
			message,
			*database,
			request,
		)
	}

	_, add := message.Request.(ldapwire.AddRequest)
	target, selectionFailure := server.selectMetaBackendTarget(
		ctx,
		state,
		*database,
		targetDN,
		add,
	)
	if selectionFailure != nil {
		return true, writeResultForMessage(connection, message, *selectionFailure)
	}
	if request, rename := message.Request.(ldapwire.ModifyDNRequest); rename &&
		request.HasNewSuperior {
		newSuperior, parseErr := directory.ParseDN(request.NewSuperior)
		if parseErr != nil {
			return true, writeResultForMessage(
				connection,
				message,
				ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "invalid newSuperior DN"),
			)
		}
		destination, failure := server.selectMetaBackendTarget(
			ctx,
			state,
			*database,
			newSuperior,
			false,
		)
		if failure != nil {
			return true, writeResultForMessage(connection, message, *failure)
		}
		if destination.configDNKey != target.configDNKey {
			return true, writeResultForMessage(
				connection,
				message,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"Cross-target rename not supported",
				),
			)
		}
	}

	mapped, err := mapMetaRequestToRemote(target.rwm, message)
	if err != nil {
		return true, writeResultForMessage(
			connection,
			message,
			metaBackendMappingFailure(err),
		)
	}
	attempt, forwarded, failure := server.executeMetaBackendOperation(
		ctx,
		state,
		*database,
		*target,
		mapped,
	)
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	if attempt.hasResult && attempt.result.Code == ldapwire.ResultSuccess {
		// Password Modify identities are expressed in the local namespace.
		forwarded.Request = message.Request
		updateLDAPBackendSimpleCredentials(state, forwarded.Request)
		server.updateMetaRouteAfterOperation(
			*database,
			*target,
			targetDN,
			message.Request,
		)
	}
	return true, server.writeLDAPBackendAttempt(connection, message, attempt)
}

func (server *Server) tryMetaBackendBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
	requestDN directory.DN,
) (bool, error) {
	database := databaseForDN(state.runtime, requestDN)
	if database == nil || database.metaBackend == nil {
		return false, nil
	}
	if rootPassword, localRoot := databaseAuthenticationRoot(
		state.runtime,
		*database,
		requestDN,
	); localRoot {
		if database.metaBackend.pseudoRootBindDefer {
			return false, nil
		}
		return true, server.bindMetaBackendPseudoRoot(
			ctx,
			connection,
			state,
			message,
			request,
			*database,
			rootPassword,
		)
	}
	target, selectionFailure := server.selectMetaBackendTarget(
		ctx,
		state,
		*database,
		requestDN,
		false,
	)
	if selectionFailure != nil {
		result := *selectionFailure
		if result.Code == ldapwire.ResultNoSuchObject {
			result = ldapwire.ResultError(ldapwire.ResultInvalidCredentials, "")
		}
		return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			result,
			nil,
		))
	}
	mapped, err := mapMetaRequestToRemote(target.rwm, message)
	if err != nil {
		return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			metaBackendMappingFailure(err),
			nil,
		))
	}

	var attempt chainAttempt
	if !target.beginAttempt() {
		attempt.result = ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"back-meta target is quarantined",
		)
		attempt.hasResult = true
		return true, server.writeLDAPBackendAttempt(connection, message, attempt)
	}
	if metaBackendSingleConnection(*target) {
		state.metaTransports.close()
	}
	remoteOrder := metaBackendRemoteOrder(
		*target,
		len(target.ldapBackend.remotes),
	)
	replayed := false
	for position := 0; position < len(remoteOrder); {
		index := remoteOrder[position]
		configured := target.ldapBackend.remotes[index]
		remote := anonymousChainRemote(configured.clone())
		cacheIdentity := configured.clone()
		if bind, ok := mapped.Request.(ldapwire.BindRequest); ok {
			cacheIdentity.bind.bindMethod = "simple"
			cacheIdentity.bind.bindDN = bind.Name
			cacheIdentity.bind.credentials = append(
				[]byte(nil),
				bind.Authentication.Simple...,
			)
			cacheIdentity.bind.credentialsSet = true
		}
		attempt = server.executeMetaBackendTargetWithCacheIdentity(
			ctx,
			state,
			*target.ldapBackend,
			remote,
			cacheIdentity,
			mapped,
			metaBackendTransportOwner(*target),
		)
		if attempt.connected {
			rememberMetaBackendRemote(*target, index)
		}
		retry, replay := metaBackendShouldRetryRemote(ctx, attempt, true, &replayed)
		if !retry {
			break
		}
		if replay {
			remoteOrder = metaBackendRemoteOrder(*target, len(target.ldapBackend.remotes))
			position = 0
			continue
		}
		position++
	}
	if ctx.Err() == nil {
		target.finishAttempt(metaBackendAttemptCode(attempt))
	}
	if attempt.hasResult && attempt.result.Code == ldapwire.ResultSuccess {
		state.boundDN = request.Name
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = request.Name
		state.bindCredentials = append([]byte(nil), request.Authentication.Simple...)
		state.metaBindDatabaseKey = database.configDNKey
		state.metaBindTargetKey = target.configDNKey
		server.metaRoutes.store(database.metaBackend, requestDN, target.configDNKey)
	}
	return true, server.writeLDAPBackendAttempt(connection, message, attempt)
}

func (server *Server) bindMetaBackendPseudoRoot(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
	database runtimeDatabase,
	rootPassword []byte,
) error {
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	if !server.verifyStoredPassword(
		ctx,
		state.runtime,
		rootPassword,
		request.Authentication.Simple,
	) {
		result = ldapwire.ResultError(ldapwire.ResultInvalidCredentials, "")
	} else {
		result = server.bindMetaBackendPseudoRootTargets(ctx, state, database)
	}
	if result.Code == ldapwire.ResultSuccess {
		state.boundDN = request.Name
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = request.Name
		state.bindCredentials = append([]byte(nil), request.Authentication.Simple...)
		state.metaBindDatabaseKey = database.configDNKey
		state.metaBindTargetKey = ""
	}
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		result,
		nil,
	))
}

func (server *Server) bindMetaBackendPseudoRootTargets(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
) ldapwire.Result {
	for _, configured := range database.metaBackend.targets {
		target := configured.clone()
		if target.onlineURIUnavailable || target.ldapBackend == nil ||
			len(target.ldapBackend.remotes) == 0 {
			continue
		}
		remoteOrder := metaBackendRemoteOrder(target, len(target.ldapBackend.remotes))
		attempted := false
		var bindErr error
		if !target.beginAttempt() {
			return ldapwire.ResultError(
				ldapwire.ResultUnavailable,
				"back-meta target is quarantined",
			)
		}
		for _, remoteIndex := range remoteOrder {
			remote := target.ldapBackend.remotes[remoteIndex].clone()
			if remote.bind.bindMethod == "" {
				continue
			}
			attempted = true
			transport, err := server.openChainTransport(
				ctx,
				state,
				remote,
				ldapwire.BindRequest{},
			)
			if err == nil {
				_ = transport.close()
				rememberMetaBackendRemote(target, remoteIndex)
				bindErr = nil
				break
			}
			bindErr = err
			var ldapError *ldap.Error
			if errors.As(err, &ldapError) &&
				ldapError.ResultCode != uint16(ldapwire.ResultUnavailable) {
				break
			}
		}
		if !attempted {
			target.finishAttempt(ldapwire.ResultSuccess)
			continue
		}
		if bindErr != nil {
			result := metaBackendPseudoRootBindError(bindErr)
			target.finishAttempt(result.Code)
			return result
		}
		target.finishAttempt(ldapwire.ResultSuccess)
	}
	return ldapwire.Result{Code: ldapwire.ResultSuccess}
}

func metaBackendPseudoRootBindError(err error) ldapwire.Result {
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		return ldapwire.Result{
			Code:              ldapwire.ResultCode(ldapError.ResultCode),
			MatchedDN:         ldapError.MatchedDN,
			DiagnosticMessage: ldapError.Err.Error(),
		}
	}
	return ldapwire.ResultError(
		ldapwire.ResultUnavailable,
		ldapBackendUnavailableDiagnostic,
	)
}

func metaBackendSingleConnection(target metaBackendTargetRuntimeConfiguration) bool {
	if target.ldapBackend == nil {
		return false
	}
	for _, remote := range target.ldapBackend.remotes {
		if remote.singleConnection {
			return true
		}
	}
	return false
}

func (server *Server) executeMetaBackendOperation(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	target metaBackendTargetRuntimeConfiguration,
	message ldapwire.Message,
) (chainAttempt, ldapwire.Message, *ldapwire.Result) {
	return server.executeMetaBackendOperationWithSink(
		ctx,
		state,
		database,
		target,
		message,
		nil,
	)
}

func (server *Server) executeMetaBackendOperationWithSink(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	target metaBackendTargetRuntimeConfiguration,
	message ldapwire.Message,
	packetSink func(*ber.Packet) error,
) (chainAttempt, ldapwire.Message, *ldapwire.Result) {
	return server.executeMetaBackendOperationWithHooks(
		ctx,
		state,
		database,
		target,
		message,
		packetSink,
		nil,
	)
}

func (server *Server) executeMetaBackendOperationWithHooks(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	target metaBackendTargetRuntimeConfiguration,
	message ldapwire.Message,
	packetSink func(*ber.Packet) error,
	requestStarted func() error,
) (chainAttempt, ldapwire.Message, *ldapwire.Result) {
	proxy := database
	proxy.metaBackend = nil
	proxy.ldapBackend = target.ldapBackend
	proxy.rwm = target.rwm
	proxy.metaTargetKey = target.configDNKey

	var (
		attempt   chainAttempt
		forwarded ldapwire.Message
	)
	if !target.beginAttempt() {
		return chainAttempt{
			result: ldapwire.ResultError(
				ldapwire.ResultUnavailable,
				"back-meta target is quarantined",
			),
			hasResult: true,
		}, message, nil
	}
	remoteOrder := metaBackendRemoteOrder(
		target,
		len(target.ldapBackend.remotes),
	)
	replayed := false
	for position := 0; position < len(remoteOrder); {
		index := remoteOrder[position]
		configured := target.ldapBackend.remotes[index]
		remote, candidate, failure := server.ldapBackendRemote(
			ctx,
			state,
			proxy,
			configured,
			message,
		)
		if failure != nil {
			return chainAttempt{}, candidate, failure
		}
		remote, candidate, failure = mapMetaRemoteIdentity(target.rwm, remote, candidate)
		if failure != nil {
			return chainAttempt{}, candidate, failure
		}
		forwarded = candidate
		attempt = server.executeMetaBackendTargetWithHooks(
			ctx,
			state,
			*target.ldapBackend,
			remote,
			remote,
			forwarded,
			metaBackendTransportOwner(target),
			packetSink,
			requestStarted,
		)
		if attempt.connected {
			rememberMetaBackendRemote(target, index)
		}
		retry, replay := metaBackendShouldRetryRemote(ctx, attempt, false, &replayed)
		if !retry {
			break
		}
		if replay {
			remoteOrder = metaBackendRemoteOrder(target, len(target.ldapBackend.remotes))
			position = 0
			continue
		}
		position++
	}
	if ctx.Err() == nil {
		target.finishAttempt(metaBackendAttemptCode(attempt))
	}
	return attempt, forwarded, nil
}

func metaBackendAttemptCode(attempt chainAttempt) ldapwire.ResultCode {
	if attempt.hasResult {
		return attempt.result.Code
	}
	if attempt.transportErr != nil {
		return ldapwire.ResultUnavailable
	}
	return ldapwire.ResultOther
}

func metaBackendShouldRetryRemote(
	ctx context.Context,
	attempt chainAttempt,
	bind bool,
	replayed *bool,
) (bool, bool) {
	if ctx.Err() != nil {
		return false, false
	}
	if errors.Is(attempt.transportErr, errMetaSearchStartupStopped) {
		return false, false
	}
	if attempt.hasResult {
		if attempt.responses > 1 {
			return false, false
		}
		if attempt.result.Code != ldapwire.ResultUnavailable || bind || *replayed {
			return false, false
		}
		*replayed = true
		return true, true
	}
	if attempt.responses != 0 || len(attempt.packets) != 0 {
		return false, false
	}
	if attempt.transportErr == nil {
		return false, false
	}
	if !attempt.requestSent {
		return true, false
	}
	if bind || *replayed {
		return false, false
	}
	*replayed = true
	return true, true
}

func metaBackendRemoteOrder(target metaBackendTargetRuntimeConfiguration, count int) []int {
	return preferredProxyRemoteOrder(target.preferred, count)
}

func rememberMetaBackendRemote(target metaBackendTargetRuntimeConfiguration, index int) {
	rememberPreferredProxyRemote(target.preferred, index)
}

func mapMetaRemoteIdentity(
	mapping *rwmRuntimeConfiguration,
	remote chainRemoteConfiguration,
	message ldapwire.Message,
) (chainRemoteConfiguration, ldapwire.Message, *ldapwire.Result) {
	if remote.bind.bindDN != "" {
		mapped, err := mapMetaDNString(mapping, remote.bind.bindDN, true)
		if err != nil {
			result := metaBackendMappingFailure(err)
			return remote, message, &result
		}
		remote.bind.bindDN = mapped
	}
	authorizationID := remote.bind.authorizationID
	if len(authorizationID) > 3 &&
		strings.EqualFold(authorizationID[:3], "dn:") {
		mapped, err := mapMetaDNString(mapping, authorizationID[3:], true)
		if err != nil {
			result := metaBackendMappingFailure(err)
			return remote, message, &result
		}
		remote.bind.authorizationID = "dn:" + mapped
	}
	for index := range message.Controls {
		control := &message.Controls[index]
		if control.OID != proxyAuthorizationControlOID || !control.HasValue {
			continue
		}
		value := string(control.Value)
		if len(value) < 3 || !strings.EqualFold(value[:3], "dn:") || len(value) == 3 {
			continue
		}
		mapped, err := mapMetaDNString(mapping, value[3:], true)
		if err != nil {
			result := metaBackendMappingFailure(err)
			return remote, message, &result
		}
		control.Value = []byte("dn:" + mapped)
	}
	return remote, message, nil
}

func metaModifyDNUsesTarget(
	configuration *metaBackendRuntimeConfiguration,
	target metaBackendTargetRuntimeConfiguration,
	request ldapwire.ModifyDNRequest,
) bool {
	dn, err := configuration.parseDN(request.DN)
	if err != nil {
		return false
	}
	parent, ok := dn.Parent()
	if !ok {
		return false
	}
	if request.HasNewSuperior {
		parent, err = configuration.parseDN(request.NewSuperior)
		if err != nil {
			return false
		}
	}
	destinationName := request.NewRDN
	if parent.Depth() != 0 {
		destinationName += "," + parent.String()
	}
	destination, err := configuration.parseDN(destinationName)
	if err != nil {
		return false
	}
	destinationTarget, found := configuration.targetForDN(destination)
	return found && destinationTarget.configDNKey == target.configDNKey
}

func metaBackendMappingFailure(err error) ldapwire.Result {
	return ldapwire.ResultError(
		ldapwire.ResultOther,
		fmt.Sprintf("back-meta mapping failed: %v", err),
	)
}
