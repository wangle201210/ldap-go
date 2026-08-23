package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"unicode"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	ldapBackendUnavailableDiagnostic = "Proxy operation retry failed"
	ldapBackendTransactionDiagnostic = "ldap proxy backend does not support transactions"
)

type ldapBackendRuntimeConfiguration struct {
	remotes   []chainRemoteConfiguration
	preferred *proxyPreferredRemoteState
}

type proxyPreferredRemoteState struct {
	mu    sync.RWMutex
	index int
}

func loadLDAPBackendRuntimeConfiguration(
	entry directory.Entry,
) (*ldapBackendRuntimeConfiguration, error) {
	if len(entry.Values("olcAccess")) != 0 {
		return nil, fmt.Errorf(
			"%s olcAccess is not supported by the ldap backend; database-local ACLs would be bypassed",
			entry.DN,
		)
	}
	values := entry.Values("olcDbURI")
	if len(values) == 0 {
		return nil, fmt.Errorf("%s ldap backend requires olcDbURI", entry.DN)
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("%s olcDbURI must be single-valued", entry.DN)
	}
	uriValues := strings.FieldsFunc(string(values[0]), func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
	if len(uriValues) == 0 {
		return nil, fmt.Errorf("%s olcDbURI contains no LDAP URLs", entry.DN)
	}

	common := defaultChainRemoteConfiguration()
	if err := loadChainRemoteConfiguration(entry.Without("olcDbURI"), &common); err != nil {
		return nil, err
	}
	configuration := &ldapBackendRuntimeConfiguration{
		remotes:   make([]chainRemoteConfiguration, 0, len(uriValues)),
		preferred: &proxyPreferredRemoteState{},
	}
	for _, value := range uriValues {
		uri, endpointKey, err := parseChainConfiguredURI(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcDbURI: %w", entry.DN, err)
		}
		remote := common.clone()
		remote.uri = uri
		remote.endpointKey = endpointKey
		configuration.remotes = append(configuration.remotes, remote)
	}
	return configuration, nil
}

func (server *Server) tryLDAPBackendOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	database := ldapBackendDatabaseForMessage(state, message)
	if database == nil {
		return false, nil
	}
	if databaseRestricts(*database, requestDatabaseRestriction(message.Request)) {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
		)
	}
	if ldapBackendTransactionRequest(message) {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				ldapBackendTransactionDiagnostic,
			),
		)
	}
	if _, search := message.Request.(ldapwire.SearchRequest); search &&
		database.pcache != nil && !database.pcache.disabled {
		if handled, err := server.tryPcacheSearch(
			ctx,
			connection,
			state,
			message,
			*database,
		); handled {
			return true, err
		}
	}

	attempt, forwarded, failure := server.executeLDAPBackendOperation(
		ctx,
		state,
		*database,
		message,
	)
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	if attempt.hasResult && attempt.result.Code == ldapwire.ResultSuccess {
		updateLDAPBackendSimpleCredentials(state, forwarded.Request)
	}
	return true, server.writeLDAPBackendAttempt(connection, message, attempt)
}

func (server *Server) tryLDAPBackendBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
	requestDN directory.DN,
) (bool, error) {
	database := databaseForDN(state.runtime, requestDN)
	if database == nil || database.ldapBackend == nil {
		return false, nil
	}
	if _, localRoot := databaseAuthenticationRoot(
		state.runtime,
		*database,
		requestDN,
	); localRoot {
		return false, nil
	}

	// A client Bind is the bind for the remote connection. Do not perform an
	// administrative identity-assertion bind before forwarding it.
	attempt := server.executeLDAPBackendBind(
		ctx,
		state,
		database.ldapBackend,
		message,
	)
	if attempt.hasResult && attempt.result.Code == ldapwire.ResultSuccess {
		state.boundDN = request.Name
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = request.Name
		state.bindCredentials = append([]byte(nil), request.Authentication.Simple...)
	}
	return true, server.writeLDAPBackendAttempt(connection, message, attempt)
}

func (server *Server) executeLDAPBackendBind(
	ctx context.Context,
	state *connectionState,
	configuration *ldapBackendRuntimeConfiguration,
	message ldapwire.Message,
) chainAttempt {
	var attempt chainAttempt
	if configuration == nil {
		return attempt
	}
	remoteOrder := preferredProxyRemoteOrder(
		configuration.preferred,
		len(configuration.remotes),
	)
	for position, index := range remoteOrder {
		configured := configuration.remotes[index]
		attempts := ldapBackendRemoteAttempts(len(configuration.remotes))
		for current := 0; current < attempts; current++ {
			remote := anonymousChainRemote(configured.clone())
			forwarded := message
			forwarded.Controls = cloneLDAPControls(message.Controls)
			attempt = server.executeLDAPBackendTarget(
				ctx,
				state,
				*configuration,
				remote,
				forwarded,
			)
			if !ldapBackendShouldFailover(ctx, attempt) {
				break
			}
		}
		if attempt.connected {
			rememberPreferredProxyRemote(configuration.preferred, index)
		}
		if !ldapBackendShouldFailover(ctx, attempt) ||
			position == len(remoteOrder)-1 {
			break
		}
	}
	return attempt
}

func ldapBackendDatabaseForMessage(
	state *connectionState,
	message ldapwire.Message,
) *runtimeDatabase {
	if _, bind := message.Request.(ldapwire.BindRequest); bind {
		return nil
	}
	if request, ok := message.Request.(ldapwire.ExtendedRequest); ok {
		if request.Name == transactionStartOID || request.Name == transactionEndOID {
			return ldapBackendDatabaseForBoundIdentity(state)
		}
		if request.Name == whoAmIOID {
			if state.boundDN == "" {
				return nil
			}
			dn, err := parseConnectionDN(state, state.boundDN)
			if err != nil {
				return nil
			}
			database := databaseForDN(state.runtime, dn)
			if database == nil || database.ldapBackend == nil ||
				databaseRootMatches(state.runtime, *database, dn) ||
				!database.ldapBackend.proxyWhoAmI() {
				return nil
			}
			return database
		}
	}
	target, _, _, ok := chainOperationTarget(state, message.Request)
	if !ok {
		return nil
	}
	database := databaseForDN(state.runtime, target)
	if database == nil || database.ldapBackend == nil {
		return nil
	}
	return database
}

func ldapBackendDatabaseForBoundIdentity(state *connectionState) *runtimeDatabase {
	if state.boundDN == "" {
		return nil
	}
	dn, err := parseConnectionDN(state, state.boundDN)
	if err != nil {
		return nil
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil || database.ldapBackend == nil {
		return nil
	}
	return database
}

func (configuration ldapBackendRuntimeConfiguration) proxyWhoAmI() bool {
	return len(configuration.remotes) > 0 && configuration.remotes[0].proxyWhoAmI
}

func ldapBackendTransactionRequest(message ldapwire.Message) bool {
	if hasLDAPControl(message.Controls, transactionSpecificationControlOID) {
		return true
	}
	request, ok := message.Request.(ldapwire.ExtendedRequest)
	return ok && (request.Name == transactionStartOID || request.Name == transactionEndOID)
}

func (server *Server) executeLDAPBackendOperation(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	message ldapwire.Message,
) (chainAttempt, ldapwire.Message, *ldapwire.Result) {
	var (
		attempt   chainAttempt
		forwarded ldapwire.Message
	)
	remoteOrder := preferredProxyRemoteOrder(
		database.ldapBackend.preferred,
		len(database.ldapBackend.remotes),
	)
	for position, index := range remoteOrder {
		configured := database.ldapBackend.remotes[index]
		attempts := ldapBackendRemoteAttempts(len(database.ldapBackend.remotes))
		for current := 0; current < attempts; current++ {
			remote, candidate, failure := server.ldapBackendRemote(
				ctx,
				state,
				database,
				configured,
				message,
			)
			if failure != nil {
				return chainAttempt{}, candidate, failure
			}
			forwarded = candidate
			attempt = server.executeLDAPBackendTarget(
				ctx,
				state,
				*database.ldapBackend,
				remote,
				forwarded,
			)
			if !ldapBackendShouldFailover(ctx, attempt) {
				break
			}
		}
		if attempt.connected {
			rememberPreferredProxyRemote(database.ldapBackend.preferred, index)
		}
		if !ldapBackendShouldFailover(ctx, attempt) ||
			position == len(remoteOrder)-1 {
			break
		}
	}
	return attempt, forwarded, nil
}

func ldapBackendRemoteAttempts(remoteCount int) int {
	if remoteCount == 1 {
		return 2
	}
	return 1
}

func preferredProxyRemoteOrder(
	preferred *proxyPreferredRemoteState,
	count int,
) []int {
	if count <= 0 {
		return nil
	}
	preferredIndex := 0
	if preferred != nil {
		preferred.mu.RLock()
		candidate := preferred.index
		preferred.mu.RUnlock()
		if candidate >= 0 && candidate < count {
			preferredIndex = candidate
		}
	}
	order := make([]int, count)
	for offset := 0; offset < count; offset++ {
		order[offset] = (preferredIndex + offset) % count
	}
	return order
}

func rememberPreferredProxyRemote(
	preferred *proxyPreferredRemoteState,
	index int,
) {
	if preferred == nil || index < 0 {
		return
	}
	preferred.mu.Lock()
	preferred.index = index
	preferred.mu.Unlock()
}

func (server *Server) ldapBackendRemote(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	configured chainRemoteConfiguration,
	message ldapwire.Message,
) (chainRemoteConfiguration, ldapwire.Message, *ldapwire.Result) {
	remote := configured.clone()
	message.Controls = cloneLDAPControls(message.Controls)
	identityState := state
	authorizationID, proxied := ldapBackendProxiedAuthorization(state)
	if proxied {
		copy := *state
		copy.boundDN = state.operationRealDN
		identityState = &copy
	}
	if !remote.identity.override && ldapBackendHasReusableSimpleIdentity(
		identityState,
		database,
	) {
		boundDN, err := parseConnectionDN(identityState, identityState.boundDN)
		if err == nil {
			if passthrough, ok := chainPassThroughRemote(identityState, remote, boundDN); ok {
				return ldapBackendApplyProxiedAuthorization(
					passthrough,
					message,
					authorizationID,
					proxied,
				)
			}
		}
	}
	remote, message, failure := server.applyChainIdentity(
		ctx,
		identityState,
		remote,
		message,
	)
	if failure != nil {
		return remote, message, failure
	}
	return ldapBackendApplyProxiedAuthorization(
		remote,
		message,
		authorizationID,
		proxied,
	)
}

func ldapBackendProxiedAuthorization(state *connectionState) (string, bool) {
	real, err := parseConnectionDN(state, state.operationRealDN)
	if err != nil {
		return "", false
	}
	effective, err := parseConnectionDN(state, state.boundDN)
	if err != nil || real.Equal(effective) {
		return "", false
	}
	return "dn:" + effective.String(), true
}

func ldapBackendApplyProxiedAuthorization(
	remote chainRemoteConfiguration,
	message ldapwire.Message,
	authorizationID string,
	proxied bool,
) (chainRemoteConfiguration, ldapwire.Message, *ldapwire.Result) {
	if !proxied {
		return remote, message, nil
	}
	message = withoutChainProxyAuthorization(message)
	message.Controls = append(message.Controls, ldapwire.Control{
		OID:      proxyAuthorizationControlOID,
		Critical: true,
		Value:    []byte(authorizationID),
		HasValue: true,
	})
	return remote, message, nil
}

func ldapBackendHasReusableSimpleIdentity(
	state *connectionState,
	database runtimeDatabase,
) bool {
	if state.authMechanism != "SIMPLE" || state.bindCredentialDN == "" ||
		len(state.bindCredentials) == 0 {
		return false
	}
	dn, err := parseConnectionDN(state, state.bindCredentialDN)
	if err != nil {
		return false
	}
	if databaseRootMatches(state.runtime, database, dn) {
		return false
	}
	credentialDatabase := databaseForDN(state.runtime, dn)
	if credentialDatabase == nil ||
		credentialDatabase.configDNKey != database.configDNKey {
		return false
	}
	if credentialDatabase.metaBackend != nil {
		return database.metaTargetKey != "" &&
			state.metaBindDatabaseKey == database.configDNKey &&
			state.metaBindTargetKey == database.metaTargetKey
	}
	return credentialDatabase.ldapBackend != nil
}

func (server *Server) executeLDAPBackendTarget(
	ctx context.Context,
	state *connectionState,
	configuration ldapBackendRuntimeConfiguration,
	remote chainRemoteConfiguration,
	message ldapwire.Message,
) chainAttempt {
	remotes := make([]chainRemoteConfiguration, 0, len(configuration.remotes))
	for _, configured := range configuration.remotes {
		remotes = append(remotes, configured.clone())
	}
	chain := chainRuntimeConfiguration{
		maxReferralDepth:       openLDAPDefaultReferralHopLimit,
		referralHopLimitResult: true,
		common:                 remote.clone(),
		remotes:                remotes,
	}
	return server.executeChainTarget(ctx, state, chain, remote, message, 0)
}

func (server *Server) executeMetaBackendTarget(
	ctx context.Context,
	state *connectionState,
	configuration ldapBackendRuntimeConfiguration,
	remote chainRemoteConfiguration,
	message ldapwire.Message,
	targetKey string,
) chainAttempt {
	return server.executeMetaBackendTargetWithCacheIdentity(
		ctx,
		state,
		configuration,
		remote,
		remote,
		message,
		targetKey,
	)
}

func (server *Server) executeMetaBackendTargetWithCacheIdentity(
	ctx context.Context,
	state *connectionState,
	configuration ldapBackendRuntimeConfiguration,
	remote chainRemoteConfiguration,
	cacheIdentity chainRemoteConfiguration,
	message ldapwire.Message,
	targetKey string,
) chainAttempt {
	return server.executeMetaBackendTargetWithSink(
		ctx,
		state,
		configuration,
		remote,
		cacheIdentity,
		message,
		targetKey,
		nil,
	)
}

func (server *Server) executeMetaBackendTargetWithSink(
	ctx context.Context,
	state *connectionState,
	configuration ldapBackendRuntimeConfiguration,
	remote chainRemoteConfiguration,
	cacheIdentity chainRemoteConfiguration,
	message ldapwire.Message,
	targetKey string,
	packetSink func(*ber.Packet) error,
) chainAttempt {
	return server.executeMetaBackendTargetWithHooks(
		ctx,
		state,
		configuration,
		remote,
		cacheIdentity,
		message,
		targetKey,
		packetSink,
		nil,
	)
}

func (server *Server) executeMetaBackendTargetWithHooks(
	ctx context.Context,
	state *connectionState,
	configuration ldapBackendRuntimeConfiguration,
	remote chainRemoteConfiguration,
	cacheIdentity chainRemoteConfiguration,
	message ldapwire.Message,
	targetKey string,
	packetSink func(*ber.Packet) error,
	requestStarted func() error,
) chainAttempt {
	remote.protocolVersion = effectiveChainProtocolVersion(state, remote, message)
	cacheIdentity.protocolVersion = remote.protocolVersion
	remotes := make([]chainRemoteConfiguration, 0, len(configuration.remotes))
	for _, configured := range configuration.remotes {
		remotes = append(remotes, configured.clone())
	}
	chain := chainRuntimeConfiguration{
		maxReferralDepth:       openLDAPDefaultReferralHopLimit,
		referralHopLimitResult: true,
		common:                 remote.clone(),
		remotes:                remotes,
		transportOwner:         targetKey,
	}
	queuedTemporary := remote.useTemporary && state != nil &&
		state.operationQueue != nil && state.operationQueue.pending() > 0
	if metaBackendUsesPrivilegedPool(state, remote, message) && !queuedTemporary {
		poolTarget := targetKey + "\x00frontend-plain"
		if state.secure {
			poolTarget = targetKey + "\x00frontend-tls"
		}
		chain.transportPool = server.metaTransports
		chain.transportKey = metaTransportKey(poolTarget, cacheIdentity)
		chain.transportPoolMax = remote.connectionPoolMax
		chain.useTemporaryPool = remote.useTemporary
	} else {
		if state != nil && !queuedTemporary {
			chain.transportCache = state.metaTransports
			chain.transportKey = metaTransportKey(targetKey, cacheIdentity)
		}
	}
	chain.packetSink = packetSink
	chain.requestStarted = requestStarted
	return server.executeChainTarget(ctx, state, chain, remote, message, 0)
}

func metaBackendUsesPrivilegedPool(
	state *connectionState,
	remote chainRemoteConfiguration,
	message ldapwire.Message,
) bool {
	if state == nil || !remote.identity.configured ||
		remote.absoluteFilters == chainFeatureDiscover ||
		remote.cancelMode == "exop-discover" {
		return false
	}
	if _, bind := message.Request.(ldapwire.BindRequest); bind {
		return false
	}
	if state.bindCredentialDN != "" &&
		connectionDNsEqual(state, remote.bind.bindDN, state.bindCredentialDN) &&
		bytes.Equal(remote.bind.credentials, state.bindCredentials) {
		return false
	}
	return true
}

func ldapBackendShouldFailover(ctx context.Context, attempt chainAttempt) bool {
	if ctx.Err() != nil || attempt.hasResult || len(attempt.packets) != 0 ||
		attempt.transportErr == nil {
		return false
	}
	var ldapError *ldap.Error
	return !errors.As(attempt.transportErr, &ldapError)
}

func (server *Server) writeLDAPBackendAttempt(
	connection net.Conn,
	message ldapwire.Message,
	attempt chainAttempt,
) error {
	if attempt.hasResult {
		return server.writeChainedPackets(connection, message, attempt.packets)
	}
	if len(attempt.packets) > 0 {
		if err := server.writeChainedPackets(connection, message, attempt.packets); err != nil {
			return err
		}
	}
	return writeResultForMessage(
		connection,
		message,
		ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			ldapBackendUnavailableDiagnostic,
		),
	)
}

func updateLDAPBackendSimpleCredentials(
	state *connectionState,
	request ldapwire.Request,
) {
	passwordRequest, ok := request.(ldapwire.ExtendedRequest)
	if !ok || passwordRequest.Name != passwordModifyOID ||
		!passwordRequest.HasValue || state.bindCredentialDN == "" {
		return
	}
	decoded, err := ldapwire.DecodePasswordModifyRequestValue(
		passwordRequest.Value,
		passwordRequest.HasValue,
	)
	if err != nil || !decoded.HasNewPassword || len(decoded.NewPassword) == 0 {
		return
	}
	targetName := state.boundDN
	if decoded.HasUserIdentity && len(decoded.UserIdentity) > 0 {
		targetName = string(decoded.UserIdentity)
	}
	target, err := parseConnectionDN(state, targetName)
	if err != nil {
		return
	}
	credentialDN, err := parseConnectionDN(state, state.bindCredentialDN)
	if err != nil || !target.Equal(credentialDN) {
		return
	}
	clear(state.bindCredentials)
	state.bindCredentials = append([]byte(nil), decoded.NewPassword...)
}
