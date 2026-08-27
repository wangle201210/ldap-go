package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	absoluteFiltersFeatureOID  = "1.3.6.1.4.1.4203.1.5.3"
	chainingBehaviorControlOID = "1.3.6.1.4.1.4203.666.11.3"
	sessionTrackingControlOID  = ldapwire.SessionTrackingControlOID
	chainCannotChainResultCode = ldapwire.ResultCode(0x4111)
)

type chainBehavior uint8

const (
	chainBehaviorChainingPreferred chainBehavior = iota
	chainBehaviorChainingRequired
	chainBehaviorReferralsPreferred
	chainBehaviorReferralsRequired
)

type chainBehaviorRequest struct {
	resolve      chainBehavior
	continuation chainBehavior
	critical     bool
}

type chainReferralTarget struct {
	uri         string
	endpointKey string
	dn          *directory.DN
	scope       *directory.Scope
	filter      *directory.Filter
}

type chainAttempt struct {
	packets      []*ber.Packet
	result       ldapwire.Result
	hasResult    bool
	hasEntries   bool
	connected    bool
	requestSent  bool
	responses    int
	transportErr error
	localResult  *ldapwire.Result
}

const openLDAPDefaultReferralHopLimit = 5

func (server *Server) tryChainOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	if state.passwordPolicyRestrictedDN != "" ||
		hasLDAPControl(message.Controls, transactionSpecificationControlOID) {
		return false, nil
	}
	target, writeOperation, searchOperation, ok := chainOperationTarget(
		state,
		message.Request,
	)
	if !ok {
		return false, nil
	}
	if searchOperation && target.Depth() == 0 &&
		state.runtime.defaultSearchBase.configured {
		target = state.runtime.defaultSearchBase.dn
	}
	database := databaseForDN(state.runtime, target)
	chain := effectiveChainConfiguration(state.runtime, database)
	behavior, _ := parseChainingBehaviorControls(message.Controls)
	if chain == nil &&
		(behavior == nil || behavior.resolve != chainBehaviorChainingRequired) {
		return false, nil
	}

	manageDsaIT := hasLDAPControl(message.Controls, manageDsaITControlOID)
	var referral *ldapwire.Result
	if database == nil {
		scope := referralScopeDefault
		if search, ok := message.Request.(ldapwire.SearchRequest); ok {
			scope = referralScopeForSearch(search.Scope)
		}
		if result, ok := globalReferralResult(state.runtime, &target, scope); ok {
			referral = &result
		}
	} else if writeOperation {
		if result := updateOperationPrecondition(
			state.runtime,
			state.boundDN,
			target,
		); result != nil {
			if result.Code != ldapwire.ResultReferral {
				return false, nil
			}
			referral = result
		}
		if result := databaseRestrictionResult(
			state.runtime,
			target,
			requestDatabaseRestriction(message.Request),
		); result != nil {
			return false, nil
		}
	} else if searchOperation &&
		hasLDAPControl(message.Controls, dontUseCopyControlOID) &&
		database.shadow {
		result := shadowSearchResult(
			state.runtime,
			*database,
			target,
			message.Request.(ldapwire.SearchRequest).Scope,
		)
		if result.Code == ldapwire.ResultReferral {
			referral = &result
		}
	}
	allowManagedReferral := behavior != nil &&
		behavior.resolve <= chainBehaviorChainingRequired
	if database != nil && referral == nil && (!manageDsaIT || allowManagedReferral) {
		result, err := server.namedReferralForChain(
			ctx,
			state,
			*database,
			target,
			message.Request,
		)
		if err != nil {
			return false, err
		}
		referral = result
	}
	if referral == nil || len(referral.Referrals) == 0 {
		return false, nil
	}
	if behavior != nil && behavior.resolve >= chainBehaviorReferralsPreferred {
		return false, nil
	}
	if chain == nil {
		return true, writeResultForMessage(
			connection,
			message,
			cannotChainResult(),
		)
	}

	attempt := server.executeChainReferrals(
		ctx,
		state,
		*chain,
		message,
		referral.Referrals,
		0,
		false,
		nil,
	)
	if attempt.localResult != nil {
		return true, writeResultForMessage(connection, message, *attempt.localResult)
	}
	if behavior != nil && behavior.resolve == chainBehaviorChainingRequired &&
		(!chainAttemptIsUsable(message.Request, attempt) ||
			attempt.result.Code == ldapwire.ResultReferral) {
		return true, writeResultForMessage(
			connection,
			message,
			cannotChainResult(),
		)
	}
	if attempt.transportErr != nil && !attempt.hasResult {
		if !chain.returnError {
			return false, nil
		}
		result := ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"referral chaining failed: "+attempt.transportErr.Error(),
		)
		return true, writeResultForMessage(connection, message, result)
	}
	if !chainAttemptIsUsable(message.Request, attempt) && !chain.returnError {
		return false, nil
	}
	return true, server.writeChainedPackets(connection, message, attempt.packets)
}

func chainOperationTarget(
	state *connectionState,
	request ldapwire.Request,
) (directory.DN, bool, bool, bool) {
	var (
		rawDN  string
		write  bool
		search bool
	)
	switch request := request.(type) {
	case ldapwire.SearchRequest:
		rawDN = request.BaseDN
		search = true
	case ldapwire.AddRequest:
		rawDN = request.Entry.DN
		write = true
	case ldapwire.ModifyRequest:
		rawDN = request.DN
		write = true
	case ldapwire.DeleteRequest:
		rawDN = request.DN
		write = true
	case ldapwire.ModifyDNRequest:
		rawDN = request.DN
		write = true
	case ldapwire.CompareRequest:
		rawDN = request.DN
	case ldapwire.ExtendedRequest:
		switch request.Name {
		case passwordModifyOID:
			decoded, err := ldapwire.DecodePasswordModifyRequestValue(
				request.Value,
				request.HasValue,
			)
			if err != nil {
				return directory.DN{}, false, false, false
			}
			rawDN = state.boundDN
			if decoded.HasUserIdentity {
				rawDN = string(decoded.UserIdentity)
			}
			write = true
		case dynamicRefreshOID:
			decoded, err := ldapwire.DecodeDynamicRefreshRequestValue(
				request.Value,
				request.HasValue,
			)
			if err != nil {
				return directory.DN{}, false, false, false
			}
			rawDN = decoded.EntryName
			write = true
		default:
			return directory.DN{}, false, false, false
		}
	default:
		return directory.DN{}, false, false, false
	}
	dn, err := parseConnectionDN(state, rawDN)
	if err != nil || dn.Depth() == 0 {
		return directory.DN{}, false, false, false
	}
	return dn, write, search, true
}

func parseConnectionDN(
	state *connectionState,
	value string,
) (directory.DN, error) {
	var runtime *runtimeState
	if state != nil {
		runtime = state.runtime
	}
	return parseRuntimeConnectionDN(runtime, value)
}

func parseRuntimeConnectionDN(
	runtime *runtimeState,
	value string,
) (directory.DN, error) {
	legacy, err := directory.ParseDN(value)
	if err != nil {
		return directory.DN{}, err
	}
	if runtime == nil || isConfigurationDN(legacy) {
		return legacy, nil
	}
	if database := databaseForDN(runtime, legacy); database != nil {
		return parseRuntimeDN(value, database.dnNormalizer)
	}
	if runtime.schema != nil {
		return runtime.schema.NormalizeDN(value)
	}
	return legacy, nil
}

func connectionDNsEqual(
	state *connectionState,
	left string,
	right string,
) bool {
	leftDN, err := parseConnectionDN(state, left)
	if err != nil {
		return false
	}
	rightDN, err := parseConnectionDN(state, right)
	return err == nil && leftDN.Equal(rightDN)
}

func effectiveChainConfiguration(
	runtime *runtimeState,
	database *runtimeDatabase,
) *chainRuntimeConfiguration {
	if database != nil && database.chain != nil {
		return database.chain
	}
	for index := range runtime.databases {
		candidate := &runtime.databases[index]
		if databaseType(candidate.name) == "frontend" && candidate.chain != nil {
			return candidate.chain
		}
	}
	return nil
}

func (server *Server) namedReferralForChain(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	target directory.DN,
	request ldapwire.Request,
) (*ldapwire.Result, error) {
	var result *ldapwire.Result
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		search, isSearch := request.(ldapwire.SearchRequest)
		if isSearch {
			value, err := server.searchReferralForChain(
				state,
				tx,
				target,
				search.Scope,
			)
			result = value
			return err
		}
		_, err := server.entryOrReferral(
			state.runtime,
			tx,
			state.boundDN,
			target,
			false,
		)
		failure := asOperationFailure(err)
		if failure != nil && failure.result.Code == ldapwire.ResultReferral {
			value := failure.result
			result = &value
			return nil
		}
		if err != nil && !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
		return nil
	})
	return result, err
}

func (server *Server) searchReferralForChain(
	state *connectionState,
	reader storage.Reader,
	target directory.DN,
	scope directory.Scope,
) (*ldapwire.Result, error) {
	entry, err := reader.Get(target)
	if err == nil {
		if !state.runtime.schema.EntryHasObjectClass(entry, "referral") {
			return nil, nil
		}
		logical, err := withCollectiveAttributes(state.runtime.schema, reader, entry)
		if err != nil {
			return nil, err
		}
		if !server.allowed(
			state.runtime,
			reader,
			state.boundDN,
			logical,
			"entry",
			nil,
			acl.Search,
		) {
			return nil, nil
		}
		value, err := referralResult(entry, &target, referralScopeForSearch(scope))
		return &value, err
	}
	if !errors.Is(err, storage.ErrEntryNotFound) {
		return nil, err
	}
	ancestor, found, err := closestExistingAncestor(reader, target)
	if err != nil || !found ||
		!state.runtime.schema.EntryHasObjectClass(ancestor, "referral") {
		return nil, err
	}
	logical, err := withCollectiveAttributes(state.runtime.schema, reader, ancestor)
	if err != nil {
		return nil, err
	}
	if !server.allowed(
		state.runtime,
		reader,
		state.boundDN,
		logical,
		"entry",
		nil,
		acl.Disclose,
	) {
		return nil, nil
	}
	value, err := referralResult(ancestor, &target, referralScopeForSearch(scope))
	return &value, err
}

func (server *Server) executeChainReferrals(
	ctx context.Context,
	state *connectionState,
	chain chainRuntimeConfiguration,
	message ldapwire.Message,
	referrals []string,
	depth int,
	continuation bool,
	parentRemote *chainRemoteConfiguration,
) chainAttempt {
	var first chainAttempt
	for _, reference := range referrals {
		target, rewritten, err := rewriteChainedRequest(
			message,
			reference,
			continuation,
		)
		if err != nil {
			if first.transportErr == nil {
				first.transportErr = err
			}
			continue
		}
		var remote chainRemoteConfiguration
		if parentRemote == nil {
			remote = selectChainRemote(chain, target)
			var identityFailure *ldapwire.Result
			remote, rewritten, identityFailure = server.applyChainIdentity(
				ctx,
				state,
				remote,
				rewritten,
			)
			if identityFailure != nil {
				result := *identityFailure
				return chainAttempt{
					result:      result,
					hasResult:   true,
					localResult: &result,
				}
			}
		} else {
			remote = chainNestedReferralRemote(*parentRemote, target)
		}
		attempt := server.executeChainTarget(
			ctx,
			state,
			chain,
			remote,
			rewritten,
			depth+1,
		)
		if chainAttemptIsUsable(message.Request, attempt) {
			return attempt
		}
		if !first.hasResult && first.transportErr == nil {
			first = attempt
		}
	}
	if first.transportErr == nil && !first.hasResult {
		first.transportErr = errors.New("no supported referral URL")
	}
	return first
}

func (server *Server) chainSearchContinuations(
	ctx context.Context,
	state *connectionState,
	message ldapwire.Message,
	references [][]string,
) ([]*ber.Packet, [][]string, *ldapwire.Result) {
	if len(references) == 0 {
		return nil, nil, nil
	}
	behavior, _ := parseChainingBehaviorControls(message.Controls)
	if behavior != nil && behavior.continuation >= chainBehaviorReferralsPreferred {
		return nil, references, nil
	}
	request, ok := message.Request.(ldapwire.SearchRequest)
	if !ok {
		return nil, references, nil
	}
	base, err := parseConnectionDN(state, request.BaseDN)
	if err != nil {
		return nil, references, nil
	}
	database := databaseForDN(state.runtime, base)
	chain := effectiveChainConfiguration(state.runtime, database)
	if chain == nil {
		if behavior != nil && behavior.continuation == chainBehaviorChainingRequired {
			result := cannotChainResult()
			return nil, nil, &result
		}
		return nil, references, nil
	}

	var (
		packets    []*ber.Packet
		unresolved [][]string
	)
	for _, group := range references {
		attempt := server.executeChainReferrals(
			ctx,
			state,
			*chain,
			message,
			group,
			0,
			true,
			nil,
		)
		if attempt.localResult != nil {
			result := *attempt.localResult
			return packets, nil, &result
		}
		if behavior != nil &&
			behavior.continuation == chainBehaviorChainingRequired &&
			(!chainAttemptIsUsable(message.Request, attempt) ||
				attempt.result.Code == ldapwire.ResultReferral) {
			result := cannotChainResult()
			return packets, nil, &result
		}
		if attempt.hasResult && attempt.result.Code == ldapwire.ResultReferral {
			packets = append(packets, withoutSearchDone(attempt.packets)...)
			if len(attempt.result.Referrals) > 0 {
				unresolved = append(unresolved, attempt.result.Referrals)
			} else {
				unresolved = append(unresolved, group)
			}
			continue
		}
		if chainAttemptIsUsable(message.Request, attempt) {
			packets = append(packets, withoutSearchDone(attempt.packets)...)
			if chain.returnError && attempt.result.Code != ldapwire.ResultSuccess {
				result := attempt.result
				return packets, nil, &result
			}
			continue
		}
		if !chain.returnError {
			unresolved = append(unresolved, group)
			continue
		}
		if attempt.hasResult {
			result := attempt.result
			return packets, nil, &result
		}
		diagnostic := "referral chaining failed"
		if attempt.transportErr != nil {
			diagnostic += ": " + attempt.transportErr.Error()
		}
		result := ldapwire.ResultError(ldapwire.ResultUnavailable, diagnostic)
		return packets, nil, &result
	}
	return packets, unresolved, nil
}

func selectChainRemote(
	chain chainRuntimeConfiguration,
	target chainReferralTarget,
) chainRemoteConfiguration {
	for _, remote := range chain.remotes {
		if remote.endpointKey == target.endpointKey {
			selected := remote.clone()
			selected.uri = target.uri
			return selected
		}
	}
	remote := chain.common.clone()
	remote.uri = target.uri
	remote.endpointKey = target.endpointKey
	remote.identity = chainIdentityAssertion{
		mode:         chainIdentityLegacy,
		prescriptive: true,
	}
	remote.bind.bindMethod = ""
	remote.bind.bindDN = ""
	remote.bind.credentials = nil
	remote.bind.credentialsSet = false
	remote.bind.saslMechanism = ""
	remote.bind.authenticationID = ""
	remote.bind.authorizationID = ""
	remote.bind.realm = ""
	return remote
}

func chainNestedReferralRemote(
	parent chainRemoteConfiguration,
	target chainReferralTarget,
) chainRemoteConfiguration {
	remote := parent.clone()
	remote.uri = target.uri
	remote.endpointKey = target.endpointKey
	if !parent.rebindAsUser || parent.bind.bindMethod != "simple" {
		remote = anonymousChainRemote(remote)
	}
	return remote
}

func (server *Server) applyChainIdentity(
	ctx context.Context,
	state *connectionState,
	remote chainRemoteConfiguration,
	message ldapwire.Message,
) (chainRemoteConfiguration, ldapwire.Message, *ldapwire.Result) {
	identity := remote.identity
	if !identity.configured {
		return remote, message, nil
	}
	boundDN, err := parseConnectionDN(state, state.boundDN)
	if err != nil {
		result := ldapwire.ResultError(
			ldapwire.ResultInappropriateAuthentication,
			"identity assertion subject is invalid",
		)
		return remote, message, &result
	}
	root := boundDN.Depth() != 0 && isAnyDatabaseRoot(state.runtime, boundDN)
	if identity.mode == chainIdentityLegacy && boundDN.Depth() == 0 {
		return anonymousChainRemote(remote), withoutChainProxyAuthorization(message), nil
	}
	if identity.mode != chainIdentityLegacy && !root {
		passThrough, err := server.chainIdentityRulesMatch(
			ctx,
			state.runtime,
			identity.passThru,
			boundDN,
		)
		if err != nil {
			result := ldapwire.ResultError(
				ldapwire.ResultInappropriateAuthentication,
				"identity assertion pass-through rule is invalid",
			)
			return remote, message, &result
		}
		if passThrough {
			passthrough, ok := chainPassThroughRemote(state, remote, boundDN)
			if !ok {
				result := ldapwire.ResultError(
					ldapwire.ResultInappropriateAuthentication,
					"identity pass-through requires reusable SIMPLE credentials",
				)
				return remote, message, &result
			}
			return passthrough, withoutChainProxyAuthorization(message), nil
		}
		if len(identity.authzFrom) > 0 {
			authorized, err := server.chainIdentityRulesMatch(
				ctx,
				state.runtime,
				identity.authzFrom,
				boundDN,
			)
			if err != nil {
				result := ldapwire.ResultError(
					ldapwire.ResultInappropriateAuthentication,
					"identity assertion authorization rule is invalid",
				)
				return remote, message, &result
			}
			if !authorized {
				if identity.prescriptive {
					result := ldapwire.ResultError(
						ldapwire.ResultInappropriateAuthentication,
						"identity assertion is not authorized",
					)
					return remote, message, &result
				}
				return anonymousChainRemote(remote), withoutChainProxyAuthorization(message), nil
			}
		} else if boundDN.Depth() == 0 {
			if identity.prescriptive {
				result := ldapwire.ResultError(
					ldapwire.ResultInappropriateAuthentication,
					"anonymous identity assertion is not authorized",
				)
				return remote, message, &result
			}
			return anonymousChainRemote(remote), withoutChainProxyAuthorization(message), nil
		}
	}

	message = withoutChainProxyAuthorization(message)
	if identity.native {
		switch identity.mode {
		case chainIdentityAnonymous:
			remote.bind.authorizationID = "dn:"
		case chainIdentityLegacy, chainIdentitySelf:
			remote.bind.authorizationID = "dn:" + state.boundDN
		case chainIdentityOtherDN, chainIdentityOtherID:
			remote.bind.authorizationID = identity.assertedID
		case chainIdentityNone:
			remote.bind.authorizationID = ""
		default:
			remote.bind.authorizationID = ""
		}
		return remote, message, nil
	}
	var authorizationID string
	switch identity.mode {
	case chainIdentityNone:
		return remote, message, nil
	case chainIdentityAnonymous:
		authorizationID = "dn:"
	case chainIdentityLegacy, chainIdentitySelf:
		authorizationID = "dn:" + state.boundDN
	case chainIdentityOtherDN, chainIdentityOtherID:
		authorizationID = identity.assertedID
	default:
		return remote, message, nil
	}
	message.Controls = append(message.Controls, ldapwire.Control{
		OID:      proxyAuthorizationControlOID,
		Critical: identity.proxyAuthzCritical,
		Value:    []byte(authorizationID),
		HasValue: true,
	})
	return remote, message, nil
}

func (server *Server) chainIdentityRulesMatch(
	ctx context.Context,
	runtime *runtimeState,
	rules []string,
	identity directory.DN,
) (bool, error) {
	for _, rawRule := range rules {
		_, _, rule, err := orderedSASLConfigurationValue(rawRule)
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(rule) == "*" && identity.Depth() == 0 {
			return true, nil
		}
		matched, err := server.authorizationRuleMatches(
			ctx,
			runtime,
			identity,
			rawRule,
			identity,
		)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func anonymousChainRemote(remote chainRemoteConfiguration) chainRemoteConfiguration {
	remote.bind.bindMethod = ""
	remote.bind.bindDN = ""
	clear(remote.bind.credentials)
	remote.bind.credentials = nil
	remote.bind.credentialsSet = false
	remote.bind.saslMechanism = ""
	remote.bind.authenticationID = ""
	remote.bind.authorizationID = ""
	remote.bind.realm = ""
	return remote
}

func chainPassThroughRemote(
	state *connectionState,
	remote chainRemoteConfiguration,
	identity directory.DN,
) (chainRemoteConfiguration, bool) {
	credentialDN, err := parseConnectionDN(state, state.bindCredentialDN)
	if err != nil {
		return chainRemoteConfiguration{}, false
	}
	identity, err = parseConnectionDN(state, identity.String())
	if err != nil || state.authMechanism != "SIMPLE" ||
		len(state.bindCredentials) == 0 || !credentialDN.Equal(identity) {
		return chainRemoteConfiguration{}, false
	}
	remote.bind.bindMethod = "simple"
	remote.bind.bindDN = state.bindCredentialDN
	remote.bind.credentials = append([]byte(nil), state.bindCredentials...)
	remote.bind.credentialsSet = true
	return remote, true
}

func withoutChainProxyAuthorization(message ldapwire.Message) ldapwire.Message {
	controls := message.Controls[:0]
	for _, control := range message.Controls {
		if control.OID != proxyAuthorizationControlOID {
			controls = append(controls, control)
		}
	}
	message.Controls = controls
	return message
}

func (server *Server) executeChainTarget(
	ctx context.Context,
	state *connectionState,
	chain chainRuntimeConfiguration,
	remote chainRemoteConfiguration,
	message ldapwire.Message,
	depth int,
) chainAttempt {
	remote.protocolVersion = effectiveChainProtocolVersion(state, remote, message)
	var protocolFailure *ldapwire.Result
	message, remote, protocolFailure = prepareChainProtocolMessage(message, remote)
	if protocolFailure != nil {
		return chainAttempt{result: *protocolFailure, hasResult: true}
	}
	if request, ok := message.Request.(ldapwire.SearchRequest); ok &&
		remote.noUndefinedFilter &&
		chainFilterHasUndefined(state.runtime.schema, request.Filter) {
		return emptySuccessfulChainSearch(message.ID)
	}
	cache := chain.transportCache
	pool := chain.transportPool
	cacheKey := chain.transportKey
	var (
		transport *syncConsumerTransport
		poolLease *metaTransportPoolLease
	)
	if pool != nil {
		var err error
		transport, poolLease, err = pool.acquireOwned(
			ctx,
			cacheKey,
			chain.transportOwner,
			remote,
			chain.transportPoolMax,
			chain.useTemporaryPool,
		)
		if err != nil {
			return chainAttempt{transportErr: err}
		}
	} else {
		transport = cache.acquireOwned(cacheKey, chain.transportOwner, remote)
	}
	if transport != nil && pool == nil {
		transport.context = ctx
		transport.operationTimeout = chainRequestTimeout(remote, message.Request)
	}
	if transport == nil {
		var err error
		transport, err = server.openChainTransport(ctx, state, remote, message.Request)
		if err != nil {
			pool.abort(poolLease)
			return chainAttempt{transportErr: err}
		}
		if pool != nil {
			pool.publish(poolLease, transport)
		}
	}
	attempt := chainAttempt{connected: true}
	healthy := false
	poolReusable := true
	cancelWriteReusable := true
	var (
		stop          chan struct{}
		cancelStopped chan struct{}
	)
	defer func() {
		if stop != nil {
			close(stop)
		}
		if pool != nil {
			if cancelStopped != nil {
				<-cancelStopped
			}
			pool.release(
				poolLease,
				remote,
				transport,
				poolReusable && cancelWriteReusable,
			)
		} else {
			healthy = healthy && ctx.Err() == nil
			if healthy && transport.clearDeadline() != nil {
				healthy = false
			}
			cache.releaseOwned(
				cacheKey,
				chain.transportOwner,
				remote,
				transport,
				healthy,
			)
		}
	}()
	if request, ok := message.Request.(ldapwire.SearchRequest); ok {
		supportsAbsoluteFilters := remote.absoluteFilters == chainFeatureEnabled
		if remote.absoluteFilters == chainFeatureDiscover {
			discovered, err := discoverChainAbsoluteFilters(transport)
			if err != nil {
				poolReusable = false
				attempt.transportErr = err
				return attempt
			}
			supportsAbsoluteFilters = discovered
		}
		if !supportsAbsoluteFilters {
			request.Filter = rewriteChainAbsoluteFilters(request.Filter)
			message.Request = request
		}
	}
	resolvedCancelMode := remote.cancelMode
	if resolvedCancelMode == "" {
		resolvedCancelMode = "exop"
	}
	if resolvedCancelMode == "exop-discover" {
		supported, err := discoverChainCancel(transport)
		if err != nil {
			poolReusable = false
			attempt.transportErr = err
			return attempt
		}
		resolvedCancelMode = "abandon"
		if supported {
			resolvedCancelMode = "exop"
		}
	}
	if remote.sessionTracking {
		message.Controls = appendChainSessionTrackingControl(message.Controls, state)
	}
	if chain.outboundChaining != nil &&
		!hasLDAPControl(message.Controls, chainingBehaviorControlOID) {
		control := *chain.outboundChaining
		control.Value = bytes.Clone(control.Value)
		message.Controls = append([]ldapwire.Control{control}, message.Controls...)
	}

	message.ID = transport.nextMessageID()
	encoded, err := ldapwire.EncodeRequestMessage(message)
	if err != nil {
		attempt.transportErr = err
		return attempt
	}
	forwardedBind := message.Request.ApplicationTag() == ldapwire.ApplicationBindRequest
	operationCtx := ctx
	var cancelOperation context.CancelFunc
	if pool != nil {
		if timeout := chainRequestTimeout(remote, message.Request); timeout > 0 {
			operationCtx, cancelOperation = context.WithTimeout(ctx, timeout)
			defer cancelOperation()
		}
	} else {
		if err := setChainRequestDeadline(transport, remote, forwardedBind); err != nil {
			attempt.transportErr = err
			return attempt
		}
	}
	var responseStream *syncConsumerResponseStream
	if pool != nil {
		if err := transport.enableMultiplexing(); err != nil {
			poolReusable = false
			attempt.transportErr = err
			return attempt
		}
		var unregister func()
		responseStream, unregister, err = transport.multiplexedResponse(message.ID)
		if err != nil {
			poolReusable = false
			attempt.transportErr = err
			return attempt
		}
		defer unregister()
	}
	connection := transport.currentConnection()
	if pool != nil {
		writeContext := operationCtx
		var cancelWrite context.CancelFunc
		if remote.bind.networkTimeout > 0 {
			writeContext, cancelWrite = context.WithTimeout(
				operationCtx,
				remote.bind.networkTimeout,
			)
		}
		outcome, writeErr := writeMetaTransportPoolPacket(
			writeContext,
			transport,
			encoded,
		)
		if cancelWrite != nil {
			cancelWrite()
		}
		attempt.requestSent = outcome.requestSent
		poolReusable = poolReusable && outcome.reusable
		if writeErr != nil {
			attempt.transportErr = writeErr
			return attempt
		}
	} else {
		if err := transport.writePacket(encoded); err != nil {
			attempt.transportErr = err
			return attempt
		}
		attempt.requestSent = true
	}
	stop = make(chan struct{})
	remoteMessageID := message.ID
	var cancelRemote sync.Once
	cancelUpstream := func() {
		cancelRemote.Do(func() {
			if pool != nil {
				cancelContext, cancel := context.WithTimeout(
					context.Background(),
					chainPooledCancelTimeout(remote, message.Request),
				)
				cancelWriteReusable = cancelChainOperation(
					cancelContext,
					transport,
					remoteMessageID,
					resolvedCancelMode,
					true,
				)
				cancel()
			} else {
				cancelChainOperation(
					context.Background(),
					transport,
					remoteMessageID,
					resolvedCancelMode,
					false,
				)
				_ = transport.close()
			}
		})
	}
	cancelStopped = make(chan struct{})
	go func() {
		defer close(cancelStopped)
		select {
		case <-operationCtx.Done():
			cancelUpstream()
		case <-stop:
		}
	}()
	if chain.requestStarted != nil {
		if err := chain.requestStarted(); err != nil {
			attempt.transportErr = err
			return attempt
		}
	}

	search := message.Request.ApplicationTag() == ldapwire.ApplicationSearchRequest
	expectedTag, responds := responseTagFor(message.Request.ApplicationTag())
	if search {
		expectedTag = ldapwire.ApplicationSearchResultDone
		responds = true
	}
	if !responds {
		poolReusable = false
		attempt.transportErr = errors.New("chained request has no response")
		return attempt
	}
	referralLimitExceeded := false
	for {
		var packet *ber.Packet
		var err error
		if responseStream != nil {
			packet, err = responseStream.next(operationCtx)
		} else {
			packet, err = readSyncConsumerPacket(connection)
		}
		if err != nil {
			if responseStream != nil && operationCtx.Err() != nil {
				cancelUpstream()
			} else if responseStream != nil {
				poolReusable = false
			}
			if responseStream != nil && forwardedBind {
				poolReusable = false
			}
			if forwardedBind && ctx.Err() == nil && chainRequestTimedOut(err) {
				result := ldapwire.ResultError(
					ldapwire.ResultAdminLimitExceeded,
					"Operation timed out",
				)
				packet, decodeErr := ber.DecodePacketErr(
					ldapwire.EncodeBindResponse(message.ID, result, nil),
				)
				if decodeErr != nil {
					attempt.transportErr = decodeErr
					return attempt
				}
				attempt.packets = append(attempt.packets, packet)
				attempt.result = result
				attempt.hasResult = true
				return attempt
			}
			attempt.transportErr = err
			return attempt
		}
		tag, err := validateChainResponseEnvelope(packet, message.ID)
		if err != nil {
			poolReusable = false
			attempt.transportErr = err
			return attempt
		}
		attempt.responses++
		if search {
			switch tag {
			case ldapwire.ApplicationSearchResultEntry:
				if err := sanitizeChainedSearchEntry(
					packet,
					state.runtime.schema,
					remote.removeUnknownSchema,
				); err != nil {
					poolReusable = false
					attempt.transportErr = err
					return attempt
				}
				attempt.hasEntries = true
				if err := emitChainSearchPackets(&attempt, chain.packetSink, packet); err != nil {
					attempt.transportErr = err
					return attempt
				}
				continue
			case ldapwire.ApplicationSearchResultReference:
				references, err := chainSearchReferences(packet)
				if err != nil {
					poolReusable = false
					attempt.transportErr = err
					return attempt
				}
				if remote.chaseReferrals {
					if depth < chain.maxReferralDepth {
						nested := server.executeChainReferrals(
							ctx,
							state,
							chain,
							message,
							references,
							depth,
							true,
							&remote,
						)
						if nested.localResult != nil ||
							chainAttemptIsUsable(message.Request, nested) {
							if err := emitChainSearchPackets(
								&attempt,
								chain.packetSink,
								withoutSearchDone(nested.packets)...,
							); err != nil {
								attempt.transportErr = err
								return attempt
							}
							attempt.hasEntries = attempt.hasEntries || nested.hasEntries
							if nested.localResult != nil {
								referralLimitExceeded = true
							}
							continue
						}
					} else if chain.referralHopLimitResult && len(references) > 0 {
						referralLimitExceeded = true
						continue
					}
				}
				if !remote.noRefs {
					if err := emitChainSearchPackets(&attempt, chain.packetSink, packet); err != nil {
						attempt.transportErr = err
						return attempt
					}
				}
				continue
			case ldapwire.ApplicationIntermediateResponse:
				if err := emitChainSearchPackets(&attempt, chain.packetSink, packet); err != nil {
					attempt.transportErr = err
					return attempt
				}
				continue
			case expectedTag:
			default:
				poolReusable = false
				attempt.transportErr = fmt.Errorf("unexpected chained search response tag %d", tag)
				return attempt
			}
		} else if tag != expectedTag {
			poolReusable = false
			attempt.transportErr = fmt.Errorf(
				"unexpected chained response tag %d, want %d",
				tag,
				expectedTag,
			)
			return attempt
		}

		result, err := chainLDAPResult(packet, message.ID, expectedTag)
		if err != nil {
			poolReusable = false
			attempt.transportErr = err
			return attempt
		}
		healthy = result.Code != ldapwire.ResultUnavailable
		if _, bind := message.Request.(ldapwire.BindRequest); bind &&
			result.Code != ldapwire.ResultSuccess {
			healthy = false
			poolReusable = false
		}
		if result.Code == ldapwire.ResultReferral &&
			remote.chaseReferrals &&
			depth < chain.maxReferralDepth &&
			len(result.Referrals) > 0 {
			nested := server.executeChainReferrals(
				ctx,
				state,
				chain,
				message,
				result.Referrals,
				depth,
				false,
				&remote,
			)
			if nested.localResult != nil || chainAttemptIsUsable(message.Request, nested) {
				if search {
					attempt.packets = append(attempt.packets, nested.packets...)
					attempt.hasEntries = attempt.hasEntries || nested.hasEntries
					attempt.result = nested.result
					attempt.hasResult = nested.hasResult
					attempt.localResult = nested.localResult
					return attempt
				}
				return nested
			}
		}
		if referralLimitExceeded ||
			(result.Code == ldapwire.ResultReferral &&
				remote.chaseReferrals &&
				chain.referralHopLimitResult &&
				depth >= chain.maxReferralDepth &&
				len(result.Referrals) > 0) {
			return chainReferralHopLimitAttempt(attempt, message.ID, expectedTag)
		}
		attempt.packets = append(attempt.packets, packet)
		attempt.result = result
		attempt.hasResult = true
		return attempt
	}
}

func chainReferralHopLimitAttempt(
	attempt chainAttempt,
	messageID int64,
	responseTag uint64,
) chainAttempt {
	result := ldapwire.ResultError(ldapwire.ResultLoopDetect, "")
	packet, err := ber.DecodePacketErr(
		ldapwire.EncodeResultResponse(messageID, responseTag, result, nil),
	)
	if err != nil {
		attempt.transportErr = err
		return attempt
	}
	attempt.packets = append(attempt.packets, packet)
	attempt.result = result
	attempt.hasResult = true
	attempt.localResult = &result
	return attempt
}

func effectiveChainProtocolVersion(
	state *connectionState,
	remote chainRemoteConfiguration,
	message ldapwire.Message,
) int {
	if remote.protocolVersion == 2 || remote.protocolVersion == 3 {
		return remote.protocolVersion
	}
	if request, bind := message.Request.(ldapwire.BindRequest); bind &&
		(request.Version == 2 || request.Version == 3) {
		return request.Version
	}
	if state != nil && (state.protocolVersion == 2 || state.protocolVersion == 3) {
		return state.protocolVersion
	}
	return 3
}

func prepareChainProtocolMessage(
	message ldapwire.Message,
	remote chainRemoteConfiguration,
) (ldapwire.Message, chainRemoteConfiguration, *ldapwire.Result) {
	if request, bind := message.Request.(ldapwire.BindRequest); bind {
		request.Version = remote.protocolVersion
		message.Request = request
	}
	if remote.protocolVersion != 2 {
		return message, remote, nil
	}
	if hasLDAPControl(message.Controls, proxyAuthorizationControlOID) {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"identity assertion requires LDAPv3",
		)
		return message, remote, &result
	}
	for _, control := range message.Controls {
		if control.Critical {
			result := ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
			return message, remote, &result
		}
	}
	message.Controls = nil
	remote.sessionTracking = false
	return message, remote, nil
}

func setChainRequestDeadline(
	transport *syncConsumerTransport,
	remote chainRemoteConfiguration,
	forwardedBind bool,
) error {
	if !forwardedBind {
		return transport.setOperationDeadline()
	}
	deadline := transport.resultPollingDeadline(syncConsumerResultPolling{
		initial:  100 * time.Millisecond,
		interval: remote.bindPollTimeout,
		retries:  remote.bindPollRetries,
	})
	return transport.currentConnection().SetDeadline(deadline)
}

func chainRequestTimedOut(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func cancelChainOperation(
	ctx context.Context,
	transport *syncConsumerTransport,
	remoteMessageID int64,
	mode string,
	pooled bool,
) bool {
	if transport == nil || remoteMessageID <= 0 || mode == "ignore" {
		return true
	}
	requestID := transport.nextMessageID()
	message := ldapwire.Message{ID: requestID}
	switch mode {
	case "abandon":
		message.Request = ldapwire.AbandonRequest{MessageID: remoteMessageID}
	case "exop":
		message.Request = ldapwire.ExtendedRequest{
			Name:     cancelOID,
			Value:    ldapwire.EncodeCancelRequestValue(remoteMessageID),
			HasValue: true,
		}
	default:
		return true
	}
	encoded, err := ldapwire.EncodeRequestMessage(message)
	if err != nil {
		return true
	}
	if pooled {
		outcome, _ := writeMetaTransportPoolPacket(ctx, transport, encoded)
		return outcome.reusable
	}
	_ = transport.writePacket(encoded)
	return true
}

func chainPooledCancelTimeout(
	remote chainRemoteConfiguration,
	request ldapwire.Request,
) time.Duration {
	if timeout := chainRequestTimeout(remote, request); timeout > 0 {
		return timeout
	}
	if remote.bind.networkTimeout > 0 {
		return remote.bind.networkTimeout
	}
	return ldap.DefaultTimeout
}

func emitChainSearchPackets(
	attempt *chainAttempt,
	sink func(*ber.Packet) error,
	packets ...*ber.Packet,
) error {
	for _, packet := range packets {
		if sink != nil {
			if err := sink(packet); err != nil {
				return err
			}
			continue
		}
		attempt.packets = append(attempt.packets, packet)
	}
	return nil
}

func (server *Server) openChainTransport(
	ctx context.Context,
	state *connectionState,
	remote chainRemoteConfiguration,
	request ldapwire.Request,
) (*syncConsumerTransport, error) {
	configuration := remote.bind
	requestTimeout := time.Duration(0)
	if timeout, found := remote.operationTimeouts[request.ApplicationTag()]; found {
		requestTimeout = timeout
	}
	bindTimeout := configuration.operationTimeout
	if requestTimeout > 0 && (bindTimeout <= 0 || requestTimeout < bindTimeout) {
		bindTimeout = requestTimeout
	}
	configuration.operationTimeout = 0
	parsed, err := parseSyncConsumerProviderURL(remote.uri)
	if err != nil {
		return nil, err
	}
	startTLS := configuration.startTLS
	switch remote.startTLSMode {
	case "propagate":
		if !state.secure {
			startTLS = syncConsumerStartTLSOff
		}
	case "try-propagate":
		if !state.secure {
			startTLS = syncConsumerStartTLSOff
		}
	}
	configuration.startTLS = startTLS
	transport, err := dialSyncConsumer(ctx, configuration, remote.uri)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*syncConsumerTransport, error) {
		_ = transport.close()
		return nil, err
	}
	ready := func() (*syncConsumerTransport, error) {
		if err := transport.clearDeadline(); err != nil {
			return fail(fmt.Errorf("clear chain transport deadline: %w", err))
		}
		transport.operationTimeout = requestTimeout
		return transport, nil
	}
	if configuration.startTLS != syncConsumerStartTLSOff &&
		strings.EqualFold(parsed.Scheme, "ldap") {
		if err := performSyncConsumerStartTLS(
			transport,
			configuration,
			parsed,
			syncConsumerResultPolling{
				initial:  100 * time.Millisecond,
				interval: 100 * time.Millisecond,
				retries:  remote.bindPollRetries,
			},
		); err != nil {
			if configuration.startTLS == syncConsumerStartTLSCritical {
				return fail(fmt.Errorf("chain StartTLS: %w", err))
			}
		}
	}
	switch configuration.bindMethod {
	case "":
		return ready()
	case "simple":
		transport.operationTimeout = bindTimeout
		pollRetries := remote.bindPollRetries
		if _, search := request.(ldapwire.SearchRequest); search {
			// OpenLDAP keeps polling an identity-assertion Bind for the
			// lifetime of the Search operation, even after nretries expires.
			pollRetries = -1
		}
		if err := bindChainSimple(
			transport,
			configuration,
			remote.protocolVersion,
			pollRetries,
			remote.bindPollTimeout,
		); err != nil {
			return fail(err)
		}
		return ready()
	case "sasl":
		transport.operationTimeout = bindTimeout
		configuration.gssapiChannelBinding = server.config.GSSAPIChannelBinding
		var bindErr error
		if ldapBackendGSSAPIConfigured(configuration) {
			bindContext := ctx
			var cancel context.CancelFunc
			if bindTimeout > 0 {
				bindContext, cancel = context.WithTimeout(ctx, bindTimeout)
				defer cancel()
			}
			bindErr = bindLDAPBackendGSSAPI(
				bindContext,
				transport,
				configuration,
				remote.uri,
			)
		} else {
			bindErr = bindSyncConsumerSASL(transport, configuration, remote.uri)
		}
		if bindErr != nil {
			return fail(fmt.Errorf("chain SASL bind: %w", bindErr))
		}
		return ready()
	default:
		return fail(fmt.Errorf("unknown chain bind method %q", configuration.bindMethod))
	}
}

func bindChainSimple(
	transport *syncConsumerTransport,
	configuration syncConsumerConfig,
	protocolVersion int,
	pollRetries int,
	pollTimeout time.Duration,
) error {
	if protocolVersion == 0 {
		protocolVersion = 3
	}
	messageID := transport.nextMessageID()
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.BindRequest{
			Version: protocolVersion,
			Name:    configuration.bindDN,
			Authentication: ldapwire.Authentication{
				Simple: configuration.credentials,
			},
		},
	})
	if err != nil {
		return err
	}
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		return err
	}
	result, err := transport.exchangeLDAPResultPolling(
		messageID,
		packet,
		ldapwire.ApplicationBindResponse,
		syncConsumerResultPolling{
			initial:  100 * time.Millisecond,
			interval: pollTimeout,
			retries:  pollRetries,
		},
	)
	if err != nil {
		return err
	}
	if result.code != uint16(ldapwire.ResultSuccess) {
		return result.err()
	}
	return nil
}

func rewriteChainedRequest(
	message ldapwire.Message,
	reference string,
	continuation bool,
) (chainReferralTarget, ldapwire.Message, error) {
	target, err := parseChainReferralTarget(reference, message.Request, continuation)
	if err != nil {
		return chainReferralTarget{}, ldapwire.Message{}, err
	}
	request := message.Request
	switch value := request.(type) {
	case ldapwire.SearchRequest:
		if target.dn != nil {
			value.BaseDN = target.dn.String()
		}
		if target.scope != nil {
			value.Scope = *target.scope
		} else if continuation && value.Scope == directory.ScopeSingleLevel {
			value.Scope = directory.ScopeBase
		}
		if target.filter != nil {
			value.Filter = *target.filter
		}
		message.Request = value
	case ldapwire.AddRequest:
		if target.dn != nil {
			value.Entry = value.Entry.Clone()
			value.Entry.DN = target.dn.String()
		}
		message.Request = value
	case ldapwire.ModifyRequest:
		if target.dn != nil {
			value.DN = target.dn.String()
		}
		message.Request = value
	case ldapwire.DeleteRequest:
		if target.dn != nil {
			value.DN = target.dn.String()
		}
		message.Request = value
	case ldapwire.ModifyDNRequest:
		if target.dn != nil {
			value.DN = target.dn.String()
		}
		message.Request = value
	case ldapwire.CompareRequest:
		if target.dn != nil {
			value.DN = target.dn.String()
		}
		message.Request = value
	case ldapwire.ExtendedRequest:
		if target.dn != nil {
			switch value.Name {
			case passwordModifyOID:
				decoded, err := ldapwire.DecodePasswordModifyRequestValue(
					value.Value,
					value.HasValue,
				)
				if err != nil {
					return chainReferralTarget{}, ldapwire.Message{}, err
				}
				decoded.UserIdentity = []byte(target.dn.String())
				decoded.HasUserIdentity = true
				value.Value = encodeChainedPasswordModifyValue(decoded)
				value.HasValue = true
			case dynamicRefreshOID:
				decoded, err := ldapwire.DecodeDynamicRefreshRequestValue(
					value.Value,
					value.HasValue,
				)
				if err != nil {
					return chainReferralTarget{}, ldapwire.Message{}, err
				}
				value.Value = ldapwire.EncodeDynamicRefreshRequestValue(
					target.dn.String(),
					decoded.RequestTTL,
				)
			}
		}
		message.Request = value
	}
	message.Controls = cloneLDAPControls(message.Controls)
	return target, message, nil
}

func parseChainReferralTarget(
	reference string,
	request ldapwire.Request,
	continuation bool,
) (chainReferralTarget, error) {
	raw := strings.TrimSpace(referralURI(reference))
	if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") {
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "<"), ">")
	}
	if len(raw) >= 4 && strings.EqualFold(raw[:4], "URL:") {
		raw = raw[4:]
	}
	parsed, err := parseSyncConsumerProviderURL(raw)
	if err != nil {
		return chainReferralTarget{}, err
	}
	endpointKey, err := chainEndpointKeyForReferral(parsed)
	if err != nil {
		return chainReferralTarget{}, err
	}
	target := chainReferralTarget{
		uri:         chainReferralEndpointURI(parsed),
		endpointKey: endpointKey,
	}
	rawPath := parsed.EscapedPath()
	if strings.EqualFold(parsed.Scheme, "ldapi") && parsed.Host == "" {
		rawPath = ""
	}
	if rawPath != "" && rawPath != "/" {
		dnText, err := url.PathUnescape(strings.TrimPrefix(rawPath, "/"))
		if err != nil {
			return chainReferralTarget{}, err
		}
		dn, err := directory.ParseDN(dnText)
		if err != nil {
			return chainReferralTarget{}, fmt.Errorf("referral DN: %w", err)
		}
		target.dn = &dn
	}
	search, isSearch := request.(ldapwire.SearchRequest)
	if !isSearch {
		return target, nil
	}
	components, ok := referralURLQuery(parsed)
	if !ok {
		return chainReferralTarget{}, fmt.Errorf("invalid LDAP referral URL %q", reference)
	}
	if len(components) > 1 && components[1] != "" {
		var scope directory.Scope
		switch strings.ToLower(components[1]) {
		case "base":
			scope = directory.ScopeBase
		case "one":
			scope = directory.ScopeSingleLevel
		case "sub":
			scope = directory.ScopeWholeSubtree
		case "subordinate":
			scope = directory.ScopeChildren
		default:
			return chainReferralTarget{}, fmt.Errorf("unknown referral scope %q", components[1])
		}
		target.scope = &scope
	} else if continuation && search.Scope == directory.ScopeSingleLevel {
		scope := directory.ScopeBase
		target.scope = &scope
	}
	if len(components) > 2 && components[2] != "" {
		filterText, err := url.PathUnescape(components[2])
		if err != nil {
			return chainReferralTarget{}, err
		}
		if !strings.EqualFold(filterText, "(objectClass=*)") {
			packet, err := ldap.CompileFilter(filterText)
			if err != nil {
				return chainReferralTarget{}, err
			}
			filter, err := ldapwire.DecodeFilter(packet.Bytes())
			if err != nil {
				return chainReferralTarget{}, err
			}
			target.filter = &filter
		}
	}
	return target, nil
}

func chainEndpointKeyForReferral(parsed *url.URL) (string, error) {
	if parsed == nil || parsed.Scheme == "" {
		return "", errors.New("referral URL has no scheme")
	}
	clone := *parsed
	if !strings.EqualFold(parsed.Scheme, "ldapi") || parsed.Host != "" {
		clone.Path = ""
		clone.RawPath = ""
	}
	clone.RawQuery = ""
	clone.ForceQuery = false
	return chainEndpointKey(&clone)
}

func chainReferralEndpointURI(parsed *url.URL) string {
	if strings.EqualFold(parsed.Scheme, "ldapi") {
		return "ldapi://" + url.PathEscape(chainLDAPISocket(parsed))
	}
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host
}

func encodeChainedPasswordModifyValue(
	request ldapwire.PasswordModifyRequestValue,
) []byte {
	packet := ber.NewSequence("PasswordModifyRequestValue")
	appendValue := func(tag uint64, value []byte, present bool) {
		if !present {
			return
		}
		child := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			ber.Tag(tag),
			nil,
			"passwordModifyValue",
		)
		_, _ = child.Data.Write(value)
		packet.AppendChild(child)
	}
	appendValue(0, request.UserIdentity, request.HasUserIdentity)
	appendValue(1, request.OldPassword, request.HasOldPassword)
	appendValue(2, request.NewPassword, request.HasNewPassword)
	return packet.Bytes()
}

func validateChainResponseEnvelope(
	packet *ber.Packet,
	messageID int64,
) (uint64, error) {
	if !syncConsumerPacketIs(
		packet,
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
	) || (len(packet.Children) != 2 && len(packet.Children) != 3) {
		return 0, errors.New("malformed chained LDAP response envelope")
	}
	responseID, err := syncConsumerPacketInteger(packet.Children[0])
	if err != nil || responseID != messageID {
		return 0, fmt.Errorf(
			"chained LDAP response message ID is %d, want %d",
			responseID,
			messageID,
		)
	}
	operation := packet.Children[1]
	if operation.ClassType != ber.ClassApplication {
		return 0, errors.New("chained LDAP response is not an application operation")
	}
	return uint64(operation.Tag), nil
}

func chainLDAPResult(
	packet *ber.Packet,
	messageID int64,
	responseTag uint64,
) (ldapwire.Result, error) {
	parsed, err := parseSyncConsumerLDAPResult(packet, messageID, responseTag)
	if err != nil {
		return ldapwire.Result{}, err
	}
	result := ldapwire.Result{
		Code:              ldapwire.ResultCode(parsed.code),
		MatchedDN:         parsed.matchedDN,
		DiagnosticMessage: parsed.diagnosticMessage,
	}
	operation := packet.Children[1]
	for _, child := range operation.Children[3:] {
		if !syncConsumerPacketIs(child, ber.ClassContext, ber.TypeConstructed, 3) {
			continue
		}
		for _, reference := range child.Children {
			value, err := syncConsumerPacketBytes(reference)
			if err != nil {
				return ldapwire.Result{}, errors.New("malformed chained LDAP referral")
			}
			result.Referrals = append(result.Referrals, string(value))
		}
	}
	return result, nil
}

func chainSearchReferences(packet *ber.Packet) ([]string, error) {
	if len(packet.Children) < 2 {
		return nil, errors.New("malformed chained search reference")
	}
	operation := packet.Children[1]
	var references []string
	for _, child := range operation.Children {
		value, err := syncConsumerPacketBytes(child)
		if err != nil {
			return nil, errors.New("malformed chained search reference URL")
		}
		references = append(references, string(value))
	}
	return references, nil
}

func sanitizeChainedSearchEntry(
	packet *ber.Packet,
	registry *schema.Registry,
	removeUnknown bool,
) error {
	if len(packet.Children) < 2 || len(packet.Children[1].Children) != 2 {
		return errors.New("malformed chained search entry")
	}
	attributes := packet.Children[1].Children[1]
	filtered := attributes.Children[:0]
	for _, attribute := range attributes.Children {
		if len(attribute.Children) != 2 {
			return errors.New("malformed chained search entry attribute")
		}
		descriptionBytes, err := syncConsumerPacketBytes(attribute.Children[0])
		if err != nil {
			return errors.New("malformed chained search entry attribute description")
		}
		description := string(descriptionBytes)
		if strings.EqualFold(description, "entryDN") {
			continue
		}
		if !removeUnknown {
			filtered = append(filtered, attribute)
			continue
		}
		if _, known := registry.AttributeType(description); !known {
			continue
		}
		if strings.EqualFold(strings.SplitN(description, ";", 2)[0], "objectClass") {
			values := attribute.Children[1]
			knownValues := values.Children[:0]
			for _, value := range values.Children {
				raw, valueErr := syncConsumerPacketBytes(value)
				if valueErr != nil {
					return errors.New("malformed chained objectClass value")
				}
				if _, known := registry.ObjectClass(string(raw)); known {
					knownValues = append(knownValues, value)
				}
			}
			values.Children = knownValues
			if len(knownValues) == 0 {
				continue
			}
		}
		filtered = append(filtered, attribute)
	}
	attributes.Children = filtered
	return nil
}

func chainFilterHasUndefined(registry *schema.Registry, filter directory.Filter) bool {
	if filter.Attribute != "" {
		if _, known := registry.AttributeType(filter.Attribute); !known {
			return true
		}
	}
	for _, child := range filter.Children {
		if chainFilterHasUndefined(registry, child) {
			return true
		}
	}
	return false
}

func rewriteChainAbsoluteFilters(filter directory.Filter) directory.Filter {
	filter.Children = append([]directory.Filter(nil), filter.Children...)
	for index := range filter.Children {
		filter.Children[index] = rewriteChainAbsoluteFilters(filter.Children[index])
	}
	if len(filter.Children) != 0 {
		return filter
	}
	switch filter.Kind {
	case directory.FilterAnd:
		return directory.Filter{
			Kind:      directory.FilterPresent,
			Attribute: "objectClass",
		}
	case directory.FilterOr:
		return directory.Filter{
			Kind: directory.FilterNot,
			Children: []directory.Filter{{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			}},
		}
	default:
		return filter
	}
}

func emptySuccessfulChainSearch(messageID int64) chainAttempt {
	encoded := ldapwire.EncodeSearchResultDone(
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		return chainAttempt{transportErr: err}
	}
	return chainAttempt{
		packets:   []*ber.Packet{packet},
		result:    ldapwire.Result{Code: ldapwire.ResultSuccess},
		hasResult: true,
	}
}

func discoverChainAbsoluteFilters(transport *syncConsumerTransport) (bool, error) {
	return discoverChainRootDSEValue(
		transport,
		"supportedFeatures",
		absoluteFiltersFeatureOID,
	)
}

func discoverChainCancel(transport *syncConsumerTransport) (bool, error) {
	return discoverChainRootDSEValue(transport, "supportedExtension", cancelOID)
}

func discoverChainRootDSEValue(
	transport *syncConsumerTransport,
	description string,
	expected string,
) (bool, error) {
	messageID := transport.nextMessageID()
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.SearchRequest{
			Scope:     directory.ScopeBase,
			SizeLimit: 1,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{description},
		},
	})
	if err != nil {
		return false, err
	}
	if err := transport.setOperationDeadline(); err != nil {
		return false, err
	}
	connection := transport.currentConnection()
	if err := writeSyncConsumerPacket(connection, encoded); err != nil {
		return false, err
	}
	found := false
	for {
		packet, err := readSyncConsumerPacket(connection)
		if err != nil {
			return false, err
		}
		tag, err := validateChainResponseEnvelope(packet, messageID)
		if err != nil {
			return false, err
		}
		switch tag {
		case ldapwire.ApplicationSearchResultEntry:
			found = found || chainedEntryHasValue(
				packet,
				description,
				expected,
			)
		case ldapwire.ApplicationSearchResultReference,
			ldapwire.ApplicationIntermediateResponse:
			continue
		case ldapwire.ApplicationSearchResultDone:
			result, err := chainLDAPResult(
				packet,
				messageID,
				ldapwire.ApplicationSearchResultDone,
			)
			if err != nil {
				return false, err
			}
			return found && result.Code == ldapwire.ResultSuccess, nil
		default:
			return false, fmt.Errorf("unexpected feature discovery response tag %d", tag)
		}
	}
}

func chainedEntryHasValue(packet *ber.Packet, description, expected string) bool {
	if len(packet.Children) < 2 || len(packet.Children[1].Children) != 2 {
		return false
	}
	for _, attribute := range packet.Children[1].Children[1].Children {
		if len(attribute.Children) != 2 {
			continue
		}
		rawDescription, err := syncConsumerPacketBytes(attribute.Children[0])
		if err != nil || !strings.EqualFold(string(rawDescription), description) {
			continue
		}
		for _, value := range attribute.Children[1].Children {
			raw, valueErr := syncConsumerPacketBytes(value)
			if valueErr == nil && strings.EqualFold(string(raw), expected) {
				return true
			}
		}
	}
	return false
}

func chainSessionTrackingControl(state *connectionState) (ldapwire.Control, bool) {
	ip := ""
	if state.connection != nil && state.connection.RemoteAddr() != nil {
		address := state.connection.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(address); err == nil {
			ip = host
		}
	}
	identifier := state.boundDN
	if ip == "" && identifier == "" {
		return ldapwire.Control{}, false
	}
	value := ldapwire.EncodeSessionTrackingValue(ldapwire.SessionTrackingValue{
		SessionSourceIP:           []byte(ip),
		FormatOID:                 []byte(sessionTrackingUsernameFormatOID),
		SessionTrackingIdentifier: []byte(identifier),
	})
	return ldapwire.Control{
		OID:      sessionTrackingControlOID,
		Value:    value,
		HasValue: true,
	}, true
}

func appendChainSessionTrackingControl(
	controls []ldapwire.Control,
	state *connectionState,
) []ldapwire.Control {
	control, ok := chainSessionTrackingControl(state)
	if !ok {
		return controls
	}
	return append(controls, control)
}

func withoutSearchDone(packets []*ber.Packet) []*ber.Packet {
	result := make([]*ber.Packet, 0, len(packets))
	for _, packet := range packets {
		if len(packet.Children) >= 2 &&
			uint64(packet.Children[1].Tag) == ldapwire.ApplicationSearchResultDone {
			continue
		}
		result = append(result, packet)
	}
	return result
}

func chainAttemptIsUsable(request ldapwire.Request, attempt chainAttempt) bool {
	if !attempt.hasResult {
		return false
	}
	if _, search := request.(ldapwire.SearchRequest); search && attempt.hasEntries {
		return true
	}
	switch attempt.result.Code {
	case ldapwire.ResultSuccess,
		ldapwire.ResultCompareFalse,
		ldapwire.ResultCompareTrue,
		ldapwire.ResultReferral,
		ldapwire.ResultTimeLimitExceeded,
		ldapwire.ResultSizeLimitExceeded,
		ldapwire.ResultAdminLimitExceeded:
		return true
	default:
		return false
	}
}

func (server *Server) writeChainedPackets(
	connection net.Conn,
	message ldapwire.Message,
	packets []*ber.Packet,
) error {
	for _, packet := range packets {
		if len(packet.Children) < 2 {
			return errors.New("malformed buffered chained LDAP response")
		}
		tag := uint64(packet.Children[1].Tag)
		final := tag == ldapwire.ApplicationSearchResultDone ||
			tag == ldapwire.ApplicationBindResponse ||
			tag == ldapwire.ApplicationModifyResponse ||
			tag == ldapwire.ApplicationAddResponse ||
			tag == ldapwire.ApplicationDeleteResponse ||
			tag == ldapwire.ApplicationModifyDNResponse ||
			tag == ldapwire.ApplicationCompareResponse ||
			tag == ldapwire.ApplicationExtendedResponse
		if final {
			if finalizer, ok := connection.(interface {
				beginFinalResponse() error
			}); ok {
				if err := finalizer.beginFinalResponse(); err != nil {
					return err
				}
			}
		}
		packet.Children[0] = ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			message.ID,
			"messageID",
		)
		rebuildChainedPacket(packet)
		if err := ldapwire.Write(connection, packet.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func rebuildChainedPacket(packet *ber.Packet) {
	if packet == nil || packet.TagType != ber.TypeConstructed {
		return
	}
	packet.Data.Reset()
	for _, child := range packet.Children {
		rebuildChainedPacket(child)
		_, _ = packet.Data.Write(child.Bytes())
	}
}

func hasLDAPControl(controls []ldapwire.Control, oid string) bool {
	for _, control := range controls {
		if control.OID == oid {
			return true
		}
	}
	return false
}

func parseChainingBehaviorControls(
	controls []ldapwire.Control,
) (*chainBehaviorRequest, *ldapwire.Result) {
	var parsed *chainBehaviorRequest
	paged := false
	for _, control := range controls {
		switch control.OID {
		case pagedResultsControlOID:
			paged = true
		case chainingBehaviorControlOID:
			if parsed != nil {
				result := ldapwire.ResultError(
					ldapwire.ResultProtocolError,
					"Chaining behavior control specified multiple times",
				)
				return nil, &result
			}
			request, err := decodeChainingBehaviorControl(control)
			if err != nil {
				result := ldapwire.ResultError(ldapwire.ResultProtocolError, err.Error())
				return nil, &result
			}
			parsed = &request
		}
	}
	if parsed != nil && paged {
		result := ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"Chaining behavior control specified with pagedResults control",
		)
		return nil, &result
	}
	return parsed, nil
}

func decodeChainingBehaviorControl(control ldapwire.Control) (chainBehaviorRequest, error) {
	request := chainBehaviorRequest{
		resolve:      chainBehaviorChainingPreferred,
		continuation: chainBehaviorChainingPreferred,
		critical:     control.Critical,
	}
	if !control.HasValue || len(control.Value) == 0 {
		return request, nil
	}
	packet, err := ber.DecodePacketErr(control.Value)
	if err != nil || !syncConsumerPacketIs(
		packet,
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
	) || len(packet.Bytes()) != len(control.Value) {
		return chainBehaviorRequest{}, errors.New(
			"Chaining behavior control decoding error",
		)
	}
	if len(packet.Children) < 1 || len(packet.Children) > 2 {
		return chainBehaviorRequest{}, errors.New(
			"Chaining behavior control must contain one or two behaviors",
		)
	}
	behaviors := make([]chainBehavior, len(packet.Children))
	for index, child := range packet.Children {
		if !syncConsumerPacketIs(
			child,
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
		) {
			return chainBehaviorRequest{}, errors.New(
				"Chaining behavior control behavior decoding error",
			)
		}
		value, err := syncConsumerPacketInteger(child)
		if err != nil || value < int64(chainBehaviorChainingPreferred) ||
			value > int64(chainBehaviorReferralsRequired) {
			return chainBehaviorRequest{}, errors.New(
				"Chaining behavior control contains an unknown behavior",
			)
		}
		behaviors[index] = chainBehavior(value)
	}
	request.resolve = behaviors[0]
	if len(behaviors) == 2 {
		request.continuation = behaviors[1]
	}
	return request, nil
}

func cannotChainResult() ldapwire.Result {
	return ldapwire.ResultError(
		chainCannotChainResultCode,
		"operation cannot be completed without chaining",
	)
}
