package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func saslAuthorizationUsesProxyBackend(database *runtimeDatabase) bool {
	return database != nil &&
		(database.ldapBackend != nil || database.metaBackend != nil)
}

func (server *Server) lookupProxySASLAuthorizationEntry(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
	attributes []string,
	subjectDN string,
) (directory.Entry, bool, error) {
	comparisonDN, err := normalizeSASLAuthorizationDatabaseDN(
		runtime,
		&database,
		dn,
	)
	if err != nil {
		return directory.Entry{}, false, err
	}
	entries, err := server.searchProxySASLAuthorization(
		ctx,
		runtime,
		database,
		ldapwire.SearchRequest{
			BaseDN:       comparisonDN.String(),
			Scope:        directory.ScopeBase,
			DerefAliases: ldapwire.NeverDerefAliases,
			SizeLimit:    2,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: append([]string(nil), attributes...),
		},
		subjectDN,
	)
	if err != nil {
		return directory.Entry{}, false, err
	}
	defer clearSASLAuthorizationEntries(entries)
	var found *directory.Entry
	for _, entry := range entries {
		entryDN, parseErr := directory.ParseDN(entry.DN)
		if parseErr == nil {
			entryDN, parseErr = normalizeSASLAuthorizationDatabaseDN(
				runtime,
				&database,
				entryDN,
			)
		}
		if parseErr != nil || !entryDN.Equal(comparisonDN) {
			return directory.Entry{}, false, fmt.Errorf(
				"SASL authorization base search for %q returned unexpected entry %q",
				dn.String(),
				entry.DN,
			)
		}
		if found != nil {
			return directory.Entry{}, false, fmt.Errorf(
				"SASL authorization base search for %q returned multiple entries",
				dn.String(),
			)
		}
		copy := entry
		found = &copy
	}
	if found == nil {
		return directory.Entry{}, false, nil
	}
	return found.Clone(), true, nil
}

func (server *Server) searchProxySASLAuthorization(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	subjectDN string,
) ([]directory.Entry, error) {
	state := newSASLAuthorizationBackendState(runtime, subjectDN)
	defer state.metaTransports.close()

	switch {
	case database.ldapBackend != nil:
		return server.searchLDAPBackendSASLAuthorization(
			ctx,
			state,
			database,
			request,
		)
	case database.metaBackend != nil:
		return server.searchMetaBackendSASLAuthorization(
			ctx,
			state,
			database,
			request,
		)
	default:
		return nil, errors.New("SASL authorization search has no proxy backend")
	}
}

func (server *Server) searchLDAPBackendSASLAuthorization(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
) ([]directory.Entry, error) {
	message := ldapwire.Message{ID: 1, Request: request}
	var attempt chainAttempt
	defer clearSASLCredentialAttempt(&attempt)
	for index, configured := range database.ldapBackend.remotes {
		attempts := ldapBackendRemoteAttempts(len(database.ldapBackend.remotes))
		for current := 0; current < attempts; current++ {
			attempt = server.executeLDAPBackendTarget(
				ctx,
				state,
				*database.ldapBackend,
				saslAuthorizationLDAPRemote(configured),
				message,
			)
			if !ldapBackendShouldFailover(ctx, attempt) {
				break
			}
		}
		if !ldapBackendShouldFailover(ctx, attempt) ||
			index == len(database.ldapBackend.remotes)-1 {
			break
		}
	}
	entries, err := decodeSASLAuthorizationSearchAttempt(attempt)
	if err != nil {
		return nil, fmt.Errorf("back-ldap SASL authorization search: %w", err)
	}
	return entries, nil
}

func (server *Server) searchMetaBackendSASLAuthorization(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
) ([]directory.Entry, error) {
	plans, err := database.metaBackend.searchPlans(request)
	if err != nil {
		return nil, fmt.Errorf("plan back-meta SASL authorization search: %w", err)
	}
	var entries []directory.Entry
	completed := false
	defer func() {
		if !completed {
			clearSASLAuthorizationEntries(entries)
		}
	}()
	for _, plan := range plans {
		message := ldapwire.Message{ID: 1, Request: plan.request}
		mapped, err := mapMetaRequestToRemote(plan.target.rwm, message)
		if err != nil {
			return nil, fmt.Errorf(
				"map back-meta SASL authorization request for target %q: %w",
				plan.target.configDNKey,
				err,
			)
		}
		attempt, err := server.executeMetaBackendSASLCredentialSearch(
			ctx,
			state,
			plan.target,
			mapped,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"back-meta SASL authorization target %q: %w",
				plan.target.configDNKey,
				err,
			)
		}
		remotePackets := append([]*ber.Packet(nil), attempt.packets...)
		attempt, err = mapMetaAttemptToLocal(plan.target.rwm, attempt)
		clearSASLCredentialPackets(remotePackets)
		if err != nil {
			clearSASLCredentialAttempt(&attempt)
			return nil, fmt.Errorf(
				"map back-meta SASL authorization result for target %q: %w",
				plan.target.configDNKey,
				err,
			)
		}
		found, err := decodeSASLAuthorizationSearchAttempt(attempt)
		clearSASLCredentialAttempt(&attempt)
		if err != nil {
			return nil, fmt.Errorf(
				"back-meta SASL authorization target %q: %w",
				plan.target.configDNKey,
				err,
			)
		}
		entries = append(entries, found...)
	}
	completed = true
	return entries, nil
}

func decodeSASLAuthorizationSearchAttempt(
	attempt chainAttempt,
) ([]directory.Entry, error) {
	if attempt.transportErr != nil {
		return nil, attempt.transportErr
	}
	if !attempt.hasResult {
		return nil, errors.New("remote search returned no LDAP result")
	}
	switch attempt.result.Code {
	case ldapwire.ResultSuccess:
	case ldapwire.ResultNoSuchObject:
		return nil, nil
	case ldapwire.ResultSizeLimitExceeded:
		return nil, errStopSASLAuthzSearch
	default:
		return nil, fmt.Errorf(
			"remote search returned LDAP result %d: %s",
			attempt.result.Code,
			attempt.result.DiagnosticMessage,
		)
	}

	var entries []directory.Entry
	for _, packet := range attempt.packets {
		if metaPacketTag(packet) != ldapwire.ApplicationSearchResultEntry {
			continue
		}
		entry, err := decodeTranslucentSearchEntry(packet)
		if err != nil {
			clearSASLAuthorizationEntries(entries)
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func saslAuthorizationLDAPRemote(
	configured chainRemoteConfiguration,
) chainRemoteConfiguration {
	remote := configured.clone()
	if remote.aclBind.bindMethod != "" {
		remote.bind = remote.aclBind
		remote.bind.credentials = bytes.Clone(remote.aclBind.credentials)
		return remote
	}
	return saslIDAssertCredentialRemote(remote)
}

func clearSASLAuthorizationEntries(entries []directory.Entry) {
	for index := range entries {
		clearSASLCredentialEntry(&entries[index])
	}
}

func newSASLAuthorizationBackendState(
	runtime *runtimeState,
	subjectDN string,
) *connectionState {
	// Auth-check operations use the privileged ACL-bind/IDAssert connection.
	// The subject is retained only in the isolated state and is never asserted
	// to the provider, matching OpenLDAP's LDAP_BACK_IDASSERT_NOASSERT path.
	return &connectionState{
		boundDN:         subjectDN,
		operationRealDN: subjectDN,
		protocolVersion: 3,
		runtime:         runtime,
		metaTransports:  newMetaTransportCache(time.Now),
	}
}
