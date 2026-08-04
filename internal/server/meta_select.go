package server

import (
	"context"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func (server *Server) selectMetaBackendTarget(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	dn directory.DN,
	add bool,
) (*metaBackendTargetRuntimeConfiguration, *ldapwire.Result) {
	candidates := database.metaBackend.candidateTargetsForDN(dn)
	if cached := server.metaRoutes.lookup(database.metaBackend, dn); cached != "" {
		for index := range candidates {
			if candidates[index].configDNKey == cached {
				return &candidates[index], nil
			}
		}
	}
	selected, found, failure := server.probeMetaBackendCandidates(
		ctx,
		state,
		database,
		dn,
		candidates,
	)
	if failure != nil || found {
		if found {
			server.metaRoutes.store(database.metaBackend, dn, selected.configDNKey)
		}
		return selected, failure
	}
	if !add {
		result := ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
		return nil, &result
	}
	parent, hasParent := dn.Parent()
	if !hasParent {
		result := ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
		return nil, &result
	}
	parentCandidates := database.metaBackend.candidateTargetsForDN(parent)
	selected, found, failure = server.probeMetaBackendCandidates(
		ctx,
		state,
		database,
		parent,
		parentCandidates,
	)
	if failure != nil || found {
		if found {
			server.metaRoutes.store(database.metaBackend, parent, selected.configDNKey)
		}
		return selected, failure
	}
	result := ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
	return nil, &result
}

func (server *Server) probeMetaBackendCandidates(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	dn directory.DN,
	candidates []metaBackendTargetRuntimeConfiguration,
) (*metaBackendTargetRuntimeConfiguration, bool, *ldapwire.Result) {
	switch len(candidates) {
	case 0:
		return nil, false, nil
	case 1:
		return &candidates[0], true, nil
	}
	for _, target := range candidates {
		found, failure := server.probeMetaBackendTarget(
			ctx,
			state,
			database,
			target,
			dn,
		)
		if failure != nil {
			return nil, false, failure
		}
		if found {
			return &target, true, nil
		}
	}
	return nil, false, nil
}

func (server *Server) probeMetaBackendTarget(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	target metaBackendTargetRuntimeConfiguration,
	dn directory.DN,
) (bool, *ldapwire.Result) {
	message := ldapwire.Message{
		ID: 0,
		Request: ldapwire.SearchRequest{
			BaseDN:    dn.String(),
			Scope:     directory.ScopeBase,
			SizeLimit: 1,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{"1.1"},
		},
	}
	mapped, err := mapMetaRequestToRemote(target.rwm, message)
	if err != nil {
		result := metaBackendMappingFailure(err)
		return false, &result
	}
	attempt, _, failure := server.executeMetaBackendOperation(
		ctx,
		state,
		database,
		target,
		mapped,
	)
	if failure != nil {
		return false, failure
	}
	if !attempt.hasResult {
		result := ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			ldapBackendUnavailableDiagnostic,
		)
		return false, &result
	}
	switch attempt.result.Code {
	case ldapwire.ResultSuccess:
		return attempt.hasEntries, nil
	case ldapwire.ResultNoSuchObject:
		return false, nil
	default:
		result := attempt.result
		return false, &result
	}
}
