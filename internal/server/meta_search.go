package server

import (
	"context"
	"errors"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type metaSearchPlan struct {
	target  metaBackendTargetRuntimeConfiguration
	request ldapwire.SearchRequest
}

func (configuration *metaBackendRuntimeConfiguration) searchPlans(
	request ldapwire.SearchRequest,
) ([]metaSearchPlan, error) {
	if configuration == nil {
		return nil, nil
	}
	base, err := configuration.parseDN(request.BaseDN)
	if err != nil {
		return nil, err
	}
	plans := make([]metaSearchPlan, 0, len(configuration.targets))
	filterText := accesslogFilterText(request.Filter)
	for _, configured := range configuration.targets {
		target := configured.clone()
		if target.onlineURIUnavailable {
			continue
		}
		candidate := request
		switch {
		case target.suffix.Equal(base), target.suffix.AncestorOf(base):
			if !target.matchesDN(base, request.Scope) {
				continue
			}
		case base.AncestorOf(target.suffix):
			parent, hasParent := target.suffix.Parent()
			directChild := hasParent && parent.Equal(base)
			switch request.Scope {
			case directory.ScopeWholeSubtree:
				candidate.BaseDN = target.suffix.String()
				candidate.Scope = target.scope
			case directory.ScopeSingleLevel:
				if !directChild {
					continue
				}
				candidate.BaseDN = target.suffix.String()
				candidate.Scope = directory.ScopeBase
			case directory.ScopeChildren:
				if !directChild {
					continue
				}
				candidate.BaseDN = target.suffix.String()
				candidate.Scope = target.scope
			default:
				continue
			}
		default:
			continue
		}
		if !target.matchesFilter(filterText) {
			continue
		}
		plans = append(plans, metaSearchPlan{target: target, request: candidate})
	}
	return plans, nil
}

func (server *Server) tryMetaBackendSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
) (bool, error) {
	if tracker, ok := connection.(interface{ enableMetaBackendSearch() }); ok {
		tracker.enableMetaBackendSearch()
	}
	plans, err := database.metaBackend.searchPlans(request)
	if err != nil {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "invalid search base DN"),
		)
	}
	if len(plans) == 0 {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(ldapwire.ResultNoSuchObject, "no back-meta target"),
		)
	}
	limit := effectiveDatabaseSearchLimit(
		state.runtime,
		database,
		state.boundDN,
		server.config.MaxSearchEntries,
		request.SizeLimit,
	)
	for index := range plans {
		plans[index].request.SizeLimit = limit
	}

	return server.runMetaBackendSearch(
		ctx,
		connection,
		state,
		message,
		database,
		request,
		plans,
		limit,
	)
}

func finalizeMetaSearchResult(
	result *ldapwire.Result,
	valid bool,
	onError string,
	reportFailure *ldapwire.Result,
	terminalLimit bool,
) {
	if valid && result.Code == ldapwire.ResultNoSuchObject {
		result.Code = ldapwire.ResultSuccess
	}
	if valid && onError == "continue" && reportFailure != nil && !terminalLimit {
		result.Code = ldapwire.ResultSuccess
		result.MatchedDN = ""
		result.DiagnosticMessage = ""
	}
	if onError == "report" && reportFailure != nil && !terminalLimit {
		*result = *reportFailure
	}
}

func metaSearchResultIsError(code ldapwire.ResultCode) bool {
	switch code {
	case ldapwire.ResultSuccess,
		ldapwire.ResultNoSuchObject,
		ldapwire.ResultReferral:
		return false
	default:
		return true
	}
}

func mergeMetaSearchResult(
	combined *ldapwire.Result,
	candidate ldapwire.Result,
	valid *bool,
) {
	if len(candidate.MatchedDN) > len(combined.MatchedDN) {
		combined.MatchedDN = candidate.MatchedDN
	}
	combined.Referrals = append(combined.Referrals, candidate.Referrals...)
	switch candidate.Code {
	case ldapwire.ResultSuccess:
		*valid = true
		combined.Code = ldapwire.ResultSuccess
		combined.DiagnosticMessage = candidate.DiagnosticMessage
	case ldapwire.ResultReferral:
		*valid = true
		if combined.Code != ldapwire.ResultSuccess {
			combined.Code = ldapwire.ResultReferral
			combined.DiagnosticMessage = candidate.DiagnosticMessage
		}
	case ldapwire.ResultNoSuchObject:
		if !*valid {
			combined.Code = candidate.Code
			combined.DiagnosticMessage = candidate.DiagnosticMessage
		}
	default:
		combined.Code = candidate.Code
		combined.DiagnosticMessage = candidate.DiagnosticMessage
	}
}

func metaPacketTag(packet *ber.Packet) uint64 {
	if packet == nil || len(packet.Children) < 2 {
		return 0
	}
	return uint64(packet.Children[1].Tag)
}

func metaSearchDonePacket(result ldapwire.Result) (*ber.Packet, error) {
	packet, err := ber.DecodePacketErr(ldapwire.EncodeSearchResultDone(0, result, nil))
	if err != nil {
		return nil, err
	}
	if len(packet.Children) != 2 {
		return nil, errors.New("encode back-meta SearchResultDone")
	}
	return packet, nil
}
