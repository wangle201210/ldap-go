package server

import (
	"context"
	"crypto/sha256"
	"net"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type searchRequestPrelude struct {
	base        directory.DN
	fingerprint [sha256.Size]byte
	revision    uint64
	baseReady   bool
	hasRevision bool
	cacheable   bool
	evaluated   bool
}

// Keep cache hits outside the full search's closure-captured candidate state.
// A miss carries its already evaluated base and cache eligibility forward.
func (server *Server) handleSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
) error {
	if handled, err := server.tryPcachePrivateSearch(connection, state, message, request); handled {
		return err
	}
	var prelude searchRequestPrelude
	if len(message.Controls) == 0 && state.passwordPolicyRestrictedDN == "" {
		base, err := normalizeConnectionSearchRequestBase(state, request.BaseDN)
		if err != nil {
			return server.writeSearchDone(connection, message.ID,
				ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
		}
		prelude.base, prelude.baseReady, prelude.evaluated = base, true, true
		if base.Depth() > 0 {
			if database := databaseForNormalizedDN(state.runtime, base); database != nil {
				cacheRequest := request
				cacheRequest.BaseDN = base.String()
				if fingerprint, cacheable := server.rootEqualitySearchCacheFingerprint(
					state, *database, cacheRequest, nil,
				); cacheable {
					if revision, available := server.currentStorageSnapshotRevision(ctx); available {
						if cached, found := state.runtime.searchResults.get(fingerprint, revision); found {
							return server.writeSearchResult(connection, message.ID, state, nil, nil,
								cached, ldapwire.Result{Code: ldapwire.ResultSuccess}, pagedSearchCursor{}, false)
						}
						prelude.fingerprint, prelude.revision = fingerprint, revision
						prelude.hasRevision, prelude.cacheable = true, true
						if handled, err := server.trySmallIndexedSearch(
							ctx, connection, state, message, request, prelude, database,
						); handled {
							return err
						}
					}
				}
				if handled, err := server.trySmallNonRootSearch(ctx, connection, state, message, request, base, database); handled {
					return err
				}
			}
		}
	}
	return server.handleUncachedSearch(ctx, connection, state, message, request, prelude)
}
