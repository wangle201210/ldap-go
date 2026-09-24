package server

import (
	"context"
	"net"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Small local reads still evaluate authorization in their current snapshot.
// Unsupported or speculative failures use the general handler without output;
// no result, base entry, or authorization decision is published to a cache.
func (server *Server) trySmallNonRootSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
	base directory.DN,
	database *runtimeDatabase,
) (bool, error) {
	if database.rootDN != nil && state.boundDN == database.rootDN.String() {
		return false, nil
	}
	if state.boundDN == "" || state.protocolVersion != 3 || base.Depth() == 0 ||
		len(message.Controls) != 0 || message.ControlsPresent ||
		state.passwordPolicyRestrictedDN != "" || state.accountUsabilityRequested ||
		isNoOpSearch(ctx) || request.SizeLimit < 0 || request.TimeLimit != 0 || request.DerefAliases != 0 ||
		len(database.searchSizeLimits) != 0 || database.shadow || database.subordinate || database.explicitGlue ||
		!databaseSearchResultCacheSafe(state.runtime, *database) ||
		!smallIndexedRuntimeProjectionSafe(state.runtime) ||
		!databaseUsesRuntimeDNIdentity(*database, state.runtime.schema) ||
		!localProjectionReadOnly(state.runtime, nil) || !state.runtime.access.CanBatchValues() ||
		!plainBoltSearchStore(server.config.Store) || isConfigurationDN(base) ||
		isRuntimeSubschemaDN(state.runtime, base) || monitorDatabaseIndexForDN(state.runtime.databases, base) >= 0 {
		return false, nil
	}
	basePresence := request.Scope == directory.ScopeBase && request.Filter.Kind == directory.FilterPresent &&
		strings.EqualFold(request.Filter.Attribute, "objectClass")
	if !basePresence && request.Filter.Kind != directory.FilterEquality {
		return false, nil
	}
	if !basePresence && (state.runtime.schema.IsOperational(request.Filter.Attribute) ||
		state.runtime.schema.IsCollective(request.Filter.Attribute)) {
		return false, nil
	}
	switch request.Scope {
	case directory.ScopeBase, directory.ScopeSingleLevel, directory.ScopeWholeSubtree:
	default:
		return false, nil
	}
	if len(request.Attributes) == 0 || autoCASearchRequested(state.runtime.schema, request.Attributes) {
		return false, nil
	}
	for _, attribute := range request.Attributes {
		if attribute == "" || attribute == "*" || attribute == "+" || strings.HasPrefix(attribute, "@") ||
			state.runtime.schema.IsOperational(attribute) || state.runtime.schema.IsCollective(attribute) {
			return false, nil
		}
	}
	selection, prepared := state.runtime.searchSelections.get(state.runtime.schema, request.Attributes)
	if !prepared {
		return false, nil
	}
	routes := databaseSearchRoutesFromNormalizedBase(state.runtime.databases, base, request.Scope)
	if len(routes) != 1 {
		return false, nil
	}
	limits := effectiveDatabaseSearchExecutionLimits(state.runtime, *database, state.boundDN,
		server.config.MaxSearchEntries, request.SizeLimit, request.TimeLimit)
	maximum := smallIndexedSearchMaximumCandidates
	if basePresence {
		maximum = 1
	}
	if limits.root || limits.time != 0 || limits.unchecked != -1 || limits.size < 1 {
		return false, nil
	}
	select {
	case <-ctx.Done():
		return false, nil
	default:
	}
	revision, available := server.currentStorageSnapshotRevision(ctx)
	if !available || !database.equalityIndexInit.readyFor(revision, available) {
		return false, nil
	}

	var entries [smallIndexedSearchMaximumCandidates]directory.Entry
	var count int
	var retainedBytes int64
	defer func() {
		if retainedBytes > 0 {
			server.searchMemoryLimiter.release(retainedBytes)
		}
	}()
	complete := false
	var failure *ldapwire.Result
	partialResults := false
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		snapshot, known := storage.ReaderSnapshotRevision(reader)
		if !known || !database.equalityIndexInit.readyFor(snapshot, known) {
			return errStopSearch
		}
		tx := readerForDatabase(reader, *database)
		if !localProjectionReadOnly(state.runtime, tx) {
			return errStopSearch
		}
		if !databaseCanReuseSearchBase(*database, state.runtime.schema, base) {
			var err error
			base, err = storage.NormalizeReaderDN(tx, base)
			if err != nil {
				return err
			}
		}
		baseEntry, err := tx.Get(base)
		if err != nil {
			return err
		}
		plan, err := runtimeCollectiveAttributePlan(state.runtime, database.partition, tx)
		if err != nil {
			return err
		}
		if len(plan.sources) != 0 || smallIndexedEntryIsSpecial(state.runtime, baseEntry) ||
			!server.allowed(state.runtime, tx, state.boundDN, baseEntry, "entry", nil, acl.Search) {
			return errStopSearch
		}
		visit := func(entry directory.Entry) error {
			inScope, err := smallIndexedEntryInScope(state.runtime, database, tx, base, entry, request.Scope)
			if err != nil || !inScope {
				return err
			}
			if smallIndexedEntryIsSpecial(state.runtime, entry) {
				return errStopSearch
			}
			matches, err := server.filterMatches(state.runtime, tx, state.boundDN, entry, request.Filter)
			if err != nil || !matches {
				return err
			}
			if !server.allowed(state.runtime, tx, state.boundDN, entry, "entry", nil, acl.Read) {
				return nil
			}
			readable := server.attributesWithPrivilege(state.runtime, tx, state.boundDN, entry, acl.Read, request.TypesOnly)
			readable = server.applyAllowedAttributes(state.runtime, tx, state.boundDN, entry, readable, request.Attributes, request.TypesOnly)
			selected := selection.Select(readable, request.TypesOnly)
			// Match the general visitor: filter and project the next surviving
			// entry before declaring overflow, but do not reserve or retain it.
			if count >= limits.size {
				result := ldapwire.ResultError(ldapwire.ResultSizeLimitExceeded, "")
				failure = &result
				partialResults = true
				return errStopSearch
			}
			size := max(int64(1), searchCandidateRetainedBytes(searchCandidate{selected: selected, dn: entry.DN}))
			if size > server.config.MaxSearchCandidateBytes-retainedBytes {
				result := ldapwire.ResultError(ldapwire.ResultAdminLimitExceeded, "search candidate budget exceeded")
				failure = &result
				return errStopSearch
			}
			if !server.searchMemoryLimiter.tryAcquire(size) {
				result := ldapwire.ResultError(ldapwire.ResultAdminLimitExceeded, "process search memory budget exceeded")
				failure = &result
				return errStopSearch
			}
			retainedBytes += size
			entries[count] = selected
			count++
			return nil
		}
		if basePresence {
			// Match the general base-candidate path after a rename, using this
			// snapshot's already-read entry and the physical normalized identity.
			dn, err := directory.ParseDNWithIdentityKey(baseEntry.DN, base.Key())
			if err != nil {
				return err
			}
			if err := visit(baseEntry.WithNormalizedDNHint(dn, "")); err != nil {
				return err
			}
			complete = true
			return nil
		}
		complete, _, err = storage.ForEachBoundedReadOnlyFilterCandidate(tx, request.Filter, maximum, visit)
		return err
	})
	if failure != nil {
		var partial []directory.Entry
		if partialResults {
			partial = entries[:count]
		}
		return true, server.writeSearchResult(connection, message.ID, state, nil, nil, partial, *failure, pagedSearchCursor{}, false)
	}
	if err != nil || !complete {
		return false, nil
	}
	return true, server.writeSearchResult(connection, message.ID, state, nil, nil, entries[:count],
		ldapwire.Result{Code: ldapwire.ResultSuccess}, pagedSearchCursor{}, false)
}

// Speculative reads must not repeat application-defined Store/Get callbacks.
// Only the server's concrete wrappers around Bolt have the needed semantics.
func plainBoltSearchStore(store storage.Store) bool {
	for {
		switch value := store.(type) {
		case *homedirEffectStore:
			if value == nil {
				return false
			}
			store = value.Store
		case *accessContextStore:
			if value == nil {
				return false
			}
			store = value.Store
		case *storage.Bolt:
			return value != nil
		default:
			return false
		}
	}
}
