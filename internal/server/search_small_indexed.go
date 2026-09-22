package server

import (
	"context"
	"net"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Match the existing result-cache admission limit, counting raw candidates,
// including duplicates and entries outside the requested scope.
const smallIndexedSearchMaximumCandidates = 4

// The caller supplies the exact cache eligibility established by handleSearch.
// A false result leaves response/error handling entirely to handleUncachedSearch.
func (server *Server) trySmallIndexedSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
	prelude searchRequestPrelude,
	database *runtimeDatabase,
) (bool, error) {
	if !prelude.cacheable || !prelude.baseReady || !prelude.hasRevision ||
		prelude.base.Depth() == 0 || len(message.Controls) != 0 ||
		state.passwordPolicyRestrictedDN != "" || state.accountUsabilityRequested ||
		isNoOpSearch(ctx) || database.shadow || database.subordinate || database.explicitGlue ||
		!smallIndexedRuntimeProjectionSafe(state.runtime) ||
		isRuntimeSubschemaDN(state.runtime, prelude.base) ||
		monitorDatabaseIndexForDN(state.runtime.databases, prelude.base) >= 0 {
		return false, nil
	}
	// The general path prepares indexes before building the collective plan.
	// A speculative first lookup could otherwise fall back to a whole-directory
	// collective scan before that initialization has established index readiness.
	if !database.equalityIndexInit.readyFor(prelude.revision, prelude.hasRevision) {
		return false, nil
	}
	switch request.Scope {
	case directory.ScopeBase, directory.ScopeSingleLevel, directory.ScopeWholeSubtree:
	default:
		return false, nil
	}
	// Empty and object-class selections can expand into projected attributes.
	// Operational selectors and overlay-dependent filters were excluded upstream.
	if len(request.Attributes) == 0 || autoCASearchRequested(state.runtime.schema, request.Attributes) {
		return false, nil
	}
	for _, attribute := range request.Attributes {
		if attribute == "" || attribute == "*" || attribute == "+" ||
			strings.HasPrefix(attribute, "@") || state.runtime.schema.IsCollective(attribute) {
			return false, nil
		}
	}
	routes := databaseSearchRoutesFromNormalizedBase(state.runtime.databases, prelude.base, request.Scope)
	if len(routes) != 1 {
		return false, nil
	}
	select {
	case <-ctx.Done():
		return false, nil
	default:
	}

	selection, prepared := state.runtime.searchSelections.get(state.runtime.schema, request.Attributes)
	var entries [smallIndexedSearchMaximumCandidates]directory.Entry
	var count int
	var candidateBytes int64
	var revision uint64
	var baseEntry directory.Entry
	base := prelude.base
	var baseCached, complete bool
	limit := effectiveSearchLimit(server.config.MaxSearchEntries, request.SizeLimit)
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		var available bool
		revision, available = storage.ReaderSnapshotRevision(reader)
		if !available {
			return errStopSearch
		}
		tx := readerForDatabase(reader, *database)
		if !databaseCanReuseSearchBase(*database, state.runtime.schema, base) {
			var err error
			base, err = storage.NormalizeReaderDN(tx, base)
			if err != nil {
				return err
			}
		}
		baseEntry, baseCached = state.runtime.searchBases.get(database.partition, base, revision)
		if !baseCached {
			var err error
			baseEntry, err = tx.Get(base)
			if err != nil {
				return err
			}
		}
		// The general path evaluates this plan even for explicit noncollective
		// selections. Retain its errors and use the shortcut only for a no-op plan.
		collective, err := runtimeCollectiveAttributePlan(state.runtime, database.partition, tx)
		if err != nil {
			return err
		}
		if len(collective.sources) != 0 || smallIndexedEntryIsSpecial(state.runtime, baseEntry) {
			return errStopSearch
		}
		complete, _, err = storage.ForEachBoundedReadOnlyFilterCandidate(
			tx, request.Filter, smallIndexedSearchMaximumCandidates, func(entry directory.Entry) error {
				inScope, err := smallIndexedEntryInScope(state.runtime, database, tx, base, entry, request.Scope)
				if err != nil || !inScope {
					return err
				}
				if smallIndexedEntryIsSpecial(state.runtime, entry) {
					return errStopSearch
				}
				matches, err := request.Filter.MatchWith(entry, state.runtime.schema)
				if err != nil || !matches {
					return err
				}
				if count >= len(entries) || count >= limit {
					return errStopSearch
				}
				readable := rootVisibleEntry(entry, request.TypesOnly)
				readable = server.applyAllowedAttributes(state.runtime, tx, state.boundDN,
					entry, readable, request.Attributes, request.TypesOnly)
				// Both selection implementations copy values and descriptors here,
				// while the borrowed entry is still valid inside its callback.
				var selected directory.Entry
				if prepared {
					selected = selection.Select(readable, request.TypesOnly)
				} else {
					selected = server.selectEntry(state.runtime, readable, request.Attributes, request.TypesOnly)
				}
				size := max(int64(1), searchCandidateRetainedBytes(searchCandidate{selected: selected, dn: entry.DN}))
				if size > server.config.MaxSearchCandidateBytes-candidateBytes {
					return errStopSearch
				}
				candidateBytes += size
				entries[count] = selected
				count++
				return nil
			},
		)
		return err
	})
	if err != nil || !complete {
		return false, nil
	}
	// A speculative failure must not increment the limiter's rejection counter:
	// the general path owns that failure and any partial-result/error semantics.
	if candidateBytes > 0 {
		limiter := &server.searchMemoryLimiter
		for {
			active := limiter.active.Load()
			if candidateBytes > limiter.maximum-active {
				return false, nil
			}
			if limiter.active.CompareAndSwap(active, active+candidateBytes) {
				break
			}
		}
		defer limiter.release(candidateBytes)
	}
	if !baseCached {
		state.runtime.searchBases.put(database.partition, base, revision, baseEntry)
	}
	state.runtime.searchResults.put(prelude.fingerprint, revision, entries[:count])
	return true, server.writeSearchResult(connection, message.ID, state, nil, nil,
		entries[:count], ldapwire.Result{Code: ldapwire.ResultSuccess}, pagedSearchCursor{}, false)
}

// Cache eligibility excludes local overlays, but frontend overlays also apply
// to this database. Retcode can terminate a miss before ordinary search begins;
// collect/nestgroup/valueSort can change its entries independently of RFC collective sources.
func smallIndexedRuntimeProjectionSafe(runtime *runtimeState) bool {
	if runtime.features.retcode {
		return false
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if database.valueSort != nil {
			return false
		}
		if databaseType(database.name) == "frontend" &&
			(len(database.retcodes) != 0 || database.collect != nil || len(database.nestGroups) != 0) {
			return false
		}
	}
	return true
}

func smallIndexedEntryIsSpecial(runtime *runtimeState, entry directory.Entry) bool {
	if runtime.searchEntryClasses != nil {
		return runtime.searchEntryClasses.Match(entry)&
			(searchEntryClassSubentry|searchEntryClassAlias|searchEntryClassReferral) != 0
	}
	return runtime.schema.EntryHasObjectClass(entry, "subentry") ||
		runtime.schema.EntryHasObjectClass(entry, "alias") ||
		runtime.schema.EntryHasObjectClass(entry, "referral")
}

func smallIndexedEntryInScope(
	runtime *runtimeState,
	database *runtimeDatabase,
	reader storage.Reader,
	base directory.DN,
	entry directory.Entry,
	scope directory.Scope,
) (bool, error) {
	dn, normalized := entry.NormalizedDNHint()
	if !normalized {
		if identity, available := entry.DNIdentity(); available && databaseUsesRuntimeDNIdentity(*database, runtime.schema) {
			return directory.IdentityKeyInScope(base, identity, scope)
		}
		var err error
		dn, err = directory.ParseDN(entry.DN)
		if err == nil {
			dn, err = storage.NormalizeReaderDN(reader, dn)
		}
		if err != nil {
			return false, err
		}
	}
	return directory.InScope(base, dn, scope), nil
}
