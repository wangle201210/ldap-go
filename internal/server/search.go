package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"
	"unsafe"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var errDatabaseSearchLimitGroupUnverifiable = errors.New(
	"group limit membership cannot be verified by this backend",
)

const objectClassAttributesFeatureOID = "1.3.6.1.4.1.4203.1.5.2"

func (server *Server) effectiveDatabaseSearchLimitsForRequest(
	runtime *runtimeState,
	database runtimeDatabase,
	boundDN string,
	requestDN directory.DN,
	reader storage.Reader,
	serverLimit,
	requestSize,
	requestTime int,
) (databaseSearchExecutionLimits, error) {
	return effectiveDatabaseSearchExecutionLimitsWithMatcher(
		runtime,
		database,
		boundDN,
		serverLimit,
		requestSize,
		requestTime,
		func(rule databaseSearchSizeLimit, subject directory.DN) (bool, error) {
			if rule.selector == databaseSearchLimitGroup {
				if reader == nil {
					return false, errDatabaseSearchLimitGroupUnverifiable
				}
				return server.databaseSearchLimitGroupMatches(
					runtime,
					reader,
					subject,
					rule,
				)
			}
			if rule.requestDN {
				subject = requestDN
			}
			return databaseSearchLimitMatches(database, rule, subject), nil
		},
	)
}

func (server *Server) databaseSearchLimitGroupMatches(
	runtime *runtimeState,
	reader storage.Reader,
	bound directory.DN,
	rule databaseSearchSizeLimit,
) (bool, error) {
	if runtime == nil || runtime.schema == nil || bound.Depth() == 0 {
		return false, nil
	}
	groupDatabase := databaseForDN(runtime, rule.subject)
	if groupDatabase == nil {
		return false, nil
	}
	if databaseSearchCandidatesAreDelegated(runtime, *groupDatabase) {
		return false, errDatabaseSearchLimitGroupUnverifiable
	}
	groupReader := readerForDatabase(reader, *groupDatabase)
	groupDN, err := storage.NormalizeReaderDN(groupReader, rule.subject)
	if err != nil {
		return false, err
	}
	group, err := groupReader.Get(groupDN)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	classMatches := false
	for _, attribute := range group.Attributes {
		if !runtime.schema.AttributeDescriptionSubtype(attribute.Description, "objectClass") {
			continue
		}
		for _, value := range attribute.Values {
			candidate := directory.Entry{Attributes: []directory.Attribute{{
				Description: "objectClass",
				Values:      [][]byte{value},
			}}}
			if runtime.schema.EntryHasObjectClass(candidate, rule.groupObjectClass) {
				classMatches = true
				break
			}
		}
		if classMatches {
			break
		}
	}
	if !classMatches {
		return false, nil
	}

	assertion, err := runtime.schema.NormalizeEqualityAssertion(
		rule.groupAttribute,
		[]byte(bound.String()),
	)
	if err != nil {
		return false, err
	}
	for _, attribute := range group.Attributes {
		if !runtime.schema.AttributeDescriptionSubtype(
			attribute.Description,
			rule.groupAttribute,
		) {
			continue
		}
		for _, value := range attribute.Values {
			normalized, normalizeErr := runtime.schema.NormalizeEqualityValue(
				rule.groupAttribute,
				value,
			)
			if normalizeErr == nil && bytes.Equal(normalized, assertion) {
				return true, nil
			}
		}
	}
	return false, nil
}

func searchRequestControlSupport(runtime *runtimeState) requestControlSupport {
	if runtime != nil && runtime.searchControlSupport != 0 {
		return runtime.searchControlSupport
	}
	if runtime == nil {
		return searchControlSupportForDatabases(nil)
	}
	return searchControlSupportForDatabases(runtime.databases)
}

func searchControlSupportForDatabases(databases []runtimeDatabase) requestControlSupport {
	support := supportsAssertion |
		supportsPagedResults |
		supportsManageDsaIT |
		supportsSubentries |
		supportsDontUseCopy |
		supportsAccountUsability |
		supportsMatchedValues |
		supportsDomainScope |
		supportsSearchOptions |
		supportsLazyCommit |
		supportsNoOp
	if runtimeSupportsDeref(databases) {
		support |= supportsDeref
	}
	if runtimeSupportsServerSideSort(databases) {
		support |= supportsServerSideSort | supportsVirtualListView
	}
	if runtimeSupportsSyncProvider(databases) {
		support |= supportsSync
	}
	if runtimeSupportsValueSort(databases) {
		support |= supportsValueSort
	}
	if runtimeSupportsNoOpSearch(databases) {
		support |= supportsNoOpSearch
	}
	return support
}

func (server *Server) handleSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
) error {
	if handled, err := server.tryPcachePrivateSearch(
		connection,
		state,
		message,
		request,
	); handled {
		return err
	}
	var (
		base                   directory.DN
		baseReady              bool
		resultCacheFingerprint [sha256.Size]byte
		resultCacheRevision    uint64
		hasResultCacheRevision bool
		resultCacheable        bool
		resultCacheEvaluated   bool
	)
	if len(message.Controls) == 0 && state.passwordPolicyRestrictedDN == "" {
		var baseErr error
		base, baseErr = normalizeConnectionSearchRequestBase(state, request.BaseDN)
		if baseErr != nil {
			return server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
			)
		}
		baseReady = true
		resultCacheEvaluated = true
		if base.Depth() > 0 {
			if database := databaseForNormalizedDN(state.runtime, base); database != nil {
				cacheRequest := request
				cacheRequest.BaseDN = base.String()
				if fingerprint, cacheable := server.rootEqualitySearchCacheFingerprint(
					state,
					*database,
					cacheRequest,
					nil,
				); cacheable {
					if revision, available := server.currentStorageSnapshotRevision(ctx); available {
						if cached, found := state.runtime.searchResults.get(
							fingerprint,
							revision,
						); found {
							return server.writeSearchResult(
								connection,
								message.ID,
								state,
								nil,
								nil,
								cached,
								ldapwire.Result{Code: ldapwire.ResultSuccess},
								pagedSearchCursor{},
								false,
							)
						}
						resultCacheFingerprint = fingerprint
						resultCacheRevision = revision
						hasResultCacheRevision = true
						resultCacheable = true
					}
				}
			}
		}
	}
	var sortLease *serverSideSortLease
	defer func() {
		releaseServerSideSortLease(state, sortLease)
	}()

	controlSupport := searchRequestControlSupport(state.runtime)
	controls, controlFailure := parseRequestControlsWithDisallows(
		message.Controls,
		controlSupport,
		state.runtime.disallows,
	)
	if controlFailure != nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			*controlFailure,
		)
	}
	searchFilters := []directory.Filter{request.Filter}
	if controls.assertion != nil {
		searchFilters = append(searchFilters, *controls.assertion)
	}
	ctx = withSQLBackendSearchRequirements(
		ctx,
		request.Attributes,
		searchFilters...,
	)
	controls.deref, controlFailure = prepareDerefControl(
		state.runtime.schema,
		controls.deref,
	)
	if controlFailure != nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			*controlFailure,
		)
	}
	state.accountUsabilityRequested = controls.accountUsability
	defer func() {
		state.accountUsabilityRequested = false
	}()
	if state.passwordPolicyRestrictedDN != "" {
		return server.writeSearchDone(
			connection,
			message.ID,
			passwordPolicyRestrictionResult(),
		)
	}
	if !baseReady {
		var baseErr error
		base, baseErr = normalizeConnectionSearchRequestBase(state, request.BaseDN)
		if baseErr != nil {
			return server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
			)
		}
	}
	ctx = withSQLBackendScopeRequirements(ctx, base, request.Scope)
	if handled, err := server.tryRetcodeSearch(
		ctx,
		connection,
		state,
		message,
		request,
		controls.manageDsaIT,
	); handled {
		return err
	}
	if !resultCacheEvaluated && base.Depth() > 0 {
		if database := databaseForNormalizedDN(state.runtime, base); database != nil {
			cacheRequest := request
			cacheRequest.BaseDN = base.String()
			if fingerprint, cacheable := server.rootEqualitySearchCacheFingerprint(
				state,
				*database,
				cacheRequest,
				message.Controls,
			); cacheable {
				if revision, available := server.currentStorageSnapshotRevision(ctx); available {
					if cached, found := state.runtime.searchResults.get(fingerprint, revision); found {
						return server.writeSearchResult(
							connection,
							message.ID,
							state,
							nil,
							nil,
							cached,
							ldapwire.Result{Code: ldapwire.ResultSuccess},
							pagedSearchCursor{},
							false,
						)
					}
					resultCacheFingerprint = fingerprint
					resultCacheable = true
				}
			}
		}
	}
	limits := databaseSearchExecutionLimits{
		size: effectiveSearchLimit(
			server.config.MaxSearchEntries,
			noOpSearchRequestedSize(ctx, request.SizeLimit),
		),
		time:      request.TimeLimit,
		unchecked: -1,
		pageSize:  -1,
		pageTotal: effectiveSearchLimit(
			server.config.MaxSearchEntries,
			noOpSearchRequestedSize(ctx, request.SizeLimit),
		),
	}
	limitBase := base
	if limitBase.Depth() == 0 &&
		request.Scope != directory.ScopeBase &&
		state.runtime.defaultSearchBase.configured {
		limitBase = state.runtime.defaultSearchBase.dn
	}
	limitDatabaseIndex := databaseIndexForNormalizedDN(
		state.runtime.databases,
		limitBase,
	)
	if limitDatabaseIndex >= 0 {
		database := state.runtime.databases[limitDatabaseIndex]
		if databaseSearchLimitsRequireRequestContext(database.searchSizeLimits) {
			err := server.config.Store.View(ctx, func(reader storage.Reader) error {
				tx := readerForDatabase(reader, database, ctx)
				requestDN, err := storage.NormalizeReaderDN(tx, base)
				if err != nil {
					return err
				}
				limits, err = server.effectiveDatabaseSearchLimitsForRequest(
					state.runtime,
					database,
					state.boundDN,
					requestDN,
					reader,
					server.config.MaxSearchEntries,
					noOpSearchRequestedSize(ctx, request.SizeLimit),
					request.TimeLimit,
				)
				return err
			})
			if err != nil {
				return fmt.Errorf("evaluate database search limits: %w", err)
			}
		} else {
			limits = effectiveDatabaseSearchExecutionLimits(
				state.runtime,
				database,
				state.boundDN,
				server.config.MaxSearchEntries,
				noOpSearchRequestedSize(ctx, request.SizeLimit),
				request.TimeLimit,
			)
		}
	}
	if isNoOpSearch(ctx) {
		limits.size = math.MaxInt32
	}
	request.TimeLimit = limits.time
	limit := limits.size
	if limits.unchecked == 0 {
		clearPagedSearch(state)
		return server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultAdminLimitExceeded, ""),
		)
	}
	paging, pagingFailure := server.preparePagedSearch(
		ctx,
		state,
		request,
		message.Controls,
		controls.paging,
		limits,
	)
	if pagingFailure != nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			*pagingFailure,
		)
	}
	if paging != nil {
		defer paging.releaseRetainedMemory()
	}
	if paging != nil && paging.abandoned {
		return server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
		)
	}
	if paging != nil {
		limit = paging.totalLimit
	}
	sorting, sortFailure := prepareServerSideSort(
		state.runtime.schema,
		controls.sorting,
		-1,
	)
	if sortFailure != nil {
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			nil,
			nil,
			*sortFailure,
			pagedSearchCursor{},
			false,
		)
	}

	rootDSESearch := base.Depth() == 0 &&
		request.Scope == directory.ScopeBase
	if !rootDSESearch &&
		base.Depth() == 0 &&
		state.runtime.defaultSearchBase.configured {
		base = state.runtime.defaultSearchBase.dn
	}
	request.BaseDN = base.String()
	subschemaSearch := isRuntimeSubschemaDN(state.runtime, base)
	if rootDSESearch || subschemaSearch {
		var derefFailure *ldapwire.Result
		connection, derefFailure = server.prepareDerefSearchTarget(
			ctx,
			connection,
			state,
			&controls,
			frontendSupportsDeref(state.runtime.databases),
		)
		if derefFailure != nil {
			return server.writeSearchDone(connection, message.ID, *derefFailure)
		}
	}
	if (rootDSESearch || subschemaSearch) && controls.sync != nil {
		if controls.sync.critical {
			return server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"Sync is not enabled for this search target",
				),
			)
		}
		controls.sync = nil
	}
	vlvRequest := controls.vlv
	if (rootDSESearch || subschemaSearch) &&
		(controls.sorting != nil || vlvRequest != nil) {
		maxKeys, enabled := serverSideSortSettingsForDatabase(
			state.runtime.databases,
			-1,
		)
		critical := vlvRequest != nil && vlvRequest.critical
		if controls.sorting != nil {
			critical = critical || controls.sorting.critical
		}
		switch {
		case !enabled && critical:
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				nil,
				nil,
				ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"server-side sorting is not enabled in this context",
				),
				pagedSearchCursor{},
				false,
			)
		case !enabled:
			sorting = nil
			vlvRequest = nil
		case controls.sorting != nil &&
			len(controls.sorting.keys) > maxKeys:
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				nil,
				nil,
				*sortOperationFailure(
					ldapwire.ResultUnwillingToPerform,
					"too many sort keys",
				),
				pagedSearchCursor{},
				false,
			)
		}
	}
	if (rootDSESearch || subschemaSearch) && vlvRequest != nil {
		if controls.paging != nil {
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				nil,
				nil,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"VLV is incompatible with paged results",
				),
				pagedSearchCursor{},
				false,
			)
		}
		if controls.sorting == nil {
			failure := newVirtualListViewFailure(
				openLDAPVLVSortControlMissing,
				"sort control is required with VLV",
				0,
				nil,
			)
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				nil,
				nil,
				failure.result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(failure.response),
			)
		}
		sorting.forceResponse = true
		virtualListView, failure := prepareVirtualListView(
			state,
			request,
			message.Controls,
			vlvRequest,
		)
		if failure != nil {
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				sorting,
				nil,
				failure.result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(failure.response),
			)
		}
		view := virtualListView.state
		if view == nil {
			lease, ok := acquireServerSideSortLease(state, -1)
			if !ok {
				return server.writeSearchResult(
					connection,
					message.ID,
					state,
					nil,
					nil,
					nil,
					serverSideSortBusyResult(),
					pagedSearchCursor{},
					false,
				)
			}
			sortLease = lease
			var err error
			view, err = server.startVirtualListView(
				state,
				virtualListView,
				nil,
				sortLease,
			)
			if err != nil {
				if errors.Is(err, errVirtualListViewMemoryLimit) {
					return server.writeSearchDone(
						connection,
						message.ID,
						ldapwire.ResultError(ldapwire.ResultAdminLimitExceeded, err.Error()),
					)
				}
				return fmt.Errorf("create special-entry VLV context: %w", err)
			}
			sortLease = nil
		}
		_, _, target, code, windowErr := virtualListViewWindow(
			state.runtime.schema,
			virtualListView.request,
			sorting.keys[0],
			view.items,
		)
		if code != ldapwire.ResultSuccess || windowErr != nil {
			diagnostic := "VLV target is invalid"
			if windowErr != nil {
				diagnostic = windowErr.Error()
			}
			failure := newVirtualListViewFailure(
				code,
				diagnostic,
				0,
				view.contextID,
			)
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				sorting,
				nil,
				failure.result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(failure.response),
			)
		}
		response := ldapwire.VirtualListViewResponse{
			TargetPosition: int64(target),
			Result:         ldapwire.ResultSuccess,
			ContextID:      view.contextID,
			HasContextID:   true,
		}
		return server.writeSearchResultWithControls(
			connection,
			message.ID,
			state,
			nil,
			sorting,
			nil,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			pagedSearchCursor{},
			false,
			virtualListViewResponseControl(response),
		)
	}
	if (rootDSESearch || subschemaSearch) && sorting.active() {
		lease, ok := acquireServerSideSortLease(state, -1)
		if !ok {
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				nil,
				nil,
				serverSideSortBusyResult(),
				pagedSearchCursor{},
				false,
			)
		}
		sortLease = lease
	}
	if (rootDSESearch || subschemaSearch) &&
		frontendRestricts(state.runtime, restrictSearch) {
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
			pagedSearchCursor{},
			false,
		)
	}
	if rootDSESearch {
		return server.searchRootDSE(
			ctx,
			connection,
			state,
			message.ID,
			request,
			controls.assertion,
			paging,
			sorting,
		)
	}
	if subschemaSearch {
		return server.searchSubschema(
			ctx,
			connection,
			state,
			message.ID,
			request,
			controls.assertion,
			paging,
			sorting,
		)
	}
	if monitorIndex := monitorDatabaseIndexForDN(state.runtime.databases, base); monitorIndex >= 0 {
		var derefFailure *ldapwire.Result
		connection, derefFailure = server.prepareDerefSearchTarget(
			ctx,
			connection,
			state,
			&controls,
			derefEnabledForDatabase(
				state.runtime.databases,
				state.runtime.databases[monitorIndex],
			),
		)
		if derefFailure != nil {
			return server.writeSearchDone(connection, message.ID, *derefFailure)
		}
		if databaseRestricts(state.runtime.databases[monitorIndex], restrictSearch) {
			if paging != nil {
				clearPagedSearch(state)
			}
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				sorting,
				nil,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"operation restricted",
				),
				pagedSearchCursor{},
				false,
			)
		}
		return server.searchMonitor(
			ctx,
			connection,
			state,
			message.ID,
			request,
			controls,
			paging,
			limit,
		)
	}
	routes := databaseSearchRoutesFromNormalizedBase(
		state.runtime.databases,
		base,
		request.Scope,
	)
	if len(routes) == 0 {
		result := ldapwire.Result{Code: ldapwire.ResultNoSuchObject}
		if referral, ok := globalReferralResult(
			state.runtime,
			&base,
			referralScopeForSearch(request.Scope),
		); ok {
			result = referral
		}
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			nil,
			result,
			pagedSearchCursor{},
			false,
		)
	}
	connection, controlFailure = server.prepareDerefSearchTarget(
		ctx,
		connection,
		state,
		&controls,
		derefEnabledForDatabase(
			state.runtime.databases,
			state.runtime.databases[routes[0].databaseIndex],
		),
	)
	if controlFailure != nil {
		return server.writeSearchDone(connection, message.ID, *controlFailure)
	}
	if databaseRestricts(
		state.runtime.databases[routes[0].databaseIndex],
		restrictSearch,
	) {
		if paging != nil {
			clearPagedSearch(state)
		}
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
			pagedSearchCursor{},
			false,
		)
	}
	if controls.dontUseCopy {
		primary := state.runtime.databases[routes[0].databaseIndex]
		if primary.shadow {
			if paging != nil {
				clearPagedSearch(state)
			}
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				nil,
				nil,
				nil,
				shadowSearchResult(state.runtime, primary, base, request.Scope),
				pagedSearchCursor{},
				false,
			)
		}
	}
	if controls.valueSort != nil && !valueSortEnabledForDatabase(
		state.runtime.databases,
		state.runtime.databases[routes[0].databaseIndex],
	) {
		if controls.valueSort.critical {
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				sorting,
				nil,
				ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"valSort is not enabled for the target database",
				),
				pagedSearchCursor{},
				false,
			)
		}
		controls.valueSort = nil
	}
	if controls.sorting != nil || vlvRequest != nil {
		maxKeys, enabled := serverSideSortSettingsForDatabase(
			state.runtime.databases,
			routes[0].databaseIndex,
		)
		critical := vlvRequest != nil && vlvRequest.critical
		if controls.sorting != nil {
			critical = critical || controls.sorting.critical
		}
		if !enabled {
			if critical {
				return server.writeSearchResult(
					connection,
					message.ID,
					state,
					paging,
					nil,
					nil,
					ldapwire.ResultError(
						ldapwire.ResultUnavailableCriticalExtension,
						"server-side sorting is not enabled for the target database",
					),
					pagedSearchCursor{},
					false,
				)
			}
			sorting = nil
			vlvRequest = nil
		} else {
			if controls.sorting != nil &&
				len(controls.sorting.keys) > maxKeys {
				return server.writeSearchResult(
					connection,
					message.ID,
					state,
					paging,
					nil,
					nil,
					*sortOperationFailure(
						ldapwire.ResultUnwillingToPerform,
						"too many sort keys",
					),
					pagedSearchCursor{},
					false,
				)
			}
		}
	}
	primaryDatabase := state.runtime.databases[routes[0].databaseIndex]
	if databaseUsesNullBackend(state.runtime, primaryDatabase) {
		if controls.sync != nil {
			if controls.sync.critical {
				return server.writeSearchResult(
					connection,
					message.ID,
					state,
					paging,
					sorting,
					nil,
					ldapwire.ResultError(
						ldapwire.ResultUnavailableCriticalExtension,
						"Sync is not enabled for this search target",
					),
					pagedSearchCursor{},
					false,
				)
			}
			controls.sync = nil
		}
		return server.searchNull(
			ctx,
			connection,
			state,
			message.ID,
			request,
			primaryDatabase,
			controls,
			paging,
			sorting,
		)
	}
	base, routes, aliasFailure, err := server.prepareAliasSearch(
		ctx,
		state,
		base,
		request.Scope,
		request.DerefAliases,
		routes,
	)
	if err != nil {
		if paging != nil {
			clearPagedSearch(state)
		}
		return fmt.Errorf("prepare alias search: %w", err)
	}
	if aliasFailure != nil {
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			nil,
			*aliasFailure,
			pagedSearchCursor{},
			false,
		)
	}
	syncSearch, syncFailure := server.prepareSyncSearch(
		state,
		request,
		routes,
		controls,
	)
	if syncFailure != nil {
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			nil,
			nil,
			nil,
			*syncFailure,
			pagedSearchCursor{},
			false,
		)
	}
	if syncSearch != nil {
		defer syncSearch.close()
	}

	var virtualListView *virtualListViewContext
	if vlvRequest != nil {
		if controls.paging != nil {
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				nil,
				nil,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"VLV is incompatible with paged results",
				),
				pagedSearchCursor{},
				false,
			)
		}
		if controls.sorting == nil {
			failure := newVirtualListViewFailure(
				openLDAPVLVSortControlMissing,
				"sort control is required with VLV",
				0,
				nil,
			)
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				nil,
				nil,
				failure.result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(failure.response),
			)
		}
		sorting.forceResponse = true
		var failure *virtualListViewFailure
		virtualListView, failure = prepareVirtualListView(
			state,
			request,
			message.Controls,
			vlvRequest,
		)
		if failure != nil {
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				sorting,
				nil,
				failure.result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(failure.response),
			)
		}
		if virtualListView.state != nil && syncSearch == nil {
			view := virtualListView.state
			start, end, target, code, windowErr := virtualListViewWindow(
				state.runtime.schema,
				virtualListView.request,
				sorting.keys[0],
				view.items,
			)
			if code != ldapwire.ResultSuccess || windowErr != nil {
				diagnostic := "VLV target is invalid"
				if windowErr != nil {
					diagnostic = windowErr.Error()
				}
				failure := newVirtualListViewFailure(
					code,
					diagnostic,
					len(view.items),
					view.contextID,
				)
				return server.writeSearchResultWithControls(
					connection,
					message.ID,
					state,
					nil,
					sorting,
					nil,
					failure.result,
					pagedSearchCursor{},
					false,
					virtualListViewResponseControl(failure.response),
				)
			}
			entries, err := server.virtualListViewEntries(
				ctx,
				state,
				routes,
				request,
				view,
				start,
				end,
				controls.valueSort != nil && controls.valueSort.raw,
				controls.manageDsaIT,
			)
			if err != nil {
				discardVirtualListView(state, view)
				if result, ok := nestGroupResourceLimitResult(err); ok {
					failure := newVirtualListViewFailure(
						result.Code,
						result.DiagnosticMessage,
						len(view.items),
						view.contextID,
					)
					return server.writeSearchResultWithControls(
						connection,
						message.ID,
						state,
						nil,
						sorting,
						nil,
						failure.result,
						pagedSearchCursor{},
						false,
						virtualListViewResponseControl(failure.response),
					)
				}
				return fmt.Errorf("read VLV window: %w", err)
			}
			result := ldapwire.Result{Code: ldapwire.ResultSuccess}
			if len(entries) > limit {
				entries = entries[:limit]
				result.Code = ldapwire.ResultSizeLimitExceeded
			}
			response := ldapwire.VirtualListViewResponse{
				TargetPosition: int64(target),
				ContentCount:   int64(len(view.items)),
				Result:         ldapwire.ResultSuccess,
				ContextID:      view.contextID,
				HasContextID:   true,
			}
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				sorting,
				entries,
				result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(response),
			)
		}
	}

	if paging != nil && paging.cursor.valid && sorting.active() {
		attributeType := ""
		if len(sorting.keys) > 0 {
			attributeType = sorting.keys[0].attribute
		}
		sorting.fail(
			ldapwire.ResultInappropriateMatching,
			attributeType,
		)
	}

	deadline := timeLimitDeadline(request.TimeLimit)
	if paging != nil && paging.sorted != nil {
		entries, result, hasMore, err := server.continueSortedPagedSearch(
			ctx,
			state,
			routes,
			request,
			paging,
			deadline,
			controls.valueSort != nil && controls.valueSort.raw,
			controls.manageDsaIT,
		)
		if err != nil {
			clearPagedSearch(state)
			return fmt.Errorf("continue sorted paged search: %w", err)
		}
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			entries,
			result,
			pagedSearchCursor{},
			hasMore,
		)
	}
	if sorting.active() &&
		(virtualListView == nil || virtualListView.state == nil) {
		lease, ok := acquireServerSideSortLease(
			state,
			routes[0].databaseIndex,
		)
		if !ok {
			return server.writeSearchResult(
				connection,
				message.ID,
				state,
				paging,
				nil,
				nil,
				serverSideSortBusyResult(),
				pagedSearchCursor{},
				false,
			)
		}
		sortLease = lease
	}
	translucentRoutes, translucentFailure, err :=
		server.prepareTranslucentSearchRoutes(
			ctx,
			state,
			message,
			request,
			routes,
			controls.manageDsaIT,
		)
	if err != nil {
		if paging != nil {
			clearPagedSearch(state)
		}
		return fmt.Errorf("search translucent remote database: %w", err)
	}
	if translucentFailure != nil {
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			nil,
			*translucentFailure,
			pagedSearchCursor{},
			false,
		)
	}

	translucent := false
	for _, route := range translucentRoutes {
		if route != nil {
			translucent = true
			break
		}
	}
	if resultCacheable && (syncSearch != nil || virtualListView != nil ||
		len(routes) != 1 || translucent) {
		resultCacheable = false
	}
	snapshotPaging := paging != nil && !sorting.active() && syncSearch == nil &&
		!state.runtime.features.chain
	snapshotCacheable := snapshotPaging && controls.assertion == nil &&
		pagedSnapshotFilterCacheable(state.runtime.schema, request.Filter)
	snapshotEntriesCacheable := snapshotCacheable &&
		pagedSnapshotAttributesCacheable(state.runtime.schema, request.Attributes)
	if snapshotCacheable {
		for _, route := range routes {
			database := state.runtime.databases[route.databaseIndex]
			if !server.isDatabaseRoot(state.runtime, database, state.boundDN) {
				snapshotCacheable = false
				break
			}
		}
	}
	if snapshotPaging {
		for _, route := range translucentRoutes {
			if route != nil {
				snapshotPaging = false
				break
			}
		}
	}
	snapshotCacheable = snapshotCacheable && snapshotPaging
	snapshotEntriesCacheable = snapshotEntriesCacheable && snapshotCacheable
	valueSortEnabled := runtimeSupportsValueSort(state.runtime.databases)
	var preparedRootSubstring *schema.PreparedSubstringMatcher
	preparedEntryClasses := state.runtime.searchEntryClasses
	preparedSelection, hasPreparedSelection := state.runtime.searchSelections.get(
		state.runtime.schema,
		request.Attributes,
	)
	if snapshotPaging {
		if request.Filter.Kind == directory.FilterSubstrings {
			preparedRootSubstring, _ = state.runtime.schema.PrepareSubstringMatcher(
				request.Filter.Attribute,
				request.Filter.Substring,
			)
		}
	}

	candidates := make([]searchCandidate, 0)
	snapshotItems := make([]pagedSortedItem, 0)
	var candidateBytes int64
	var snapshotBytes int64
	var processSearchBytes int64
	defer func() {
		if processSearchBytes > 0 {
			server.searchMemoryLimiter.release(processSearchBytes)
		}
	}()
	references := make([][]string, 0)
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	entryLimit := limit
	remaining := limit
	if paging != nil {
		remaining = limit - paging.count
		if remaining < 0 {
			remaining = 0
		}
		entryLimit = min(paging.size, remaining)
	}
	var (
		hasMore                  bool
		lastCursor               pagedSearchCursor
		sortTruncated            bool
		inDirectoryRetcodeResult *retcodeItem
	)
	projectSubschemaReference := searchRequestsSubschemaReference(
		state.runtime.schema,
		request,
		controls.assertion,
	)
	if sorting.active() {
		for _, key := range sorting.keys {
			if state.runtime.schema.AttributeDescriptionSubtype(
				key.attribute,
				"subschemaSubentry",
			) {
				projectSubschemaReference = true
				break
			}
		}
	}

	server.prepareAutoCASearch(ctx, state, request, routes)
	if err := server.ensureSearchEqualityIndexes(ctx, state.runtime, routes); err != nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultOperationsError,
				"cannot prepare configured search indexes",
			),
		)
	}
	stableCursorPaging := false
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		primary := routes[0]
		primaryDatabase := &state.runtime.databases[primary.databaseIndex]
		primaryReader := readerForDatabase(reader, *primaryDatabase)
		stableCursorPaging = snapshotPaging && len(routes) == 1 &&
			databaseSupportsPhysicalKeyPaging(*primaryDatabase, request.Filter) &&
			storage.SupportsStablePhysicalEntryContinuation(primaryReader)
		if stableCursorPaging {
			snapshotPaging = false
			snapshotCacheable = false
			snapshotEntriesCacheable = false
		}
		if resultCacheable {
			resultCacheRevision, hasResultCacheRevision =
				storage.ReaderSnapshotRevision(reader)
		}
		if snapshotPaging {
			paging.storageRevision, paging.hasStorageRevision =
				storage.ReaderSnapshotRevision(reader)
		}
		if syncSearch != nil {
			if err := syncSearch.captureSnapshot(reader); err != nil {
				return err
			}
			if failure := syncSearch.snapshotFailure(); failure != nil {
				result = *failure
				return nil
			}
			failure, err := server.prepareSyncRefresh(
				state,
				request,
				reader,
				syncSearch,
			)
			if err != nil {
				return err
			}
			if failure != nil {
				result = *failure
				return nil
			}
		}
		collectivePlans := newCollectiveAttributePlanCache(
			state.runtime.schema,
			state.runtime.collectivePlans,
		)
		collectResponses := newCollectProjectionCache(
			server,
			state.runtime,
			reader,
			state.boundDN,
		)
		dynlistPlans := newDynlistProjectionCache(
			ctx,
			server,
			state.runtime,
			reader,
			state.boundDN,
			dynlistProjectionRequest{
				attributes: request.Attributes,
				filter:     &request.Filter,
			},
		)
		nestGroupPlans := newNestGroupProjectionCache(
			ctx,
			server,
			state.runtime,
			reader,
			state.boundDN,
			nestGroupProjectionRequest{
				attributes: request.Attributes,
				typesOnly:  request.TypesOnly,
				filter:     request.Filter,
			},
		)
		primaryRoot := server.isDatabaseRoot(
			state.runtime,
			*primaryDatabase,
			state.boundDN,
		)
		primaryBase := base
		if !databaseCanReuseSearchBase(*primaryDatabase, state.runtime.schema, base) {
			primaryBase, err = storage.NormalizeReaderDN(primaryReader, base)
			if err != nil {
				return fmt.Errorf("normalize primary search base %q: %w", base.String(), err)
			}
		}
		var baseEntry directory.Entry
		if translucentRoutes[0] != nil {
			baseEntry, err = translucentMergedRemoteEntry(
				primaryReader,
				*translucentRoutes[0].base,
			)
		} else {
			baseEntry, err = primaryReader.Get(primaryBase)
		}
		if err != nil {
			if errors.Is(err, storage.ErrEntryNotFound) {
				ancestor, found, ancestorErr := closestExistingAncestor(
					primaryReader,
					primaryBase,
				)
				if ancestorErr != nil {
					return ancestorErr
				}
				if found {
					ancestor, ancestorErr = collectivePlans.apply(
						primaryDatabase.partition,
						primaryReader,
						ancestor,
					)
					if ancestorErr != nil {
						return ancestorErr
					}
				}
				if found &&
					state.runtime.schema.EntryHasObjectClass(
						ancestor,
						"referral",
					) &&
					server.allowed(
						state.runtime,
						primaryReader,
						state.boundDN,
						ancestor,
						"entry",
						nil,
						acl.Disclose,
					) {
					referral, referralErr := referralResult(
						ancestor,
						&primaryBase,
						referralScopeForSearch(request.Scope),
					)
					if referralErr != nil {
						return referralErr
					}
					result = referral
					return nil
				}
				if !found {
					if referral, ok := globalReferralResult(
						state.runtime,
						&primaryBase,
						referralScopeForSearch(request.Scope),
					); ok {
						result = referral
						return nil
					}
				}
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = server.disclosedAncestor(
					state.runtime,
					primaryReader,
					state.boundDN,
					primaryBase,
				)
				return nil
			}
			return err
		}
		if projectSubschemaReference {
			baseEntry = withSubschemaReference(baseEntry)
		}
		baseEntry, err = collectivePlans.apply(
			primaryDatabase.partition,
			primaryReader,
			baseEntry,
		)
		if err != nil {
			return err
		}
		if !primaryRoot && !server.allowed(
			state.runtime,
			primaryReader,
			state.boundDN,
			baseEntry,
			"entry",
			nil,
			acl.Search,
		) {
			if server.allowed(
				state.runtime,
				primaryReader,
				state.boundDN,
				baseEntry,
				"entry",
				nil,
				acl.Disclose,
			) {
				result.Code = ldapwire.ResultInsufficientAccessRights
			} else {
				result.Code = ldapwire.ResultNoSuchObject
			}
			return nil
		}
		if !controls.manageDsaIT &&
			state.runtime.schema.EntryHasObjectClass(
				baseEntry,
				"referral",
			) {
			referral, referralErr := referralResult(
				baseEntry,
				&primaryBase,
				referralScopeForSearch(request.Scope),
			)
			if referralErr != nil {
				return referralErr
			}
			result = referral
			return nil
		}
		if err := server.checkAssertion(
			state.runtime,
			primaryReader,
			state.boundDN,
			baseEntry,
			controls.assertion,
		); err != nil {
			result.Code = ldapwire.ResultAssertionFailed
			return nil
		}

		for routeIndex, route := range routes {
			if paging != nil && paging.cursor.valid && !sorting.active() &&
				routeIndex < paging.cursor.route {
				continue
			}
			database := &state.runtime.databases[route.databaseIndex]
			routeContext := withSQLBackendScopeRequirements(ctx, route.base, route.scope)
			tx := readerForDatabase(reader, *database, routeContext)
			routeRoot := primaryRoot && routeIndex == 0
			if routeIndex != 0 {
				routeRoot = server.isDatabaseRoot(
					state.runtime,
					*database,
					state.boundDN,
				)
			}
			scopeBase := route.base
			comparisonBase := base
			if !databaseCanReuseSearchBase(
				*database,
				state.runtime.schema,
				route.base,
			) {
				var normalizeErr error
				scopeBase, normalizeErr = storage.NormalizeReaderDN(tx, route.base)
				if normalizeErr != nil {
					return fmt.Errorf(
						"normalize search route base %q: %w",
						route.base.String(),
						normalizeErr,
					)
				}
				comparisonBase, normalizeErr = storage.NormalizeReaderDN(tx, base)
				if normalizeErr != nil {
					return fmt.Errorf(
						"normalize search base %q: %w",
						base.String(),
						normalizeErr,
					)
				}
			}
			translucentRoute := translucentRoutes[routeIndex]
			if translucentRoute != nil {
				references = append(references, translucentRoute.references...)
				if result.Code == ldapwire.ResultSuccess &&
					translucentRoute.result.Code != ldapwire.ResultSuccess {
					result = translucentRoute.result
				}
			}
			if routeIndex > 0 {
				var routeBaseEntry directory.Entry
				var err error
				if translucentRoute != nil {
					routeBaseEntry, err = translucentMergedRemoteEntry(
						tx,
						*translucentRoute.base,
					)
				} else {
					routeBaseEntry, err = tx.Get(route.base)
				}
				if errors.Is(err, storage.ErrEntryNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if projectSubschemaReference {
					routeBaseEntry = withSubschemaReference(routeBaseEntry)
				}
				routeBaseEntry, err = collectivePlans.apply(
					database.partition,
					tx,
					routeBaseEntry,
				)
				if err != nil {
					return err
				}
				if !routeRoot && !server.allowed(
					state.runtime,
					tx,
					state.boundDN,
					routeBaseEntry,
					"entry",
					nil,
					acl.Search,
				) {
					continue
				}
			}
			routeLimits := limits
			if route.databaseIndex != limitDatabaseIndex {
				var limitErr error
				routeLimits, limitErr = server.effectiveDatabaseSearchLimitsForRequest(
					state.runtime,
					*database,
					state.boundDN,
					comparisonBase,
					reader,
					server.config.MaxSearchEntries,
					request.SizeLimit,
					request.TimeLimit,
				)
				if limitErr != nil {
					return limitErr
				}
			}
			if routeLimits.unchecked == 0 {
				candidates = nil
				result = ldapwire.ResultError(
					ldapwire.ResultAdminLimitExceeded,
					"",
				)
				return errStopSearch
			}
			if routeLimits.unchecked >= 0 {
				_, countErr := countLocalSearchCandidates(
					tx,
					request.Filter,
					scopeBase,
					route.scope,
					translucentRoute,
					routeLimits.unchecked,
				)
				if errors.Is(countErr, errSearchCandidateLimit) {
					candidates = nil
					result = ldapwire.ResultError(
						ldapwire.ResultAdminLimitExceeded,
						"",
					)
					return errStopSearch
				}
				if countErr != nil {
					return countErr
				}
			}

			physicalCursorKey := ""
			visitEntry := func(entry directory.Entry) error {
				if translucentRoute != nil {
					var mergeErr error
					entry, mergeErr = translucentMergedRemoteEntry(tx, entry)
					if mergeErr != nil {
						return mergeErr
					}
				}
				var storedEntry directory.Entry
				if syncSearch != nil {
					storedEntry = entry.Clone()
				}
				candidate, candidateReady := entry.NormalizedDNHint()
				candidateIdentityKey, hasCandidateIdentity := entry.DNIdentity()
				identityScope := stableCursorPaging ||
					(!candidateReady && hasCandidateIdentity &&
						databaseUsesRuntimeDNIdentity(*database, state.runtime.schema))
				resolveCandidate := func() error {
					if candidateReady {
						return nil
					}
					var resolveErr error
					if identityScope {
						identityKey := candidateIdentityKey
						if stableCursorPaging {
							identityKey = physicalCursorKey
						}
						candidate, resolveErr = directory.ParseDNWithIdentityKey(
							entry.DN,
							identityKey,
						)
					} else {
						candidate, resolveErr = directory.ParseDN(entry.DN)
						if resolveErr == nil {
							candidate, resolveErr = storage.NormalizeReaderDN(tx, candidate)
						}
					}
					if resolveErr != nil {
						return fmt.Errorf("normalize search candidate %q: %w", entry.DN, resolveErr)
					}
					candidateReady = true
					return nil
				}
				candidateOrderKey := ""
				if !stableCursorPaging && (paging != nil || sorting.active()) {
					if err := resolveCandidate(); err != nil {
						return err
					}
					var ordered bool
					candidateOrderKey, ordered = entry.DNOrderKeyHint()
					if !ordered {
						candidateOrderKey, err = storage.ReaderDNOrderKey(tx, candidate)
						if err != nil {
							return fmt.Errorf("order search candidate %q: %w", entry.DN, err)
						}
					}
				}
				candidateCursorKey := candidateOrderKey
				if stableCursorPaging {
					if physicalCursorKey == "" {
						return errors.New("stable physical paging candidate has no cursor key")
					}
					candidateCursorKey = physicalCursorKey
				}
				if paging != nil && paging.cursor.valid && !sorting.active() &&
					!stableCursorPaging {
					if routeIndex < paging.cursor.route ||
						(routeIndex == paging.cursor.route &&
							candidateOrderKey <= paging.cursor.dnKey) {
						return nil
					}
				}
				if expired(deadline) {
					result.Code = ldapwire.ResultTimeLimitExceeded
					return errStopSearch
				}
				if !identityScope && !candidateReady {
					if err := resolveCandidate(); err != nil {
						return err
					}
				}
				inScope := false
				if identityScope {
					identityKey := candidateIdentityKey
					if stableCursorPaging {
						identityKey = physicalCursorKey
					}
					inScope, err = directory.IdentityKeyInScope(
						scopeBase,
						identityKey,
						route.scope,
					)
					if err != nil {
						return err
					}
				} else {
					inScope = directory.InScope(scopeBase, candidate, route.scope)
				}
				if !inScope {
					return nil
				}
				if projectSubschemaReference {
					entry = withSubschemaReference(entry)
				}
				entry, err = collectivePlans.apply(database.partition, tx, entry)
				if err != nil {
					return err
				}
				unprojectedEntry := entry
				filterEntry := entry
				effectiveFilter := request.Filter
				if !controls.manageDsaIT {
					projected, projectedFilterEntry, projectErr :=
						dynlistPlans.apply(*database, entry)
					if projectErr != nil {
						return projectErr
					}
					entry = projected
					filterEntry = projectedFilterEntry
					if controls.paging != nil &&
						!dynlistFilterReferencesMemberOf(
							state.runtime.schema,
							*database,
							request.Filter,
						) {
						filterEntry = unprojectedEntry
					}
					entry, filterEntry, effectiveFilter, projectErr =
						nestGroupPlans.apply(*database, entry, filterEntry)
					if projectErr != nil {
						if failure, ok := nestGroupResourceLimitResult(projectErr); ok {
							result = failure
							return errStopSearch
						}
						return projectErr
					}
				}
				var subentry, alias, referral bool
				if preparedEntryClasses != nil {
					classFlags := preparedEntryClasses.Match(entry)
					subentry = classFlags&searchEntryClassSubentry != 0
					alias = classFlags&searchEntryClassAlias != 0
					referral = classFlags&searchEntryClassReferral != 0
				} else {
					subentry = state.runtime.schema.EntryHasObjectClass(entry, "subentry")
					alias = state.runtime.schema.EntryHasObjectClass(entry, "alias")
					referral = state.runtime.schema.EntryHasObjectClass(entry, "referral")
				}
				if !subentrySearchVisibleClassified(
					subentry,
					request.Scope,
					controls.subentries,
				) {
					return nil
				}
				if derefAliasesWhileSearching(request.DerefAliases) && alias {
					if derefAliasesWhileFinding(request.DerefAliases) {
						return nil
					}
					if err := resolveCandidate(); err != nil {
						return err
					}
					if !candidate.Equal(comparisonBase) {
						return nil
					}
				}
				if !controls.manageDsaIT && referral {
					if routeRoot || (server.allowed(
						state.runtime,
						tx,
						state.boundDN,
						entry,
						"entry",
						nil,
						acl.Read,
					) && server.allowed(
						state.runtime,
						tx,
						state.boundDN,
						entry,
						"ref",
						nil,
						acl.Read,
					)) {
						referrals, err := rewrittenReferralURLs(
							entry,
							nil,
							referralScopeForReference(request.Scope),
						)
						if err != nil {
							return err
						}
						if len(referrals) > 0 {
							references = append(references, referrals)
						}
					}
					return nil
				}
				var matches bool
				if routeRoot && preparedRootSubstring != nil &&
					len(database.nestGroups) == 0 {
					matches, err = preparedRootSubstring.Match(filterEntry)
				} else if routeRoot {
					matches, err = effectiveFilter.MatchWith(
						filterEntry,
						state.runtime.schema,
					)
				} else {
					matches, err = server.filterMatches(
						state.runtime,
						tx,
						state.boundDN,
						filterEntry,
						effectiveFilter,
					)
				}
				if err != nil {
					result.Code = ldapwire.ResultInappropriateMatching
					result.DiagnosticMessage = err.Error()
					return errStopSearch
				}
				if !matches {
					return nil
				}
				if !routeRoot && !server.allowed(
					state.runtime,
					tx,
					state.boundDN,
					entry,
					"entry",
					nil,
					acl.Read,
				) {
					return nil
				}
				if !controls.manageDsaIT &&
					retcodeInDirectoryEnabled(
						state.runtime.databases,
						*database,
					) {
					item, applies := retcodeItemFromDirectoryEntry(
						state.runtime,
						entry,
						retcodeOperationSearch,
					)
					if applies {
						if item.code == ldapwire.ResultSuccess && !item.preDisconnect {
							retcodeSleep(item.sleepSeconds)
						} else {
							inDirectoryRetcodeResult = &item
							return errStopSearch
						}
					}
				}
				var syncUUID ldapwire.SyncUUID
				if syncSearch != nil {
					syncUUID, err = syncUUIDFromEntry(storedEntry)
					if err != nil {
						result.Code = ldapwire.ResultOperationsError
						result.DiagnosticMessage = err.Error()
						return errStopSearch
					}
					syncSearch.observeCurrent(syncUUID)
					if !syncSearch.entryChanged(storedEntry) {
						if !syncSearch.refreshDeletes {
							syncSearch.present = append(
								syncSearch.present,
								syncUUID,
							)
						}
						return nil
					}
				} else {
					entry, err = withSyncProviderContextCSNs(
						reader,
						*database,
						entry,
					)
					if err != nil {
						return err
					}
				}
				if snapshotPaging {
					if len(snapshotItems) >= remaining {
						sortTruncated = true
						return errStopSearch
					}
					itemBytes := int64(unsafe.Sizeof(pagedSortedItem{})) +
						int64(len(entry.DN)*2)
					if itemBytes > server.config.MaxSearchCandidateBytes-snapshotBytes {
						candidates = nil
						result = ldapwire.ResultError(
							ldapwire.ResultAdminLimitExceeded,
							"paged search snapshot budget exceeded",
						)
						return errStopSearch
					}
					snapshotBytes += itemBytes
					snapshotItems = append(snapshotItems, pagedSortedItem{
						route:        routeIndex,
						dn:           entry.DN,
						normalizedDN: candidate,
					})
					if len(candidates) >= entryLimit && !snapshotEntriesCacheable {
						return nil
					}
				}
				var sortReadable directory.Entry
				if sorting.active() {
					if routeRoot {
						sortReadable = entry
					} else {
						sortReadable = server.attributesWithPrivilege(
							state.runtime,
							tx,
							state.boundDN,
							entry,
							acl.Read,
							false,
						)
					}
					if database.dds != nil {
						sortReadable = projectDDSRemainingTTL(
							sortReadable,
							entry,
							time.Now(),
						)
					}
					if syncSearch != nil {
						sortReadable = stripSyncExcludedAttributes(
							state.runtime.schema,
							sortReadable,
						)
					}
				}
				responseEntry, err := collectResponses.apply(*database, entry)
				if err != nil {
					return err
				}
				var readable directory.Entry
				if routeRoot {
					readable = rootVisibleEntry(responseEntry, request.TypesOnly)
				} else {
					readable = server.attributesWithPrivilege(
						state.runtime,
						tx,
						state.boundDN,
						responseEntry,
						acl.Read,
						request.TypesOnly,
					)
				}
				if database.dds != nil {
					readable = projectDDSRemainingTTL(
						readable,
						responseEntry,
						time.Now(),
					)
				}
				if syncSearch != nil {
					readable = stripSyncExcludedAttributes(
						state.runtime.schema,
						readable,
					)
				}
				var selected directory.Entry
				if hasPreparedSelection {
					selected = preparedSelection.Select(readable, request.TypesOnly)
				} else {
					selected = server.selectEntry(
						state.runtime,
						readable,
						request.Attributes,
						request.TypesOnly,
					)
				}
				if snapshotEntriesCacheable {
					item := &snapshotItems[len(snapshotItems)-1]
					previousBytes := pagedSortedItemBytes(*item)
					previousDN := item.dn
					previousNormalizedDN := item.normalizedDN
					item.dn = ""
					item.normalizedDN = directory.DN{}
					item.selected = selected
					item.hasSelected = true
					delta := pagedSortedItemBytes(*item) - previousBytes
					if delta > server.config.MaxSearchCandidateBytes-snapshotBytes {
						item.dn = previousDN
						item.normalizedDN = previousNormalizedDN
						item.selected = directory.Entry{}
						item.hasSelected = false
						snapshotEntriesCacheable = false
					} else {
						snapshotBytes += delta
					}
				}
				if valueSortEnabled && syncSearch == nil &&
					(controls.valueSort == nil || !controls.valueSort.raw) {
					applyValueSort(
						state.runtime.schema,
						valueSortRulesForDatabase(
							state.runtime.databases,
							*database,
						),
						&selected,
					)
				}
				if snapshotPaging && len(candidates) >= entryLimit {
					return nil
				}
				if !sorting.active() && !snapshotPaging && len(candidates) >= entryLimit {
					if paging != nil && entryLimit == paging.size {
						hasMore = true
					} else {
						result.Code = ldapwire.ResultSizeLimitExceeded
					}
					return errStopSearch
				}
				retainedCandidate := searchCandidate{
					selected:     selected,
					readable:     sortReadable,
					normalizedDN: candidate,
					route:        routeIndex,
					dn:           entry.DN,
					cursorKey:    candidateCursorKey,
					syncUUID:     syncUUID,
				}
				candidateSize := searchCandidateRetainedBytes(retainedCandidate)
				if candidateSize <= 0 {
					candidateSize = 1
				}
				if candidateSize > server.config.MaxSearchCandidateBytes-candidateBytes ||
					(sorting.active() && len(candidates) >= server.config.MaxSearchCandidates) {
					candidates = nil
					result = ldapwire.ResultError(
						ldapwire.ResultAdminLimitExceeded,
						"search candidate budget exceeded",
					)
					return errStopSearch
				}
				if !server.searchMemoryLimiter.tryAcquire(candidateSize) {
					candidates = nil
					result = ldapwire.ResultError(
						ldapwire.ResultAdminLimitExceeded,
						"process search memory budget exceeded",
					)
					return errStopSearch
				}
				candidateBytes += candidateSize
				processSearchBytes += candidateSize
				candidates = append(candidates, retainedCandidate)
				if !sorting.active() {
					lastCursor = pagedSearchCursor{
						route: routeIndex,
						dnKey: candidateCursorKey,
						valid: true,
					}
				}
				return nil
			}
			var err error
			if translucentRoute == nil {
				var planned bool
				planned, _, err = storage.ForEachFilterCandidate(
					tx,
					request.Filter,
					visitEntry,
				)
				if err == nil && !planned {
					absent, cached, cacheErr := state.runtime.unindexedValues.definitelyAbsent(
						state.runtime.schema,
						*database,
						tx,
						request.Filter,
					)
					if cacheErr != nil {
						err = cacheErr
					} else if !cached || !absent {
						streamed := false
						if stableCursorPaging {
							after := ""
							if paging.cursor.valid {
								after = paging.cursor.dnKey
							}
							streamed, err = storage.ForEachStablePhysicalEntryAfter(
								tx,
								after,
								func(entry directory.Entry, key string) error {
									physicalCursorKey = key
									return visitEntry(entry)
								},
							)
						} else if !sorting.active() && syncSearch == nil {
							streamed, err = storage.ForEachStablePhysicalEntry(tx, visitEntry)
						}
						if err == nil && !streamed {
							err = tx.ForEach(visitEntry)
						}
					}
				}
			} else {
				for _, remoteEntry := range translucentRoute.entries {
					if err = visitEntry(remoteEntry); err != nil {
						break
					}
				}
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopSearch) {
		if paging != nil {
			clearPagedSearch(state)
		}
		if failure := asOperationFailure(err); failure != nil {
			return server.writeSearchDoneWithControls(
				connection,
				message.ID,
				failure.result,
				failure.controls,
			)
		}
		return fmt.Errorf("search directory: %w", err)
	}
	if inDirectoryRetcodeResult != nil {
		return server.writeRetcodeInDirectorySearch(
			connection,
			state,
			message,
			candidates,
			*inDirectoryRetcodeResult,
		)
	}
	chainedPackets, references, chainFailure := server.chainSearchContinuations(
		ctx,
		state,
		message,
		references,
	)
	if chainFailure != nil && result.Code == ldapwire.ResultSuccess {
		result = *chainFailure
	}

	if sorting.active() {
		additionalReservation := candidateBytes +
			int64(len(candidates)*len(sorting.keys)*32)
		if additionalReservation > 0 &&
			!server.searchMemoryLimiter.tryAcquire(additionalReservation) {
			candidates = nil
			result = ldapwire.ResultError(
				ldapwire.ResultAdminLimitExceeded,
				"process search sort memory budget exceeded",
			)
			sorting.fail(ldapwire.ResultAdminLimitExceeded, "")
		} else {
			processSearchBytes += additionalReservation
		}
	}
	if sorting.active() && result.Code == ldapwire.ResultSuccess {
		if err := sortSearchCandidates(
			state.runtime.schema,
			sorting,
			candidates,
		); err != nil {
			attributeType := ""
			if len(sorting.keys) > 0 {
				attributeType = sorting.keys[0].attribute
			}
			sorting.fail(
				ldapwire.ResultInappropriateMatching,
				attributeType,
			)
			if sorting.critical {
				candidates = nil
				result = ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"server-side sorting could not be performed",
				)
			}
		}
	}

	if virtualListView != nil {
		if !sorting.active() {
			failure := newVirtualListViewFailure(
				sorting.result,
				"server-side sorting could not be performed for VLV",
				len(candidates),
				nil,
			)
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				sorting,
				nil,
				failure.result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(failure.response),
			)
		}
		view := virtualListView.state
		if view == nil {
			var err error
			view, err = server.startVirtualListView(
				state,
				virtualListView,
				candidates,
				sortLease,
			)
			if err != nil {
				if errors.Is(err, errVirtualListViewMemoryLimit) {
					return server.writeSearchDone(
						connection,
						message.ID,
						ldapwire.ResultError(ldapwire.ResultAdminLimitExceeded, err.Error()),
					)
				}
				return fmt.Errorf("create VLV context: %w", err)
			}
			sortLease = nil
		}
		start, end, target, code, windowErr := virtualListViewWindow(
			state.runtime.schema,
			virtualListView.request,
			sorting.keys[0],
			view.items,
		)
		if code != ldapwire.ResultSuccess || windowErr != nil {
			diagnostic := "VLV target is invalid"
			if windowErr != nil {
				diagnostic = windowErr.Error()
			}
			failure := newVirtualListViewFailure(
				code,
				diagnostic,
				len(view.items),
				view.contextID,
			)
			return server.writeSearchResultWithControls(
				connection,
				message.ID,
				state,
				nil,
				sorting,
				nil,
				failure.result,
				pagedSearchCursor{},
				false,
				virtualListViewResponseControl(failure.response),
			)
		}
		windowCandidates := virtualListViewSearchCandidates(
			candidates,
			view.items[start:end],
		)
		if len(windowCandidates) > limit {
			windowCandidates = windowCandidates[:limit]
			if result.Code == ldapwire.ResultSuccess {
				result.Code = ldapwire.ResultSizeLimitExceeded
			}
		}
		response := ldapwire.VirtualListViewResponse{
			TargetPosition: int64(target),
			ContentCount:   int64(len(view.items)),
			Result:         ldapwire.ResultSuccess,
			ContextID:      view.contextID,
			HasContextID:   true,
		}
		if syncSearch != nil {
			responseControls := serverSideSortResponseControl(
				sorting,
				result,
				len(windowCandidates),
			)
			responseControls = append(
				responseControls,
				virtualListViewResponseControl(response)...,
			)
			return server.writeSyncSearch(
				ctx,
				connection,
				state,
				message.ID,
				request,
				syncSearch,
				windowCandidates,
				result,
				responseControls,
			)
		}
		entries := selectedSearchEntries(windowCandidates)
		return server.writeSearchResultWithChainedReferencesAndControls(
			connection,
			message.ID,
			state,
			nil,
			sorting,
			entries,
			result,
			pagedSearchCursor{},
			false,
			references,
			virtualListViewResponseControl(response),
			chainedPackets,
		)
	}

	if len(candidates) > limit {
		sortTruncated = true
		candidates = candidates[:limit]
		if paging == nil && result.Code == ldapwire.ResultSuccess {
			result.Code = ldapwire.ResultSizeLimitExceeded
		}
	}

	var entries []directory.Entry
	if sorting.active() {
		if paging == nil {
			entries = selectedSearchEntries(candidates)
		} else {
			pageEnd := min(paging.size, len(candidates))
			entries = selectedSearchEntries(candidates[:pageEnd])
			paging.sorted = &pagedSortedSearch{
				items:     pagedSortedItems(candidates),
				offset:    pageEnd,
				truncated: sortTruncated,
			}
			switch {
			case result.Code != ldapwire.ResultSuccess:
				paging.sorted = nil
			case pageEnd < len(candidates):
				hasMore = true
			case sortTruncated:
				result.Code = ldapwire.ResultSizeLimitExceeded
			}
		}
	} else if snapshotPaging {
		pageEnd := min(entryLimit, len(candidates))
		entries = selectedSearchEntries(candidates[:pageEnd])
		if pageEnd > 0 {
			last := candidates[pageEnd-1]
			lastCursor = pagedSearchCursor{
				route: last.route,
				dnKey: last.cursorKey,
				valid: true,
			}
		}
		paging.sorted = &pagedSortedSearch{
			items:     snapshotItems,
			offset:    pageEnd,
			truncated: sortTruncated,
			live:      true,
		}
		if snapshotCacheable && paging.hasStorageRevision {
			state.runtime.pagedSnapshots.put(
				paging.fingerprint,
				paging.storageRevision,
				snapshotItems,
			)
		}
		switch {
		case result.Code != ldapwire.ResultSuccess:
			paging.sorted = nil
		case pageEnd < len(snapshotItems):
			hasMore = true
		case sortTruncated:
			result.Code = ldapwire.ResultSizeLimitExceeded
		}
	} else {
		if paging != nil && len(candidates) > entryLimit {
			candidates = candidates[:entryLimit]
			hasMore = true
		}
		if paging != nil && len(candidates) > 0 {
			last := candidates[len(candidates)-1]
			lastCursor = pagedSearchCursor{
				route: last.route,
				dnKey: last.cursorKey,
				valid: true,
			}
		}
		entries = selectedSearchEntries(candidates)
	}

	if sorting.active() &&
		paging != nil &&
		paging.sorted != nil &&
		hasMore &&
		result.Code == ldapwire.ResultSuccess {
		paging.sortLease = sortLease
	}
	if syncSearch != nil {
		responseControls := serverSideSortResponseControl(
			sorting,
			result,
			len(candidates),
		)
		return server.writeSyncSearch(
			ctx,
			connection,
			state,
			message.ID,
			request,
			syncSearch,
			candidates,
			result,
			responseControls,
		)
	}
	if resultCacheable && hasResultCacheRevision &&
		result.Code == ldapwire.ResultSuccess && !hasMore &&
		len(entries) <= 4 && len(references) == 0 && len(chainedPackets) == 0 {
		state.runtime.searchResults.put(
			resultCacheFingerprint,
			resultCacheRevision,
			entries,
		)
	}
	writeErr := server.writeSearchResultWithChainedReferences(
		connection,
		message.ID,
		state,
		paging,
		sorting,
		entries,
		result,
		lastCursor,
		hasMore,
		references,
		chainedPackets,
	)
	if sortLease != nil &&
		state.pagedSearch != nil &&
		state.pagedSearch.sortLease == sortLease {
		sortLease = nil
	}
	return writeErr
}

func pagedSnapshotFilterCacheable(
	registry *schema.Registry,
	filter directory.Filter,
) bool {
	if registry == nil {
		return false
	}
	if filter.Attribute != "" && registry.IsOperational(filter.Attribute) {
		return false
	}
	if filter.Kind == directory.FilterExtensible && filter.Attribute == "" {
		return false
	}
	for _, child := range filter.Children {
		if !pagedSnapshotFilterCacheable(registry, child) {
			return false
		}
	}
	return true
}

func databaseSupportsPhysicalKeyPaging(
	database runtimeDatabase,
	filter directory.Filter,
) bool {
	if filter.Kind != directory.FilterSubstrings {
		return false
	}
	normalizer, ok := database.dnNormalizer.(*databaseEqualityIndexNormalizer)
	if !ok {
		return false
	}
	_, initial, any, final, err := normalizer.ResolveSubstringIndexAttribute(
		filter.Attribute,
	)
	return err == nil && !initial && !any && !final
}

func pagedSnapshotAttributesCacheable(
	registry *schema.Registry,
	attributes []string,
) bool {
	if registry == nil {
		return false
	}
	for _, attribute := range attributes {
		switch attribute {
		case "", "1.1":
			continue
		case "*", "+":
			return false
		}
		if registry.IsOperational(attribute) {
			return false
		}
	}
	return true
}

func normalizeConnectionSearchRequestBase(
	state *connectionState,
	value string,
) (directory.DN, error) {
	if state != nil {
		if cached, ok := state.dnCache.get(state.runtime, value); ok {
			return cached, nil
		}
	}
	var runtime *runtimeState
	if state != nil {
		runtime = state.runtime
	}
	dn, err := normalizeSearchRequestBase(runtime, value)
	if err == nil && state != nil {
		state.dnCache.put(runtime, value, dn)
	}
	return dn, err
}

func invalidSearchParameterResult(
	request ldapwire.SearchRequest,
) *ldapwire.Result {
	diagnostic := ""
	switch {
	case request.TimeLimit < 0:
		diagnostic = "invalid time limit"
	case request.SizeLimit < 0:
		diagnostic = "invalid size limit"
	case request.Scope < directory.ScopeBase || request.Scope > directory.ScopeChildren:
		diagnostic = "invalid scope"
	case request.DerefAliases < 0 || request.DerefAliases > 3:
		diagnostic = "invalid deref"
	default:
		return nil
	}
	result := ldapwire.ResultError(ldapwire.ResultProtocolError, diagnostic)
	return &result
}

func (server *Server) ensureSearchEqualityIndexes(
	ctx context.Context,
	runtime *runtimeState,
	routes []databaseSearchRoute,
) error {
	seen := make(map[int]struct{}, len(routes))
	for _, route := range routes {
		if _, duplicate := seen[route.databaseIndex]; duplicate {
			continue
		}
		seen[route.databaseIndex] = struct{}{}
		if route.databaseIndex < 0 || route.databaseIndex >= len(runtime.databases) {
			continue
		}
		database := &runtime.databases[route.databaseIndex]
		initialization := database.equalityIndexInit
		if initialization == nil || database.partition == "" {
			continue
		}
		revision, hasRevision := server.currentStorageSnapshotRevision(ctx)
		if initialization.readyFor(revision, hasRevision) {
			continue
		}
		schema, ok := database.dnNormalizer.(storage.EqualityIndexSchema)
		if !ok {
			continue
		}
		current, err := server.searchEqualityIndexesCurrent(
			ctx,
			database.partition,
			schema,
		)
		if err != nil {
			server.logSearchEqualityIndexError(database, err)
			return err
		}
		if current {
			initialization.markReady(revision, hasRevision)
			continue
		}
		initialization.mu.Lock()
		current, err = server.searchEqualityIndexesCurrent(
			ctx,
			database.partition,
			schema,
		)
		if err == nil && !current {
			err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
				return storage.EnsureEqualityIndexes(
					writer,
					database.partition,
					schema,
				)
			})
		}
		initialization.mu.Unlock()
		if err == nil {
			revision, hasRevision = server.currentStorageSnapshotRevision(ctx)
			initialization.markReady(revision, hasRevision)
		}
		if err != nil {
			server.logSearchEqualityIndexError(database, err)
			return err
		}
	}
	return nil
}

func (server *Server) searchEqualityIndexesCurrent(
	ctx context.Context,
	partition string,
	schema storage.EqualityIndexSchema,
) (bool, error) {
	var current bool
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		var err error
		current, err = storage.EqualityIndexesCurrent(reader, partition, schema)
		return err
	})
	return current, err
}

func (server *Server) logSearchEqualityIndexError(
	database *runtimeDatabase,
	err error,
) {
	server.config.Logger.Error(
		"prepare LDAP equality indexes",
		"database", database.name,
		"partition", database.partition,
		"error", err,
	)
}

func selectedSearchEntries(candidates []searchCandidate) []directory.Entry {
	entries := make([]directory.Entry, len(candidates))
	for index := range candidates {
		entries[index] = candidates[index].selected
	}
	return entries
}

func virtualListViewSearchCandidates(
	candidates []searchCandidate,
	items []virtualListViewItem,
) []searchCandidate {
	type candidateKey struct {
		route int
		dn    string
	}
	byKey := make(map[candidateKey]searchCandidate, len(candidates))
	for _, candidate := range candidates {
		byKey[candidateKey{
			route: candidate.route,
			dn:    candidate.dn,
		}] = candidate
	}
	window := make([]searchCandidate, 0, len(items))
	for _, item := range items {
		candidate, exists := byKey[candidateKey{
			route: item.route,
			dn:    item.dn,
		}]
		if exists {
			window = append(window, candidate)
		}
	}
	return window
}

func pagedSortedItems(candidates []searchCandidate) []pagedSortedItem {
	items := make([]pagedSortedItem, len(candidates))
	for index := range candidates {
		items[index] = pagedSortedItem{
			route:        candidates[index].route,
			dn:           candidates[index].dn,
			normalizedDN: candidates[index].normalizedDN,
		}
	}
	return items
}

func (server *Server) continueSortedPagedSearch(
	ctx context.Context,
	state *connectionState,
	routes []databaseSearchRoute,
	request ldapwire.SearchRequest,
	paging *pagedSearchContext,
	deadline time.Time,
	rawValueOrder bool,
	manageDsaIT bool,
) ([]directory.Entry, ldapwire.Result, bool, error) {
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	entries := make([]directory.Entry, 0, paging.size)
	hasMore := false
	sorted := paging.sorted
	if sorted == nil {
		return nil, result, false, errors.New("sorted paged search state is absent")
	}
	pageEnd := min(sorted.offset+paging.size, len(sorted.items))
	allSelected := sorted.live
	for index := sorted.offset; allSelected && index < pageEnd; index++ {
		allSelected = sorted.items[index].hasSelected
	}
	if allSelected {
		for sorted.offset < pageEnd {
			if expired(deadline) {
				result.Code = ldapwire.ResultTimeLimitExceeded
				return entries, result, false, nil
			}
			entries = append(entries, sorted.items[sorted.offset].selected)
			sorted.offset++
		}
		if sorted.offset < len(sorted.items) {
			return entries, result, true, nil
		}
		if sorted.truncated {
			result.Code = ldapwire.ResultSizeLimitExceeded
		}
		return entries, result, false, nil
	}
	valueSortEnabled := runtimeSupportsValueSort(state.runtime.databases)

	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		collectivePlans := newCollectiveAttributePlanCache(
			state.runtime.schema,
			state.runtime.collectivePlans,
		)
		collectResponses := newCollectProjectionCache(
			server,
			state.runtime,
			reader,
			state.boundDN,
		)
		dynlistPlans := newDynlistProjectionCache(
			ctx,
			server,
			state.runtime,
			reader,
			state.boundDN,
			dynlistProjectionRequest{
				attributes: request.Attributes,
				filter:     &request.Filter,
			},
		)
		nestGroupPlans := newNestGroupProjectionCache(
			ctx,
			server,
			state.runtime,
			reader,
			state.boundDN,
			nestGroupProjectionRequest{
				attributes: request.Attributes,
				typesOnly:  request.TypesOnly,
				filter:     request.Filter,
			},
		)
		routeRoots := make(map[int]bool, len(routes))
		for sorted.offset < len(sorted.items) {
			if expired(deadline) {
				result.Code = ldapwire.ResultTimeLimitExceeded
				return nil
			}
			if len(entries) >= paging.size {
				hasMore = true
				return nil
			}
			item := sorted.items[sorted.offset]
			if item.hasSelected {
				entries = append(entries, item.selected)
				sorted.offset++
				continue
			}
			if item.route < 0 || item.route >= len(routes) {
				return fmt.Errorf("sorted paged search route %d is invalid", item.route)
			}
			database := &state.runtime.databases[routes[item.route].databaseIndex]
			tx := readerForDatabase(reader, *database)
			dn := item.normalizedDN
			if dn.Depth() == 0 && item.dn != "" {
				var err error
				dn, err = directory.ParseDN(item.dn)
				if err != nil {
					return fmt.Errorf("parse sorted paged search DN %q: %w", item.dn, err)
				}
				dn, err = storage.NormalizeReaderDN(tx, dn)
				if err != nil {
					return fmt.Errorf("normalize sorted paged search DN %q: %w", item.dn, err)
				}
			}
			entry, err := tx.Get(dn)
			if errors.Is(err, storage.ErrEntryNotFound) {
				sorted.offset++
				continue
			}
			if err != nil {
				return err
			}
			entry = withSubschemaReference(entry)
			entry, err = collectivePlans.apply(database.partition, tx, entry)
			if err != nil {
				return err
			}
			if !manageDsaIT {
				entry, _, err = dynlistPlans.apply(*database, entry)
				if err != nil {
					return err
				}
				entry, err = nestGroupPlans.project(*database, entry)
				if err != nil {
					if failure, ok := nestGroupResourceLimitResult(err); ok {
						result = failure
						return nil
					}
					return err
				}
			}
			entry, err = withSyncProviderContextCSNs(
				reader,
				*database,
				entry,
			)
			if err != nil {
				return err
			}
			routeRoot, knownRoot := routeRoots[item.route]
			if !knownRoot {
				routeRoot = server.isDatabaseRoot(state.runtime, *database, state.boundDN)
				routeRoots[item.route] = routeRoot
			}
			if !routeRoot && !server.allowed(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				"entry",
				nil,
				acl.Read,
			) {
				sorted.offset++
				continue
			}
			responseEntry, err := collectResponses.apply(*database, entry)
			if err != nil {
				return err
			}
			var readable directory.Entry
			if routeRoot {
				readable = rootVisibleEntry(responseEntry, request.TypesOnly)
			} else {
				readable = server.attributesWithPrivilege(
					state.runtime,
					tx,
					state.boundDN,
					responseEntry,
					acl.Read,
					request.TypesOnly,
				)
			}
			if database.dds != nil {
				readable = projectDDSRemainingTTL(readable, responseEntry, time.Now())
			}
			selected := server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			)
			if valueSortEnabled && !rawValueOrder {
				applyValueSort(
					state.runtime.schema,
					valueSortRulesForDatabase(state.runtime.databases, *database),
					&selected,
				)
			}
			entries = append(entries, selected)
			sorted.offset++
		}
		if sorted.truncated {
			result.Code = ldapwire.ResultSizeLimitExceeded
		}
		return nil
	})
	return entries, result, hasMore, err
}

type databaseSearchRoute struct {
	databaseIndex int
	base          directory.DN
	scope         directory.Scope
}

func databaseSearchRoutes(
	databases []runtimeDatabase,
	base directory.DN,
	scope directory.Scope,
) []databaseSearchRoute {
	primaryIndex := databaseIndexForDN(databases, base)
	if primaryIndex < 0 {
		return nil
	}
	return databaseSearchRoutesFromPrimary(
		databases,
		primaryIndex,
		base,
		scope,
	)
}

func databaseSearchRoutesFromNormalizedBase(
	databases []runtimeDatabase,
	base directory.DN,
	scope directory.Scope,
) []databaseSearchRoute {
	primaryIndex := databaseIndexForNormalizedDN(databases, base)
	if primaryIndex < 0 {
		return nil
	}
	return databaseSearchRoutesFromPrimary(
		databases,
		primaryIndex,
		base,
		scope,
	)
}

func databaseSearchRoutesFromPrimary(
	databases []runtimeDatabase,
	primaryIndex int,
	base directory.DN,
	scope directory.Scope,
) []databaseSearchRoute {
	if primaryIndex < 0 || primaryIndex >= len(databases) {
		return nil
	}
	superiorIndex := primaryIndex
	if databases[primaryIndex].subordinate {
		superiorIndex = glueSuperiorDatabaseIndex(databases, primaryIndex)
		if superiorIndex < 0 {
			return nil
		}
	}
	routes := []databaseSearchRoute{{
		databaseIndex: primaryIndex,
		base:          base,
		scope:         scope,
	}}
	if scope == directory.ScopeBase {
		return routes
	}

	var subordinateRoutes []databaseSearchRoute
	for index := range databases {
		database := &databases[index]
		if index == primaryIndex ||
			database.hidden ||
			database.disabled ||
			!database.subordinate ||
			len(database.suffixes) != 1 ||
			glueSuperiorDatabaseIndex(databases, index) != superiorIndex {
			continue
		}

		suffix := database.suffixes[0]
		route := databaseSearchRoute{
			databaseIndex: index,
			base:          suffix,
		}
		switch scope {
		case directory.ScopeSingleLevel:
			parent, ok := suffix.Parent()
			if !ok || !databaseDNEqual(*database, parent, base) {
				continue
			}
			route.scope = directory.ScopeBase
		case directory.ScopeWholeSubtree:
			if !databaseDNAtOrBelow(*database, suffix, base) {
				continue
			}
			route.scope = directory.ScopeWholeSubtree
		case directory.ScopeChildren:
			if !databaseDNStrictlyBelow(*database, suffix, base) {
				continue
			}
			route.scope = directory.ScopeWholeSubtree
		default:
			continue
		}
		subordinateRoutes = append(subordinateRoutes, route)
	}
	sort.SliceStable(subordinateRoutes, func(i, j int) bool {
		return subordinateRoutes[i].base.Depth() >
			subordinateRoutes[j].base.Depth()
	})
	return append(routes, subordinateRoutes...)
}

func (server *Server) searchRootDSE(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
	assertion *directory.Filter,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
) error {
	entry := server.rootDSE(state)
	var selected *directory.Entry
	assertionFailed := false
	err := server.config.Store.View(ctx, func(tx storage.Reader) error {
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			assertion,
		); err != nil {
			assertionFailed = true
			return nil
		}
		matches, err := server.filterMatches(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			request.Filter,
		)
		if err != nil {
			return err
		}
		if !matches || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			"entry",
			nil,
			acl.Read,
		) {
			return nil
		}
		readable := server.attributesWithPrivilege(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			acl.Read,
			request.TypesOnly && !sorting.active(),
		)
		value := server.selectEntry(
			state.runtime,
			readable,
			request.Attributes,
			request.TypesOnly,
		)
		selected = &value
		return nil
	})
	if err != nil {
		return server.writeSearchResult(
			connection,
			messageID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.ResultError(ldapwire.ResultInappropriateMatching, err.Error()),
			pagedSearchCursor{},
			false,
		)
	}
	if assertionFailed {
		return server.writeSearchResult(
			connection,
			messageID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.Result{Code: ldapwire.ResultAssertionFailed},
			pagedSearchCursor{},
			false,
		)
	}
	var entries []directory.Entry
	if selected != nil {
		entries = append(entries, *selected)
	}
	return server.writeSearchResult(
		connection,
		messageID,
		state,
		paging,
		sorting,
		entries,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		pagedSearchCursor{},
		false,
	)
}

func (server *Server) searchSubschema(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
	assertion *directory.Filter,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
) error {
	entry := server.subschemaEntry(state.runtime)
	candidate, err := state.runtime.schema.NormalizeDN(entry.DN)
	if err != nil {
		if paging != nil {
			clearPagedSearch(state)
		}
		return fmt.Errorf("parse subschema DN: %w", err)
	}
	base, err := state.runtime.schema.NormalizeDN(request.BaseDN)
	if err != nil {
		return server.writeSearchResult(
			connection,
			messageID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
			pagedSearchCursor{},
			false,
		)
	}
	if !directory.InScope(base, candidate, request.Scope) {
		return server.writeSearchResult(
			connection,
			messageID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			pagedSearchCursor{},
			false,
		)
	}
	var selected *directory.Entry
	assertionFailed := false
	err = server.config.Store.View(ctx, func(tx storage.Reader) error {
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			assertion,
		); err != nil {
			assertionFailed = true
			return nil
		}
		matches, err := server.filterMatches(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			request.Filter,
		)
		if err != nil {
			return err
		}
		if !matches || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			"entry",
			nil,
			acl.Read,
		) {
			return nil
		}
		readable := server.attributesWithPrivilege(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			acl.Read,
			request.TypesOnly && !sorting.active(),
		)
		value := server.selectEntry(
			state.runtime,
			readable,
			request.Attributes,
			request.TypesOnly,
		)
		selected = &value
		return nil
	})
	if err != nil {
		return server.writeSearchResult(
			connection,
			messageID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.ResultError(ldapwire.ResultInappropriateMatching, err.Error()),
			pagedSearchCursor{},
			false,
		)
	}
	if assertionFailed {
		return server.writeSearchResult(
			connection,
			messageID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.Result{Code: ldapwire.ResultAssertionFailed},
			pagedSearchCursor{},
			false,
		)
	}
	var entries []directory.Entry
	if selected != nil {
		entries = append(entries, *selected)
	}
	return server.writeSearchResult(
		connection,
		messageID,
		state,
		paging,
		sorting,
		entries,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		pagedSearchCursor{},
		false,
	)
}

func (server *Server) rootDSE(
	state *connectionState,
) directory.Entry {
	runtime := state.runtime
	var namingContexts []string
	var configContexts []string
	var monitorContexts []string
	for _, database := range runtime.databases {
		if database.hidden || len(database.suffixes) == 0 {
			continue
		}
		switch {
		case isConfigDatabase(database):
			for _, suffix := range database.suffixes {
				configContexts = append(configContexts, suffix.String())
			}
		case isMonitorDatabase(database):
			for _, suffix := range database.suffixes {
				monitorContexts = append(monitorContexts, suffix.String())
			}
		default:
			if database.subordinate && !database.advertise {
				continue
			}
			for _, suffix := range database.suffixes {
				namingContexts = append(namingContexts, suffix.String())
			}
		}
	}
	sort.Strings(namingContexts)
	sort.Strings(configContexts)
	sort.Strings(monitorContexts)

	entry := directory.Entry{
		DN: "",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("top")}},
			{Description: "subschemaSubentry", Values: [][]byte{[]byte("cn=Subschema")}},
			{Description: "supportedLDAPVersion", Values: [][]byte{[]byte("3")}},
			{Description: "vendorName", Values: [][]byte{[]byte("ldap-go")}},
			{Description: "vendorVersion", Values: [][]byte{[]byte("0.1-dev")}},
		},
	}
	if len(namingContexts) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "namingContexts",
			Values:      stringValues(namingContexts...),
		})
	}
	if len(configContexts) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "configContext",
			Values:      stringValues(configContexts...),
		})
	}
	if len(monitorContexts) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "monitorContext",
			Values:      stringValues(monitorContexts...),
		})
	}
	if len(runtime.defaultReferrals) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "ref",
			Values:      stringValues(runtime.defaultReferrals...),
		})
	}
	supportedExtensions := []string{
		cancelOID,
		passwordModifyOID,
		transactionStartOID,
		transactionEndOID,
		whoAmIOID,
	}
	if server.secureTransport != nil {
		supportedExtensions = append([]string{startTLSOID}, supportedExtensions...)
	}
	if runtimeSupportsPcachePrivateDatabase(runtime.databases) {
		supportedExtensions = append(supportedExtensions, pcacheQueryDeleteOID)
	}
	if onlineBackupConfigured(server.config) {
		supportedExtensions = append(supportedExtensions, onlineBackupOID)
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "supportedExtension",
		Values:      stringValues(supportedExtensions...),
	})
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "supportedFeatures",
		Values: stringValues(
			absoluteFiltersFeatureOID,
			objectClassAttributesFeatureOID,
		),
	})
	if subtrees := dynamicSubtrees(runtime.databases); len(subtrees) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "dynamicSubtrees",
			Values:      stringValues(subtrees...),
		})
	}
	supportedControls := []string{
		assertionControlOID,
		chainingBehaviorControlOID,
		manageDsaITControlOID,
		preReadControlOID,
		postReadControlOID,
		pagedResultsControlOID,
		subentriesControlOID,
		dontUseCopyControlOID,
		proxyAuthorizationControlOID,
		passwordPolicyControlOID,
		ldapwire.PasswordHashSchemeControlOID,
		accountUsabilityControlOID,
		netscapePasswordExpiredOID,
		netscapePasswordExpiringOID,
		ldapwire.MatchedValuesControlOID,
	}
	if runtimeSupportsDeref(runtime.databases) {
		supportedControls = append(supportedControls, ldapwire.DerefControlOID)
	}
	if runtimeSupportsServerSideSort(runtime.databases) {
		supportedControls = append(
			supportedControls,
			sortRequestControlOID,
			vlvRequestControlOID,
		)
	}
	if runtimeSupportsSyncProvider(runtime.databases) {
		supportedControls = append(supportedControls, syncRequestControlOID)
	}
	if runtimeSupportsPcachePrivateDatabase(runtime.databases) {
		supportedControls = append(supportedControls, pcachePrivateDBControl)
	}
	if runtimeSupportsNoOpSearch(runtime.databases) {
		supportedControls = append(supportedControls, noOpSearchControlOID)
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "supportedControl",
		Values:      stringValues(supportedControls...),
	})
	if mechanisms := supportedSASLMechanisms(state); len(mechanisms) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "supportedSASLMechanisms",
			Values:      stringValues(mechanisms...),
		})
	}
	mergeRootDSEAttributes(&entry, runtime.rootDSEAttributes)
	return entry
}

func (server *Server) subschemaEntry(runtime *runtimeState) directory.Entry {
	registry := runtime.schema
	entry := directory.Entry{
		DN: "cn=Subschema",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: stringValues(
					"top",
					"subentry",
					"subschema",
					"extensibleObject",
				),
			},
			{Description: "cn", Values: stringValues("Subschema")},
			{
				Description: "structuralObjectClass",
				Values:      stringValues("subentry"),
			},
			{
				Description: "attributeTypes",
				Values:      stringValues(registry.AttributeTypeDescriptions()...),
			},
			{
				Description: "objectClasses",
				Values:      stringValues(registry.ObjectClassDescriptions()...),
			},
		},
	}
	if descriptions := registry.DITContentRuleDescriptions(); len(descriptions) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "dITContentRules",
			Values:      stringValues(descriptions...),
		})
	}
	if descriptions := registry.NameFormDescriptions(); len(descriptions) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "nameForms",
			Values:      stringValues(descriptions...),
		})
	}
	if descriptions := registry.DITStructureRuleDescriptions(); len(descriptions) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "dITStructureRules",
			Values:      stringValues(descriptions...),
		})
	}
	return entry
}

func (server *Server) selectEntry(
	runtime *runtimeState,
	entry directory.Entry,
	requested []string,
	typesOnly bool,
) directory.Entry {
	return entry.SelectWithMatcher(
		requested,
		typesOnly,
		runtime.schema.IsOperational,
		runtime.schema.AttributeDescriptionSubtype,
	)
}

func expandObjectClassAttributeSelection(
	registry *schema.Registry,
	requested []string,
) []string {
	if registry == nil || len(requested) == 0 {
		return requested
	}
	expanded := make([]string, 0, len(requested))
	for _, selector := range requested {
		if len(selector) < 2 || selector[0] != '@' {
			expanded = append(expanded, selector)
			continue
		}
		attributes, extensible, known := registry.ObjectClassAttributeDescriptions(
			selector[1:],
		)
		if !known {
			expanded = append(expanded, selector)
			continue
		}
		if extensible {
			expanded = append(expanded, "*", "+")
		} else if len(attributes) == 0 {
			expanded = append(expanded, "1.1")
		} else {
			expanded = append(expanded, attributes...)
		}
	}
	return uniqueAttributeSelections(expanded)
}

func uniqueAttributeSelections(attributes []string) []string {
	seen := make(map[string]struct{}, len(attributes))
	unique := attributes[:0]
	for _, attribute := range attributes {
		key := strings.ToLower(attribute)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, attribute)
	}
	return unique
}

func subentrySearchVisible(
	runtime *runtimeState,
	entry directory.Entry,
	scope directory.Scope,
	visibility *bool,
) bool {
	subentry := runtime.schema.EntryHasObjectClass(entry, "subentry")
	return subentrySearchVisibleClassified(subentry, scope, visibility)
}

func subentrySearchVisibleClassified(
	subentry bool,
	scope directory.Scope,
	visibility *bool,
) bool {
	if visibility != nil {
		return subentry == *visibility
	}
	return scope == directory.ScopeBase || !subentry
}

const (
	searchEntryClassSubentry uint64 = 1 << iota
	searchEntryClassAlias
	searchEntryClassReferral
)

func withSubschemaReference(entry directory.Entry) directory.Entry {
	if entry.HasAttribute("subschemaSubentry") {
		return entry
	}
	entry = entry.Clone()
	entry.ReplaceValues("subschemaSubentry", stringValues("cn=Subschema"))
	return entry
}

func searchRequestsSubschemaReference(
	registry *schema.Registry,
	request ldapwire.SearchRequest,
	assertion *directory.Filter,
) bool {
	if registry == nil {
		return true
	}
	for _, attribute := range request.Attributes {
		if attribute == "+" || registry.AttributeDescriptionSubtype(
			attribute,
			"subschemaSubentry",
		) {
			return true
		}
	}
	if filterReferencesSubschema(registry, request.Filter) {
		return true
	}
	return assertion != nil && filterReferencesSubschema(registry, *assertion)
}

func filterReferencesSubschema(
	registry *schema.Registry,
	filter directory.Filter,
) bool {
	if filter.Attribute != "" && registry.AttributeDescriptionSubtype(
		filter.Attribute,
		"subschemaSubentry",
	) {
		return true
	}
	for _, child := range filter.Children {
		if filterReferencesSubschema(registry, child) {
			return true
		}
	}
	return false
}

func stringValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = []byte(values[i])
	}
	return result
}

func isRuntimeSubschemaDN(runtime *runtimeState, dn directory.DN) bool {
	if runtime == nil || runtime.schema == nil {
		return isSubschemaDN(dn)
	}
	subSchema, err := runtime.schema.NormalizeDN("cn=Subschema")
	return err == nil && dn.Equal(subSchema)
}

func normalizeSearchRequestBase(
	runtime *runtimeState,
	value string,
) (directory.DN, error) {
	legacy, err := directory.ParseDN(value)
	if err != nil {
		return directory.DN{}, err
	}
	if isConfigurationDN(legacy) || runtime == nil || runtime.schema == nil {
		return legacy, nil
	}
	return runtime.schema.NormalizeDN(value)
}

func isSubschemaDN(dn directory.DN) bool {
	subSchema, err := directory.ParseDN("cn=Subschema")
	return err == nil && dn.Equal(subSchema)
}

func (server *Server) disclosedAncestor(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	dn directory.DN,
) string {
	current := dn
	for {
		parent, ok := current.Parent()
		if !ok || parent.Depth() == 0 {
			return ""
		}
		if entry, err := reader.Get(parent); err == nil {
			entry, err = withCollectiveAttributes(runtime.schema, reader, entry)
			if err != nil {
				return ""
			}
			if server.allowed(
				runtime,
				reader,
				subjectDN,
				entry,
				"entry",
				nil,
				acl.Disclose,
			) {
				return entry.DN
			}
			return ""
		}
		current = parent
	}
}

func (server *Server) writeSearchDone(
	connection net.Conn,
	messageID int64,
	result ldapwire.Result,
) error {
	return server.writeSearchDoneWithControls(
		connection,
		messageID,
		result,
		nil,
	)
}

func (server *Server) writeSearchDoneWithControls(
	connection net.Conn,
	messageID int64,
	result ldapwire.Result,
	controls []ldapwire.Control,
) error {
	if finalizer, ok := connection.(interface {
		beginFinalResponse() error
	}); ok {
		if err := finalizer.beginFinalResponse(); err != nil {
			return err
		}
	}
	return ldapwire.Write(
		connection,
		ldapwire.EncodeSearchResultDone(messageID, result, controls),
	)
}

func (server *Server) writeSearchResult(
	connection net.Conn,
	messageID int64,
	state *connectionState,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
	entries []directory.Entry,
	result ldapwire.Result,
	cursor pagedSearchCursor,
	hasMore bool,
) error {
	return server.writeSearchResultResponse(
		connection,
		messageID,
		state,
		paging,
		sorting,
		entries,
		result,
		cursor,
		hasMore,
		nil,
		nil,
		nil,
	)
}

func (server *Server) writeSearchResultWithChainedReferences(
	connection net.Conn,
	messageID int64,
	state *connectionState,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
	entries []directory.Entry,
	result ldapwire.Result,
	cursor pagedSearchCursor,
	hasMore bool,
	references [][]string,
	chainedPackets []*ber.Packet,
) error {
	return server.writeSearchResultResponse(
		connection,
		messageID,
		state,
		paging,
		sorting,
		entries,
		result,
		cursor,
		hasMore,
		references,
		nil,
		chainedPackets,
	)
}

func (server *Server) writeSearchResultWithControls(
	connection net.Conn,
	messageID int64,
	state *connectionState,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
	entries []directory.Entry,
	result ldapwire.Result,
	cursor pagedSearchCursor,
	hasMore bool,
	additionalControls []ldapwire.Control,
) error {
	return server.writeSearchResultResponse(
		connection,
		messageID,
		state,
		paging,
		sorting,
		entries,
		result,
		cursor,
		hasMore,
		nil,
		additionalControls,
		nil,
	)
}

func (server *Server) writeSearchResultWithChainedReferencesAndControls(
	connection net.Conn,
	messageID int64,
	state *connectionState,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
	entries []directory.Entry,
	result ldapwire.Result,
	cursor pagedSearchCursor,
	hasMore bool,
	references [][]string,
	additionalControls []ldapwire.Control,
	chainedPackets []*ber.Packet,
) error {
	return server.writeSearchResultResponse(
		connection,
		messageID,
		state,
		paging,
		sorting,
		entries,
		result,
		cursor,
		hasMore,
		references,
		additionalControls,
		chainedPackets,
	)
}

func (server *Server) writeSearchResultResponse(
	connection net.Conn,
	messageID int64,
	state *connectionState,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
	entries []directory.Entry,
	result ldapwire.Result,
	cursor pagedSearchCursor,
	hasMore bool,
	references [][]string,
	additionalControls []ldapwire.Control,
	chainedPackets []*ber.Packet,
) (responseErr error) {
	responseControls := serverSideSortResponseControl(
		sorting,
		result,
		len(entries),
	)
	responseControls = append(responseControls, additionalControls...)
	pagingControls, err := server.completePagedSearch(
		state,
		paging,
		result,
		len(entries),
		cursor,
		hasMore,
	)
	if err != nil {
		if errors.Is(err, errPagedSearchMemoryLimit) {
			return server.writeSearchDone(
				connection,
				messageID,
				ldapwire.ResultError(
					ldapwire.ResultAdminLimitExceeded,
					err.Error(),
				),
			)
		}
		return fmt.Errorf("complete paged search: %w", err)
	}
	responseControls = append(responseControls, pagingControls...)
	batched := newLDAPResponseBatchConnection(connection)
	connection = batched
	defer func() {
		if err := batched.Flush(); responseErr == nil {
			responseErr = err
		}
	}()
	for _, entry := range entries {
		entryControls := server.passwordPolicySearchEntryControls(
			context.Background(),
			state,
			entry,
		)
		if err := server.writeSearchEntry(
			connection,
			messageID,
			entry,
			entryControls,
		); err != nil {
			return err
		}
	}
	if err := server.writeChainedPackets(
		connection,
		ldapwire.Message{ID: messageID},
		chainedPackets,
	); err != nil {
		return err
	}
	for _, referral := range references {
		if err := ldapwire.Write(
			connection,
			ldapwire.EncodeSearchResultReference(
				messageID,
				referral,
				nil,
			),
		); err != nil {
			return err
		}
	}
	return server.writeSearchDoneWithControls(
		connection,
		messageID,
		result,
		responseControls,
	)
}

func (server *Server) writeSearchEntry(
	connection net.Conn,
	messageID int64,
	entry directory.Entry,
	controls []ldapwire.Control,
) error {
	size := ldapwire.SearchResultEntryEncodedSize(messageID, entry, controls)
	if server.config.MaxResponsePDUBytes > 0 && size > server.config.MaxResponsePDUBytes {
		return errSearchResponseLimit
	}
	reserved := server.responseByteLimiter.limit() > 0
	if reserved && !server.responseByteLimiter.tryAcquire(size) {
		return errSearchResponseLimit
	}
	encoded := ldapwire.EncodeSearchResultEntry(messageID, entry, controls)
	if reserved {
		server.responseByteLimiter.release(size)
	}
	return ldapwire.Write(connection, encoded)
}

var (
	errStopSearch           = errors.New("stop search")
	errSearchCandidateLimit = errors.New("search candidate limit exceeded")
)

func countLocalSearchCandidates(
	reader storage.Reader,
	filter directory.Filter,
	base directory.DN,
	scope directory.Scope,
	translucent *translucentSearchRouteResult,
	limit int,
) (int, error) {
	count := 0
	visit := func(entry directory.Entry) error {
		candidate, normalized := entry.NormalizedDNHint()
		if !normalized {
			var err error
			candidate, err = directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			candidate, err = storage.NormalizeReaderDN(reader, candidate)
			if err != nil {
				return err
			}
		}
		if !directory.InScope(base, candidate, scope) {
			return nil
		}
		count++
		if limit >= 0 && count > limit {
			return errSearchCandidateLimit
		}
		return nil
	}
	if translucent != nil {
		for _, entry := range translucent.entries {
			if err := visit(entry); err != nil {
				return count, err
			}
		}
		return count, nil
	}
	planned, _, err := storage.ForEachFilterCandidate(reader, filter, visit)
	if err != nil || planned {
		return count, err
	}
	streamed, err := storage.ForEachStablePhysicalEntry(reader, visit)
	if err == nil && !streamed {
		err = reader.ForEach(visit)
	}
	return count, err
}
