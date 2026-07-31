package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) handleSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
) error {
	var sortLease *serverSideSortLease
	defer func() {
		releaseServerSideSortLease(state, sortLease)
	}()

	controlSupport := supportsAssertion |
		supportsPagedResults |
		supportsManageDsaIT |
		supportsSubentries |
		supportsDontUseCopy
	if runtimeSupportsServerSideSort(state.runtime.databases) {
		controlSupport |= supportsServerSideSort | supportsVirtualListView
	}
	if runtimeSupportsSyncProvider(state.runtime.databases) {
		controlSupport |= supportsSync
	}
	controls, controlFailure := parseRequestControls(
		message.Controls,
		controlSupport,
	)
	if controlFailure != nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			*controlFailure,
		)
	}
	limit := effectiveSearchLimit(server.config.MaxSearchEntries, request.SizeLimit)
	paging, pagingFailure := preparePagedSearch(
		state,
		request,
		message.Controls,
		controls.paging,
		limit,
	)
	if pagingFailure != nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			*pagingFailure,
		)
	}
	if paging != nil && paging.abandoned {
		return server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
		)
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

	base, err := directory.ParseDN(request.BaseDN)
	if err != nil {
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
			pagedSearchCursor{},
			false,
		)
	}

	rootDSESearch := base.Depth() == 0 &&
		request.Scope == directory.ScopeBase
	subschemaSearch := isSubschemaDN(base)
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
			view, err = startVirtualListView(
				state,
				virtualListView,
				nil,
				sortLease,
			)
			if err != nil {
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
	routes := databaseSearchRoutes(state.runtime.databases, base, request.Scope)
	if len(routes) == 0 {
		return server.writeSearchResult(
			connection,
			message.ID,
			state,
			paging,
			sorting,
			nil,
			ldapwire.Result{Code: ldapwire.ResultReferral},
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
				shadowSearchResult(primary, base, request.Scope),
				pagedSearchCursor{},
				false,
			)
		}
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
			)
			if err != nil {
				discardVirtualListView(state, view)
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

	candidates := make([]searchCandidate, 0)
	references := make([][]string, 0)
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	entryLimit := limit
	if paging != nil {
		remaining := limit - paging.count
		if remaining < 0 {
			remaining = 0
		}
		entryLimit = min(paging.size, remaining)
	}
	var (
		hasMore       bool
		lastCursor    pagedSearchCursor
		sortTruncated bool
	)

	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
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
		collectivePlans := newCollectiveAttributePlanCache(state.runtime.schema)
		primary := routes[0]
		primaryDatabase := &state.runtime.databases[primary.databaseIndex]
		primaryReader := storage.ReaderInPartition(reader, primaryDatabase.partition)
		baseEntry, err := primaryReader.Get(base)
		if err != nil {
			if errors.Is(err, storage.ErrEntryNotFound) {
				ancestor, found, ancestorErr := closestExistingAncestor(
					primaryReader,
					base,
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
						&base,
						referralScopeForSearch(request.Scope),
					)
					if referralErr != nil {
						return referralErr
					}
					result = referral
					return nil
				}
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = server.disclosedAncestor(
					state.runtime,
					primaryReader,
					state.boundDN,
					base,
				)
				return nil
			}
			return err
		}
		baseEntry = withSubschemaReference(baseEntry)
		baseEntry, err = collectivePlans.apply(
			primaryDatabase.partition,
			primaryReader,
			baseEntry,
		)
		if err != nil {
			return err
		}
		if !server.allowed(
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
				&base,
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
			tx := storage.ReaderInPartition(reader, database.partition)
			if routeIndex > 0 {
				routeBaseEntry, err := tx.Get(route.base)
				if errors.Is(err, storage.ErrEntryNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				routeBaseEntry = withSubschemaReference(routeBaseEntry)
				routeBaseEntry, err = collectivePlans.apply(
					database.partition,
					tx,
					routeBaseEntry,
				)
				if err != nil {
					return err
				}
				if !server.allowed(
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

			err := tx.ForEach(func(entry directory.Entry) error {
				storedEntry := entry.Clone()
				candidate, err := directory.ParseDN(entry.DN)
				if err != nil {
					return err
				}
				if paging != nil && paging.cursor.valid && !sorting.active() {
					if routeIndex < paging.cursor.route ||
						(routeIndex == paging.cursor.route &&
							candidate.Key() <= paging.cursor.dnKey) {
						return nil
					}
				}
				if expired(deadline) {
					result.Code = ldapwire.ResultTimeLimitExceeded
					return errStopSearch
				}
				if !directory.InScope(route.base, candidate, route.scope) {
					return nil
				}
				entry = withSubschemaReference(entry)
				entry, err = collectivePlans.apply(database.partition, tx, entry)
				if err != nil {
					return err
				}
				if !subentrySearchVisible(
					state.runtime,
					entry,
					request.Scope,
					controls.subentries,
				) {
					return nil
				}
				if derefAliasesWhileSearching(request.DerefAliases) &&
					state.runtime.schema.EntryHasObjectClass(
						entry,
						"alias",
					) &&
					(derefAliasesWhileFinding(request.DerefAliases) ||
						!candidate.Equal(base)) {
					return nil
				}
				if !controls.manageDsaIT &&
					state.runtime.schema.EntryHasObjectClass(
						entry,
						"referral",
					) {
					if server.allowed(
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
					) {
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
				matches, err := server.filterMatches(
					state.runtime,
					tx,
					state.boundDN,
					entry,
					request.Filter,
				)
				if err != nil {
					result.Code = ldapwire.ResultInappropriateMatching
					result.DiagnosticMessage = err.Error()
					return errStopSearch
				}
				if !matches {
					return nil
				}
				if !server.allowed(
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
				readable := server.attributesWithPrivilege(
					state.runtime,
					tx,
					state.boundDN,
					entry,
					acl.Read,
					request.TypesOnly && !sorting.active(),
				)
				readable = projectDDSRemainingTTL(
					readable,
					entry,
					time.Now(),
				)
				if syncSearch != nil {
					readable = stripSyncExcludedAttributes(
						state.runtime.schema,
						readable,
					)
				}
				selected := server.selectEntry(
					state.runtime,
					readable,
					request.Attributes,
					request.TypesOnly,
				)
				if !sorting.active() && len(candidates) >= entryLimit {
					if paging != nil &&
						paging.count+len(candidates) < limit {
						hasMore = true
					} else {
						result.Code = ldapwire.ResultSizeLimitExceeded
					}
					return errStopSearch
				}
				candidates = append(candidates, searchCandidate{
					selected: selected,
					readable: readable,
					route:    routeIndex,
					dn:       entry.DN,
					syncUUID: syncUUID,
				})
				if !sorting.active() {
					lastCursor = pagedSearchCursor{
						route: routeIndex,
						dnKey: candidate.Key(),
						valid: true,
					}
				}
				return nil
			})
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
		return fmt.Errorf("search directory: %w", err)
	}

	if sorting.active() {
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
			view, err = startVirtualListView(
				state,
				virtualListView,
				candidates,
				sortLease,
			)
			if err != nil {
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
		return server.writeSearchResultWithReferencesAndControls(
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
	} else {
		if paging != nil && len(candidates) > entryLimit {
			candidates = candidates[:entryLimit]
			hasMore = true
		}
		if paging != nil && len(candidates) > 0 {
			last := candidates[len(candidates)-1]
			lastDN, parseErr := directory.ParseDN(last.dn)
			if parseErr != nil {
				clearPagedSearch(state)
				return fmt.Errorf("parse paged result DN %q: %w", last.dn, parseErr)
			}
			lastCursor = pagedSearchCursor{
				route: last.route,
				dnKey: lastDN.Key(),
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
	writeErr := server.writeSearchResultWithReferences(
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
	)
	if sortLease != nil &&
		state.pagedSearch != nil &&
		state.pagedSearch.sortLease == sortLease {
		sortLease = nil
	}
	return writeErr
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
			route: candidates[index].route,
			dn:    candidates[index].dn,
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
) ([]directory.Entry, ldapwire.Result, bool, error) {
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	entries := make([]directory.Entry, 0, paging.size)
	hasMore := false
	sorted := paging.sorted
	if sorted == nil {
		return nil, result, false, errors.New("sorted paged search state is absent")
	}

	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		collectivePlans := newCollectiveAttributePlanCache(state.runtime.schema)
		for sorted.offset < len(sorted.items) {
			if expired(deadline) {
				result.Code = ldapwire.ResultTimeLimitExceeded
				return nil
			}
			item := sorted.items[sorted.offset]
			if item.route < 0 || item.route >= len(routes) {
				return fmt.Errorf("sorted paged search route %d is invalid", item.route)
			}
			dn, err := directory.ParseDN(item.dn)
			if err != nil {
				return fmt.Errorf("parse sorted paged search DN %q: %w", item.dn, err)
			}
			database := &state.runtime.databases[routes[item.route].databaseIndex]
			tx := storage.ReaderInPartition(reader, database.partition)
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
			entry, err = withSyncProviderContextCSNs(
				reader,
				*database,
				entry,
			)
			if err != nil {
				return err
			}
			if !server.allowed(
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
			if len(entries) >= paging.size {
				hasMore = true
				return nil
			}
			readable := server.attributesWithPrivilege(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				acl.Read,
				false,
			)
			readable = projectDDSRemainingTTL(readable, entry, time.Now())
			entries = append(entries, server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			))
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
			if !ok || !parent.Equal(base) {
				continue
			}
			route.scope = directory.ScopeBase
		case directory.ScopeWholeSubtree:
			if !base.Equal(suffix) && !base.AncestorOf(suffix) {
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
	candidate, err := directory.ParseDN(entry.DN)
	if err != nil {
		if paging != nil {
			clearPagedSearch(state)
		}
		return fmt.Errorf("parse subschema DN: %w", err)
	}
	base, err := directory.ParseDN(request.BaseDN)
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
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "supportedExtension",
		Values:      stringValues(supportedExtensions...),
	})
	if subtrees := dynamicSubtrees(runtime.databases); len(subtrees) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "dynamicSubtrees",
			Values:      stringValues(subtrees...),
		})
	}
	supportedControls := []string{
		assertionControlOID,
		manageDsaITControlOID,
		preReadControlOID,
		postReadControlOID,
		pagedResultsControlOID,
		subentriesControlOID,
		dontUseCopyControlOID,
		transactionSpecificationControlOID,
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
	return entry
}

func (server *Server) subschemaEntry(runtime *runtimeState) directory.Entry {
	registry := runtime.schema
	return directory.Entry{
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

func subentrySearchVisible(
	runtime *runtimeState,
	entry directory.Entry,
	scope directory.Scope,
	visibility *bool,
) bool {
	subentry := runtime.schema.EntryHasObjectClass(entry, "subentry")
	if visibility != nil {
		return subentry == *visibility
	}
	return scope == directory.ScopeBase || !subentry
}

func withSubschemaReference(entry directory.Entry) directory.Entry {
	if entry.HasAttribute("subschemaSubentry") {
		return entry
	}
	entry = entry.Clone()
	entry.ReplaceValues("subschemaSubentry", stringValues("cn=Subschema"))
	return entry
}

func stringValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = []byte(values[i])
	}
	return result
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
	)
}

func (server *Server) writeSearchResultWithReferences(
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
	)
}

func (server *Server) writeSearchResultWithReferencesAndControls(
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
) error {
	responseControls := serverSideSortResponseControl(
		sorting,
		result,
		len(entries),
	)
	responseControls = append(responseControls, additionalControls...)
	pagingControls, err := completePagedSearch(
		state,
		paging,
		result,
		len(entries),
		cursor,
		hasMore,
	)
	if err != nil {
		return fmt.Errorf("complete paged search: %w", err)
	}
	responseControls = append(responseControls, pagingControls...)
	for _, entry := range entries {
		if err := ldapwire.Write(
			connection,
			ldapwire.EncodeSearchResultEntry(messageID, entry, nil),
		); err != nil {
			return err
		}
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

var errStopSearch = errors.New("stop search")
