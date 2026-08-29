package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const syncIDSetChunkSize = 128

var errSyncSearchBaseChanged = errors.New("Sync search base has changed")

type syncSearchContext struct {
	control            *syncRequestControl
	cookie             openLDAPSyncCookie
	partitions         []string
	partitionSnapshots map[string]syncCSNState
	policies           map[string]syncSearchPolicy
	routes             []syncSearchRoute
	manageDsaIT        bool
	subentries         *bool
	snapshot           syncCSNState
	liveCSNs           syncCSNState
	present            []ldapwire.SyncUUID
	deleted            map[ldapwire.SyncUUID]openLDAPCSN
	refreshDeletes     bool
	subscription       *syncChangeSubscription
}

type syncSearchPolicy struct {
	sessionLogSize int
	noPresent      bool
	reloadHint     bool
}

type syncSearchRoute struct {
	partition     string
	databaseIndex int
	rwm           *rwmRuntimeConfiguration
	base          directory.DN
	scope         directory.Scope
}

type syncDeletedUUID struct {
	uuid ldapwire.SyncUUID
	csn  openLDAPCSN
}

func (server *Server) prepareSyncSearch(
	state *connectionState,
	request ldapwire.SearchRequest,
	routes []databaseSearchRoute,
	controls requestControls,
) (*syncSearchContext, *ldapwire.Result) {
	control := controls.sync
	if control == nil {
		return nil, nil
	}
	if request.DerefAliases == ldapwire.DerefInSearching ||
		request.DerefAliases == ldapwire.DerefAlways {
		result := ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"illegal value for derefAliases",
		)
		return nil, &result
	}

	partitionSet := make(map[string]struct{})
	partitions := make([]string, 0, len(routes))
	policies := make(map[string]syncSearchPolicy)
	syncRoutes := make([]syncSearchRoute, 0, len(routes))
	for _, route := range routes {
		database := state.runtime.databases[route.databaseIndex]
		providerIndex := effectiveSyncProviderDatabaseIndex(
			state.runtime.databases,
			route.databaseIndex,
		)
		if providerIndex < 0 {
			if !control.critical {
				return nil, nil
			}
			result := ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"Sync is not enabled for the target database",
			)
			return nil, &result
		}
		provider := state.runtime.databases[providerIndex]
		if _, exists := partitionSet[provider.partition]; !exists {
			partitionSet[provider.partition] = struct{}{}
			partitions = append(partitions, provider.partition)
			policies[provider.partition] = syncSearchPolicy{
				sessionLogSize: provider.syncSessionLogSize,
				noPresent:      provider.syncNoPresent,
				reloadHint:     provider.syncReloadHint,
			}
		}
		syncRoutes = append(syncRoutes, syncSearchRoute{
			partition:     database.partition,
			databaseIndex: route.databaseIndex,
			rwm:           database.rwm,
			base:          route.base,
			scope:         route.scope,
		})
	}
	syncSearch := &syncSearchContext{
		control:     control,
		cookie:      emptyOpenLDAPSyncCookie(0, false),
		partitions:  partitions,
		policies:    policies,
		routes:      syncRoutes,
		manageDsaIT: controls.manageDsaIT,
		subentries:  controls.subentries,
	}
	if control.request.HasCookie {
		syncSearch.cookie = parseOpenLDAPSyncCookie(control.request.Cookie)
	}
	if control.request.Mode == ldapwire.SyncRefreshAndPersist {
		syncSearch.subscription = server.syncChanges.subscribe(partitions)
	}
	return syncSearch, nil
}

func (syncSearch *syncSearchContext) close() {
	if syncSearch != nil && syncSearch.subscription != nil {
		syncSearch.subscription.unsubscribe()
	}
}

func (syncSearch *syncSearchContext) captureSnapshot(
	reader storage.Reader,
) error {
	syncSearch.snapshot = make(syncCSNState)
	syncSearch.partitionSnapshots = make(map[string]syncCSNState)
	for _, partition := range syncSearch.partitions {
		state, err := syncContextCSNs(reader, partition)
		if err != nil {
			return err
		}
		syncSearch.partitionSnapshots[partition] = cloneSyncCSNState(state)
		mergeSyncCSNState(syncSearch.snapshot, state)
	}
	return nil
}

func (syncSearch *syncSearchContext) snapshotFailure() *ldapwire.Result {
	if len(syncSearch.cookie.csns) == 0 {
		return nil
	}
	if len(syncSearch.snapshot) == 0 {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"consumer has state but provider does not",
		)
		return &result
	}
	for serverID, requestCSN := range syncSearch.cookie.csns {
		providerCSN, providerHasCSN := syncSearch.snapshot[serverID]
		if !providerHasCSN {
			delete(syncSearch.cookie.csns, serverID)
			continue
		}
		if serverID == 0 &&
			compareOpenLDAPCSN(requestCSN, providerCSN) > 0 {
			result := ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"consumer state is newer than provider",
			)
			return &result
		}
	}
	if len(syncSearch.cookie.csns) != len(syncSearch.snapshot) {
		syncSearch.cookie.csns = make(syncCSNState)
	}
	return nil
}

func (server *Server) prepareSyncRefresh(
	state *connectionState,
	request ldapwire.SearchRequest,
	reader storage.Reader,
	syncSearch *syncSearchContext,
) (*ldapwire.Result, error) {
	if len(syncSearch.cookie.csns) == 0 {
		return nil, nil
	}

	allSessionLogs := len(syncSearch.partitions) > 0
	anySessionLog := false
	allNoPresent := len(syncSearch.partitions) > 0
	reloadHint := false
	var replay []syncChange
	for _, partition := range syncSearch.partitions {
		policy := syncSearch.policies[partition]
		allNoPresent = allNoPresent && policy.noPresent
		reloadHint = reloadHint || policy.reloadHint
		if policy.sessionLogSize == 0 {
			allSessionLogs = false
			continue
		}
		anySessionLog = true
		changes, usable := server.syncChanges.replay(
			partition,
			syncSearch.cookie.csns,
			syncSearch.partitionSnapshots[partition],
		)
		if !usable {
			allSessionLogs = false
			continue
		}
		replay = append(replay, changes...)
	}

	switch {
	case allSessionLogs:
		sort.SliceStable(replay, func(i, j int) bool {
			comparison := compareOpenLDAPCSN(replay[i].csn, replay[j].csn)
			if comparison != 0 {
				return comparison < 0
			}
			if replay[i].partition != replay[j].partition {
				return replay[i].partition < replay[j].partition
			}
			return replay[i].before.DN < replay[j].before.DN
		})
		syncSearch.refreshDeletes = true
		syncSearch.deleted = make(map[ldapwire.SyncUUID]openLDAPCSN)
		for _, change := range replay {
			baseChanged, baseErr := syncSearchBaseChanged(
				state.runtime,
				syncSearch,
				change,
			)
			if baseErr != nil {
				return nil, baseErr
			}
			if baseChanged {
				result := ldapwire.ResultError(
					ldapwire.ResultSyncRefreshRequired,
					errSyncSearchBaseChanged.Error(),
				)
				return &result, nil
			}
			var (
				beforeUUID  ldapwire.SyncUUID
				beforeMatch bool
				afterUUID   ldapwire.SyncUUID
				afterMatch  bool
				err         error
			)
			if change.hasBefore {
				_, beforeUUID, beforeMatch, err = server.syncEventEntry(
					state.runtime,
					state.boundDN,
					request,
					syncSearch,
					reader,
					change.partition,
					change.before,
				)
				if err != nil {
					return nil, err
				}
			}
			if change.hasAfter {
				_, afterUUID, afterMatch, err = server.syncEventEntry(
					state.runtime,
					state.boundDN,
					request,
					syncSearch,
					reader,
					change.partition,
					change.after,
				)
				if err != nil {
					return nil, err
				}
			}
			if beforeMatch && !afterMatch {
				syncSearch.deleted[beforeUUID] = change.csn
			}
			if afterMatch {
				delete(syncSearch.deleted, afterUUID)
			}
		}
		return nil, nil
	case !anySessionLog && allNoPresent:
		withinMinimum, err := syncCookieWithinMinimumCSNs(
			state.runtime,
			reader,
			syncSearch,
		)
		if err != nil {
			return nil, err
		}
		if !withinMinimum {
			result := ldapwire.ResultError(
				ldapwire.ResultSyncRefreshRequired,
				"sync cookie is stale",
			)
			return &result, nil
		}
		syncSearch.refreshDeletes = true
		return nil, nil
	}

	exists, err := syncCookieStateExists(reader, syncSearch)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, nil
	}
	if reloadHint && !syncSearch.control.request.ReloadHint {
		result := ldapwire.ResultError(
			ldapwire.ResultSyncRefreshRequired,
			"sync cookie is stale",
		)
		return &result, nil
	}
	syncSearch.cookie.csns = make(syncCSNState)
	return nil, nil
}

func syncCookieWithinMinimumCSNs(
	runtime *runtimeState,
	reader storage.Reader,
	syncSearch *syncSearchContext,
) (bool, error) {
	seen := make(map[int]struct{})
	for _, route := range syncSearch.routes {
		providerIndex := effectiveSyncProviderDatabaseIndex(
			runtime.databases,
			route.databaseIndex,
		)
		if providerIndex < 0 {
			continue
		}
		if _, alreadyChecked := seen[providerIndex]; alreadyChecked {
			continue
		}
		seen[providerIndex] = struct{}{}
		provider := runtime.databases[providerIndex]
		policy := syncSearch.policies[provider.partition]
		if !policy.noPresent || !policy.reloadHint ||
			policy.sessionLogSize != 0 {
			continue
		}
		tx := storage.ReaderInPartition(reader, provider.partition)
		for _, suffix := range provider.suffixes {
			entry, err := tx.Get(suffix)
			switch {
			case err == nil:
			case errors.Is(err, storage.ErrEntryNotFound):
				continue
			default:
				return false, err
			}
			for _, raw := range entry.Values("minCSN") {
				minimum, err := parseOpenLDAPCSN(string(raw))
				if err != nil {
					return false, fmt.Errorf(
						"%s has invalid minCSN %q: %w",
						entry.DN,
						raw,
						err,
					)
				}
				consumer, exists := syncSearch.cookie.csns[minimum.serverID]
				if !exists || compareOpenLDAPCSN(consumer, minimum) < 0 {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

func syncCookieStateExists(
	reader storage.Reader,
	syncSearch *syncSearchContext,
) (bool, error) {
	var minimum openLDAPCSN
	hasMinimum := false
	for _, csn := range syncSearch.cookie.csns {
		if !hasMinimum || compareOpenLDAPCSN(csn, minimum) < 0 {
			minimum = csn
			hasMinimum = true
		}
	}
	if !hasMinimum {
		return false, nil
	}
	found := false
	seenPartitions := make(map[string]struct{}, len(syncSearch.routes))
	for _, route := range syncSearch.routes {
		if _, seen := seenPartitions[route.partition]; seen {
			continue
		}
		seenPartitions[route.partition] = struct{}{}
		tx := storage.ReaderInPartition(reader, route.partition)
		if err := tx.ForEach(func(entry directory.Entry) error {
			values := entry.Values("entryCSN")
			if len(values) != 1 {
				return nil
			}
			csn, err := parseOpenLDAPCSN(string(values[0]))
			if err == nil && compareOpenLDAPCSN(csn, minimum) <= 0 {
				found = true
			}
			return nil
		}); err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

func mergeSyncCSNState(destination, source syncCSNState) {
	for serverID, candidate := range source {
		current, exists := destination[serverID]
		if !exists || compareOpenLDAPCSN(candidate, current) > 0 {
			destination[serverID] = candidate
		}
	}
}

func (syncSearch *syncSearchContext) entryChanged(
	entry directory.Entry,
) bool {
	values := entry.Values("entryCSN")
	if len(values) != 1 {
		return true
	}
	csn, err := parseOpenLDAPCSN(string(values[0]))
	if err != nil {
		return true
	}
	consumerCSN, exists := syncSearch.cookie.csns[csn.serverID]
	return !exists || compareOpenLDAPCSN(csn, consumerCSN) > 0
}

func (syncSearch *syncSearchContext) observeCurrent(uuid ldapwire.SyncUUID) {
	if syncSearch.deleted != nil {
		delete(syncSearch.deleted, uuid)
	}
}

func (syncSearch *syncSearchContext) deletedUUIDs() []syncDeletedUUID {
	uuids := make([]syncDeletedUUID, 0, len(syncSearch.deleted))
	for uuid, csn := range syncSearch.deleted {
		uuids = append(uuids, syncDeletedUUID{uuid: uuid, csn: csn})
	}
	sort.Slice(uuids, func(i, j int) bool {
		comparison := compareOpenLDAPCSN(uuids[i].csn, uuids[j].csn)
		if comparison != 0 {
			return comparison < 0
		}
		return bytes.Compare(uuids[i].uuid[:], uuids[j].uuid[:]) < 0
	})
	return uuids
}

func syncUUIDFromEntry(entry directory.Entry) (ldapwire.SyncUUID, error) {
	values := entry.Values("entryUUID")
	if len(values) != 1 {
		return ldapwire.SyncUUID{}, fmt.Errorf(
			"%s entryUUID is not single-valued",
			entry.DN,
		)
	}
	value := strings.TrimSpace(string(values[0]))
	if len(value) != 36 ||
		value[8] != '-' ||
		value[13] != '-' ||
		value[18] != '-' ||
		value[23] != '-' {
		return ldapwire.SyncUUID{}, fmt.Errorf(
			"%s entryUUID %q is not canonical",
			entry.DN,
			value,
		)
	}
	encoded := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(ldapwire.SyncUUID{}) {
		return ldapwire.SyncUUID{}, fmt.Errorf(
			"%s entryUUID %q is invalid",
			entry.DN,
			value,
		)
	}
	var uuid ldapwire.SyncUUID
	copy(uuid[:], decoded)
	return uuid, nil
}

func stripSyncExcludedAttributes(
	registry *schema.Registry,
	entry directory.Entry,
) directory.Entry {
	collectiveSource := registry.EntryHasObjectClass(
		entry,
		"collectiveAttributeSubentry",
	)
	filtered := entry.Clone()
	attributes := filtered.Attributes
	filtered.Attributes = attributes[:0]
	for _, attribute := range attributes {
		attributeType, known := registry.AttributeType(attribute.Description)
		if known && attributeType.Usage == schema.UsageDSAOperation {
			continue
		}
		if !collectiveSource && registry.IsCollective(attribute.Description) {
			continue
		}
		filtered.Attributes = append(filtered.Attributes, attribute)
	}
	return filtered
}

func (server *Server) writeSyncSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
	syncSearch *syncSearchContext,
	candidates []searchCandidate,
	result ldapwire.Result,
	responseControls []ldapwire.Control,
) error {
	if result.Code == ldapwire.ResultSuccess {
		for start := 0; start < len(syncSearch.present); start += syncIDSetChunkSize {
			end := min(start+syncIDSetChunkSize, len(syncSearch.present))
			info := ldapwire.SyncInfoValue{
				Kind:  ldapwire.SyncInfoIDSet,
				UUIDs: syncSearch.present[start:end],
			}
			if err := server.writeSyncInfo(
				connection,
				messageID,
				info,
			); err != nil {
				return err
			}
		}
	}

	for _, candidate := range candidates {
		control := syncStateResponseControl(
			syncSearch.control.critical,
			ldapwire.SyncStateValue{
				State:     ldapwire.SyncStateAdd,
				EntryUUID: candidate.syncUUID,
			},
		)
		entryControls := []ldapwire.Control{control}
		entryControls = append(
			entryControls,
			server.passwordPolicySearchEntryControls(
				ctx,
				state,
				candidate.selected,
			)...,
		)
		if err := server.writeSearchEntry(
			connection,
			messageID,
			candidate.selected,
			entryControls,
		); err != nil {
			return err
		}
	}
	if result.Code == ldapwire.ResultSuccess {
		deleted := syncSearch.deletedUUIDs()
		cookieState := cloneSyncCSNState(syncSearch.cookie.csns)
		for start := 0; start < len(deleted); {
			csn := deleted[start].csn
			end := start + 1
			for end < len(deleted) &&
				end-start < syncIDSetChunkSize &&
				compareOpenLDAPCSN(deleted[end].csn, csn) == 0 {
				end++
			}
			current, exists := cookieState[csn.serverID]
			if !exists || compareOpenLDAPCSN(csn, current) > 0 {
				cookieState[csn.serverID] = csn
			}
			identifiers := make([]ldapwire.SyncUUID, 0, end-start)
			for _, deletion := range deleted[start:end] {
				identifiers = append(identifiers, deletion.uuid)
			}
			info := ldapwire.SyncInfoValue{
				Kind: ldapwire.SyncInfoIDSet,
				Cookie: composeOpenLDAPSyncDeleteCookie(
					syncSearch.cookie.rid,
					cookieState,
					csn,
				),
				HasCookie:      true,
				RefreshDeletes: true,
				UUIDs:          identifiers,
			}
			if err := server.writeSyncInfo(
				connection,
				messageID,
				info,
			); err != nil {
				return err
			}
			start = end
		}
	}
	if result.Code != ldapwire.ResultSuccess {
		return server.writeSearchDoneWithControls(
			connection,
			messageID,
			result,
			responseControls,
		)
	}

	cookie := composeOpenLDAPSyncCookie(
		syncSearch.cookie.rid,
		syncSearch.snapshot,
	)
	if syncSearch.control.request.Mode == ldapwire.SyncRefreshOnly {
		done := ldapwire.SyncDoneValue{
			Cookie:         cookie,
			HasCookie:      len(syncSearch.snapshot) > 0,
			RefreshDeletes: syncSearch.refreshDeletes,
		}
		controls := []ldapwire.Control{{
			OID:      syncDoneControlOID,
			Critical: syncSearch.control.critical,
			Value:    ldapwire.EncodeSyncDoneValue(done),
			HasValue: true,
		}}
		controls = append(controls, responseControls...)
		return server.writeSearchDoneWithControls(
			connection,
			messageID,
			result,
			controls,
		)
	}

	refreshKind := ldapwire.SyncInfoRefreshPresent
	if syncSearch.refreshDeletes {
		refreshKind = ldapwire.SyncInfoRefreshDelete
	}
	if err := server.writeSyncInfoWithControls(
		connection,
		messageID,
		ldapwire.SyncInfoValue{
			Kind:        refreshKind,
			Cookie:      cookie,
			HasCookie:   len(syncSearch.snapshot) > 0,
			RefreshDone: true,
		},
		responseControls,
	); err != nil {
		return err
	}
	return server.persistSyncSearch(
		ctx,
		connection,
		state,
		messageID,
		request,
		syncSearch,
	)
}

func syncStateResponseControl(
	critical bool,
	value ldapwire.SyncStateValue,
) ldapwire.Control {
	return ldapwire.Control{
		OID:      syncStateControlOID,
		Critical: critical,
		Value:    ldapwire.EncodeSyncStateValue(value),
		HasValue: true,
	}
}

func (server *Server) writeSyncInfo(
	connection net.Conn,
	messageID int64,
	info ldapwire.SyncInfoValue,
) error {
	return server.writeSyncInfoWithControls(
		connection,
		messageID,
		info,
		nil,
	)
}

func (server *Server) writeSyncInfoWithControls(
	connection net.Conn,
	messageID int64,
	info ldapwire.SyncInfoValue,
	controls []ldapwire.Control,
) error {
	return ldapwire.Write(
		connection,
		ldapwire.EncodeIntermediateResponse(
			messageID,
			syncInfoOID,
			ldapwire.EncodeSyncInfoValue(info),
			controls,
		),
	)
}

func (server *Server) persistSyncSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
	syncSearch *syncSearchContext,
) error {
	if syncSearch.subscription == nil {
		return errors.New("persistent Sync subscription is absent")
	}
	syncSearch.liveCSNs = make(syncCSNState)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case change, ok := <-syncSearch.subscription.events:
			if !ok {
				if syncSearch.subscription.overflow.Load() {
					return server.writeSearchDone(
						connection,
						messageID,
						ldapwire.ResultError(
							ldapwire.ResultSyncRefreshRequired,
							"persistent Sync change queue overflowed",
						),
					)
				}
				return nil
			}
			if current, exists := syncSearch.snapshot[change.csn.serverID]; exists {
				comparison := compareOpenLDAPCSN(change.csn, current)
				if comparison < 0 {
					continue
				}
				if comparison == 0 {
					live, seenLive := syncSearch.liveCSNs[change.csn.serverID]
					if !seenLive ||
						compareOpenLDAPCSN(change.csn, live) != 0 {
						continue
					}
				}
			}
			syncSearch.snapshot[change.csn.serverID] = change.csn
			syncSearch.liveCSNs[change.csn.serverID] = change.csn

			entry, syncState, uuid, visible, err := server.syncChangeResponse(
				ctx,
				state,
				request,
				syncSearch,
				change,
			)
			if err != nil {
				code := ldapwire.ResultOperationsError
				if errors.Is(err, errSyncSearchBaseChanged) {
					code = ldapwire.ResultSyncRefreshRequired
				}
				return server.writeSearchDone(
					connection,
					messageID,
					ldapwire.ResultError(
						code,
						err.Error(),
					),
				)
			}
			cookie := composeOpenLDAPSyncCookie(
				syncSearch.cookie.rid,
				syncSearch.snapshot,
			)
			if !visible {
				if err := server.writeSyncInfo(
					connection,
					messageID,
					ldapwire.SyncInfoValue{
						Kind:      ldapwire.SyncInfoNewCookie,
						Cookie:    cookie,
						HasCookie: true,
					},
				); err != nil {
					return err
				}
				continue
			}
			entryCookie := composeOpenLDAPSyncCookie(
				syncSearch.cookie.rid,
				syncCSNState{change.csn.serverID: change.csn},
			)
			control := syncStateResponseControl(
				syncSearch.control.critical,
				ldapwire.SyncStateValue{
					State:     syncState,
					EntryUUID: uuid,
					Cookie:    entryCookie,
					HasCookie: true,
				},
			)
			entryControls := []ldapwire.Control{control}
			entryControls = append(
				entryControls,
				server.passwordPolicySearchEntryControls(
					ctx,
					state,
					entry,
				)...,
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
	}
}

func (server *Server) syncChangeResponse(
	ctx context.Context,
	state *connectionState,
	request ldapwire.SearchRequest,
	syncSearch *syncSearchContext,
	change syncChange,
) (
	directory.Entry,
	ldapwire.SyncState,
	ldapwire.SyncUUID,
	bool,
	error,
) {
	runtime := server.runtime.Load()
	if runtime == nil {
		runtime = state.runtime
	}
	baseChanged, err := syncSearchBaseChanged(runtime, syncSearch, change)
	if err != nil {
		return directory.Entry{}, 0, ldapwire.SyncUUID{}, false, err
	}
	if baseChanged {
		return directory.Entry{},
			0,
			ldapwire.SyncUUID{},
			false,
			errSyncSearchBaseChanged
	}
	var (
		beforeEntry directory.Entry
		beforeUUID  ldapwire.SyncUUID
		beforeMatch bool
		afterEntry  directory.Entry
		afterUUID   ldapwire.SyncUUID
		afterMatch  bool
	)
	err = server.config.Store.View(
		ctx,
		func(reader storage.Reader) error {
			var err error
			if change.hasBefore {
				beforeEntry, beforeUUID, beforeMatch, err =
					server.syncEventEntry(
						runtime,
						state.boundDN,
						request,
						syncSearch,
						reader,
						change.partition,
						change.before,
					)
				if err != nil {
					return err
				}
			}
			if change.hasAfter {
				afterEntry, afterUUID, afterMatch, err =
					server.syncEventEntry(
						runtime,
						state.boundDN,
						request,
						syncSearch,
						reader,
						change.partition,
						change.after,
					)
			}
			return err
		},
	)
	if err != nil {
		return directory.Entry{}, 0, ldapwire.SyncUUID{}, false, err
	}

	switch {
	case !beforeMatch && afterMatch:
		return afterEntry, ldapwire.SyncStateAdd, afterUUID, true, nil
	case beforeMatch && afterMatch:
		return afterEntry, ldapwire.SyncStateModify, afterUUID, true, nil
	case beforeMatch && !afterMatch:
		return directory.Entry{DN: beforeEntry.DN},
			ldapwire.SyncStateDelete,
			beforeUUID,
			true,
			nil
	default:
		return directory.Entry{}, 0, ldapwire.SyncUUID{}, false, nil
	}
}

func syncSearchBaseChanged(
	runtime *runtimeState,
	syncSearch *syncSearchContext,
	change syncChange,
) (bool, error) {
	if !change.hasBefore {
		return false, nil
	}
	beforeDN, err := normalizeSyncSearchDN(runtime, change.before.DN)
	if err != nil {
		return false, err
	}
	var afterDN directory.DN
	afterAtSameDN := false
	if change.hasAfter {
		afterDN, err = normalizeSyncSearchDN(runtime, change.after.DN)
		if err != nil {
			return false, err
		}
		afterAtSameDN = beforeDN.Equal(afterDN)
	}
	if afterAtSameDN {
		return false, nil
	}
	for _, route := range syncSearch.routes {
		if route.partition != change.partition {
			continue
		}
		routeBefore, err := route.localDN(runtime, beforeDN)
		if err != nil {
			return false, err
		}
		routeBase, err := normalizeSyncSearchDN(runtime, route.base.String())
		if err != nil {
			return false, err
		}
		routeAfterAtSameDN := false
		if change.hasAfter {
			routeAfter, mapErr := route.localDN(runtime, afterDN)
			if mapErr != nil {
				return false, mapErr
			}
			routeAfterAtSameDN = routeBefore.Equal(routeAfter)
		}
		if routeAfterAtSameDN {
			continue
		}
		if routeBefore.Equal(routeBase) || routeBefore.AncestorOf(routeBase) {
			return true, nil
		}
	}
	return false, nil
}

func (server *Server) syncEventEntry(
	runtime *runtimeState,
	boundDN string,
	request ldapwire.SearchRequest,
	syncSearch *syncSearchContext,
	reader storage.Reader,
	partition string,
	entry directory.Entry,
) (directory.Entry, ldapwire.SyncUUID, bool, error) {
	databaseIndex, err := syncSearchDatabaseIndexForEntry(
		runtime,
		syncSearch,
		partition,
		entry.DN,
	)
	if err != nil {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, err
	}
	if databaseIndex < 0 || databaseIndex >= len(runtime.databases) {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, nil
	}

	if runtime.databases[databaseIndex].rwm != nil {
		entry, err = runtime.databases[databaseIndex].rwm.mapEntryToLocal(entry)
		if err != nil {
			return directory.Entry{}, ldapwire.SyncUUID{}, false, err
		}
	}

	tx := readerForDatabase(reader, runtime.databases[databaseIndex])
	entry = withSubschemaReference(entry)
	entry, err = withCollectiveAttributes(runtime.schema, tx, entry)
	if err != nil {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, err
	}
	filterEntry := entry
	if !syncSearch.manageDsaIT {
		projected, projectedFilterEntry, projectErr := newDynlistProjectionCache(
			context.Background(),
			server,
			runtime,
			reader,
			boundDN,
			dynlistProjectionRequest{
				attributes: request.Attributes,
				filter:     &request.Filter,
			},
		).apply(runtime.databases[databaseIndex], entry)
		if projectErr != nil {
			return directory.Entry{}, ldapwire.SyncUUID{}, false, projectErr
		}
		entry = projected
		filterEntry = projectedFilterEntry
	}
	if !subentrySearchVisible(
		runtime,
		entry,
		request.Scope,
		syncSearch.subentries,
	) {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, nil
	}
	if !syncSearch.manageDsaIT &&
		runtime.schema.EntryHasObjectClass(entry, "referral") {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, nil
	}
	matches, err := server.filterMatches(
		runtime,
		tx,
		boundDN,
		filterEntry,
		request.Filter,
	)
	if err != nil {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, err
	}
	if !matches || !server.allowed(
		runtime,
		tx,
		boundDN,
		entry,
		"entry",
		nil,
		acl.Read,
	) {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, nil
	}
	uuid, err := syncUUIDFromEntry(entry)
	if err != nil {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, err
	}
	readable := server.attributesWithPrivilege(
		runtime,
		tx,
		boundDN,
		entry,
		acl.Read,
		request.TypesOnly,
	)
	readable = stripSyncExcludedAttributes(runtime.schema, readable)
	selected := server.selectEntry(
		runtime,
		readable,
		request.Attributes,
		request.TypesOnly,
	)
	return selected, uuid, true, nil
}

func syncSearchDatabaseIndexForEntry(
	runtime *runtimeState,
	syncSearch *syncSearchContext,
	partition string,
	entryDN string,
) (int, error) {
	storedDN, err := normalizeSyncSearchDN(runtime, entryDN)
	if err != nil {
		return -1, err
	}
	for _, route := range syncSearch.routes {
		if route.partition != partition {
			continue
		}
		localDN, err := route.localDN(runtime, storedDN)
		if err != nil {
			return -1, err
		}
		base, err := normalizeSyncSearchDN(runtime, route.base.String())
		if err != nil {
			return -1, err
		}
		if directory.InScope(base, localDN, route.scope) {
			return route.databaseIndex, nil
		}
	}
	return -1, nil
}

func normalizeSyncSearchDN(
	runtime *runtimeState,
	value string,
) (directory.DN, error) {
	if runtime != nil && runtime.schema != nil {
		return runtime.schema.NormalizeDN(value)
	}
	return directory.ParseDN(value)
}

func (route syncSearchRoute) localDN(
	runtime *runtimeState,
	dn directory.DN,
) (directory.DN, error) {
	dn, err := normalizeSyncSearchDN(runtime, dn.String())
	if err != nil {
		return directory.DN{}, err
	}
	if route.rwm != nil {
		dn, err = route.rwm.mapDNToLocal(dn)
		if err != nil {
			return directory.DN{}, err
		}
	}
	return normalizeSyncSearchDN(runtime, dn.String())
}
