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
	present            []ldapwire.SyncUUID
	deleted            map[ldapwire.SyncUUID]struct{}
	refreshDeletes     bool
	subscription       *syncChangeSubscription
}

type syncSearchPolicy struct {
	sessionLogSize int
	noPresent      bool
	reloadHint     bool
}

type syncSearchRoute struct {
	partition string
	base      directory.DN
	scope     directory.Scope
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
		if !database.syncProvider {
			if !control.critical {
				return nil, nil
			}
			result := ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"Sync is not enabled for the target database",
			)
			return nil, &result
		}
		if _, exists := partitionSet[database.partition]; !exists {
			partitionSet[database.partition] = struct{}{}
			partitions = append(partitions, database.partition)
			policies[database.partition] = syncSearchPolicy{
				sessionLogSize: database.syncSessionLogSize,
				noPresent:      database.syncNoPresent,
				reloadHint:     database.syncReloadHint,
			}
		}
		syncRoutes = append(syncRoutes, syncSearchRoute{
			partition: database.partition,
			base:      route.base,
			scope:     route.scope,
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
		syncSearch.deleted = make(map[ldapwire.SyncUUID]struct{})
		for _, change := range replay {
			if syncSearchBaseChanged(syncSearch, change) {
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
				syncSearch.deleted[beforeUUID] = struct{}{}
			}
			if afterMatch {
				delete(syncSearch.deleted, afterUUID)
			}
		}
		return nil, nil
	case !anySessionLog && allNoPresent:
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
	for _, partition := range syncSearch.partitions {
		tx := storage.ReaderInPartition(reader, partition)
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

func (syncSearch *syncSearchContext) deletedUUIDs() []ldapwire.SyncUUID {
	uuids := make([]ldapwire.SyncUUID, 0, len(syncSearch.deleted))
	for uuid := range syncSearch.deleted {
		uuids = append(uuids, uuid)
	}
	sort.Slice(uuids, func(i, j int) bool {
		return bytes.Compare(uuids[i][:], uuids[j][:]) < 0
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
) error {
	if result.Code == ldapwire.ResultSuccess {
		deleted := syncSearch.deletedUUIDs()
		for start := 0; start < len(deleted); start += syncIDSetChunkSize {
			end := min(start+syncIDSetChunkSize, len(deleted))
			info := ldapwire.SyncInfoValue{
				Kind:           ldapwire.SyncInfoIDSet,
				RefreshDeletes: true,
				UUIDs:          deleted[start:end],
			}
			if err := server.writeSyncInfo(
				connection,
				messageID,
				info,
			); err != nil {
				return err
			}
		}
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
		if err := ldapwire.Write(
			connection,
			ldapwire.EncodeSearchResultEntry(
				messageID,
				candidate.selected,
				[]ldapwire.Control{control},
			),
		); err != nil {
			return err
		}
	}
	if result.Code != ldapwire.ResultSuccess {
		return server.writeSearchDone(connection, messageID, result)
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
		return server.writeSearchDoneWithControls(
			connection,
			messageID,
			result,
			[]ldapwire.Control{{
				OID:      syncDoneControlOID,
				Critical: syncSearch.control.critical,
				Value:    ldapwire.EncodeSyncDoneValue(done),
				HasValue: true,
			}},
		)
	}

	refreshKind := ldapwire.SyncInfoRefreshPresent
	if syncSearch.refreshDeletes {
		refreshKind = ldapwire.SyncInfoRefreshDelete
	}
	if err := server.writeSyncInfo(
		connection,
		messageID,
		ldapwire.SyncInfoValue{
			Kind:        refreshKind,
			Cookie:      cookie,
			HasCookie:   len(syncSearch.snapshot) > 0,
			RefreshDone: true,
		},
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
	return ldapwire.Write(
		connection,
		ldapwire.EncodeIntermediateResponse(
			messageID,
			syncInfoOID,
			ldapwire.EncodeSyncInfoValue(info),
			nil,
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
			if current, exists := syncSearch.snapshot[change.csn.serverID]; exists &&
				compareOpenLDAPCSN(change.csn, current) <= 0 {
				continue
			}
			syncSearch.snapshot[change.csn.serverID] = change.csn

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
			control := syncStateResponseControl(
				syncSearch.control.critical,
				ldapwire.SyncStateValue{
					State:     syncState,
					EntryUUID: uuid,
					Cookie:    cookie,
					HasCookie: true,
				},
			)
			if err := ldapwire.Write(
				connection,
				ldapwire.EncodeSearchResultEntry(
					messageID,
					entry,
					[]ldapwire.Control{control},
				),
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
	if syncSearchBaseChanged(syncSearch, change) {
		return directory.Entry{},
			0,
			ldapwire.SyncUUID{},
			false,
			errSyncSearchBaseChanged
	}
	runtime := server.runtime.Load()
	if runtime == nil {
		runtime = state.runtime
	}
	var (
		beforeEntry directory.Entry
		beforeUUID  ldapwire.SyncUUID
		beforeMatch bool
		afterEntry  directory.Entry
		afterUUID   ldapwire.SyncUUID
		afterMatch  bool
	)
	err := server.config.Store.View(
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
	syncSearch *syncSearchContext,
	change syncChange,
) bool {
	if !change.hasBefore {
		return false
	}
	beforeDN, err := directory.ParseDN(change.before.DN)
	if err != nil {
		return false
	}
	var afterDN directory.DN
	afterAtSameDN := false
	if change.hasAfter {
		afterDN, err = directory.ParseDN(change.after.DN)
		afterAtSameDN = err == nil && beforeDN.Equal(afterDN)
	}
	if afterAtSameDN {
		return false
	}
	for _, route := range syncSearch.routes {
		if route.partition == change.partition &&
			(beforeDN.Equal(route.base) || beforeDN.AncestorOf(route.base)) {
			return true
		}
	}
	return false
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
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, err
	}
	inScope := false
	for _, route := range syncSearch.routes {
		if route.partition == partition &&
			directory.InScope(route.base, dn, route.scope) {
			inScope = true
			break
		}
	}
	if !inScope {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, nil
	}

	tx := storage.ReaderInPartition(reader, partition)
	entry = withSubschemaReference(entry)
	entry, err = withCollectiveAttributes(runtime.schema, tx, entry)
	if err != nil {
		return directory.Entry{}, ldapwire.SyncUUID{}, false, err
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
		entry,
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
