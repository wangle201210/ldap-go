package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var errSyncConsumerAccesslogGap = errors.New(
	"accesslog change cannot be replayed safely",
)

type syncConsumerAccesslogOperationKind uint8

const (
	syncConsumerAccesslogAdd syncConsumerAccesslogOperationKind = iota
	syncConsumerAccesslogDelete
	syncConsumerAccesslogModify
	syncConsumerAccesslogModifyDN
)

type syncConsumerAccesslogModification struct {
	description string
	operation   byte
	values      [][]byte
}

type syncConsumerAccesslogOperation struct {
	kind          syncConsumerAccesslogOperationKind
	remoteDN      directory.DN
	newRemoteDN   *directory.DN
	deleteOldRDN  bool
	modifications []syncConsumerAccesslogModification
	csn           openLDAPCSN
}

func (server *Server) runSyncConsumerAccesslogSearch(
	ctx context.Context,
	connection *ldap.Conn,
	config syncConsumerConfig,
	consumerMode syncConsumerMode,
	cookie []byte,
) error {
	if config.logBase == nil || config.logFilter == nil {
		return errors.New("accesslog search requires logbase and logfilter")
	}
	connection.SetTimeout(config.operationTimeout)
	searchContext := ctx
	var watchdog *syncConsumerRefreshWatchdog
	if consumerMode == syncConsumerRefreshAndPersist {
		connection.SetTimeout(0)
		searchContext, watchdog = startSyncConsumerRefreshWatchdog(
			ctx,
			consumerMode,
			config.operationTimeout,
		)
		defer watchdog.stop()
	}

	controls := []ldap.Control{ldap.NewControlManageDsaIT(true)}
	if config.authorizationID != "" {
		controls = append(controls, ldap.NewControlString(
			syncConsumerProxyAuthzOID,
			true,
			config.authorizationID,
		))
	}
	request := ldap.NewSearchRequest(
		config.logBase.String(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		config.sizeLimit,
		config.timeLimit,
		false,
		config.logFilterText,
		[]string{
			"reqDN",
			"reqType",
			"reqMod",
			"reqNewRDN",
			"reqDeleteOldRDN",
			"reqNewSuperior",
			"reqControls",
			"entryCSN",
		},
		controls,
	)
	mode := ldap.SyncRequestModeRefreshOnly
	if consumerMode == syncConsumerRefreshAndPersist {
		mode = ldap.SyncRequestModeRefreshAndPersist
	}
	response := connection.Syncrepl(
		searchContext,
		request,
		syncConsumerResponseBuffer,
		mode,
		cookie,
		false,
	)
	refresh := syncConsumerRefreshState{}
	for response.Next() {
		if err := server.processSyncConsumerAccesslogResponse(
			searchContext,
			config,
			&refresh,
			response.Entry(),
			response.Controls(),
		); err != nil {
			resetErr := server.resetSyncConsumerCookie(ctx, config)
			return errors.Join(
				fmt.Errorf("%w: %v", errSyncConsumerAccesslogGap, err),
				resetErr,
			)
		}
		if refresh.complete {
			watchdog.markComplete()
		}
	}
	if err := watchdog.timeoutError(); err != nil {
		return err
	}
	if err := response.Err(); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSyncRefreshRequired) {
			resetErr := server.resetSyncConsumerCookie(ctx, config)
			return errors.Join(
				fmt.Errorf("%w: provider requested a refresh", errSyncConsumerAccesslogGap),
				resetErr,
			)
		}
		return fmt.Errorf("accesslog syncrepl search: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := connection.GetLastError(); err != nil {
		return fmt.Errorf("accesslog syncrepl connection: %w", err)
	}
	if consumerMode == syncConsumerRefreshOnly && !refresh.complete {
		return errors.New("accesslog refresh ended without Sync Done")
	}
	return nil
}

func (server *Server) processSyncConsumerAccesslogResponse(
	ctx context.Context,
	config syncConsumerConfig,
	refresh *syncConsumerRefreshState,
	entry *ldap.Entry,
	controls []ldap.Control,
) error {
	if entry != nil {
		state, err := syncConsumerStateControl(controls)
		if err != nil {
			return err
		}
		if state.State == ldap.SyncStateDelete {
			if err := server.storeSyncConsumerCookie(
				ctx,
				config,
				state.Cookie,
			); err != nil {
				return err
			}
		} else if err := server.applySyncConsumerAccesslogEntry(
			ctx,
			config,
			entry,
			state.Cookie,
		); err != nil {
			return err
		}
	}

	for _, control := range controls {
		switch typed := control.(type) {
		case *ldap.ControlSyncState:
			if entry == nil {
				return errors.New("Sync State control has no accesslog entry")
			}
		case *ldap.ControlSyncDone:
			if err := server.storeSyncConsumerCookie(
				ctx,
				config,
				typed.Cookie,
			); err != nil {
				return err
			}
			refresh.complete = true
		case *ldap.ControlSyncInfo:
			complete, err := server.processSyncConsumerAccesslogInfo(
				ctx,
				config,
				typed,
			)
			if err != nil {
				return err
			}
			refresh.complete = refresh.complete || complete
		}
	}
	return nil
}

func (server *Server) processSyncConsumerAccesslogInfo(
	ctx context.Context,
	config syncConsumerConfig,
	info *ldap.ControlSyncInfo,
) (bool, error) {
	var (
		cookie   []byte
		complete bool
	)
	switch info.Value {
	case ldap.SyncInfoNewcookie:
		if info.NewCookie == nil {
			return false, errors.New("newCookie Sync Info has no value")
		}
		cookie = info.NewCookie.Cookie
	case ldap.SyncInfoRefreshDelete:
		if info.RefreshDelete == nil {
			return false, errors.New("refreshDelete Sync Info has no value")
		}
		cookie = info.RefreshDelete.Cookie
		complete = info.RefreshDelete.RefreshDone
	case ldap.SyncInfoRefreshPresent:
		if info.RefreshPresent == nil {
			return false, errors.New("refreshPresent Sync Info has no value")
		}
		cookie = info.RefreshPresent.Cookie
		complete = info.RefreshPresent.RefreshDone
	case ldap.SyncInfoSyncIdSet:
		if info.SyncIdSet == nil {
			return false, errors.New("syncIdSet Sync Info has no value")
		}
		cookie = info.SyncIdSet.Cookie
	default:
		return false, fmt.Errorf("unknown Sync Info value %d", info.Value)
	}
	return complete, server.storeSyncConsumerCookie(ctx, config, cookie)
}

func (server *Server) applySyncConsumerAccesslogEntry(
	ctx context.Context,
	config syncConsumerConfig,
	source *ldap.Entry,
	responseCookie []byte,
) error {
	runtime := server.runtime.Load()
	operation, err := parseSyncConsumerAccesslogOperation(
		runtime,
		config,
		source,
	)
	if err != nil {
		return fmt.Errorf("parse accesslog entry %s: %w", source.DN, err)
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		alreadyApplied, err := syncConsumerAccesslogOperationApplied(
			writer,
			config,
			operation.csn,
		)
		if err != nil {
			return err
		}
		cookie, err := syncConsumerAccesslogCookie(
			writer,
			config,
			responseCookie,
			operation.csn,
		)
		if err != nil {
			return err
		}
		if alreadyApplied {
			return updateSyncConsumerCookie(writer, config, cookie)
		}

		switch operation.kind {
		case syncConsumerAccesslogAdd:
			err = applySyncConsumerAccesslogAdd(
				runtime,
				writer,
				config,
				operation,
			)
		case syncConsumerAccesslogDelete:
			err = applySyncConsumerAccesslogDelete(
				writer,
				config,
				operation,
			)
		case syncConsumerAccesslogModify:
			err = applySyncConsumerAccesslogModify(
				runtime,
				writer,
				config,
				operation,
			)
		case syncConsumerAccesslogModifyDN:
			err = applySyncConsumerAccesslogModifyDN(
				runtime,
				writer,
				config,
				operation,
			)
		default:
			err = errors.New("unknown accesslog operation")
		}
		if err != nil {
			return err
		}
		return updateSyncConsumerCookie(writer, config, cookie)
	})
}

func parseSyncConsumerAccesslogOperation(
	runtime *runtimeState,
	config syncConsumerConfig,
	source *ldap.Entry,
) (syncConsumerAccesslogOperation, error) {
	if source == nil {
		return syncConsumerAccesslogOperation{}, errors.New("nil accesslog entry")
	}
	rawDN, err := syncConsumerAccesslogSingleValue(source, "reqDN", true)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	remoteDN, err := directory.ParseDN(string(rawDN))
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	rawType, err := syncConsumerAccesslogSingleValue(source, "reqType", true)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	var kind syncConsumerAccesslogOperationKind
	switch strings.ToLower(string(rawType)) {
	case "add":
		kind = syncConsumerAccesslogAdd
	case "delete":
		kind = syncConsumerAccesslogDelete
	case "modify":
		kind = syncConsumerAccesslogModify
	case "modrdn", "moddn":
		kind = syncConsumerAccesslogModifyDN
	default:
		return syncConsumerAccesslogOperation{}, fmt.Errorf(
			"unknown reqType %q",
			rawType,
		)
	}
	rawCSN, err := syncConsumerAccesslogSingleValue(source, "entryCSN", true)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	csn, err := parseOpenLDAPCSN(string(rawCSN))
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	modifications, err := parseSyncConsumerAccesslogModifications(
		runtime,
		config,
		source.GetEqualFoldRawAttributeValues("reqMod"),
	)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	if (kind == syncConsumerAccesslogAdd ||
		kind == syncConsumerAccesslogModify) &&
		len(modifications) == 0 {
		return syncConsumerAccesslogOperation{}, errors.New(
			"add or modify accesslog entry has no reqMod values",
		)
	}

	operation := syncConsumerAccesslogOperation{
		kind:          kind,
		remoteDN:      remoteDN,
		modifications: modifications,
		csn:           csn,
	}
	if kind != syncConsumerAccesslogModifyDN {
		return operation, nil
	}
	rawRDN, err := syncConsumerAccesslogSingleValue(source, "reqNewRDN", true)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	superior, ok := remoteDN.Parent()
	if !ok {
		return syncConsumerAccesslogOperation{}, errors.New(
			"cannot rename the root DSE",
		)
	}
	rawSuperior, err := syncConsumerAccesslogSingleValue(
		source,
		"reqNewSuperior",
		false,
	)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	if rawSuperior != nil {
		superior, err = directory.ParseDN(string(rawSuperior))
		if err != nil {
			return syncConsumerAccesslogOperation{}, err
		}
	}
	newRemoteDN, err := directory.ComposeDN(string(rawRDN), superior)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	rawDeleteOld, err := syncConsumerAccesslogSingleValue(
		source,
		"reqDeleteOldRDN",
		false,
	)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	if rawDeleteOld != nil {
		switch strings.ToLower(string(rawDeleteOld)) {
		case "true":
			operation.deleteOldRDN = true
		case "false":
		default:
			return syncConsumerAccesslogOperation{}, fmt.Errorf(
				"invalid reqDeleteOldRDN %q",
				rawDeleteOld,
			)
		}
	}
	operation.newRemoteDN = &newRemoteDN
	return operation, nil
}

func syncConsumerAccesslogSingleValue(
	entry *ldap.Entry,
	description string,
	required bool,
) ([]byte, error) {
	values := entry.GetEqualFoldRawAttributeValues(description)
	if len(values) == 0 && !required {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, fmt.Errorf(
			"%s must have exactly one value, got %d",
			description,
			len(values),
		)
	}
	return bytes.Clone(values[0]), nil
}

func parseSyncConsumerAccesslogModifications(
	runtime *runtimeState,
	config syncConsumerConfig,
	values [][]byte,
) ([]syncConsumerAccesslogModification, error) {
	var (
		result  []syncConsumerAccesslogModification
		current *syncConsumerAccesslogModification
	)
	for _, raw := range values {
		colon := bytes.IndexByte(raw, ':')
		if colon < 0 {
			return nil, fmt.Errorf("invalid reqMod value %q", raw)
		}
		if colon == 0 {
			current = nil
			continue
		}
		if colon+1 >= len(raw) {
			return nil, fmt.Errorf("invalid reqMod operation %q", raw)
		}
		description := string(raw[:colon])
		if runtime != nil {
			if _, found := runtime.schema.AttributeType(description); !found {
				return nil, fmt.Errorf(
					"reqMod references unknown attribute %q",
					description,
				)
			}
		}
		if syncConsumerAccesslogAttributeExcluded(
			runtime,
			config,
			description,
		) {
			current = nil
			continue
		}
		operation := raw[colon+1]
		switch operation {
		case '+', '-', '=', '#':
		default:
			return nil, fmt.Errorf("invalid reqMod operation %q", raw)
		}
		hasValue := false
		var value []byte
		if colon+2 < len(raw) {
			if raw[colon+2] != ' ' {
				return nil, fmt.Errorf("invalid reqMod value delimiter %q", raw)
			}
			hasValue = true
			value = bytes.Clone(raw[colon+3:])
			if config.suffixMap != nil &&
				runtime != nil &&
				runtime.schema.IsDNValued(description) {
				mapped, err := mapSyncConsumerAttributeDN(config, value)
				if err != nil {
					return nil, fmt.Errorf(
						"map reqMod %s value: %w",
						description,
						err,
					)
				}
				value = mapped
			}
		}
		if current == nil ||
			!strings.EqualFold(current.description, description) ||
			current.operation != operation {
			result = append(result, syncConsumerAccesslogModification{
				description: description,
				operation:   operation,
			})
			current = &result[len(result)-1]
		}
		if hasValue {
			current.values = append(current.values, value)
		}
	}
	return result, nil
}

func syncConsumerAccesslogAttributeExcluded(
	runtime *runtimeState,
	config syncConsumerConfig,
	description string,
) bool {
	switch strings.ToLower(description) {
	case "entrydn", "hassubordinates", "subschemasubentry":
		return true
	}
	return syncConsumerAttributeExcluded(runtime, config, description)
}

func applySyncConsumerAccesslogAdd(
	runtime *runtimeState,
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) error {
	if !directory.InScope(config.searchBase, operation.remoteDN, config.scope) {
		return nil
	}
	targetDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return err
	}
	if _, err := writer.GetIn(config.partition, targetDN); err == nil {
		return storage.ErrEntryExists
	} else if !errors.Is(err, storage.ErrEntryNotFound) {
		return err
	}
	if !targetDN.Equal(config.localBase) {
		parent, ok := targetDN.Parent()
		if !ok {
			return errors.New("accesslog add has no parent")
		}
		if _, err := writer.GetIn(config.partition, parent); err != nil {
			return fmt.Errorf("accesslog add parent %s: %w", parent.String(), err)
		}
	}
	entry := directory.Entry{DN: targetDN.String()}
	if err := applySyncConsumerAccesslogModifications(
		runtime,
		&entry,
		operation.modifications,
	); err != nil {
		return err
	}
	matches, err := syncConsumerAccesslogEntryMatches(runtime, config, entry)
	if err != nil || !matches {
		return err
	}
	if config.schemaChecking && runtime != nil {
		if err := runtime.schema.ValidateEntry(entry); err != nil {
			return fmt.Errorf("validate accesslog add %s: %w", entry.DN, err)
		}
	}
	return writer.PutIn(config.partition, entry, false)
}

func applySyncConsumerAccesslogDelete(
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) error {
	if !directory.InScope(config.searchBase, operation.remoteDN, config.scope) {
		return nil
	}
	targetDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return err
	}
	if _, err := writer.GetIn(config.partition, targetDN); err != nil {
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		return err
	}
	hasChild := false
	if err := writer.ForEachIn(
		config.partition,
		func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if targetDN.AncestorOf(candidate) {
				hasChild = true
			}
			return nil
		},
	); err != nil {
		return err
	}
	if hasChild {
		return errors.New("accesslog delete targets a non-leaf entry")
	}
	return writer.DeleteIn(config.partition, targetDN)
}

func applySyncConsumerAccesslogModify(
	runtime *runtimeState,
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) error {
	if !directory.InScope(config.searchBase, operation.remoteDN, config.scope) {
		return nil
	}
	targetDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return err
	}
	entry, err := writer.GetIn(config.partition, targetDN)
	if err != nil {
		return err
	}
	if err := applySyncConsumerAccesslogModifications(
		runtime,
		&entry,
		operation.modifications,
	); err != nil {
		return err
	}
	matches, err := syncConsumerAccesslogEntryMatches(runtime, config, entry)
	if err != nil {
		return err
	}
	if !matches {
		return writer.DeleteIn(config.partition, targetDN)
	}
	if config.schemaChecking && runtime != nil {
		if err := runtime.schema.ValidateEntry(entry); err != nil {
			return fmt.Errorf("validate accesslog modify %s: %w", entry.DN, err)
		}
	}
	return writer.PutIn(config.partition, entry, true)
}

func applySyncConsumerAccesslogModifyDN(
	runtime *runtimeState,
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) error {
	if operation.newRemoteDN == nil {
		return errors.New("accesslog modrdn has no destination DN")
	}
	oldInScope := directory.InScope(
		config.searchBase,
		operation.remoteDN,
		config.scope,
	)
	newInScope := directory.InScope(
		config.searchBase,
		*operation.newRemoteDN,
		config.scope,
	)
	switch {
	case !oldInScope && !newInScope:
		return nil
	case !oldInScope && newInScope:
		return errors.New("accesslog rename enters the replication scope")
	}
	oldDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return err
	}
	if !newInScope {
		return deleteSyncConsumerAccesslogSubtree(writer, config.partition, oldDN)
	}
	newDN, err := mapSyncConsumerAccesslogDN(config, *operation.newRemoteDN)
	if err != nil {
		return err
	}

	type move struct {
		oldDN directory.DN
		newDN directory.DN
		entry directory.Entry
	}
	var moves []move
	oldKeys := make(map[string]struct{})
	if err := writer.ForEachIn(
		config.partition,
		func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if !oldDN.Equal(candidate) && !oldDN.AncestorOf(candidate) {
				return nil
			}
			replaced, err := candidate.ReplaceAncestor(oldDN, newDN)
			if err != nil {
				return err
			}
			moves = append(moves, move{
				oldDN: candidate,
				newDN: replaced,
				entry: entry,
			})
			oldKeys[candidate.Key()] = struct{}{}
			return nil
		},
	); err != nil {
		return err
	}
	if len(moves) == 0 {
		return storage.ErrEntryNotFound
	}
	for _, item := range moves {
		if _, moving := oldKeys[item.newDN.Key()]; moving {
			continue
		}
		if _, err := writer.GetIn(config.partition, item.newDN); err == nil {
			return storage.ErrEntryExists
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
	}
	for index := range moves {
		item := &moves[index]
		item.entry.DN = item.newDN.String()
		if !item.oldDN.Equal(oldDN) {
			continue
		}
		if operation.deleteOldRDN {
			item.entry.DeleteRDNValues(oldDN)
		}
		item.entry.EnsureRDNValues(newDN)
		if err := applySyncConsumerAccesslogModifications(
			runtime,
			&item.entry,
			operation.modifications,
		); err != nil {
			return err
		}
		if config.schemaChecking && runtime != nil {
			if err := runtime.schema.ValidateEntry(item.entry); err != nil {
				return fmt.Errorf(
					"validate accesslog modrdn %s: %w",
					item.entry.DN,
					err,
				)
			}
		}
	}
	sort.Slice(moves, func(i, j int) bool {
		return moves[i].oldDN.Depth() > moves[j].oldDN.Depth()
	})
	for _, item := range moves {
		if err := writer.DeleteIn(config.partition, item.oldDN); err != nil {
			return err
		}
	}
	sort.Slice(moves, func(i, j int) bool {
		return moves[i].newDN.Depth() < moves[j].newDN.Depth()
	})
	for _, item := range moves {
		if err := writer.PutIn(config.partition, item.entry, false); err != nil {
			return err
		}
	}
	return nil
}

func applySyncConsumerAccesslogModifications(
	runtime *runtimeState,
	entry *directory.Entry,
	modifications []syncConsumerAccesslogModification,
) error {
	for _, modification := range modifications {
		singleValue := false
		if runtime != nil {
			if attributeType, found := runtime.schema.AttributeType(
				modification.description,
			); found {
				singleValue = attributeType.SingleValue
			}
		}
		var err error
		switch modification.operation {
		case '+':
			if singleValue {
				entry.ReplaceValues(
					modification.description,
					modification.values,
				)
				continue
			}
			err = entry.AddValues(
				modification.description,
				modification.values,
			)
		case '-':
			err = entry.DeleteValues(
				modification.description,
				modification.values,
			)
			if singleValue && errors.Is(err, directory.ErrNoSuchAttribute) {
				err = nil
			}
		case '=':
			entry.ReplaceValues(
				modification.description,
				modification.values,
			)
		case '#':
			if len(modification.values) != 1 {
				return fmt.Errorf(
					"increment %s requires exactly one value",
					modification.description,
				)
			}
			err = entry.Increment(
				modification.description,
				modification.values[0],
			)
		default:
			return fmt.Errorf(
				"unknown modification operation %q",
				modification.operation,
			)
		}
		if err != nil {
			return fmt.Errorf(
				"apply %c modification to %s: %w",
				modification.operation,
				modification.description,
				err,
			)
		}
	}
	return nil
}

func syncConsumerAccesslogEntryMatches(
	runtime *runtimeState,
	config syncConsumerConfig,
	entry directory.Entry,
) (bool, error) {
	if runtime == nil {
		return true, nil
	}
	return config.filter.MatchWith(entry, runtime.schema)
}

func mapSyncConsumerAccesslogDN(
	config syncConsumerConfig,
	remote directory.DN,
) (directory.DN, error) {
	if config.suffixMap == nil {
		return remote, nil
	}
	if !config.searchBase.Equal(remote) &&
		!config.searchBase.AncestorOf(remote) {
		return directory.DN{}, errors.New(
			"accesslog DN is outside the suffixmassage source subtree",
		)
	}
	return remote.ReplaceAncestor(config.searchBase, config.localBase)
}

func deleteSyncConsumerAccesslogSubtree(
	writer storage.Writer,
	partition string,
	base directory.DN,
) error {
	var dns []directory.DN
	if err := writer.ForEachIn(
		partition,
		func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if base.Equal(candidate) || base.AncestorOf(candidate) {
				dns = append(dns, candidate)
			}
			return nil
		},
	); err != nil {
		return err
	}
	if len(dns) == 0 {
		return storage.ErrEntryNotFound
	}
	sort.Slice(dns, func(i, j int) bool {
		return dns[i].Depth() > dns[j].Depth()
	})
	for _, dn := range dns {
		if err := writer.DeleteIn(partition, dn); err != nil {
			return err
		}
	}
	return nil
}

func syncConsumerAccesslogOperationApplied(
	reader storage.Reader,
	config syncConsumerConfig,
	csn openLDAPCSN,
) (bool, error) {
	raw, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
	if errors.Is(err, storage.ErrMetadataNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	current, found := parseOpenLDAPSyncCookie(raw).csns[csn.serverID]
	return found && compareOpenLDAPCSN(current, csn) >= 0, nil
}

func syncConsumerAccesslogCookie(
	reader storage.Reader,
	config syncConsumerConfig,
	responseCookie []byte,
	csn openLDAPCSN,
) ([]byte, error) {
	state := make(syncCSNState)
	rawStored, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
	switch {
	case err == nil:
		mergeSyncConsumerAccesslogCSNs(
			state,
			parseOpenLDAPSyncCookie(rawStored).csns,
		)
	case errors.Is(err, storage.ErrMetadataNotFound):
	default:
		return nil, err
	}
	mergeSyncConsumerAccesslogCSNs(
		state,
		parseOpenLDAPSyncCookie(responseCookie).csns,
	)
	if current, found := state[csn.serverID]; !found ||
		compareOpenLDAPCSN(csn, current) > 0 {
		state[csn.serverID] = csn
	}
	return composeOpenLDAPSyncCookie(config.rid, state), nil
}

func mergeSyncConsumerAccesslogCSNs(
	destination syncCSNState,
	source syncCSNState,
) {
	for serverID, csn := range source {
		current, found := destination[serverID]
		if !found || compareOpenLDAPCSN(csn, current) > 0 {
			destination[serverID] = csn
		}
	}
}

func (server *Server) resetSyncConsumerCookie(
	ctx context.Context,
	config syncConsumerConfig,
) error {
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		err := writer.DeleteMetadata(syncConsumerCookieMetadataKey(config))
		if errors.Is(err, storage.ErrMetadataNotFound) {
			return nil
		}
		return err
	})
}
