package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var errSyncConsumerAccesslogGap = errors.New(
	"accesslog change cannot be replayed safely",
)

const syncConsumerAccesslogBootstrapMetadataPrefix = "openldap/syncrepl/accesslog-bootstrap/"

type syncConsumerAccesslogBootstrapStatus uint8

const (
	syncConsumerAccesslogBootstrapMissing syncConsumerAccesslogBootstrapStatus = iota
	syncConsumerAccesslogBootstrapInProgress
	syncConsumerAccesslogBootstrapComplete
	syncConsumerAccesslogBootstrapUnknown
)

type syncConsumerAccesslogBootstrapState struct {
	status          syncConsumerAccesslogBootstrapStatus
	identityMatches bool
}

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
	kind           syncConsumerAccesslogOperationKind
	remoteDN       directory.DN
	newRemoteDN    *directory.DN
	newRDN         string
	hasNewSuperior bool
	deleteOldRDN   bool
	modifications  []syncConsumerAccesslogModification
	csn            openLDAPCSN
}

type syncConsumerAccesslogApplyResult struct {
	eligible  bool
	applied   bool
	requestDN directory.DN
	newDN     *directory.DN
	afterDN   *directory.DN
	before    *directory.Entry
	after     *directory.Entry
}

type syncConsumerAccesslogConflictHistory struct {
	csn           openLDAPCSN
	modifications []syncConsumerAccesslogModification
}

func validateDeltaMultiProviderDatabases(databases []runtimeDatabase) error {
	for _, database := range databases {
		if !database.multiProvider {
			continue
		}
		delta := false
		for _, consumer := range database.syncConsumers {
			delta = delta || consumer.syncData == "accesslog"
		}
		if !delta {
			continue
		}
		log := database.accesslog
		if log == nil || log.operations&accesslogWrites != accesslogWrites {
			return fmt.Errorf("%s writable delta-syncrepl requires a local accesslog recording all writes", database.name)
		}
		if !databaseUsesLocalContentStorage(database) || !database.syncProvider || !database.lastMod ||
			log.targetDatabaseIndex < 0 || log.targetDatabaseIndex >= len(databases) ||
			!databaseUsesLocalContentStorage(databases[log.targetDatabaseIndex]) ||
			!databases[log.targetDatabaseIndex].syncProvider {
			return fmt.Errorf("%s writable delta-syncrepl requires local content and accesslog databases with syncprov and lastmod", database.name)
		}
		for _, consumer := range database.syncConsumers {
			if consumer.syncData != "accesslog" || consumer.suffixMap != nil ||
				len(database.suffixes) != 1 || !consumer.searchBase.Equal(database.suffixes[0]) ||
				consumer.scope != directory.ScopeWholeSubtree ||
				!strings.EqualFold(consumer.filterText, "(objectclass=*)") ||
				len(consumer.attributes) != 2 || consumer.attributes[0] != "*" || consumer.attributes[1] != "+" ||
				len(consumer.exAttributes) != 0 || consumer.attributesOnly ||
				!strings.EqualFold(consumer.logFilterText, "(&(objectClass=auditWriteObject)(reqResult=0))") {
				return fmt.Errorf("%s writable delta-syncrepl requires unfiltered full-suffix accesslog consumers without attribute selection or suffixmassage", database.name)
			}
		}
	}
	return nil
}

func syncConsumerAccesslogBootstrapMetadataKey(config syncConsumerConfig) string {
	partition := base64.RawURLEncoding.EncodeToString([]byte(config.partition))
	return fmt.Sprintf(
		"%s%s/%03d",
		syncConsumerAccesslogBootstrapMetadataPrefix,
		partition,
		config.rid,
	)
}

func syncConsumerAccesslogBootstrapIdentity(config syncConsumerConfig) []byte {
	digest := sha256.New()
	write := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(value))
	}
	write(config.partition)
	write(fmt.Sprint(config.rid))
	write(config.databaseID)
	write(config.syncData)
	write(config.bindMethod)
	write(config.bindDN)
	write(config.saslMechanism)
	write(config.authenticationID)
	write(config.authorizationID)
	write(config.realm)
	write(config.searchBase.String())
	write(config.localBase.String())
	if config.suffixMap != nil {
		write(config.suffixMap.String())
	} else {
		write("")
	}
	write(fmt.Sprint(config.scope))
	write(config.filterText)
	write(fmt.Sprint(len(config.attributes)))
	for _, value := range config.attributes {
		write(value)
	}
	write(fmt.Sprint(len(config.exAttributes)))
	for _, value := range config.exAttributes {
		write(value)
	}
	write(fmt.Sprint(
		config.attributesOnly,
		config.schemaChecking,
		config.manageDSAit,
	))
	if config.logBase != nil {
		write(config.logBase.String())
	} else {
		write("")
	}
	write(config.logFilterText)
	return digest.Sum(nil)
}

func syncConsumerAccesslogBootstrapValue(
	status syncConsumerAccesslogBootstrapStatus,
	config syncConsumerConfig,
) []byte {
	var prefix string
	switch status {
	case syncConsumerAccesslogBootstrapInProgress:
		prefix = "in-progress:"
	case syncConsumerAccesslogBootstrapComplete:
		prefix = "complete:"
	default:
		return nil
	}
	return append([]byte(prefix), syncConsumerAccesslogBootstrapIdentity(config)...)
}

func syncConsumerAccesslogBootstrapStateReader(
	reader storage.Reader,
	config syncConsumerConfig,
) (syncConsumerAccesslogBootstrapState, error) {
	raw, err := reader.Metadata(syncConsumerAccesslogBootstrapMetadataKey(config))
	switch {
	case errors.Is(err, storage.ErrMetadataNotFound):
		return syncConsumerAccesslogBootstrapState{
			status: syncConsumerAccesslogBootstrapMissing,
		}, nil
	case err != nil:
		return syncConsumerAccesslogBootstrapState{}, err
	}
	for _, candidate := range []syncConsumerAccesslogBootstrapStatus{
		syncConsumerAccesslogBootstrapInProgress,
		syncConsumerAccesslogBootstrapComplete,
	} {
		value := syncConsumerAccesslogBootstrapValue(candidate, config)
		prefixLength := len(value) - sha256.Size
		if len(raw) >= prefixLength && bytes.Equal(raw[:prefixLength], value[:prefixLength]) {
			return syncConsumerAccesslogBootstrapState{
				status:          candidate,
				identityMatches: bytes.Equal(raw, value),
			}, nil
		}
	}
	return syncConsumerAccesslogBootstrapState{
		status: syncConsumerAccesslogBootstrapUnknown,
	}, nil
}

func syncConsumerAccesslogBootstrapCompleteReader(
	reader storage.Reader,
	config syncConsumerConfig,
) (bool, error) {
	state, err := syncConsumerAccesslogBootstrapStateReader(reader, config)
	return state.status == syncConsumerAccesslogBootstrapComplete &&
		state.identityMatches, err
}

func (server *Server) syncConsumerAccesslogBootstrapComplete(
	ctx context.Context,
	config syncConsumerConfig,
) (bool, error) {
	var complete bool
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		var err error
		complete, err = syncConsumerAccesslogBootstrapCompleteReader(reader, config)
		return err
	})
	return complete, err
}

func (server *Server) prepareSyncConsumerAccesslogBootstrap(
	ctx context.Context,
	config syncConsumerConfig,
) (bool, error) {
	state := syncConsumerAccesslogBootstrapState{}
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		var err error
		state, err = syncConsumerAccesslogBootstrapStateReader(reader, config)
		return err
	})
	if err != nil || state.status == syncConsumerAccesslogBootstrapComplete &&
		state.identityMatches {
		return state.status == syncConsumerAccesslogBootstrapComplete &&
			state.identityMatches, err
	}
	complete := false
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		current, err := syncConsumerAccesslogBootstrapStateReader(writer, config)
		if err != nil {
			return err
		}
		if current.status == syncConsumerAccesslogBootstrapComplete &&
			current.identityMatches {
			complete = true
			return nil
		}
		if err := deleteSyncConsumerMetadata(
			writer,
			syncConsumerCookieMetadataKey(config),
		); err != nil {
			return err
		}
		database := runtimeDatabaseForPartition(
			server.runtime.Load(),
			config.partition,
		)
		if current.status != syncConsumerAccesslogBootstrapInProgress {
			adopt, err := syncConsumerAccesslogBootstrapCanAdopt(
				writer,
				database,
			)
			if err != nil {
				return err
			}
			if adopt {
				complete = true
				return writer.SetMetadata(
					syncConsumerAccesslogBootstrapMetadataKey(config),
					syncConsumerAccesslogBootstrapValue(
						syncConsumerAccesslogBootstrapComplete,
						config,
					),
				)
			}
		}
		return writer.SetMetadata(
			syncConsumerAccesslogBootstrapMetadataKey(config),
			syncConsumerAccesslogBootstrapValue(
				syncConsumerAccesslogBootstrapInProgress,
				config,
			),
		)
	})
	return complete, err
}

func syncConsumerAccesslogBootstrapCanAdopt(
	reader storage.Reader,
	database *runtimeDatabase,
) (bool, error) {
	if database == nil || !database.multiProvider {
		return false, nil
	}
	state, err := syncContextCSNs(reader, database.partition)
	if err != nil {
		return false, err
	}
	if len(state) != 0 {
		return true, nil
	}
	hasEntries := false
	err = readerForDatabase(reader, *database).ForEach(
		func(directory.Entry) error {
			hasEntries = true
			return nil
		},
	)
	if err != nil {
		return false, err
	}
	if hasEntries {
		return false, fmt.Errorf(
			"%w: writable database has entries but no authoritative contextCSN",
			errSyncConsumerAccesslogGap,
		)
	}
	return false, nil
}

func deleteSyncConsumerMetadata(writer storage.Writer, key string) error {
	err := writer.DeleteMetadata(key)
	if errors.Is(err, storage.ErrMetadataNotFound) {
		return nil
	}
	return err
}

func (server *Server) syncConsumerDeltaInitialCookie(ctx context.Context, config syncConsumerConfig) ([]byte, error) {
	database := runtimeDatabaseForPartition(server.runtime.Load(), config.partition)
	if database == nil || !database.multiProvider {
		return nil, nil
	}
	var cookie []byte
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		complete, err := syncConsumerAccesslogBootstrapCompleteReader(reader, config)
		if err != nil || !complete {
			return err
		}
		state, err := syncContextCSNs(reader, database.partition)
		if err == nil && len(state) != 0 {
			cookie = composeOpenLDAPSyncCookie(config.rid, state)
		}
		if err == nil && len(state) == 0 {
			return readerForDatabase(reader, *database).ForEach(func(entry directory.Entry) error {
				return fmt.Errorf("%w: writable database contains %s without a bootstrap contextCSN", errSyncConsumerAccesslogGap, entry.DN)
			})
		}
		return err
	})
	return cookie, err
}

func (server *Server) syncConsumerAccesslogFailure(ctx context.Context, config syncConsumerConfig, cause error) error {
	database := runtimeDatabaseForPartition(server.runtime.Load(), config.partition)
	if database != nil && database.multiProvider {
		// A full-entry refresh cannot recover attribute history on a writable peer.
		// Keep the last committed cookie so reconnects cannot silently use that path.
		return fmt.Errorf("writable delta-syncrepl stopped: %w", cause)
	}
	return errors.Join(fmt.Errorf("%w: %v", errSyncConsumerAccesslogGap, cause), server.resetSyncConsumerCookie(ctx, config))
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
			"reqEntryUUID",
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
			return server.syncConsumerAccesslogFailure(ctx, config, err)
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
			return server.syncConsumerAccesslogFailure(ctx, config, err)
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
			if err := server.storeSyncConsumerAccesslogCookie(
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
			if err := server.storeSyncConsumerAccesslogCookie(
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
	return complete, server.storeSyncConsumerAccesslogCookie(ctx, config, cookie)
}

func (server *Server) applySyncConsumerAccesslogEntry(
	ctx context.Context,
	config syncConsumerConfig,
	source *ldap.Entry,
	responseCookie []byte,
) error {
	runtime := server.runtime.Load()
	database := runtimeDatabaseForPartition(runtime, config.partition)
	operation, err := parseSyncConsumerAccesslogOperation(
		runtime,
		config,
		source,
	)
	if err != nil {
		return fmt.Errorf("parse accesslog entry: %w", err)
	}
	var syncChanges []*syncChange
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		syncChanges = nil
		alreadyApplied, err := syncConsumerAccesslogOperationApplied(
			writer,
			runtime,
			database,
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

		applied, err := prepareSyncConsumerAccesslogApplyResult(
			writer,
			config,
			operation,
		)
		if err != nil {
			return err
		}
		effectiveOperation := operation
		softDeletes := false
		if database != nil && database.multiProvider {
			if err := validateSyncConsumerDeltaOperation(runtime, operation, applied.before, source); err != nil {
				return err
			}
			if operation.kind == syncConsumerAccesslogAdd {
				for _, mod := range operation.modifications {
					if !constraintAttributeDescriptionsEqual(runtime.schema, mod.description, "entryUUID") || len(mod.values) != 1 {
						continue
					}
					identifier := string(mod.values[0])
					if _, deleted, err := syncTombstoneCSN(writer, database.partition, identifier); err != nil {
						return err
					} else if deleted {
						return fmt.Errorf("%w: writable delta add conflicts with a deleted UUID", errSyncConsumerAccesslogGap)
					}
					if _, found, err := syncConsumerEntryByUUID(syncConsumerReader(writer, database, config), database.partition, identifier); err != nil {
						return err
					} else if found {
						return fmt.Errorf("%w: writable delta add conflicts with an existing UUID", errSyncConsumerAccesslogGap)
					}
				}
			}
		}
		if operation.kind == syncConsumerAccesslogModify &&
			database != nil && database.multiProvider && applied.before != nil {
			effectiveOperation, softDeletes, err =
				resolveSyncConsumerDeltaMultiProviderModify(
					writer,
					runtime,
					*database,
					config,
					operation,
					*applied.before,
				)
			if err != nil {
				return err
			}
		}
		switch effectiveOperation.kind {
		case syncConsumerAccesslogAdd:
			err = applySyncConsumerAccesslogAdd(
				runtime,
				writer,
				config,
				effectiveOperation,
			)
		case syncConsumerAccesslogDelete:
			err = applySyncConsumerAccesslogDelete(
				writer,
				config,
				effectiveOperation,
			)
		case syncConsumerAccesslogModify:
			err = applySyncConsumerAccesslogModify(
				runtime,
				writer,
				config,
				effectiveOperation,
				softDeletes,
			)
		case syncConsumerAccesslogModifyDN:
			err = applySyncConsumerAccesslogModifyDN(
				runtime,
				writer,
				config,
				effectiveOperation,
			)
		default:
			err = errors.New("unknown accesslog operation")
		}
		if err != nil {
			return err
		}
		if err := completeSyncConsumerAccesslogApplyResult(
			writer,
			config,
			effectiveOperation,
			&applied,
		); err != nil {
			return err
		}
		if applied.applied && database != nil {
			sourceChange, changeErr := server.recordSyncChangeCSN(
				writer,
				runtime,
				*database,
				applied.before,
				applied.after,
				operation.csn,
			)
			if changeErr != nil {
				return changeErr
			}
			syncChanges = appendSyncChanges(syncChanges, sourceChange)

			logSourceChange := &syncChange{csn: operation.csn}
			logChanges, logErr := server.recordAccesslogWrite(
				ctx,
				writer,
				runtime,
				*database,
				syncConsumerAccesslogWriteRecord(operation, applied),
				logSourceChange,
			)
			if logErr != nil {
				return logErr
			}
			syncChanges = append(syncChanges, logChanges...)
		}
		return updateSyncConsumerCookie(writer, config, cookie)
	})
	if err != nil {
		return err
	}
	for _, change := range syncChanges {
		server.publishSyncChange(change)
	}
	return nil
}

func (server *Server) storeSyncConsumerAccesslogCookie(
	ctx context.Context,
	config syncConsumerConfig,
	cookie []byte,
) error {
	if len(cookie) == 0 {
		return nil
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		return updateSyncConsumerCookie(writer, config, cookie)
	})
}

func prepareSyncConsumerAccesslogApplyResult(
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) (syncConsumerAccesslogApplyResult, error) {
	content := syncConsumerWriter(writer, nil, config)
	searchBase, err := storage.NormalizeReaderDN(content, config.searchBase)
	if err != nil {
		return syncConsumerAccesslogApplyResult{}, err
	}
	oldInScope := directory.InScope(searchBase, operation.remoteDN, config.scope)
	result := syncConsumerAccesslogApplyResult{eligible: oldInScope}
	if operation.kind == syncConsumerAccesslogModifyDN {
		if operation.newRemoteDN == nil {
			return result, nil
		}
		newInScope := directory.InScope(
			searchBase,
			*operation.newRemoteDN,
			config.scope,
		)
		result.eligible = oldInScope || newInScope
		if newInScope {
			newDN, mapErr := mapSyncConsumerAccesslogDN(
				config,
				*operation.newRemoteDN,
			)
			if mapErr != nil {
				return syncConsumerAccesslogApplyResult{}, mapErr
			}
			result.newDN = &newDN
			result.afterDN = &newDN
		} else {
			newDN := *operation.newRemoteDN
			result.newDN = &newDN
		}
	}
	if !oldInScope {
		return result, nil
	}
	requestDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return syncConsumerAccesslogApplyResult{}, err
	}
	result.requestDN = requestDN
	before, found, err := syncConsumerAccesslogOptionalEntry(content, requestDN)
	if err != nil {
		return syncConsumerAccesslogApplyResult{}, err
	}
	if found {
		result.before = &before
	}
	return result, nil
}

func completeSyncConsumerAccesslogApplyResult(
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
	result *syncConsumerAccesslogApplyResult,
) error {
	if result == nil || !result.eligible {
		return nil
	}
	content := syncConsumerWriter(writer, nil, config)
	switch operation.kind {
	case syncConsumerAccesslogAdd:
		after, found, err := syncConsumerAccesslogOptionalEntry(
			content,
			result.requestDN,
		)
		if err != nil {
			return err
		}
		if found {
			result.after = &after
			result.applied = true
		}
	case syncConsumerAccesslogDelete:
		result.applied = result.before != nil
	case syncConsumerAccesslogModify:
		if result.before == nil {
			return nil
		}
		after, found, err := syncConsumerAccesslogOptionalEntry(
			content,
			result.requestDN,
		)
		if err != nil {
			return err
		}
		if found {
			result.after = &after
		}
		result.applied = true
	case syncConsumerAccesslogModifyDN:
		if result.before == nil {
			return nil
		}
		if result.afterDN != nil {
			after, found, err := syncConsumerAccesslogOptionalEntry(
				content,
				*result.afterDN,
			)
			if err != nil {
				return err
			}
			if found {
				result.after = &after
			}
		}
		result.applied = true
	}
	return nil
}

func syncConsumerAccesslogOptionalEntry(
	reader storage.Reader,
	dn directory.DN,
) (directory.Entry, bool, error) {
	entry, err := reader.Get(dn)
	switch {
	case err == nil:
		return entry.Clone(), true, nil
	case errors.Is(err, storage.ErrEntryNotFound):
		return directory.Entry{}, false, nil
	default:
		return directory.Entry{}, false, err
	}
}

func syncConsumerAccesslogWriteRecord(
	operation syncConsumerAccesslogOperation,
	applied syncConsumerAccesslogApplyResult,
) accesslogWriteRecord {
	record := accesslogWriteRecord{
		requestDN:     applied.requestDN,
		before:        applied.before,
		after:         applied.after,
		deleteOldRDN:  operation.deleteOldRDN,
		modifications: syncConsumerAccesslogLDAPModifications(operation.modifications),
	}
	if applied.before != nil && applied.after == nil {
		record.operation = accesslogDelete
		record.modifications = nil
		return record
	}
	switch operation.kind {
	case syncConsumerAccesslogAdd:
		record.operation = accesslogAdd
	case syncConsumerAccesslogDelete:
		record.operation = accesslogDelete
	case syncConsumerAccesslogModify:
		record.operation = accesslogModify
	case syncConsumerAccesslogModifyDN:
		record.operation = accesslogModifyDN
		record.newRDN = operation.newRDN
		if operation.hasNewSuperior && applied.newDN != nil {
			if newParent, ok := applied.newDN.Parent(); ok {
				record.newSuperior = &newParent
			}
		}
	}
	return record
}

func syncConsumerAccesslogLDAPModifications(
	modifications []syncConsumerAccesslogModification,
) []ldapwire.Modification {
	result := make([]ldapwire.Modification, 0, len(modifications))
	for _, modification := range modifications {
		var operation ldapwire.ModificationOperation
		switch modification.operation {
		case '+':
			operation = ldapwire.ModificationAdd
		case '-':
			operation = ldapwire.ModificationDelete
		case '=':
			operation = ldapwire.ModificationReplace
		case '#':
			operation = ldapwire.ModificationIncrement
		default:
			continue
		}
		values := make([][]byte, len(modification.values))
		for index := range modification.values {
			values[index] = bytes.Clone(modification.values[index])
		}
		result = append(result, ldapwire.Modification{
			Operation: operation,
			Attribute: directory.Attribute{
				Description: modification.description,
				Values:      values,
			},
		})
	}
	return result
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
	remoteDN, err := parseRuntimeDN(string(rawDN), config.normalizer)
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
		superior, err = parseRuntimeDN(string(rawSuperior), config.normalizer)
		if err != nil {
			return syncConsumerAccesslogOperation{}, err
		}
	}
	newRemoteDN, err := directory.ComposeDN(string(rawRDN), superior)
	if err != nil {
		return syncConsumerAccesslogOperation{}, err
	}
	newRemoteDN, err = parseRuntimeDN(newRemoteDN.String(), config.normalizer)
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
	operation.newRDN = string(rawRDN)
	operation.hasNewSuperior = rawSuperior != nil
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

func validateSyncConsumerDeltaOperation(
	runtime *runtimeState,
	operation syncConsumerAccesslogOperation,
	current *directory.Entry,
	source *ldap.Entry,
) error {
	if operation.kind == syncConsumerAccesslogModifyDN || operation.kind == syncConsumerAccesslogDelete {
		return fmt.Errorf("%w: writable delta delete/rename conflict resolution is not implemented", errSyncConsumerAccesslogGap)
	}
	if len(source.GetEqualFoldRawAttributeValues("reqControls")) != 0 {
		return fmt.Errorf("%w: writable delta request controls are not implemented", errSyncConsumerAccesslogGap)
	}
	if current != nil {
		uuids := current.Values("entryUUID")
		if uuid := source.GetEqualFoldAttributeValue("reqEntryUUID"); uuid != "" &&
			(len(uuids) != 1 || !strings.EqualFold(uuid, string(uuids[0]))) {
			return fmt.Errorf("%w: writable delta entryUUID mismatch", errSyncConsumerAccesslogGap)
		}
	}
	csnMods := 0
	uuidMods := 0
	for _, mod := range operation.modifications {
		if mod.operation == '#' || runtime.schema.HasOrderedValues(mod.description) {
			return fmt.Errorf("%w: writable delta increment/ordered-value merging is not implemented", errSyncConsumerAccesslogGap)
		}
		if constraintAttributeDescriptionsEqual(runtime.schema, mod.description, "entryCSN") {
			csnMods++
			if (mod.operation != '=' && mod.operation != '+') || len(mod.values) != 1 || string(mod.values[0]) != operation.csn.raw {
				return fmt.Errorf("%w: reqMod entryCSN does not match operation CSN", errSyncConsumerAccesslogGap)
			}
		}
		if constraintAttributeDescriptionsEqual(runtime.schema, mod.description, "entryUUID") {
			uuidMods++
			if operation.kind == syncConsumerAccesslogModify {
				return fmt.Errorf("%w: writable delta cannot modify entryUUID", errSyncConsumerAccesslogGap)
			}
			if (mod.operation != '+' && mod.operation != '=') || len(mod.values) != 1 || uuid.Validate(string(mod.values[0])) != nil {
				return fmt.Errorf("%w: invalid writable delta add entryUUID", errSyncConsumerAccesslogGap)
			}
		}
	}
	if csnMods != 1 {
		return fmt.Errorf("%w: writable delta requires exactly one entryCSN modification", errSyncConsumerAccesslogGap)
	}
	if operation.kind == syncConsumerAccesslogAdd && uuidMods != 1 {
		return fmt.Errorf("%w: writable delta add requires entryUUID", errSyncConsumerAccesslogGap)
	}
	return nil
}

func resolveSyncConsumerDeltaMultiProviderModify(
	writer storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
	current directory.Entry,
) (syncConsumerAccesslogOperation, bool, error) {
	values := current.Values("entryCSN")
	if len(values) != 1 {
		return operation, false, fmt.Errorf(
			"%w: %s has %d entryCSN values",
			errSyncConsumerAccesslogGap,
			current.DN,
			len(values),
		)
	}
	currentCSN, err := parseOpenLDAPCSN(string(values[0]))
	if err != nil {
		return operation, false, fmt.Errorf(
			"%w: parse current entryCSN for %s: %v",
			errSyncConsumerAccesslogGap,
			current.DN,
			err,
		)
	}
	if compareOpenLDAPCSN(operation.csn, currentCSN) == 0 {
		return operation, false, fmt.Errorf("%w: entryCSN already present without committed cookie", errSyncConsumerAccesslogGap)
	}
	if compareOpenLDAPCSN(operation.csn, currentCSN) > 0 {
		return operation, true, nil
	}

	resolved := operation
	resolved.modifications = duplicateOlderSyncConsumerAccesslogModifications(
		runtime,
		operation.modifications,
	)
	history, err := loadSyncConsumerDeltaMultiProviderHistory(
		writer,
		runtime,
		database,
		config,
		operation.csn,
		operation.remoteDN,
		currentCSN,
	)
	if err != nil {
		return operation, false, err
	}
	for _, newer := range history {
		resolved.modifications, err = resolveSyncConsumerDeltaMultiProviderMods(
			runtime,
			current,
			resolved.modifications,
			newer.modifications,
		)
		if err != nil {
			return operation, false, err
		}
	}
	return resolved, true, nil
}

func duplicateOlderSyncConsumerAccesslogModifications(
	runtime *runtimeState,
	modifications []syncConsumerAccesslogModification,
) []syncConsumerAccesslogModification {
	result := make([]syncConsumerAccesslogModification, 0, len(modifications)+1)
	for _, modification := range modifications {
		if runtime != nil && syncConsumerDeltaOperationalAttribute(
			runtime,
			modification.description,
		) {
			continue
		}
		if modification.operation == '=' {
			result = append(result, syncConsumerAccesslogModification{
				description: modification.description,
				operation:   '-',
			})
			if len(modification.values) == 0 {
				continue
			}
			modification.operation = '+'
		}
		modification.values = cloneSyncConsumerAccesslogValues(
			modification.values,
		)
		result = append(result, modification)
	}
	return result
}

func syncConsumerDeltaOperationalAttribute(
	runtime *runtimeState,
	description string,
) bool {
	for _, operational := range []string{
		"entryCSN",
		"modifiersName",
		"modifyTimestamp",
	} {
		if constraintAttributeDescriptionsEqual(
			runtime.schema,
			description,
			operational,
		) {
			return true
		}
	}
	return false
}

func syncConsumerDeltaHistoryFloorKey(partition string) string {
	return "openldap/sync/delta-history-floor/" + partition
}

func loadSyncConsumerDeltaMultiProviderHistory(
	writer storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	config syncConsumerConfig,
	incoming openLDAPCSN,
	remoteDN directory.DN,
	currentCSN openLDAPCSN,
) ([]syncConsumerAccesslogConflictHistory, error) {
	configuration := database.accesslog
	if configuration == nil ||
		configuration.targetDatabaseIndex < 0 ||
		configuration.targetDatabaseIndex >= len(runtime.databases) {
		return nil, fmt.Errorf(
			"%w: delta multi-provider database %s has no local accesslog",
			errSyncConsumerAccesslogGap,
			database.name,
		)
	}
	targetDN, err := mapSyncConsumerAccesslogDN(config, remoteDN)
	if err != nil {
		return nil, err
	}
	target := runtime.databases[configuration.targetDatabaseIndex]
	rawFloor, err := writer.Metadata(syncConsumerDeltaHistoryFloorKey(target.partition))
	if err != nil && !errors.Is(err, storage.ErrMetadataNotFound) {
		return nil, err
	}
	if len(rawFloor) != 0 {
		floor, err := parseOpenLDAPCSN(string(rawFloor))
		if err != nil || compareOpenLDAPCSN(floor, incoming) >= 0 {
			return nil, fmt.Errorf("%w: local accesslog conflict history was purged through %s", errSyncConsumerAccesslogGap, rawFloor)
		}
	}
	logReader := writerForDatabase(writer, target)
	container, err := logReader.Get(configuration.targetSuffix)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: read local accesslog container: %v",
			errSyncConsumerAccesslogGap,
			err,
		)
	}
	minimums := container.Values("minCSN")
	if len(minimums) == 0 {
		return nil, fmt.Errorf(
			"%w: local accesslog has no minCSN",
			errSyncConsumerAccesslogGap,
		)
	}
	// minCSN is either the first logged change for a SID, or its last
	// purged change. A retained row distinguishes those two cases.
	boundaries := make(map[string]bool)
	for _, raw := range minimums {
		minimum, parseErr := parseOpenLDAPCSN(string(raw))
		if parseErr != nil {
			return nil, fmt.Errorf(
				"%w: parse local accesslog minCSN %q: %v",
				errSyncConsumerAccesslogGap,
				raw,
				parseErr,
			)
		}
		if compareOpenLDAPCSN(minimum, incoming) >= 0 {
			boundaries[minimum.raw] = false
		}
	}

	localConfig := config
	localConfig.suffixMap = nil
	var history []syncConsumerAccesslogConflictHistory
	currentFound := false
	err = logReader.ForEach(func(entry directory.Entry) error {
		entryDN, parseErr := syncConsumerParseDN(logReader, entry.DN)
		if parseErr != nil {
			return parseErr
		}
		if !configuration.targetSuffix.AncestorOf(entryDN) {
			return nil
		}
		if values := entry.Values("entryCSN"); len(values) == 1 {
			if _, found := boundaries[string(values[0])]; found {
				boundaries[string(values[0])] = true
			}
		}
		rawDN := entry.Values("reqDN")
		if len(rawDN) == 0 {
			return nil
		}
		if len(rawDN) != 1 {
			return fmt.Errorf("accesslog entry %s has %d reqDN values", entry.DN, len(rawDN))
		}
		requestDN, parseErr := parseRuntimeDN(
			string(rawDN[0]),
			database.dnNormalizer,
		)
		if parseErr != nil {
			return fmt.Errorf("accesslog entry %s reqDN: %w", entry.DN, parseErr)
		}
		if !requestDN.Equal(targetDN) {
			return nil
		}
		matches, matchErr := config.logFilter.MatchWith(entry, runtime.schema)
		if matchErr != nil {
			return fmt.Errorf("match local accesslog entry %s: %w", entry.DN, matchErr)
		}
		if !matches {
			return nil
		}
		rawCSN := entry.Values("entryCSN")
		if len(rawCSN) != 1 {
			return fmt.Errorf("accesslog entry %s has %d entryCSN values", entry.DN, len(rawCSN))
		}
		csn, parseErr := parseOpenLDAPCSN(string(rawCSN[0]))
		if parseErr != nil {
			return fmt.Errorf("accesslog entry %s entryCSN: %w", entry.DN, parseErr)
		}
		if compareOpenLDAPCSN(csn, incoming) < 0 {
			return nil
		}
		requestTypes := entry.Values("reqType")
		if len(requestTypes) != 1 || !strings.EqualFold(string(requestTypes[0]), "modify") {
			return fmt.Errorf("non-modify history for %s at %s", entry.DN, csn.raw)
		}
		currentFound = currentFound || compareOpenLDAPCSN(csn, currentCSN) == 0
		modifications, parseErr := parseSyncConsumerAccesslogModifications(
			runtime,
			localConfig,
			entry.Values("reqMod"),
		)
		if parseErr != nil {
			return fmt.Errorf("accesslog entry %s reqMod: %w", entry.DN, parseErr)
		}
		if len(modifications) == 0 {
			return fmt.Errorf("accesslog entry %s has no modifications", entry.DN)
		}
		for _, mod := range modifications {
			if mod.operation == '#' || runtime.schema.HasOrderedValues(mod.description) {
				return fmt.Errorf("unsupported increment/ordered-value history at %s", entry.DN)
			}
		}
		if len(modifications) != 0 {
			history = append(history, syncConsumerAccesslogConflictHistory{
				csn:           csn,
				modifications: modifications,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: query local accesslog conflict history: %v",
			errSyncConsumerAccesslogGap,
			err,
		)
	}
	for boundary, retained := range boundaries {
		if !retained {
			return nil, fmt.Errorf("%w: local accesslog history is unavailable before %s", errSyncConsumerAccesslogGap, boundary)
		}
	}
	if !currentFound {
		return nil, fmt.Errorf("%w: current entryCSN %s is missing from local history", errSyncConsumerAccesslogGap, currentCSN.raw)
	}
	sort.Slice(history, func(left, right int) bool {
		return compareOpenLDAPCSN(history[left].csn, history[right].csn) < 0
	})
	return history, nil
}

func resolveSyncConsumerDeltaMultiProviderMods(
	runtime *runtimeState,
	current directory.Entry,
	older []syncConsumerAccesslogModification,
	newer []syncConsumerAccesslogModification,
) ([]syncConsumerAccesslogModification, error) {
	for _, committed := range newer {
		for index := 0; index < len(older); {
			candidate := &older[index]
			if !constraintAttributeDescriptionsEqual(
				runtime.schema,
				candidate.description,
				committed.description,
			) {
				index++
				continue
			}
			drop := false
			if committed.operation == '-' || committed.operation == '=' {
				if committed.operation == '=' || len(committed.values) == 0 {
					drop = true
				} else if candidate.operation == '-' && len(candidate.values) != 0 ||
					candidate.operation == '+' {
					var err error
					candidate.values, err = subtractSyncConsumerDeltaValues(
						runtime,
						candidate.description,
						candidate.values,
						committed.values,
					)
					if err != nil {
						return nil, err
					}
					drop = len(candidate.values) == 0
				}
			}
			if !drop && (committed.operation == '+' || committed.operation == '=') {
				singleValue, err := syncConsumerDeltaSingleValue(
					runtime,
					candidate.description,
				)
				if err != nil {
					return nil, err
				}
				if singleValue {
					drop = true
				} else {
					if candidate.operation == '-' && len(candidate.values) == 0 {
						candidate.values = syncConsumerDeltaCurrentValues(
							runtime,
							current,
							candidate.description,
						)
						if len(candidate.values) == 0 {
							drop = true
						}
					}
					if !drop {
						candidate.values, err = subtractSyncConsumerDeltaValues(
							runtime,
							candidate.description,
							candidate.values,
							committed.values,
						)
						if err != nil {
							return nil, err
						}
						drop = len(candidate.values) == 0
					}
				}
			}
			if drop {
				older = append(older[:index], older[index+1:]...)
				continue
			}
			index++
		}
	}
	return older, nil
}

func subtractSyncConsumerDeltaValues(
	runtime *runtimeState,
	description string,
	values,
	committed [][]byte,
) ([][]byte, error) {
	remaining := make([][]byte, 0, len(values))
	for _, value := range values {
		matched := false
		for _, newer := range committed {
			equal, err := schemaAttributeValuesEqual(
				runtime.schema,
				description,
				value,
				newer,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"compare delta conflict value for %s: %w",
					description,
					err,
				)
			}
			if equal {
				matched = true
				break
			}
		}
		if !matched {
			remaining = append(remaining, bytes.Clone(value))
		}
	}
	return remaining, nil
}

func syncConsumerDeltaSingleValue(
	runtime *runtimeState,
	description string,
) (bool, error) {
	attribute, found, err := runtime.schema.EffectiveAttributeType(description)
	if err != nil {
		return false, err
	}
	if !found {
		return false, fmt.Errorf("unknown delta conflict attribute %q", description)
	}
	return attribute.SingleValue, nil
}

func syncConsumerDeltaCurrentValues(
	runtime *runtimeState,
	entry directory.Entry,
	description string,
) [][]byte {
	var result [][]byte
	for _, attribute := range entry.Attributes {
		if constraintAttributeDescriptionsEqual(
			runtime.schema,
			attribute.Description,
			description,
		) {
			result = append(
				result,
				cloneSyncConsumerAccesslogValues(attribute.Values)...,
			)
		}
	}
	return result
}

func cloneSyncConsumerAccesslogValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func applySyncConsumerAccesslogAdd(
	runtime *runtimeState,
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) error {
	content := syncConsumerWriter(writer, nil, config)
	searchBase, err := storage.NormalizeReaderDN(content, config.searchBase)
	if err != nil {
		return err
	}
	if !directory.InScope(searchBase, operation.remoteDN, config.scope) {
		return nil
	}
	targetDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return err
	}
	if _, err := content.Get(targetDN); err == nil {
		return storage.ErrEntryExists
	} else if !errors.Is(err, storage.ErrEntryNotFound) {
		return err
	}
	localBase, err := storage.NormalizeReaderDN(content, config.localBase)
	if err != nil {
		return err
	}
	if !targetDN.Equal(localBase) {
		parent, ok := targetDN.Parent()
		if !ok {
			return errors.New("accesslog add has no parent")
		}
		if _, err := content.Get(parent); err != nil {
			return fmt.Errorf("accesslog add parent %s: %w", parent.String(), err)
		}
	}
	entry := directory.Entry{DN: targetDN.String()}
	if err := applySyncConsumerAccesslogModifications(
		runtime,
		&entry,
		operation.modifications,
		false,
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
	return content.Put(entry, false)
}

func applySyncConsumerAccesslogDelete(
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) error {
	content := syncConsumerWriter(writer, nil, config)
	searchBase, err := storage.NormalizeReaderDN(content, config.searchBase)
	if err != nil {
		return err
	}
	if !directory.InScope(searchBase, operation.remoteDN, config.scope) {
		return nil
	}
	targetDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return err
	}
	if _, err := content.Get(targetDN); err != nil {
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		return err
	}
	hasChild := false
	if err := content.ForEach(
		func(entry directory.Entry) error {
			candidate, err := syncConsumerParseDN(content, entry.DN)
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
	return content.Delete(targetDN)
}

func applySyncConsumerAccesslogModify(
	runtime *runtimeState,
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
	softDeletes bool,
) error {
	content := syncConsumerWriter(writer, nil, config)
	searchBase, err := storage.NormalizeReaderDN(content, config.searchBase)
	if err != nil {
		return err
	}
	if !directory.InScope(searchBase, operation.remoteDN, config.scope) {
		return nil
	}
	targetDN, err := mapSyncConsumerAccesslogDN(config, operation.remoteDN)
	if err != nil {
		return err
	}
	entry, err := content.Get(targetDN)
	if err != nil {
		return err
	}
	if err := applySyncConsumerAccesslogModifications(
		runtime,
		&entry,
		operation.modifications,
		softDeletes,
	); err != nil {
		return err
	}
	matches, err := syncConsumerAccesslogEntryMatches(runtime, config, entry)
	if err != nil {
		return err
	}
	if !matches {
		return content.Delete(targetDN)
	}
	if config.schemaChecking && runtime != nil {
		if err := runtime.schema.ValidateEntry(entry); err != nil {
			return fmt.Errorf("validate accesslog modify %s: %w", entry.DN, err)
		}
	}
	return content.Put(entry, true)
}

func applySyncConsumerAccesslogModifyDN(
	runtime *runtimeState,
	writer storage.Writer,
	config syncConsumerConfig,
	operation syncConsumerAccesslogOperation,
) error {
	content := syncConsumerWriter(writer, nil, config)
	if operation.newRemoteDN == nil {
		return errors.New("accesslog modrdn has no destination DN")
	}
	searchBase, err := storage.NormalizeReaderDN(content, config.searchBase)
	if err != nil {
		return err
	}
	oldInScope := directory.InScope(
		searchBase,
		operation.remoteDN,
		config.scope,
	)
	newInScope := directory.InScope(
		searchBase,
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
		return deleteSyncConsumerAccesslogSubtree(content, oldDN)
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
	if err := content.ForEach(
		func(entry directory.Entry) error {
			candidate, err := syncConsumerParseDN(content, entry.DN)
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
		if _, err := content.Get(item.newDN); err == nil {
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
			false,
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
		if err := content.Delete(item.oldDN); err != nil {
			return err
		}
	}
	sort.Slice(moves, func(i, j int) bool {
		return moves[i].newDN.Depth() < moves[j].newDN.Depth()
	})
	for _, item := range moves {
		if err := putRenamedSyncConsumerEntry(writer, content, config, item.entry, item.oldDN.Equal(oldDN)); err != nil {
			return err
		}
	}
	return nil
}

func applySyncConsumerAccesslogModifications(
	runtime *runtimeState,
	entry *directory.Entry,
	modifications []syncConsumerAccesslogModification,
	softDeletes bool,
) error {
	for _, modification := range modifications {
		if softDeletes && runtime != nil {
			changes := syncConsumerAccesslogLDAPModifications([]syncConsumerAccesslogModification{modification})
			if len(changes) != 1 {
				return fmt.Errorf("unknown modification operation %q", modification.operation)
			}
			change := changes[0]
			singleValue, err := syncConsumerDeltaSingleValue(runtime, modification.description)
			if err != nil {
				return err
			}
			if singleValue && change.Operation == ldapwire.ModificationAdd {
				change.Operation = ldapwire.ModificationReplace
			}
			if err := applyModificationWithPermissive(entry, change, change.Operation == ldapwire.ModificationDelete, runtime.schema); err != nil {
				return err
			}
			continue
		}
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
			if (softDeletes || singleValue) &&
				errors.Is(err, directory.ErrNoSuchAttribute) {
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
	base directory.DN,
) error {
	var dns []directory.DN
	if err := writer.ForEach(
		func(entry directory.Entry) error {
			candidate, err := syncConsumerParseDN(writer, entry.DN)
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
		if err := writer.Delete(dn); err != nil {
			return err
		}
	}
	return nil
}

func syncConsumerAccesslogOperationApplied(
	reader storage.Reader,
	runtime *runtimeState,
	database *runtimeDatabase,
	config syncConsumerConfig,
	csn openLDAPCSN,
) (bool, error) {
	raw, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
	switch {
	case err == nil:
		current, found := parseOpenLDAPSyncCookie(raw).csns[csn.serverID]
		if found && compareOpenLDAPCSN(current, csn) >= 0 {
			return true, nil
		}
	case errors.Is(err, storage.ErrMetadataNotFound):
	default:
		return false, err
	}
	if database == nil {
		return false, nil
	}
	provider := effectiveSyncProviderDatabase(runtime, *database)
	if provider == nil {
		return false, nil
	}
	state, err := syncContextCSNs(reader, provider.partition)
	if err != nil {
		return false, err
	}
	current, found := state[csn.serverID]
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
		for _, key := range []string{
			syncConsumerCookieMetadataKey(config),
			syncConsumerAccesslogBootstrapMetadataKey(config),
		} {
			if err := deleteSyncConsumerMetadata(writer, key); err != nil {
				return err
			}
		}
		return nil
	})
}
