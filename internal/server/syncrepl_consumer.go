package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncConsumerCookieMetadataPrefix = "openldap/syncrepl/cookie/"
	syncConsumerProxyAuthzOID        = "2.16.840.1.113730.3.4.18"
	syncConsumerResponseBuffer       = 64
)

type syncConsumerRefreshState struct {
	seen     map[string]struct{}
	complete bool
}

type syncConsumerRefreshWatchdog struct {
	timeout  time.Duration
	cancel   context.CancelFunc
	timer    *time.Timer
	finished atomic.Bool
	timedOut atomic.Bool
}

type syncConsumerRetryCursor struct {
	policy []syncConsumerRetry
	index  int
	used   int
}

func startSyncConsumerRefreshWatchdog(
	parent context.Context,
	mode syncConsumerMode,
	timeout time.Duration,
) (context.Context, *syncConsumerRefreshWatchdog) {
	if mode != syncConsumerRefreshAndPersist || timeout <= 0 {
		return parent, nil
	}
	ctx, cancel := context.WithCancel(parent)
	watchdog := &syncConsumerRefreshWatchdog{
		timeout: timeout,
		cancel:  cancel,
	}
	watchdog.timer = time.AfterFunc(timeout, func() {
		if watchdog.finished.CompareAndSwap(false, true) {
			watchdog.timedOut.Store(true)
			cancel()
		}
	})
	return ctx, watchdog
}

func (watchdog *syncConsumerRefreshWatchdog) markComplete() {
	if watchdog == nil {
		return
	}
	if watchdog.finished.CompareAndSwap(false, true) {
		watchdog.timer.Stop()
	}
}

func (watchdog *syncConsumerRefreshWatchdog) stop() {
	if watchdog == nil {
		return
	}
	watchdog.finished.Store(true)
	watchdog.timer.Stop()
	watchdog.cancel()
}

func (watchdog *syncConsumerRefreshWatchdog) timeoutError() error {
	if watchdog == nil || !watchdog.timedOut.Load() {
		return nil
	}
	return fmt.Errorf(
		"syncrepl refresh timed out after %s",
		watchdog.timeout,
	)
}

func (server *Server) runSyncConsumer(
	ctx context.Context,
	config syncConsumerConfig,
) {
	retry := syncConsumerRetryCursor{policy: config.retry}
	providerIndex := 0
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		provider := config.providerURLs[providerIndex%len(config.providerURLs)]
		providerIndex++
		err := server.runSyncConsumerCycle(ctx, config, provider)
		if ctx.Err() != nil {
			return
		}
		if err == nil && config.mode == syncConsumerRefreshOnly {
			retry = syncConsumerRetryCursor{policy: config.retry}
			if !waitSyncConsumer(ctx, config.interval) {
				return
			}
			continue
		}
		if err == nil {
			err = errors.New("refreshAndPersist stream ended")
		}

		delay, retryable := retry.next()
		if !retryable {
			server.config.Logger.Error(
				"syncrepl consumer stopped after retry policy was exhausted",
				"rid",
				fmt.Sprintf("%03d", config.rid),
				"provider",
				provider,
				"error",
				err,
			)
			return
		}
		server.config.Logger.Debug(
			"syncrepl consumer will retry",
			"rid",
			fmt.Sprintf("%03d", config.rid),
			"provider",
			provider,
			"delay",
			delay,
			"error",
			err,
		)
		if !waitSyncConsumer(ctx, delay) {
			return
		}
	}
}

func (server *Server) runSyncConsumerCycle(
	ctx context.Context,
	config syncConsumerConfig,
	provider string,
) error {
	cookie, err := server.loadSyncConsumerCookie(ctx, config)
	if err != nil {
		return err
	}
	transport, err := dialSyncConsumer(ctx, config, provider)
	if err != nil {
		return err
	}
	var connection *ldap.Conn
	defer func() {
		if connection != nil {
			_ = connection.Close()
			return
		}
		_ = transport.close()
	}()

	stopClose := make(chan struct{})
	go func(active *syncConsumerTransport) {
		select {
		case <-ctx.Done():
			_ = active.close()
		case <-stopClose:
		}
	}(transport)
	defer close(stopClose)

	if config.startTLS != syncConsumerStartTLSOff {
		parsed, parseErr := parseSyncConsumerProviderURL(provider)
		if parseErr != nil {
			return parseErr
		}
		if strings.EqualFold(parsed.Scheme, "ldaps") ||
			strings.EqualFold(parsed.Scheme, "ldap+tlcp") {
			return errors.New(
				"starttls cannot be combined with an implicit secure provider",
			)
		}
		if startErr := performSyncConsumerStartTLS(
			transport,
			config,
			parsed,
		); startErr != nil {
			var resultError *ldap.Error
			if config.startTLS == syncConsumerStartTLSCritical ||
				!errors.As(startErr, &resultError) {
				return fmt.Errorf("start TLS: %w", startErr)
			}
			server.config.Logger.Warn(
				"syncrepl StartTLS was rejected; continuing without TLS",
				"rid",
				fmt.Sprintf("%03d", config.rid),
				"provider",
				provider,
				"error",
				startErr,
			)
		}
	}

	rawSASL := config.bindMethod == "sasl" &&
		!strings.EqualFold(config.saslMechanism, "GSSAPI")
	if rawSASL {
		if err := bindSyncConsumerSASL(transport, config, provider); err != nil {
			return err
		}
	}
	if err := transport.clearDeadline(); err != nil {
		return fmt.Errorf("clear syncrepl connection deadline: %w", err)
	}
	connection = ldap.NewConn(&syncConsumerResponseConn{
		Conn: transport.currentConnection(),
	}, transport.secure)
	connection.Start()
	if config.operationTimeout > 0 {
		connection.SetTimeout(config.operationTimeout)
	}
	if !rawSASL {
		if err := bindSyncConsumer(
			connection,
			config,
			provider,
			transport.ssf,
		); err != nil {
			return err
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	switch config.syncData {
	case "default":
		return server.runSyncConsumerStandardSearch(
			ctx,
			connection,
			config,
			config.mode,
			cookie,
		)
	case "accesslog":
		if len(cookie) == 0 {
			if err := server.runSyncConsumerStandardSearch(
				ctx,
				connection,
				config,
				syncConsumerRefreshOnly,
				nil,
			); err != nil {
				return fmt.Errorf("accesslog fallback refresh: %w", err)
			}
			cookie, err = server.loadSyncConsumerCookie(ctx, config)
			if err != nil {
				return err
			}
			if len(cookie) == 0 {
				return errors.New(
					"accesslog fallback refresh produced no sync cookie",
				)
			}
		}
		return server.runSyncConsumerAccesslogSearch(
			ctx,
			connection,
			config,
			config.mode,
			cookie,
		)
	case "changelog":
		return server.runSyncConsumerChangelog(
			ctx,
			connection,
			config,
			config.mode,
		)
	default:
		return fmt.Errorf("unknown syncdata mode %q", config.syncData)
	}
}

func (server *Server) runSyncConsumerStandardSearch(
	ctx context.Context,
	connection *ldap.Conn,
	config syncConsumerConfig,
	consumerMode syncConsumerMode,
	cookie []byte,
) error {
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
		config.searchBase.String(),
		int(config.scope),
		ldap.NeverDerefAliases,
		config.sizeLimit,
		config.timeLimit,
		config.attributesOnly,
		config.filterText,
		syncConsumerRequestedAttributes(config),
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
		true,
	)
	refresh := syncConsumerRefreshState{seen: make(map[string]struct{})}
	for response.Next() {
		if err := server.processSyncConsumerResponse(
			searchContext,
			config,
			&refresh,
			response.Entry(),
			response.Controls(),
		); err != nil {
			return err
		}
		if refresh.complete {
			watchdog.markComplete()
		}
	}
	if err := watchdog.timeoutError(); err != nil {
		return err
	}
	if err := response.Err(); err != nil {
		return fmt.Errorf("syncrepl search: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := connection.GetLastError(); err != nil {
		return fmt.Errorf("syncrepl connection: %w", err)
	}
	if consumerMode == syncConsumerRefreshOnly && !refresh.complete {
		return errors.New("syncrepl refresh ended without Sync Done")
	}
	return nil
}

func (server *Server) processSyncConsumerResponse(
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
		if err := server.applySyncConsumerEntry(
			ctx,
			config,
			entry,
			state,
		); err != nil {
			return err
		}
		if state.State != ldap.SyncStateDelete {
			refresh.seen[state.EntryUUID.String()] = struct{}{}
		}
	}

	for _, control := range controls {
		switch typed := control.(type) {
		case *ldap.ControlSyncState:
			if entry == nil {
				return errors.New("Sync State control has no search entry")
			}
		case *ldap.ControlSyncDone:
			if err := server.finishSyncConsumerRefresh(
				ctx,
				config,
				refresh,
				typed.RefreshDeletes,
				typed.Cookie,
			); err != nil {
				return err
			}
		case *ldap.ControlSyncInfo:
			if err := server.processSyncConsumerInfo(
				ctx,
				config,
				refresh,
				typed,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func syncConsumerStateControl(
	controls []ldap.Control,
) (*ldap.ControlSyncState, error) {
	var state *ldap.ControlSyncState
	for _, control := range controls {
		typed, ok := control.(*ldap.ControlSyncState)
		if !ok {
			continue
		}
		if state != nil {
			return nil, errors.New("search entry has multiple Sync State controls")
		}
		state = typed
	}
	if state == nil {
		return nil, errors.New("syncrepl search entry has no Sync State control")
	}
	switch state.State {
	case ldap.SyncStatePresent,
		ldap.SyncStateAdd,
		ldap.SyncStateModify,
		ldap.SyncStateDelete:
	default:
		return nil, fmt.Errorf("unknown Sync State value %d", state.State)
	}
	return state, nil
}

func (server *Server) processSyncConsumerInfo(
	ctx context.Context,
	config syncConsumerConfig,
	refresh *syncConsumerRefreshState,
	info *ldap.ControlSyncInfo,
) error {
	switch info.Value {
	case ldap.SyncInfoNewcookie:
		if info.NewCookie == nil {
			return errors.New("newCookie Sync Info has no value")
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.NewCookie.Cookie,
		)
	case ldap.SyncInfoRefreshDelete:
		if info.RefreshDelete == nil {
			return errors.New("refreshDelete Sync Info has no value")
		}
		if info.RefreshDelete.RefreshDone {
			return server.finishSyncConsumerRefresh(
				ctx,
				config,
				refresh,
				true,
				info.RefreshDelete.Cookie,
			)
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.RefreshDelete.Cookie,
		)
	case ldap.SyncInfoRefreshPresent:
		if info.RefreshPresent == nil {
			return errors.New("refreshPresent Sync Info has no value")
		}
		if info.RefreshPresent.RefreshDone {
			return server.finishSyncConsumerRefresh(
				ctx,
				config,
				refresh,
				false,
				info.RefreshPresent.Cookie,
			)
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.RefreshPresent.Cookie,
		)
	case ldap.SyncInfoSyncIdSet:
		if info.SyncIdSet == nil {
			return errors.New("syncIdSet Sync Info has no value")
		}
		if info.SyncIdSet.RefreshDeletes {
			identifiers := make([]string, 0, len(info.SyncIdSet.SyncUUIDs))
			for _, identifier := range info.SyncIdSet.SyncUUIDs {
				identifiers = append(identifiers, identifier.String())
			}
			return server.deleteSyncConsumerUUIDs(
				ctx,
				config,
				identifiers,
				info.SyncIdSet.Cookie,
			)
		}
		for _, identifier := range info.SyncIdSet.SyncUUIDs {
			refresh.seen[identifier.String()] = struct{}{}
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.SyncIdSet.Cookie,
		)
	default:
		return fmt.Errorf("unknown Sync Info value %d", info.Value)
	}
}

func (server *Server) applySyncConsumerEntry(
	ctx context.Context,
	config syncConsumerConfig,
	source *ldap.Entry,
	state *ldap.ControlSyncState,
) error {
	if state.State == ldap.SyncStateDelete {
		return server.deleteSyncConsumerUUIDs(
			ctx,
			config,
			[]string{state.EntryUUID.String()},
			state.Cookie,
		)
	}

	runtime := server.runtime.Load()
	database := runtimeDatabaseForPartition(runtime, config.partition)
	entry, err := syncConsumerDirectoryEntry(runtime, config, source, state)
	if err != nil {
		return err
	}
	if database != nil && database.dnNormalizer != nil {
		targetDN, err := parseRuntimeDN(entry.DN, database.dnNormalizer)
		if err != nil {
			return err
		}
		entry.DN = targetDN.String()
	}
	incomingCSN, hasIncomingCSN, err := syncConsumerEntryCSN(entry)
	if err != nil {
		return err
	}
	if database != nil && database.multiProvider && !hasIncomingCSN {
		return fmt.Errorf(
			"replicated entry %s has no single-valued entryCSN",
			entry.DN,
		)
	}

	var changes []syncChange
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		content := syncConsumerWriter(writer, database, config)
		cookieAdvances, err := syncConsumerCookieAdvances(
			writer,
			config,
			state.Cookie,
		)
		if err != nil {
			return err
		}
		if hasIncomingCSN {
			tombstone, exists, err := syncTombstoneCSN(
				writer,
				config.partition,
				state.EntryUUID.String(),
			)
			if err != nil {
				return err
			}
			if exists &&
				compareOpenLDAPCSN(incomingCSN, tombstone) <= 0 {
				if err := updateSyncConsumerCookie(
					writer,
					config,
					state.Cookie,
				); err != nil {
					return err
				}
				return server.recordSyncConsumerContextChanges(
					writer,
					runtime,
					database,
					cookieAdvances,
					nil,
					&changes,
				)
			}
		}
		existing, found, findErr := syncConsumerEntryByUUID(
			content,
			config.partition,
			state.EntryUUID.String(),
		)
		if findErr != nil {
			return findErr
		}
		nextDN, parseErr := syncConsumerParseDN(content, entry.DN)
		if parseErr != nil {
			return parseErr
		}
		target, targetErr := content.Get(nextDN)
		targetFound := targetErr == nil
		if targetErr != nil && !errors.Is(targetErr, storage.ErrEntryNotFound) {
			return targetErr
		}

		current := directory.Entry{}
		currentFound := false
		if found {
			current = existing
			currentFound = true
		}
		if targetFound &&
			(!found || !syncConsumerEntriesHaveSameUUID(existing, target)) {
			if !currentFound ||
				syncConsumerEntryIsNewer(target, current) {
				current = target
				currentFound = true
			}
		}
		if currentFound && hasIncomingCSN {
			currentCSN, hasCurrentCSN, csnErr := syncConsumerEntryCSN(current)
			if csnErr != nil {
				return csnErr
			}
			if hasCurrentCSN &&
				compareOpenLDAPCSN(incomingCSN, currentCSN) <= 0 {
				if err := updateSyncConsumerCookie(
					writer,
					config,
					state.Cookie,
				); err != nil {
					return err
				}
				return server.recordSyncConsumerContextChanges(
					writer,
					runtime,
					database,
					cookieAdvances,
					nil,
					&changes,
				)
			}
		}

		var before *directory.Entry
		if currentFound {
			cloned := current.Clone()
			before = &cloned
		}
		if found {
			existingDN, parseErr := syncConsumerParseDN(content, existing.DN)
			if parseErr != nil {
				return parseErr
			}
			if !existingDN.Equal(nextDN) {
				if deleteErr := content.Delete(existingDN); deleteErr != nil {
					return deleteErr
				}
			}
		}
		if err := content.Put(entry, true); err != nil {
			return err
		}
		if hasIncomingCSN {
			if err := clearSyncTombstoneBefore(
				writer,
				config.partition,
				state.EntryUUID.String(),
				incomingCSN,
			); err != nil {
				return err
			}
		}
		if err := updateSyncConsumerCookie(writer, config, state.Cookie); err != nil {
			return err
		}
		if database != nil && hasIncomingCSN {
			change, changeErr := server.recordSyncChangeCSN(
				writer,
				runtime,
				*database,
				before,
				&entry,
				incomingCSN,
			)
			if changeErr != nil {
				return changeErr
			}
			if change != nil {
				changes = append(changes, *change)
			}
		}
		var visibleCSN *openLDAPCSN
		if hasIncomingCSN {
			visibleCSN = &incomingCSN
		}
		return server.recordSyncConsumerContextChanges(
			writer,
			runtime,
			database,
			cookieAdvances,
			visibleCSN,
			&changes,
		)
	})
	if err == nil {
		for index := range changes {
			server.publishSyncChange(&changes[index])
		}
	}
	return err
}

func syncConsumerCookieAdvances(
	reader storage.Reader,
	config syncConsumerConfig,
	cookie []byte,
) ([]openLDAPCSN, error) {
	if len(cookie) == 0 {
		return nil, nil
	}
	current := make(syncCSNState)
	rawCurrent, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
	switch {
	case err == nil:
		current = parseOpenLDAPSyncCookie(rawCurrent).csns
	case errors.Is(err, storage.ErrMetadataNotFound):
	default:
		return nil, err
	}
	var advances []openLDAPCSN
	for serverID, candidate := range parseOpenLDAPSyncCookie(cookie).csns {
		known, exists := current[serverID]
		if !exists || compareOpenLDAPCSN(candidate, known) > 0 {
			advances = append(advances, candidate)
		}
	}
	sort.Slice(advances, func(i, j int) bool {
		return compareOpenLDAPCSN(advances[i], advances[j]) < 0
	})
	return advances, nil
}

func (server *Server) recordSyncConsumerContextChanges(
	writer storage.Writer,
	runtime *runtimeState,
	database *runtimeDatabase,
	csns []openLDAPCSN,
	visibleCSN *openLDAPCSN,
	changes *[]syncChange,
) error {
	if database == nil {
		return nil
	}
	for _, csn := range csns {
		if visibleCSN != nil && compareOpenLDAPCSN(csn, *visibleCSN) == 0 {
			continue
		}
		change, err := server.recordSyncChangeCSN(
			writer,
			runtime,
			*database,
			nil,
			nil,
			csn,
		)
		if err != nil {
			return err
		}
		if change != nil {
			*changes = append(*changes, *change)
		}
	}
	return nil
}

func syncConsumerEntryCSN(
	entry directory.Entry,
) (openLDAPCSN, bool, error) {
	values := entry.Values("entryCSN")
	if len(values) == 0 {
		return openLDAPCSN{}, false, nil
	}
	if len(values) != 1 {
		return openLDAPCSN{}, false, fmt.Errorf(
			"%s has multiple entryCSN values",
			entry.DN,
		)
	}
	csn, err := parseOpenLDAPCSN(string(values[0]))
	if err != nil {
		return openLDAPCSN{}, false, fmt.Errorf(
			"%s entryCSN: %w",
			entry.DN,
			err,
		)
	}
	return csn, true, nil
}

func syncConsumerEntriesHaveSameUUID(
	left,
	right directory.Entry,
) bool {
	leftValues := left.Values("entryUUID")
	rightValues := right.Values("entryUUID")
	return len(leftValues) == 1 &&
		len(rightValues) == 1 &&
		strings.EqualFold(string(leftValues[0]), string(rightValues[0]))
}

func syncConsumerEntryIsNewer(left, right directory.Entry) bool {
	leftCSN, leftFound, leftErr := syncConsumerEntryCSN(left)
	rightCSN, rightFound, rightErr := syncConsumerEntryCSN(right)
	switch {
	case leftErr != nil || !leftFound:
		return false
	case rightErr != nil || !rightFound:
		return true
	default:
		return compareOpenLDAPCSN(leftCSN, rightCSN) > 0
	}
}

func syncConsumerDirectoryEntry(
	runtime *runtimeState,
	config syncConsumerConfig,
	source *ldap.Entry,
	state *ldap.ControlSyncState,
) (directory.Entry, error) {
	if source == nil {
		return directory.Entry{}, errors.New("syncrepl entry is nil")
	}
	targetDN, err := mapSyncConsumerDN(config, source.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	entry := directory.Entry{DN: targetDN.String()}
	for _, attribute := range source.Attributes {
		if syncConsumerAttributeExcluded(runtime, config, attribute.Name) {
			continue
		}
		values := make([][]byte, len(attribute.ByteValues))
		for index := range attribute.ByteValues {
			values[index] = bytes.Clone(attribute.ByteValues[index])
			if config.suffixMap != nil &&
				runtime != nil &&
				runtime.schema.IsDNValued(attribute.Name) {
				mapped, mapErr := mapSyncConsumerAttributeDN(
					config,
					values[index],
				)
				if mapErr != nil {
					return directory.Entry{}, fmt.Errorf(
						"map %s on %s: %w",
						attribute.Name,
						source.DN,
						mapErr,
					)
				}
				values[index] = mapped
			}
		}
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: attribute.Name,
			Values:      values,
		})
	}

	identifier := state.EntryUUID.String()
	entryUUIDValues := entry.Values("entryUUID")
	switch len(entryUUIDValues) {
	case 0:
		entry.ReplaceValues("entryUUID", [][]byte{[]byte(identifier)})
	case 1:
		parsed, parseErr := uuid.Parse(string(entryUUIDValues[0]))
		if parseErr != nil || parsed != state.EntryUUID {
			return directory.Entry{}, fmt.Errorf(
				"%s entryUUID does not match Sync State UUID %s",
				source.DN,
				identifier,
			)
		}
	default:
		return directory.Entry{}, fmt.Errorf(
			"%s has multiple entryUUID values",
			source.DN,
		)
	}
	if config.schemaChecking && runtime != nil {
		if err := runtime.schema.ValidateEntry(entry); err != nil {
			return directory.Entry{}, fmt.Errorf(
				"validate replicated entry %s: %w",
				entry.DN,
				err,
			)
		}
	}
	return entry, nil
}

func syncConsumerAttributeExcluded(
	runtime *runtimeState,
	config syncConsumerConfig,
	description string,
) bool {
	for _, excluded := range config.exAttributes {
		if runtime != nil &&
			runtime.schema.AttributeDescriptionSubtype(description, excluded) {
			return true
		}
		if strings.EqualFold(description, excluded) {
			return true
		}
	}
	return false
}

func mapSyncConsumerDN(
	config syncConsumerConfig,
	rawDN string,
) (directory.DN, error) {
	remote, err := parseRuntimeDN(rawDN, config.normalizer)
	if err != nil {
		return directory.DN{}, err
	}
	if !directory.InScope(config.searchBase, remote, config.scope) {
		return directory.DN{}, fmt.Errorf(
			"provider returned %q outside the configured replication scope",
			rawDN,
		)
	}
	if config.suffixMap == nil {
		return remote, nil
	}
	local, err := remote.ReplaceAncestor(config.searchBase, config.localBase)
	if err != nil {
		return directory.DN{}, fmt.Errorf("apply suffixmassage: %w", err)
	}
	return local, nil
}

func mapSyncConsumerAttributeDN(
	config syncConsumerConfig,
	value []byte,
) ([]byte, error) {
	remote, err := parseRuntimeDN(string(value), config.normalizer)
	if err != nil {
		return nil, err
	}
	if !config.searchBase.Equal(remote) &&
		!config.searchBase.AncestorOf(remote) {
		return bytes.Clone(value), nil
	}
	local, err := remote.ReplaceAncestor(config.searchBase, config.localBase)
	if err != nil {
		return nil, err
	}
	return []byte(local.String()), nil
}

func (server *Server) deleteSyncConsumerUUIDs(
	ctx context.Context,
	config syncConsumerConfig,
	identifiers []string,
	cookie []byte,
) error {
	wanted := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		wanted[strings.ToLower(identifier)] = struct{}{}
	}
	runtime := server.runtime.Load()
	database := runtimeDatabaseForPartition(runtime, config.partition)
	var changes []syncChange
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		content := syncConsumerWriter(writer, database, config)
		cookieAdvances, err := syncConsumerCookieAdvances(
			writer,
			config,
			cookie,
		)
		if err != nil {
			return err
		}
		parsedCookie := parseOpenLDAPSyncCookie(cookie)
		var deletionCSN *openLDAPCSN
		if parsedCookie.hasDeletion {
			candidate := parsedCookie.deletionCSN
			deletionCSN = &candidate
		} else if len(cookieAdvances) > 0 {
			candidate := cookieAdvances[len(cookieAdvances)-1]
			deletionCSN = &candidate
		} else if len(cookie) > 0 {
			return updateSyncConsumerCookie(writer, config, cookie)
		}

		type deletion struct {
			dn    directory.DN
			entry directory.Entry
		}
		var deletions []deletion
		if err := content.ForEach(
			func(entry directory.Entry) error {
				values := entry.Values("entryUUID")
				if len(values) != 1 {
					return nil
				}
				if _, found := wanted[strings.ToLower(string(values[0]))]; !found {
					return nil
				}
				dn, err := syncConsumerParseDN(content, entry.DN)
				if err != nil {
					return err
				}
				if deletionCSN != nil {
					entryCSN, found, err := syncConsumerEntryCSN(entry)
					if err != nil {
						return err
					}
					if found &&
						compareOpenLDAPCSN(entryCSN, *deletionCSN) > 0 {
						return nil
					}
				}
				deletions = append(deletions, deletion{
					dn:    dn,
					entry: entry,
				})
				return nil
			},
		); err != nil {
			return err
		}
		for _, item := range deletions {
			if err := content.Delete(item.dn); err != nil {
				return err
			}
		}
		if err := updateSyncConsumerCookie(writer, config, cookie); err != nil {
			return err
		}
		if deletionCSN != nil {
			for identifier := range wanted {
				if err := advanceSyncTombstone(
					writer,
					config.partition,
					identifier,
					*deletionCSN,
				); err != nil {
					return err
				}
			}
		}
		if database != nil && deletionCSN != nil {
			for index := range deletions {
				before := deletions[index].entry
				change, err := server.recordSyncChangeCSN(
					writer,
					runtime,
					*database,
					&before,
					nil,
					*deletionCSN,
				)
				if err != nil {
					return err
				}
				if change != nil {
					changes = append(changes, *change)
				}
			}
		}
		var visibleCSN *openLDAPCSN
		if len(deletions) > 0 {
			visibleCSN = deletionCSN
		}
		return server.recordSyncConsumerContextChanges(
			writer,
			runtime,
			database,
			cookieAdvances,
			visibleCSN,
			&changes,
		)
	})
	if err == nil {
		for index := range changes {
			server.publishSyncChange(&changes[index])
		}
	}
	return err
}

func (server *Server) finishSyncConsumerRefresh(
	ctx context.Context,
	config syncConsumerConfig,
	refresh *syncConsumerRefreshState,
	refreshDeletes bool,
	cookie []byte,
) error {
	if refresh.complete {
		return server.storeSyncConsumerCookie(ctx, config, cookie)
	}
	runtime := server.runtime.Load()
	database := runtimeDatabaseForPartition(runtime, config.partition)
	var changes []syncChange
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		content := syncConsumerWriter(writer, database, config)
		cookieAdvances, err := syncConsumerCookieAdvances(
			writer,
			config,
			cookie,
		)
		if err != nil {
			return err
		}
		cookieState := parseOpenLDAPSyncCookie(cookie).csns
		var deletionCSN *openLDAPCSN
		for _, candidate := range cookieState {
			if deletionCSN == nil ||
				compareOpenLDAPCSN(candidate, *deletionCSN) > 0 {
				value := candidate
				deletionCSN = &value
			}
		}

		type deletion struct {
			dn    directory.DN
			entry directory.Entry
		}
		var deletions []deletion
		if !refreshDeletes {
			localBase, err := storage.NormalizeReaderDN(
				content,
				config.localBase,
			)
			if err != nil {
				return err
			}
			if err := content.ForEach(
				func(entry directory.Entry) error {
					dn, err := syncConsumerParseDN(content, entry.DN)
					if err != nil {
						return err
					}
					if !directory.InScope(localBase, dn, config.scope) {
						return nil
					}
					matches, err := config.filter.MatchWith(
						entry,
						runtime.schema,
					)
					if err != nil || !matches {
						return err
					}
					values := entry.Values("entryUUID")
					if len(values) == 1 {
						identifier := strings.ToLower(string(values[0]))
						if _, present := refresh.seen[identifier]; present {
							return nil
						}
					}
					entryCSN, found, err := syncConsumerEntryCSN(entry)
					if err != nil {
						return err
					}
					if found {
						covered, exists := cookieState[entryCSN.serverID]
						if !exists ||
							compareOpenLDAPCSN(entryCSN, covered) > 0 {
							return nil
						}
					}
					deletions = append(deletions, deletion{
						dn:    dn,
						entry: entry,
					})
					return nil
				},
			); err != nil {
				return err
			}
			sort.Slice(deletions, func(i, j int) bool {
				return deletions[i].dn.Depth() > deletions[j].dn.Depth()
			})
			for _, item := range deletions {
				if err := content.Delete(item.dn); err != nil {
					return err
				}
			}
		}
		if err := updateSyncConsumerCookie(writer, config, cookie); err != nil {
			return err
		}
		if database != nil && deletionCSN != nil {
			for index := range deletions {
				before := deletions[index].entry
				change, err := server.recordSyncChangeCSN(
					writer,
					runtime,
					*database,
					&before,
					nil,
					*deletionCSN,
				)
				if err != nil {
					return err
				}
				if change != nil {
					changes = append(changes, *change)
				}
			}
		}
		var visibleCSN *openLDAPCSN
		if len(deletions) > 0 {
			visibleCSN = deletionCSN
		}
		return server.recordSyncConsumerContextChanges(
			writer,
			runtime,
			database,
			cookieAdvances,
			visibleCSN,
			&changes,
		)
	})
	if err != nil {
		return err
	}
	for index := range changes {
		server.publishSyncChange(&changes[index])
	}
	refresh.complete = true
	return nil
}

func (server *Server) loadSyncConsumerCookie(
	ctx context.Context,
	config syncConsumerConfig,
) ([]byte, error) {
	var cookie []byte
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		value, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
		switch {
		case err == nil:
			cookie = bytes.Clone(value)
			return nil
		case errors.Is(err, storage.ErrMetadataNotFound):
			return nil
		default:
			return err
		}
	})
	if err != nil {
		return nil, fmt.Errorf("load syncrepl cookie: %w", err)
	}
	return cookie, nil
}

func (server *Server) storeSyncConsumerCookie(
	ctx context.Context,
	config syncConsumerConfig,
	cookie []byte,
) error {
	if len(cookie) == 0 {
		return nil
	}
	runtime := server.runtime.Load()
	database := runtimeDatabaseForPartition(runtime, config.partition)
	var changes []syncChange
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		advances, err := syncConsumerCookieAdvances(writer, config, cookie)
		if err != nil {
			return err
		}
		if err := updateSyncConsumerCookie(writer, config, cookie); err != nil {
			return err
		}
		return server.recordSyncConsumerContextChanges(
			writer,
			runtime,
			database,
			advances,
			nil,
			&changes,
		)
	})
	if err == nil {
		for index := range changes {
			server.publishSyncChange(&changes[index])
		}
	}
	return err
}

func updateSyncConsumerCookie(
	writer storage.Writer,
	config syncConsumerConfig,
	cookie []byte,
) error {
	if len(cookie) == 0 {
		return nil
	}
	parsed := parseOpenLDAPSyncCookie(cookie)
	merged := make(syncCSNState)
	var deletion *openLDAPCSN
	rawCurrent, err := writer.Metadata(syncConsumerCookieMetadataKey(config))
	switch {
	case err == nil:
		current := parseOpenLDAPSyncCookie(rawCurrent)
		for serverID, csn := range current.csns {
			merged[serverID] = csn
		}
		if current.hasDeletion {
			value := current.deletionCSN
			deletion = &value
		}
	case errors.Is(err, storage.ErrMetadataNotFound):
	default:
		return err
	}
	for serverID, candidate := range parsed.csns {
		known, exists := merged[serverID]
		if !exists || compareOpenLDAPCSN(candidate, known) > 0 {
			merged[serverID] = candidate
		}
	}
	if parsed.hasDeletion &&
		(deletion == nil || compareOpenLDAPCSN(parsed.deletionCSN, *deletion) > 0) {
		value := parsed.deletionCSN
		deletion = &value
	}
	storedCookie := composeOpenLDAPSyncCookie(config.rid, merged)
	if deletion != nil {
		storedCookie = append(
			storedCookie,
			[]byte(",delcsn="+deletion.raw)...,
		)
	}
	if err := writer.SetMetadata(
		syncConsumerCookieMetadataKey(config),
		storedCookie,
	); err != nil {
		return err
	}
	for _, csn := range merged {
		if err := advanceSyncContextCSN(writer, config.partition, csn); err != nil {
			return err
		}
	}
	return nil
}

func syncConsumerCookieMetadataKey(config syncConsumerConfig) string {
	partition := base64.RawURLEncoding.EncodeToString(
		[]byte(config.partition),
	)
	return fmt.Sprintf(
		"%s%s/%03d",
		syncConsumerCookieMetadataPrefix,
		partition,
		config.rid,
	)
}

func syncConsumerEntryByUUID(
	reader storage.Reader,
	partition string,
	identifier string,
) (directory.Entry, bool, error) {
	var (
		result directory.Entry
		found  bool
	)
	err := reader.ForEach(func(entry directory.Entry) error {
		values := entry.Values("entryUUID")
		if len(values) != 1 ||
			!strings.EqualFold(string(values[0]), identifier) {
			return nil
		}
		if found {
			return fmt.Errorf(
				"entryUUID %s exists more than once in partition %q",
				identifier,
				partition,
			)
		}
		result = entry
		found = true
		return nil
	})
	return result, found, err
}

func syncConsumerWriter(
	writer storage.Writer,
	database *runtimeDatabase,
	config syncConsumerConfig,
) storage.Writer {
	if database != nil {
		return writerForDatabase(writer, *database)
	}
	if config.normalizer != nil {
		return storage.WriterInPartitionWithNormalizer(
			writer,
			config.partition,
			config.normalizer,
		)
	}
	return storage.WriterInPartition(writer, config.partition)
}

func syncConsumerReader(
	reader storage.Reader,
	database *runtimeDatabase,
	config syncConsumerConfig,
) storage.Reader {
	if database != nil {
		return readerForDatabase(reader, *database)
	}
	if config.normalizer != nil {
		return storage.ReaderInPartitionWithNormalizer(
			reader,
			config.partition,
			config.normalizer,
		)
	}
	return storage.ReaderInPartition(reader, config.partition)
}

func syncConsumerParseDN(reader storage.Reader, raw string) (directory.DN, error) {
	dn, err := directory.ParseDN(raw)
	if err != nil {
		return directory.DN{}, err
	}
	return storage.NormalizeReaderDN(reader, dn)
}

func syncConsumerRequestedAttributes(config syncConsumerConfig) []string {
	attributes := append([]string(nil), config.attributes...)
	requiredAttributes := []struct {
		description string
		wildcard    string
	}{
		{description: "objectClass", wildcard: "*"},
		{description: "structuralObjectClass", wildcard: "+"},
		{description: "entryCSN", wildcard: "+"},
		{description: "entryUUID", wildcard: "+"},
	}
	for _, required := range requiredAttributes {
		if !slices.ContainsFunc(attributes, func(value string) bool {
			return strings.EqualFold(value, required.description) ||
				strings.EqualFold(value, required.wildcard)
		}) {
			attributes = append(attributes, required.description)
		}
	}
	return attributes
}

func bindSyncConsumer(
	connection *ldap.Conn,
	config syncConsumerConfig,
	provider string,
	externalSSF uint32,
) error {
	switch config.bindMethod {
	case "simple":
		if config.bindDN == "" && len(config.credentials) == 0 {
			return nil
		}
		if err := connection.Bind(
			config.bindDN,
			string(config.credentials),
		); err != nil {
			return fmt.Errorf("simple bind: %w", err)
		}
		return nil
	case "sasl":
		switch strings.ToUpper(config.saslMechanism) {
		case "GSSAPI":
			if err := validateSyncConsumerSASLSecurity(
				config.securityProperties,
				"GSSAPI",
				externalSSF,
			); err != nil {
				return err
			}
			return bindSyncConsumerGSSAPI(connection, config, provider)
		default:
			return fmt.Errorf(
				"SASL mechanism %q requires the raw consumer transport",
				config.saslMechanism,
			)
		}
	default:
		return fmt.Errorf("unknown bind method %q", config.bindMethod)
	}
}

func buildSyncConsumerTLSConfig(
	config syncConsumerConfig,
	provider *url.URL,
) (*tls.Config, error) {
	if config.tls.tlcpEncryptionCertificate != "" ||
		config.tls.tlcpEncryptionKey != "" {
		return nil, errors.New(
			"tlcp_enc_cert and tlcp_enc_key require an ldap+tlcp provider",
		)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: provider.Hostname(),
	}
	if config.tls.cipherSuite != "" {
		cipherSuites, err := parseSyncConsumerCipherSuites(
			config.tls.cipherSuite,
		)
		if err != nil {
			return nil, err
		}
		tlsConfig.CipherSuites = cipherSuites
	}
	if config.tls.ecName != "" {
		curves, err := parseSyncConsumerCurvePreferences(config.tls.ecName)
		if err != nil {
			return nil, err
		}
		tlsConfig.CurvePreferences = curves
	}
	if config.tls.protocolMinimum != "" {
		version, err := parseSyncConsumerTLSVersion(
			config.tls.protocolMinimum,
		)
		if err != nil {
			return nil, err
		}
		tlsConfig.MinVersion = version
	}
	material, err := loadSyncConsumerTLSMaterial(config.tls)
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = material.roots
	if err := configureSyncConsumerTLSVerification(
		tlsConfig,
		config.tls,
		material.crls,
	); err != nil {
		return nil, err
	}
	if config.tls.certificateFile != "" || config.tls.keyFile != "" {
		if config.tls.certificateFile == "" || config.tls.keyFile == "" {
			return nil, errors.New(
				"tls_cert and tls_key must be configured together",
			)
		}
		certificate, err := tls.LoadX509KeyPair(
			config.tls.certificateFile,
			config.tls.keyFile,
		)
		if err != nil {
			return nil, fmt.Errorf("load syncrepl TLS certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

func parseSyncConsumerTLSVersion(value string) (uint16, error) {
	switch value {
	case "1", "1.0", "3.1":
		return tls.VersionTLS10, nil
	case "1.1", "3.2":
		return tls.VersionTLS11, nil
	case "1.2", "3.3":
		return tls.VersionTLS12, nil
	case "1.3", "3.4":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown tls_protocol_min value %q", value)
	}
}

func (cursor *syncConsumerRetryCursor) next() (time.Duration, bool) {
	for cursor.index < len(cursor.policy) {
		current := cursor.policy[cursor.index]
		if current.attempts < 0 {
			return current.interval, true
		}
		if cursor.used < current.attempts {
			cursor.used++
			return current.interval, true
		}
		cursor.index++
		cursor.used = 0
	}
	return 0, false
}

func waitSyncConsumer(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
