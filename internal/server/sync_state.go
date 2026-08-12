package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncContextCSNMetadataPrefix = "openldap/sync/context-csn/"
	syncTombstoneMetadataPrefix  = "openldap/sync/tombstone/"
	syncCheckpointMetadataPrefix = "openldap/sync/checkpoint/"
	syncChangeBufferSize         = 256
	openLDAPSyncRIDMax           = 999
	openLDAPCSNCounterMax        = 0xffffff
)

type openLDAPCSN struct {
	timestamp    time.Time
	timestampRaw string
	counter      uint32
	serverID     uint16
	modifier     uint32
	raw          string
}

type openLDAPSyncCookie struct {
	rid         int
	hasRID      bool
	csns        syncCSNState
	deletionCSN openLDAPCSN
	hasDeletion bool
}

type syncCSNState map[uint16]openLDAPCSN

type syncCheckpointState struct {
	Operations int   `json:"operations"`
	LastUnix   int64 `json:"last_unix"`
}

type syncChange struct {
	partition         string
	providerPartition string
	csn               openLDAPCSN
	before            directory.Entry
	hasBefore         bool
	after             directory.Entry
	hasAfter          bool
}

type syncChangeHub struct {
	mu            sync.Mutex
	nextID        uint64
	subscriptions map[uint64]*syncChangeSubscription
	logs          map[string]*syncSessionLog
}

type syncSessionLog struct {
	size    int
	base    syncCSNState
	latest  syncCSNState
	changes []syncChange
}

type syncChangeSubscription struct {
	hub        *syncChangeHub
	id         uint64
	partitions map[string]struct{}
	events     chan syncChange
	overflow   atomic.Bool
}

func newSyncChangeHub() *syncChangeHub {
	return &syncChangeHub{
		subscriptions: make(map[uint64]*syncChangeSubscription),
		logs:          make(map[string]*syncSessionLog),
	}
}

func (hub *syncChangeHub) subscribe(
	partitions []string,
) *syncChangeSubscription {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	hub.nextID++
	partitionSet := make(map[string]struct{}, len(partitions))
	for _, partition := range partitions {
		partitionSet[partition] = struct{}{}
	}
	subscription := &syncChangeSubscription{
		hub:        hub,
		id:         hub.nextID,
		partitions: partitionSet,
		events:     make(chan syncChange, syncChangeBufferSize),
	}
	hub.subscriptions[subscription.id] = subscription
	return subscription
}

func (hub *syncChangeHub) publish(change syncChange) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if log := hub.logs[change.providerPartition]; log != nil {
		log.append(change)
	}
	for id, subscription := range hub.subscriptions {
		if _, subscribed := subscription.partitions[change.providerPartition]; !subscribed {
			continue
		}
		select {
		case subscription.events <- change:
		default:
			subscription.overflow.Store(true)
			close(subscription.events)
			delete(hub.subscriptions, id)
		}
	}
}

func (hub *syncChangeHub) configure(runtime *runtimeState) {
	type desiredLog struct {
		size    int
		context syncCSNState
	}
	desired := make(map[string]desiredLog)
	if runtime != nil {
		for _, database := range runtime.databases {
			if !database.syncProvider || database.syncSessionLogSize == 0 {
				continue
			}
			desired[database.partition] = desiredLog{
				size:    database.syncSessionLogSize,
				context: cloneSyncCSNState(runtime.syncContexts[database.partition]),
			}
		}
	}

	hub.mu.Lock()
	defer hub.mu.Unlock()
	for partition := range hub.logs {
		if _, keep := desired[partition]; !keep {
			delete(hub.logs, partition)
		}
	}
	for partition, configuration := range desired {
		log := hub.logs[partition]
		if log == nil ||
			!syncCSNStateCovers(log.latest, configuration.context) {
			hub.logs[partition] = &syncSessionLog{
				size:   configuration.size,
				base:   cloneSyncCSNState(configuration.context),
				latest: cloneSyncCSNState(configuration.context),
			}
			continue
		}
		log.size = configuration.size
		log.trim()
	}
}

func (hub *syncChangeHub) replay(
	partition string,
	cookie syncCSNState,
	snapshot syncCSNState,
) ([]syncChange, bool) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	log := hub.logs[partition]
	if log == nil ||
		!syncCSNStateCovers(log.latest, snapshot) ||
		!syncCSNStateCovers(cookie, log.base) {
		return nil, false
	}
	changes := make([]syncChange, 0, len(log.changes))
	for _, change := range log.changes {
		snapshotCSN, exists := snapshot[change.csn.serverID]
		if !exists || compareOpenLDAPCSN(change.csn, snapshotCSN) > 0 {
			continue
		}
		consumerCSN, exists := cookie[change.csn.serverID]
		if exists && compareOpenLDAPCSN(change.csn, consumerCSN) <= 0 {
			continue
		}
		changes = append(changes, cloneSyncChange(change))
	}
	return changes, true
}

func (log *syncSessionLog) append(change syncChange) {
	if current, exists := log.latest[change.csn.serverID]; exists &&
		compareOpenLDAPCSN(change.csn, current) < 0 {
		return
	}
	log.latest[change.csn.serverID] = change.csn
	if !change.hasBefore && change.hasAfter {
		return
	}
	log.changes = append(log.changes, cloneSyncChange(change))
	log.trim()
}

func (log *syncSessionLog) trim() {
	for len(log.changes) > log.size {
		expired := log.changes[0]
		log.changes[0] = syncChange{}
		log.changes = log.changes[1:]
		current, exists := log.base[expired.csn.serverID]
		if !exists || compareOpenLDAPCSN(expired.csn, current) > 0 {
			log.base[expired.csn.serverID] = expired.csn
		}
	}
}

func cloneSyncChange(change syncChange) syncChange {
	cloned := change
	if change.hasBefore {
		cloned.before = change.before.Clone()
	}
	if change.hasAfter {
		cloned.after = change.after.Clone()
	}
	return cloned
}

func cloneSyncCSNState(state syncCSNState) syncCSNState {
	cloned := make(syncCSNState, len(state))
	for serverID, csn := range state {
		cloned[serverID] = csn
	}
	return cloned
}

func syncCSNStateCovers(candidate, required syncCSNState) bool {
	for serverID, requiredCSN := range required {
		candidateCSN, exists := candidate[serverID]
		if !exists || compareOpenLDAPCSN(candidateCSN, requiredCSN) < 0 {
			return false
		}
	}
	return true
}

func (subscription *syncChangeSubscription) unsubscribe() {
	if subscription == nil || subscription.hub == nil {
		return
	}
	subscription.hub.mu.Lock()
	delete(subscription.hub.subscriptions, subscription.id)
	subscription.hub.mu.Unlock()
}

func parseOpenLDAPCSN(value string) (openLDAPCSN, error) {
	parts := strings.Split(value, "#")
	if len(parts) != 4 ||
		len(parts[1]) != 6 ||
		(len(parts[2]) != 2 && len(parts[2]) != 3) ||
		len(parts[3]) != 6 {
		return openLDAPCSN{}, fmt.Errorf("invalid CSN %q", value)
	}
	timestamp, timestampRaw, err := parseOpenLDAPCSNTimestamp(parts[0])
	if err != nil {
		return openLDAPCSN{}, fmt.Errorf("invalid CSN timestamp %q", value)
	}
	for _, field := range parts[1:] {
		for index := range field {
			if !isOpenLDAPHexDigit(field[index]) {
				return openLDAPCSN{}, fmt.Errorf(
					"invalid CSN hexadecimal field %q",
					value,
				)
			}
		}
	}
	counter, err := strconv.ParseUint(parts[1], 16, 24)
	if err != nil {
		return openLDAPCSN{}, fmt.Errorf("invalid CSN counter %q", value)
	}
	serverID, err := strconv.ParseUint(parts[2], 16, 12)
	if err != nil {
		return openLDAPCSN{}, fmt.Errorf("invalid CSN server ID %q", value)
	}
	modifier, err := strconv.ParseUint(parts[3], 16, 24)
	if err != nil {
		return openLDAPCSN{}, fmt.Errorf("invalid CSN modifier %q", value)
	}
	return openLDAPCSN{
		timestamp:    timestamp,
		timestampRaw: timestampRaw,
		counter:      uint32(counter),
		serverID:     uint16(serverID),
		modifier:     uint32(modifier),
		raw: fmt.Sprintf(
			"%s#%06x#%03x#%06x",
			timestampRaw,
			counter,
			serverID,
			modifier,
		),
	}, nil
}

func parseOpenLDAPCSNTimestamp(value string) (time.Time, string, error) {
	var fraction string
	switch len(value) {
	case len("20060102150405Z"):
		if value[len(value)-1] != 'Z' {
			return time.Time{}, "", errors.New("CSN timestamp is not UTC")
		}
		fraction = "000000"
	case len("20060102150405.000000Z"):
		if (value[14] != '.' && value[14] != ',') ||
			value[len(value)-1] != 'Z' {
			return time.Time{}, "", errors.New("invalid CSN timestamp delimiter")
		}
		fraction = value[15 : len(value)-1]
		for index := range fraction {
			if fraction[index] < '0' || fraction[index] > '9' {
				return time.Time{}, "", errors.New(
					"invalid CSN timestamp fraction",
				)
			}
		}
	default:
		return time.Time{}, "", errors.New("invalid CSN timestamp length")
	}
	base := value[:14]
	for index := range base {
		if base[index] < '0' || base[index] > '9' {
			return time.Time{}, "", errors.New("invalid CSN timestamp digit")
		}
	}
	parseBase := base
	leapSecond := base[12:] == "60"
	if leapSecond {
		parseBase = base[:12] + "59"
	}
	timestamp, err := time.Parse(
		"20060102150405.000000Z",
		parseBase+"."+fraction+"Z",
	)
	if err != nil {
		return time.Time{}, "", err
	}
	if leapSecond {
		timestamp = timestamp.Add(time.Second)
	}
	return timestamp, base + "." + fraction + "Z", nil
}

func isOpenLDAPHexDigit(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}

func compareOpenLDAPCSN(left, right openLDAPCSN) int {
	switch {
	case left.timestampRaw < right.timestampRaw:
		return -1
	case left.timestampRaw > right.timestampRaw:
		return 1
	case left.counter < right.counter:
		return -1
	case left.counter > right.counter:
		return 1
	case left.serverID < right.serverID:
		return -1
	case left.serverID > right.serverID:
		return 1
	case left.modifier < right.modifier:
		return -1
	case left.modifier > right.modifier:
		return 1
	default:
		return 0
	}
}

func parseOpenLDAPSyncCookie(value []byte) openLDAPSyncCookie {
	cookie := openLDAPSyncCookie{
		rid:  0,
		csns: make(syncCSNState),
	}
	if len(value) == 0 {
		return cookie
	}
	for _, field := range strings.Split(string(value), ",") {
		switch {
		case strings.HasPrefix(field, "rid="):
			rid, err := strconv.Atoi(strings.TrimPrefix(field, "rid="))
			if err != nil || rid < 0 || rid > openLDAPSyncRIDMax {
				return emptyOpenLDAPSyncCookie(0, false)
			}
			cookie.rid = rid
			cookie.hasRID = true
		case strings.HasPrefix(field, "sid="):
			rawSID := strings.TrimPrefix(field, "sid=")
			if _, err := strconv.ParseUint(rawSID, 16, 12); err != nil {
				return emptyOpenLDAPSyncCookie(cookie.rid, cookie.hasRID)
			}
		case strings.HasPrefix(field, "csn="):
			rawCSNs := strings.Split(strings.TrimPrefix(field, "csn="), ";")
			for _, rawCSN := range rawCSNs {
				csn, err := parseOpenLDAPCSN(rawCSN)
				if err != nil {
					return emptyOpenLDAPSyncCookie(cookie.rid, cookie.hasRID)
				}
				current, exists := cookie.csns[csn.serverID]
				if !exists || compareOpenLDAPCSN(csn, current) > 0 {
					cookie.csns[csn.serverID] = csn
				}
			}
		case strings.HasPrefix(field, "delcsn="):
			deletionCSN, err := parseOpenLDAPCSN(
				strings.TrimPrefix(field, "delcsn="),
			)
			if err != nil {
				return emptyOpenLDAPSyncCookie(cookie.rid, cookie.hasRID)
			}
			cookie.deletionCSN = deletionCSN
			cookie.hasDeletion = true
		default:
			return emptyOpenLDAPSyncCookie(cookie.rid, cookie.hasRID)
		}
	}
	return cookie
}

func emptyOpenLDAPSyncCookie(rid int, hasRID bool) openLDAPSyncCookie {
	return openLDAPSyncCookie{
		rid:    rid,
		hasRID: hasRID,
		csns:   make(syncCSNState),
	}
}

func composeOpenLDAPSyncCookie(rid int, state syncCSNState) []byte {
	if rid < 0 || rid > openLDAPSyncRIDMax {
		rid = 0
	}
	if len(state) == 0 {
		return []byte(fmt.Sprintf("rid=%03d", rid))
	}
	rawCSNs := orderedSyncCSNs(state)
	return []byte(fmt.Sprintf(
		"rid=%03d,csn=%s",
		rid,
		strings.Join(rawCSNs, ";"),
	))
}

func composeOpenLDAPSyncDeleteCookie(
	rid int,
	state syncCSNState,
	deletionCSN openLDAPCSN,
) []byte {
	cookie := composeOpenLDAPSyncCookie(rid, state)
	return append(
		cookie,
		[]byte(",delcsn="+deletionCSN.raw)...,
	)
}

func orderedSyncCSNs(state syncCSNState) []string {
	serverIDs := make([]int, 0, len(state))
	for serverID := range state {
		serverIDs = append(serverIDs, int(serverID))
	}
	sort.Ints(serverIDs)
	rawCSNs := make([]string, 0, len(serverIDs))
	for _, serverID := range serverIDs {
		rawCSNs = append(rawCSNs, state[uint16(serverID)].raw)
	}
	return rawCSNs
}

func syncContextCSNMetadataKey(partition string) string {
	return syncContextCSNMetadataPrefix +
		base64.RawURLEncoding.EncodeToString([]byte(partition))
}

func syncCheckpointMetadataKey(partition string) string {
	return syncCheckpointMetadataPrefix +
		base64.RawURLEncoding.EncodeToString([]byte(partition))
}

func syncTombstoneMetadataKey(partition, identifier string) string {
	return syncTombstoneMetadataPrefix +
		base64.RawURLEncoding.EncodeToString([]byte(partition)) + "/" +
		base64.RawURLEncoding.EncodeToString(
			[]byte(strings.ToLower(identifier)),
		)
}

func syncTombstoneCSN(
	reader storage.Reader,
	partition,
	identifier string,
) (openLDAPCSN, bool, error) {
	raw, err := reader.Metadata(syncTombstoneMetadataKey(partition, identifier))
	if errors.Is(err, storage.ErrMetadataNotFound) {
		return openLDAPCSN{}, false, nil
	}
	if err != nil {
		return openLDAPCSN{}, false, err
	}
	csn, err := parseOpenLDAPCSN(string(raw))
	if err != nil {
		return openLDAPCSN{}, false, fmt.Errorf(
			"parse sync tombstone for %s: %w",
			identifier,
			err,
		)
	}
	return csn, true, nil
}

func advanceSyncTombstone(
	writer storage.Writer,
	partition,
	identifier string,
	csn openLDAPCSN,
) error {
	current, exists, err := syncTombstoneCSN(writer, partition, identifier)
	if err != nil {
		return err
	}
	if exists && compareOpenLDAPCSN(csn, current) <= 0 {
		return nil
	}
	return writer.SetMetadata(
		syncTombstoneMetadataKey(partition, identifier),
		[]byte(csn.raw),
	)
}

func clearSyncTombstoneBefore(
	writer storage.Writer,
	partition,
	identifier string,
	csn openLDAPCSN,
) error {
	current, exists, err := syncTombstoneCSN(writer, partition, identifier)
	if err != nil || !exists {
		return err
	}
	if compareOpenLDAPCSN(csn, current) <= 0 {
		return nil
	}
	err = writer.DeleteMetadata(
		syncTombstoneMetadataKey(partition, identifier),
	)
	if errors.Is(err, storage.ErrMetadataNotFound) {
		return nil
	}
	return err
}

func syncEntryUUID(entry *directory.Entry) (string, bool) {
	if entry == nil {
		return "", false
	}
	values := entry.Values("entryUUID")
	if len(values) != 1 {
		return "", false
	}
	return strings.ToLower(string(values[0])), true
}

func updateSyncChangeTombstones(
	writer storage.Writer,
	partition string,
	before,
	after *directory.Entry,
	csn openLDAPCSN,
) error {
	beforeUUID, hasBeforeUUID := syncEntryUUID(before)
	afterUUID, hasAfterUUID := syncEntryUUID(after)
	if hasBeforeUUID &&
		(!hasAfterUUID || !strings.EqualFold(beforeUUID, afterUUID)) {
		if err := advanceSyncTombstone(
			writer,
			partition,
			beforeUUID,
			csn,
		); err != nil {
			return err
		}
	}
	if hasAfterUUID {
		return clearSyncTombstoneBefore(
			writer,
			partition,
			afterUUID,
			csn,
		)
	}
	return nil
}

func withSyncProviderContextCSNs(
	reader storage.Reader,
	database runtimeDatabase,
	entry directory.Entry,
) (directory.Entry, error) {
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	if len(database.suffixes) == 0 ||
		!database.suffixes[0].Equal(entryDN) {
		return entry, nil
	}
	if database.syncProvider {
		state, err := syncContextCSNs(reader, database.partition)
		if err != nil {
			return directory.Entry{}, err
		}
		values := make([][]byte, 0, len(state))
		for _, rawCSN := range orderedSyncCSNs(state) {
			values = append(values, []byte(rawCSN))
		}
		entry = entry.Clone()
		entry.ReplaceValues("contextCSN", values)
	}
	if database.accesslog != nil {
		if !database.syncProvider {
			entry = entry.Clone()
		}
		entry.ReplaceValues(
			"auditContext",
			stringValues(database.accesslog.targetSuffix.String()),
		)
	}
	return entry, nil
}

func syncContextCSNs(
	reader storage.Reader,
	partition string,
) (syncCSNState, error) {
	state := make(syncCSNState)
	rawMetadata, err := reader.Metadata(syncContextCSNMetadataKey(partition))
	switch {
	case err == nil:
		stored, parseErr := parseStoredSyncContextCSNs(rawMetadata)
		if parseErr != nil {
			return nil, fmt.Errorf("parse stored sync contextCSN: %w", parseErr)
		}
		for serverID, csn := range stored {
			state[serverID] = csn
		}
	case errors.Is(err, storage.ErrMetadataNotFound):
	default:
		return nil, fmt.Errorf("read stored sync contextCSN: %w", err)
	}

	tx := storage.ReaderInPartition(reader, partition)
	err = tx.ForEach(func(entry directory.Entry) error {
		for _, attribute := range []string{"entryCSN", "contextCSN"} {
			for _, rawValue := range entry.Values(attribute) {
				csn, parseErr := parseOpenLDAPCSN(string(rawValue))
				if parseErr != nil {
					if attribute == "contextCSN" {
						return fmt.Errorf(
							"%s has invalid contextCSN: %w",
							entry.DN,
							parseErr,
						)
					}
					continue
				}
				current, exists := state[csn.serverID]
				if !exists || compareOpenLDAPCSN(csn, current) > 0 {
					state[csn.serverID] = csn
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan sync contextCSN: %w", err)
	}
	return state, nil
}

func advanceSyncContextCSN(
	writer storage.Writer,
	partition string,
	csn openLDAPCSN,
) error {
	key := syncContextCSNMetadataKey(partition)
	state := make(syncCSNState)
	rawCurrent, err := writer.Metadata(key)
	switch {
	case err == nil:
		stored, parseErr := parseStoredSyncContextCSNs(rawCurrent)
		if parseErr != nil {
			return fmt.Errorf("parse stored sync contextCSN: %w", parseErr)
		}
		state = stored
		if current, exists := state[csn.serverID]; exists &&
			compareOpenLDAPCSN(csn, current) <= 0 {
			return nil
		}
	case errors.Is(err, storage.ErrMetadataNotFound):
		var currentErr error
		state, currentErr = syncContextCSNs(writer, partition)
		if currentErr != nil {
			return currentErr
		}
		if current, exists := state[csn.serverID]; exists &&
			compareOpenLDAPCSN(current, csn) > 0 {
			csn = current
		}
	default:
		return fmt.Errorf("read stored sync contextCSN: %w", err)
	}
	state[csn.serverID] = csn
	encoded, err := encodeStoredSyncContextCSNs(state)
	if err != nil {
		return err
	}
	return writer.SetMetadata(key, encoded)
}

func parseStoredSyncContextCSNs(raw []byte) (syncCSNState, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty contextCSN metadata")
	}
	rawValues := []string{string(raw)}
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &rawValues); err != nil {
			return nil, err
		}
	}
	if len(rawValues) == 0 {
		return nil, errors.New("empty contextCSN vector")
	}
	state := make(syncCSNState, len(rawValues))
	for _, rawValue := range rawValues {
		csn, err := parseOpenLDAPCSN(rawValue)
		if err != nil {
			return nil, err
		}
		if current, exists := state[csn.serverID]; exists &&
			compareOpenLDAPCSN(csn, current) <= 0 {
			continue
		}
		state[csn.serverID] = csn
	}
	return state, nil
}

func encodeStoredSyncContextCSNs(state syncCSNState) ([]byte, error) {
	values := orderedSyncCSNs(state)
	if len(values) == 0 {
		return nil, errors.New("cannot encode an empty contextCSN vector")
	}
	if len(values) == 1 {
		return []byte(values[0]), nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("encode stored sync contextCSN: %w", err)
	}
	return encoded, nil
}

func updateSyncCheckpoint(
	writer storage.Writer,
	database runtimeDatabase,
	now time.Time,
) error {
	if database.syncCheckpointOps == 0 ||
		database.syncCheckpointMinutes == 0 ||
		len(database.suffixes) == 0 {
		return nil
	}

	key := syncCheckpointMetadataKey(database.partition)
	var state syncCheckpointState
	rawState, err := writer.Metadata(key)
	switch {
	case err == nil:
		if err := json.Unmarshal(rawState, &state); err != nil {
			return fmt.Errorf("decode sync checkpoint state: %w", err)
		}
		if state.Operations < 0 || state.LastUnix <= 0 {
			return errors.New("stored sync checkpoint state is invalid")
		}
	case errors.Is(err, storage.ErrMetadataNotFound):
		state.LastUnix = now.Unix()
	default:
		return fmt.Errorf("read sync checkpoint state: %w", err)
	}

	state.Operations++
	dueOperations := state.Operations >= database.syncCheckpointOps
	dueTime := !now.Before(time.Unix(state.LastUnix, 0).Add(
		time.Duration(database.syncCheckpointMinutes) * time.Minute,
	))
	if dueOperations || dueTime {
		tx := storage.WriterInPartition(writer, database.partition)
		suffix, getErr := tx.Get(database.suffixes[0])
		switch {
		case getErr == nil:
			contextCSNs, contextErr := syncContextCSNs(
				writer,
				database.partition,
			)
			if contextErr != nil {
				return contextErr
			}
			values := make([][]byte, 0, len(contextCSNs))
			for _, rawCSN := range orderedSyncCSNs(contextCSNs) {
				values = append(values, []byte(rawCSN))
			}
			suffix.ReplaceValues("contextCSN", values)
			if err := tx.Put(suffix, true); err != nil {
				return fmt.Errorf("write sync checkpoint contextCSN: %w", err)
			}
			state.Operations = 0
			state.LastUnix = now.Unix()
		case errors.Is(getErr, storage.ErrEntryNotFound):
			// A deleted suffix cannot carry a checkpoint. Retain the
			// counters so the next successful write retries it.
		default:
			return fmt.Errorf("read sync checkpoint suffix: %w", getErr)
		}
	}

	rawState, err = json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode sync checkpoint state: %w", err)
	}
	if err := writer.SetMetadata(key, rawState); err != nil {
		return fmt.Errorf("store sync checkpoint state: %w", err)
	}
	return nil
}

func (server *Server) recordSyncChange(
	writer storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	before *directory.Entry,
	after *directory.Entry,
) (*syncChange, error) {
	return server.recordSyncChangeContext(
		context.Background(), writer, runtime, database, before, after,
	)
}

func (server *Server) recordSyncChangeContext(
	ctx context.Context,
	writer storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	before *directory.Entry,
	after *directory.Entry,
) (*syncChange, error) {
	provider := effectiveSyncProviderDatabase(runtime, database)
	if provider == nil {
		return nil, nil
	}
	var rawCSN string
	if after != nil {
		values := after.Values("entryCSN")
		if len(values) != 1 {
			return nil, fmt.Errorf(
				"sync provider entry %s has no single-valued entryCSN",
				after.DN,
			)
		}
		rawCSN = string(values[0])
	} else {
		rawCSN = server.nextCSNContext(ctx, runtime.serverID)
	}
	csn, err := parseOpenLDAPCSN(rawCSN)
	if err != nil {
		return nil, err
	}
	return server.recordSyncChangeCSN(
		writer,
		runtime,
		database,
		before,
		after,
		csn,
	)
}

func (server *Server) recordSyncChangeCSN(
	writer storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	before *directory.Entry,
	after *directory.Entry,
	csn openLDAPCSN,
) (*syncChange, error) {
	provider := effectiveSyncProviderDatabase(runtime, database)
	if provider == nil {
		return nil, nil
	}
	if err := updateSyncChangeTombstones(
		writer,
		database.partition,
		before,
		after,
		csn,
	); err != nil {
		return nil, err
	}
	if err := advanceSyncContextCSN(writer, provider.partition, csn); err != nil {
		return nil, err
	}
	if err := updateSyncCheckpoint(writer, *provider, time.Now().UTC()); err != nil {
		return nil, err
	}
	change := &syncChange{
		partition:         database.partition,
		providerPartition: provider.partition,
		csn:               csn,
	}
	if before != nil {
		change.before = before.Clone()
		change.hasBefore = true
	}
	if after != nil {
		change.after = after.Clone()
		change.hasAfter = true
	}
	return change, nil
}

func runtimeDatabaseForPartition(
	runtime *runtimeState,
	partition string,
) *runtimeDatabase {
	if runtime == nil {
		return nil
	}
	for index := range runtime.databases {
		if runtime.databases[index].partition == partition {
			return &runtime.databases[index]
		}
	}
	return nil
}

func (server *Server) publishSyncChange(change *syncChange) {
	if change == nil {
		return
	}
	server.syncChanges.publish(*change)
}

func (server *Server) seedCSNClock(runtime *runtimeState) error {
	return server.config.Store.View(
		context.Background(),
		func(reader storage.Reader) error {
			return server.observeRuntimeCSNs(reader, runtime)
		},
	)
}

func (server *Server) observeRuntimeCSNs(
	reader storage.Reader,
	runtime *runtimeState,
) error {
	runtime.syncContexts = make(map[string]syncCSNState)
	seenPartitions := make(map[string]struct{})
	for _, database := range runtime.databases {
		if !database.syncProvider {
			continue
		}
		if _, seen := seenPartitions[database.partition]; seen {
			continue
		}
		seenPartitions[database.partition] = struct{}{}
		state, err := syncContextCSNs(reader, database.partition)
		if err != nil {
			return err
		}
		runtime.syncContexts[database.partition] = cloneSyncCSNState(state)
		for _, csn := range state {
			server.observeCSN(csn)
		}
	}
	return nil
}

func (server *Server) activateRuntime(runtime *runtimeState) {
	if runtime == nil {
		return
	}
	server.runtimeActivationMu.Lock()
	defer server.runtimeActivationMu.Unlock()
	if runtime.revision == 0 {
		runtime.revision = server.nextRuntimeRevision()
	} else {
		server.observeRuntimeRevision(runtime.revision)
	}
	previous := server.runtime.Load()
	if previous != nil && runtime.revision <= previous.revision {
		return
	}
	server.prepareMetaTransportLifecycle(previous, runtime)
	server.configureMetaTransportOwners(metaBackendTransportOwners(runtime))
	server.syncChanges.configure(runtime)
	server.runtime.Store(runtime)
	server.syncConsumers.configure(runtime)
	select {
	case server.ddsWake <- struct{}{}:
	default:
	}
	select {
	case server.accesslogWake <- struct{}{}:
	default:
	}
}

func (server *Server) closeSQLBackends() {
	server.sqlBackendsMu.Lock()
	configurations := make([]*sqlBackendRuntimeConfiguration, 0, len(server.sqlBackends))
	for configuration := range server.sqlBackends {
		configurations = append(configurations, configuration)
	}
	clear(server.sqlBackends)
	server.sqlBackendsMu.Unlock()
	for _, configuration := range configurations {
		if err := configuration.close(); err != nil {
			server.config.Logger.Error("close SQL backend", "error", err)
		}
	}
}

func (server *Server) registerSQLBackend(configuration *sqlBackendRuntimeConfiguration) {
	if configuration == nil {
		return
	}
	server.sqlBackendsMu.Lock()
	server.sqlBackends[configuration] = struct{}{}
	server.sqlBackendsMu.Unlock()
}

func (server *Server) nextRuntimeRevision() uint64 {
	return server.runtimeSequence.Add(1)
}

func (server *Server) observeRuntimeRevision(revision uint64) {
	for {
		current := server.runtimeSequence.Load()
		if revision <= current || server.runtimeSequence.CompareAndSwap(current, revision) {
			return
		}
	}
}

func (server *Server) configureMetaTransportOwners(active map[string]struct{}) {
	server.metaTransports.configureOwners(active)
	server.metaTransportCachesMu.Lock()
	caches := make([]*metaTransportCache, 0, len(server.metaTransportCaches))
	for cache := range server.metaTransportCaches {
		caches = append(caches, cache)
	}
	server.metaTransportCachesMu.Unlock()
	for _, cache := range caches {
		cache.configureOwners(active)
	}
}

func (server *Server) registerMetaTransportCache(cache *metaTransportCache) {
	if cache == nil {
		return
	}
	server.runtimeActivationMu.Lock()
	defer server.runtimeActivationMu.Unlock()
	cache.configureOwners(metaBackendTransportOwners(server.runtime.Load()))
	server.metaTransportCachesMu.Lock()
	if server.metaTransportCaches == nil {
		server.metaTransportCaches = make(map[*metaTransportCache]struct{})
	}
	server.metaTransportCaches[cache] = struct{}{}
	server.metaTransportCachesMu.Unlock()
}

func (server *Server) unregisterMetaTransportCache(cache *metaTransportCache) {
	if cache == nil {
		return
	}
	server.metaTransportCachesMu.Lock()
	delete(server.metaTransportCaches, cache)
	server.metaTransportCachesMu.Unlock()
}

func (server *Server) observeCSN(csn openLDAPCSN) {
	server.csnMu.Lock()
	defer server.csnMu.Unlock()
	if server.lastCSN.IsZero() ||
		csn.timestamp.After(server.lastCSN) ||
		(csn.timestamp.Equal(server.lastCSN) && csn.counter > server.csnCounter) {
		server.lastCSN = csn.timestamp
		server.csnCounter = csn.counter
	}
}
