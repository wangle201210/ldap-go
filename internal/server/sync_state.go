package server

import (
	"context"
	"encoding/base64"
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
	rid    int
	hasRID bool
	csns   syncCSNState
}

type syncCSNState map[uint16]openLDAPCSN

type syncChange struct {
	partition string
	csn       openLDAPCSN
	before    directory.Entry
	hasBefore bool
	after     directory.Entry
	hasAfter  bool
}

type syncChangeHub struct {
	mu            sync.Mutex
	nextID        uint64
	subscriptions map[uint64]*syncChangeSubscription
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
	for id, subscription := range hub.subscriptions {
		if _, subscribed := subscription.partitions[change.partition]; !subscribed {
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
			if _, err := parseOpenLDAPCSN(
				strings.TrimPrefix(field, "delcsn="),
			); err != nil {
				return emptyOpenLDAPSyncCookie(cookie.rid, cookie.hasRID)
			}
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

func withSyncProviderContextCSNs(
	reader storage.Reader,
	database runtimeDatabase,
	entry directory.Entry,
) (directory.Entry, error) {
	if !database.syncProvider || len(database.suffixes) == 0 {
		return entry, nil
	}
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	if !database.suffixes[0].Equal(entryDN) {
		return entry, nil
	}
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
		csn, parseErr := parseOpenLDAPCSN(string(rawMetadata))
		if parseErr != nil {
			return nil, fmt.Errorf("parse stored sync contextCSN: %w", parseErr)
		}
		if csn.serverID != 0 {
			return nil, fmt.Errorf(
				"stored sync contextCSN has server ID %03x, want 000",
				csn.serverID,
			)
		}
		state[csn.serverID] = csn
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
	rawCurrent, err := writer.Metadata(key)
	switch {
	case err == nil:
		current, parseErr := parseOpenLDAPCSN(string(rawCurrent))
		if parseErr != nil {
			return fmt.Errorf("parse stored sync contextCSN: %w", parseErr)
		}
		if current.serverID != csn.serverID {
			return fmt.Errorf(
				"stored sync contextCSN has server ID %03x, want %03x",
				current.serverID,
				csn.serverID,
			)
		}
		if compareOpenLDAPCSN(csn, current) <= 0 {
			return nil
		}
	case errors.Is(err, storage.ErrMetadataNotFound):
		state, currentErr := syncContextCSNs(writer, partition)
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
	return writer.SetMetadata(key, []byte(csn.raw))
}

func (server *Server) recordSyncChange(
	writer storage.Writer,
	database runtimeDatabase,
	before *directory.Entry,
	after *directory.Entry,
) (*syncChange, error) {
	if !database.syncProvider {
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
		rawCSN = server.nextCSN()
	}
	csn, err := parseOpenLDAPCSN(rawCSN)
	if err != nil {
		return nil, err
	}
	if err := advanceSyncContextCSN(writer, database.partition, csn); err != nil {
		return nil, err
	}
	change := &syncChange{
		partition: database.partition,
		csn:       csn,
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
		for _, csn := range state {
			server.observeCSN(csn)
		}
	}
	return nil
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
