package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	pcachePersistenceVersion        = 2
	pcacheMaxPersistedSnapshotBytes = 64 << 20
	pcacheMaxPersistenceGuardBytes  = 4 << 10
	pcachePersistenceMetadataPrefix = "pcache/state/v1/"
	pcachePersistenceGuardSuffix    = "/guard-v2"
)

var (
	errPcachePersistenceRetired  = errors.New("pcache persistence generation is no longer active")
	errPcachePersistenceConflict = errors.New("pcache persistence generation changed")
)

type pcachePersistence struct {
	store       storage.Store
	metadataKey string
	guardKey    string
	fingerprint string
	epoch       string
	enabled     bool
	identityMu  sync.Mutex
	serialOnce  sync.Once
	serial      chan struct{}
	retired     atomic.Bool
}

type pcachePersistedSnapshot struct {
	Version          int                    `json:"version"`
	Fingerprint      string                 `json:"fingerprint"`
	PersistenceEpoch string                 `json:"persistenceEpoch"`
	Epoch            time.Time              `json:"epoch"`
	Sequence         uint64                 `json:"sequence"`
	Generation       uint64                 `json:"generation"`
	Entries          int                    `json:"entries"`
	Queries          []pcachePersistedQuery `json:"queries,omitempty"`
	Binds            []pcachePersistedBind  `json:"binds,omitempty"`
	PrivateEntries   []directory.Entry      `json:"privateEntries,omitempty"`
}

type pcachePersistenceGuard struct {
	Version     int    `json:"version"`
	Fingerprint string `json:"fingerprint"`
	Epoch       string `json:"epoch"`
	Retired     bool   `json:"retired"`
}

type pcachePersistedQuery struct {
	Key        string                  `json:"key"`
	Identifier string                  `json:"identifier,omitempty"`
	Attrset    int                     `json:"attrset"`
	Response   pcachePersistedResponse `json:"response"`
	Replay     ldapwire.SearchRequest  `json:"replay"`
	Remote     pcachePersistedRemote   `json:"remote"`
	PurgeAt    time.Time               `json:"purgeAt"`
	RefreshAt  time.Time               `json:"refreshAt,omitempty"`
	LastUsed   uint64                  `json:"lastUsed"`
	Generation uint64                  `json:"generation"`
	Referenced bool                    `json:"referenced"`
}

type pcachePersistedBind struct {
	Key          string    `json:"key"`
	PasswordHash []byte    `json:"passwordHash"`
	PurgeAt      time.Time `json:"purgeAt"`
	LastUsed     uint64    `json:"lastUsed"`
	Generation   uint64    `json:"generation"`
}

type pcachePersistedResponse struct {
	Items        []pcachePersistedItem `json:"items,omitempty"`
	Result       ldapwire.Result       `json:"result"`
	DoneControls []ldapwire.Control    `json:"doneControls,omitempty"`
}

type pcachePersistedItem struct {
	Entry      *directory.Entry   `json:"entry,omitempty"`
	References []string           `json:"references,omitempty"`
	Controls   []ldapwire.Control `json:"controls,omitempty"`
}

type pcachePersistedRemote struct {
	ConnectionID    uint64 `json:"connectionId,omitempty"`
	BoundDN         string `json:"boundDn,omitempty"`
	OperationRealDN string `json:"operationRealDn,omitempty"`
	AuthMechanism   string `json:"authMechanism,omitempty"`
	CredentialDN    string `json:"credentialDn,omitempty"`
	Secure          bool   `json:"secure,omitempty"`
	ExternalSSF     uint32 `json:"externalSsf,omitempty"`
	TransportSSF    uint32 `json:"transportSsf,omitempty"`
	TLSSSF          uint32 `json:"tlsSsf,omitempty"`
	SASLSSF         uint32 `json:"saslSsf,omitempty"`
	ExternalDN      string `json:"externalDn,omitempty"`
}

type pcacheStateBackup struct {
	queries    map[string]pcacheCachedQuery
	binds      map[string]pcacheCachedBind
	private    map[string]directory.Entry
	entries    int
	sequence   uint64
	generation uint64
}

type pcacheQueryReadBaseline struct {
	generation uint64
	lastUsed   uint64
	referenced bool
	refreshing bool
	refreshAt  time.Time
	purgeAt    time.Time
}

type pcacheBindReadBaseline struct {
	generation uint64
	lastUsed   uint64
}

type pcacheStateBaseline struct {
	queries    map[string]pcacheQueryReadBaseline
	binds      map[string]pcacheBindReadBaseline
	sequence   uint64
	generation uint64
}

func newPcacheQueryIdentifier(entries int) string {
	if entries == 0 {
		return ""
	}
	return uuid.NewString()
}

func pcachePersistenceMetadataKey(configDNKey string) string {
	digest := sha256.Sum256([]byte(configDNKey))
	return pcachePersistenceMetadataPrefix + hex.EncodeToString(digest[:])
}

func pcachePersistenceGuardKey(metadataKey string) string {
	return metadataKey + pcachePersistenceGuardSuffix
}

func (persistence *pcachePersistence) ensureIdentity() {
	if persistence == nil {
		return
	}
	persistence.identityMu.Lock()
	defer persistence.identityMu.Unlock()
	if persistence.guardKey == "" {
		persistence.guardKey = pcachePersistenceGuardKey(persistence.metadataKey)
	}
	if persistence.epoch == "" {
		persistence.epoch = uuid.NewString()
	}
}

func (persistence *pcachePersistence) retire() {
	if persistence != nil {
		persistence.retired.Store(true)
	}
}

func encodePcachePersistenceGuard(
	persistence *pcachePersistence,
	retired bool,
) ([]byte, error) {
	if persistence == nil {
		return nil, errors.New("pcache persistence is not configured")
	}
	persistence.ensureIdentity()
	return json.Marshal(pcachePersistenceGuard{
		Version:     pcachePersistenceVersion,
		Fingerprint: persistence.fingerprint,
		Epoch:       persistence.epoch,
		Retired:     retired,
	})
}

func decodePcachePersistenceGuard(raw []byte) (pcachePersistenceGuard, error) {
	if len(raw) == 0 || len(raw) > pcacheMaxPersistenceGuardBytes {
		return pcachePersistenceGuard{}, errors.New("invalid pcache persistence guard size")
	}
	var guard pcachePersistenceGuard
	if err := json.Unmarshal(raw, &guard); err != nil {
		return pcachePersistenceGuard{}, err
	}
	if guard.Epoch == "" {
		return pcachePersistenceGuard{}, errors.New("pcache persistence guard has no epoch")
	}
	if _, err := uuid.Parse(guard.Epoch); err != nil {
		return pcachePersistenceGuard{}, fmt.Errorf("invalid pcache persistence epoch: %w", err)
	}
	return guard, nil
}

func (server *Server) preparePcachePersistence(
	reader storage.Reader,
	runtime *runtimeState,
) error {
	if runtime == nil {
		return nil
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		configuration := database.pcache
		if configuration == nil || configuration.state == nil {
			continue
		}
		metadataKey := pcachePersistenceMetadataKey(configuration.configDNKey)
		persistence := &pcachePersistence{
			store:       server.config.Store,
			metadataKey: metadataKey,
			guardKey:    pcachePersistenceGuardKey(metadataKey),
			fingerprint: configuration.fingerprint,
			epoch:       uuid.NewString(),
			enabled:     configuration.persist,
		}
		var snapshot *pcachePersistedSnapshot
		if configuration.persist {
			guardRaw, err := reader.Metadata(persistence.guardKey)
			switch {
			case errors.Is(err, storage.ErrMetadataNotFound):
				clear(guardRaw)
			case err != nil:
				clear(guardRaw)
				return fmt.Errorf("load pcache persistence guard for %s: %w", database.name, err)
			default:
				guard, decodeErr := decodePcachePersistenceGuard(guardRaw)
				clear(guardRaw)
				if decodeErr != nil {
					return fmt.Errorf("decode pcache persistence guard for %s: %w", database.name, decodeErr)
				}
				if !guard.Retired && guard.Version == pcachePersistenceVersion &&
					guard.Fingerprint == configuration.fingerprint {
					persistence.epoch = guard.Epoch
					raw, snapshotErr := reader.Metadata(persistence.metadataKey)
					switch {
					case errors.Is(snapshotErr, storage.ErrMetadataNotFound):
						clear(raw)
					case snapshotErr != nil:
						clear(raw)
						return fmt.Errorf("load pcache persistence for %s: %w", database.name, snapshotErr)
					case len(raw) > pcacheMaxPersistedSnapshotBytes:
						clear(raw)
						return fmt.Errorf("pcache persistence for %s exceeds %d bytes", database.name, pcacheMaxPersistedSnapshotBytes)
					default:
						var restored pcachePersistedSnapshot
						decodeErr := json.Unmarshal(raw, &restored)
						clear(raw)
						if decodeErr != nil {
							return fmt.Errorf("decode pcache persistence for %s: %w", database.name, decodeErr)
						}
						if restored.Version == pcachePersistenceVersion &&
							restored.Fingerprint == configuration.fingerprint &&
							restored.PersistenceEpoch == persistence.epoch {
							snapshot = &restored
						} else {
							clearPcachePersistedSnapshot(&restored)
						}
					}
				}
			}
		}
		configuration.state.mu.Lock()
		current := configuration.state.persistence
		if current == nil || current.metadataKey != persistence.metadataKey ||
			current.fingerprint != persistence.fingerprint ||
			current.enabled != persistence.enabled ||
			current.epoch != persistence.epoch || current.retired.Load() {
			configuration.state.persistence = persistence
		}
		configuration.state.mu.Unlock()
		if !configuration.persist {
			continue
		}
		if snapshot == nil {
			continue
		}
		if err := server.restorePcacheSnapshot(runtime, database, *snapshot); err != nil {
			return fmt.Errorf("restore pcache persistence for %s: %w", database.name, err)
		}
	}
	return nil
}

func (server *Server) ensurePcachePersistence(
	writer storage.Writer,
	runtime *runtimeState,
) error {
	if runtime == nil {
		return nil
	}
	for index := range runtime.databases {
		configuration := runtime.databases[index].pcache
		if configuration == nil || configuration.state == nil {
			continue
		}
		configuration.state.mu.Lock()
		persistence := configuration.state.persistence
		configuration.state.mu.Unlock()
		if persistence == nil {
			continue
		}
		persistence.ensureIdentity()
		raw, err := writer.Metadata(persistence.metadataKey)
		if !configuration.persist {
			guard, encodeErr := encodePcachePersistenceGuard(
				persistence,
				true,
			)
			if encodeErr != nil {
				clear(raw)
				return encodeErr
			}
			if err := writer.SetMetadata(persistence.guardKey, guard); err != nil {
				clear(raw)
				return err
			}
			if err == nil {
				if deleteErr := writer.DeleteMetadata(persistence.metadataKey); deleteErr != nil {
					clear(raw)
					return deleteErr
				}
			} else if !errors.Is(err, storage.ErrMetadataNotFound) {
				clear(raw)
				return err
			}
			clear(raw)
			continue
		}
		matching := false
		guardRaw, guardErr := writer.Metadata(persistence.guardKey)
		if err == nil && guardErr == nil && len(raw) <= pcacheMaxPersistedSnapshotBytes {
			guard, decodeErr := decodePcachePersistenceGuard(guardRaw)
			var header struct {
				Version          int    `json:"version"`
				Fingerprint      string `json:"fingerprint"`
				PersistenceEpoch string `json:"persistenceEpoch"`
			}
			if decodeErr == nil && json.Unmarshal(raw, &header) == nil {
				matching = header.Version == pcachePersistenceVersion &&
					header.Fingerprint == persistence.fingerprint &&
					header.PersistenceEpoch == persistence.epoch &&
					!guard.Retired &&
					guard.Version == pcachePersistenceVersion &&
					guard.Fingerprint == persistence.fingerprint &&
					guard.Epoch == persistence.epoch
			}
		}
		clear(raw)
		clear(guardRaw)
		if err != nil && !errors.Is(err, storage.ErrMetadataNotFound) {
			return err
		}
		if guardErr != nil && !errors.Is(guardErr, storage.ErrMetadataNotFound) {
			return guardErr
		}
		if matching {
			continue
		}
		configuration.state.privateSnapshotMu.RLock()
		configuration.state.mu.Lock()
		snapshot := snapshotPcacheStateLocked(configuration.state)
		epoch := configuration.state.epoch
		configuration.state.mu.Unlock()
		candidate := detachPcacheSnapshot(snapshot)
		clearPcacheShallowSnapshot(snapshot)
		configuration.state.privateSnapshotMu.RUnlock()
		encoded, encodeErr := encodePcachePersistedSnapshot(
			persistence,
			epoch,
			candidate,
		)
		clearPcacheBackup(candidate)
		if encodeErr != nil {
			return encodeErr
		}
		guard, encodeErr := encodePcachePersistenceGuard(persistence, false)
		if encodeErr != nil {
			clear(encoded)
			return encodeErr
		}
		if err := writer.SetMetadata(persistence.guardKey, guard); err != nil {
			clear(encoded)
			return err
		}
		if err := writer.SetMetadata(persistence.metadataKey, encoded); err != nil {
			clear(encoded)
			return err
		}
		clear(encoded)
	}
	return nil
}

func (server *Server) restorePcacheSnapshot(
	runtime *runtimeState,
	database *runtimeDatabase,
	snapshot pcachePersistedSnapshot,
) error {
	defer clearPcachePersistedSnapshot(&snapshot)
	configuration := database.pcache
	state := configuration.state
	now := state.clock()
	restoredQueries := make(map[string]pcacheCachedQuery, len(snapshot.Queries))
	identifiers := make(map[string]struct{}, len(snapshot.Queries))
	entries := 0
	for _, persisted := range snapshot.Queries {
		if persisted.Key == "" || now.After(persisted.PurgeAt) || now.Equal(persisted.PurgeAt) {
			continue
		}
		if _, duplicate := restoredQueries[persisted.Key]; duplicate {
			return fmt.Errorf("duplicate query key %q", persisted.Key)
		}
		if persisted.Identifier != "" {
			if _, err := uuid.Parse(persisted.Identifier); err != nil {
				return fmt.Errorf("invalid query identifier %q", persisted.Identifier)
			}
			if _, duplicate := identifiers[persisted.Identifier]; duplicate {
				return fmt.Errorf("duplicate query identifier %q", persisted.Identifier)
			}
			identifiers[persisted.Identifier] = struct{}{}
		}
		match, ok := server.matchPcacheRequest(runtime, *configuration, persisted.Replay)
		if !ok || match.key != persisted.Key || match.attrset.index != persisted.Attrset {
			return fmt.Errorf("persisted query %q no longer matches its template", persisted.Key)
		}
		response := persisted.Response.runtimeResponse()
		count := response.entryCount()
		if count > configuration.entryLimit || (count > 0 && persisted.Identifier == "") {
			return fmt.Errorf("persisted query %q has invalid entry metadata", persisted.Key)
		}
		if !pcacheResponseCacheable(runtime.schema, persisted.Replay.Filter, response, configuration.validate) {
			return fmt.Errorf("persisted query %q is not cacheable", persisted.Key)
		}
		entries += count
		remote := persisted.Remote.runtimeRemote()
		restoredQueries[persisted.Key] = pcacheCachedQuery{
			identifier: persisted.Identifier,
			attrset:    persisted.Attrset,
			response:   response,
			replay: ldapwire.Message{
				Request:  persisted.Replay,
				Controls: nil,
			},
			remote: remote,
			policy: pcacheRefreshPolicy{
				positiveTTL:       match.template.ttl,
				negativeTTL:       match.template.negativeTTL,
				ttr:               match.template.ttr,
				consistencyPeriod: configuration.consistencyPeriod,
				entryLimit:        configuration.entryLimit,
				attrset:           match.attrset.index,
			},
			purgeAt:    persisted.PurgeAt,
			refreshAt:  persisted.RefreshAt,
			entries:    count,
			lastUsed:   persisted.LastUsed,
			generation: persisted.Generation,
			referenced: persisted.Referenced,
		}
	}
	if len(restoredQueries) > configuration.maxQueries || entries > configuration.maxEntries {
		return errors.New("persisted query cache exceeds configured limits")
	}
	restoredBinds := make(map[string]pcacheCachedBind, len(snapshot.Binds))
	for _, persisted := range snapshot.Binds {
		if persisted.Key == "" || len(persisted.PasswordHash) == 0 ||
			now.After(persisted.PurgeAt) || now.Equal(persisted.PurgeAt) {
			continue
		}
		if _, duplicate := restoredBinds[persisted.Key]; duplicate {
			return fmt.Errorf("duplicate cached Bind key %q", persisted.Key)
		}
		restoredBinds[persisted.Key] = pcacheCachedBind{
			passwordHash: bytes.Clone(persisted.PasswordHash),
			purgeAt:      persisted.PurgeAt,
			lastUsed:     persisted.LastUsed,
			generation:   persisted.Generation,
		}
		entries++
	}
	if len(restoredQueries)+len(restoredBinds) > configuration.maxQueries ||
		entries > configuration.maxEntries {
		return errors.New("persisted cache exceeds configured limits")
	}
	restoredPrivate := make(map[string]directory.Entry, len(snapshot.PrivateEntries))
	for _, persisted := range snapshot.PrivateEntries {
		dn, err := runtime.schema.NormalizeDN(persisted.DN)
		if err != nil || !databaseContainsDN(*database, dn) {
			return fmt.Errorf("invalid private cache entry DN %q", persisted.DN)
		}
		if _, duplicate := restoredPrivate[dn.Key()]; duplicate {
			return fmt.Errorf("duplicate private cache entry DN %q", persisted.DN)
		}
		if failure := pcachePrivateValidateAddEntry(persisted); failure != nil {
			return fmt.Errorf(
				"invalid private cache entry %q: %s",
				persisted.DN,
				failure.DiagnosticMessage,
			)
		}
		persisted.DN = dn.String()
		if failure := pcachePrivateSchemaResult(runtime, persisted, dn); failure != nil {
			return fmt.Errorf(
				"invalid private cache entry %q: %s",
				persisted.DN,
				failure.DiagnosticMessage,
			)
		}
		restoredPrivate[dn.Key()] = persisted.Clone()
		entries++
	}
	if entries > configuration.maxEntries {
		return errors.New("persisted private cache exceeds configured limits")
	}
	restoredState := &pcacheState{
		queries: restoredQueries,
		private: restoredPrivate,
		entries: entries,
	}
	visible := restoredState.privateEntriesUnlocked(
		runtime,
		*database,
		configuration.persist,
		now,
	)
	for _, entry := range restoredPrivate {
		dn, _ := runtime.schema.NormalizeDN(entry.DN)
		if !pcachePrivateParentExists(*database, dn, visible) {
			return fmt.Errorf("private cache entry %q has no parent", entry.DN)
		}
	}
	state.queries = restoredQueries
	state.binds = restoredBinds
	state.private = restoredPrivate
	state.entries = entries
	state.sequence = snapshot.Sequence
	state.generation = snapshot.Generation
	if !snapshot.Epoch.IsZero() {
		state.epoch = snapshot.Epoch
	}
	return nil
}

func databaseContainsDN(database runtimeDatabase, dn directory.DN) bool {
	for _, suffix := range database.suffixes {
		if databaseDNEqual(database, suffix, dn) || suffix.AncestorOf(dn) {
			return true
		}
	}
	return false
}

func (state *pcacheState) encodePersistedSnapshotLocked() ([]byte, error) {
	if state.persistence == nil {
		return nil, errors.New("pcache persistence is not configured")
	}
	candidate := state.backupLocked()
	defer clearPcacheBackup(candidate)
	return encodePcachePersistedSnapshot(state.persistence, state.epoch, candidate)
}

func encodePcachePersistedSnapshot(
	persistence *pcachePersistence,
	epoch time.Time,
	candidate pcacheStateBackup,
) ([]byte, error) {
	if persistence == nil {
		return nil, errors.New("pcache persistence is not configured")
	}
	persistence.ensureIdentity()
	snapshot := pcachePersistedSnapshot{
		Version:          pcachePersistenceVersion,
		Fingerprint:      persistence.fingerprint,
		PersistenceEpoch: persistence.epoch,
		Epoch:            epoch,
		Sequence:         candidate.sequence,
		Generation:       candidate.generation,
		Entries:          candidate.entries,
	}
	privateKeys := make([]string, 0, len(candidate.private))
	for key := range candidate.private {
		privateKeys = append(privateKeys, key)
	}
	sort.Strings(privateKeys)
	for _, key := range privateKeys {
		snapshot.PrivateEntries = append(
			snapshot.PrivateEntries,
			candidate.private[key].Clone(),
		)
	}
	queryKeys := make([]string, 0, len(candidate.queries))
	for key := range candidate.queries {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	for _, key := range queryKeys {
		query := candidate.queries[key]
		request, ok := query.replay.Request.(ldapwire.SearchRequest)
		if !ok {
			return nil, fmt.Errorf("pcache query %q has a non-search replay", key)
		}
		snapshot.Queries = append(snapshot.Queries, pcachePersistedQuery{
			Key:        key,
			Identifier: query.identifier,
			Attrset:    query.attrset,
			Response:   persistedPcacheResponse(query.response),
			Replay:     request,
			Remote:     persistedPcacheRemote(query.remote),
			PurgeAt:    query.purgeAt,
			RefreshAt:  query.refreshAt,
			LastUsed:   query.lastUsed,
			Generation: query.generation,
			Referenced: query.referenced,
		})
	}
	bindKeys := make([]string, 0, len(candidate.binds))
	for key := range candidate.binds {
		bindKeys = append(bindKeys, key)
	}
	sort.Strings(bindKeys)
	for _, key := range bindKeys {
		bind := candidate.binds[key]
		snapshot.Binds = append(snapshot.Binds, pcachePersistedBind{
			Key:          key,
			PasswordHash: bytes.Clone(bind.passwordHash),
			PurgeAt:      bind.purgeAt,
			LastUsed:     bind.lastUsed,
			Generation:   bind.generation,
		})
	}
	encoded, err := json.Marshal(snapshot)
	clearPcachePersistedSnapshot(&snapshot)
	if err != nil {
		return nil, err
	}
	if len(encoded) > pcacheMaxPersistedSnapshotBytes {
		clear(encoded)
		return nil, fmt.Errorf("pcache persistence exceeds %d bytes", pcacheMaxPersistedSnapshotBytes)
	}
	return encoded, nil
}

func (persistence *pcachePersistence) acquire(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	persistence.ensureIdentity()
	if persistence.retired.Load() {
		return false
	}
	persistence.serialOnce.Do(func() {
		persistence.serial = make(chan struct{}, 1)
		persistence.serial <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return false
	case <-persistence.serial:
		if persistence.retired.Load() {
			persistence.release()
			return false
		}
		return true
	}
}

func (persistence *pcachePersistence) release() {
	persistence.serial <- struct{}{}
}

func (persistence *pcachePersistence) persistSnapshot(
	ctx context.Context,
	expectedGeneration uint64,
	encoded []byte,
) error {
	if persistence == nil || !persistence.enabled || persistence.store == nil {
		return nil
	}
	persistence.ensureIdentity()
	if persistence.retired.Load() {
		return errPcachePersistenceRetired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return persistence.store.Update(ctx, func(writer storage.Writer) error {
		guardRaw, guardErr := writer.Metadata(persistence.guardKey)
		defer clear(guardRaw)
		switch {
		case errors.Is(guardErr, storage.ErrMetadataNotFound):
			if expectedGeneration != 0 {
				persistence.retire()
				return errPcachePersistenceConflict
			}
			guard, err := encodePcachePersistenceGuard(persistence, false)
			if err != nil {
				return err
			}
			if err := writer.SetMetadata(persistence.guardKey, guard); err != nil {
				return err
			}
		case guardErr != nil:
			return guardErr
		default:
			guard, err := decodePcachePersistenceGuard(guardRaw)
			if err != nil || guard.Retired ||
				guard.Version != pcachePersistenceVersion ||
				guard.Fingerprint != persistence.fingerprint ||
				guard.Epoch != persistence.epoch {
				persistence.retire()
				return errPcachePersistenceRetired
			}
		}

		current, err := writer.Metadata(persistence.metadataKey)
		defer clear(current)
		if err == nil {
			var header struct {
				Version          int    `json:"version"`
				Fingerprint      string `json:"fingerprint"`
				PersistenceEpoch string `json:"persistenceEpoch"`
				Generation       uint64 `json:"generation"`
			}
			if json.Unmarshal(current, &header) != nil ||
				header.Version != pcachePersistenceVersion ||
				header.Fingerprint != persistence.fingerprint ||
				header.PersistenceEpoch != persistence.epoch {
				persistence.retire()
				return errPcachePersistenceRetired
			}
			if header.Generation != expectedGeneration {
				persistence.retire()
				return errPcachePersistenceConflict
			}
		} else if !errors.Is(err, storage.ErrMetadataNotFound) {
			return err
		} else if expectedGeneration != 0 {
			persistence.retire()
			return errPcachePersistenceConflict
		}
		return writer.SetMetadata(persistence.metadataKey, encoded)
	})
}

func (state *pcacheState) backupLocked() pcacheStateBackup {
	backup := pcacheStateBackup{
		queries:    make(map[string]pcacheCachedQuery, len(state.queries)),
		binds:      make(map[string]pcacheCachedBind, len(state.binds)),
		private:    make(map[string]directory.Entry, len(state.private)),
		entries:    state.entries,
		sequence:   state.sequence,
		generation: state.generation,
	}
	for key, query := range state.queries {
		backup.queries[key] = clonePcacheCachedQuery(query)
	}
	for key, bind := range state.binds {
		bind.passwordHash = bytes.Clone(bind.passwordHash)
		backup.binds[key] = bind
	}
	for key, entry := range state.private {
		backup.private[key] = entry.Clone()
	}
	return backup
}

// snapshotPcacheStateLocked captures map membership and the only byte slices
// that concurrent removals clear. Query responses and replay requests are
// immutable after publication, so their expensive deep copy is deferred until
// after state.mu is released.
func snapshotPcacheStateLocked(state *pcacheState) pcacheStateBackup {
	snapshot := pcacheStateBackup{
		queries:    make(map[string]pcacheCachedQuery, len(state.queries)),
		binds:      make(map[string]pcacheCachedBind, len(state.binds)),
		private:    make(map[string]directory.Entry, len(state.private)),
		entries:    state.entries,
		sequence:   state.sequence,
		generation: state.generation,
	}
	for key, query := range state.queries {
		query.remote.bindCredentials = bytes.Clone(query.remote.bindCredentials)
		snapshot.queries[key] = query
	}
	for key, bind := range state.binds {
		bind.passwordHash = bytes.Clone(bind.passwordHash)
		snapshot.binds[key] = bind
	}
	for key, entry := range state.private {
		snapshot.private[key] = entry
	}
	return snapshot
}

func detachPcacheSnapshot(snapshot pcacheStateBackup) pcacheStateBackup {
	detached := pcacheStateBackup{
		queries:    make(map[string]pcacheCachedQuery, len(snapshot.queries)),
		binds:      make(map[string]pcacheCachedBind, len(snapshot.binds)),
		private:    make(map[string]directory.Entry, len(snapshot.private)),
		entries:    snapshot.entries,
		sequence:   snapshot.sequence,
		generation: snapshot.generation,
	}
	for key, query := range snapshot.queries {
		query.response = clonePcacheSearchResponse(query.response)
		query.replay = clonePcacheMessage(query.replay)
		query.remote.bindCredentials = bytes.Clone(query.remote.bindCredentials)
		detached.queries[key] = query
	}
	for key, bind := range snapshot.binds {
		bind.passwordHash = bytes.Clone(bind.passwordHash)
		detached.binds[key] = bind
	}
	for key, entry := range snapshot.private {
		detached.private[key] = entry.Clone()
	}
	return detached
}

func clearPcacheShallowSnapshot(snapshot pcacheStateBackup) {
	clearPcacheStateSecrets(snapshot.queries, snapshot.binds)
}

// mutate serializes durable mutations without holding state.mu during storage
// I/O. Persistent candidates remain private until Store.Update commits, so
// readers continue to observe the previous committed state while a slow store
// is blocked. The callback must increment state.generation whenever changed is
// true.
func (state *pcacheState) mutate(
	ctx context.Context,
	mutation func(*pcacheState) (changed bool, accepted bool),
) bool {
	if state == nil || mutation == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		state.privateSnapshotMu.Lock()
		state.mu.Lock()
		persistence := state.persistence
		if persistence == nil || !persistence.enabled || persistence.store == nil {
			backup := state.backupLocked()
			previousPrivate := snapshotPcachePrivateEntriesShallow(state.private)
			changed, accepted := mutation(state)
			clearRetiredPcachePrivateValues(previousPrivate, state.private)
			if !accepted || !changed {
				state.restoreBackupLocked(backup)
			} else {
				clearPcacheBackup(backup)
			}
			state.mu.Unlock()
			state.privateSnapshotMu.Unlock()
			return accepted
		}
		state.mu.Unlock()
		state.privateSnapshotMu.Unlock()

		if !persistence.acquire(ctx) {
			return false
		}
		state.privateSnapshotMu.RLock()
		state.mu.Lock()
		if state.persistence != persistence || !persistence.enabled ||
			persistence.store == nil || persistence.retired.Load() {
			state.mu.Unlock()
			state.privateSnapshotMu.RUnlock()
			persistence.release()
			if err := ctx.Err(); err != nil {
				return false
			}
			continue
		}

		baseline := capturePcacheStateBaselineLocked(state)
		// Capture only map membership and clearable secrets while locked. The
		// potentially large immutable responses are detached after unlocking.
		snapshot := snapshotPcacheStateLocked(state)
		epoch := state.epoch
		clock := state.clock
		state.mu.Unlock()
		candidate := detachPcacheSnapshot(snapshot)
		clearPcacheShallowSnapshot(snapshot)
		state.privateSnapshotMu.RUnlock()
		working := &pcacheState{
			epoch:       epoch,
			clock:       clock,
			queries:     candidate.queries,
			binds:       candidate.binds,
			private:     candidate.private,
			entries:     candidate.entries,
			sequence:    candidate.sequence,
			generation:  candidate.generation,
			persistence: persistence,
		}

		previousPrivate := snapshotPcachePrivateEntriesShallow(working.private)
		changed, accepted := mutation(working)
		clearRetiredPcachePrivateValues(previousPrivate, working.private)
		candidate = pcacheStateBackup{
			queries:    working.queries,
			binds:      working.binds,
			private:    working.private,
			entries:    working.entries,
			sequence:   working.sequence,
			generation: working.generation,
		}
		if !accepted || !changed {
			persistence.release()
			clearPcacheBackup(candidate)
			return accepted
		}
		if candidate.generation <= baseline.generation {
			persistence.release()
			clearPcacheBackup(candidate)
			return false
		}
		encoded, err := encodePcachePersistedSnapshot(
			persistence,
			epoch,
			candidate,
		)
		if err != nil {
			persistence.release()
			clearPcacheBackup(candidate)
			return false
		}

		err = persistence.persistSnapshot(ctx, baseline.generation, encoded)
		clear(encoded)
		if err != nil {
			persistence.release()
			clearPcacheBackup(candidate)
			return false
		}

		state.privateSnapshotMu.Lock()
		state.mu.Lock()
		if state.persistence != persistence ||
			state.generation != baseline.generation {
			state.mu.Unlock()
			state.privateSnapshotMu.Unlock()
			persistence.release()
			clearPcacheBackup(candidate)
			return false
		}
		mergePcacheConcurrentReadsLocked(state, baseline, &candidate)
		clearPcacheStateSecrets(state.queries, state.binds)
		clearPcachePrivateEntries(state.private)
		state.queries = candidate.queries
		state.binds = candidate.binds
		state.private = candidate.private
		state.entries = candidate.entries
		state.sequence = candidate.sequence
		state.generation = candidate.generation
		state.mu.Unlock()
		state.privateSnapshotMu.Unlock()
		persistence.release()
		return true
	}
}

func capturePcacheStateBaselineLocked(state *pcacheState) pcacheStateBaseline {
	baseline := pcacheStateBaseline{
		queries:    make(map[string]pcacheQueryReadBaseline, len(state.queries)),
		binds:      make(map[string]pcacheBindReadBaseline, len(state.binds)),
		sequence:   state.sequence,
		generation: state.generation,
	}
	for key, query := range state.queries {
		baseline.queries[key] = pcacheQueryReadBaseline{
			generation: query.generation,
			lastUsed:   query.lastUsed,
			referenced: query.referenced,
			refreshing: query.refreshing,
			refreshAt:  query.refreshAt,
			purgeAt:    query.purgeAt,
		}
	}
	for key, bind := range state.binds {
		baseline.binds[key] = pcacheBindReadBaseline{
			generation: bind.generation,
			lastUsed:   bind.lastUsed,
		}
	}
	return baseline
}

func mergePcacheConcurrentReadsLocked(
	state *pcacheState,
	baseline pcacheStateBaseline,
	candidate *pcacheStateBackup,
) {
	mutationSequenceDelta := candidate.sequence - baseline.sequence
	if state.sequence >= baseline.sequence {
		candidate.sequence += state.sequence - baseline.sequence
	}
	for key, before := range baseline.queries {
		current, currentFound := state.queries[key]
		next, nextFound := candidate.queries[key]
		if !currentFound || !nextFound || current.generation != before.generation {
			continue
		}
		if current.lastUsed != before.lastUsed && next.lastUsed == before.lastUsed {
			next.lastUsed = addPcacheSequence(current.lastUsed, mutationSequenceDelta)
		}
		if current.referenced != before.referenced && next.referenced == before.referenced {
			next.referenced = current.referenced
		}
		if current.refreshing != before.refreshing && next.refreshing == before.refreshing {
			next.refreshing = current.refreshing
		}
		if !current.refreshAt.Equal(before.refreshAt) && next.refreshAt.Equal(before.refreshAt) {
			next.refreshAt = current.refreshAt
		}
		if !current.purgeAt.Equal(before.purgeAt) && next.purgeAt.Equal(before.purgeAt) {
			next.purgeAt = current.purgeAt
		}
		candidate.queries[key] = next
	}
	for key, before := range baseline.binds {
		current, currentFound := state.binds[key]
		next, nextFound := candidate.binds[key]
		if !currentFound || !nextFound || current.generation != before.generation {
			continue
		}
		if current.lastUsed != before.lastUsed && next.lastUsed == before.lastUsed {
			next.lastUsed = addPcacheSequence(current.lastUsed, mutationSequenceDelta)
			candidate.binds[key] = next
		}
	}
}

func addPcacheSequence(value, delta uint64) uint64 {
	result := value + delta
	if result < value {
		return ^uint64(0)
	}
	return result
}

func (state *pcacheState) restoreBackupLocked(backup pcacheStateBackup) {
	clearPcacheStateSecrets(state.queries, state.binds)
	clearPcachePrivateEntries(state.private)
	state.queries = backup.queries
	state.binds = backup.binds
	state.private = backup.private
	state.entries = backup.entries
	state.sequence = backup.sequence
	state.generation = backup.generation
}

func clearPcacheBackup(backup pcacheStateBackup) {
	clearPcacheStateSecrets(backup.queries, backup.binds)
	clearPcachePrivateEntries(backup.private)
}

func clearPcachePrivateEntries(entries map[string]directory.Entry) {
	for key, entry := range entries {
		clearEntryValues(entry)
		delete(entries, key)
	}
}

func snapshotPcachePrivateEntriesShallow(
	entries map[string]directory.Entry,
) map[string]directory.Entry {
	snapshot := make(map[string]directory.Entry, len(entries))
	for key, entry := range entries {
		snapshot[key] = entry
	}
	return snapshot
}

func clearRetiredPcachePrivateValues(
	previous,
	current map[string]directory.Entry,
) {
	retained := make(map[*byte]struct{})
	for _, entry := range current {
		for _, attribute := range entry.Attributes {
			for _, value := range attribute.Values {
				if len(value) != 0 {
					retained[&value[0]] = struct{}{}
				}
			}
		}
	}
	for previousKey, entry := range previous {
		for attributeIndex := range entry.Attributes {
			for valueIndex := range entry.Attributes[attributeIndex].Values {
				value := entry.Attributes[attributeIndex].Values[valueIndex]
				if len(value) == 0 {
					continue
				}
				if _, retained := retained[&value[0]]; !retained {
					clear(value)
				}
			}
		}
		delete(previous, previousKey)
	}
}

func clearPcachePersistedSnapshot(snapshot *pcachePersistedSnapshot) {
	if snapshot == nil {
		return
	}
	for index := range snapshot.PrivateEntries {
		clearEntryValues(snapshot.PrivateEntries[index])
	}
	for queryIndex := range snapshot.Queries {
		for itemIndex := range snapshot.Queries[queryIndex].Response.Items {
			entry := snapshot.Queries[queryIndex].Response.Items[itemIndex].Entry
			if entry != nil {
				clearEntryValues(*entry)
			}
		}
	}
	for index := range snapshot.Binds {
		clear(snapshot.Binds[index].PasswordHash)
	}
}

func clearPcacheStateSecrets(
	queries map[string]pcacheCachedQuery,
	binds map[string]pcacheCachedBind,
) {
	for _, query := range queries {
		clear(query.remote.bindCredentials)
	}
	for _, bind := range binds {
		clear(bind.passwordHash)
	}
}

func clonePcacheCachedQuery(query pcacheCachedQuery) pcacheCachedQuery {
	query.response = clonePcacheSearchResponse(query.response)
	query.replay = clonePcacheMessage(query.replay)
	query.remote = clonePcacheRemoteContext(query.remote)
	return query
}

func persistedPcacheResponse(response pcacheSearchResponse) pcachePersistedResponse {
	persisted := pcachePersistedResponse{
		Result:       response.result,
		DoneControls: cloneLDAPControls(response.doneControls),
		Items:        make([]pcachePersistedItem, 0, len(response.items)),
	}
	for _, item := range response.items {
		persistedItem := pcachePersistedItem{
			References: append([]string(nil), item.references...),
			Controls:   cloneLDAPControls(item.controls),
		}
		if item.entry != nil {
			entry := item.entry.Clone()
			persistedItem.Entry = &entry
		}
		persisted.Items = append(persisted.Items, persistedItem)
	}
	return persisted
}

func (response pcachePersistedResponse) runtimeResponse() pcacheSearchResponse {
	runtime := pcacheSearchResponse{
		result:       response.Result,
		doneControls: cloneLDAPControls(response.DoneControls),
		items:        make([]pcacheSearchItem, 0, len(response.Items)),
	}
	for _, item := range response.Items {
		runtimeItem := pcacheSearchItem{
			references: append([]string(nil), item.References...),
			controls:   cloneLDAPControls(item.Controls),
		}
		if item.Entry != nil {
			entry := item.Entry.Clone()
			runtimeItem.entry = &entry
		}
		runtime.items = append(runtime.items, runtimeItem)
	}
	return runtime
}

func persistedPcacheRemote(remote pcacheRemoteContext) pcachePersistedRemote {
	return pcachePersistedRemote{
		ConnectionID:    remote.connectionID,
		BoundDN:         remote.boundDN,
		OperationRealDN: remote.operationRealDN,
		AuthMechanism:   remote.authMechanism,
		CredentialDN:    remote.bindCredentialDN,
		Secure:          remote.secure,
		ExternalSSF:     remote.externalSSF,
		TransportSSF:    remote.transportSSF,
		TLSSSF:          remote.tlsSSF,
		SASLSSF:         remote.saslSSF,
		ExternalDN:      remote.externalDN,
	}
}

func (remote pcachePersistedRemote) runtimeRemote() pcacheRemoteContext {
	return pcacheRemoteContext{
		connectionID:     remote.ConnectionID,
		boundDN:          remote.BoundDN,
		operationRealDN:  remote.OperationRealDN,
		authMechanism:    remote.AuthMechanism,
		bindCredentialDN: remote.CredentialDN,
		secure:           remote.Secure,
		externalSSF:      remote.ExternalSSF,
		transportSSF:     remote.TransportSSF,
		tlsSSF:           remote.TLSSSF,
		saslSSF:          remote.SASLSSF,
		externalDN:       remote.ExternalDN,
	}
}
