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
	"time"

	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	pcachePersistenceVersion        = 1
	pcacheMaxPersistedSnapshotBytes = 64 << 20
	pcachePersistenceMetadataPrefix = "pcache/state/v1/"
)

var errPcachePersistenceRetired = errors.New("pcache persistence generation is no longer active")

type pcachePersistence struct {
	store       storage.Store
	metadataKey string
	fingerprint string
	enabled     bool
}

type pcachePersistedSnapshot struct {
	Version     int                    `json:"version"`
	Fingerprint string                 `json:"fingerprint"`
	Epoch       time.Time              `json:"epoch"`
	Sequence    uint64                 `json:"sequence"`
	Generation  uint64                 `json:"generation"`
	Entries     int                    `json:"entries"`
	Queries     []pcachePersistedQuery `json:"queries,omitempty"`
	Binds       []pcachePersistedBind  `json:"binds,omitempty"`
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
	SASLSSF         uint32 `json:"saslSsf,omitempty"`
	ExternalDN      string `json:"externalDn,omitempty"`
}

type pcacheStateBackup struct {
	queries    map[string]pcacheCachedQuery
	binds      map[string]pcacheCachedBind
	entries    int
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
		configuration.state.persistence = &pcachePersistence{
			store:       server.config.Store,
			metadataKey: pcachePersistenceMetadataKey(configuration.configDNKey),
			fingerprint: configuration.fingerprint,
			enabled:     configuration.persist,
		}
		if !configuration.persist {
			continue
		}
		raw, err := reader.Metadata(configuration.state.persistence.metadataKey)
		if errors.Is(err, storage.ErrMetadataNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load pcache persistence for %s: %w", database.name, err)
		}
		if len(raw) > pcacheMaxPersistedSnapshotBytes {
			return fmt.Errorf("pcache persistence for %s exceeds %d bytes", database.name, pcacheMaxPersistedSnapshotBytes)
		}
		var snapshot pcachePersistedSnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return fmt.Errorf("decode pcache persistence for %s: %w", database.name, err)
		}
		if snapshot.Version != pcachePersistenceVersion ||
			snapshot.Fingerprint != configuration.fingerprint {
			continue
		}
		if err := server.restorePcacheSnapshot(runtime, database, snapshot); err != nil {
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
		if configuration == nil || configuration.state == nil ||
			configuration.state.persistence == nil {
			continue
		}
		persistence := configuration.state.persistence
		raw, err := writer.Metadata(persistence.metadataKey)
		if !configuration.persist {
			if err == nil {
				if err := writer.DeleteMetadata(persistence.metadataKey); err != nil {
					return err
				}
			} else if !errors.Is(err, storage.ErrMetadataNotFound) {
				return err
			}
			continue
		}
		matching := false
		if err == nil && len(raw) <= pcacheMaxPersistedSnapshotBytes {
			var header struct {
				Version     int    `json:"version"`
				Fingerprint string `json:"fingerprint"`
			}
			if json.Unmarshal(raw, &header) == nil {
				matching = header.Version == pcachePersistenceVersion &&
					header.Fingerprint == persistence.fingerprint
			}
		} else if err != nil && !errors.Is(err, storage.ErrMetadataNotFound) {
			return err
		}
		if matching {
			continue
		}
		configuration.state.mu.Lock()
		encoded, encodeErr := configuration.state.encodePersistedSnapshotLocked()
		configuration.state.mu.Unlock()
		if encodeErr != nil {
			return encodeErr
		}
		if err := writer.SetMetadata(persistence.metadataKey, encoded); err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) restorePcacheSnapshot(
	runtime *runtimeState,
	database *runtimeDatabase,
	snapshot pcachePersistedSnapshot,
) error {
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
	state.queries = restoredQueries
	state.binds = restoredBinds
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
	snapshot := pcachePersistedSnapshot{
		Version:     pcachePersistenceVersion,
		Fingerprint: state.persistence.fingerprint,
		Epoch:       state.epoch,
		Sequence:    state.sequence,
		Generation:  state.generation,
		Entries:     state.entries,
	}
	queryKeys := make([]string, 0, len(state.queries))
	for key := range state.queries {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	for _, key := range queryKeys {
		query := state.queries[key]
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
	bindKeys := make([]string, 0, len(state.binds))
	for key := range state.binds {
		bindKeys = append(bindKeys, key)
	}
	sort.Strings(bindKeys)
	for _, key := range bindKeys {
		bind := state.binds[key]
		snapshot.Binds = append(snapshot.Binds, pcachePersistedBind{
			Key:          key,
			PasswordHash: bytes.Clone(bind.passwordHash),
			PurgeAt:      bind.purgeAt,
			LastUsed:     bind.lastUsed,
			Generation:   bind.generation,
		})
	}
	encoded, err := json.Marshal(snapshot)
	for index := range snapshot.Binds {
		clear(snapshot.Binds[index].PasswordHash)
	}
	if err != nil {
		return nil, err
	}
	if len(encoded) > pcacheMaxPersistedSnapshotBytes {
		return nil, fmt.Errorf("pcache persistence exceeds %d bytes", pcacheMaxPersistedSnapshotBytes)
	}
	return encoded, nil
}

func (state *pcacheState) persistLocked() error {
	if state.persistence == nil || !state.persistence.enabled || state.persistence.store == nil {
		return nil
	}
	encoded, err := state.encodePersistedSnapshotLocked()
	if err != nil {
		return err
	}
	persistence := state.persistence
	return persistence.store.Update(context.Background(), func(writer storage.Writer) error {
		current, err := writer.Metadata(persistence.metadataKey)
		if err == nil {
			var header struct {
				Version     int    `json:"version"`
				Fingerprint string `json:"fingerprint"`
			}
			if json.Unmarshal(current, &header) != nil ||
				header.Version != pcachePersistenceVersion ||
				header.Fingerprint != persistence.fingerprint {
				return errPcachePersistenceRetired
			}
		} else if !errors.Is(err, storage.ErrMetadataNotFound) {
			return err
		}
		return writer.SetMetadata(persistence.metadataKey, encoded)
	})
}

func (state *pcacheState) backupLocked() pcacheStateBackup {
	backup := pcacheStateBackup{
		queries:    make(map[string]pcacheCachedQuery, len(state.queries)),
		binds:      make(map[string]pcacheCachedBind, len(state.binds)),
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
	return backup
}

func (state *pcacheState) finishMutationLocked(backup pcacheStateBackup) bool {
	if state.persistence == nil || !state.persistence.enabled {
		clearPcacheBackup(backup)
		return true
	}
	if err := state.persistLocked(); err == nil {
		clearPcacheBackup(backup)
		return true
	}
	clearPcacheStateSecrets(state.queries, state.binds)
	state.queries = backup.queries
	state.binds = backup.binds
	state.entries = backup.entries
	state.sequence = backup.sequence
	state.generation = backup.generation
	return false
}

func (state *pcacheState) restoreBackupLocked(backup pcacheStateBackup) {
	clearPcacheStateSecrets(state.queries, state.binds)
	state.queries = backup.queries
	state.binds = backup.binds
	state.entries = backup.entries
	state.sequence = backup.sequence
	state.generation = backup.generation
}

func clearPcacheBackup(backup pcacheStateBackup) {
	clearPcacheStateSecrets(backup.queries, backup.binds)
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
		saslSSF:          remote.SASLSSF,
		externalDN:       remote.ExternalDN,
	}
}
