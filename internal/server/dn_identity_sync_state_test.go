package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncStateExactOID = "1.3.6.1.4.1.99999.923.1"
	syncStateFoldOID  = "1.3.6.1.4.1.99999.923.2"
	syncStateCSN      = "20260823010101.000001Z#000000#001#000000"
)

func TestDNIdentitySyncProviderState(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store {
			return storage.NewMemory()
		}},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			t.Helper()
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}

	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			registry := newDNIdentitySyncStateRegistry(t)

			t.Run("context_entry", func(t *testing.T) {
				testDNIdentitySyncStateContextEntry(t, store, registry)
			})
			t.Run("checkpoint_suffix", func(t *testing.T) {
				testDNIdentitySyncStateCheckpoint(t, store, registry)
			})
			t.Run("tombstone_sessionlog", func(t *testing.T) {
				testDNIdentitySyncStateChange(t, store, registry)
			})
		})
	}
}

func testDNIdentitySyncStateContextEntry(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	database := runtimeDatabase{
		name:         "mdb",
		partition:    "sync-state-context",
		suffixes:     []directory.DN{mustDNIdentitySyncStateDN(t, registry, syncStateSuffix())},
		dnNormalizer: registry,
		syncProvider: true,
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.SetMetadata(
			syncContextCSNMetadataKey(database.partition),
			[]byte(syncStateCSN),
		)
	}); err != nil {
		t.Fatalf("seed contextCSN metadata: %v", err)
	}

	tests := []struct {
		name string
		dn   string
		want bool
	}{
		{
			name: "caseIgnore alias OID and multiAVA equivalent",
			dn: syncStateFoldOID +
				"= RESEARCH +syncStateExactAlias=Tenant,DC=EXAMPLE,DC=COM",
			want: true,
		},
		{
			name: "caseExact value remains distinct",
			dn: "syncStateExactAlias=tenant+syncStateFoldAlias=research," +
				"dc=example,dc=com",
			want: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var projected directory.Entry
			err := store.View(context.Background(), func(reader storage.Reader) error {
				var err error
				projected, err = withSyncProviderContextCSNs(
					reader,
					database,
					directory.Entry{DN: test.dn},
				)
				return err
			})
			if err != nil {
				t.Fatalf("withSyncProviderContextCSNs(): %v", err)
			}
			if got := len(projected.Values("contextCSN")) == 1; got != test.want {
				t.Fatalf("contextCSN present = %t, want %t", got, test.want)
			}
		})
	}

	legacy := runtimeDatabase{
		name:         "config",
		partition:    "sync-state-config",
		suffixes:     []directory.DN{mustLegacyDNIdentitySyncStateDN(t, "cn=config")},
		dnNormalizer: registry,
		syncProvider: true,
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.SetMetadata(
			syncContextCSNMetadataKey(legacy.partition),
			[]byte(syncStateCSN),
		)
	}); err != nil {
		t.Fatalf("seed config contextCSN metadata: %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := withSyncProviderContextCSNs(
			reader,
			legacy,
			directory.Entry{DN: "CN=CONFIG"},
		)
		if err != nil {
			return err
		}
		if len(entry.Values("contextCSN")) != 1 {
			t.Fatal("legacy cn=config context entry did not receive contextCSN")
		}
		return nil
	}); err != nil {
		t.Fatalf("withSyncProviderContextCSNs(cn=config): %v", err)
	}
}

func testDNIdentitySyncStateCheckpoint(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	database := runtimeDatabase{
		name:                  "mdb",
		partition:             "sync-state-checkpoint",
		suffixes:              []directory.DN{mustDNIdentitySyncStateDN(t, registry, syncStateSuffix())},
		dnNormalizer:          registry,
		syncProvider:          true,
		syncCheckpointOps:     1,
		syncCheckpointMinutes: 60,
	}
	storedDN := syncStateFoldOID +
		"=research+syncStateExactAlias=Tenant,dc=example,dc=com"
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := storage.WriterInPartition(writer, database.partition).Put(
			directory.Entry{DN: storedDN},
			false,
		); err != nil {
			return err
		}
		if err := writer.SetMetadata(
			syncContextCSNMetadataKey(database.partition),
			[]byte(syncStateCSN),
		); err != nil {
			return err
		}
		return updateSyncCheckpoint(
			writer,
			database,
			time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC),
		)
	})
	if err != nil {
		t.Fatalf("updateSyncCheckpoint(): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := readerForDatabase(reader, database).Get(database.suffixes[0])
		if err != nil {
			return err
		}
		values := entry.Values("contextCSN")
		if len(values) != 1 || string(values[0]) != syncStateCSN {
			t.Fatalf("checkpoint contextCSN = %q, want %q", values, syncStateCSN)
		}
		wantDN := mustDNIdentitySyncStateDN(t, registry, storedDN).String()
		if entry.DN != wantDN {
			t.Fatalf("checkpoint DN = %q, want canonical %q", entry.DN, wantDN)
		}
		return nil
	}); err != nil {
		t.Fatalf("read checkpoint suffix: %v", err)
	}

	exactDatabase := database
	exactDatabase.partition = "sync-state-checkpoint-exact"
	exactDatabase.suffixes = []directory.DN{mustDNIdentitySyncStateDN(
		t,
		registry,
		"syncStateExactName=Tenant,dc=example,dc=com",
	)}
	wrongCaseDN := "syncStateExactAlias=tenant,dc=example,dc=com"
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		if err := storage.WriterInPartition(writer, exactDatabase.partition).Put(
			directory.Entry{DN: wrongCaseDN},
			false,
		); err != nil {
			return err
		}
		if err := writer.SetMetadata(
			syncContextCSNMetadataKey(exactDatabase.partition),
			[]byte(syncStateCSN),
		); err != nil {
			return err
		}
		return updateSyncCheckpoint(writer, exactDatabase, time.Now().UTC())
	})
	if err != nil {
		t.Fatalf("updateSyncCheckpoint(caseExact sibling): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := storage.ReaderInPartition(
			reader,
			exactDatabase.partition,
		).Get(mustLegacyDNIdentitySyncStateDN(t, wrongCaseDN))
		if err != nil {
			return err
		}
		if len(entry.Values("contextCSN")) != 0 {
			t.Fatal("caseExact sibling received the provider checkpoint")
		}
		return nil
	}); err != nil {
		t.Fatalf("read caseExact sibling: %v", err)
	}
}

func testDNIdentitySyncStateChange(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	baseline := mustDNIdentitySyncStateCSN(
		t,
		"20260823010101.000000Z#000000#001#000000",
	)
	deletion := mustDNIdentitySyncStateCSN(t, syncStateCSN)
	database := runtimeDatabase{
		name:               "mdb",
		partition:          "sync-state-change",
		suffixes:           []directory.DN{mustDNIdentitySyncStateDN(t, registry, syncStateSuffix())},
		dnNormalizer:       registry,
		syncProvider:       true,
		syncSessionLogSize: 4,
	}
	runtime := &runtimeState{
		schema:    registry,
		databases: []runtimeDatabase{database},
		syncContexts: map[string]syncCSNState{
			database.partition: {baseline.serverID: baseline},
		},
	}
	instance := &Server{
		config:      Config{Store: store},
		syncChanges: newSyncChangeHub(),
	}
	instance.syncChanges.configure(runtime)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.SetMetadata(
			syncContextCSNMetadataKey(database.partition),
			[]byte(baseline.raw),
		)
	}); err != nil {
		t.Fatalf("seed sessionlog contextCSN: %v", err)
	}

	rawDN := syncStateFoldOID +
		"= RESEARCH +syncStateExactAlias=Tenant,DC=EXAMPLE,DC=COM"
	entryUUID := "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"
	before := directory.Entry{DN: rawDN, Attributes: []directory.Attribute{{
		Description: "entryUUID",
		Values:      stringValues(entryUUID),
	}}}
	var change *syncChange
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		var err error
		change, err = instance.recordSyncChangeCSN(
			writer,
			runtime,
			database,
			&before,
			nil,
			deletion,
		)
		return err
	})
	if err != nil {
		t.Fatalf("recordSyncChangeCSN(): %v", err)
	}
	wantDN := mustDNIdentitySyncStateDN(t, registry, rawDN).String()
	if change == nil || !change.hasBefore || change.before.DN != wantDN {
		t.Fatalf("normalized sync change = %#v, want before DN %q", change, wantDN)
	}
	if before.DN != rawDN {
		t.Fatalf("recordSyncChangeCSN mutated caller entry DN to %q", before.DN)
	}

	instance.publishSyncChange(change)
	replay, usable := instance.syncChanges.replay(
		database.partition,
		syncCSNState{baseline.serverID: baseline},
		syncCSNState{deletion.serverID: deletion},
	)
	if !usable || len(replay) != 1 || replay[0].before.DN != wantDN {
		t.Fatalf("schema-aware sessionlog replay = %#v, usable %t", replay, usable)
	}

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		stored, exists, err := syncTombstoneCSN(
			reader,
			database.partition,
			"abcdefab-cdef-abcd-efab-cdefabcdefab",
		)
		if err != nil {
			return err
		}
		if !exists || compareOpenLDAPCSN(stored, deletion) != 0 {
			t.Fatalf("case-insensitive UUID tombstone = %#v, exists %t", stored, exists)
		}
		return nil
	}); err != nil {
		t.Fatalf("read sync tombstone: %v", err)
	}

	lower, err := normalizeSyncStateEntry(database, &directory.Entry{
		DN: "syncStateExactName=tenant+syncStateFoldName=research,dc=example,dc=com",
	})
	if err != nil {
		t.Fatalf("normalizeSyncStateEntry(caseExact sibling): %v", err)
	}
	canonicalChangeDN := mustDNIdentitySyncStateDN(t, registry, change.before.DN)
	lowerDN := mustDNIdentitySyncStateDN(t, registry, lower.DN)
	if canonicalChangeDN.Equal(lowerDN) {
		t.Fatal("caseExact sessionlog identities collapsed")
	}

	legacyEntry := directory.Entry{DN: "UID=Legacy,DC=EXAMPLE,DC=COM"}
	legacy, err := normalizeSyncStateEntry(runtimeDatabase{
		name:         "config",
		partition:    "config",
		dnNormalizer: registry,
	}, &legacyEntry)
	if err != nil {
		t.Fatalf("normalizeSyncStateEntry(legacy): %v", err)
	}
	if legacy.DN != legacyEntry.DN {
		t.Fatalf("legacy sync state DN = %q, want %q", legacy.DN, legacyEntry.DN)
	}
}

func newDNIdentitySyncStateRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( " + syncStateExactOID + " NAME ( 'syncStateExactName' 'syncStateExactAlias' ) " +
			"EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( " + syncStateFoldOID + " NAME ( 'syncStateFoldName' 'syncStateFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(): %v", err)
		}
	}
	return registry
}

func syncStateSuffix() string {
	return "syncStateExactName=Tenant+syncStateFoldName=Research," +
		"dc=example,dc=com"
}

func mustDNIdentitySyncStateDN(
	t *testing.T,
	normalizer directory.DNAttributeNormalizer,
	raw string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(raw, normalizer)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", raw, err)
	}
	return dn
}

func mustLegacyDNIdentitySyncStateDN(t *testing.T, raw string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", raw, err)
	}
	return dn
}

func mustDNIdentitySyncStateCSN(t *testing.T, raw string) openLDAPCSN {
	t.Helper()
	csn, err := parseOpenLDAPCSN(raw)
	if err != nil {
		t.Fatalf("parseOpenLDAPCSN(%q): %v", raw, err)
	}
	return csn
}
