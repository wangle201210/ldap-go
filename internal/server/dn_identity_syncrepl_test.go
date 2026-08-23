package server

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentitySyncreplPaths(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
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
			t.Run("refresh", func(t *testing.T) {
				testDNIdentitySyncreplRefresh(t, backend.open)
			})
			t.Run("accesslog", func(t *testing.T) {
				testDNIdentitySyncreplAccesslog(t, backend.open)
			})
			t.Run("changelog", func(t *testing.T) {
				testDNIdentitySyncreplChangelog(t, backend.open)
			})
			t.Run("changelog_snapshot", func(t *testing.T) {
				testDNIdentitySyncreplChangelogSnapshot(t, backend.open)
			})
		})
	}
}

func TestDNIdentityAccesslogConfiguration(t *testing.T) {
	registry := newDNIdentityRegistry(t)
	sourceSuffix := mustDNIdentityDN(t, registry, "dc=example,dc=com")
	targetSuffix := mustDNIdentityDN(t, registry, "cn=log")
	configuration := &accesslogRuntimeConfiguration{
		targetSuffix: mustLegacyDNIdentityDN(t, "CN=LOG"),
		bases: []accesslogBaseConfiguration{
			{
				operations: accesslogModify,
				base: mustLegacyDNIdentityDN(
					t,
					"exactName=Alice,dc=example,dc=com",
				),
			},
			{
				operations: accesslogDelete,
				base: mustLegacyDNIdentityDN(
					t,
					"foldName=Alice Smith,dc=example,dc=com",
				),
			},
		},
	}
	databases := []runtimeDatabase{
		{
			name: "mdb", partition: "source",
			suffixes: []directory.DN{sourceSuffix}, dnNormalizer: registry,
			accesslog: configuration,
		},
		{
			name: "mdb", partition: "accesslog",
			suffixes: []directory.DN{targetSuffix}, dnNormalizer: registry,
		},
	}
	if err := resolveAccesslogDatabases(databases); err != nil {
		t.Fatalf("resolveAccesslogDatabases(): %v", err)
	}
	if !configuration.targetSuffix.Equal(targetSuffix) {
		t.Fatalf(
			"resolved accesslog target = %q, want %q",
			configuration.targetSuffix.String(),
			targetSuffix.String(),
		)
	}
	if accesslogConfigurationApplies(
		configuration,
		accesslogModify,
		mustDNIdentityDN(t, registry, "exactName=alice,dc=example,dc=com"),
	) {
		t.Fatal("caseExact accesslog base matched a differently cased DN")
	}
	if !accesslogConfigurationApplies(
		configuration,
		accesslogModify,
		mustDNIdentityDN(t, registry, "exactName=Alice,DC=EXAMPLE,DC=COM"),
	) {
		t.Fatal("caseExact accesslog base did not match its schema-equivalent DN")
	}
	if !accesslogConfigurationApplies(
		configuration,
		accesslogDelete,
		mustDNIdentityDN(
			t,
			registry,
			"foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
		),
	) {
		t.Fatal("caseIgnore accesslog base did not match its schema-equivalent DN")
	}

	entry := directory.Entry{}
	observation := &operationAuditObservation{message: ldapwire.Message{
		Request: ldapwire.ModifyDNRequest{
			DN:             "exactName=Alice,dc=example,dc=com",
			NewRDN:         "exactName=Alice",
			DeleteOldRDN:   true,
			NewSuperior:    "CN=DESTINATION,DC=EXAMPLE,DC=COM",
			HasNewSuperior: true,
		},
	}}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return (&Server{}).populateObservedAccesslogRequest(
			reader,
			&runtimeState{schema: registry, databases: databases},
			databases[0],
			configuration,
			observation,
			accesslogModifyDN,
			mustDNIdentityDN(
				t,
				registry,
				"exactName=Alice,dc=example,dc=com",
			),
			&entry,
		)
	}); err != nil {
		t.Fatalf("populateObservedAccesslogRequest(): %v", err)
	}
	assertDNIdentityAttributeDN(
		t,
		registry,
		entry,
		"reqNewSuperior",
		"cn=destination,dc=example,dc=com",
	)
	assertDNIdentityAttributeDN(
		t,
		registry,
		entry,
		"reqNewDN",
		"exactName=Alice,cn=destination,dc=example,dc=com",
	)
}

func testDNIdentitySyncreplRefresh(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	server, store, config := newDNIdentitySyncreplServer(t, openStore)
	upperUUID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	lowerUUID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	foldUUID := uuid.MustParse("33333333-3333-3333-3333-333333333333")

	applyDNIdentitySyncEntry(t, server, config, upperUUID,
		"exactName=Alice,dc=example,dc=com", "Upper", "exactName", "Alice", 1)
	applyDNIdentitySyncEntry(t, server, config, lowerUUID,
		"exactName=alice,dc=example,dc=com", "Lower", "exactName", "alice", 2)
	applyDNIdentitySyncEntry(t, server, config, foldUUID,
		"foldName=Alice Smith,dc=example,dc=com", "Fold", "foldName", "Alice Smith", 3)

	applyDNIdentitySyncEntry(t, server, config, upperUUID,
		"exactName=ALICE,dc=example,dc=com", "Upper Renamed", "exactName", "ALICE", 4)
	applyDNIdentitySyncEntry(t, server, config, foldUUID,
		"foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
		"Fold Refreshed", "foldName", " ALICE  SMITH ", 5)
	assertDNIdentitySyncreplEntry(t, store, config,
		"exactName=ALICE,dc=example,dc=com", "Upper Renamed")
	assertDNIdentitySyncreplEntry(t, store, config,
		"exactName=alice,dc=example,dc=com", "Lower")
	assertDNIdentitySyncreplEntry(t, store, config,
		"foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
		"Fold Refreshed")
	assertDNIdentitySyncreplUUIDCount(t, store, config, foldUUID.String(), 1)
}

func testDNIdentitySyncreplAccesslog(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	server, store, config := newDNIdentitySyncreplServer(t, openStore)
	seedDNIdentitySyncreplEntries(t, store, config, []directory.Entry{
		dnIdentitySyncEntry("exactName=Alice,dc=example,dc=com", "Upper", "exactName", "Alice", "11111111-1111-1111-1111-111111111111"),
		dnIdentitySyncEntry("exactName=alice,dc=example,dc=com", "Lower", "exactName", "alice", "22222222-2222-2222-2222-222222222222"),
		dnIdentitySyncEntry("foldName=Alice Smith,dc=example,dc=com", "Fold", "foldName", "Alice Smith", "33333333-3333-3333-3333-333333333333"),
		dnIdentitySyncEntry("cn=destination,dc=example,dc=com", "Destination", "cn", "destination", "44444444-4444-4444-4444-444444444444"),
	})

	modifyCSN := "20260813010101.000001Z#000000#001#000000"
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(), config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260813010101.000001Z,cn=log",
			"foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
			"modify", modifyCSN, []string{"cn:= Fold Modified"}, nil,
		),
		syncConsumerAccesslogTestCookie(modifyCSN),
	); err != nil {
		t.Fatalf("apply caseIgnore accesslog modify: %v", err)
	}
	assertDNIdentitySyncreplEntry(t, store, config,
		"foldName=alice smith,dc=example,dc=com", "Fold Modified")

	renameCSN := "20260813010102.000001Z#000000#001#000000"
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(), config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260813010102.000001Z,cn=log",
			"exactName=Alice,dc=example,dc=com",
			"modrdn", renameCSN, nil,
			map[string][]string{
				"reqNewRDN":       {"exactName=Alice"},
				"reqDeleteOldRDN": {"TRUE"},
				"reqNewSuperior":  {"CN=DESTINATION,DC=EXAMPLE,DC=COM"},
			},
		),
		syncConsumerAccesslogTestCookie(renameCSN),
	); err != nil {
		t.Fatalf("apply caseExact accesslog modrdn: %v", err)
	}
	assertDNIdentitySyncreplEntry(t, store, config,
		"exactName=Alice,cn=destination,dc=example,dc=com", "Upper")
	assertDNIdentitySyncreplEntry(t, store, config,
		"exactName=alice,dc=example,dc=com", "Lower")
}

func testDNIdentitySyncreplChangelog(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	server, store, config := newDNIdentitySyncreplServer(t, openStore)
	config.syncData = "changelog"
	seedDNIdentitySyncreplEntries(t, store, config, []directory.Entry{
		dnIdentitySyncEntry("exactName=Alice,dc=example,dc=com", "Upper", "exactName", "Alice", "11111111-1111-1111-1111-111111111111"),
		dnIdentitySyncEntry("exactName=alice,dc=example,dc=com", "Lower", "exactName", "alice", "22222222-2222-2222-2222-222222222222"),
		dnIdentitySyncEntry("foldName=Alice Smith,dc=example,dc=com", "Fold", "foldName", "Alice Smith", "33333333-3333-3333-3333-333333333333"),
		dnIdentitySyncEntry("cn=destination,dc=example,dc=com", "Destination", "cn", "destination", "44444444-4444-4444-4444-444444444444"),
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return updateSyncConsumerChangelogState(writer, config, 0)
	}); err != nil {
		t.Fatalf("seed changelog state: %v", err)
	}

	if err := server.applySyncConsumerChangelogEntry(
		context.Background(), config,
		syncConsumerChangelogTestEntry(
			1,
			"foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
			"modify", "replace: cn\ncn: Fold Changed\n-", nil,
		),
	); err != nil {
		t.Fatalf("apply caseIgnore changelog modify: %v", err)
	}
	assertDNIdentitySyncreplEntry(t, store, config,
		"foldName=alice smith,dc=example,dc=com", "Fold Changed")

	if err := server.applySyncConsumerChangelogEntry(
		context.Background(), config,
		syncConsumerChangelogTestEntry(
			2, "exactName=Alice,dc=example,dc=com", "modrdn", "",
			map[string][]string{
				"newRDN":       {"exactName=Alice"},
				"deleteOldRDN": {"TRUE"},
				"newSuperior":  {"CN=DESTINATION,DC=EXAMPLE,DC=COM"},
			},
		),
	); err != nil {
		t.Fatalf("apply caseExact changelog modrdn: %v", err)
	}
	assertDNIdentitySyncreplEntry(t, store, config,
		"exactName=Alice,cn=destination,dc=example,dc=com", "Upper")
	assertDNIdentitySyncreplEntry(t, store, config,
		"exactName=alice,dc=example,dc=com", "Lower")
}

func testDNIdentitySyncreplChangelogSnapshot(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	server, store, config := newDNIdentitySyncreplServer(t, openStore)
	seedDNIdentitySyncreplEntries(t, store, config, []directory.Entry{
		dnIdentitySyncEntry("exactName=Alice,dc=example,dc=com", "Upper", "exactName", "Alice", "11111111-1111-1111-1111-111111111111"),
		dnIdentitySyncEntry("exactName=alice,dc=example,dc=com", "Lower", "exactName", "alice", "22222222-2222-2222-2222-222222222222"),
	})
	seen := map[string]struct{}{
		mustDNIdentityDN(t, config.normalizer, "dc=example,dc=com").Key(): {},
		mustDNIdentityDN(
			t,
			config.normalizer,
			"exactName=Alice,dc=example,dc=com",
		).Key(): {},
	}
	if err := server.finishSyncConsumerChangelogSnapshot(
		context.Background(),
		config,
		seen,
		7,
	); err != nil {
		t.Fatalf("finishSyncConsumerChangelogSnapshot(): %v", err)
	}
	assertDNIdentitySyncreplEntry(t, store, config,
		"exactName=Alice,dc=example,dc=com", "Upper")
	assertDNIdentitySyncreplEntryMissing(t, store, config,
		"exactName=alice,dc=example,dc=com")
}

func newDNIdentitySyncreplServer(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) (*Server, storage.Store, syncConsumerConfig) {
	t.Helper()
	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	registry := newDNIdentityRegistry(t)
	filter, err := compileSyncConsumerFilter("(objectClass=*)")
	if err != nil {
		t.Fatalf("compileSyncConsumerFilter(): %v", err)
	}
	base, err := registry.NormalizeDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("NormalizeDN(base): %v", err)
	}
	config := syncConsumerConfig{
		rid:            1,
		partition:      "dn-identity-syncrepl",
		normalizer:     registry,
		searchBase:     base,
		localBase:      base,
		filterText:     "(objectClass=*)",
		filter:         filter,
		scope:          directory.ScopeWholeSubtree,
		schemaChecking: false,
	}
	instance, err := New(Config{Store: store, Schema: registry})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	instance.runtime.Store(&runtimeState{
		schema: registry,
		databases: []runtimeDatabase{{
			name: "mdb", partition: config.partition,
			suffixes: []directory.DN{base}, dnNormalizer: registry,
		}},
	})
	seedDNIdentitySyncreplEntries(t, store, config, []directory.Entry{
		dnIdentitySyncEntry("dc=example,dc=com", "Base", "dc", "example", "00000000-0000-0000-0000-000000000001"),
	})
	return instance, store, config
}

func newDNIdentityRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.915.1 NAME 'exactName' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.915.2 NAME 'foldName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(): %v", err)
		}
	}
	return registry
}

func applyDNIdentitySyncEntry(
	t *testing.T,
	server *Server,
	config syncConsumerConfig,
	identifier uuid.UUID,
	dn, commonName, namingAttribute, namingValue string,
	sequence int,
) {
	t.Helper()
	entry := ldap.NewEntry(dn, map[string][]string{
		"objectClass":   {"top"},
		"cn":            {commonName},
		namingAttribute: {namingValue},
	})
	if err := server.applySyncConsumerEntry(
		context.Background(), config, entry,
		&ldap.ControlSyncState{State: ldap.SyncStateModify, EntryUUID: identifier},
	); err != nil {
		t.Fatalf("apply sync entry %d %q: %v", sequence, dn, err)
	}
}

func dnIdentitySyncEntry(
	dn, commonName, namingAttribute, namingValue, identifier string,
) directory.Entry {
	return directory.Entry{DN: dn, Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues("top")},
		{Description: "cn", Values: stringValues(commonName)},
		{Description: namingAttribute, Values: stringValues(namingValue)},
		{Description: "entryUUID", Values: stringValues(identifier)},
	}}
}

func seedDNIdentitySyncreplEntries(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	entries []directory.Entry,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		content := syncConsumerWriter(writer, nil, config)
		for _, entry := range entries {
			if err := content.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed DN identity syncrepl entries: %v", err)
	}
}

func assertDNIdentitySyncreplEntry(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	rawDN, wantCN string,
) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	var entry directory.Entry
	err = store.View(context.Background(), func(reader storage.Reader) error {
		var readErr error
		entry, readErr = syncConsumerReader(reader, nil, config).Get(dn)
		return readErr
	})
	if err != nil {
		if errors.Is(err, storage.ErrEntryNotFound) {
			t.Fatalf("entry %q is missing", rawDN)
		}
		t.Fatalf("read %q: %v", rawDN, err)
	}
	values := entry.Values("cn")
	if len(values) != 1 || string(values[0]) != wantCN {
		t.Fatalf("%q cn = %q, want %q", rawDN, values, wantCN)
	}
}

func assertDNIdentitySyncreplEntryMissing(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	rawDN string,
) {
	t.Helper()
	dn := mustLegacyDNIdentityDN(t, rawDN)
	err := store.View(context.Background(), func(reader storage.Reader) error {
		_, readErr := syncConsumerReader(reader, nil, config).Get(dn)
		return readErr
	})
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("missing entry %q lookup error = %v", rawDN, err)
	}
}

func assertDNIdentitySyncreplUUIDCount(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	identifier string,
	want int,
) {
	t.Helper()
	count := 0
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return reader.ForEachIn(config.partition, func(entry directory.Entry) error {
			values := entry.Values("entryUUID")
			if len(values) == 1 && string(values[0]) == identifier {
				count++
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("count entryUUID %q: %v", identifier, err)
	}
	if count != want {
		t.Fatalf("entryUUID %q count = %d, want %d", identifier, count, want)
	}
}

func assertDNIdentityAttributeDN(
	t *testing.T,
	normalizer directory.DNAttributeNormalizer,
	entry directory.Entry,
	description,
	wantRaw string,
) {
	t.Helper()
	values := entry.Values(description)
	if len(values) != 1 {
		t.Fatalf("%s values = %q, want one DN", description, values)
	}
	got := mustDNIdentityDN(t, normalizer, string(values[0]))
	want := mustDNIdentityDN(t, normalizer, wantRaw)
	if !got.Equal(want) {
		t.Fatalf("%s = %q, want DN-equivalent to %q", description, values[0], wantRaw)
	}
}

func mustDNIdentityDN(
	t *testing.T,
	normalizer directory.DNAttributeNormalizer,
	rawDN string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(rawDN, normalizer)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", rawDN, err)
	}
	return dn
}

func mustLegacyDNIdentityDN(t *testing.T, rawDN string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	return dn
}
