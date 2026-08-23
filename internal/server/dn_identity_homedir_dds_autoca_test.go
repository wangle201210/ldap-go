package server

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityRuntimeOverlayPartition = "dn-identity-runtime-overlays"
	dnIdentityRuntimeOverlayBase      = "dc=example,dc=com"
)

func TestDNIdentityAutoCARuntimeScopeAndCandidates(t *testing.T) {
	registry := dnIdentityRuntimeOverlayRegistry(t)
	exactSuffix := dnIdentityRuntimeOverlayDN(
		t,
		registry,
		"runtimeExactName=Tenant",
	)
	foldSuffix := dnIdentityRuntimeOverlayDN(
		t,
		registry,
		"runtimeFoldName=Remote Tenant",
	)

	exactDatabase := runtimeDatabase{
		name:         "{1}mdb",
		partition:    "autoca-exact",
		suffixes:     []directory.DN{exactSuffix},
		dnNormalizer: registry,
	}
	exactDifferentCase := dnIdentityRuntimeOverlayLegacyDN(
		t,
		"runtimeExactName=tenant",
	)
	if err := validateAutoCADatabase(exactDatabase, autoCARuntimeConfiguration{
		configDNKey: "autoca-exact",
		localDN:     &exactDifferentCase,
	}); err == nil {
		t.Fatal("AutoCA accepted a caseExact-different localDN inside the suffix")
	}

	foldDatabase := runtimeDatabase{
		name:         "{2}mdb",
		partition:    "autoca-fold",
		suffixes:     []directory.DN{foldSuffix},
		dnNormalizer: registry,
	}
	foldEquivalentChild := dnIdentityRuntimeOverlayLegacyDN(
		t,
		`cn=ldap,runtimeFoldName=\20REMOTE\20\20TENANT\20`,
	)
	if err := validateAutoCADatabase(foldDatabase, autoCARuntimeConfiguration{
		configDNKey: "autoca-fold",
		localDN:     &foldEquivalentChild,
	}); err != nil {
		t.Fatalf("AutoCA rejected a caseIgnore-equivalent localDN: %v", err)
	}

	for _, backend := range dnIdentityRuntimeOverlayBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			testDNIdentityAutoCACandidates(t, store, registry)
		})
	}
}

func testDNIdentityAutoCACandidates(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	entries := []directory.Entry{
		{DN: "runtimeExactName=Alice," + dnIdentityRuntimeOverlayBase},
		{DN: "runtimeExactName=alice," + dnIdentityRuntimeOverlayBase},
		{DN: "runtimeFoldName=Alice Smith," + dnIdentityRuntimeOverlayBase},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartitionWithNormalizer(
			writer,
			dnIdentityRuntimeOverlayPartition,
			registry,
		)
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed AutoCA candidates: %v", err)
	}

	tests := []struct {
		name string
		base string
		want string
	}{
		{
			name: "caseExact upper",
			base: "runtimeExactName=Alice," + dnIdentityRuntimeOverlayBase,
			want: "runtimeExactName=Alice," + dnIdentityRuntimeOverlayBase,
		},
		{
			name: "caseExact lower",
			base: "runtimeExactName=alice," + dnIdentityRuntimeOverlayBase,
			want: "runtimeExactName=alice," + dnIdentityRuntimeOverlayBase,
		},
		{
			name: "caseIgnore equivalent",
			base: `runtimeFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`,
			want: "runtimeFoldName=Alice Smith," + dnIdentityRuntimeOverlayBase,
		},
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		tx := storage.ReaderInPartitionWithNormalizer(
			reader,
			dnIdentityRuntimeOverlayPartition,
			registry,
		)
		for _, test := range tests {
			base := dnIdentityRuntimeOverlayLegacyDN(t, test.base)
			candidates, err := autoCASearchCandidates(
				tx,
				dnIdentityRuntimeOverlayPartition,
				base,
				directory.ScopeBase,
				make(map[string]struct{}),
			)
			if err != nil {
				return err
			}
			if len(candidates) != 1 || candidates[0].String() != test.want {
				t.Fatalf(
					"AutoCA candidates for %s = %v, want [%s]",
					test.name,
					candidates,
					test.want,
				)
			}
		}
		base := dnIdentityRuntimeOverlayLegacyDN(t, dnIdentityRuntimeOverlayBase)
		candidates, err := autoCASearchCandidates(
			tx,
			dnIdentityRuntimeOverlayPartition,
			base,
			directory.ScopeWholeSubtree,
			make(map[string]struct{}),
		)
		if err != nil {
			return err
		}
		if len(candidates) != len(entries) {
			t.Fatalf(
				"AutoCA subtree candidates = %d, want %d",
				len(candidates),
				len(entries),
			)
		}
		return nil
	}); err != nil {
		t.Fatalf("select AutoCA candidates: %v", err)
	}
}

func TestDNIdentityDDSRuntimeExpiration(t *testing.T) {
	for _, backend := range dnIdentityRuntimeOverlayBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			registry := dnIdentityRuntimeOverlayRegistry(t)
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			testDNIdentityDDSExpiration(t, store, registry)
		})
	}
}

func testDNIdentityDDSExpiration(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	base := dnIdentityRuntimeOverlayDN(t, registry, dnIdentityRuntimeOverlayBase)
	database := runtimeDatabase{
		name:         "{1}mdb",
		partition:    dnIdentityRuntimeOverlayPartition,
		suffixes:     []directory.DN{base},
		dnNormalizer: registry,
		dds: &ddsRuntimeConfiguration{
			enabled:   true,
			tolerance: 0,
		},
	}
	exactUpperDN := "runtimeExactName=Alice," + dnIdentityRuntimeOverlayBase
	exactLowerChildDN := "cn=lower-child,runtimeExactName=alice," +
		dnIdentityRuntimeOverlayBase
	foldParentDN := "runtimeFoldName=Alice Smith," + dnIdentityRuntimeOverlayBase
	foldEquivalentChildDN := `cn=fold-child,runtimeFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`
	entries := []directory.Entry{
		ddsDNIdentityRuntimeEntry(exactUpperDN, now.Add(-time.Minute), true),
		ddsDNIdentityRuntimeEntry(exactLowerChildDN, now.Add(time.Hour), false),
		ddsDNIdentityRuntimeEntry(foldParentDN, now.Add(-time.Minute), true),
		ddsDNIdentityRuntimeEntry(foldEquivalentChildDN, now.Add(time.Hour), false),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartitionWithNormalizer(
			writer,
			database.partition,
			registry,
		)
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed DDS identity hierarchy: %v", err)
	}

	exactLower := dnIdentityRuntimeOverlayLegacyDN(
		t,
		"runtimeExactName=alice,"+dnIdentityRuntimeOverlayBase,
	)
	if databaseHasExactSuffix(runtimeDatabase{
		suffixes:     []directory.DN{dnIdentityRuntimeOverlayDN(t, registry, exactUpperDN)},
		dnNormalizer: registry,
	}, exactLower) {
		t.Fatal("DDS treated a caseExact-different DN as the exact suffix")
	}
	foldEquivalent := dnIdentityRuntimeOverlayLegacyDN(
		t,
		`runtimeFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`,
	)
	if !databaseHasExactSuffix(runtimeDatabase{
		suffixes: []directory.DN{
			dnIdentityRuntimeOverlayDN(t, registry, foldParentDN),
		},
		dnNormalizer: registry,
	}, foldEquivalent) {
		t.Fatal("DDS did not recognize a caseIgnore-equivalent exact suffix")
	}

	runtime := &runtimeState{
		schema:    registry,
		databases: []runtimeDatabase{database},
	}
	server := &Server{config: Config{Store: store}}
	server.runtime.Store(runtime)
	if err := server.expireDDSDatabase(context.Background(), database, now); err != nil {
		t.Fatalf("expireDDSDatabase(): %v", err)
	}

	assertDNIdentityRuntimeOverlayStored(
		t,
		store,
		database,
		registry,
		exactUpperDN,
		false,
	)
	assertDNIdentityRuntimeOverlayStored(
		t,
		store,
		database,
		registry,
		exactLowerChildDN,
		true,
	)
	assertDNIdentityRuntimeOverlayStored(
		t,
		store,
		database,
		registry,
		foldParentDN,
		true,
	)
}

func TestDNIdentityHomedirRuntimeTrackingAndScope(t *testing.T) {
	for _, backend := range dnIdentityRuntimeOverlayBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			registry := dnIdentityRuntimeOverlayRegistry(t)
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			testDNIdentityHomedirTrackingAndScope(t, store, registry)
		})
	}
}

func testDNIdentityHomedirTrackingAndScope(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	base := dnIdentityRuntimeOverlayDN(t, registry, dnIdentityRuntimeOverlayBase)
	database := runtimeDatabase{
		name:         "{1}mdb",
		partition:    dnIdentityRuntimeOverlayPartition,
		suffixes:     []directory.DN{base},
		dnNormalizer: registry,
		homedir:      &homedirRuntimeConfiguration{},
	}
	runtime := &runtimeState{
		schema:    registry,
		databases: []runtimeDatabase{database},
	}
	exactUpperDN := "runtimeExactName=Alice," + dnIdentityRuntimeOverlayBase
	exactLowerDN := "runtimeExactName=alice," + dnIdentityRuntimeOverlayBase
	foldDN := "runtimeFoldName=Alice Smith," + dnIdentityRuntimeOverlayBase
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartitionWithNormalizer(
			writer,
			database.partition,
			registry,
		)
		for _, entry := range []directory.Entry{
			{DN: exactUpperDN},
			{DN: exactLowerDN},
			{DN: foldDN},
		} {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed homedir identity entries: %v", err)
	}

	var exactChanges []homedirStorageChange
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tracker := newHomedirTrackingWriter(writer, runtime)
		tx := writerForDatabase(tracker, database)
		for index, rawDN := range []string{exactUpperDN, exactLowerDN} {
			dn := dnIdentityRuntimeOverlayLegacyDN(t, rawDN)
			entry, err := tx.Get(dn)
			if err != nil {
				return err
			}
			entry.ReplaceValues("homeDirectory", stringValues("/home/exact-"+string(rune('0'+index))))
			if err := tx.Put(entry, true); err != nil {
				return err
			}
		}
		exactChanges = tracker.changes()
		return nil
	}); err != nil {
		t.Fatalf("track caseExact homedir changes: %v", err)
	}
	if len(exactChanges) != 2 {
		t.Fatalf("caseExact homedir changes = %d, want 2", len(exactChanges))
	}

	var foldChanges []homedirStorageChange
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tracker := newHomedirTrackingWriter(writer, runtime)
		tx := writerForDatabase(tracker, database)
		for index, rawDN := range []string{
			foldDN,
			`runtimeFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`,
		} {
			dn := dnIdentityRuntimeOverlayLegacyDN(t, rawDN)
			entry, err := tx.Get(dn)
			if err != nil {
				return err
			}
			entry.ReplaceValues("homeDirectory", stringValues("/home/fold-"+string(rune('0'+index))))
			if err := tx.Put(entry, true); err != nil {
				return err
			}
		}
		foldChanges = tracker.changes()
		return nil
	}); err != nil {
		t.Fatalf("track caseIgnore homedir changes: %v", err)
	}
	if len(foldChanges) != 1 {
		t.Fatalf("caseIgnore-equivalent homedir changes = %d, want 1", len(foldChanges))
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tracker := newHomedirTrackingWriter(writer, runtime)
		equivalent := dnIdentityRuntimeOverlayLegacyDN(
			t,
			`runtimeFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`,
		)
		if err := tracker.DeleteIn(database.partition, equivalent); err != nil {
			return err
		}
		if changes := tracker.changes(); len(changes) != 1 ||
			changes[0].before == nil || changes[0].after != nil {
			t.Fatalf("caseIgnore-equivalent homedir delete changes = %#v", changes)
		}
		return nil
	}); err != nil {
		t.Fatalf("track caseIgnore-equivalent homedir delete: %v", err)
	}
	assertDNIdentityRuntimeOverlayStored(
		t,
		store,
		database,
		registry,
		foldDN,
		false,
	)

	exactDifferentCase := dnIdentityRuntimeOverlayLegacyDN(t, exactLowerDN)
	exactScopedDatabase := database
	exactScopedDatabase.suffixes = []directory.DN{
		dnIdentityRuntimeOverlayDN(t, registry, exactUpperDN),
	}
	exactScopedRuntime := &runtimeState{databases: []runtimeDatabase{exactScopedDatabase}}
	if configurations := homedirConfigurationsForEntry(
		exactScopedRuntime,
		database.partition,
		exactDifferentCase,
	); len(configurations) != 0 {
		t.Fatal("homedir selected a caseExact-different suffix")
	}

	foldEquivalent := dnIdentityRuntimeOverlayLegacyDN(
		t,
		`runtimeFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`,
	)
	foldScopedDatabase := database
	foldScopedDatabase.suffixes = []directory.DN{
		dnIdentityRuntimeOverlayDN(t, registry, foldDN),
	}
	foldScopedRuntime := &runtimeState{databases: []runtimeDatabase{foldScopedDatabase}}
	if configurations := homedirConfigurationsForEntry(
		foldScopedRuntime,
		database.partition,
		foldEquivalent,
	); len(configurations) != 1 {
		t.Fatalf(
			"homedir caseIgnore-equivalent configurations = %d, want 1",
			len(configurations),
		)
	}
}

func ddsDNIdentityRuntimeEntry(
	dn string,
	expires time.Time,
	dynamic bool,
) directory.Entry {
	classes := []string{"top", "organizationalRole"}
	if dynamic {
		classes = append(classes, "dynamicObject")
	}
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues(classes...)},
			{Description: "cn", Values: stringValues("identity runtime entry")},
			{Description: "entryTtl", Values: stringValues("60")},
			{
				Description: "entryExpireTimestamp",
				Values:      stringValues(formatDDSExpiration(expires)),
			},
		},
	}
}

func assertDNIdentityRuntimeOverlayStored(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	registry *schema.Registry,
	rawDN string,
	want bool,
) {
	t.Helper()
	dn := dnIdentityRuntimeOverlayLegacyDN(t, rawDN)
	err := store.View(context.Background(), func(reader storage.Reader) error {
		tx := storage.ReaderInPartitionWithNormalizer(
			reader,
			database.partition,
			registry,
		)
		_, err := tx.Get(dn)
		return err
	})
	switch {
	case err == nil && want:
	case errors.Is(err, storage.ErrEntryNotFound) && !want:
	case err != nil:
		t.Fatalf("read stored DN %q: %v", rawDN, err)
	default:
		t.Fatalf("stored DN %q exists = %t, want %t", rawDN, err == nil, want)
	}
}

func dnIdentityRuntimeOverlayRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.920.1 NAME 'runtimeExactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.920.2 NAME 'runtimeFoldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityRuntimeOverlayDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(value, registry)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", value, err)
	}
	return dn
}

func dnIdentityRuntimeOverlayLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

type dnIdentityRuntimeOverlayBackend struct {
	name string
	open func(*testing.T) storage.Store
}

func dnIdentityRuntimeOverlayBackends() []dnIdentityRuntimeOverlayBackend {
	return []dnIdentityRuntimeOverlayBackend{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) storage.Store {
				t.Helper()
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}
}
