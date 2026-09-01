package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDatabaseUsesRuntimeDNIdentity(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	other, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(other): %v", err)
	}
	for _, database := range []runtimeDatabase{
		{name: "{1}mdb", partition: "db", dnNormalizer: registry},
		{name: "{1}mdb", partition: "db", dnNormalizer: &databaseEqualityIndexNormalizer{registry: registry}},
	} {
		if !databaseUsesRuntimeDNIdentity(database, registry) {
			t.Fatalf("database normalizer %T did not reuse runtime identity", database.dnNormalizer)
		}
		if databaseUsesRuntimeDNIdentity(database, other) {
			t.Fatalf("database normalizer %T reused another registry", database.dnNormalizer)
		}
		base, err := registry.NormalizeDN("ou=people,dc=example,dc=com")
		if err != nil || !databaseCanReuseSearchBase(database, registry, base) {
			t.Fatalf("database normalizer %T did not reuse common base: %v", database.dnNormalizer, err)
		}
	}
	if databaseUsesRuntimeDNIdentity(runtimeDatabase{}, registry) {
		t.Fatal("database without a normalizer reused runtime identity")
	}
}

func TestLoadRuntimeDatabasesIgnoresBusinessConfigurationAttributes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "uid=attacker,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcRootDN", Values: stringValues("uid=attacker,dc=example,dc=com")},
			{Description: "olcRootPW", Values: stringValues("secret")},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		if err := tx.Put(entry, false); err != nil {
			return err
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	dn, err := directory.ParseDN("uid=attacker,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	index := databaseIndexForDN(databases, dn)
	if index < 0 {
		t.Fatal("bootstrap naming context was not loaded")
	}
	if databases[index].rootDN != nil || databases[index].rootPasswordSet {
		t.Fatal("business entry created a runtime database root")
	}
}

func TestLoadRuntimeDatabasesRejectsDuplicateSuffixes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
		t.Fatal("duplicate database suffixes were accepted")
	}
}

func TestLoadRuntimeDatabasesAppliesOperationalSettings(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				{Description: "olcReadOnly", Values: stringValues("TRUE")},
				{Description: "olcMaxDerefDepth", Values: stringValues("9")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcReadOnly", Values: stringValues("FALSE")},
				{Description: "olcLastMod", Values: stringValues("FALSE")},
				{Description: "olcMaxDerefDepth", Values: stringValues("3")},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=other,dc=com")},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return tx.SetNamingContexts([]string{
			"dc=example,dc=com",
			"dc=other,dc=com",
			"dc=bootstrap,dc=com",
		})
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	exampleDN, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(example): %v", err)
	}
	example := databases[databaseIndexForDN(databases, exampleDN)]
	if !example.readOnly {
		t.Fatal("frontend olcReadOnly did not restrict an explicitly writable database")
	}
	if example.lastMod {
		t.Fatal("database olcLastMod FALSE was ignored")
	}
	if example.maxDerefDepth != 3 {
		t.Fatalf(
			"database olcMaxDerefDepth = %d, want 3",
			example.maxDerefDepth,
		)
	}

	otherDN, err := directory.ParseDN("dc=other,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(other): %v", err)
	}
	other := databases[databaseIndexForDN(databases, otherDN)]
	if !other.readOnly {
		t.Fatal("frontend olcReadOnly was not inherited")
	}
	if !other.lastMod {
		t.Fatal("olcLastMod did not default to TRUE")
	}
	if other.maxDerefDepth != defaultAliasDerefDepth {
		t.Fatalf(
			"default olcMaxDerefDepth = %d, want %d",
			other.maxDerefDepth,
			defaultAliasDerefDepth,
		)
	}

	bootstrapDN, err := directory.ParseDN("dc=bootstrap,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(bootstrap): %v", err)
	}
	bootstrap := databases[databaseIndexForDN(databases, bootstrapDN)]
	if !bootstrap.readOnly {
		t.Fatal("frontend olcReadOnly was not inherited by a bootstrap database")
	}
	if bootstrap.maxDerefDepth != defaultAliasDerefDepth {
		t.Fatalf(
			"bootstrap olcMaxDerefDepth = %d, want %d",
			bootstrap.maxDerefDepth,
			defaultAliasDerefDepth,
		)
	}
}

func TestLoadRuntimeDatabasesLoadsServerSideSortOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
				{Description: "olcSssVlvMax", Values: stringValues("2")},
				{Description: "olcSssVlvMaxKeys", Values: stringValues("3")},
				{Description: "olcSssVlvMaxPerConn", Values: stringValues("4")},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=default,dc=com")},
			},
		},
		{
			DN: "olcOverlay={0}sssvlv,olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcOverlay",
				Values:      stringValues("{0}sssvlv"),
			}},
		},
		{
			DN: "uid=not-config,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("sssvlv")},
				{Description: "olcSssVlvMaxKeys", Values: stringValues("-1")},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	dn, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databases[databaseIndexForDN(databases, dn)]
	if !database.serverSideSort ||
		database.sortMaxKeys != 3 ||
		database.sortLimiter == nil ||
		database.sortLimiter.max != 2 ||
		database.sortLimiter.maxPerConn != 4 {
		t.Fatalf("server-side sort database = %#v", database)
	}

	defaultDN, err := directory.ParseDN("dc=default,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(default): %v", err)
	}
	defaultDatabase := databases[databaseIndexForDN(databases, defaultDN)]
	if !defaultDatabase.serverSideSort ||
		defaultDatabase.sortMaxKeys != defaultServerSideSortMaxKeys ||
		defaultDatabase.sortLimiter == nil ||
		defaultDatabase.sortLimiter.max != defaultServerSideSortMax ||
		defaultDatabase.sortLimiter.maxPerConn !=
			defaultServerSideSortMaxPerConn {
		t.Fatalf("default server-side sort database = %#v", defaultDatabase)
	}
}

func TestLoadRuntimeDatabasesLoadsSyncProviderSettings(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcLastMod", Values: stringValues("TRUE")},
			},
		},
		{
			DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}syncprov")},
				{Description: "olcSpCheckpoint", Values: stringValues("100 10")},
				{Description: "olcSpSessionlog", Values: stringValues("250")},
				{Description: "olcSpNoPresent", Values: stringValues("TRUE")},
				{Description: "olcSpReloadHint", Values: stringValues("TRUE")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed syncprov settings: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databases[databaseIndexForDN(databases, suffix)]
	if !database.syncProvider ||
		database.syncCheckpointOps != 100 ||
		database.syncCheckpointMinutes != 10 ||
		database.syncSessionLogSize != 250 ||
		!database.syncNoPresent ||
		!database.syncReloadHint {
		t.Fatalf("sync provider settings = %#v", database)
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidSyncProviderSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		attribute string
		values    []string
	}{
		{
			name:      "checkpoint field count",
			attribute: "olcSpCheckpoint",
			values:    []string{"100"},
		},
		{
			name:      "checkpoint zero operations",
			attribute: "olcSpCheckpoint",
			values:    []string{"0 10"},
		},
		{
			name:      "checkpoint zero minutes",
			attribute: "olcSpCheckpoint",
			values:    []string{"100 0"},
		},
		{
			name:      "checkpoint duplicate",
			attribute: "olcSpCheckpoint",
			values:    []string{"100 10", "200 20"},
		},
		{
			name:      "negative sessionlog",
			attribute: "olcSpSessionlog",
			values:    []string{"-1"},
		},
		{
			name:      "invalid nopresent",
			attribute: "olcSpNoPresent",
			values:    []string{"sometimes"},
		},
		{
			name:      "invalid reloadhint",
			attribute: "olcSpReloadHint",
			values:    []string{"sometimes"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			overlay := directory.Entry{
				DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcOverlay",
						Values:      stringValues("{0}syncprov"),
					},
					{
						Description: test.attribute,
						Values:      stringValues(test.values...),
					},
				},
			}
			if err := store.Update(
				context.Background(),
				func(writer storage.Writer) error {
					if err := writer.Put(directory.Entry{
						DN: "olcDatabase={1}mdb,cn=config",
						Attributes: []directory.Attribute{
							{
								Description: "olcDatabase",
								Values:      stringValues("{1}mdb"),
							},
							{
								Description: "olcSuffix",
								Values: stringValues(
									"dc=example,dc=com",
								),
							},
						},
					}, false); err != nil {
						return err
					}
					return writer.Put(overlay, false)
				},
			); err != nil {
				t.Fatalf("seed invalid syncprov setting: %v", err)
			}
			if _, err := loadRuntimeDatabases(
				context.Background(),
				store,
			); err == nil {
				t.Fatalf(
					"invalid %s values %q were accepted",
					test.attribute,
					test.values,
				)
			}
		})
	}
}

func TestServerSideSortSettingsFollowTargetAndFrontend(t *testing.T) {
	t.Parallel()

	databases := []runtimeDatabase{
		{name: "{-1}frontend"},
		{
			name:           "{1}mdb",
			serverSideSort: true,
			sortMaxKeys:    2,
			sortLimiter:    &serverSideSortLimiter{},
		},
		{name: "{2}mdb"},
	}
	if maxKeys, enabled := serverSideSortSettingsForDatabase(
		databases,
		1,
	); !enabled || maxKeys != 2 {
		t.Fatalf("target sort settings = %d, %t", maxKeys, enabled)
	}
	if _, enabled := serverSideSortSettingsForDatabase(
		databases,
		2,
	); enabled {
		t.Fatal("unconfigured target inherited a database-local overlay")
	}

	databases[0].serverSideSort = true
	databases[0].sortMaxKeys = 4
	databases[0].sortLimiter = &serverSideSortLimiter{}
	if maxKeys, enabled := serverSideSortSettingsForDatabase(
		databases,
		2,
	); !enabled || maxKeys != 4 {
		t.Fatalf("frontend sort settings = %d, %t", maxKeys, enabled)
	}

	databases[0].sortMaxKeys = 1
	if maxKeys, enabled := serverSideSortSettingsForDatabase(
		databases,
		1,
	); !enabled || maxKeys != 1 {
		t.Fatalf("combined sort settings = %d, %t", maxKeys, enabled)
	}
	if limiters := serverSideSortLimitersForDatabase(databases, 1); len(limiters) != 2 ||
		limiters[0] != databases[1].sortLimiter ||
		limiters[1] != databases[0].sortLimiter {
		t.Fatalf("combined sort limiters = %#v", limiters)
	}
	if limiters := serverSideSortLimitersForDatabase(databases, 2); len(limiters) != 1 ||
		limiters[0] != databases[0].sortLimiter {
		t.Fatalf("frontend sort limiters = %#v", limiters)
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidServerSideSortOverlay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		overlays []directory.Entry
	}{
		{
			name: "invalid maximum keys",
			overlays: []directory.Entry{{
				DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
					{Description: "olcSssVlvMaxKeys", Values: stringValues("-1")},
				},
			}},
		},
		{
			name: "invalid maximum requests",
			overlays: []directory.Entry{{
				DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
					{Description: "olcSssVlvMax", Values: stringValues("-1")},
				},
			}},
		},
		{
			name: "multiple per-connection maxima",
			overlays: []directory.Entry{{
				DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
					{
						Description: "olcSssVlvMaxPerConn",
						Values:      stringValues("1", "2"),
					},
				},
			}},
		},
		{
			name: "duplicate overlay",
			overlays: []directory.Entry{
				{
					DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
					},
				},
				{
					DN: "olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcOverlay", Values: stringValues("{1}sssvlv")},
					},
				},
			},
		},
		{
			name: "orphan overlay",
			overlays: []directory.Entry{{
				DN: "olcOverlay={0}sssvlv,olcDatabase={9}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
				},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			database := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				},
			}
			if err := store.Update(context.Background(), func(tx storage.Writer) error {
				if err := tx.Put(database, false); err != nil {
					return err
				}
				for _, overlay := range test.overlays {
					if err := tx.Put(overlay, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("seed store: %v", err)
			}
			if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
				t.Fatal("invalid sssvlv overlay was accepted")
			}
		})
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidOperationalSettings(t *testing.T) {
	t.Parallel()

	for _, attribute := range []string{
		"olcReadOnly",
		"olcDisabled",
		"olcHidden",
		"olcLastMod",
		"olcMaxDerefDepth",
		"olcSubordinate",
	} {
		attribute := attribute
		t.Run(attribute, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			entry := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
					{Description: attribute, Values: stringValues("sometimes")},
				},
			}
			if err := store.Update(context.Background(), func(tx storage.Writer) error {
				return tx.Put(entry, false)
			}); err != nil {
				t.Fatalf("seed store: %v", err)
			}

			if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
				t.Fatalf("invalid %s was accepted", attribute)
			}
		})
	}
}

func TestLoadRuntimeDatabasesLoadsSubordinateHierarchy(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("ou=people,dc=example,dc=com")},
				{Description: "olcSubordinate", Values: stringValues("advertise")},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	parentIndex := -1
	childIndex := -1
	for index := range databases {
		switch databases[index].name {
		case "{1}mdb":
			parentIndex = index
		case "{2}mdb":
			childIndex = index
		}
	}
	if parentIndex < 0 || childIndex < 0 {
		t.Fatalf("loaded databases = %#v", databases)
	}
	if !databases[childIndex].subordinate || !databases[childIndex].advertise {
		t.Fatalf("subordinate database = %#v", databases[childIndex])
	}
	if got := glueSuperiorDatabaseIndex(databases, childIndex); got != parentIndex {
		t.Fatalf("glue superior index = %d, want %d", got, parentIndex)
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidSubordinateShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		suffixes []string
		values   []string
	}{
		{name: "missing suffix", values: []string{"TRUE"}},
		{name: "false without suffix", values: []string{"FALSE"}},
		{
			name:     "multiple suffixes",
			suffixes: []string{"ou=people,dc=example,dc=com", "ou=users,dc=example,dc=com"},
			values:   []string{"TRUE"},
		},
		{
			name:     "multiple values",
			suffixes: []string{"ou=people,dc=example,dc=com"},
			values:   []string{"TRUE", "advertise"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			entry := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues(test.suffixes...)},
					{Description: "olcSubordinate", Values: stringValues(test.values...)},
				},
			}
			if err := store.Update(context.Background(), func(tx storage.Writer) error {
				return tx.Put(entry, false)
			}); err != nil {
				t.Fatalf("seed store: %v", err)
			}

			if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
				t.Fatal("invalid olcSubordinate configuration was accepted")
			}
		})
	}
}

func TestDatabaseSearchRoutesFollowGlueScope(t *testing.T) {
	t.Parallel()

	mustDN := func(t *testing.T, raw string) directory.DN {
		t.Helper()
		dn, err := directory.ParseDN(raw)
		if err != nil {
			t.Fatalf("ParseDN(%q): %v", raw, err)
		}
		return dn
	}
	databases := []runtimeDatabase{
		{
			name:     "parent",
			suffixes: []directory.DN{mustDN(t, "dc=example,dc=com")},
		},
		{
			name:        "people",
			suffixes:    []directory.DN{mustDN(t, "ou=people,dc=example,dc=com")},
			subordinate: true,
		},
		{
			name:        "teams",
			suffixes:    []directory.DN{mustDN(t, "ou=teams,ou=people,dc=example,dc=com")},
			subordinate: true,
		},
		{
			name:        "devices",
			suffixes:    []directory.DN{mustDN(t, "ou=devices,dc=example,dc=com")},
			subordinate: true,
			advertise:   true,
		},
		{
			name:     "external",
			suffixes: []directory.DN{mustDN(t, "ou=external,dc=example,dc=com")},
		},
		{
			name:        "managed",
			suffixes:    []directory.DN{mustDN(t, "ou=managed,ou=external,dc=example,dc=com")},
			subordinate: true,
		},
	}

	tests := []struct {
		name  string
		base  string
		scope directory.Scope
		want  []string
	}{
		{
			name:  "parent base",
			base:  "dc=example,dc=com",
			scope: directory.ScopeBase,
			want:  []string{"parent"},
		},
		{
			name:  "parent one level",
			base:  "dc=example,dc=com",
			scope: directory.ScopeSingleLevel,
			want:  []string{"parent", "people", "devices"},
		},
		{
			name:  "parent subtree",
			base:  "dc=example,dc=com",
			scope: directory.ScopeWholeSubtree,
			want:  []string{"parent", "teams", "people", "devices"},
		},
		{
			name:  "subordinate base",
			base:  "ou=people,dc=example,dc=com",
			scope: directory.ScopeBase,
			want:  []string{"people"},
		},
		{
			name:  "subordinate one level",
			base:  "ou=people,dc=example,dc=com",
			scope: directory.ScopeSingleLevel,
			want:  []string{"people", "teams"},
		},
		{
			name:  "subordinate subtree",
			base:  "ou=people,dc=example,dc=com",
			scope: directory.ScopeWholeSubtree,
			want:  []string{"people", "teams"},
		},
		{
			name:  "independent subtree",
			base:  "ou=external,dc=example,dc=com",
			scope: directory.ScopeWholeSubtree,
			want:  []string{"external", "managed"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			routes := databaseSearchRoutes(
				databases,
				mustDN(t, test.base),
				test.scope,
			)
			got := make([]string, len(routes))
			for index, route := range routes {
				got[index] = databases[route.databaseIndex].name
			}
			if len(got) != len(test.want) {
				t.Fatalf("route databases = %v, want %v", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("route databases = %v, want %v", got, test.want)
				}
			}
		})
	}
}

func TestDatabaseSearchRoutesRejectOrphanSubordinate(t *testing.T) {
	t.Parallel()

	suffix, err := directory.ParseDN("ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	databases := []runtimeDatabase{{
		name:        "orphan",
		suffixes:    []directory.DN{suffix},
		subordinate: true,
	}}
	if routes := databaseSearchRoutes(
		databases,
		suffix,
		directory.ScopeBase,
	); len(routes) != 0 {
		t.Fatalf("orphan subordinate routes = %#v", routes)
	}
}

func TestLoadRuntimeDatabasesAllowsHiddenDuplicateSuffix(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcHidden", Values: stringValues("TRUE")},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	dn, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	index := databaseIndexForDN(databases, dn)
	if index < 0 || databases[index].name != "{1}mdb" {
		t.Fatalf("selected database = %d, %#v", index, databases)
	}
	if _, err := databaseIndexForLegacyDN(databases, dn); err == nil {
		t.Fatal("ambiguous unpartitioned entry was assigned across duplicate suffixes")
	}
}
