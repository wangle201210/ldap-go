package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

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
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcReadOnly", Values: stringValues("FALSE")},
				{Description: "olcLastMod", Values: stringValues("FALSE")},
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

	bootstrapDN, err := directory.ParseDN("dc=bootstrap,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(bootstrap): %v", err)
	}
	bootstrap := databases[databaseIndexForDN(databases, bootstrapDN)]
	if !bootstrap.readOnly {
		t.Fatal("frontend olcReadOnly was not inherited by a bootstrap database")
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
				{Description: "olcSssVlvMaxKeys", Values: stringValues("3")},
			},
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
	if !database.serverSideSort || database.sortMaxKeys != 3 {
		t.Fatalf("server-side sort database = %#v", database)
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
