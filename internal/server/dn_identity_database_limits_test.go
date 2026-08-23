package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestDNIdentityDatabaseSearchLimitSelectors(t *testing.T) {
	registry := dnIdentityDatabaseLimitRegistry(t)
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values: stringValues(
				`{0}dn.self.exact="dbLimitExactAlias=Alice+dbLimitFoldAlias=Primary Team,dbLimitFoldAlias=Tenant" size=11`,
				`{1}dn.self.subtree="dbLimitFoldAlias=People,dbLimitFoldAlias=Tenant" size=12`,
				`{2}dn.onelevel="dbLimitFoldAlias=Groups,dbLimitFoldAlias=Tenant" size=13`,
				`{3}dn.children="dbLimitFoldAlias=Units,dbLimitFoldAlias=Tenant" size=14`,
				`{4}anonymous size=15`,
				`{5}users size=16`,
				`{6}* size=17`,
			),
		}},
	}
	limits, err := loadDatabaseSearchSizeLimitsWithNormalizer(entry, registry)
	if err != nil {
		t.Fatalf("loadDatabaseSearchSizeLimits(): %v", err)
	}
	if len(limits) != 7 {
		t.Fatalf("limit count = %d, want 7", len(limits))
	}
	database := runtimeDatabase{
		name:             "{1}mdb",
		searchSizeLimits: limits,
	}
	runtime := &runtimeState{schema: registry}

	for _, test := range []struct {
		name    string
		boundDN string
		want    int
	}{
		{
			name: "exact alias oid and multi AVA order",
			boundDN: `1.3.6.1.4.1.99999.931.2=\20PRIMARY\20\20TEAM\20+` +
				`1.3.6.1.4.1.99999.931.1=Alice,dbLimitFoldName=TENANT`,
			want: 11,
		},
		{
			name: "caseExact mismatch falls through to users",
			boundDN: `dbLimitFoldAlias=primary team+dbLimitExactAlias=alice,` +
				`dbLimitFoldAlias=tenant`,
			want: 16,
		},
		{
			name:    "subtree includes base",
			boundDN: `dbLimitFoldName=\20PEOPLE\20,dbLimitFoldName=tenant`,
			want:    12,
		},
		{
			name: "subtree includes descendants",
			boundDN: `uid=alice,dbLimitFoldName=people,` +
				`dbLimitFoldName=tenant`,
			want: 12,
		},
		{
			name: "onelevel includes direct child",
			boundDN: `uid=alice,dbLimitFoldName=groups,` +
				`dbLimitFoldName=tenant`,
			want: 13,
		},
		{
			name: "onelevel excludes deeper child",
			boundDN: `cn=device,uid=alice,dbLimitFoldName=groups,` +
				`dbLimitFoldName=tenant`,
			want: 16,
		},
		{
			name:    "children excludes base",
			boundDN: `dbLimitFoldName=units,dbLimitFoldName=tenant`,
			want:    16,
		},
		{
			name: "children includes descendants",
			boundDN: `uid=alice,dbLimitFoldName=units,` +
				`dbLimitFoldName=tenant`,
			want: 14,
		},
		{name: "anonymous", boundDN: "", want: 15},
		{name: "users", boundDN: "uid=other,dc=example,dc=com", want: 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := effectiveDatabaseSearchLimit(
				runtime,
				database,
				test.boundDN,
				100,
				0,
			); got != test.want {
				t.Fatalf("effective limit = %d, want %d", got, test.want)
			}
		})
	}

	anyEntry := entry.Clone()
	anyEntry.ReplaceValues("olcLimits", stringValues(`dn=* size=19`))
	anyLimits, err := loadDatabaseSearchSizeLimitsWithNormalizer(anyEntry, registry)
	if err != nil {
		t.Fatalf("load any selector: %v", err)
	}
	database.searchSizeLimits = anyLimits
	if got := effectiveDatabaseSearchLimit(runtime, database, "", 100, 0); got != 19 {
		t.Fatalf("anonymous any limit = %d, want 19", got)
	}
}

func TestDNIdentityDatabaseSearchLimitRootAndLegacyConfig(t *testing.T) {
	registry := dnIdentityDatabaseLimitRegistry(t)
	root := dnIdentityDatabaseLimitDN(
		t,
		registry,
		"dbLimitExactAlias=Admin+dbLimitFoldAlias=Primary Team,dbLimitFoldAlias=Tenant",
	)
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values:      stringValues("users size=7"),
		}},
	}
	limits, err := loadDatabaseSearchSizeLimitsWithNormalizer(entry, registry)
	if err != nil {
		t.Fatalf("loadDatabaseSearchSizeLimits(): %v", err)
	}
	database := runtimeDatabase{
		name:             "{1}mdb",
		dnNormalizer:     registry,
		rootDN:           &root,
		searchSizeLimits: limits,
	}
	runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}
	equivalentRoot := `1.3.6.1.4.1.99999.931.2=primary team+` +
		`1.3.6.1.4.1.99999.931.1=Admin,dbLimitFoldName=tenant`
	if got := effectiveDatabaseSearchLimit(
		runtime,
		database,
		equivalentRoot,
		100,
		30,
	); got != 30 {
		t.Fatalf("root limit = %d, want client limit 30", got)
	}
	caseMismatch := `dbLimitExactName=admin+dbLimitFoldName=primary team,` +
		`dbLimitFoldName=tenant`
	if got := effectiveDatabaseSearchLimit(
		runtime,
		database,
		caseMismatch,
		100,
		30,
	); got != 7 {
		t.Fatalf("caseExact-mismatched root limit = %d, want 7", got)
	}

	legacyRoot := dnIdentityDatabaseLimitLegacyDN(t, "CN=CONFIG")
	legacyEntry := directory.Entry{
		DN: "olcDatabase={0}config,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values:      stringValues(`dn.exact="cn=config" size=3`),
		}},
	}
	legacyLimits, err := loadDatabaseSearchSizeLimits(legacyEntry)
	if err != nil {
		t.Fatalf("load legacy config limits: %v", err)
	}
	configDatabase := runtimeDatabase{
		name:             "{0}config",
		suffixes:         []directory.DN{legacyRoot},
		searchSizeLimits: legacyLimits,
	}
	configRuntime := &runtimeState{schema: registry}
	if got := effectiveDatabaseSearchLimit(
		configRuntime,
		configDatabase,
		"CN=CONFIG",
		100,
		0,
	); got != 3 {
		t.Fatalf("legacy cn=config limit = %d, want 3", got)
	}
	if index := databaseIndexForDN(
		[]runtimeDatabase{configDatabase},
		dnIdentityDatabaseLimitLegacyDN(t, "cn=config"),
	); index != 0 {
		t.Fatalf("cn=config database index = %d, want 0", index)
	}
}

func TestDNIdentityDatabaseSuffixAndRootRouting(t *testing.T) {
	registry := dnIdentityDatabaseLimitRegistry(t)
	exactSuffix := dnIdentityDatabaseLimitDN(
		t,
		registry,
		"dbLimitExactAlias=Tenant+dbLimitFoldAlias=Primary Region",
	)
	foldSuffix := dnIdentityDatabaseLimitDN(
		t,
		registry,
		"dbLimitFoldAlias=Remote Tenant",
	)
	exactRoot := dnIdentityDatabaseLimitDN(
		t,
		registry,
		"uid=admin,dbLimitExactAlias=Tenant+dbLimitFoldAlias=Primary Region",
	)
	databases := []runtimeDatabase{
		{
			name:         "{1}mdb",
			suffixes:     []directory.DN{exactSuffix},
			dnNormalizer: registry,
			rootDN:       &exactRoot,
		},
		{
			name:         "{2}mdb",
			suffixes:     []directory.DN{foldSuffix},
			dnNormalizer: registry,
		},
	}

	exactEquivalent := dnIdentityDatabaseLimitLegacyDN(
		t,
		`uid=alice,1.3.6.1.4.1.99999.931.2=\20PRIMARY\20\20REGION\20+`+
			`1.3.6.1.4.1.99999.931.1=Tenant`,
	)
	if index := databaseIndexForDN(databases, exactEquivalent); index != 0 {
		t.Fatalf("exact alias/OID route index = %d, want 0", index)
	}
	if index := databaseIndexForRootOverride(databases, exactEquivalent); index != 0 {
		t.Fatalf("root override route index = %d, want 0", index)
	}
	if !databaseHasSuffix(
		databases,
		dnIdentityDatabaseLimitLegacyDN(
			t,
			`1.3.6.1.4.1.99999.931.2=primary region+`+
				`1.3.6.1.4.1.99999.931.1=Tenant`,
		),
	) {
		t.Fatal("databaseHasSuffix rejected alias/OID multi-AVA identity")
	}
	legacyEquivalentSuffix := dnIdentityDatabaseLimitLegacyDN(
		t,
		`1.3.6.1.4.1.99999.931.2=primary region+`+
			`1.3.6.1.4.1.99999.931.1=Tenant`,
	)
	duplicate := append([]runtimeDatabase(nil), databases...)
	duplicate = append(duplicate, runtimeDatabase{
		name:         "{3}mdb",
		suffixes:     []directory.DN{legacyEquivalentSuffix},
		dnNormalizer: registry,
	})
	if err := validateDatabaseSuffixes(duplicate); err == nil {
		t.Fatal("validateDatabaseSuffixes accepted alias/OID duplicate suffix")
	}
	caseMismatch := dnIdentityDatabaseLimitLegacyDN(
		t,
		"uid=alice,dbLimitExactName=tenant+dbLimitFoldName=primary region",
	)
	if index := databaseIndexForDN(databases, caseMismatch); index != -1 {
		t.Fatalf("caseExact mismatch route index = %d, want -1", index)
	}
	foldEquivalent := dnIdentityDatabaseLimitLegacyDN(
		t,
		`uid=alice,dbLimitFoldName=\20REMOTE\20\20TENANT\20`,
	)
	if index := databaseIndexForDN(databases, foldEquivalent); index != 1 {
		t.Fatalf("caseIgnore route index = %d, want 1", index)
	}

	runtime := &runtimeState{schema: registry, databases: databases}
	rootEquivalent := dnIdentityDatabaseLimitLegacyDN(
		t,
		`uid=admin,1.3.6.1.4.1.99999.931.2=primary region+`+
			`1.3.6.1.4.1.99999.931.1=Tenant`,
	)
	if !databaseRootMatches(runtime, databases[0], rootEquivalent) {
		t.Fatal("databaseRootMatches rejected schema-equivalent root DN")
	}
	rootCaseMismatch := dnIdentityDatabaseLimitLegacyDN(
		t,
		"uid=admin,dbLimitExactName=tenant+dbLimitFoldName=primary region",
	)
	if databaseRootMatches(runtime, databases[0], rootCaseMismatch) {
		t.Fatal("databaseRootMatches accepted caseExact mismatch")
	}
}

func dnIdentityDatabaseLimitRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.931.1 NAME ( 'dbLimitExactName' 'dbLimitExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.931.2 NAME ( 'dbLimitFoldName' 'dbLimitFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityDatabaseLimitDN(
	t *testing.T,
	registry *schema.Registry,
	raw string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(raw)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", raw, err)
	}
	return dn
}

func dnIdentityDatabaseLimitLegacyDN(t *testing.T, raw string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", raw, err)
	}
	return dn
}
