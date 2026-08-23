package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSQLBackendCollectivePlanIgnoresSearchCandidatePruning(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "collective.db")
	seedSQLCollectiveDatabase(t, databaseName, "shared")

	store := newSQLCollectiveStore(t, databaseName)
	address, stop := startServer(t, store, Config{
		Schema:    collectiveServerRegistry(t),
		SQLDriver: "sqlite",
	})
	t.Cleanup(stop)

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid", "c-description", "collectiveAttributeSubentries"},
		nil,
	))
	if err != nil {
		t.Fatalf("SQL collective Search(): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("SQL collective Search entries = %d, want 1", len(result.Entries))
	}
	entry := result.Entries[0]
	if got := entry.GetAttributeValue("c-description"); got != "shared" {
		t.Fatalf("SQL collective value = %q, want shared", got)
	}
	if got := entry.GetAttributeValue("collectiveAttributeSubentries"); got != "cn=collective,dc=example,dc=com" {
		t.Fatalf("SQL collective source = %q", got)
	}
}

func TestSQLBackendCollectivePlanCacheSeparatesDatabases(t *testing.T) {
	registry := collectiveServerRegistry(t)
	cache := newCollectiveAttributePlanCache(registry)

	cacheKeys := []string{
		"olcDatabase={1}sql,cn=config",
		"olcDatabase={2}sql,cn=config",
	}
	for index, value := range []string{"first", "second"} {
		databaseName := filepath.Join(t.TempDir(), value+".db")
		seedSQLCollectiveDatabase(t, databaseName, value)
		configuration := sqlCollectiveConfiguration(t, databaseName, registry)
		configuration.collectivePlanKey = cacheKeys[index]
		t.Cleanup(func() { _ = configuration.close() })

		reader := &sqlBackendReader{
			configuration: configuration,
			ctx:           context.Background(),
		}
		targetDN, err := registry.NormalizeDN("uid=alice,dc=example,dc=com")
		if err != nil {
			t.Fatalf("NormalizeDN(): %v", err)
		}
		entry, err := reader.Get(targetDN)
		if err != nil {
			t.Fatalf("SQL reader %d Get(): %v", index, err)
		}
		derived, err := cache.apply("", reader, entry)
		if err != nil {
			t.Fatalf("SQL collective cache apply %d: %v", index, err)
		}
		values := derived.Values("c-description")
		if len(values) != 1 || string(values[0]) != value {
			t.Fatalf("SQL collective cache value %d = %q, want %q", index, values, value)
		}
	}
	if len(cache.plans) != 2 {
		t.Fatalf("SQL collective plan cache size = %d, want 2", len(cache.plans))
	}
}

func TestSQLBackendCollectivePlanReaderPreservesReadTransaction(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "collective-transaction.db")
	seedSQLCollectiveDatabase(t, databaseName, "transactional")
	registry := collectiveServerRegistry(t)
	configuration := sqlCollectiveConfiguration(t, databaseName, registry)
	configuration.collectivePlanKey = "olcDatabase={1}sql,cn=config"
	t.Cleanup(func() { _ = configuration.close() })

	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	coordinator := newSQLBackendReadCoordinator(context.Background())
	t.Cleanup(coordinator.close)

	baseDN, err := registry.NormalizeDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("NormalizeDN(base): %v", err)
	}
	searchContext := withSQLBackendSearchRequirements(
		context.Background(),
		[]string{"uid", "c-description"},
		directory.Filter{
			Kind:      directory.FilterEquality,
			Attribute: "uid",
			Assertion: []byte("alice"),
		},
	)
	searchContext = withSQLBackendScopeRequirements(
		searchContext,
		baseDN,
		directory.ScopeWholeSubtree,
	)

	if err := base.View(context.Background(), func(baseReader storage.Reader) error {
		searchReader := coordinator.reader(configuration, baseReader, searchContext)
		if _, ok := searchReader.queryer.(*sql.Tx); !ok {
			t.Fatalf("search queryer = %T, want *sql.Tx", searchReader.queryer)
		}
		_, planReader, changed := collectiveAttributePlanReader("", searchReader)
		if !changed {
			t.Fatal("SQL collective plan reader was not specialized")
		}
		metadataReader, ok := planReader.(*sqlBackendReader)
		if !ok {
			t.Fatalf("collective plan reader = %T, want *sqlBackendReader", planReader)
		}
		if metadataReader.queryer != searchReader.queryer {
			t.Fatal("collective metadata reader did not preserve the search transaction")
		}
		if _, specified := metadataReader.sqlBackendSearchRequirements(); specified {
			t.Fatal("collective metadata reader retained search candidate requirements")
		}

		targetDN, normalizeErr := registry.NormalizeDN("uid=alice,dc=example,dc=com")
		if normalizeErr != nil {
			return normalizeErr
		}
		entry, getErr := searchReader.Get(targetDN)
		if getErr != nil {
			return getErr
		}
		derived, applyErr := newCollectiveAttributePlanCache(registry).apply("", searchReader, entry)
		if applyErr != nil {
			return applyErr
		}
		values := derived.Values("c-description")
		if len(values) != 1 || string(values[0]) != "transactional" {
			t.Fatalf("transactional collective values = %q", values)
		}
		return nil
	}); err != nil {
		t.Fatalf("SQL collective transaction view: %v", err)
	}
}

func newSQLCollectiveStore(t *testing.T, databaseName string) storage.Store {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	return store
}

func sqlCollectiveConfiguration(
	t *testing.T,
	databaseName string,
	registry *schema.Registry,
) *sqlBackendRuntimeConfiguration {
	t.Helper()
	entry := sqlDirectiveConfigurationEntry("")
	entry.ReplaceValues("olcDbName", stringValues(databaseName))
	configuration, err := loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("load SQL collective configuration: %v", err)
	}
	configuration.setRuntime(registry, "sqlite", nil)
	return configuration
}

func seedSQLCollectiveDatabase(t *testing.T, databaseName, value string) {
	t.Helper()
	seedSQLBackendDatabase(t, databaseName)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open SQL collective fixture: %v", err)
	}
	defer database.Close()

	statements := []string{
		`ALTER TABLE organizations ADD COLUMN administrative_role TEXT`,
		`UPDATE organizations SET administrative_role='collectiveAttributeSpecificArea' WHERE id=10`,
		`CREATE TABLE collective_sources (
			id INTEGER PRIMARY KEY, cn TEXT, subtree_specification TEXT,
			collective_description TEXT
		)`,
		`INSERT INTO collective_sources VALUES (30,'collective','{}',?)`,
		`INSERT INTO ldap_oc_mappings VALUES (4,'subentry','collective_sources','id',NULL,NULL,0)`,
		`INSERT INTO ldap_attr_mappings VALUES
			(7,3,'administrativeRole','organizations.administrative_role','organizations',NULL,NULL,NULL,0,0,NULL),
			(8,4,'cn','collective_sources.cn','collective_sources',NULL,NULL,NULL,0,0,NULL),
			(9,4,'subtreeSpecification','collective_sources.subtree_specification','collective_sources',NULL,NULL,NULL,0,0,NULL),
			(10,4,'collectiveDescription','collective_sources.collective_description','collective_sources',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO ldap_entries VALUES (3,'cn=collective,dc=example,dc=com',4,1,30)`,
		`INSERT INTO ldap_entry_objclasses VALUES (3,'collectiveAttributeSubentry')`,
	}
	for index, statement := range statements {
		var execErr error
		if index == 3 {
			_, execErr = database.Exec(statement, value)
		} else {
			_, execErr = database.Exec(statement)
		}
		if execErr != nil {
			t.Fatalf("SQL collective fixture statement %d: %v\n%s", index, execErr, statement)
		}
	}
}
