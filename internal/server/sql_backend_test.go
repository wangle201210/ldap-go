package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
	_ "modernc.org/sqlite"
)

func TestSQLBackendLDAPReadOperations(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "back-sql.db")
	seedSQLBackendDatabase(t, databaseName)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)

	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	if err := client.Bind("uid=alice,dc=example,dc=com", "alice-secret"); err != nil {
		t.Fatalf("SQL user Bind(): %v", err)
	}
	assertLDAPResultCode(
		t,
		client.Bind("uid=alice,dc=example,dc=com", "wrong-secret"),
		ldap.LDAPResultInvalidCredentials,
	)
	if err := client.Bind("uid=alice,dc=example,dc=com", "alice-secret"); err != nil {
		t.Fatalf("restore SQL user Bind(): %v", err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=inetOrgPerson)(cn=Alice*))",
		[]string{"uid", "cn", "jpegPhoto", "entryUUID", "structuralObjectClass", "hasSubordinates"},
		nil,
	))
	if err != nil {
		t.Fatalf("SQL subtree Search(): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("SQL subtree Search entry count = %d, want 1", len(result.Entries))
	}
	entry := result.Entries[0]
	if entry.DN != "uid=alice,dc=example,dc=com" ||
		entry.GetAttributeValue("uid") != "alice" ||
		entry.GetAttributeValue("cn") != "Alice Example" ||
		entry.GetAttributeValue("structuralObjectClass") != "inetOrgPerson" ||
		entry.GetAttributeValue("entryUUID") != "00000001-0000-0014-0000-000000000000" ||
		entry.GetAttributeValue("hasSubordinates") != "FALSE" {
		t.Fatalf("SQL Search entry = %#v", entry)
	}
	if got := entry.GetRawAttributeValue("jpegPhoto"); string(got) != string([]byte{0, 0xff, 0x10}) {
		t.Fatalf("jpegPhoto = %v", got)
	}
	limited, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"objectClass"},
		nil,
	))
	if err == nil {
		t.Fatal("SQL size-limited Search unexpectedly succeeded")
	}
	assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)
	if len(limited.Entries) != 1 {
		t.Fatalf("SQL size-limited Search returned %d entries, want 1", len(limited.Entries))
	}

	equal, err := client.Compare("uid=alice,dc=example,dc=com", "uid", "alice")
	if err != nil || !equal {
		t.Fatalf("SQL Compare true = %t, %v", equal, err)
	}
	equal, err = client.Compare("uid=alice,dc=example,dc=com", "uid", "bob")
	if err != nil || equal {
		t.Fatalf("SQL Compare false = %t, %v", equal, err)
	}

	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("SQL root Bind(): %v", err)
	}
	request := ldap.NewAddRequest("uid=bob,dc=example,dc=com", nil)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{"bob"})
	request.Attribute("cn", []string{"Bob Example"})
	request.Attribute("sn", []string{"Example"})
	assertLDAPResultCode(t, client.Add(request), ldap.LDAPResultUnwillingToPerform)
}

func TestLoadSQLBackendRuntimeConfiguration(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}sql,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDbName", Values: stringValues("directory")},
			{Description: "olcDbUser", Values: stringValues("ldap")},
			{Description: "olcDbPass", Values: stringValues("secret")},
			{Description: "olcSqlCreateNeedsSelect", Values: stringValues("TRUE")},
			{Description: "olcSqlFailIfNoMapping", Values: stringValues("TRUE")},
			{Description: "olcSqlAliasingKeyword", Values: stringValues("AS")},
		},
	}
	configuration, err := loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadSQLBackendRuntimeConfiguration(): %v", err)
	}
	if configuration.databaseName != "directory" ||
		configuration.databaseUser != "ldap" ||
		configuration.databasePass != "secret" ||
		!configuration.createNeedsSelect ||
		!configuration.failIfNoMapping ||
		configuration.ocQuery != defaultSQLSelectOCQuery ||
		configuration.aliasingKeyword != "AS " {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestLoadSQLBackendRuntimeConfigurationRequiresOpenLDAPFields(t *testing.T) {
	_, err := loadSQLBackendRuntimeConfiguration(directory.Entry{
		DN: "olcDatabase={1}sql,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDbName", Values: stringValues("directory")},
		},
	})
	if err == nil {
		t.Fatal("missing olcDbUser was accepted")
	}
	if got := err.Error(); got != "olcDatabase={1}sql,cn=config SQL backend requires olcDbUser" {
		t.Fatalf("error = %q", got)
	}
}

func TestSQLBackendUnavailablePreventsServerStart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, filepath.Join(t.TempDir(), "missing", "back-sql.db"))

	server, err := New(Config{Store: store, SQLDriver: "sqlite"})
	if server != nil {
		server.closeSQLBackends()
	}
	if err == nil || !strings.Contains(err.Error(), "initialize SQL backend") ||
		!strings.Contains(err.Error(), "SQL backend unavailable") {
		t.Fatalf("New() error = %v", err)
	}

	_, err = ValidateConfiguration(
		context.Background(),
		Config{Store: store, SQLDriver: "sqlite"},
	)
	if err == nil || !strings.Contains(err.Error(), "SQL backend unavailable") {
		t.Fatalf("ValidateConfiguration() error = %v", err)
	}
}

func TestSQLBackendReadViewUsesOneTransactionSnapshot(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "read-snapshot.db")
	seedSQLBackendDatabase(t, databaseName)
	configuration := &sqlBackendRuntimeConfiguration{
		databaseName:      databaseName,
		databaseUser:      "unused",
		driverName:        "sqlite",
		ocQuery:           defaultSQLOCQuery,
		attributeQuery:    defaultSQLATQuery,
		idQuery:           defaultSQLIDQuery,
		insertEntry:       defaultSQLInsertEntryStatement,
		deleteEntry:       defaultSQLDeleteEntryStatement,
		renameEntry:       defaultSQLRenameEntryStatement,
		deleteObjectClass: defaultSQLDeleteObjectClassesStatement,
		aliasingKeyword:   "AS ",
		registry:          testSQLBuiltinRegistry(t),
	}
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	store := &accessContextStore{Store: base}
	var transaction *sql.Tx
	err := store.View(context.Background(), func(reader storage.Reader) error {
		first := readerForDatabase(reader, runtimeDatabase{sqlBackend: configuration}).(*sqlBackendReader)
		second := readerForDatabase(reader, runtimeDatabase{sqlBackend: configuration}).(*sqlBackendReader)
		if first.queryer == nil || first.queryer != second.queryer {
			t.Fatal("SQL readers in one View did not share a transaction")
		}
		var ok bool
		transaction, ok = first.queryer.(*sql.Tx)
		if !ok {
			t.Fatalf("SQL snapshot queryer = %T, want *sql.Tx", first.queryer)
		}
		dn, parseErr := directory.ParseDN("uid=alice,dc=example,dc=com")
		if parseErr != nil {
			return parseErr
		}
		_, getErr := first.Get(dn)
		return getErr
	})
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	var count int
	err = transaction.QueryRowContext(
		context.Background(),
		"SELECT COUNT(*) FROM ldap_entries",
	).Scan(&count)
	if !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("query after View error = %v, want sql.ErrTxDone", err)
	}
	_ = configuration.close()
}

func TestSQLBackendReadViewFallsBackToDefaultTransactionOptions(t *testing.T) {
	state := &sqlBackendProcedureDriverState{rejectRichTxOptions: true}
	databaseName := registerSQLBackendProcedureDriver(t, state)
	database, err := sql.Open(sqlBackendProcedureDriverName, databaseName)
	if err != nil {
		t.Fatalf("open SQL fallback fixture: %v", err)
	}
	configuration := &sqlBackendRuntimeConfiguration{db: database}
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	coordinator := newSQLBackendReadCoordinator(context.Background())
	if err := base.View(context.Background(), func(baseReader storage.Reader) error {
		reader := coordinator.reader(configuration, baseReader)
		if reader.initializationErr != nil {
			t.Fatalf("initialize fallback SQL reader: %v", reader.initializationErr)
		}
		if _, ok := reader.queryer.(*sql.Tx); !ok {
			t.Fatalf("fallback SQL queryer = %T, want *sql.Tx", reader.queryer)
		}
		return nil
	}); err != nil {
		t.Fatalf("view fallback SQL reader: %v", err)
	}
	coordinator.close()
	_ = configuration.close()

	state.mu.Lock()
	options := append([]driver.TxOptions(nil), state.beginOptions...)
	state.mu.Unlock()
	if len(options) != 2 ||
		options[0].Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) ||
		!options[0].ReadOnly || options[1] != (driver.TxOptions{}) {
		t.Fatalf("BeginTx options = %#v", options)
	}
}

func TestSQLBackendOnlineConfigurationFailureRollsBack(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "online-config.db")
	seedSQLBackendDatabase(t, databaseName)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		if err := writer.Delete(dn); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcDatabase={1}sql,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcSqlConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}sql")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=example,dc=com")},
				{Description: "olcRootPW", Values: stringValues("admin-secret")},
				{Description: "olcDbName", Values: stringValues(databaseName)},
				{Description: "olcDbUser", Values: stringValues("unused")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed online SQL configuration: %v", err)
	}

	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()
	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	dataClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(data): %v", err)
	}
	defer dataClient.Close()
	if err := dataClient.Bind("uid=alice,dc=example,dc=com", "alice-secret"); err != nil {
		t.Fatalf("SQL Bind before invalid configuration: %v", err)
	}

	modify := ldap.NewModifyRequest("olcDatabase={1}sql,cn=config", nil)
	modify.Replace("olcDbName", []string{filepath.Join(t.TempDir(), "missing", "bad.db")})
	assertLDAPResultCode(t, configClient.Modify(modify), ldap.LDAPResultConstraintViolation)

	if err := dataClient.Bind("uid=alice,dc=example,dc=com", "alice-secret"); err != nil {
		t.Fatalf("SQL Bind after rejected configuration: %v", err)
	}
	result, err := configClient.Search(ldap.NewSearchRequest(
		"olcDatabase={1}sql,cn=config",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcDbName"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(SQL config): %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("olcDbName") != databaseName {
		t.Fatalf("persisted olcDbName = %q, want %q", result.Entries[0].GetAttributeValue("olcDbName"), databaseName)
	}
}

func TestLoadSQLBackendRuntimeConfigurationRejectsUnsupportedLayers(t *testing.T) {
	for _, attribute := range []string{"olcSqlBaseObject", "olcSqlLayer"} {
		t.Run(attribute, func(t *testing.T) {
			_, err := loadSQLBackendRuntimeConfiguration(directory.Entry{
				DN: "olcDatabase={1}sql,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDbName", Values: stringValues("directory")},
					{Description: "olcDbUser", Values: stringValues("ldap")},
					{Description: attribute, Values: stringValues("unsupported")},
				},
			})
			if err == nil {
				t.Fatalf("%s was accepted", attribute)
			}
		})
	}
}

func TestSQLBackendDefaultIDQueryUsesOpenLDAPDNSettings(t *testing.T) {
	configuration := &sqlBackendRuntimeConfiguration{upperFunction: "UPPER"}
	configuration.prepareDefaultIDQuery()
	if got, want := configuration.idQuery,
		"SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE UPPER(dn)=UPPER(?)"; got != want {
		t.Fatalf("upper id query = %q, want %q", got, want)
	}
	configuration = &sqlBackendRuntimeConfiguration{hasReversedDN: true}
	configuration.prepareDefaultIDQuery()
	if got, want := configuration.idQuery,
		"SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE dn_ru=?"; got != want {
		t.Fatalf("dn_ru id query = %q, want %q", got, want)
	}
}

func TestSQLBackendAttributeQueryMergesKeyTable(t *testing.T) {
	configuration := &sqlBackendRuntimeConfiguration{aliasingKeyword: "AS "}
	query := configuration.attributeSelectQuery(
		&sqlObjectClassMapping{keyTable: "persons", keyColumn: "id"},
		sqlAttributeMapping{
			name:             "description",
			selectExpression: "descriptions.value",
			fromTables:       "descriptions",
			joinWhere:        "persons.id=descriptions.person_id",
		},
	)
	want := "SELECT descriptions.value AS description FROM descriptions,persons " +
		"WHERE persons.id=? AND persons.id=descriptions.person_id ORDER BY description"
	if query != want {
		t.Fatalf("attribute query = %q, want %q", query, want)
	}
	if got := mergeSQLFromTable("persons AS p,descriptions", "persons"); got != "persons AS p,descriptions" {
		t.Fatalf("existing key table was duplicated: %q", got)
	}
}

func TestReuseSQLBackendOnlineConfigurationState(t *testing.T) {
	registry := testSQLBuiltinRegistry(t)
	previousConfiguration := &sqlBackendRuntimeConfiguration{
		databaseName: "directory",
		databaseUser: "ldap",
		driverName:   "sqlite",
		registry:     registry,
	}
	nextConfiguration := &sqlBackendRuntimeConfiguration{
		databaseName: "directory",
		databaseUser: "ldap",
		driverName:   "sqlite",
		registry:     registry.Clone(),
	}
	previousConfiguration.hasReversedDN = true
	previousConfiguration.idQuery = "SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE dn_ru=?"
	previous := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: "olcdatabase={1}sql,cn=config",
		sqlBackend:  previousConfiguration,
	}}}
	next := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: "olcdatabase={1}sql,cn=config",
		sqlBackend:  nextConfiguration,
	}}}
	reuseSQLBackendOnlineConfigurationState(previous, next)
	if next.databases[0].sqlBackend != previousConfiguration {
		t.Fatal("equivalent SQL backend did not reuse runtime state")
	}

	changed := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: "olcdatabase={1}sql,cn=config",
		sqlBackend: &sqlBackendRuntimeConfiguration{
			databaseName: "other",
			databaseUser: "ldap",
			driverName:   "sqlite",
			registry:     registry.Clone(),
		},
	}}}
	reuseSQLBackendOnlineConfigurationState(previous, changed)
	if changed.databases[0].sqlBackend == previousConfiguration {
		t.Fatal("changed SQL backend reused stale runtime state")
	}
}

func TestSQLBackendRuntimePoolRetirement(t *testing.T) {
	server := newRuntimeActivationTestServer()
	server.sqlBackends = make(map[*sqlBackendRuntimeConfiguration]struct{})
	defer server.closeSQLBackends()

	firstConfiguration := openSQLBackendPoolFixture(t)
	server.registerSQLBackend(firstConfiguration)
	first := &runtimeState{
		revision:  1,
		databases: []runtimeDatabase{{sqlBackend: firstConfiguration}},
	}
	server.activateRuntime(first)
	retained := server.retainActiveRuntime()
	if retained != first {
		t.Fatalf("retained runtime = %p, want %p", retained, first)
	}

	secondConfiguration := openSQLBackendPoolFixture(t)
	server.registerSQLBackend(secondConfiguration)
	second := &runtimeState{
		revision:  2,
		databases: []runtimeDatabase{{sqlBackend: secondConfiguration}},
	}
	server.activateRuntime(second)
	if !firstConfiguration.opened() {
		t.Fatal("old SQL pool closed while an operation retained its runtime")
	}
	retiredDatabase, err := firstConfiguration.database(context.Background())
	if err != nil {
		t.Fatalf("retained operation could not use retired SQL pool: %v", err)
	}
	var value int
	if err := retiredDatabase.QueryRow("SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("query retained retired SQL pool = %d, %v", value, err)
	}
	server.releaseRuntimeSQLBackends(retained)
	if firstConfiguration.opened() {
		t.Fatal("old SQL pool remained open after its last operation released it")
	}
	if _, err := firstConfiguration.database(context.Background()); err == nil {
		t.Fatal("released retired SQL pool reopened")
	}
	server.sqlBackendsMu.Lock()
	_, registered := server.sqlBackends[firstConfiguration]
	server.sqlBackendsMu.Unlock()
	if registered {
		t.Fatal("retired SQL pool remained registered")
	}

	third := &runtimeState{revision: 3}
	server.activateRuntime(third)
	if secondConfiguration.opened() {
		t.Fatal("unreferenced SQL pool was not retired immediately")
	}
}

func TestSQLBackendCandidatePoolCleanup(t *testing.T) {
	server := &Server{sqlBackends: make(map[*sqlBackendRuntimeConfiguration]struct{})}
	activeConfiguration := openSQLBackendPoolFixture(t)
	candidateConfiguration := openSQLBackendPoolFixture(t)
	server.registerSQLBackend(activeConfiguration)
	server.registerSQLBackend(candidateConfiguration)
	active := &runtimeState{databases: []runtimeDatabase{{sqlBackend: activeConfiguration}}}
	candidate := &runtimeState{databases: []runtimeDatabase{{sqlBackend: candidateConfiguration}}}

	server.closeCandidateSQLBackends(candidate, active)
	if !activeConfiguration.opened() {
		t.Fatal("candidate cleanup closed the active SQL pool")
	}
	if candidateConfiguration.opened() {
		t.Fatal("candidate cleanup left the failed SQL pool open")
	}
	server.closeSQLBackends()
}

func TestSQLBackendCandidatePoolCleanupAfterStoreCommitFailure(t *testing.T) {
	server := &Server{sqlBackends: make(map[*sqlBackendRuntimeConfiguration]struct{})}
	candidate := openSQLBackendPoolFixture(t)
	server.registerSQLBackend(candidate)
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	store := &homedirEffectStore{
		Store: &sqlBackendCommitFailureStore{
			Store: &accessContextStore{Store: base},
		},
		server: server,
	}

	err := store.Update(context.Background(), func(writer storage.Writer) error {
		provider, ok := writer.(interface {
			StorageContext() context.Context
		})
		if !ok {
			t.Fatalf("candidate writer = %T, want StorageContext provider", writer)
		}
		coordinator := sqlBackendTransactionCoordinatorFromContext(provider.StorageContext())
		if coordinator == nil {
			t.Fatal("candidate update has no SQL transaction coordinator")
		}
		coordinator.setCandidateCleanup(func() {
			server.closeCandidateSQLBackends(
				&runtimeState{databases: []runtimeDatabase{{sqlBackend: candidate}}},
				nil,
			)
		})
		return nil
	})
	if err == nil || err.Error() != "injected store commit failure" {
		t.Fatalf("Update() error = %v", err)
	}
	if candidate.opened() {
		t.Fatal("candidate SQL pool remained open after store commit failure")
	}
}

func TestSQLBackendRejectedRuntimeRetiresCandidatePool(t *testing.T) {
	server := newRuntimeActivationTestServer()
	server.sqlBackends = make(map[*sqlBackendRuntimeConfiguration]struct{})
	defer server.closeSQLBackends()
	activeConfiguration := openSQLBackendPoolFixture(t)
	staleConfiguration := openSQLBackendPoolFixture(t)
	server.registerSQLBackend(activeConfiguration)
	server.registerSQLBackend(staleConfiguration)
	active := &runtimeState{
		revision:  2,
		databases: []runtimeDatabase{{sqlBackend: activeConfiguration}},
	}
	stale := &runtimeState{
		revision:  1,
		databases: []runtimeDatabase{{sqlBackend: staleConfiguration}},
	}

	server.activateRuntime(active)
	server.activateRuntime(stale)
	if server.runtime.Load() != active {
		t.Fatal("stale runtime replaced the active runtime")
	}
	if !activeConfiguration.opened() {
		t.Fatal("stale runtime cleanup closed the active SQL pool")
	}
	if staleConfiguration.opened() {
		t.Fatal("rejected stale runtime left its SQL pool open")
	}
}

func TestSQLBackendDDSOperationRetainsRuntimePool(t *testing.T) {
	server := newRuntimeActivationTestServer()
	server.sqlBackends = make(map[*sqlBackendRuntimeConfiguration]struct{})
	defer server.closeSQLBackends()
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	blocking := &sqlBackendBlockingUpdateStore{
		Store:   base,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	server.config.Store = blocking
	oldConfiguration := openSQLBackendPoolFixture(t)
	server.registerSQLBackend(oldConfiguration)
	oldRuntime := &runtimeState{
		revision: 1,
		databases: []runtimeDatabase{{
			partition:  "data",
			sqlBackend: oldConfiguration,
		}},
	}
	server.activateRuntime(oldRuntime)

	done := make(chan error, 1)
	go func() {
		done <- server.expireDDSDatabase(
			context.Background(),
			runtimeDatabase{partition: "data"},
			time.Now(),
		)
	}()
	<-blocking.entered
	server.activateRuntime(&runtimeState{revision: 2})
	if !oldConfiguration.opened() {
		t.Fatal("runtime switch closed SQL pool during DDS operation")
	}
	close(blocking.release)
	if err := <-done; err != nil {
		t.Fatalf("expireDDSDatabase(): %v", err)
	}
	if oldConfiguration.opened() {
		t.Fatal("DDS operation release left retired SQL pool open")
	}
}

type sqlBackendCommitFailureStore struct {
	storage.Store
}

func (store *sqlBackendCommitFailureStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	if err := store.Store.Update(ctx, update); err != nil {
		return err
	}
	return errors.New("injected store commit failure")
}

type sqlBackendBlockingUpdateStore struct {
	storage.Store
	entered chan struct{}
	release chan struct{}
}

func (store *sqlBackendBlockingUpdateStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	close(store.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-store.release:
	}
	return store.Store.Update(ctx, update)
}

func TestSQLBackendTransactionRejectsMultipleBackends(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	first := openSQLBackendPoolFixture(t)
	second := openSQLBackendPoolFixture(t)
	t.Cleanup(func() {
		_ = first.close()
		_ = second.close()
	})

	coordinator := newSQLBackendTransactionCoordinator(context.Background())
	defer coordinator.rollback()
	err := store.Update(context.Background(), func(base storage.Writer) error {
		firstWriter := coordinator.writer(first, base)
		if firstWriter.initializationErr != nil {
			t.Fatalf("initialize first SQL writer: %v", firstWriter.initializationErr)
		}
		secondWriter := coordinator.writer(second, base)
		failure := asOperationFailure(secondWriter.initializationErr)
		if failure == nil || failure.result.Code != ldapwire.ResultUnwillingToPerform {
			t.Fatalf("second SQL writer failure = %#v", secondWriter.initializationErr)
		}
		return coordinator.commit()
	})
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf("multi-backend commit failure = %#v", err)
	}
}

func openSQLBackendPoolFixture(t *testing.T) *sqlBackendRuntimeConfiguration {
	t.Helper()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open SQL pool fixture: %v", err)
	}
	if err := database.Ping(); err != nil {
		t.Fatalf("ping SQL pool fixture: %v", err)
	}
	return &sqlBackendRuntimeConfiguration{db: database}
}

func testSQLBuiltinRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	return registry
}

func seedSQLBackendConfiguration(t *testing.T, store storage.Store, databaseName string) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}sql,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcSqlConfig")},
			{Description: "olcDatabase", Values: stringValues("{1}sql")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcRootDN", Values: stringValues("cn=admin,dc=example,dc=com")},
			{Description: "olcRootPW", Values: stringValues("admin-secret")},
			{Description: "olcDbName", Values: stringValues(databaseName)},
			{Description: "olcDbUser", Values: stringValues("unused")},
			{Description: "olcAccess", Values: stringValues(
				"{0}to attrs=userPassword by anonymous auth by self write by * none",
				"{1}to * by users read by * read",
			)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed SQL backend configuration: %v", err)
	}
}

func seedSQLBackendOnlineAdministration(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "cn=schema,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcSchemaConfig")},
				{Description: "cn", Values: stringValues("schema")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * none")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	}); err != nil {
		t.Fatalf("seed online SQL administration: %v", err)
	}
}

func seedSQLBackendDatabase(t *testing.T, databaseName string) {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open SQLite fixture: %v", err)
	}
	defer database.Close()
	statements := []string{
		`CREATE TABLE ldap_oc_mappings (
			id INTEGER PRIMARY KEY, name TEXT, keytbl TEXT, keycol TEXT,
			create_proc TEXT, delete_proc TEXT, expect_return INTEGER
		)`,
		`CREATE TABLE ldap_attr_mappings (
			id INTEGER PRIMARY KEY, oc_map_id INTEGER, name TEXT,
			sel_expr TEXT, from_tbls TEXT, join_where TEXT,
			add_proc TEXT, delete_proc TEXT, param_order INTEGER,
			expect_return INTEGER, sel_expr_u TEXT
		)`,
		`CREATE TABLE ldap_entries (
			id INTEGER PRIMARY KEY, dn TEXT UNIQUE, oc_map_id INTEGER,
			parent INTEGER, keyval INTEGER
		)`,
		`CREATE TABLE ldap_entry_objclasses (entry_id INTEGER, oc_name TEXT)`,
		`CREATE TABLE organizations (id INTEGER PRIMARY KEY, dc TEXT)`,
		`CREATE TABLE persons (
			id INTEGER PRIMARY KEY, uid TEXT, cn TEXT, sn TEXT,
			user_password BLOB, jpeg_photo BLOB
		)`,
		`INSERT INTO ldap_oc_mappings VALUES (1,'inetOrgPerson','persons','id',NULL,NULL,0)`,
		`INSERT INTO ldap_oc_mappings VALUES (3,'domain','organizations','id',NULL,NULL,0)`,
		`INSERT INTO ldap_attr_mappings VALUES (1,3,'dc','organizations.dc','organizations',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO ldap_attr_mappings VALUES (2,1,'uid','persons.uid','persons',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO ldap_attr_mappings VALUES (3,1,'cn','persons.cn','persons',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO ldap_attr_mappings VALUES (4,1,'sn','persons.sn','persons',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO ldap_attr_mappings VALUES (5,1,'userPassword','persons.user_password','persons',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO ldap_attr_mappings VALUES (6,1,'jpegPhoto','persons.jpeg_photo','persons',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO organizations VALUES (10,'example')`,
		`INSERT INTO persons VALUES (20,'alice','Alice Example','Example','alice-secret',X'00FF10')`,
		`INSERT INTO ldap_entries VALUES (1,'dc=example,dc=com',3,0,10)`,
		`INSERT INTO ldap_entries VALUES (2,'uid=alice,dc=example,dc=com',1,1,20)`,
	}
	for index, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("SQL fixture statement %d: %v\n%s", index, err, statement)
		}
	}
	if err := database.Ping(); err != nil {
		t.Fatalf("ping SQLite fixture: %v", err)
	}
}
