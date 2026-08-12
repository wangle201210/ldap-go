package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSQLBackendLDAPWriteOperations(t *testing.T) {
	database, client := startWritableSQLBackend(t)

	request := writableSQLPersonAddRequest(
		"bob",
		"Bob Example",
		"Example",
		"initial description",
	)
	if err := client.Add(request); err != nil {
		t.Fatalf("SQL Add(): %v", err)
	}

	personID := writableSQLPersonID(t, database, "bob")
	assertWritableSQLPerson(t, database, personID, "bob", "Bob Example", "Example")
	assertWritableSQLDescriptions(t, database, personID, "initial description")
	assertWritableSQLEntry(t, database, request.DN, personID)
	clearWritableSQLProcedureEvents(t, database)

	add := ldap.NewModifyRequest(request.DN, nil)
	add.Add("description", []string{"second description"})
	if err := client.Modify(add); err != nil {
		t.Fatalf("SQL Modify add: %v", err)
	}
	assertWritableSQLDescriptions(
		t,
		database,
		personID,
		"initial description",
		"second description",
	)
	assertWritableSQLProcedureEvents(t, database, "add:second description")
	clearWritableSQLProcedureEvents(t, database)

	remove := ldap.NewModifyRequest(request.DN, nil)
	remove.Delete("description", []string{"initial description"})
	if err := client.Modify(remove); err != nil {
		t.Fatalf("SQL Modify delete: %v", err)
	}
	assertWritableSQLDescriptions(t, database, personID, "second description")
	assertWritableSQLProcedureEvents(t, database, "delete:initial description")
	clearWritableSQLProcedureEvents(t, database)

	replace := ldap.NewModifyRequest(request.DN, nil)
	replace.Replace("cn", []string{"Robert Example"})
	if err := client.Modify(replace); err != nil {
		t.Fatalf("SQL Modify replace: %v", err)
	}
	assertWritableSQLPerson(t, database, personID, "bob", "Robert Example", "Example")
	assertWritableSQLProcedureEvents(t, database, "delete-cn:Bob Example", "add-cn:Robert Example")

	incrementEntry := writableSQLPersonAddRequest("increment", "Increment User", "10")
	if err := client.Add(incrementEntry); err != nil {
		t.Fatalf("SQL Add increment fixture: %v", err)
	}
	incrementID := writableSQLPersonID(t, database, "increment")
	increment := ldap.NewModifyRequest(incrementEntry.DN, nil)
	increment.Increment("sn", "1")
	if err := client.Modify(increment); err != nil {
		t.Fatalf("SQL Modify increment with fail_if_no_mapping=false: %v", err)
	}
	assertWritableSQLScalar(t, database, "SELECT sn FROM persons WHERE id=?", incrementID, "10")
	if err := client.Del(ldap.NewDelRequest(incrementEntry.DN, nil)); err != nil {
		t.Fatalf("SQL Delete increment fixture: %v", err)
	}

	rename := ldap.NewModifyDNRequest(request.DN, "uid=robert", true, "")
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("SQL ModifyDN(): %v", err)
	}
	renamedDN := "uid=robert,dc=example,dc=com"
	assertWritableSQLPerson(t, database, personID, "robert", "Robert Example", "Example")
	assertWritableSQLEntry(t, database, renamedDN, personID)

	if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("SQL Delete(): %v", err)
	}
	assertWritableSQLCount(t, database, "persons", 0)
	assertWritableSQLCount(t, database, "person_descriptions", 0)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 0, renamedDN)
}

func TestSQLBackendIncrementFailsWhenMappingFailureIsRequired(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "increment.db")
	seedWritableSQLBackendDatabase(t, databaseName)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	seedSQLBackendOnlineAdministration(t, store)
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	request := writableSQLPersonAddRequest("counter", "Counter User", "10")
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(): %v", err)
	}
	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	modifyConfig := ldap.NewModifyRequest("olcDatabase={1}sql,cn=config", nil)
	modifyConfig.Replace("olcSqlFailIfNoMapping", []string{"TRUE"})
	if err := configClient.Modify(modifyConfig); err != nil {
		t.Fatalf("enable olcSqlFailIfNoMapping: %v", err)
	}
	increment := ldap.NewModifyRequest(request.DN, nil)
	increment.Increment("sn", "1")
	assertLDAPResultCode(t, client.Modify(increment), ldap.LDAPResultOther)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer database.Close()
	personID := writableSQLPersonID(t, database, "counter")
	assertWritableSQLScalar(t, database, "SELECT sn FROM persons WHERE id=?", personID, "10")
}

func TestSQLBackendWriterUsesTransactionCoordinator(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "coordinator.db")
	seedWritableSQLBackendDatabase(t, databaseName)
	registry := testSQLBuiltinRegistry(t)
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
		registry:          registry,
	}
	coordinator := newSQLBackendTransactionCoordinator(context.Background())
	ctx := withSQLBackendTransactionCoordinator(context.Background(), coordinator)
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	if err := base.Update(ctx, func(raw storage.Writer) error {
		writer := accessWriterFromContext(ctx, raw)
		tx := writerForDatabase(writer, runtimeDatabase{sqlBackend: configuration})
		if _, ok := tx.(*sqlBackendWriter); !ok {
			t.Fatalf("writerForDatabase() = %T", tx)
		}
		entry := writableSQLPersonEntry("direct", "Direct User", "User")
		entry.ReplaceValues("structuralObjectClass", stringValues("inetOrgPerson"))
		if err := tx.Put(entry, false); err != nil {
			return err
		}
		backend := tx.(*sqlBackendWriter)
		var count int
		if err := backend.tx.QueryRowContext(
			ctx,
			"SELECT COUNT(*) FROM persons WHERE uid='direct'",
		).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("transaction person count = %d, want 1", count)
		}
		return coordinator.commit()
	}); err != nil {
		t.Fatalf("coordinated Put(): %v", err)
	}
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if got := writableSQLPersonID(t, database, "direct"); got == 0 {
		t.Fatal("coordinated Put did not persist")
	}
}

func TestSQLBackendProcedureParameterContracts(t *testing.T) {
	state := &sqlBackendProcedureDriverState{}
	databaseName := registerSQLBackendProcedureDriver(t, state)
	database, err := sql.Open(sqlBackendProcedureDriverName, databaseName)
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer database.Close()
	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx(): %v", err)
	}
	defer transaction.Rollback()
	writer := &sqlBackendWriter{
		tx: transaction,
		reader: &sqlBackendReader{
			ctx: context.Background(),
			configuration: &sqlBackendRuntimeConfiguration{
				registry: testSQLBuiltinRegistry(t),
			},
		},
	}

	keyValue, err := writer.createMappedObject(
		writableSQLPersonEntry("hint", "Hint User", "User"),
		&sqlObjectClassMapping{
			name:            "inetOrgPerson",
			createProcedure: "create-object",
			expectReturn:    1,
			createHint:      "uid",
		},
	)
	if err != nil {
		t.Fatalf("createMappedObject(): %v", err)
	}
	if keyValue != 42 {
		t.Fatalf("created key = %d, want 42", keyValue)
	}
	if err := writer.executeObjectDelete(&sqlObjectClassMapping{
		name:            "inetOrgPerson",
		deleteProcedure: "delete-object",
		expectReturn:    2,
	}, 42); err != nil {
		t.Fatalf("executeObjectDelete(): %v", err)
	}

	attributeCases := []struct {
		name           string
		add            bool
		parameterOrder int64
		expectReturn   int64
		want           []any
	}{
		{name: "add-key-value", add: true, want: []any{int64(42), "value"}},
		{name: "add-value-key", add: true, parameterOrder: 1, want: []any{"value", int64(42)}},
		{name: "delete-key-value", want: []any{int64(42), "value"}},
		{name: "delete-value-key", parameterOrder: 2, want: []any{"value", int64(42)}},
		{name: "add-output", add: true, expectReturn: 1, want: []any{sqlBackendProcedureOut{}, int64(42), "value"}},
		{name: "delete-output", expectReturn: 2, want: []any{sqlBackendProcedureOut{}, int64(42), "value"}},
	}
	for _, test := range attributeCases {
		if err := writer.executeAttributeProcedure(sqlAttributeMapping{
			name:            "cn",
			addProcedure:    test.name,
			deleteProcedure: test.name,
			parameterOrder:  test.parameterOrder,
			expectReturn:    test.expectReturn,
		}, test.add, 42, []byte("value")); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
	}

	calls := state.callsSnapshot()
	if len(calls) != 2+len(attributeCases) {
		t.Fatalf("procedure calls = %d, want %d", len(calls), 2+len(attributeCases))
	}
	assertSQLBackendProcedureArguments(t, calls[0], []any{sqlBackendProcedureOut{}, "hint"})
	assertSQLBackendProcedureArguments(t, calls[1], []any{sqlBackendProcedureOut{}, int64(42)})
	for index, test := range attributeCases {
		assertSQLBackendProcedureArguments(t, calls[index+2], test.want)
	}
}

func TestSQLBackendLDAPNoOpRollsBack(t *testing.T) {
	database, client := startWritableSQLBackend(t)

	request := writableSQLPersonAddRequest(
		"noop",
		"No-Op User",
		"User",
		"must roll back",
	)
	request.Controls = []ldap.Control{
		ldap.NewControlString(noOpControlOID, true, ""),
	}
	assertLDAPResultCode(t, client.Add(request), uint16(ldapwire.ResultNoOperation))

	assertWritableSQLCount(t, database, "persons", 0)
	assertWritableSQLCount(t, database, "person_descriptions", 0)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 0, request.DN)
}

func TestSQLBackendLDAPAutocommitPreservesNoOpWrites(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "autocommit.db")
	seedWritableSQLBackendDatabase(t, databaseName)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}sql,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSqlAutocommit", stringValues("TRUE"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("enable SQL autocommit: %v", err)
	}
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	request := writableSQLPersonAddRequest("autocommit", "Autocommit User", "User")
	request.Controls = []ldap.Control{
		ldap.NewControlString(noOpControlOID, true, ""),
	}
	assertLDAPResultCode(t, client.Add(request), uint16(ldapwire.ResultNoOperation))
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer database.Close()
	if got := writableSQLPersonID(t, database, "autocommit"); got == 0 {
		t.Fatal("autocommit No-Op Add did not preserve SQL writes")
	}
}

func TestSQLBackendLDAPWriteFailureRollsBack(t *testing.T) {
	database, client := startWritableSQLBackend(t)

	request := writableSQLPersonAddRequest(
		"rollback",
		"Rollback User",
		"FORCE-ROLLBACK",
		"created before the forced failure",
	)
	assertLDAPResultCode(t, client.Add(request), ldap.LDAPResultOther)

	assertWritableSQLCount(t, database, "persons", 0)
	assertWritableSQLCount(t, database, "person_descriptions", 0)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 0, request.DN)
}

func TestSQLBackendRejectsRFC5805Transactions(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "back-sql-write.db")
	seedWritableSQLBackendDatabase(t, databaseName)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := writableSQLPersonEntry(
		"transaction",
		"Transaction User",
		"User",
		"must not be queued",
	)
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(entry),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultUnwillingToPerform))
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 4, false, identifier),
		int64(ldapwire.ResultSuccess),
	)

	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open writable SQLite fixture: %v", err)
	}
	defer database.Close()
	assertWritableSQLCount(t, database, "persons", 0)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 0, entry.DN)
}

func startWritableSQLBackend(t *testing.T) (*sql.DB, *ldap.Conn) {
	t.Helper()
	databaseName := filepath.Join(t.TempDir(), "back-sql-write.db")
	seedWritableSQLBackendDatabase(t, databaseName)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	t.Cleanup(stop)

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("SQL root Bind(): %v", err)
	}

	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open writable SQLite fixture: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, client
}

func seedWritableSQLBackendDatabase(t *testing.T, databaseName string) {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open writable SQLite fixture: %v", err)
	}
	defer database.Close()

	statements := []string{
		`CREATE TABLE ldap_oc_mappings (
			id INTEGER PRIMARY KEY, name TEXT NOT NULL, keytbl TEXT NOT NULL,
			keycol TEXT NOT NULL, create_proc TEXT, create_keyval TEXT,
			delete_proc TEXT, expect_return INTEGER NOT NULL DEFAULT 0,
			create_hint TEXT
		)`,
		`CREATE TABLE ldap_attr_mappings (
			id INTEGER PRIMARY KEY, oc_map_id INTEGER NOT NULL, name TEXT NOT NULL,
			sel_expr TEXT NOT NULL, from_tbls TEXT, join_where TEXT,
			add_proc TEXT, delete_proc TEXT, param_order INTEGER NOT NULL DEFAULT 0,
			expect_return INTEGER NOT NULL DEFAULT 0, sel_expr_u TEXT
		)`,
		`CREATE TABLE ldap_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT, dn TEXT NOT NULL UNIQUE,
			oc_map_id INTEGER NOT NULL, parent INTEGER NOT NULL, keyval INTEGER NOT NULL,
			UNIQUE (oc_map_id, keyval)
		)`,
		`CREATE TABLE ldap_entry_objclasses (
			entry_id INTEGER NOT NULL, oc_name TEXT NOT NULL,
			PRIMARY KEY (entry_id, oc_name)
		)`,
		`CREATE TABLE organizations (id INTEGER PRIMARY KEY, dc TEXT NOT NULL)`,
		`CREATE TABLE persons (
			id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT UNIQUE, cn TEXT, sn TEXT
		)`,
		`CREATE TABLE person_descriptions (
			person_id INTEGER NOT NULL, value TEXT NOT NULL,
			PRIMARY KEY (person_id, value)
		)`,
		`CREATE TABLE procedure_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL
		)`,
		`CREATE TRIGGER log_description_add
			AFTER INSERT ON person_descriptions
			BEGIN
				INSERT INTO procedure_events(event) VALUES ('add:' || NEW.value);
			END`,
		`CREATE TRIGGER log_description_delete
			AFTER DELETE ON person_descriptions
			BEGIN
				INSERT INTO procedure_events(event) VALUES ('delete:' || OLD.value);
			END`,
		`CREATE TRIGGER log_cn_add
			AFTER UPDATE OF cn ON persons
			WHEN NEW.cn IS NOT NULL
			BEGIN
				INSERT INTO procedure_events(event) VALUES ('add-cn:' || NEW.cn);
			END`,
		`CREATE TRIGGER log_cn_delete
			AFTER UPDATE OF cn ON persons
			WHEN OLD.cn IS NOT NULL AND NEW.cn IS NULL
			BEGIN
				INSERT INTO procedure_events(event) VALUES ('delete-cn:' || OLD.cn);
			END`,
		`CREATE TRIGGER reject_forced_sn
			BEFORE UPDATE OF sn ON persons
			WHEN NEW.sn = 'FORCE-ROLLBACK'
			BEGIN
				SELECT RAISE(ABORT, 'forced mapped attribute failure');
			END`,
		`INSERT INTO ldap_oc_mappings (
			id, name, keytbl, keycol, create_proc, delete_proc, expect_return
		) VALUES (
			1, 'inetOrgPerson', 'persons', 'id',
			'INSERT INTO persons DEFAULT VALUES RETURNING id',
			'DELETE FROM persons WHERE id=?', 0
		)`,
		`INSERT INTO ldap_oc_mappings (
			id, name, keytbl, keycol, create_proc, delete_proc, expect_return
		) VALUES (3, 'domain', 'organizations', 'id', NULL, NULL, 0)`,
		`INSERT INTO ldap_attr_mappings (
			id, oc_map_id, name, sel_expr, from_tbls, join_where,
			add_proc, delete_proc, param_order, expect_return
		) VALUES (
			1, 3, 'dc', 'organizations.dc', 'organizations', NULL,
			NULL, NULL, 0, 0
		)`,
		`INSERT INTO ldap_attr_mappings (
			id, oc_map_id, name, sel_expr, from_tbls, join_where,
			add_proc, delete_proc, param_order, expect_return
		) VALUES
			(2, 1, 'uid', 'persons.uid', 'persons', NULL,
			 'UPDATE persons SET uid=? WHERE id=?',
			 'UPDATE persons SET uid=NULL WHERE uid=? AND id=?', 3, 0),
			(3, 1, 'cn', 'persons.cn', 'persons', NULL,
			 'UPDATE persons SET cn=? WHERE id=?',
			 'UPDATE persons SET cn=NULL WHERE cn=? AND id=?', 3, 0),
			(4, 1, 'sn', 'persons.sn', 'persons', NULL,
			 'UPDATE persons SET sn=? WHERE id=?',
			 'UPDATE persons SET sn=NULL WHERE sn=? AND id=?', 3, 0),
			(5, 1, 'description', 'person_descriptions.value', 'person_descriptions',
			 'persons.id=person_descriptions.person_id',
			 'INSERT INTO person_descriptions (value,person_id) VALUES (?,?)',
			 'DELETE FROM person_descriptions WHERE value=? AND person_id=?', 3, 0)`,
		`INSERT INTO organizations (id, dc) VALUES (10, 'example')`,
		`INSERT INTO ldap_entries (id, dn, oc_map_id, parent, keyval)
		 VALUES (1, 'dc=example,dc=com', 3, 0, 10)`,
	}
	for index, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("writable SQL fixture statement %d: %v\n%s", index, err, statement)
		}
	}
	if err := database.Ping(); err != nil {
		t.Fatalf("ping writable SQLite fixture: %v", err)
	}
}

func writableSQLPersonAddRequest(
	uid string,
	cn string,
	sn string,
	descriptions ...string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest("uid="+uid+",dc=example,dc=com", nil)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{cn})
	request.Attribute("sn", []string{sn})
	if len(descriptions) != 0 {
		request.Attribute("description", descriptions)
	}
	return request
}

func writableSQLPersonEntry(
	uid string,
	cn string,
	sn string,
	descriptions ...string,
) directory.Entry {
	entry := directory.Entry{
		DN: "uid=" + uid + ",dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(cn)},
			{Description: "sn", Values: stringValues(sn)},
		},
	}
	if len(descriptions) != 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "description",
			Values:      stringValues(descriptions...),
		})
	}
	return entry
}

const sqlBackendProcedureDriverName = "ldap-go-sql-procedure-contract"

var (
	sqlBackendProcedureDriverOnce   sync.Once
	sqlBackendProcedureDriverStates sync.Map
)

type sqlBackendProcedureDriver struct{}

type sqlBackendProcedureDriverState struct {
	mu                  sync.Mutex
	calls               []sqlBackendProcedureCall
	beginOptions        []driver.TxOptions
	rejectRichTxOptions bool
}

type sqlBackendProcedureCall struct {
	query     string
	arguments []any
}

type sqlBackendProcedureConnection struct {
	state *sqlBackendProcedureDriverState
}

type sqlBackendProcedureTransaction struct{}

type sqlBackendProcedureOut struct{}

type sqlBackendProcedureOutBinding struct {
	destination any
}

func registerSQLBackendProcedureDriver(
	t *testing.T,
	state *sqlBackendProcedureDriverState,
) string {
	t.Helper()
	sqlBackendProcedureDriverOnce.Do(func() {
		sql.Register(sqlBackendProcedureDriverName, sqlBackendProcedureDriver{})
	})
	name := t.Name() + "/" + t.TempDir()
	sqlBackendProcedureDriverStates.Store(name, state)
	t.Cleanup(func() { sqlBackendProcedureDriverStates.Delete(name) })
	return name
}

func (sqlBackendProcedureDriver) Open(
	name string,
) (driver.Conn, error) {
	state, found := sqlBackendProcedureDriverStates.Load(name)
	if !found {
		return nil, errors.New("unknown SQL procedure test state")
	}
	return &sqlBackendProcedureConnection{
		state: state.(*sqlBackendProcedureDriverState),
	}, nil
}

func (connection *sqlBackendProcedureConnection) Prepare(
	string,
) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not implemented")
}

func (connection *sqlBackendProcedureConnection) Close() error {
	return nil
}

func (connection *sqlBackendProcedureConnection) Begin() (driver.Tx, error) {
	return sqlBackendProcedureTransaction{}, nil
}

func (connection *sqlBackendProcedureConnection) BeginTx(
	_ context.Context,
	options driver.TxOptions,
) (driver.Tx, error) {
	connection.state.mu.Lock()
	connection.state.beginOptions = append(connection.state.beginOptions, options)
	reject := connection.state.rejectRichTxOptions &&
		(options.Isolation != 0 || options.ReadOnly)
	connection.state.mu.Unlock()
	if reject {
		return nil, errors.New("transaction options are not supported")
	}
	return sqlBackendProcedureTransaction{}, nil
}

func (connection *sqlBackendProcedureConnection) CheckNamedValue(
	value *driver.NamedValue,
) error {
	output, ok := value.Value.(sql.Out)
	if ok {
		value.Value = sqlBackendProcedureOutBinding{destination: output.Dest}
	}
	return nil
}

func (connection *sqlBackendProcedureConnection) ExecContext(
	_ context.Context,
	query string,
	arguments []driver.NamedValue,
) (driver.Result, error) {
	call := sqlBackendProcedureCall{query: query, arguments: make([]any, 0, len(arguments))}
	for _, argument := range arguments {
		if output, ok := argument.Value.(sqlBackendProcedureOutBinding); ok {
			value := int64(ldapwire.ResultSuccess)
			if query == "create-object" {
				value = 42
			}
			destination, ok := output.destination.(*int64)
			if !ok {
				return nil, errors.New("unexpected SQL output destination")
			}
			*destination = value
			call.arguments = append(call.arguments, sqlBackendProcedureOut{})
			continue
		}
		call.arguments = append(call.arguments, argument.Value)
	}
	connection.state.mu.Lock()
	connection.state.calls = append(connection.state.calls, call)
	connection.state.mu.Unlock()
	return driver.RowsAffected(1), nil
}

func (sqlBackendProcedureTransaction) Commit() error {
	return nil
}

func (sqlBackendProcedureTransaction) Rollback() error {
	return nil
}

func (state *sqlBackendProcedureDriverState) callsSnapshot() []sqlBackendProcedureCall {
	state.mu.Lock()
	defer state.mu.Unlock()
	calls := make([]sqlBackendProcedureCall, len(state.calls))
	for index := range state.calls {
		calls[index] = sqlBackendProcedureCall{
			query:     state.calls[index].query,
			arguments: append([]any(nil), state.calls[index].arguments...),
		}
	}
	return calls
}

func assertSQLBackendProcedureArguments(
	t *testing.T,
	call sqlBackendProcedureCall,
	want []any,
) {
	t.Helper()
	if !reflect.DeepEqual(call.arguments, want) {
		t.Fatalf("%s arguments = %#v, want %#v", call.query, call.arguments, want)
	}
}

func writableSQLPersonID(t *testing.T, database *sql.DB, uid string) int64 {
	t.Helper()
	var id int64
	if err := database.QueryRowContext(
		context.Background(),
		"SELECT id FROM persons WHERE uid=?",
		uid,
	).Scan(&id); err != nil {
		t.Fatalf("select person %q: %v", uid, err)
	}
	return id
}

func assertWritableSQLPerson(
	t *testing.T,
	database *sql.DB,
	id int64,
	wantUID string,
	wantCN string,
	wantSN string,
) {
	t.Helper()
	var uid, cn, sn string
	if err := database.QueryRowContext(
		context.Background(),
		"SELECT uid,cn,sn FROM persons WHERE id=?",
		id,
	).Scan(&uid, &cn, &sn); err != nil {
		t.Fatalf("select person %d: %v", id, err)
	}
	if uid != wantUID || cn != wantCN || sn != wantSN {
		t.Fatalf(
			"person %d = uid %q, cn %q, sn %q; want %q, %q, %q",
			id,
			uid,
			cn,
			sn,
			wantUID,
			wantCN,
			wantSN,
		)
	}
}

func assertWritableSQLDescriptions(
	t *testing.T,
	database *sql.DB,
	personID int64,
	want ...string,
) {
	t.Helper()
	rows, err := database.QueryContext(
		context.Background(),
		"SELECT value FROM person_descriptions WHERE person_id=? ORDER BY value",
		personID,
	)
	if err != nil {
		t.Fatalf("select descriptions for person %d: %v", personID, err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scan description for person %d: %v", personID, err)
		}
		got = append(got, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate descriptions for person %d: %v", personID, err)
	}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("descriptions for person %d = %q, want %q", personID, got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("descriptions for person %d = %q, want %q", personID, got, want)
		}
	}
}

func clearWritableSQLProcedureEvents(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec("DELETE FROM procedure_events"); err != nil {
		t.Fatalf("clear procedure events: %v", err)
	}
}

func assertWritableSQLProcedureEvents(
	t *testing.T,
	database *sql.DB,
	want ...string,
) {
	t.Helper()
	rows, err := database.Query("SELECT event FROM procedure_events ORDER BY id")
	if err != nil {
		t.Fatalf("query procedure events: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var event string
		if err := rows.Scan(&event); err != nil {
			t.Fatalf("scan procedure event: %v", err)
		}
		got = append(got, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("procedure events: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("procedure events = %q, want %q", got, want)
	}
}

func assertWritableSQLScalar(
	t *testing.T,
	database *sql.DB,
	query string,
	argument any,
	want string,
) {
	t.Helper()
	var got string
	if err := database.QueryRow(query, argument).Scan(&got); err != nil {
		t.Fatalf("query SQL scalar: %v", err)
	}
	if got != want {
		t.Fatalf("SQL scalar = %q, want %q", got, want)
	}
}

func assertWritableSQLEntry(
	t *testing.T,
	database *sql.DB,
	dn string,
	wantKeyValue int64,
) {
	t.Helper()
	var objectClassID, parentID, keyValue int64
	if err := database.QueryRowContext(
		context.Background(),
		"SELECT oc_map_id,parent,keyval FROM ldap_entries WHERE dn=?",
		dn,
	).Scan(&objectClassID, &parentID, &keyValue); err != nil {
		t.Fatalf("select ldap_entries row %q: %v", dn, err)
	}
	if objectClassID != 1 || parentID != 1 || keyValue != wantKeyValue {
		t.Fatalf(
			"ldap_entries %q = oc_map_id %d, parent %d, keyval %d; want 1, 1, %d",
			dn,
			objectClassID,
			parentID,
			keyValue,
			wantKeyValue,
		)
	}
}

func assertWritableSQLCount(
	t *testing.T,
	database *sql.DB,
	from string,
	want int,
	arguments ...any,
) {
	t.Helper()
	var got int
	if err := database.QueryRowContext(
		context.Background(),
		"SELECT COUNT(*) FROM "+from,
		arguments...,
	).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", from, err)
	}
	if got != want {
		t.Fatalf("count %s = %d, want %d", from, got, want)
	}
}
