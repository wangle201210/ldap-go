package server

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/slingdata-io/godbc"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const sqlBackendModifyDNFailureDriverName = "ldap-go-sql-modifydn-failure"

var (
	sqlBackendModifyDNFailureDriverOnce   sync.Once
	sqlBackendModifyDNFailureDriverStates sync.Map
)

type sqlBackendModifyDNFailureStage string

const (
	sqlBackendModifyDNFailPrepare  sqlBackendModifyDNFailureStage = "prepare"
	sqlBackendModifyDNFailBind     sqlBackendModifyDNFailureStage = "bind"
	sqlBackendModifyDNFailExecute  sqlBackendModifyDNFailureStage = "execute"
	sqlBackendModifyDNFailCanceled sqlBackendModifyDNFailureStage = "canceled"
	sqlBackendModifyDNFailBadConn  sqlBackendModifyDNFailureStage = "bad-connection"
)

type sqlBackendModifyDNFailureDriver struct{}

type sqlBackendModifyDNFailureState struct {
	mu           sync.Mutex
	stage        sqlBackendModifyDNFailureStage
	resultCode   int64
	beginCalls   int
	queryCalls   int
	prepareCalls int
	executeCalls int
}

type sqlBackendModifyDNFailureConnection struct {
	state *sqlBackendModifyDNFailureState
}

type sqlBackendModifyDNFailureStatement struct {
	state *sqlBackendModifyDNFailureState
}

func TestSQLBackendModifyDNProcedureFailureStages(t *testing.T) {
	for _, test := range []struct {
		stage     sqlBackendModifyDNFailureStage
		ignorable bool
	}{
		{stage: sqlBackendModifyDNFailPrepare},
		{stage: sqlBackendModifyDNFailBind},
		{stage: sqlBackendModifyDNFailExecute, ignorable: true},
		{stage: sqlBackendModifyDNFailCanceled},
		{stage: sqlBackendModifyDNFailBadConn},
	} {
		t.Run(string(test.stage), func(t *testing.T) {
			ctx := context.Background()
			writer, closeWriter := newSQLBackendModifyDNFailureWriter(t, ctx, test.stage)
			defer closeWriter()

			err := writer.executePreparedAttributeProcedure(sqlAttributeMapping{
				name:           "uid",
				addProcedure:   "UPDATE persons SET uid=? WHERE id=?",
				parameterOrder: 1,
			}, true, 42, []byte("renamed"))
			var executionError *sqlBackendAttributeProcedureExecutionError
			if got := errors.As(err, &executionError); got != test.ignorable {
				t.Fatalf("execution error classification = %v, want %v (err=%v)", got, test.ignorable, err)
			}
			if test.stage == sqlBackendModifyDNFailCanceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v, want context.Canceled", err)
			}
			if test.stage == sqlBackendModifyDNFailBadConn &&
				!errors.Is(err, driver.ErrBadConn) && !errors.Is(err, sql.ErrConnDone) {
				t.Fatalf("bad connection error = %v, want driver.ErrBadConn/sql.ErrConnDone", err)
			}
		})
	}
}

func TestSQLBackendModifyDNProcedureErrorClassifier(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "odbc constraint", err: &godbc.Error{SQLState: "23000", NativeError: 19}, want: true},
		{name: "wrapped odbc constraint", err: fmt.Errorf("wrapped: %w", &godbc.Error{SQLState: "23000", NativeError: 19}), want: true},
		{name: "odbc sqlite execute", err: &godbc.Error{SQLState: "HY000", NativeError: 19}, want: true},
		{name: "odbc ambiguous general", err: &godbc.Error{SQLState: "HY000"}},
		{name: "odbc unrelated native", err: &godbc.Error{SQLState: "HY000", NativeError: 1}},
		{name: "odbc bind", err: &godbc.Error{SQLState: "HY090", NativeError: 0}},
		{name: "odbc data conversion", err: &godbc.Error{SQLState: "22003", NativeError: 0}},
		{name: "odbc parameter", err: &godbc.ParameterError{Message: "injected"}},
		{name: "database sql conversion", err: fmt.Errorf("sql: converting argument $1 type: %w", &godbc.Error{SQLState: "23000", NativeError: 19})},
		{name: "database sql arity", err: errors.New("sql: expected 2 arguments, got 1")},
		{name: "context canceled", err: context.Canceled},
		{name: "context deadline", err: context.DeadlineExceeded},
		{name: "bad connection", err: driver.ErrBadConn},
		{name: "unknown", err: errors.New("unknown driver failure")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sqlBackendIgnorableProcedureExecutionError(ctx, test.err); got != test.want {
				t.Fatalf("classification = %v, want %v", got, test.want)
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if sqlBackendIgnorableProcedureExecutionError(
		canceled,
		&godbc.Error{SQLState: "23000", NativeError: 19},
	) {
		t.Fatal("execution error was ignored after context cancellation")
	}
}

func TestSQLBackendModifyDNProcedureResultPrecedesExecutionFailure(t *testing.T) {
	state := &sqlBackendModifyDNFailureState{
		stage:      sqlBackendModifyDNFailExecute,
		resultCode: int64(ldapwire.ResultConstraintViolation),
	}
	databaseName := registerSQLBackendModifyDNFailureDriver(t, state)
	database, err := sql.Open(sqlBackendModifyDNFailureDriverName, databaseName)
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("database.Conn(): %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	writer := &sqlBackendWriter{
		conn:     connection,
		executor: connection,
		reader: &sqlBackendReader{
			ctx: context.Background(),
			configuration: &sqlBackendRuntimeConfiguration{
				registry: testSQLBuiltinRegistry(t),
			},
		},
	}

	err = writer.executePreparedAttributeProcedure(sqlAttributeMapping{
		name:           "uid",
		addProcedure:   "UPDATE persons SET uid=? WHERE id=?",
		parameterOrder: 1,
		expectReturn:   1,
	}, true, 42, []byte("renamed"))
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultConstraintViolation {
		t.Fatalf("procedure result = %#v, want constraintViolation", err)
	}
	var executionError *sqlBackendAttributeProcedureExecutionError
	if errors.As(err, &executionError) {
		t.Fatalf("procedure LDAP result was misclassified as ignorable execution failure: %v", err)
	}
}

func TestOpenLDAPReferenceSQLBackendModifyDNAutocommitFailure(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	requireOpenLDAPSQLBackend(t, tools)
	driver := requireSQLiteODBCDriver(t)
	databaseName := filepath.Join(t.TempDir(), "openldap-autocommit.db")
	seedSQLDifferentialDatabase(t, databaseName)

	uri := startOpenLDAPSQLReferenceServerWithAutocommit(
		t,
		tools,
		driver,
		databaseName,
	)
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	const (
		sourceDN = "uid=rollback-move,ou=people,dc=example,dc=com"
		targetDN = "uid=rollback-moved,ou=people,dc=example,dc=com"
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(ldap.NewModifyDNRequest(sourceDN, "uid=rollback-moved", true, "")),
		ldap.LDAPResultNamingViolation,
	)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open reference database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 0, sourceDN)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 1, targetDN)
	assertWritableSQLCount(t, database, "persons WHERE id = 33 AND uid IS NULL", 1)
}

func startOpenLDAPSQLReferenceServerWithAutocommit(
	t *testing.T,
	tools openLDAPReferenceTools,
	driver,
	databaseName string,
) string {
	t.Helper()
	root := t.TempDir()
	odbcinstPath := filepath.Join(root, "odbcinst.ini")
	odbcPath := filepath.Join(root, "odbc.ini")
	configPath := filepath.Join(root, "slapd.conf")
	if err := os.WriteFile(odbcinstPath, []byte(fmt.Sprintf(
		"[SQLite3]\nDescription=SQLite3 ODBC Driver\nDriver=%s\nSetup=%s\nThreading=2\n",
		driver,
		driver,
	)), 0o600); err != nil {
		t.Fatalf("write odbcinst.ini: %v", err)
	}
	if err := os.WriteFile(odbcPath, []byte(fmt.Sprintf(
		"[ldap-go-sql-autocommit]\nDriver=SQLite3\nDatabase=%s\nTimeout=5000\nNoWCHAR=1\n",
		databaseName,
	)), 0o600); err != nil {
		t.Fatalf("write odbc.ini: %v", err)
	}
	config := fmt.Sprintf(`include %s
include %s
include %s
pidfile %s
argsfile %s

access to * by * read

database sql
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw admin-secret
dbname ldap-go-sql-autocommit
dbuser unused
dbpasswd unused
upper_func UPPER
concat_pattern "?||?"
subtree_cond "UPPER(ldap_entries.dn) LIKE '%%'||UPPER(?)"
has_ldapinfo_dn_ru no
autocommit yes
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write SQL slapd.conf: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve SQL reference port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release SQL reference port: %v", err)
	}
	uri := "ldap://" + address
	var logs bytes.Buffer
	command := exec.Command(tools.slapd, "-f", configPath, "-h", uri, "-d", "0")
	command.Env = append(os.Environ(),
		"ODBCSYSINI="+root,
		"ODBCINSTINI=odbcinst.ini",
		"ODBCINI="+odbcPath,
	)
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		t.Fatalf("start OpenLDAP SQL reference: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		select {
		case <-done:
			return
		default:
		}
		if command.Process != nil {
			if err := command.Process.Signal(os.Interrupt); err != nil {
				_ = command.Process.Kill()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
		}
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(8 * time.Second)
	for {
		select {
		case waitErr := <-done:
			stopped = true
			t.Fatalf("OpenLDAP SQL reference exited: %v\n%s", waitErr, logs.String())
		default:
		}
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return uri
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("OpenLDAP SQL reference did not start: %v\n%s", dialErr, logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSQLBackendModifyDNAutocommitFailureRollsBack(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "autocommit-rename.db")
	seedWritableSQLBackendDatabase(t, databaseName)
	const (
		personID = int64(20)
		sourceDN = "uid=rename-source,dc=example,dc=com"
		targetDN = "uid=rename-target,dc=example,dc=com"
	)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open writable SQLite fixture: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec(
		"INSERT INTO persons (id,uid,cn,sn) VALUES (?,?,?,?)",
		personID,
		"rename-source",
		"Rename",
		"User",
	); err != nil {
		t.Fatalf("insert rename source person: %v", err)
	}
	if _, err := database.Exec(
		"INSERT INTO ldap_entries (id,dn,oc_map_id,parent,keyval) VALUES (?,?,?,?,?)",
		int64(2),
		sourceDN,
		int64(1),
		int64(1),
		personID,
	); err != nil {
		t.Fatalf("insert rename source entry: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_autocommit_renamed_uid
		BEFORE UPDATE OF uid ON persons
		WHEN NEW.uid = 'rename-target'
		BEGIN
			SELECT RAISE(ABORT, 'forced RDN add failure');
		END`); err != nil {
		t.Fatalf("create RDN failure trigger: %v", err)
	}

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
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	assertLDAPResultCode(
		t,
		client.ModifyDN(ldap.NewModifyDNRequest(sourceDN, "uid=rename-target", true, "")),
		ldap.LDAPResultNamingViolation,
	)
	assertWritableSQLPerson(t, database, personID, "rename-source", "Rename", "User")
	assertWritableSQLEntry(t, database, sourceDN, personID)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 0, targetDN)
}

func TestSQLBackendModifyDNAutocommitSuccessCommits(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "autocommit-rename-success.db")
	seedWritableSQLBackendDatabase(t, databaseName)
	const (
		personID = int64(20)
		sourceDN = "uid=rename-source,dc=example,dc=com"
		targetDN = "uid=rename-target,dc=example,dc=com"
	)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open writable SQLite fixture: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec(
		"INSERT INTO persons (id,uid,cn,sn) VALUES (?,?,?,?)",
		personID,
		"rename-source",
		"Rename",
		"User",
	); err != nil {
		t.Fatalf("insert rename source person: %v", err)
	}
	if _, err := database.Exec(
		"INSERT INTO ldap_entries (id,dn,oc_map_id,parent,keyval) VALUES (?,?,?,?,?)",
		int64(2),
		sourceDN,
		int64(1),
		int64(1),
		personID,
	); err != nil {
		t.Fatalf("insert rename source entry: %v", err)
	}

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
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	if err := client.ModifyDN(
		ldap.NewModifyDNRequest(sourceDN, "uid=rename-target", true, ""),
	); err != nil {
		t.Fatalf("ModifyDN(): %v", err)
	}
	assertWritableSQLPerson(t, database, personID, "rename-target", "Rename", "User")
	assertWritableSQLEntry(t, database, targetDN, personID)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn = ?", 0, sourceDN)
}

func TestSQLBackendModifyDNODBCExecuteFailureClassification(t *testing.T) {
	driverPath := requireSQLiteODBCDriver(t)
	root := t.TempDir()
	databaseName := filepath.Join(root, "odbc-execute.db")
	seedWritableSQLBackendDatabase(t, databaseName)

	fixture, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open SQLite fixture: %v", err)
	}
	if _, err := fixture.Exec(
		"INSERT INTO persons (id,uid,cn,sn) VALUES (?,?,?,?)",
		int64(20),
		"rename-source",
		"Rename",
		"User",
	); err != nil {
		_ = fixture.Close()
		t.Fatalf("insert rename source: %v", err)
	}
	if _, err := fixture.Exec(`CREATE TRIGGER reject_odbc_renamed_uid
		BEFORE UPDATE OF uid ON persons
		WHEN NEW.uid = 'rename-target'
		BEGIN
			SELECT RAISE(ABORT, 'forced RDN add failure');
		END`); err != nil {
		_ = fixture.Close()
		t.Fatalf("create ODBC failure trigger: %v", err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatalf("close SQLite fixture: %v", err)
	}

	connector, err := newSQLBackendODBCConnector(
		fmt.Sprintf(
			"Driver={%s};Database=%s;Timeout=5000;NoWCHAR=1",
			driverPath,
			databaseName,
		),
	)
	if err != nil {
		t.Fatalf("newSQLBackendODBCConnector(): %v", err)
	}
	database := sql.OpenDB(connector)
	t.Cleanup(func() { _ = database.Close() })
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx(): %v", err)
	}
	writer := &sqlBackendWriter{
		tx: tx,
		reader: &sqlBackendReader{
			ctx: context.Background(),
			configuration: &sqlBackendRuntimeConfiguration{
				registry: testSQLBuiltinRegistry(t),
			},
		},
	}
	err = writer.executePreparedAttributeProcedure(sqlAttributeMapping{
		name:           "uid",
		addProcedure:   "UPDATE persons SET uid=? WHERE id=?",
		parameterOrder: 1,
	}, true, 20, []byte("rename-target"))
	var executionError *sqlBackendAttributeProcedureExecutionError
	if !errors.As(err, &executionError) {
		_ = tx.Rollback()
		t.Fatalf("ODBC execution error = %T %v, want classified SQLExecute failure", err, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback(): %v", err)
	}

	verify, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("reopen SQLite fixture: %v", err)
	}
	t.Cleanup(func() { _ = verify.Close() })
	assertWritableSQLPerson(t, verify, 20, "rename-source", "Rename", "User")
}

func TestSQLBackendModifyDNAutocommitRequiresTransactionSupport(t *testing.T) {
	databaseName := registerSQLBackendModifyDNFailureDriver(t, &sqlBackendModifyDNFailureState{
		stage: sqlBackendModifyDNFailExecute,
	})
	database, err := sql.Open(sqlBackendModifyDNFailureDriverName, databaseName)
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	configuration := &sqlBackendRuntimeConfiguration{db: database, autocommit: true}
	oldDN, _ := directory.ParseDN("uid=old,dc=example,dc=com")
	newDN, _ := directory.ParseDN("uid=new,dc=example,dc=com")
	ctx := withSQLBackendRename(context.Background(), oldDN, newDN)
	coordinator := newSQLBackendTransactionCoordinator(ctx)
	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	var writer *sqlBackendWriter
	if err := base.Update(ctx, func(raw storage.Writer) error {
		writer = coordinator.writer(configuration, raw)
		return nil
	}); err != nil {
		t.Fatalf("create SQL writer: %v", err)
	}
	if writer.initializationErr == nil {
		t.Fatal("autocommit ModifyDN writer accepted a driver without transaction support")
	}
	failure := asOperationFailure(writer.initializationErr)
	if failure == nil || failure.result.Code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf(
			"autocommit ModifyDN transaction failure = %#v, want unwillingToPerform",
			writer.initializationErr,
		)
	}
	if _, err := writer.Get(oldDN); asOperationFailure(err) == nil {
		t.Fatalf("reader after BeginTx failure = %v, want LDAP operation failure", err)
	}
	state := sqlBackendModifyDNFailureDriverState(t, databaseName)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.beginCalls != 1 || state.queryCalls != 0 ||
		state.prepareCalls != 0 || state.executeCalls != 0 {
		t.Fatalf(
			"driver calls = begin:%d query:%d prepare:%d execute:%d, want 1/0/0/0",
			state.beginCalls,
			state.queryCalls,
			state.prepareCalls,
			state.executeCalls,
		)
	}
}

func newSQLBackendModifyDNFailureWriter(
	t *testing.T,
	ctx context.Context,
	stage sqlBackendModifyDNFailureStage,
) (*sqlBackendWriter, func()) {
	t.Helper()
	databaseName := registerSQLBackendModifyDNFailureDriver(t, &sqlBackendModifyDNFailureState{
		stage: stage,
	})
	database, err := sql.Open(sqlBackendModifyDNFailureDriverName, databaseName)
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	connection, err := database.Conn(context.Background())
	if err != nil {
		_ = database.Close()
		t.Fatalf("database.Conn(): %v", err)
	}
	writer := &sqlBackendWriter{
		conn:     connection,
		executor: connection,
		reader: &sqlBackendReader{
			ctx: ctx,
			configuration: &sqlBackendRuntimeConfiguration{
				registry: testSQLBuiltinRegistry(t),
			},
		},
	}
	return writer, func() {
		_ = connection.Close()
		_ = database.Close()
	}
}

func registerSQLBackendModifyDNFailureDriver(
	t *testing.T,
	state *sqlBackendModifyDNFailureState,
) string {
	t.Helper()
	sqlBackendModifyDNFailureDriverOnce.Do(func() {
		sql.Register(sqlBackendModifyDNFailureDriverName, sqlBackendModifyDNFailureDriver{})
	})
	name := t.Name() + "/" + t.TempDir()
	sqlBackendModifyDNFailureDriverStates.Store(name, state)
	t.Cleanup(func() { sqlBackendModifyDNFailureDriverStates.Delete(name) })
	return name
}

func (sqlBackendModifyDNFailureDriver) Open(name string) (driver.Conn, error) {
	state, found := sqlBackendModifyDNFailureDriverStates.Load(name)
	if !found {
		return nil, errors.New("unknown SQL ModifyDN failure test state")
	}
	return &sqlBackendModifyDNFailureConnection{
		state: state.(*sqlBackendModifyDNFailureState),
	}, nil
}

func (connection *sqlBackendModifyDNFailureConnection) Prepare(query string) (driver.Stmt, error) {
	return connection.PrepareContext(context.Background(), query)
}

func (connection *sqlBackendModifyDNFailureConnection) PrepareContext(
	_ context.Context,
	_ string,
) (driver.Stmt, error) {
	connection.state.mu.Lock()
	connection.state.prepareCalls++
	connection.state.mu.Unlock()
	if connection.state.stage == sqlBackendModifyDNFailPrepare {
		return nil, errors.New("injected prepare failure")
	}
	return &sqlBackendModifyDNFailureStatement{state: connection.state}, nil
}

func (*sqlBackendModifyDNFailureConnection) Close() error { return nil }

func (*sqlBackendModifyDNFailureConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}

func (connection *sqlBackendModifyDNFailureConnection) BeginTx(
	context.Context,
	driver.TxOptions,
) (driver.Tx, error) {
	connection.state.mu.Lock()
	connection.state.beginCalls++
	connection.state.mu.Unlock()
	return nil, errors.New("transactions are not supported")
}

func (connection *sqlBackendModifyDNFailureConnection) QueryContext(
	context.Context,
	string,
	[]driver.NamedValue,
) (driver.Rows, error) {
	connection.state.mu.Lock()
	connection.state.queryCalls++
	connection.state.mu.Unlock()
	return &sqlBackendModifyDNEmptyRows{}, nil
}

func (*sqlBackendModifyDNFailureStatement) Close() error  { return nil }
func (*sqlBackendModifyDNFailureStatement) NumInput() int { return -1 }

func (statement *sqlBackendModifyDNFailureStatement) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("unexpected legacy Exec")
}

func (*sqlBackendModifyDNFailureStatement) Query([]driver.Value) (driver.Rows, error) {
	return &sqlBackendModifyDNEmptyRows{}, nil
}

func (statement *sqlBackendModifyDNFailureStatement) ExecContext(
	ctx context.Context,
	arguments []driver.NamedValue,
) (driver.Result, error) {
	statement.state.mu.Lock()
	statement.state.executeCalls++
	statement.state.mu.Unlock()
	switch statement.state.stage {
	case sqlBackendModifyDNFailExecute:
		if statement.state.resultCode != 0 {
			for _, argument := range arguments {
				output, ok := argument.Value.(sql.Out)
				if !ok {
					continue
				}
				destination, ok := output.Dest.(*int64)
				if ok {
					*destination = statement.state.resultCode
				}
			}
		}
		return nil, &godbc.Error{SQLState: "23000", NativeError: 19}
	case sqlBackendModifyDNFailCanceled:
		return nil, context.Canceled
	case sqlBackendModifyDNFailBadConn:
		return nil, driver.ErrBadConn
	default:
		return driver.RowsAffected(1), nil
	}
}

func (statement *sqlBackendModifyDNFailureStatement) CheckNamedValue(*driver.NamedValue) error {
	if statement.state.stage == sqlBackendModifyDNFailBind {
		return &godbc.Error{SQLState: "23000", NativeError: 19}
	}
	return nil
}

type sqlBackendModifyDNEmptyRows struct{}

func (*sqlBackendModifyDNEmptyRows) Columns() []string         { return nil }
func (*sqlBackendModifyDNEmptyRows) Close() error              { return nil }
func (*sqlBackendModifyDNEmptyRows) Next([]driver.Value) error { return io.EOF }

var _ driver.Driver = sqlBackendModifyDNFailureDriver{}
var _ driver.ConnPrepareContext = (*sqlBackendModifyDNFailureConnection)(nil)
var _ driver.ConnBeginTx = (*sqlBackendModifyDNFailureConnection)(nil)
var _ driver.QueryerContext = (*sqlBackendModifyDNFailureConnection)(nil)
var _ driver.StmtExecContext = (*sqlBackendModifyDNFailureStatement)(nil)
var _ driver.NamedValueChecker = (*sqlBackendModifyDNFailureStatement)(nil)
var _ driver.Rows = (*sqlBackendModifyDNEmptyRows)(nil)

func sqlBackendModifyDNFailureDriverState(
	t *testing.T,
	name string,
) *sqlBackendModifyDNFailureState {
	t.Helper()
	state, found := sqlBackendModifyDNFailureDriverStates.Load(name)
	if !found {
		t.Fatalf("SQL ModifyDN failure driver state %q was not found", name)
	}
	return state.(*sqlBackendModifyDNFailureState)
}
