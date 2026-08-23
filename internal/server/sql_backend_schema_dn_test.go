package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
	_ "modernc.org/sqlite"
)

func TestSQLBackendSchemaAwareDNSQLiteMappings(t *testing.T) {
	registry := sqlBackendSchemaDNRegistry(t)
	databaseName := filepath.Join(t.TempDir(), "schema-dn.db")
	seedSQLBackendDatabase(t, databaseName)

	exactUpper := sqlBackendSchemaNormalizedDN(t, registry, "exactName=Tenant,dc=example,dc=com")
	exactLower := sqlBackendSchemaNormalizedDN(t, registry, "exactName=tenant,dc=example,dc=com")
	folded := sqlBackendSchemaNormalizedDN(t, registry, "foldName=Remote Tenant,dc=example,dc=com")
	multiAVA := sqlBackendSchemaNormalizedDN(
		t,
		registry,
		"foldName=Branch+exactName=Tenant,dc=example,dc=com",
	)
	child := sqlBackendSchemaNormalizedDN(
		t,
		registry,
		"foldName=Child,exactName=Tenant,dc=example,dc=com",
	)
	sqlBackendSeedSchemaDNRows(t, databaseName, []sqlBackendSchemaDNRow{
		{id: 3, parent: 1, key: 21, dn: exactUpper.NormalizedString(), uid: "upper"},
		{id: 4, parent: 1, key: 22, dn: exactLower.NormalizedString(), uid: "lower"},
		{id: 5, parent: 1, key: 23, dn: folded.NormalizedString(), uid: "folded"},
		{id: 6, parent: 1, key: 24, dn: multiAVA.NormalizedString(), uid: "multi"},
		{id: 7, parent: 3, key: 25, dn: child.NormalizedString(), uid: "child"},
	})

	configuration := &sqlBackendRuntimeConfiguration{
		databaseName:      databaseName,
		databaseUser:      "unused",
		driverName:        "sqlite",
		ocQuery:           defaultSQLOCQuery,
		attributeQuery:    defaultSQLATQuery,
		idQuery:           defaultSQLIDQuery,
		aliasingKeyword:   "AS ",
		insertEntry:       defaultSQLInsertEntryStatement,
		deleteEntry:       defaultSQLDeleteEntryStatement,
		renameEntry:       defaultSQLRenameEntryStatement,
		deleteObjectClass: defaultSQLDeleteObjectClassesStatement,
		registry:          registry,
	}
	if _, err := configuration.database(context.Background()); err != nil {
		t.Fatalf("initialize schema-aware SQL backend: %v", err)
	}
	t.Cleanup(func() { _ = configuration.close() })

	reader := &sqlBackendReader{
		configuration: configuration,
		ctx: withSQLBackendSearchRequirements(
			context.Background(),
			[]string{"entryUUID", "hasSubordinates"},
		),
	}

	upperEntry := sqlBackendSchemaGet(t, reader, "exactAlias=Tenant,dc=EXAMPLE,dc=COM")
	lowerEntry := sqlBackendSchemaGet(t, reader, "1.3.6.1.4.1.99999.940.1=tenant,dc=example,dc=com")
	if sqlBackendSchemaValue(upperEntry, "uid") != "upper" ||
		sqlBackendSchemaValue(lowerEntry, "uid") != "lower" {
		t.Fatalf("caseExact rows collapsed: upper=%#v lower=%#v", upperEntry, lowerEntry)
	}
	if upperEntry.DN != exactUpper.String() || lowerEntry.DN != exactLower.String() {
		t.Fatalf("canonical SQL DNs = %q, %q", upperEntry.DN, lowerEntry.DN)
	}
	if sqlBackendSchemaValue(upperEntry, "entryUUID") != sqlEntryUUID(1, 21) ||
		sqlBackendSchemaValue(lowerEntry, "entryUUID") != sqlEntryUUID(1, 22) {
		t.Fatalf(
			"entryUUID values = %q, %q",
			sqlBackendSchemaValue(upperEntry, "entryUUID"),
			sqlBackendSchemaValue(lowerEntry, "entryUUID"),
		)
	}
	if sqlBackendSchemaValue(upperEntry, "hasSubordinates") != "TRUE" ||
		sqlBackendSchemaValue(lowerEntry, "hasSubordinates") != "FALSE" {
		t.Fatalf(
			"caseExact hasSubordinates = %q, %q",
			sqlBackendSchemaValue(upperEntry, "hasSubordinates"),
			sqlBackendSchemaValue(lowerEntry, "hasSubordinates"),
		)
	}

	foldedEntry := sqlBackendSchemaGet(
		t,
		reader,
		`foldAlias=\20REMOTE\20\20TENANT\20,0.9.2342.19200300.100.1.25=EXAMPLE,dc=COM`,
	)
	if sqlBackendSchemaValue(foldedEntry, "uid") != "folded" ||
		foldedEntry.DN != folded.NormalizedString() {
		t.Fatalf("caseIgnore/alias lookup = %#v", foldedEntry)
	}
	multiEntry := sqlBackendSchemaGet(
		t,
		reader,
		"1.3.6.1.4.1.99999.940.1=Tenant+foldAlias=BRANCH,dc=example,dc=com",
	)
	if sqlBackendSchemaValue(multiEntry, "uid") != "multi" ||
		multiEntry.DN != multiAVA.NormalizedString() {
		t.Fatalf("multi-AVA lookup = %#v", multiEntry)
	}

	normalizedBase, err := storage.NormalizeReaderDN(reader, exactUpper)
	if err != nil {
		t.Fatalf("normalize scope base: %v", err)
	}
	normalizedChild, err := storage.NormalizeReaderDN(reader, child)
	if err != nil {
		t.Fatalf("normalize scope child: %v", err)
	}
	normalizedLower, err := storage.NormalizeReaderDN(reader, exactLower)
	if err != nil {
		t.Fatalf("normalize caseExact sibling: %v", err)
	}
	if !directory.InScope(normalizedBase, normalizedChild, directory.ScopeWholeSubtree) ||
		directory.InScope(normalizedBase, normalizedLower, directory.ScopeWholeSubtree) {
		t.Fatal("SQL candidate scope did not preserve schema-aware DN identity")
	}
}

func TestSQLBackendSchemaAwareDNQueryParameters(t *testing.T) {
	registry := sqlBackendSchemaDNRegistry(t)
	requested := sqlBackendSchemaNormalizedDN(
		t,
		registry,
		"foldAlias=BRANCH+1.3.6.1.4.1.99999.940.1=Tenant,dc=EXAMPLE,dc=COM",
	)

	for _, test := range []struct {
		name     string
		reversed bool
		want     string
	}{
		{name: "dn", want: requested.NormalizedString()},
		{name: "dn_ru", reversed: true, want: reverseUpperASCII(requested.NormalizedString())},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &sqlBackendSchemaDNDriverState{returnedDN: requested.String()}
			database := openSQLBackendSchemaDNDriver(t, state)
			reader := &sqlBackendReader{
				configuration: &sqlBackendRuntimeConfiguration{
					registry:      registry,
					idQuery:       "entry-id",
					hasReversedDN: test.reversed,
				},
				ctx: context.Background(),
			}
			if _, err := reader.entryIDWithQueryer(database, requested); err != nil {
				t.Fatalf("entryIDWithQueryer(): %v", err)
			}
			call := state.singleCall(t)
			if call.query != "entry-id" || len(call.arguments) != 1 || call.arguments[0] != test.want {
				t.Fatalf("ID query call = %#v, want parameter %q", call, test.want)
			}
			if strings.HasPrefix(call.arguments[0].(string), "dn:v2:") {
				t.Fatalf("internal DN identity leaked to SQL: %q", call.arguments[0])
			}
		})
	}

	state := &sqlBackendSchemaDNDriverState{returnedDN: requested.String(), childCount: 1}
	database := openSQLBackendSchemaDNDriver(t, state)
	reader := &sqlBackendReader{
		configuration: &sqlBackendRuntimeConfiguration{
			registry:         registry,
			hasChildrenQuery: "has-children",
		},
		ctx: context.Background(),
	}
	hasChildren, err := reader.hasChildrenWithQueryer(database, requested)
	if err != nil || !hasChildren {
		t.Fatalf("hasChildrenWithQueryer() = %t, %v", hasChildren, err)
	}
	call := state.singleCall(t)
	if call.query != "has-children" || len(call.arguments) != 1 ||
		call.arguments[0] != requested.NormalizedString() {
		t.Fatalf("has-children query call = %#v", call)
	}
	if strings.HasPrefix(call.arguments[0].(string), "dn:v2:") {
		t.Fatalf("internal DN identity leaked to subordinate query: %q", call.arguments[0])
	}
}

func TestSQLBackendSchemaAwareDNRejectsCaseExactWrongRow(t *testing.T) {
	registry := sqlBackendSchemaDNRegistry(t)
	requested := sqlBackendSchemaNormalizedDN(t, registry, "exactName=Tenant,dc=example,dc=com")
	state := &sqlBackendSchemaDNDriverState{
		returnedDN: "exactName=tenant,dc=example,dc=com",
	}
	database := openSQLBackendSchemaDNDriver(t, state)
	reader := &sqlBackendReader{
		configuration: &sqlBackendRuntimeConfiguration{registry: registry, idQuery: "entry-id"},
		ctx:           context.Background(),
	}
	_, err := reader.entryIDWithQueryer(database, requested)
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("caseExact mismatched SQL row error = %v, want ErrEntryNotFound", err)
	}
}

func sqlBackendSchemaDNRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry := testSQLBuiltinRegistry(t)
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.940.1 NAME ( 'exactName' 'exactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.940.2 NAME ( 'foldName' 'foldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register schema-aware SQL attribute: %v", err)
		}
	}
	return registry
}

func sqlBackendSchemaNormalizedDN(
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

type sqlBackendSchemaDNRow struct {
	id     int64
	parent int64
	key    int64
	dn     string
	uid    string
}

func sqlBackendSeedSchemaDNRows(
	t *testing.T,
	databaseName string,
	rows []sqlBackendSchemaDNRow,
) {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open schema DN fixture: %v", err)
	}
	defer database.Close()
	for _, row := range rows {
		if _, err := database.Exec(
			"INSERT INTO persons VALUES (?,?,?,?,?,?)",
			row.key, row.uid, row.uid, "Schema", "secret", nil,
		); err != nil {
			t.Fatalf("insert schema DN person %d: %v", row.key, err)
		}
		if _, err := database.Exec(
			"INSERT INTO ldap_entries VALUES (?,?,?,?,?)",
			row.id, row.dn, 1, row.parent, row.key,
		); err != nil {
			t.Fatalf("insert schema DN entry %q: %v", row.dn, err)
		}
	}
}

func sqlBackendSchemaGet(
	t *testing.T,
	reader *sqlBackendReader,
	rawDN string,
) directory.Entry {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	entry, err := reader.Get(dn)
	if err != nil {
		t.Fatalf("SQL Get(%q): %v", rawDN, err)
	}
	return entry
}

func sqlBackendSchemaValue(entry directory.Entry, attribute string) string {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return ""
	}
	return string(values[0])
}

const sqlBackendSchemaDNDriverName = "ldap-go-sql-schema-dn-test"

var (
	sqlBackendSchemaDNDriverOnce   sync.Once
	sqlBackendSchemaDNDriverStates sync.Map
)

type sqlBackendSchemaDNDriver struct{}

type sqlBackendSchemaDNDriverState struct {
	mu         sync.Mutex
	returnedDN string
	childCount int64
	calls      []sqlBackendSchemaDNDriverCall
}

type sqlBackendSchemaDNDriverCall struct {
	query     string
	arguments []any
}

type sqlBackendSchemaDNConnection struct {
	state *sqlBackendSchemaDNDriverState
}

type sqlBackendSchemaDNRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func openSQLBackendSchemaDNDriver(
	t *testing.T,
	state *sqlBackendSchemaDNDriverState,
) *sql.DB {
	t.Helper()
	sqlBackendSchemaDNDriverOnce.Do(func() {
		sql.Register(sqlBackendSchemaDNDriverName, sqlBackendSchemaDNDriver{})
	})
	name := t.Name() + "/" + t.TempDir()
	sqlBackendSchemaDNDriverStates.Store(name, state)
	database, err := sql.Open(sqlBackendSchemaDNDriverName, name)
	if err != nil {
		t.Fatalf("open schema DN SQL driver: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
		sqlBackendSchemaDNDriverStates.Delete(name)
	})
	return database
}

func (sqlBackendSchemaDNDriver) Open(name string) (driver.Conn, error) {
	state, found := sqlBackendSchemaDNDriverStates.Load(name)
	if !found {
		return nil, errors.New("unknown schema DN SQL driver state")
	}
	return &sqlBackendSchemaDNConnection{state: state.(*sqlBackendSchemaDNDriverState)}, nil
}

func (connection *sqlBackendSchemaDNConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not implemented")
}

func (connection *sqlBackendSchemaDNConnection) Close() error { return nil }

func (connection *sqlBackendSchemaDNConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not implemented")
}

func (connection *sqlBackendSchemaDNConnection) QueryContext(
	_ context.Context,
	query string,
	arguments []driver.NamedValue,
) (driver.Rows, error) {
	call := sqlBackendSchemaDNDriverCall{query: query, arguments: make([]any, len(arguments))}
	for index := range arguments {
		call.arguments[index] = arguments[index].Value
	}
	connection.state.mu.Lock()
	connection.state.calls = append(connection.state.calls, call)
	returnedDN := connection.state.returnedDN
	childCount := connection.state.childCount
	connection.state.mu.Unlock()
	switch query {
	case "entry-id":
		return &sqlBackendSchemaDNRows{
			columns: []string{"id", "keyval", "oc_map_id", "dn"},
			values:  [][]driver.Value{{int64(17), int64(21), int64(1), returnedDN}},
		}, nil
	case "has-children":
		return &sqlBackendSchemaDNRows{
			columns: []string{"count"},
			values:  [][]driver.Value{{childCount}},
		}, nil
	default:
		return nil, errors.New("unexpected schema DN SQL query")
	}
}

func (rows *sqlBackendSchemaDNRows) Columns() []string { return rows.columns }

func (rows *sqlBackendSchemaDNRows) Close() error { return nil }

func (rows *sqlBackendSchemaDNRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func (state *sqlBackendSchemaDNDriverState) singleCall(
	t *testing.T,
) sqlBackendSchemaDNDriverCall {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.calls) != 1 {
		t.Fatalf("SQL call count = %d, want 1", len(state.calls))
	}
	return state.calls[0]
}
