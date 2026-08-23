package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type sqlDifferentialEntry struct {
	DN         string
	Attributes map[string][]string
}

type sqlDifferentialSearch struct {
	Code    uint16
	Entries []sqlDifferentialEntry
}

type sqlDifferentialObservation struct {
	BindCodes    []uint16
	Searches     []sqlDifferentialSearch
	CompareCodes []uint16
}

type sqlDifferentialDatabaseState struct {
	Entries             []string
	EntryObjectClasses  []string
	Domains             []string
	OrganizationalUnits []string
	Persons             []string
}

type sqlDifferentialLDAPResult struct {
	Operation  string
	Code       uint16
	MatchedDN  string
	Diagnostic string
}

type sqlDifferentialSQLStateExpectation uint8

const (
	sqlDifferentialSQLStateChanged sqlDifferentialSQLStateExpectation = iota
	sqlDifferentialSQLStateBaseline
)

type sqlDifferentialWriteExpectation struct {
	Operation   string
	Code        uint16
	SQLState    sqlDifferentialSQLStateExpectation
	SearchCodes []uint16
}

type sqlDifferentialWriteObservation struct {
	Baseline          sqlDifferentialDatabaseState
	NoOpResults       []sqlDifferentialLDAPResult
	NoOpStates        []sqlDifferentialDatabaseState
	NoOpSearches      []sqlDifferentialSearch
	FailureResults    []sqlDifferentialLDAPResult
	FailureStates     []sqlDifferentialDatabaseState
	FailureSearches   []sqlDifferentialSearch
	LifecycleResults  []sqlDifferentialLDAPResult
	LifecycleStates   []sqlDifferentialDatabaseState
	LifecycleSearches []sqlDifferentialSearch
}

func TestOpenLDAPReferenceSQLBackend(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	requireOpenLDAPSQLBackend(t, tools)
	driver := requireSQLiteODBCDriver(t)

	root := t.TempDir()
	referenceDatabase := filepath.Join(root, "openldap.db")
	localDatabase := filepath.Join(root, "ldap-go.db")
	seedSQLDifferentialDatabase(t, referenceDatabase)
	seedSQLDifferentialDatabase(t, localDatabase)

	referenceURI := startOpenLDAPSQLReferenceServer(
		t,
		tools,
		driver,
		referenceDatabase,
	)
	localURI := startLDAPGoSQLDifferentialServer(t, localDatabase)

	reference := observeSQLDifferentialServer(t, referenceURI)
	local := observeSQLDifferentialServer(t, localURI)
	if !reflect.DeepEqual(local, reference) {
		t.Fatalf("back-sql differential mismatch\nOpenLDAP: %#v\nldap-go:  %#v", reference, local)
	}

	referenceWrites := observeSQLDifferentialWrites(t, referenceURI, referenceDatabase)
	localWrites := observeSQLDifferentialWrites(t, localURI, localDatabase)
	t.Run("OpenLDAP write semantics", func(t *testing.T) {
		assertSQLDifferentialWriteSemantics(t, referenceWrites)
	})
	t.Run("ldap-go write state semantics", func(t *testing.T) {
		assertSQLDifferentialWriteStateSemantics(t, localWrites)
	})
	compareSQLDifferentialWrites(t, referenceWrites, localWrites)
}

func requireOpenLDAPSQLBackend(t *testing.T, tools openLDAPReferenceTools) {
	t.Helper()
	output, _ := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "sql" {
			return
		}
	}
	t.Skip("OpenLDAP reference slapd does not include the SQL backend")
}

func requireSQLiteODBCDriver(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("LDAP_GO_SQLITE_ODBC_DRIVER"); configured != "" {
		if info, err := os.Stat(configured); err == nil && !info.IsDir() {
			return configured
		}
		t.Fatalf("LDAP_GO_SQLITE_ODBC_DRIVER is not a file: %s", configured)
	}
	candidates := []string{
		"/opt/homebrew/opt/sqliteodbc/lib/libsqlite3odbc.dylib",
		"/usr/local/lib/libsqlite3odbc.so",
		"/usr/lib/odbc/libsqlite3odbc.so",
	}
	patterns := []string{
		"/usr/lib/*/odbc/libsqlite3odbc*.so",
		"/usr/lib/*/libsqlite3odbc*.so",
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		candidates = append(candidates, matches...)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("SQLite ODBC driver was not found; set LDAP_GO_SQLITE_ODBC_DRIVER")
	return ""
}

func startOpenLDAPSQLReferenceServer(
	t *testing.T,
	tools openLDAPReferenceTools,
	driver string,
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
		"[ldap-go-sql-differential]\nDriver=SQLite3\nDatabase=%s\nTimeout=5000\nNoWCHAR=1\n",
		databaseName,
	)), 0o600); err != nil {
		t.Fatalf("write odbc.ini: %v", err)
	}
	// Keep fail_if_no_mapping unset. OpenLDAP zero-initializes this flag to false,
	// which exposes its native namingViolation result after a failed RDN value add.
	config := fmt.Sprintf(`include %s
include %s
include %s
pidfile %s
argsfile %s

access to attrs=userPassword
    by anonymous auth
    by self write
    by * none
access to *
    by * read

database sql
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw admin-secret
dbname ldap-go-sql-differential
dbuser unused
dbpasswd unused
upper_func UPPER
concat_pattern "?||?"
subtree_cond "UPPER(ldap_entries.dn) LIKE '%%'||UPPER(?)"
has_ldapinfo_dn_ru no
autocommit no
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
		if command.Process == nil {
			return
		}
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
	t.Cleanup(stop)

	deadline := time.Now().Add(8 * time.Second)
	for {
		select {
		case waitErr := <-done:
			stopped = true
			t.Fatalf(
				"OpenLDAP SQL reference exited during startup: %v\nslapd.conf:\n%s\nlog:\n%s",
				waitErr,
				config,
				logs.String(),
			)
		default:
		}
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("OpenLDAP SQL reference did not start: %v\n%s", dialErr, logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return uri
}

func startLDAPGoSQLDifferentialServer(t *testing.T, databaseName string) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	// Match the reference's omitted/false olcSqlFailIfNoMapping setting.
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
			{Description: "olcSqlUpperFunc", Values: stringValues("UPPER")},
			{Description: "olcSqlSubtreeCond", Values: stringValues("UPPER(ldap_entries.dn) LIKE UPPER(?)")},
			{Description: "olcSqlHasLDAPinfoDnRu", Values: stringValues("FALSE")},
			{Description: "olcSqlAutocommit", Values: stringValues("FALSE")},
			{Description: "olcAccess", Values: stringValues(
				"{0}to attrs=userPassword by anonymous auth by self write by * none",
				"{1}to * by * read",
			)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed ldap-go SQL configuration: %v", err)
	}
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	t.Cleanup(stop)
	return "ldap://" + address
}

func observeSQLDifferentialServer(t *testing.T, uri string) sqlDifferentialObservation {
	t.Helper()
	result := sqlDifferentialObservation{
		BindCodes: []uint16{
			observeSQLBind(t, uri, "uid=alice,ou=people,dc=example,dc=com", "alice-secret"),
			observeSQLBind(t, uri, "uid=alice,ou=people,dc=example,dc=com", "wrong-secret"),
			observeSQLBind(t, uri, "cn=admin,dc=example,dc=com", "admin-secret"),
		},
	}
	searches := []struct {
		base       string
		scope      int
		filter     string
		attributes []string
	}{
		{"dc=example,dc=com", ldap.ScopeBaseObject, "(objectClass=domain)", stableSQLDifferentialAttributes()},
		{"ou=people,dc=example,dc=com", ldap.ScopeSingleLevel, "(&(objectClass=inetOrgPerson)(|(cn=*example)(sn=builder)))", stableSQLDifferentialAttributes()},
		{"ou=people,dc=example,dc=com", ldap.ScopeWholeSubtree, "(objectClass=person)", stableSQLDifferentialAttributes()},
		{"dc=example,dc=com", ldap.ScopeWholeSubtree, "(objectClass=person)", stableSQLDifferentialAttributes()},
		{"dc=example,dc=com", ldap.ScopeWholeSubtree, "(cn=alice example)", stableSQLDifferentialAttributes()},
		{"dc=example,dc=com", ldap.ScopeWholeSubtree, "(cn=*build*)", stableSQLDifferentialAttributes()},
		{"uid=missing,dc=example,dc=com", ldap.ScopeBaseObject, "(objectClass=*)", stableSQLDifferentialAttributes()},
	}
	for _, search := range searches {
		result.Searches = append(result.Searches, observeSQLSearch(
			t,
			uri,
			search.base,
			search.scope,
			search.filter,
			search.attributes,
		))
	}
	const aliceDN = "uid=alice,ou=people,dc=example,dc=com"
	result.CompareCodes = []uint16{
		observeSQLCompare(t, uri, aliceDN, "cn", []byte("alice example")),
		observeSQLCompare(t, uri, aliceDN, "cn", []byte("not alice")),
		observeSQLCompare(t, uri, aliceDN, "jpegPhoto", []byte{0, 0xff, 0x10}),
		observeSQLCompare(t, uri, aliceDN, "missingAttribute", []byte("value")),
	}
	return result
}

func observeSQLDifferentialWrites(
	t *testing.T,
	uri,
	databaseName string,
) sqlDifferentialWriteObservation {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("bind SQL differential writer %s: %v", uri, err)
	}

	const (
		aliceDN        = "uid=alice,ou=people,dc=example,dc=com"
		bobDN          = "uid=bob,ou=people,dc=example,dc=com"
		rollbackDN     = "uid=rollback,ou=people,dc=example,dc=com"
		rollbackAddDN  = "uid=rollback-add,ou=people,dc=example,dc=com"
		rollbackMoveDN = "uid=rollback-move,ou=people,dc=example,dc=com"
		rollbackMoved  = "uid=rollback-moved,ou=people,dc=example,dc=com"
		rollbackDelDN  = "uid=rollback-delete,ou=people,dc=example,dc=com"
		noOpAddDN      = "uid=noop-add,ou=people,dc=example,dc=com"
		noOpRenamedDN  = "uid=noop-renamed,ou=people,dc=example,dc=com"
		lifecycleDN    = "uid=lifecycle,ou=people,dc=example,dc=com"
		lifecycleNewDN = "uid=lifecycle-renamed,ou=people,dc=example,dc=com"
	)
	result := sqlDifferentialWriteObservation{
		Baseline: snapshotSQLDifferentialDatabase(t, databaseName),
	}
	noOp := ldap.NewControlString(noOpControlOID, true, "")

	noOpAdd := sqlDifferentialPersonAddRequest(
		noOpAddDN,
		"noop-add",
		"No-Op Add",
		"NoOp",
		"must not persist",
	)
	noOpAdd.Controls = []ldap.Control{noOp}
	result.NoOpResults = append(
		result.NoOpResults,
		observeSQLDifferentialResult("Add No-Op", client.Add(noOpAdd)),
	)
	result.NoOpStates = append(result.NoOpStates, snapshotSQLDifferentialDatabase(t, databaseName))
	result.NoOpSearches = append(result.NoOpSearches, observeSQLWriteEntry(t, uri, noOpAddDN))

	noOpModify := ldap.NewModifyRequest(aliceDN, []ldap.Control{noOp})
	noOpModify.Replace("cn", []string{"No-Op Alice"})
	result.NoOpResults = append(
		result.NoOpResults,
		observeSQLDifferentialResult("Modify No-Op", client.Modify(noOpModify)),
	)
	result.NoOpStates = append(result.NoOpStates, snapshotSQLDifferentialDatabase(t, databaseName))
	result.NoOpSearches = append(result.NoOpSearches, observeSQLWriteEntry(t, uri, aliceDN))

	noOpRename := ldap.NewModifyDNRequest(aliceDN, "uid=noop-renamed", true, "")
	noOpRename.Controls = []ldap.Control{noOp}
	result.NoOpResults = append(
		result.NoOpResults,
		observeSQLDifferentialResult("ModifyDN No-Op", client.ModifyDN(noOpRename)),
	)
	result.NoOpStates = append(result.NoOpStates, snapshotSQLDifferentialDatabase(t, databaseName))
	result.NoOpSearches = append(
		result.NoOpSearches,
		observeSQLWriteEntry(t, uri, aliceDN),
		observeSQLWriteEntry(t, uri, noOpRenamedDN),
	)

	noOpDelete := ldap.NewDelRequest(bobDN, []ldap.Control{noOp})
	result.NoOpResults = append(
		result.NoOpResults,
		observeSQLDifferentialResult("Delete No-Op", client.Del(noOpDelete)),
	)
	result.NoOpStates = append(result.NoOpStates, snapshotSQLDifferentialDatabase(t, databaseName))
	result.NoOpSearches = append(result.NoOpSearches, observeSQLWriteEntry(t, uri, bobDN))

	rollbackAdd := sqlDifferentialPersonAddRequest(
		rollbackAddDN,
		"rollback-add",
		"Rollback Add",
		"Rollback",
		"created before the forced failure",
	)
	result.FailureResults = append(
		result.FailureResults,
		observeSQLDifferentialResult(
			"Add forced ldap_entries insert failure",
			client.Add(rollbackAdd),
		),
	)
	result.FailureStates = append(
		result.FailureStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.FailureSearches = append(
		result.FailureSearches,
		observeSQLWriteEntry(t, uri, rollbackAddDN),
	)

	rollbackModify := ldap.NewModifyRequest(rollbackDN, nil)
	rollbackModify.Replace("cn", []string{"Rollback Changed"})
	rollbackModify.Replace("sn", []string{"Changed"})
	result.FailureResults = append(
		result.FailureResults,
		observeSQLDifferentialResult(
			"Modify forced mapped sn delete failure",
			client.Modify(rollbackModify),
		),
	)
	result.FailureStates = append(
		result.FailureStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.FailureSearches = append(
		result.FailureSearches,
		observeSQLWriteEntry(t, uri, rollbackDN),
	)

	rollbackRename := ldap.NewModifyDNRequest(
		rollbackMoveDN,
		"uid=rollback-moved",
		true,
		"",
	)
	result.FailureResults = append(
		result.FailureResults,
		observeSQLDifferentialResult(
			"ModifyDN forced mapped uid add failure",
			client.ModifyDN(rollbackRename),
		),
	)
	result.FailureStates = append(
		result.FailureStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.FailureSearches = append(
		result.FailureSearches,
		observeSQLWriteEntry(t, uri, rollbackMoveDN),
		observeSQLWriteEntry(t, uri, rollbackMoved),
	)

	result.FailureResults = append(
		result.FailureResults,
		observeSQLDifferentialResult(
			"Delete forced ldap_entries delete failure",
			client.Del(ldap.NewDelRequest(rollbackDelDN, nil)),
		),
	)
	result.FailureStates = append(
		result.FailureStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.FailureSearches = append(
		result.FailureSearches,
		observeSQLWriteEntry(t, uri, rollbackDelDN),
	)

	lifecycleAdd := sqlDifferentialPersonAddRequest(
		lifecycleDN,
		"lifecycle",
		"Lifecycle Added",
		"Lifecycle",
		"created",
	)
	result.LifecycleResults = append(
		result.LifecycleResults,
		observeSQLDifferentialResult("Add lifecycle", client.Add(lifecycleAdd)),
	)
	result.LifecycleStates = append(
		result.LifecycleStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.LifecycleSearches = append(
		result.LifecycleSearches,
		observeSQLWriteEntry(t, uri, lifecycleDN),
	)

	lifecycleModify := ldap.NewModifyRequest(lifecycleDN, nil)
	lifecycleModify.Replace("cn", []string{"Lifecycle Modified"})
	lifecycleModify.Replace("description", []string{"modified"})
	result.LifecycleResults = append(
		result.LifecycleResults,
		observeSQLDifferentialResult("Modify lifecycle", client.Modify(lifecycleModify)),
	)
	result.LifecycleStates = append(
		result.LifecycleStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.LifecycleSearches = append(
		result.LifecycleSearches,
		observeSQLWriteEntry(t, uri, lifecycleDN),
	)

	lifecycleRename := ldap.NewModifyDNRequest(
		lifecycleDN,
		"uid=lifecycle-renamed",
		true,
		"",
	)
	result.LifecycleResults = append(
		result.LifecycleResults,
		observeSQLDifferentialResult(
			"ModifyDN lifecycle",
			client.ModifyDN(lifecycleRename),
		),
	)
	result.LifecycleStates = append(
		result.LifecycleStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.LifecycleSearches = append(
		result.LifecycleSearches,
		observeSQLWriteEntry(t, uri, lifecycleDN),
		observeSQLWriteEntry(t, uri, lifecycleNewDN),
	)

	result.LifecycleResults = append(
		result.LifecycleResults,
		observeSQLDifferentialResult(
			"Delete lifecycle",
			client.Del(ldap.NewDelRequest(lifecycleNewDN, nil)),
		),
	)
	result.LifecycleStates = append(
		result.LifecycleStates,
		snapshotSQLDifferentialDatabase(t, databaseName),
	)
	result.LifecycleSearches = append(
		result.LifecycleSearches,
		observeSQLWriteEntry(t, uri, lifecycleNewDN),
	)
	return result
}

func sqlDifferentialPersonAddRequest(
	dn,
	uid,
	cn,
	sn,
	description string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute(
		"objectClass",
		[]string{"top", "person", "organizationalPerson", "inetOrgPerson"},
	)
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{cn})
	request.Attribute("sn", []string{sn})
	request.Attribute("description", []string{description})
	return request
}

func observeSQLWriteEntry(t *testing.T, uri, dn string) sqlDifferentialSearch {
	t.Helper()
	return observeSQLSearch(
		t,
		uri,
		dn,
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{
			"objectClass",
			"uid",
			"cn",
			"sn",
			"description",
			"hasSubordinates",
		},
	)
}

func stableSQLDifferentialAttributes() []string {
	return []string{
		"objectClass",
		"dc",
		"ou",
		"uid",
		"cn",
		"sn",
		"description",
		"jpegPhoto",
		"structuralObjectClass",
		"entryUUID",
		"hasSubordinates",
	}
}

func observeSQLBind(t *testing.T, uri, dn, password string) uint16 {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	return sqlDifferentialResultCode(client.Bind(dn, password))
}

func observeSQLSearch(
	t *testing.T,
	uri string,
	base string,
	scope int,
	filter string,
	attributes []string,
) sqlDifferentialSearch {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	response, err := client.Search(ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	))
	observation := sqlDifferentialSearch{Code: sqlDifferentialResultCode(err)}
	if response == nil {
		return observation
	}
	for _, entry := range response.Entries {
		observed := sqlDifferentialEntry{
			DN:         strings.ToLower(entry.DN),
			Attributes: make(map[string][]string),
		}
		for _, attribute := range entry.Attributes {
			name := strings.ToLower(attribute.Name)
			for _, value := range attribute.ByteValues {
				observed.Attributes[name] = append(
					observed.Attributes[name],
					base64.StdEncoding.EncodeToString(value),
				)
			}
			sort.Strings(observed.Attributes[name])
		}
		observation.Entries = append(observation.Entries, observed)
	}
	sort.Slice(observation.Entries, func(left, right int) bool {
		return observation.Entries[left].DN < observation.Entries[right].DN
	})
	return observation
}

func observeSQLCompare(
	t *testing.T,
	uri string,
	dn string,
	attribute string,
	value []byte,
) uint16 {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	matched, err := client.Compare(dn, attribute, string(value))
	if err != nil {
		return sqlDifferentialResultCode(err)
	}
	if matched {
		return ldap.LDAPResultCompareTrue
	}
	return ldap.LDAPResultCompareFalse
}

func dialSQLDifferentialServer(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial %s: %v", uri, err)
	}
	return client
}

func sqlDifferentialResultCode(err error) uint16 {
	return observeSQLDifferentialResult("", err).Code
}

func observeSQLDifferentialResult(operation string, err error) sqlDifferentialLDAPResult {
	result := sqlDifferentialLDAPResult{
		Operation: operation,
		Code:      ldap.LDAPResultSuccess,
	}
	if err == nil {
		return result
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		result.Code = ldapError.ResultCode
		result.MatchedDN = ldapError.MatchedDN
		if ldapError.Err != nil {
			result.Diagnostic = ldapError.Err.Error()
		}
		return result
	}
	result.Code = ldap.ErrorNetwork
	result.Diagnostic = err.Error()
	return result
}

func snapshotSQLDifferentialDatabase(
	t *testing.T,
	databaseName string,
) sqlDifferentialDatabaseState {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open SQL differential snapshot: %v", err)
	}
	defer database.Close()
	return sqlDifferentialDatabaseState{
		Entries: snapshotSQLDifferentialRows(
			t,
			database,
			`SELECT id,dn,oc_map_id,parent,keyval FROM ldap_entries ORDER BY id`,
			5,
		),
		EntryObjectClasses: snapshotSQLDifferentialRows(
			t,
			database,
			`SELECT entry_id,oc_name FROM ldap_entry_objclasses ORDER BY entry_id,oc_name`,
			2,
		),
		Domains: snapshotSQLDifferentialRows(
			t,
			database,
			`SELECT id,dc FROM domains ORDER BY id`,
			2,
		),
		OrganizationalUnits: snapshotSQLDifferentialRows(
			t,
			database,
			`SELECT id,ou,description FROM organizational_units ORDER BY id`,
			3,
		),
		Persons: snapshotSQLDifferentialRows(
			t,
			database,
			`SELECT id,uid,cn,sn,description,user_password,hex(jpeg_photo)
			 FROM persons ORDER BY id`,
			7,
		),
	}
}

func snapshotSQLDifferentialRows(
	t *testing.T,
	database *sql.DB,
	query string,
	columnCount int,
) []string {
	t.Helper()
	rows, err := database.Query(query)
	if err != nil {
		t.Fatalf("query SQL differential snapshot: %v\n%s", err, query)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		values := make([]any, columnCount)
		destinations := make([]any, columnCount)
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			t.Fatalf("scan SQL differential snapshot: %v", err)
		}
		encoded := make([]string, columnCount)
		for index, value := range values {
			switch typed := value.(type) {
			case nil:
				encoded[index] = "null"
			case []byte:
				encoded[index] = "value:" + base64.StdEncoding.EncodeToString(typed)
			case string:
				encoded[index] = "value:" + base64.StdEncoding.EncodeToString([]byte(typed))
			default:
				encoded[index] = fmt.Sprintf("%T:%v", value, value)
			}
		}
		result = append(result, strings.Join(encoded, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate SQL differential snapshot: %v", err)
	}
	return result
}

func assertSQLDifferentialWriteSemantics(
	t *testing.T,
	observation sqlDifferentialWriteObservation,
) {
	t.Helper()
	assertSQLDifferentialOperationSemantics(
		t,
		observation.Baseline,
		observation.NoOpResults,
		observation.NoOpStates,
		observation.NoOpSearches,
		sqlDifferentialNoOpExpectations(),
		true,
	)
	assertSQLDifferentialOperationSemantics(
		t,
		observation.Baseline,
		observation.FailureResults,
		observation.FailureStates,
		observation.FailureSearches,
		sqlDifferentialFailureExpectations(),
		true,
	)
	assertSQLDifferentialOperationSemantics(
		t,
		observation.Baseline,
		observation.LifecycleResults,
		observation.LifecycleStates,
		observation.LifecycleSearches,
		sqlDifferentialLifecycleExpectations(),
		true,
	)
}

func assertSQLDifferentialWriteStateSemantics(
	t *testing.T,
	observation sqlDifferentialWriteObservation,
) {
	t.Helper()
	assertSQLDifferentialOperationSemantics(
		t,
		observation.Baseline,
		observation.NoOpResults,
		observation.NoOpStates,
		observation.NoOpSearches,
		sqlDifferentialNoOpExpectations(),
		false,
	)
	assertSQLDifferentialOperationSemantics(
		t,
		observation.Baseline,
		observation.FailureResults,
		observation.FailureStates,
		observation.FailureSearches,
		sqlDifferentialFailureExpectations(),
		false,
	)
	assertSQLDifferentialOperationSemantics(
		t,
		observation.Baseline,
		observation.LifecycleResults,
		observation.LifecycleStates,
		observation.LifecycleSearches,
		sqlDifferentialLifecycleExpectations(),
		true,
	)
}

func sqlDifferentialNoOpExpectations() []sqlDifferentialWriteExpectation {
	return []sqlDifferentialWriteExpectation{
		{"Add No-Op", uint16(ldapwire.ResultNoOperation), sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultNoSuchObject}},
		{"Modify No-Op", uint16(ldapwire.ResultNoOperation), sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultSuccess}},
		{"ModifyDN No-Op", uint16(ldapwire.ResultNoOperation), sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultSuccess, ldap.LDAPResultNoSuchObject}},
		{"Delete No-Op", uint16(ldapwire.ResultNoOperation), sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultSuccess}},
	}
}

func sqlDifferentialFailureExpectations() []sqlDifferentialWriteExpectation {
	return []sqlDifferentialWriteExpectation{
		{"Add forced ldap_entries insert failure", ldap.LDAPResultOther, sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultNoSuchObject}},
		{"Modify forced mapped sn delete failure", ldap.LDAPResultOther, sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultSuccess}},
		{"ModifyDN forced mapped uid add failure", ldap.LDAPResultNamingViolation, sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultSuccess, ldap.LDAPResultNoSuchObject}},
		{"Delete forced ldap_entries delete failure", ldap.LDAPResultOther, sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultSuccess}},
	}
}

func sqlDifferentialLifecycleExpectations() []sqlDifferentialWriteExpectation {
	return []sqlDifferentialWriteExpectation{
		{"Add lifecycle", ldap.LDAPResultSuccess, sqlDifferentialSQLStateChanged, []uint16{ldap.LDAPResultSuccess}},
		{"Modify lifecycle", ldap.LDAPResultSuccess, sqlDifferentialSQLStateChanged, []uint16{ldap.LDAPResultSuccess}},
		{"ModifyDN lifecycle", ldap.LDAPResultSuccess, sqlDifferentialSQLStateChanged, []uint16{ldap.LDAPResultNoSuchObject, ldap.LDAPResultSuccess}},
		{"Delete lifecycle", ldap.LDAPResultSuccess, sqlDifferentialSQLStateBaseline, []uint16{ldap.LDAPResultNoSuchObject}},
	}
}

func assertSQLDifferentialOperationSemantics(
	t *testing.T,
	baseline sqlDifferentialDatabaseState,
	results []sqlDifferentialLDAPResult,
	states []sqlDifferentialDatabaseState,
	searches []sqlDifferentialSearch,
	expectations []sqlDifferentialWriteExpectation,
	checkResultCode bool,
) {
	t.Helper()
	if len(results) != len(expectations) || len(states) != len(expectations) {
		t.Fatalf(
			"write observation count mismatch: results=%d states=%d expectations=%d",
			len(results),
			len(states),
			len(expectations),
		)
	}
	searchIndex := 0
	for index, expectation := range expectations {
		result := results[index]
		if result.Operation != expectation.Operation {
			t.Fatalf(
				"operation %d name = %q, want %q",
				index,
				result.Operation,
				expectation.Operation,
			)
		}
		if checkResultCode && result.Code != expectation.Code {
			t.Fatalf(
				"unexpected LDAP result\ngot:  %s\nwant: operation=%q resultCode=0x%04x (%d)",
				formatSQLDifferentialLDAPResult(result),
				expectation.Operation,
				expectation.Code,
				expectation.Code,
			)
		}

		stateMatchesBaseline := reflect.DeepEqual(states[index], baseline)
		switch expectation.SQLState {
		case sqlDifferentialSQLStateBaseline:
			if !stateMatchesBaseline {
				t.Fatalf(
					"%s did not restore SQL baseline\nbefore: %#v\nafter:  %#v",
					expectation.Operation,
					baseline,
					states[index],
				)
			}
		case sqlDifferentialSQLStateChanged:
			if stateMatchesBaseline {
				t.Fatalf("%s did not change SQL state", expectation.Operation)
			}
		default:
			t.Fatalf("%s has unknown SQL state expectation %d", expectation.Operation, expectation.SQLState)
		}

		for _, code := range expectation.SearchCodes {
			if searchIndex >= len(searches) {
				t.Fatalf("%s LDAP state observation is missing", expectation.Operation)
			}
			if searches[searchIndex].Code != code {
				t.Fatalf(
					"%s LDAP state %d resultCode=0x%04x (%d), want 0x%04x (%d)",
					expectation.Operation,
					searchIndex,
					searches[searchIndex].Code,
					searches[searchIndex].Code,
					code,
					code,
				)
			}
			searchIndex++
		}
	}
	if searchIndex != len(searches) {
		t.Fatalf("unused LDAP state observations: used=%d total=%d", searchIndex, len(searches))
	}
}

func compareSQLDifferentialWrites(
	t *testing.T,
	reference,
	local sqlDifferentialWriteObservation,
) {
	t.Helper()
	compareSQLDifferentialLDAPResults(t, "No-Op LDAP results", reference.NoOpResults, local.NoOpResults)
	compareSQLDifferentialLDAPResults(t, "failure LDAP results", reference.FailureResults, local.FailureResults)
	compareSQLDifferentialLDAPResults(t, "lifecycle LDAP results", reference.LifecycleResults, local.LifecycleResults)
	tests := []struct {
		name      string
		reference any
		local     any
	}{
		{"baseline", reference.Baseline, local.Baseline},
		{"No-Op SQL states", reference.NoOpStates, local.NoOpStates},
		{"No-Op LDAP states", reference.NoOpSearches, local.NoOpSearches},
		{"failure SQL states", reference.FailureStates, local.FailureStates},
		{"failure LDAP states", reference.FailureSearches, local.FailureSearches},
		{"lifecycle SQL states", reference.LifecycleStates, local.LifecycleStates},
		{"lifecycle LDAP states", reference.LifecycleSearches, local.LifecycleSearches},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(test.local, test.reference) {
				t.Fatalf(
					"back-sql differential mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
					test.reference,
					test.local,
				)
			}
		})
	}
}

func compareSQLDifferentialLDAPResults(
	t *testing.T,
	label string,
	reference,
	local []sqlDifferentialLDAPResult,
) {
	t.Helper()
	t.Run(label, func(t *testing.T) {
		if len(local) != len(reference) {
			t.Fatalf(
				"LDAP result count mismatch: OpenLDAP=%d ldap-go=%d\nOpenLDAP: %#v\nldap-go: %#v",
				len(reference),
				len(local),
				reference,
				local,
			)
		}
		for index := range reference {
			index := index
			operation := reference[index].Operation
			t.Run(operation, func(t *testing.T) {
				referenceResult := reference[index]
				localResult := local[index]
				if localResult.Operation != referenceResult.Operation ||
					localResult.Code != referenceResult.Code ||
					localResult.MatchedDN != referenceResult.MatchedDN {
					t.Fatalf(
						"back-sql LDAP result mismatch\nOpenLDAP: %s\nldap-go:  %s",
						formatSQLDifferentialLDAPResult(referenceResult),
						formatSQLDifferentialLDAPResult(localResult),
					)
				}
				if localResult.Diagnostic != referenceResult.Diagnostic {
					t.Logf(
						"diagnostic differs with matching result semantics\nOpenLDAP: %s\nldap-go:  %s",
						formatSQLDifferentialLDAPResult(referenceResult),
						formatSQLDifferentialLDAPResult(localResult),
					)
				}
			})
		}
	})
}

func formatSQLDifferentialLDAPResult(result sqlDifferentialLDAPResult) string {
	return fmt.Sprintf(
		"operation=%q resultCode=0x%04x (%d) matchedDN=%q diagnostic=%q",
		result.Operation,
		result.Code,
		result.Code,
		result.MatchedDN,
		result.Diagnostic,
	)
}

func seedSQLDifferentialDatabase(t *testing.T, databaseName string) {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open SQL differential fixture: %v", err)
	}
	defer database.Close()
	statements := []string{
		`CREATE TABLE ldap_oc_mappings (
			id INTEGER PRIMARY KEY, name TEXT NOT NULL, keytbl TEXT NOT NULL,
			keycol TEXT NOT NULL, create_proc TEXT, delete_proc TEXT,
			expect_return INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE ldap_attr_mappings (
			id INTEGER PRIMARY KEY, oc_map_id INTEGER NOT NULL, name TEXT NOT NULL,
			sel_expr TEXT NOT NULL, from_tbls TEXT NOT NULL, join_where TEXT,
			add_proc TEXT, delete_proc TEXT, param_order INTEGER NOT NULL DEFAULT 0,
			expect_return INTEGER NOT NULL DEFAULT 0, sel_expr_u TEXT
		)`,
		`CREATE TABLE ldap_entries (
			id INTEGER PRIMARY KEY, dn TEXT NOT NULL UNIQUE, oc_map_id INTEGER NOT NULL,
			parent INTEGER NOT NULL, keyval INTEGER NOT NULL, UNIQUE (oc_map_id, keyval)
		)`,
		`CREATE TABLE ldap_entry_objclasses (
			entry_id INTEGER NOT NULL, oc_name TEXT NOT NULL,
			PRIMARY KEY (entry_id, oc_name)
		)`,
		`CREATE TABLE domains (id INTEGER PRIMARY KEY, dc TEXT NOT NULL)`,
		`CREATE TABLE organizational_units (
			id INTEGER PRIMARY KEY, ou TEXT NOT NULL, description TEXT
		)`,
		`CREATE TABLE persons (
			id INTEGER PRIMARY KEY, uid TEXT UNIQUE, cn TEXT,
			sn TEXT, description TEXT, user_password BLOB, jpeg_photo BLOB
		)`,
		`CREATE TRIGGER reject_rollback_add_entry
			BEFORE INSERT ON ldap_entries
			WHEN NEW.dn='uid=rollback-add,ou=people,dc=example,dc=com'
			BEGIN
				SELECT RAISE(ABORT, 'forced ldap_entries insert failure');
			END`,
		`CREATE TRIGGER reject_rollback_sn_delete
			BEFORE UPDATE OF sn ON persons
			WHEN OLD.sn='TriggerRollback' AND NEW.sn IS NULL
			BEGIN
				SELECT RAISE(ABORT, 'forced mapped attribute failure');
			END`,
		`CREATE TRIGGER reject_rollback_uid_add
			BEFORE UPDATE OF uid ON persons
			WHEN NEW.uid='rollback-moved'
			BEGIN
				SELECT RAISE(ABORT, 'forced rename attribute failure');
			END`,
		`CREATE TRIGGER reject_rollback_entry_delete
			BEFORE DELETE ON ldap_entries
			WHEN OLD.dn='uid=rollback-delete,ou=people,dc=example,dc=com'
			BEGIN
				SELECT RAISE(ABORT, 'forced ldap_entries delete failure');
			END`,
		`INSERT INTO ldap_oc_mappings VALUES
			(1,'domain','domains','id',NULL,NULL,0),
			(2,'organizationalUnit','organizational_units','id',NULL,NULL,0),
			(3,'inetOrgPerson','persons','id',
			 'INSERT INTO persons DEFAULT VALUES RETURNING id',
			 'DELETE FROM persons WHERE id=?',0)`,
		`INSERT INTO ldap_attr_mappings VALUES
			(1,1,'dc','domains.dc','domains',NULL,NULL,NULL,0,0,'UPPER(domains.dc)'),
			(2,2,'ou','organizational_units.ou','organizational_units',NULL,NULL,NULL,0,0,'UPPER(organizational_units.ou)'),
			(3,2,'description','organizational_units.description','organizational_units','organizational_units.description IS NOT NULL',NULL,NULL,0,0,'UPPER(organizational_units.description)'),
			(4,3,'uid','persons.uid','persons',NULL,
			 'UPDATE persons SET uid=? WHERE id=?',
			 'UPDATE persons SET uid=NULL WHERE uid=? AND id=?',3,0,'UPPER(persons.uid)'),
			(5,3,'cn','persons.cn','persons',NULL,
			 'UPDATE persons SET cn=? WHERE id=?',
			 'UPDATE persons SET cn=NULL WHERE cn=? AND id=?',3,0,'UPPER(persons.cn)'),
			(6,3,'sn','persons.sn','persons',NULL,
			 'UPDATE persons SET sn=? WHERE id=?',
			 'UPDATE persons SET sn=NULL WHERE sn=? AND id=?',3,0,'UPPER(persons.sn)'),
			(7,3,'description','persons.description','persons','persons.description IS NOT NULL',
			 'UPDATE persons SET description=? WHERE id=?',
			 'UPDATE persons SET description=NULL WHERE description=? AND id=?',3,0,'UPPER(persons.description)'),
			(8,3,'userPassword','persons.user_password','persons','persons.user_password IS NOT NULL',
			 'UPDATE persons SET user_password=? WHERE id=?',
			 'UPDATE persons SET user_password=NULL WHERE user_password=? AND id=?',3,0,NULL),
			(9,3,'jpegPhoto','persons.jpeg_photo','persons','persons.jpeg_photo IS NOT NULL',
			 'UPDATE persons SET jpeg_photo=? WHERE id=?',
			 'UPDATE persons SET jpeg_photo=NULL WHERE jpeg_photo=? AND id=?',3,0,NULL)`,
		`INSERT INTO domains VALUES (10,'example')`,
		`INSERT INTO organizational_units VALUES (20,'people','Directory users')`,
		`INSERT INTO persons VALUES
			(30,'alice','Alice Example','Example','First account','alice-secret',X'00FF10'),
			(31,'bob','Bob Builder','Builder',NULL,'bob-secret',X'010203'),
			(32,'rollback','Rollback Original','TriggerRollback',
			 'Must survive failed modify','rollback-secret',NULL),
			(33,'rollback-move','Rollback Move','Move',
			 'Must survive failed rename','rollback-move-secret',NULL),
			(34,'rollback-delete','Rollback Delete','Delete',
			 'Must survive failed delete','rollback-delete-secret',NULL)`,
		`INSERT INTO ldap_entries VALUES
			(1,'dc=example,dc=com',1,0,10),
			(2,'ou=people,dc=example,dc=com',2,1,20),
			(3,'uid=alice,ou=people,dc=example,dc=com',3,2,30),
			(4,'uid=bob,ou=people,dc=example,dc=com',3,2,31),
			(5,'uid=rollback,ou=people,dc=example,dc=com',3,2,32),
			(6,'uid=rollback-move,ou=people,dc=example,dc=com',3,2,33),
			(7,'uid=rollback-delete,ou=people,dc=example,dc=com',3,2,34)`,
		`INSERT INTO ldap_entry_objclasses VALUES
			(1,'top'),(2,'top'),
			(3,'top'),(3,'person'),(3,'organizationalPerson'),
			(4,'top'),(4,'person'),(4,'organizationalPerson'),
			(5,'top'),(5,'person'),(5,'organizationalPerson'),
			(6,'top'),(6,'person'),(6,'organizationalPerson'),
			(7,'top'),(7,'person'),(7,'organizationalPerson')`,
	}
	for index, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("SQL differential fixture statement %d: %v\n%s", index, err, statement)
		}
	}
	if err := database.Ping(); err != nil {
		t.Fatalf("ping SQL differential fixture: %v", err)
	}
}
