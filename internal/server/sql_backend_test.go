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

func TestSQLBackendUnavailableReturnsLDAPResult(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, filepath.Join(t.TempDir(), "missing", "back-sql.db"))

	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	assertLDAPResultCode(
		t,
		client.Bind("uid=alice,dc=example,dc=com", "alice-secret"),
		ldap.LDAPResultUnavailable,
	)
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnavailable)
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
