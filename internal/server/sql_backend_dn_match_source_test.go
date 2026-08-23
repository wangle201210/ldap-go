package server

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
	_ "modernc.org/sqlite"
)

func TestSQLBackendDNMatchSourceDefaultQuery(t *testing.T) {
	t.Parallel()

	// OpenLDAP 2.6.13 back-sql/init.c composes sql_has_children_query from
	// sql_aliasing and sql_dn_match_cond after preparing upper_func wrappers.
	tests := []struct {
		name          string
		configuration *sqlBackendRuntimeConfiguration
		want          string
	}{
		{
			name: "plain",
			configuration: &sqlBackendRuntimeConfiguration{
				aliasingKeyword: "AS ",
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries AS subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND ldap_entries.dn=?",
		},
		{
			name: "aliasing keyword disabled",
			configuration: &sqlBackendRuntimeConfiguration{
				aliasingKeyword: "",
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND ldap_entries.dn=?",
		},
		{
			name: "upper function",
			configuration: &sqlBackendRuntimeConfiguration{
				aliasingKeyword: "AS ",
				upperFunction:   "UPPER",
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries AS subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND " +
				"UPPER(ldap_entries.dn)=UPPER(?)",
		},
		{
			name: "upper function with cast",
			configuration: &sqlBackendRuntimeConfiguration{
				aliasingKeyword: "AS ",
				upperFunction:   "UPPER",
				upperNeedsCast:  true,
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries AS subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND " +
				"UPPER(ldap_entries.dn)=UPPER(cast (? as varchar(255)))",
		},
		{
			name: "configured condition overrides generated upper expression",
			configuration: &sqlBackendRuntimeConfiguration{
				aliasingKeyword:   "AS ",
				upperFunction:     "UPPER",
				upperNeedsCast:    true,
				dnMatchCondition:  "LOWER(ldap_entries.dn)=LOWER(?)",
				dnMatchConfigured: true,
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries AS subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND " +
				"LOWER(ldap_entries.dn)=LOWER(?)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.configuration.prepareHasChildrenQuery()
			if got := test.configuration.hasChildrenQuery; got != test.want {
				t.Fatalf("has-children query = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSQLBackendDNMatchSourceConfigurationEquivalence(t *testing.T) {
	t.Parallel()

	load := func(condition *string) *sqlBackendRuntimeConfiguration {
		attributes := []directory.Attribute{
			{Description: "olcDbName", Values: sourceDNMatchStringValues("directory")},
			{Description: "olcDbUser", Values: sourceDNMatchStringValues("ldap")},
		}
		if condition != nil {
			attributes = append(attributes, directory.Attribute{
				Description: "olcSqlDnMatchCond",
				Values:      sourceDNMatchStringValues(*condition),
			})
		}
		configuration, err := loadSQLBackendRuntimeConfiguration(directory.Entry{
			DN:         "olcDatabase={1}sql,cn=config",
			Attributes: attributes,
		})
		if err != nil {
			t.Fatalf("load SQL configuration: %v", err)
		}
		return configuration
	}

	firstCondition := "LOWER(ldap_entries.dn)=LOWER(?)"
	secondCondition := "ldap_entries.dn=?"
	previousConfiguration := load(&firstCondition)
	equivalentConfiguration := load(&firstCondition)
	changedConfiguration := load(&secondCondition)
	defaultConfiguration := load(nil)

	if !previousConfiguration.equivalent(equivalentConfiguration) {
		t.Fatal("identical olcSqlDnMatchCond configurations are not equivalent")
	}
	if previousConfiguration.equivalent(changedConfiguration) {
		t.Fatal("changed olcSqlDnMatchCond configuration is equivalent to stale state")
	}
	if changedConfiguration.equivalent(defaultConfiguration) {
		t.Fatal("explicit and generated DN-match configurations lost configured state")
	}

	previous := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: "olcdatabase={1}sql,cn=config",
		sqlBackend:  previousConfiguration,
	}}}
	equivalent := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: "olcdatabase={1}sql,cn=config",
		sqlBackend:  equivalentConfiguration,
	}}}
	reuseSQLBackendOnlineConfigurationState(previous, equivalent)
	if equivalent.databases[0].sqlBackend != previousConfiguration {
		t.Fatal("identical DN-match configuration did not reuse the open runtime")
	}

	changed := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: "olcdatabase={1}sql,cn=config",
		sqlBackend:  changedConfiguration,
	}}}
	reuseSQLBackendOnlineConfigurationState(previous, changed)
	if changed.databases[0].sqlBackend == previousConfiguration {
		t.Fatal("changed DN-match configuration reused the stale runtime")
	}
}

func TestSQLBackendDNMatchSourceRuntimeConsumers(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "dn-match-source.db")
	sourceDNMatchSeedDatabase(t, databaseName)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	sourceDNMatchSeedConfiguration(
		t,
		store,
		databaseName,
		"ldap_entries.dn=? AND subordinates.id=3",
	)

	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()
	dataClient := sourceDNMatchDialAndBind(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
	configClient := sourceDNMatchDialAndBind(t, address, "cn=config", "config-secret")
	defer configClient.Close()

	const parentDN = "ou=people,dc=example,dc=com"
	sourceDNMatchAssertSearch(t, dataClient, parentDN, true)
	sourceDNMatchAssertLDAPCode(
		t,
		dataClient.Del(ldap.NewDelRequest(parentDN, nil)),
		ldap.LDAPResultNotAllowedOnNonLeaf,
	)
	sourceDNMatchAssertLDAPCode(
		t,
		dataClient.ModifyDN(ldap.NewModifyDNRequest(parentDN, "ou=members", true, "")),
		ldap.LDAPResultNotAllowedOnNonLeaf,
	)

	sourceDNMatchReplaceCondition(
		t,
		configClient,
		"ldap_entries.dn=? AND subordinates.id=999",
	)
	sourceDNMatchAssertSearch(t, dataClient, parentDN, false)
	sourceDNMatchAssertLDAPCode(
		t,
		dataClient.Del(ldap.NewDelRequest(parentDN, nil)),
		ldap.LDAPResultUnwillingToPerform,
	)
	sourceDNMatchAssertLDAPCode(
		t,
		dataClient.ModifyDN(ldap.NewModifyDNRequest(parentDN, "ou=members", true, "")),
		ldap.LDAPResultNamingViolation,
	)

	sourceDNMatchReplaceCondition(
		t,
		configClient,
		"ldap_entries.dn=? AND subordinates.id=3",
	)
	sourceDNMatchAssertSearch(t, dataClient, parentDN, true)
	sourceDNMatchAssertLDAPCode(
		t,
		dataClient.Del(ldap.NewDelRequest(parentDN, nil)),
		ldap.LDAPResultNotAllowedOnNonLeaf,
	)
	sourceDNMatchAssertLDAPCode(
		t,
		dataClient.ModifyDN(ldap.NewModifyDNRequest(parentDN, "ou=members", true, "")),
		ldap.LDAPResultNotAllowedOnNonLeaf,
	)
}

func TestSQLBackendDNMatchSourceErrorMapping(t *testing.T) {
	t.Parallel()

	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.Ping(); err != nil {
		t.Fatalf("ping SQLite: %v", err)
	}

	dn, err := directory.ParseDN("ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	queryFailure := &sqlBackendReader{
		configuration: &sqlBackendRuntimeConfiguration{
			db:               database,
			hasChildrenQuery: "SELECT child_count FROM missing_subordinate_table WHERE dn=?",
		},
		ctx: context.Background(),
	}
	_, err = queryFailure.sqlBackendHasChildren(dn)
	sourceDNMatchAssertOperationCode(t, err, ldapwire.ResultOther)

	longDN, err := directory.ParseDN(
		"cn=" + strings.Repeat("a", 256) + ",dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("ParseDN(long): %v", err)
	}
	lengthFailure := &sqlBackendReader{
		configuration: &sqlBackendRuntimeConfiguration{
			db:               database,
			hasChildrenQuery: "SELECT 0",
		},
		ctx: context.Background(),
	}
	_, err = lengthFailure.sqlBackendHasChildren(longDN)
	sourceDNMatchAssertOperationCode(t, err, ldapwire.ResultOther)

	unavailable := &sqlBackendReader{
		initializationErr: &sqlBackendUnavailableError{err: errors.New("offline")},
	}
	_, err = unavailable.sqlBackendHasChildren(dn)
	sourceDNMatchAssertOperationCode(t, err, ldapwire.ResultUnavailable)
}

func sourceDNMatchSeedDatabase(t *testing.T, databaseName string) {
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
		`CREATE TABLE organizational_units (id INTEGER PRIMARY KEY, ou TEXT)`,
		`INSERT INTO ldap_oc_mappings VALUES
			(1,'domain','organizations','id',NULL,NULL,0),
			(2,'organizationalUnit','organizational_units','id',NULL,NULL,0)`,
		`INSERT INTO ldap_attr_mappings VALUES
			(1,1,'dc','organizations.dc','organizations',NULL,NULL,NULL,0,0,NULL),
			(2,2,'ou','organizational_units.ou','organizational_units',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO organizations VALUES (10,'example')`,
		`INSERT INTO organizational_units VALUES (20,'people'),(21,'child')`,
		`INSERT INTO ldap_entries VALUES
			(1,'dc=example,dc=com',1,0,10),
			(2,'ou=people,dc=example,dc=com',2,1,20),
			(3,'ou=child,ou=people,dc=example,dc=com',2,2,21)`,
	}
	for index, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("SQLite fixture statement %d: %v\n%s", index, err, statement)
		}
	}
}

func sourceDNMatchSeedConfiguration(
	t *testing.T,
	store storage.Store,
	databaseName,
	condition string,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: sourceDNMatchStringValues("olcGlobal")},
				{Description: "cn", Values: sourceDNMatchStringValues("config")},
			},
		},
		{
			DN: "cn=schema,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: sourceDNMatchStringValues("olcSchemaConfig")},
				{Description: "cn", Values: sourceDNMatchStringValues("schema")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: sourceDNMatchStringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: sourceDNMatchStringValues("{0}config")},
				{Description: "olcRootDN", Values: sourceDNMatchStringValues("cn=config")},
				{Description: "olcRootPW", Values: sourceDNMatchStringValues("config-secret")},
				{Description: "olcAccess", Values: sourceDNMatchStringValues("{0}to * by * none")},
			},
		},
		{
			DN: "olcDatabase={1}sql,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: sourceDNMatchStringValues("olcSqlConfig")},
				{Description: "olcDatabase", Values: sourceDNMatchStringValues("{1}sql")},
				{Description: "olcSuffix", Values: sourceDNMatchStringValues("dc=example,dc=com")},
				{Description: "olcRootDN", Values: sourceDNMatchStringValues("cn=admin,dc=example,dc=com")},
				{Description: "olcRootPW", Values: sourceDNMatchStringValues("admin-secret")},
				{Description: "olcDbName", Values: sourceDNMatchStringValues(databaseName)},
				{Description: "olcDbUser", Values: sourceDNMatchStringValues("unused")},
				{Description: "olcSqlDnMatchCond", Values: sourceDNMatchStringValues(condition)},
				{Description: "olcAccess", Values: sourceDNMatchStringValues("{0}to * by * read")},
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
		t.Fatalf("seed SQL configuration: %v", err)
	}
}

func sourceDNMatchDialAndBind(
	t *testing.T,
	address,
	bindDN,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(bindDN, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", bindDN, err)
	}
	return client
}

func sourceDNMatchAssertSearch(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	want bool,
) {
	t.Helper()
	assertion := "FALSE"
	if want {
		assertion = "TRUE"
	}
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(hasSubordinates="+assertion+")",
		[]string{"ou", "hasSubordinates"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(hasSubordinates=%s): %v", assertion, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(hasSubordinates=%s) entries = %d, want 1", assertion, len(result.Entries))
	}
	if got := result.Entries[0].GetAttributeValue("hasSubordinates"); got != assertion {
		t.Fatalf("hasSubordinates = %q, want %q", got, assertion)
	}
}

func sourceDNMatchReplaceCondition(t *testing.T, client *ldap.Conn, condition string) {
	t.Helper()
	request := ldap.NewModifyRequest("olcDatabase={1}sql,cn=config", nil)
	request.Replace("olcSqlDnMatchCond", []string{condition})
	if err := client.Modify(request); err != nil {
		t.Fatalf("replace olcSqlDnMatchCond: %v", err)
	}
}

func sourceDNMatchAssertLDAPCode(t *testing.T, err error, want uint16) {
	t.Helper()
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != want {
		t.Fatalf("LDAP error = %v, want result code %d", err, want)
	}
}

func sourceDNMatchAssertOperationCode(
	t *testing.T,
	err error,
	want ldapwire.ResultCode,
) {
	t.Helper()
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != want {
		t.Fatalf("operation error = %#v, want result code %d", err, want)
	}
}

func sourceDNMatchStringValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = []byte(value)
	}
	return result
}
