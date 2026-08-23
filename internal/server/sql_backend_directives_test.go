package server

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSQLBackendBaseObjectFileMergesRecordsAndTracksContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "base-object.ldif")
	writeSQLBaseObjectFixture(t, path, "first", true)
	first := loadSQLDirectiveConfiguration(t, path)
	first.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
	if err := first.prepareBaseObject(); err != nil {
		t.Fatalf("prepare first baseObject: %v", err)
	}
	entry := first.baseObjectClone()
	if entry == nil || entry.DN != "dc=example,dc=com" ||
		!entry.HasValue("description", []byte("first")) ||
		!entry.HasValue("description", []byte("merged")) ||
		!entry.HasValue("dc", []byte("example")) {
		t.Fatalf("merged baseObject = %#v", entry)
	}

	writeSQLBaseObjectFixture(t, path, "second", false)
	second := loadSQLDirectiveConfiguration(t, path)
	second.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
	if first.equivalent(second) {
		t.Fatal("same-path baseObject content change was treated as equivalent")
	}
	if err := second.prepareBaseObject(); err != nil {
		t.Fatalf("prepare second baseObject: %v", err)
	}
	if got := second.baseObjectClone(); got == nil ||
		!got.HasValue("description", []byte("second")) ||
		got.HasValue("description", []byte("first")) {
		t.Fatalf("reloaded baseObject = %#v", got)
	}
}

func TestSQLBackendBaseObjectFileRejectsUnsafeOrInvalidInput(t *testing.T) {
	directoryPath := t.TempDir()
	valid := filepath.Join(directoryPath, "valid.ldif")
	writeSQLBaseObjectFixture(t, valid, "valid", false)

	t.Run("relative path", func(t *testing.T) {
		entry := sqlDirectiveConfigurationEntry("relative.ldif")
		if _, err := loadSQLBackendRuntimeConfiguration(entry); err == nil ||
			!strings.Contains(err.Error(), "absolute path") {
			t.Fatalf("relative baseObject error = %v", err)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		link := filepath.Join(directoryPath, "link.ldif")
		if err := os.Symlink(valid, link); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		entry := sqlDirectiveConfigurationEntry(link)
		if _, err := loadSQLBackendRuntimeConfiguration(entry); err == nil ||
			!strings.Contains(err.Error(), "symbolic links") {
			t.Fatalf("symlink baseObject error = %v", err)
		}
	})

	t.Run("wrong DN", func(t *testing.T) {
		path := filepath.Join(directoryPath, "wrong-dn.ldif")
		if err := os.WriteFile(path, []byte(
			"dn: dc=other,dc=com\nobjectClass: domain\ndc: other\n",
		), 0o600); err != nil {
			t.Fatalf("write wrong-DN fixture: %v", err)
		}
		configuration := loadSQLDirectiveConfiguration(t, path)
		configuration.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
		if err := configuration.prepareBaseObject(); err == nil ||
			!strings.Contains(err.Error(), "is not the SQL suffix") {
			t.Fatalf("wrong-DN baseObject error = %v", err)
		}
	})

	t.Run("undefined attribute", func(t *testing.T) {
		path := filepath.Join(directoryPath, "undefined.ldif")
		if err := os.WriteFile(path, []byte(
			"dn: dc=example,dc=com\nobjectClass: domain\ndc: example\nundefinedSQLAttribute: value\n",
		), 0o600); err != nil {
			t.Fatalf("write undefined-attribute fixture: %v", err)
		}
		configuration := loadSQLDirectiveConfiguration(t, path)
		configuration.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
		if err := configuration.prepareBaseObject(); err == nil ||
			!strings.Contains(err.Error(), "is undefined") {
			t.Fatalf("undefined-attribute baseObject error = %v", err)
		}
	})
}

func TestSQLBackendLayerSafeSubsetAndEndToEndMapping(t *testing.T) {
	entry := sqlDirectiveConfigurationEntry("")
	entry.ReplaceValues("olcSqlLayer", stringValues(
		"{0}identity",
		`{1}suffixmassage "dc=example,dc=com" "dc=stored,dc=test"`,
	))
	configuration, err := loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("load suffix layer: %v", err)
	}
	configuration.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
	local := mustSQLDirectiveDN(t, "uid=alice,dc=example,dc=com")
	stored, err := configuration.mapLDAPDNToSQL(local)
	if err != nil || stored.String() != "uid=alice,dc=stored,dc=test" {
		t.Fatalf("LDAP to SQL DN = %q, %v", stored.String(), err)
	}
	roundTrip, err := configuration.mapSQLDNToLDAP(stored)
	if err != nil || !roundTrip.Equal(local) {
		t.Fatalf("SQL to LDAP DN = %q, %v", roundTrip.String(), err)
	}

	for _, layer := range []string{
		"native-plugin argument",
		"suffixmassage dc=other,dc=com dc=stored,dc=test",
		"suffixmassage dc=example,dc=com",
	} {
		rejected := sqlDirectiveConfigurationEntry("")
		rejected.ReplaceValues("olcSqlLayer", stringValues(layer))
		if _, err := loadSQLBackendRuntimeConfiguration(rejected); err == nil {
			t.Fatalf("unsafe olcSqlLayer %q was accepted", layer)
		}
	}

	databaseName := filepath.Join(t.TempDir(), "layer.db")
	seedSQLBackendDatabase(t, databaseName)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open layer fixture: %v", err)
	}
	if _, err := database.Exec(`UPDATE ldap_entries SET dn =
		CASE id WHEN 1 THEN 'dc=stored,dc=test'
		ELSE 'uid=alice,dc=stored,dc=test' END`); err != nil {
		_ = database.Close()
		t.Fatalf("rewrite fixture DNs: %v", err)
	}
	_ = database.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn := mustSQLDirectiveDN(t, "olcDatabase={1}sql,cn=config")
		configured, err := writer.Get(dn)
		if err != nil {
			return err
		}
		configured.ReplaceValues("olcSqlLayer", stringValues(
			`suffixmassage "dc=example,dc=com" "dc=stored,dc=test"`,
		))
		return writer.Put(configured, true)
	}); err != nil {
		t.Fatalf("configure SQL layer: %v", err)
	}
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial layer server: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("uid=alice,dc=example,dc=com", "alice-secret"); err != nil {
		t.Fatalf("bind through SQL layer: %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"uid"}, nil,
	))
	if err != nil {
		t.Fatalf("search through SQL layer: %v", err)
	}
	if len(result.Entries) != 2 || result.Entries[0].DN != "dc=example,dc=com" ||
		result.Entries[1].DN != "uid=alice,dc=example,dc=com" {
		t.Fatalf("layer search entries = %#v", result.Entries)
	}
}

func TestSQLBackendScopeTemplatesAreParameterizedAndShortcutSuffix(t *testing.T) {
	configuration, database := openSQLBackendQueryPlanner(t)
	configuration.subtreeTemplate = sqlScopeTemplateLike
	configuration.childrenTemplate = sqlScopeTemplateUpperLike
	configuration.useSubtreeShortcut = false
	recorder := &sqlBackendQueryRecorder{database: database}

	injection := "x') OR 1=1 --"
	base := mustSQLDirectiveDN(t, "ou="+injection+",dc=example,dc=com")
	ctx := withSQLBackendSearchRequirements(context.Background(), nil)
	ctx = withSQLBackendScopeRequirements(ctx, base, directory.ScopeWholeSubtree)
	reader := &sqlBackendReader{configuration: configuration, queryer: recorder, ctx: ctx}
	if _, planned, err := reader.sqlBackendScopeCandidates(recorder); err != nil || !planned {
		t.Fatalf("subtree candidates planned=%t error=%v", planned, err)
	}
	calls := recorder.snapshot()
	if len(calls) != 1 || strings.Contains(calls[0].query, injection) ||
		len(calls[0].arguments) != 1 || !strings.Contains(calls[0].query, "dn LIKE ?") {
		t.Fatalf("parameterized subtree calls = %#v", calls)
	}
	if got := calls[0].arguments[0]; got != "%"+base.NormalizedString() {
		t.Fatalf("subtree parameter = %#v", got)
	}

	configuration.useSubtreeShortcut = true
	configuration.suffixes = []string{"dc=example,dc=com"}
	recorder = &sqlBackendQueryRecorder{database: database}
	base = mustSQLDirectiveDN(t, "dc=example,dc=com")
	ctx = withSQLBackendSearchRequirements(context.Background(), nil)
	ctx = withSQLBackendScopeRequirements(ctx, base, directory.ScopeWholeSubtree)
	reader = &sqlBackendReader{configuration: configuration, queryer: recorder, ctx: ctx}
	ids, planned, err := reader.sqlBackendScopeCandidates(recorder)
	if err != nil || !planned || len(ids) != 2 {
		t.Fatalf("shortcut candidates = %#v, planned=%t error=%v", ids, planned, err)
	}
	calls = recorder.snapshot()
	if len(calls) != 1 || strings.Contains(strings.ToUpper(calls[0].query), " WHERE ") ||
		len(calls[0].arguments) != 0 {
		t.Fatalf("shortcut query calls = %#v", calls)
	}

	for _, value := range []string{
		"ldap_entries.dn LIKE '%' || ?",
		"ldap_entries.dn LIKE ? OR 1=1",
		"ldap_entries.dn LIKE ?; DROP TABLE ldap_entries",
		"ldap_entries.parent=?",
	} {
		if _, err := parseSQLScopeTemplate(value); err == nil {
			t.Fatalf("unsafe scope template %q was accepted", value)
		}
	}
}

func TestSQLBackendCheckSchemaDefaultAndMappedRead(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "check-schema.db")
	seedSQLBackendDatabase(t, databaseName)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open check-schema fixture: %v", err)
	}
	if _, err := database.Exec(
		"INSERT INTO ldap_entry_objclasses(entry_id,oc_name) VALUES (1,'person')",
	); err != nil {
		_ = database.Close()
		t.Fatalf("insert conflicting structural class: %v", err)
	}
	_ = database.Close()

	entry := sqlDirectiveConfigurationEntry("")
	entry.ReplaceValues("olcDbName", stringValues(databaseName))
	configuration, err := loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("load default check-schema configuration: %v", err)
	}
	if !configuration.checkSchema {
		t.Fatal("olcSqlCheckSchema default is false, want true")
	}
	configuration.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
	reader := &sqlBackendReader{configuration: configuration, ctx: context.Background()}
	if _, err := reader.Get(mustSQLDirectiveDN(t, "dc=example,dc=com")); err == nil {
		t.Fatal("check_schema accepted conflicting structural object classes")
	}
	_ = configuration.close()

	entry.ReplaceValues("olcSqlCheckSchema", stringValues("FALSE"))
	configuration, err = loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("load disabled check-schema configuration: %v", err)
	}
	configuration.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
	reader = &sqlBackendReader{configuration: configuration, ctx: context.Background()}
	if _, err := reader.Get(mustSQLDirectiveDN(t, "dc=example,dc=com")); err != nil {
		t.Fatalf("disabled check_schema read: %v", err)
	}
	_ = configuration.close()
}

func TestSQLBackendCheckSchemaAcceptsMappedStructuralSubclass(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "check-schema-subclass.db")
	seedSQLBackendDatabase(t, databaseName)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open check-schema subclass fixture: %v", err)
	}
	if _, err := database.Exec(
		"UPDATE ldap_oc_mappings SET name='person' WHERE id=1",
	); err != nil {
		_ = database.Close()
		t.Fatalf("replace structural mapping with superclass: %v", err)
	}
	if _, err := database.Exec(
		"INSERT INTO ldap_entry_objclasses(entry_id,oc_name) VALUES (2,'inetOrgPerson')",
	); err != nil {
		_ = database.Close()
		t.Fatalf("insert mapped structural subclass: %v", err)
	}
	_ = database.Close()

	entry := sqlDirectiveConfigurationEntry("")
	entry.ReplaceValues("olcDbName", stringValues(databaseName))
	configuration, err := loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("load check-schema subclass configuration: %v", err)
	}
	t.Cleanup(func() { _ = configuration.close() })
	configuration.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
	reader := &sqlBackendReader{configuration: configuration, ctx: context.Background()}
	alice, err := reader.Get(mustSQLDirectiveDN(t, "uid=alice,dc=example,dc=com"))
	if err != nil {
		t.Fatalf("check_schema subclass read: %v", err)
	}
	if got := firstSQLValue(alice.Values("structuralObjectClass")); got != "inetOrgPerson" {
		t.Fatalf("structuralObjectClass = %q, want inetOrgPerson", got)
	}
}

func TestSQLBackendDirectiveReloadRollback(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "reload.db")
	seedSQLBackendDatabase(t, databaseName)
	baseObjectPath := filepath.Join(t.TempDir(), "base-object.ldif")
	writeSQLBaseObjectFixture(t, baseObjectPath, "first", false)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Delete(mustSQLDirectiveDN(t, "olcDatabase={1}mdb,cn=config")); err != nil {
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
				{Description: "olcSqlBaseObject", Values: stringValues(baseObjectPath)},
				{Description: "olcSqlCheckSchema", Values: stringValues("TRUE")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed reload SQL configuration: %v", err)
	}

	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	t.Cleanup(stop)
	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial config client: %v", err)
	}
	t.Cleanup(func() { _ = configClient.Close() })
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind config client: %v", err)
	}
	dataClient := dialSQLDirectiveClient(t, address)
	t.Cleanup(func() { _ = dataClient.Close() })
	assertSQLDirectiveBaseDescription(t, dataClient, "first")

	stopSearches := make(chan struct{})
	searchErrors := make(chan error, 1)
	var searches sync.WaitGroup
	var stopSearchesOnce sync.Once
	searches.Add(1)
	go func() {
		defer searches.Done()
		client, dialErr := ldap.DialURL("ldap://" + address)
		if dialErr != nil {
			searchErrors <- dialErr
			return
		}
		defer client.Close()
		if bindErr := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); bindErr != nil {
			searchErrors <- bindErr
			return
		}
		for {
			select {
			case <-stopSearches:
				return
			default:
			}
			_, searchErr := client.Search(ldap.NewSearchRequest(
				"dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
				0, 0, false, "(objectClass=*)", []string{"description"}, nil,
			))
			if searchErr != nil {
				searchErrors <- searchErr
				return
			}
		}
	}()
	stopConcurrentSearches := func() {
		stopSearchesOnce.Do(func() {
			close(stopSearches)
			searches.Wait()
		})
	}
	defer stopConcurrentSearches()

	writeSQLBaseObjectFixtureAtomic(t, baseObjectPath, "second")
	modify := ldap.NewModifyRequest("olcDatabase={1}sql,cn=config", nil)
	modify.Replace("olcSqlCheckSchema", []string{"FALSE"})
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("reload valid baseObject: %v", err)
	}
	assertSQLDirectiveBaseDescription(t, dataClient, "second")

	if err := os.WriteFile(baseObjectPath, []byte(
		"dn: dc=wrong,dc=com\nobjectClass: domain\ndc: wrong\n",
	), 0o600); err != nil {
		t.Fatalf("write invalid reload fixture: %v", err)
	}
	modify = ldap.NewModifyRequest("olcDatabase={1}sql,cn=config", nil)
	modify.Replace("olcSqlCheckSchema", []string{"TRUE"})
	assertLDAPResultCode(t, configClient.Modify(modify), ldap.LDAPResultConstraintViolation)
	assertSQLDirectiveBaseDescription(t, dataClient, "second")

	configurationResult, err := configClient.Search(ldap.NewSearchRequest(
		"olcDatabase={1}sql,cn=config", ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
		[]string{"olcSqlCheckSchema"}, nil,
	))
	if err != nil {
		t.Fatalf("read rolled-back SQL configuration: %v", err)
	}
	if len(configurationResult.Entries) != 1 ||
		configurationResult.Entries[0].GetAttributeValue("olcSqlCheckSchema") != "FALSE" {
		t.Fatalf("rolled-back check_schema = %#v", configurationResult.Entries)
	}

	stopConcurrentSearches()
	select {
	case err := <-searchErrors:
		t.Fatalf("concurrent search during reload: %v", err)
	default:
	}
}

func sqlDirectiveConfigurationEntry(baseObject string) directory.Entry {
	entry := directory.Entry{
		DN: "olcDatabase={1}sql,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcSqlConfig")},
			{Description: "olcDatabase", Values: stringValues("{1}sql")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcDbName", Values: stringValues("unused")},
			{Description: "olcDbUser", Values: stringValues("unused")},
		},
	}
	if baseObject != "" {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcSqlBaseObject", Values: stringValues(baseObject),
		})
	}
	return entry
}

func loadSQLDirectiveConfiguration(
	t *testing.T,
	baseObject string,
) *sqlBackendRuntimeConfiguration {
	t.Helper()
	configuration, err := loadSQLBackendRuntimeConfiguration(
		sqlDirectiveConfigurationEntry(baseObject),
	)
	if err != nil {
		t.Fatalf("load SQL directive configuration: %v", err)
	}
	return configuration
}

func writeSQLBaseObjectFixture(t *testing.T, path, description string, merge bool) {
	t.Helper()
	input := "dn: dc=example,dc=com\n" +
		"objectClass: domain\n" +
		"dc: example\n" +
		"description: " + description + "\n"
	if merge {
		input += "\ndn: DC=example,DC=com\ndescription: merged\n"
	}
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write baseObject fixture: %v", err)
	}
}

func writeSQLBaseObjectFixtureAtomic(t *testing.T, path, description string) {
	t.Helper()
	temporary := path + ".new"
	writeSQLBaseObjectFixture(t, temporary, description, false)
	if err := os.Rename(temporary, path); err != nil {
		t.Fatalf("replace baseObject fixture: %v", err)
	}
}

func dialSQLDirectiveClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial SQL directive server: %v", err)
	}
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		_ = client.Close()
		t.Fatalf("bind SQL directive server: %v", err)
	}
	return client
}

func assertSQLDirectiveBaseDescription(
	t *testing.T,
	client *ldap.Conn,
	want string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"description"}, nil,
	))
	if err != nil {
		t.Fatalf("search SQL baseObject: %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("description") != want {
		t.Fatalf("baseObject description = %#v, want %q", result.Entries, want)
	}
}

func mustSQLDirectiveDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
