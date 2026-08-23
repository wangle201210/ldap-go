package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSQLBackendWriteSchemaDNLifecycle(t *testing.T) {
	configuration, database, registry := newSQLBackendWriteSchemaFixture(t)

	exactUpperRaw := "exactAlias=Tenant,dc=EXAMPLE,0.9.2342.19200300.100.1.25=COM"
	exactLowerRaw := "1.3.6.1.4.1.99999.940.1=tenant,dc=example,dc=com"
	foldedRaw := "foldAlias=BRANCH,dc=example,dc=com"
	memberRaw := "foldAlias=MEMBER+exactAlias=Target,dc=EXAMPLE,dc=COM"
	foldedEntry := sqlBackendWriteSchemaEntry(
		foldedRaw,
		"folded",
		"Folded",
		"User",
		"",
		"BRANCH",
	)
	foldedEntry.ReplaceValues("member", stringValues(memberRaw))
	for _, entry := range []directory.Entry{
		sqlBackendWriteSchemaEntry(exactUpperRaw, "exact-upper", "Exact Upper", "User", "Tenant", ""),
		sqlBackendWriteSchemaEntry(exactLowerRaw, "exact-lower", "Exact Lower", "User", "tenant", ""),
		foldedEntry,
	} {
		entry := entry
		if err := runSQLBackendWriteSchemaTransaction(
			t,
			configuration,
			context.Background(),
			true,
			func(writer *sqlBackendWriter) error { return writer.Put(entry, false) },
		); err != nil {
			t.Fatalf("Add %q: %v", entry.DN, err)
		}
	}

	exactUpper := sqlBackendSchemaNormalizedDN(t, registry, exactUpperRaw)
	exactLower := sqlBackendSchemaNormalizedDN(t, registry, exactLowerRaw)
	folded := sqlBackendSchemaNormalizedDN(t, registry, foldedRaw)
	assertSQLBackendWriteSchemaStoredDN(t, database, "exact-upper", exactUpper.String())
	assertSQLBackendWriteSchemaStoredDN(t, database, "exact-lower", exactLower.String())
	assertSQLBackendWriteSchemaStoredDN(t, database, "folded", folded.String())
	member := sqlBackendSchemaNormalizedDN(t, registry, memberRaw)
	assertSQLBackendWriteSchemaMember(t, database, "folded", member.NormalizedString())
	if exactUpper.Equal(exactLower) || exactUpper.NormalizedString() == exactLower.NormalizedString() {
		t.Fatal("caseExact DNs collapsed")
	}
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn LIKE 'exactName=%'", 2)

	exactLowerDN := mustSQLBackendWriteSchemaLegacyDN(
		t,
		"1.3.6.1.4.1.99999.940.1=tenant,dc=EXAMPLE,dc=COM",
	)
	exactChanges := []ldapwire.Modification{{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{Description: "cn", Values: stringValues("Exact Lower Modified")},
	}}
	exactCtx := withSQLBackendModify(
		context.Background(),
		&sqlBackendModifyContext{dn: exactLowerDN, changes: exactChanges},
	)
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		exactCtx,
		true,
		func(writer *sqlBackendWriter) error {
			id, err := writer.entryID(exactLowerDN)
			if err != nil {
				return err
			}
			entry, err := writer.reader.loadEntry(writer.sqlExecutor(), id)
			if err != nil {
				return err
			}
			entry.ReplaceValues("cn", stringValues("Exact Lower Modified"))
			return writer.Put(entry, true)
		},
	); err != nil {
		t.Fatalf("Modify caseExact sibling: %v", err)
	}
	assertSQLBackendWriteSchemaPerson(t, database, "exact-upper", "Exact Upper", "User", "Tenant", "")
	assertSQLBackendWriteSchemaPerson(t, database, "exact-lower", "Exact Lower Modified", "User", "tenant", "")
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		context.Background(),
		true,
		func(writer *sqlBackendWriter) error { return writer.Delete(exactLowerDN) },
	); err != nil {
		t.Fatalf("Delete caseExact sibling: %v", err)
	}
	assertWritableSQLCount(t, database, "persons WHERE uid=?", 1, "exact-upper")
	assertWritableSQLCount(t, database, "persons WHERE uid=?", 0, "exact-lower")
	assertSQLBackendWriteSchemaStoredDN(t, database, "exact-upper", exactUpper.String())

	modifyRaw := "1.3.6.1.4.1.99999.940.2= branch ,dc=EXAMPLE,dc=COM"
	modifyDN := mustSQLBackendWriteSchemaLegacyDN(t, modifyRaw)
	changes := []ldapwire.Modification{{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{Description: "cn", Values: stringValues("Folded Modified")},
	}, {
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{
			Description: "member",
			Values: stringValues(
				"1.3.6.1.4.1.99999.940.1=Target+foldAlias= member ,dc=example,dc=com",
			),
		},
	}}
	ctx := withSQLBackendModify(
		context.Background(),
		&sqlBackendModifyContext{dn: modifyDN, changes: changes},
	)
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		ctx,
		true,
		func(writer *sqlBackendWriter) error {
			entry, err := writer.Get(modifyDN)
			if err != nil {
				return err
			}
			entry.ReplaceValues("cn", stringValues("Folded Modified"))
			entry.ReplaceValues(
				"member",
				stringValues(
					"1.3.6.1.4.1.99999.940.1=Target+foldAlias= member ,dc=example,dc=com",
				),
			)
			return writer.Put(entry, true)
		},
	); err != nil {
		t.Fatalf("Modify through OID/caseIgnore equivalent DN: %v", err)
	}
	assertSQLBackendWriteSchemaPerson(t, database, "folded", "Folded Modified", "User", "", "BRANCH")
	assertSQLBackendWriteSchemaMember(t, database, "folded", member.NormalizedString())

	deleteDN := mustSQLBackendWriteSchemaLegacyDN(
		t,
		"foldAlias=BRANCH,0.9.2342.19200300.100.1.25=example,dc=com",
	)
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		context.Background(),
		true,
		func(writer *sqlBackendWriter) error { return writer.Delete(deleteDN) },
	); err != nil {
		t.Fatalf("Delete through alias/caseIgnore equivalent DN: %v", err)
	}
	assertWritableSQLCount(t, database, "persons WHERE uid=?", 0, "folded")
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn=?", 0, folded.String())
	assertWritableSQLCount(t, database, "person_members", 0)
	assertWritableSQLCount(t, database, "persons WHERE uid LIKE 'exact-%'", 1)
}

func TestSQLBackendWriteSchemaDNRollback(t *testing.T) {
	configuration, database, registry := newSQLBackendWriteSchemaFixture(t)

	noopRaw := "foldAlias=NOOP,dc=example,dc=com"
	noopEntry := sqlBackendWriteSchemaEntry(noopRaw, "noop", "No Op", "User", "", "NOOP")
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		context.Background(),
		false,
		func(writer *sqlBackendWriter) error { return writer.Put(noopEntry, false) },
	); err != nil {
		t.Fatalf("NoOp Add candidate: %v", err)
	}
	noopDN := sqlBackendSchemaNormalizedDN(t, registry, noopRaw)
	assertWritableSQLCount(t, database, "persons WHERE uid=?", 0, "noop")
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn=?", 0, noopDN.String())

	failureRaw := "foldAlias=FAILURE,dc=example,dc=com"
	failureEntry := sqlBackendWriteSchemaEntry(
		failureRaw,
		"failure",
		"Failure",
		"FORCE-ROLLBACK",
		"",
		"FAILURE",
	)
	err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		context.Background(),
		true,
		func(writer *sqlBackendWriter) error { return writer.Put(failureEntry, false) },
	)
	if err == nil {
		t.Fatal("mapped Add failure unexpectedly succeeded")
	}
	failureDN := sqlBackendSchemaNormalizedDN(t, registry, failureRaw)
	assertWritableSQLCount(t, database, "persons WHERE uid=?", 0, "failure")
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn=?", 0, failureDN.String())

	stableRaw := "foldAlias=STABLE,dc=example,dc=com"
	stableEntry := sqlBackendWriteSchemaEntry(stableRaw, "stable", "Stable", "User", "", "STABLE")
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		context.Background(),
		true,
		func(writer *sqlBackendWriter) error { return writer.Put(stableEntry, false) },
	); err != nil {
		t.Fatalf("Add stable rollback fixture: %v", err)
	}
	stableDN := mustSQLBackendWriteSchemaLegacyDN(t, "1.3.6.1.4.1.99999.940.2=stable,dc=EXAMPLE,dc=COM")
	changes := []ldapwire.Modification{
		{
			Operation: ldapwire.ModificationReplace,
			Attribute: directory.Attribute{Description: "cn", Values: stringValues("Changed Before Failure")},
		},
		{
			Operation: ldapwire.ModificationReplace,
			Attribute: directory.Attribute{Description: "sn", Values: stringValues("FORCE-ROLLBACK")},
		},
	}
	ctx := withSQLBackendModify(
		context.Background(),
		&sqlBackendModifyContext{dn: stableDN, changes: changes},
	)
	err = runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		ctx,
		true,
		func(writer *sqlBackendWriter) error {
			entry, err := writer.Get(stableDN)
			if err != nil {
				return err
			}
			entry.ReplaceValues("cn", stringValues("Changed Before Failure"))
			entry.ReplaceValues("sn", stringValues("FORCE-ROLLBACK"))
			return writer.Put(entry, true)
		},
	)
	if err == nil {
		t.Fatal("mapped Modify failure unexpectedly succeeded")
	}
	assertSQLBackendWriteSchemaPerson(t, database, "stable", "Stable", "User", "", "STABLE")
}

func TestSQLBackendWriteSchemaDNModifyDNRDNDelta(t *testing.T) {
	configuration, database, registry := newSQLBackendWriteSchemaFixture(t)

	oldRaw := "foldAlias=BRANCH+exactAlias=Tenant,dc=example,dc=com"
	entry := sqlBackendWriteSchemaEntry(oldRaw, "rename", "Rename", "User", "Tenant", "BRANCH")
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		context.Background(),
		true,
		func(writer *sqlBackendWriter) error { return writer.Put(entry, false) },
	); err != nil {
		t.Fatalf("Add ModifyDN fixture: %v", err)
	}
	clearWritableSQLProcedureEvents(t, database)

	oldDN := mustSQLBackendWriteSchemaLegacyDN(
		t,
		"1.3.6.1.4.1.99999.940.1=Tenant+foldAlias= branch ,dc=EXAMPLE,dc=COM",
	)
	newRaw := "foldAlias=NEW BRANCH+1.3.6.1.4.1.99999.940.1=Tenant,dc=example,dc=com"
	newDN := mustSQLBackendWriteSchemaLegacyDN(t, newRaw)
	ctx := withSQLBackendRename(context.Background(), oldDN, newDN)
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		ctx,
		true,
		func(writer *sqlBackendWriter) error {
			source, err := writer.Get(oldDN)
			if err != nil {
				return err
			}
			if err := writer.Delete(oldDN); err != nil {
				return err
			}
			source.DN = newRaw
			source.ReplaceValues("foldName", stringValues("NEW BRANCH"))
			return writer.Put(source, false)
		},
	); err != nil {
		t.Fatalf("ModifyDN through alias/OID/multi-AVA DN: %v", err)
	}

	oldNormalized := sqlBackendSchemaNormalizedDN(t, registry, oldRaw)
	newNormalized := sqlBackendSchemaNormalizedDN(t, registry, newRaw)
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn=?", 0, oldNormalized.String())
	assertSQLBackendWriteSchemaStoredDN(t, database, "rename", newNormalized.String())
	assertSQLBackendWriteSchemaPerson(
		t,
		database,
		"rename",
		"Rename",
		"User",
		"Tenant",
		"NEW BRANCH",
	)
	assertWritableSQLProcedureEvents(t, database, "delete-fold:BRANCH", "add-fold:NEW BRANCH")

	rollbackRaw := "exactAlias=Tenant+foldAlias=ROLLBACK,dc=example,dc=com"
	rollbackDN := mustSQLBackendWriteSchemaLegacyDN(t, rollbackRaw)
	ctx = withSQLBackendRename(context.Background(), newDN, rollbackDN)
	if err := runSQLBackendWriteSchemaTransaction(
		t,
		configuration,
		ctx,
		false,
		func(writer *sqlBackendWriter) error {
			source, err := writer.Get(newDN)
			if err != nil {
				return err
			}
			if err := writer.Delete(newDN); err != nil {
				return err
			}
			source.DN = rollbackRaw
			source.ReplaceValues("foldName", stringValues("ROLLBACK"))
			return writer.Put(source, false)
		},
	); err != nil {
		t.Fatalf("NoOp ModifyDN candidate: %v", err)
	}
	rollbackNormalized := sqlBackendSchemaNormalizedDN(t, registry, rollbackRaw)
	assertSQLBackendWriteSchemaStoredDN(t, database, "rename", newNormalized.String())
	assertWritableSQLCount(t, database, "ldap_entries WHERE dn=?", 0, rollbackNormalized.String())
	assertSQLBackendWriteSchemaPerson(
		t,
		database,
		"rename",
		"Rename",
		"User",
		"Tenant",
		"NEW BRANCH",
	)
}

func newSQLBackendWriteSchemaFixture(
	t *testing.T,
) (*sqlBackendRuntimeConfiguration, *sql.DB, *schema.Registry) {
	t.Helper()
	databaseName := filepath.Join(t.TempDir(), "write-schema-dn.db")
	seedWritableSQLBackendDatabase(t, databaseName)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open schema-aware writable fixture: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	statements := []string{
		"ALTER TABLE persons ADD COLUMN exact_name TEXT",
		"ALTER TABLE persons ADD COLUMN fold_name TEXT",
		`CREATE TABLE person_members (
			person_id INTEGER NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (person_id,value)
		)`,
		`INSERT INTO ldap_attr_mappings (
			id,oc_map_id,name,sel_expr,from_tbls,join_where,
			add_proc,delete_proc,param_order,expect_return
		) VALUES (
			6,1,'exactName','persons.exact_name','persons',NULL,
			'UPDATE persons SET exact_name=? WHERE id=?',
			'UPDATE persons SET exact_name=NULL WHERE exact_name=? AND id=?',3,0
		)`,
		`INSERT INTO ldap_attr_mappings (
			id,oc_map_id,name,sel_expr,from_tbls,join_where,
			add_proc,delete_proc,param_order,expect_return
		) VALUES (
			7,1,'foldName','persons.fold_name','persons',NULL,
			'UPDATE persons SET fold_name=? WHERE id=?',
			'UPDATE persons SET fold_name=NULL WHERE fold_name=? AND id=?',3,0
		)`,
		`INSERT INTO ldap_attr_mappings (
			id,oc_map_id,name,sel_expr,from_tbls,join_where,
			add_proc,delete_proc,param_order,expect_return
		) VALUES (
			8,1,'member','person_members.value','person_members',
			'persons.id=person_members.person_id',
			'INSERT INTO person_members (value,person_id) VALUES (?,?)',
			'DELETE FROM person_members WHERE value=? AND person_id=?',3,0
		)`,
		`CREATE TRIGGER log_exact_name_delta
			AFTER UPDATE OF exact_name ON persons
			WHEN OLD.exact_name IS NOT NEW.exact_name
			BEGIN
				INSERT INTO procedure_events(event) VALUES (
					CASE WHEN NEW.exact_name IS NULL
					THEN 'delete-exact:' || OLD.exact_name
					ELSE 'add-exact:' || NEW.exact_name END
				);
			END`,
		`CREATE TRIGGER log_fold_name_delta
			AFTER UPDATE OF fold_name ON persons
			WHEN OLD.fold_name IS NOT NEW.fold_name
			BEGIN
				INSERT INTO procedure_events(event) VALUES (
					CASE WHEN NEW.fold_name IS NULL
					THEN 'delete-fold:' || OLD.fold_name
					ELSE 'add-fold:' || NEW.fold_name END
				);
			END`,
	}
	for index, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("schema-aware writable fixture statement %d: %v\n%s", index, err, statement)
		}
	}

	registry := sqlBackendSchemaDNRegistry(t)
	if err := registry.ParseAndRegisterObjectClass(
		"( 1.3.6.1.4.1.99999.940.3 NAME 'sqlWriteIdentityAux' " +
			"SUP top AUXILIARY MAY ( exactName $ foldName $ member ) )",
	); err != nil {
		t.Fatalf("register SQL write auxiliary objectClass: %v", err)
	}
	configuration := &sqlBackendRuntimeConfiguration{
		databaseName:      databaseName,
		databaseUser:      "unused",
		driverName:        "sqlite",
		ocQuery:           defaultSQLOCQuery,
		attributeQuery:    defaultSQLATQuery,
		idQuery:           "SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE UPPER(dn)=UPPER(?)",
		idQueryConfigured: true,
		aliasingKeyword:   "AS ",
		insertEntry:       defaultSQLInsertEntryStatement,
		deleteEntry:       defaultSQLDeleteEntryStatement,
		renameEntry:       defaultSQLRenameEntryStatement,
		deleteObjectClass: defaultSQLDeleteObjectClassesStatement,
		registry:          registry,
	}
	if _, err := configuration.database(context.Background()); err != nil {
		t.Fatalf("initialize schema-aware writable SQL backend: %v", err)
	}
	t.Cleanup(func() { _ = configuration.close() })
	return configuration, database, registry
}

func runSQLBackendWriteSchemaTransaction(
	t *testing.T,
	configuration *sqlBackendRuntimeConfiguration,
	ctx context.Context,
	commit bool,
	operation func(*sqlBackendWriter) error,
) error {
	t.Helper()
	coordinator := newSQLBackendTransactionCoordinator(ctx)
	store := storage.NewMemory()
	defer store.Close()
	return store.Update(ctx, func(base storage.Writer) error {
		writer := coordinator.writer(configuration, base)
		if err := operation(writer); err != nil {
			coordinator.rollback()
			return err
		}
		if !commit {
			coordinator.rollback()
			return nil
		}
		return coordinator.commit()
	})
}

func sqlBackendWriteSchemaEntry(
	dn,
	uid,
	cn,
	sn,
	exactName,
	foldName string,
) directory.Entry {
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson", "sqlWriteIdentityAux")},
			{Description: "structuralObjectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(cn)},
			{Description: "sn", Values: stringValues(sn)},
		},
	}
	if exactName != "" {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "exactName",
			Values:      stringValues(exactName),
		})
	}
	if foldName != "" {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "foldName",
			Values:      stringValues(foldName),
		})
	}
	return entry
}

func mustSQLBackendWriteSchemaLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func assertSQLBackendWriteSchemaStoredDN(
	t *testing.T,
	database *sql.DB,
	uid,
	want string,
) {
	t.Helper()
	var got string
	if err := database.QueryRow(
		"SELECT ldap_entries.dn FROM ldap_entries "+
			"JOIN persons ON persons.id=ldap_entries.keyval "+
			"WHERE ldap_entries.oc_map_id=1 AND persons.uid=?",
		uid,
	).Scan(&got); err != nil {
		t.Fatalf("select stored DN for %q: %v", uid, err)
	}
	if got != want {
		t.Fatalf("stored DN for %q = %q, want %q", uid, got, want)
	}
	if strings.HasPrefix(got, "dn:v2:") {
		t.Fatalf("internal DN identity leaked to ldap_entries: %q", got)
	}
	var parent int64
	if err := database.QueryRow(
		"SELECT parent FROM ldap_entries WHERE dn=?",
		got,
	).Scan(&parent); err != nil {
		t.Fatalf("select parent for %q: %v", got, err)
	}
	if parent != 1 {
		t.Fatalf("parent for %q = %d, want 1", got, parent)
	}
}

func assertSQLBackendWriteSchemaPerson(
	t *testing.T,
	database *sql.DB,
	uid,
	wantCN,
	wantSN,
	wantExact,
	wantFold string,
) {
	t.Helper()
	var cn, sn string
	var exactName, foldName sql.NullString
	if err := database.QueryRow(
		"SELECT cn,sn,exact_name,fold_name FROM persons WHERE uid=?",
		uid,
	).Scan(&cn, &sn, &exactName, &foldName); err != nil {
		t.Fatalf("select schema-aware person %q: %v", uid, err)
	}
	if cn != wantCN || sn != wantSN || exactName.String != wantExact || foldName.String != wantFold {
		t.Fatalf(
			"person %q = cn %q, sn %q, exact %q, fold %q; want %q, %q, %q, %q",
			uid,
			cn,
			sn,
			exactName.String,
			foldName.String,
			wantCN,
			wantSN,
			wantExact,
			wantFold,
		)
	}
}

func assertSQLBackendWriteSchemaMember(
	t *testing.T,
	database *sql.DB,
	uid,
	want string,
) {
	t.Helper()
	var got string
	if err := database.QueryRow(
		"SELECT person_members.value FROM person_members "+
			"JOIN persons ON persons.id=person_members.person_id WHERE persons.uid=?",
		uid,
	).Scan(&got); err != nil {
		t.Fatalf("select mapped member for %q: %v", uid, err)
	}
	if got != want {
		t.Fatalf("mapped member for %q = %q, want %q", uid, got, want)
	}
	if strings.HasPrefix(got, "dn:v2:") {
		t.Fatalf("internal DN identity leaked to mapped procedure: %q", got)
	}
}
