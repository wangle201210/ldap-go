package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSQLBackendHasChildrenQueryMatchesOpenLDAPDefaults(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
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
			name: "upper",
			configuration: &sqlBackendRuntimeConfiguration{
				upperFunction:   "UPPER",
				aliasingKeyword: "AS ",
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries AS subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND " +
				"UPPER(ldap_entries.dn)=UPPER(?)",
		},
		{
			name: "upper with cast",
			configuration: &sqlBackendRuntimeConfiguration{
				upperFunction:   "UPPER",
				upperNeedsCast:  true,
				aliasingKeyword: "AS ",
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries AS subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND " +
				"UPPER(ldap_entries.dn)=UPPER(cast (? as varchar(255)))",
		},
		{
			name: "configured",
			configuration: &sqlBackendRuntimeConfiguration{
				dnMatchCondition:  "LOWER(ldap_entries.dn)=LOWER(?)",
				dnMatchConfigured: true,
				aliasingKeyword:   "AS ",
			},
			want: "SELECT COUNT(distinct subordinates.id) " +
				"FROM ldap_entries,ldap_entries AS subordinates " +
				"WHERE subordinates.parent=ldap_entries.id AND " +
				"LOWER(ldap_entries.dn)=LOWER(?)",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.configuration.prepareHasChildrenQuery()
			if test.configuration.hasChildrenQuery != test.want {
				t.Fatalf(
					"has-children query = %q, want %q",
					test.configuration.hasChildrenQuery,
					test.want,
				)
			}
		})
	}
}

func TestLoadSQLBackendDNMatchCondition(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "olcDatabase={1}sql,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDbName", Values: stringValues("directory")},
			{Description: "olcDbUser", Values: stringValues("ldap")},
			{Description: "olcSqlDnMatchCond", Values: stringValues(
				"LOWER(ldap_entries.dn)=LOWER(?)",
			)},
		},
	}
	configuration, err := loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadSQLBackendRuntimeConfiguration(): %v", err)
	}
	if !configuration.dnMatchConfigured ||
		configuration.dnMatchCondition != "LOWER(ldap_entries.dn)=LOWER(?)" {
		t.Fatalf("DN-match configuration = %#v", configuration)
	}

	changedEntry := entry.Clone()
	changedEntry.ReplaceValues("olcSqlDnMatchCond", stringValues("ldap_entries.dn=?"))
	changed, err := loadSQLBackendRuntimeConfiguration(changedEntry)
	if err != nil {
		t.Fatalf("load changed SQL backend configuration: %v", err)
	}
	if configuration.equivalent(changed) {
		t.Fatal("changed olcSqlDnMatchCond reused stale SQL runtime state")
	}
}

func TestSQLBackendDNMatchConditionControlsSubordinates(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "dn-match.db")
	seedSQLBackendDatabase(t, databaseName)
	seedSQLBackendDNMatchHierarchy(t, databaseName)

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
		entry.ReplaceValues("olcSqlDnMatchCond", stringValues(
			"LOWER(ldap_entries.dn)=LOWER(?) AND subordinates.id<>999",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure olcSqlDnMatchCond: %v", err)
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

	const parentDN = "ou=people,dc=example,dc=com"
	result, err := client.Search(ldap.NewSearchRequest(
		parentDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(hasSubordinates=TRUE)",
		[]string{"ou", "hasSubordinates"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(hasSubordinates=TRUE): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("hasSubordinates") != "TRUE" {
		t.Fatalf("hasSubordinates result = %#v", result.Entries)
	}

	assertLDAPResultCode(
		t,
		client.Del(ldap.NewDelRequest(parentDN, nil)),
		ldap.LDAPResultNotAllowedOnNonLeaf,
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(ldap.NewModifyDNRequest(parentDN, "ou=members", true, "")),
		ldap.LDAPResultNotAllowedOnNonLeaf,
	)
}

func seedSQLBackendDNMatchHierarchy(t *testing.T, databaseName string) {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open DN-match fixture: %v", err)
	}
	defer database.Close()
	statements := []string{
		`CREATE TABLE organizational_units (id INTEGER PRIMARY KEY, ou TEXT)`,
		`INSERT INTO ldap_oc_mappings VALUES
			(4,'organizationalUnit','organizational_units','id',NULL,NULL,0)`,
		`INSERT INTO ldap_attr_mappings VALUES
			(7,4,'ou','organizational_units.ou','organizational_units',NULL,NULL,NULL,0,0,NULL)`,
		`INSERT INTO organizational_units VALUES (30,'people')`,
		`INSERT INTO ldap_entries VALUES
			(3,'ou=people,dc=example,dc=com',4,1,30)`,
		`UPDATE ldap_entries SET parent=3 WHERE id=2`,
	}
	for index, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("DN-match fixture statement %d: %v\n%s", index, err, statement)
		}
	}
}
