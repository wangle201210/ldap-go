package server

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	treeDeleteTestBaseDN  = "uid=tree,dc=example,dc=com"
	treeDeleteTestChildDN = "uid=child,uid=tree,dc=example,dc=com"
	treeDeleteTestLeafDN  = "uid=leaf,uid=child,uid=tree,dc=example,dc=com"
	treeDeleteTestUserDN  = "uid=tree-deleter,dc=example,dc=com"
)

func TestLDAPTreeDeleteControlProtocolAndNativeBackend(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	const (
		rootDN       = "cn=admin,dc=example,dc=com"
		rootPassword = "admin-secret"
	)
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
	})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, rootDN, rootPassword)
	defer connection.Close()

	tests := []struct {
		name     string
		controls []*ber.Packet
		want     ldapwire.ResultCode
	}{
		{
			name: "value absent critical",
			controls: []*ber.Packet{
				rawTreeDeleteControl(true, false, nil),
			},
			want: ldapwire.ResultUnavailableCriticalExtension,
		},
		{
			name: "value absent noncritical",
			controls: []*ber.Packet{
				rawTreeDeleteControl(false, false, nil),
			},
			want: ldapwire.ResultNotAllowedOnNonLeaf,
		},
		{
			name: "empty value",
			controls: []*ber.Packet{
				rawTreeDeleteControl(false, true, nil),
			},
			want: ldapwire.ResultProtocolError,
		},
		{
			name: "nonempty value",
			controls: []*ber.Packet{
				rawTreeDeleteControl(false, true, []byte{0x30, 0x00}),
			},
			want: ldapwire.ResultProtocolError,
		},
		{
			name: "duplicate",
			controls: []*ber.Packet{
				rawTreeDeleteControl(false, false, nil),
				rawTreeDeleteControl(false, false, nil),
			},
			want: ldapwire.ResultProtocolError,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := sendRawLDAPOperation(
				t,
				connection,
				int64(index+2),
				rawDeleteRequest("ou=people,dc=example,dc=com"),
				test.controls...,
			)
			assertRawLDAPResult(t, response, int64(test.want))
			if !entryExists(t, store, "ou=people,dc=example,dc=com") ||
				!entryExists(t, store, aliceDN) {
				t.Fatal("rejected native Tree Delete changed the directory")
			}
		})
	}
}

func TestLDAPTreeDeleteSQLBackendDeletesThreeLevels(t *testing.T) {
	fixture := startTreeDeleteSQLFixture(t, false, nil)

	response := sendRawLDAPOperation(
		t,
		fixture.connection,
		2,
		rawDeleteRequest(treeDeleteTestBaseDN),
		rawTreeDeleteControl(true, false, nil),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	assertTreeDeleteSQLState(t, fixture.database, false)
	assertWritableSQLCount(t, fixture.database, "procedure_events", 6)
}

func TestLDAPTreeDeleteSQLBackendACLFailureRollsBackEntireTree(t *testing.T) {
	fixture := startTreeDeleteSQLFixture(t, true, func(store storage.Store) {
		replaceTreeDeleteSQLAccess(t, store,
			"{0}to attrs=userPassword by anonymous auth by self write by * none",
			`{1}to dn.exact="`+treeDeleteTestLeafDN+`" by dn.exact="`+
				treeDeleteTestUserDN+`" none by * break`,
			`{2}to * by dn.exact="`+treeDeleteTestUserDN+`" write by * none`,
		)
	})

	response := sendRawLDAPOperation(
		t,
		fixture.connection,
		2,
		rawDeleteRequest(treeDeleteTestBaseDN),
		rawTreeDeleteControl(true, false, nil),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultInsufficientAccessRights))
	assertTreeDeleteSQLState(t, fixture.database, true)
	assertWritableSQLCount(t, fixture.database, "procedure_events", 0)
}

func TestLDAPTreeDeleteSQLBackendNoOpRollsBackEntireTree(t *testing.T) {
	fixture := startTreeDeleteSQLFixture(t, false, nil)

	response := sendRawLDAPOperation(
		t,
		fixture.connection,
		2,
		rawDeleteRequest(treeDeleteTestBaseDN),
		rawTreeDeleteControl(true, false, nil),
		rawOIDControl(noOpControlOID, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultNoOperation))
	assertNoRawResponseControls(t, response)
	assertTreeDeleteSQLState(t, fixture.database, true)
	assertWritableSQLCount(t, fixture.database, "procedure_events", 0)
}

func TestLDAPTreeDeleteSQLBackendForcesTransactionWithAutocommit(t *testing.T) {
	fixture := startTreeDeleteSQLFixture(t, false, func(store storage.Store) {
		replaceTreeDeleteSQLAutocommit(t, store, true)
	})

	response := sendRawLDAPOperation(
		t,
		fixture.connection,
		2,
		rawDeleteRequest(treeDeleteTestBaseDN),
		rawTreeDeleteControl(true, false, nil),
		rawOIDControl(noOpControlOID, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultNoOperation))
	assertTreeDeleteSQLState(t, fixture.database, true)
	assertWritableSQLCount(t, fixture.database, "procedure_events", 0)
}

func TestLDAPTreeDeleteSQLBackendPreReadContainsOnlyBaseEntry(t *testing.T) {
	fixture := startTreeDeleteSQLFixture(t, false, nil)

	response := sendRawLDAPOperation(
		t,
		fixture.connection,
		2,
		rawDeleteRequest(treeDeleteTestBaseDN),
		rawTreeDeleteControl(true, false, nil),
		rawReadControl(preReadControlOID, true, "uid"),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	if len(response.Children) != 3 || len(response.Children[2].Children) != 1 {
		t.Fatalf("Tree Delete response controls = %#v, want one pre-read control", response)
	}
	preRead := rawReadControlEntry(t, response, preReadControlOID)
	if preRead.DN != treeDeleteTestBaseDN ||
		len(preRead.Values("uid")) != 1 ||
		string(preRead.Values("uid")[0]) != "tree" {
		t.Fatalf("Tree Delete pre-read entry = %#v, want only base %q", preRead, treeDeleteTestBaseDN)
	}
	for _, subordinateUID := range []string{"child", "leaf"} {
		if preRead.HasValue("uid", []byte(subordinateUID)) {
			t.Fatalf("Tree Delete pre-read included subordinate uid %q", subordinateUID)
		}
	}
	assertTreeDeleteSQLState(t, fixture.database, false)
}

type treeDeleteSQLFixture struct {
	database   *sql.DB
	connection net.Conn
}

func startTreeDeleteSQLFixture(
	t *testing.T,
	bindAsUser bool,
	configure func(storage.Store),
) treeDeleteSQLFixture {
	t.Helper()
	databaseName := filepath.Join(t.TempDir(), "tree-delete.db")
	seedWritableSQLBackendDatabase(t, databaseName)
	seedTreeDeleteSQLRows(t, databaseName, bindAsUser)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	if configure != nil {
		configure(store)
	}
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	t.Cleanup(stop)

	bindDN := "cn=admin,dc=example,dc=com"
	password := "admin-secret"
	if bindAsUser {
		bindDN = treeDeleteTestUserDN
		password = "tree-delete-secret"
	}
	connection := dialAndBindRawLDAP(t, address, bindDN, password)
	t.Cleanup(func() { _ = connection.Close() })

	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open Tree Delete SQLite fixture: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return treeDeleteSQLFixture{database: database, connection: connection}
}

func seedTreeDeleteSQLRows(t *testing.T, databaseName string, includeUser bool) {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open Tree Delete SQLite seed: %v", err)
	}
	defer database.Close()

	statements := []string{
		`INSERT INTO persons (id,uid,cn,sn) VALUES
			(20,'tree','Tree Base','Base'),
			(21,'child','Tree Child','Child'),
			(22,'leaf','Tree Leaf','Leaf')`,
		`INSERT INTO ldap_entries (id,dn,oc_map_id,parent,keyval) VALUES
			(2,'` + treeDeleteTestBaseDN + `',1,1,20),
			(3,'` + treeDeleteTestChildDN + `',1,2,21),
			(4,'` + treeDeleteTestLeafDN + `',1,3,22)`,
		`INSERT INTO person_descriptions (person_id,value) VALUES
			(20,'base description'),
			(21,'child description'),
			(22,'leaf description')`,
		`DELETE FROM procedure_events`,
	}
	if includeUser {
		statements = append(statements,
			`ALTER TABLE persons ADD COLUMN user_password BLOB`,
			`INSERT INTO ldap_attr_mappings (
				id,oc_map_id,name,sel_expr,from_tbls,join_where,
				add_proc,delete_proc,param_order,expect_return
			) VALUES (
				6,1,'userPassword','persons.user_password','persons',NULL,
				'UPDATE persons SET user_password=? WHERE id=?',
				'UPDATE persons SET user_password=NULL WHERE user_password=? AND id=?',3,0
			)`,
			`INSERT INTO persons (id,uid,cn,sn,user_password) VALUES
				(23,'tree-deleter','Tree Deleter','Deleter','tree-delete-secret')`,
			`INSERT INTO ldap_entries (id,dn,oc_map_id,parent,keyval) VALUES
				(5,'`+treeDeleteTestUserDN+`',1,1,23)`,
		)
	}
	for index, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("Tree Delete SQLite seed statement %d: %v\n%s", index, err, statement)
		}
	}
}

func replaceTreeDeleteSQLAccess(t *testing.T, store storage.Store, rules ...string) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}sql,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(rules...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure Tree Delete SQL ACL: %v", err)
	}
}

func replaceTreeDeleteSQLAutocommit(t *testing.T, store storage.Store, enabled bool) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}sql,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		value := "FALSE"
		if enabled {
			value = "TRUE"
		}
		entry.ReplaceValues("olcSqlAutocommit", stringValues(value))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure Tree Delete SQL autocommit: %v", err)
	}
}

func assertTreeDeleteSQLState(t *testing.T, database *sql.DB, present bool) {
	t.Helper()
	want := 0
	if present {
		want = 3
	}
	assertWritableSQLCount(
		t,
		database,
		"ldap_entries WHERE dn IN (?,?,?)",
		want,
		treeDeleteTestBaseDN,
		treeDeleteTestChildDN,
		treeDeleteTestLeafDN,
	)
	assertWritableSQLCount(
		t,
		database,
		"persons WHERE uid IN (?,?,?)",
		want,
		"tree",
		"child",
		"leaf",
	)
	assertWritableSQLCount(
		t,
		database,
		"person_descriptions WHERE person_id IN (?,?,?)",
		want,
		20,
		21,
		22,
	)
}

func rawTreeDeleteControl(critical, hasValue bool, value []byte) *ber.Packet {
	control := ber.NewSequence("TreeDeleteControl")
	control.AppendChild(rawOctetString([]byte(treeDeleteControlOID)))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if hasValue {
		control.AppendChild(rawOctetString(value))
	}
	return control
}
