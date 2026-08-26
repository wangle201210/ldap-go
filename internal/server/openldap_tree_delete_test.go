package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPTreeDeleteVersion = "2.6.13"
	openLDAPTreeDeleteCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
)

func TestOpenLDAPReferenceTreeDeleteMDBProtocol(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"access to * by * read",
		"",
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedTreeDeleteMDBLeaf(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopLocal)
	localURI := "ldap://" + localAddress

	absent := func(critical bool) ldap.Control {
		return treeDeleteWireControl(critical, false, nil)
	}
	value := func(critical bool, value []byte) ldap.Control {
		return treeDeleteWireControl(critical, true, value)
	}
	nonLeafDN := "ou=people,dc=example,dc=com"
	for _, test := range []struct {
		name     string
		controls []ldap.Control
		want     uint16
	}{
		{name: "absent noncritical", controls: []ldap.Control{absent(false)}, want: ldap.LDAPResultNotAllowedOnNonLeaf},
		{name: "absent critical", controls: []ldap.Control{absent(true)}, want: ldap.LDAPResultUnavailableCriticalExtension},
		{name: "empty noncritical", controls: []ldap.Control{value(false, nil)}, want: ldap.LDAPResultProtocolError},
		{name: "empty critical", controls: []ldap.Control{value(true, nil)}, want: ldap.LDAPResultProtocolError},
		{name: "nonempty noncritical", controls: []ldap.Control{value(false, []byte{0})}, want: ldap.LDAPResultProtocolError},
		{name: "nonempty critical", controls: []ldap.Control{value(true, []byte{0})}, want: ldap.LDAPResultProtocolError},
		{name: "duplicate noncritical", controls: []ldap.Control{absent(false), absent(false)}, want: ldap.LDAPResultProtocolError},
		{name: "duplicate mixed criticality", controls: []ldap.Control{absent(false), absent(true)}, want: ldap.LDAPResultProtocolError},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference := observeTreeDelete(t, referenceURI, nonLeafDN, test.controls)
			local := observeTreeDelete(t, localURI, nonLeafDN, test.controls)
			if reference != test.want || local != test.want {
				t.Fatalf(
					"Tree Delete result: OpenLDAP=%d ldap-go=%d, want both %d",
					reference,
					local,
					test.want,
				)
			}
		})
	}

	t.Run("noncritical leaf is an ordinary MDB delete", func(t *testing.T) {
		const dn = "uid=bob,ou=people,dc=example,dc=com"
		reference := observeTreeDelete(t, referenceURI, dn, []ldap.Control{absent(false)})
		local := observeTreeDelete(t, localURI, dn, []ldap.Control{absent(false)})
		if reference != ldap.LDAPResultSuccess || local != ldap.LDAPResultSuccess {
			t.Fatalf("leaf result: OpenLDAP=%d ldap-go=%d, want success", reference, local)
		}
		assertTreeDeleteEntryPresence(t, referenceURI, dn, false)
		assertTreeDeleteEntryPresence(t, localURI, dn, false)
	})

	t.Run("critical leaf is rejected by MDB", func(t *testing.T) {
		const dn = "uid=alice,ou=people,dc=example,dc=com"
		reference := observeTreeDelete(t, referenceURI, dn, []ldap.Control{absent(true)})
		local := observeTreeDelete(t, localURI, dn, []ldap.Control{absent(true)})
		if reference != ldap.LDAPResultUnavailableCriticalExtension ||
			local != ldap.LDAPResultUnavailableCriticalExtension {
			t.Fatalf("leaf result: OpenLDAP=%d ldap-go=%d, want unavailableCriticalExtension", reference, local)
		}
		assertTreeDeleteEntryPresence(t, referenceURI, dn, true)
		assertTreeDeleteEntryPresence(t, localURI, dn, true)
	})

	for _, test := range []struct {
		name    string
		control ldap.Control
		want    uint16
	}{
		{name: "noncritical on Search is ignored without value validation", control: value(false, []byte{0}), want: ldap.LDAPResultSuccess},
		{name: "critical on Search is unsupported", control: absent(true), want: ldap.LDAPResultUnavailableCriticalExtension},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference := observeTreeDeleteSearch(t, referenceURI, test.control)
			local := observeTreeDeleteSearch(t, localURI, test.control)
			if reference != test.want || local != test.want {
				t.Fatalf("Search result: OpenLDAP=%d ldap-go=%d, want both %d", reference, local, test.want)
			}
		})
	}

	t.Run("hidden from Root DSE", func(t *testing.T) {
		for name, uri := range map[string]string{"OpenLDAP": referenceURI, "ldap-go": localURI} {
			if treeDeleteRootDSEAdvertisesControl(t, uri) {
				t.Fatalf("%s Root DSE advertises hidden Tree Delete control", name)
			}
		}
	})
}

func TestOpenLDAPReferenceTreeDeleteBackSQL(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	requireOpenLDAPSQLBackend(t, tools)
	driver := requireSQLiteODBCDriver(t)

	for _, test := range []struct {
		name                string
		controls            func() []ldap.Control
		bindDN              string
		password            string
		acl                 string
		wantOpenLDAPCode    uint16
		wantLDAPGoCode      uint16
		wantReferenceChange bool
		wantLocalChange     bool
		hardenedDivergence  bool
	}{
		{
			name: "noncritical success",
			controls: func() []ldap.Control {
				return []ldap.Control{treeDeleteWireControl(false, false, nil)}
			},
			bindDN: "cn=admin,dc=example,dc=com", password: "admin-secret",
			wantOpenLDAPCode:    ldap.LDAPResultSuccess,
			wantLDAPGoCode:      ldap.LDAPResultSuccess,
			wantReferenceChange: true,
			wantLocalChange:     true,
		},
		{
			name: "critical success",
			controls: func() []ldap.Control {
				return []ldap.Control{treeDeleteWireControl(true, false, nil)}
			},
			bindDN: "cn=admin,dc=example,dc=com", password: "admin-secret",
			wantOpenLDAPCode:    ldap.LDAPResultSuccess,
			wantLDAPGoCode:      ldap.LDAPResultSuccess,
			wantReferenceChange: true,
			wantLocalChange:     true,
		},
		{
			name: "No-Op rolls back complete subtree",
			controls: func() []ldap.Control {
				return []ldap.Control{
					treeDeleteWireControl(true, false, nil),
					ldap.NewControlString(noOpControlOID, true, ""),
				}
			},
			bindDN: "cn=admin,dc=example,dc=com", password: "admin-secret",
			wantOpenLDAPCode:    uint16(0x410e),
			wantLDAPGoCode:      uint16(0x410e),
			wantReferenceChange: false,
			wantLocalChange:     false,
		},
		{
			name: "ACL denial exposes reference partial commit and ldap-go rollback",
			controls: func() []ldap.Control {
				return []ldap.Control{treeDeleteWireControl(true, false, nil)}
			},
			bindDN: "uid=alice,ou=people,dc=example,dc=com", password: "alice-secret",
			acl: openLDAPTreeDeleteRollbackACL(),
			// OpenLDAP 2.6.13 reports success and commits the prefix deleted
			// before its subtree-search callback reaches the denied entry.
			wantOpenLDAPCode:    ldap.LDAPResultSuccess,
			wantLDAPGoCode:      ldap.LDAPResultInsufficientAccessRights,
			wantReferenceChange: true,
			wantLocalChange:     false,
			hardenedDivergence:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			referenceDatabase := filepath.Join(root, "openldap.db")
			localDatabase := filepath.Join(root, "ldap-go.db")
			seedSQLDifferentialDatabase(t, referenceDatabase)
			seedSQLDifferentialDatabase(t, localDatabase)
			enableTreeDeleteSQLMappings(t, referenceDatabase)
			enableTreeDeleteSQLMappings(t, localDatabase)

			referenceURI := startOpenLDAPTreeDeleteSQLServer(
				t,
				tools,
				driver,
				referenceDatabase,
				test.acl,
			)
			localURI := startLDAPGoTreeDeleteSQLServer(t, localDatabase, test.acl)
			referenceBaseline := snapshotSQLDifferentialDatabase(t, referenceDatabase)
			localBaseline := snapshotSQLDifferentialDatabase(t, localDatabase)
			if !reflect.DeepEqual(referenceBaseline, localBaseline) {
				t.Fatalf("fixture baselines differ\nOpenLDAP: %#v\nldap-go:  %#v", referenceBaseline, localBaseline)
			}

			referenceResult := observeBoundTreeDeleteResult(
				t, referenceURI, test.bindDN, test.password,
				"ou=people,dc=example,dc=com", test.controls(),
			)
			localResult := observeBoundTreeDeleteResult(
				t, localURI, test.bindDN, test.password,
				"ou=people,dc=example,dc=com", test.controls(),
			)
			if referenceResult.Code != test.wantOpenLDAPCode ||
				localResult.Code != test.wantLDAPGoCode {
				t.Errorf(
					"back-sql result:\nOpenLDAP: %#v (want %d)\nldap-go:  %#v (want %d)",
					referenceResult,
					test.wantOpenLDAPCode,
					localResult,
					test.wantLDAPGoCode,
				)
			}

			referenceState := snapshotSQLDifferentialDatabase(t, referenceDatabase)
			localState := snapshotSQLDifferentialDatabase(t, localDatabase)
			if !test.hardenedDivergence && !reflect.DeepEqual(referenceState, localState) {
				t.Fatalf("back-sql state mismatch\nOpenLDAP: %#v\nldap-go:  %#v", referenceState, localState)
			}
			referenceChanged := !reflect.DeepEqual(referenceState, referenceBaseline)
			localChanged := !reflect.DeepEqual(localState, localBaseline)
			if referenceChanged != test.wantReferenceChange || localChanged != test.wantLocalChange {
				t.Fatalf(
					"database changes = OpenLDAP:%t ldap-go:%t, want %t/%t\nOpenLDAP: %#v\nldap-go: %#v",
					referenceChanged,
					localChanged,
					test.wantReferenceChange,
					test.wantLocalChange,
					referenceState,
					localState,
				)
			}
			if test.wantLocalChange {
				assertTreeDeleteSQLSubtreeRemoved(t, referenceState)
				assertTreeDeleteSQLSubtreeRemoved(t, localState)
			}
			if test.hardenedDivergence {
				assertOpenLDAPTreeDeleteACLPartialCommit(t, referenceState)
				if !reflect.DeepEqual(localState, localBaseline) {
					t.Fatalf("ldap-go did not atomically roll back ACL denial: %#v", localState)
				}
			}
		})
	}
}

func TestOpenLDAP2613TreeDeleteSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	command := exec.Command("git", "-C", sourceRoot, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("read pinned OpenLDAP commit: %v", err)
	}
	if commit := strings.TrimSpace(string(output)); commit != openLDAPTreeDeleteCommit {
		t.Fatalf("OpenLDAP source commit = %s, want %s (%s)", commit, openLDAPTreeDeleteCommit, openLDAPTreeDeleteVersion)
	}

	files := []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: "servers/slapd/controls.c",
			hash: "dac19d7202fd319e7d79487a0d3263e5f773750f1459457ae88f5179bb9e61d6",
			anchors: []string{
				"SLAP_CTRL_DELETE|SLAP_CTRL_HIDE",
				"parseTreeDelete",
				"treeDelete control specified multiple times",
				"treeDelete control value not absent",
			},
		},
		{
			path: "servers/slapd/back-sql/init.c",
			hash: "96328512f05f63cb8de2db3f6006a25b21d2f40b8be60e008179a139d33dc3fc",
			anchors: []string{
				"SLAP_CONTROL_X_TREE_DELETE",
				"bi->bi_controls = controls;",
			},
		},
		{
			path: "servers/slapd/back-sql/delete.c",
			hash: "41a5497030e7d9ec76607f9db405b5b007a13631fe80dfcd9f914d35dfeb3e35",
			anchors: []string{
				"perform an internal subtree search as the rootdn",
				"ACL_WDEL",
				"subtree delete not possible",
				"if ( rs->sr_err == LDAP_SUCCESS && !op->o_noop )",
				"CompletionType = SQL_COMMIT;",
			},
		},
		{
			path: "servers/slapd/backend.c",
			hash: "3857ce86f0b38d765a6c83a81ac8216726fed735fb1cef805e8bfa69215c00cf",
			anchors: []string{
				"LDAP_UNAVAILABLE_CRITICAL_EXTENSION",
				"bi->bi_controls",
			},
		},
		{
			path: "servers/slapd/slap.h",
			hash: "c3533216d0ebbc881f3719cc2badcb6941dc09d25a14b438eeb0d6b01c734d6d",
			anchors: []string{
				"#define SLAP_CONTROL_X_TREE_DELETE LDAP_CONTROL_X_TREE_DELETE",
				"#define get_treeDelete(op)",
			},
		},
	}
	for _, file := range files {
		contents, readErr := os.ReadFile(filepath.Join(sourceRoot, file.path))
		if readErr != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", file.path, readErr)
		}
		gotHash := fmt.Sprintf("%x", sha256.Sum256(contents))
		if gotHash != file.hash {
			t.Fatalf("pinned OpenLDAP source %s SHA-256 = %s, want %s", file.path, gotHash, file.hash)
		}
		for _, anchor := range file.anchors {
			if !bytes.Contains(contents, []byte(anchor)) {
				t.Fatalf("pinned OpenLDAP source %s lacks %q", file.path, anchor)
			}
		}
	}
}

func treeDeleteWireControl(critical, hasValue bool, value []byte) ldap.Control {
	return &domainScopeWireControl{
		oid: treeDeleteControlOID, critical: critical,
		hasValue: hasValue, value: append([]byte(nil), value...),
	}
}

func seedTreeDeleteMDBLeaf(t *testing.T, store storage.Store) {
	t.Helper()
	entry := directory.Entry{
		DN: "uid=bob,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("bob")},
			{Description: "cn", Values: stringValues("Bob")},
			{Description: "sn", Values: stringValues("Bob")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed ldap-go Tree Delete MDB leaf: %v", err)
	}
}

func observeTreeDelete(
	t *testing.T,
	uri,
	dn string,
	controls []ldap.Control,
) uint16 {
	t.Helper()
	return observeBoundTreeDelete(
		t,
		uri,
		"cn=admin,dc=example,dc=com",
		"secret",
		dn,
		controls,
	)
}

func observeBoundTreeDelete(
	t *testing.T,
	uri,
	bindDN,
	password,
	dn string,
	controls []ldap.Control,
) uint16 {
	t.Helper()
	return observeBoundTreeDeleteResult(t, uri, bindDN, password, dn, controls).Code
}

func observeBoundTreeDeleteResult(
	t *testing.T,
	uri,
	bindDN,
	password,
	dn string,
	controls []ldap.Control,
) sqlDifferentialLDAPResult {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	if err := client.Bind(bindDN, password); err != nil {
		t.Fatalf("bind %s as %s: %v", uri, bindDN, err)
	}
	return observeSQLDifferentialResult(
		"Tree Delete "+dn,
		client.Del(ldap.NewDelRequest(dn, controls)),
	)
}

func observeTreeDeleteSearch(t *testing.T, uri string, control ldap.Control) uint16 {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind %s: %v", uri, err)
	}
	_, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		[]ldap.Control{control},
	))
	return sqlDifferentialResultCode(err)
}

func assertTreeDeleteEntryPresence(t *testing.T, uri, dn string, want bool) {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind %s: %v", uri, err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	present := err == nil && result != nil && len(result.Entries) == 1
	if present != want {
		t.Fatalf("entry %s present = %t, want %t (result=%#v err=%v)", dn, present, want, result, err)
	}
}

func treeDeleteRootDSEAdvertisesControl(t *testing.T, uri string) bool {
	t.Helper()
	client := dialSQLDifferentialServer(t, uri)
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	if err != nil || result == nil || len(result.Entries) != 1 {
		t.Fatalf("read Root DSE from %s: result=%#v err=%v", uri, result, err)
	}
	for _, oid := range result.Entries[0].GetAttributeValues("supportedControl") {
		if oid == treeDeleteControlOID {
			return true
		}
	}
	return false
}

func enableTreeDeleteSQLMappings(t *testing.T, databaseName string) {
	t.Helper()
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("open Tree Delete SQL fixture: %v", err)
	}
	defer database.Close()
	for _, statement := range []string{
		`DROP TRIGGER reject_rollback_add_entry`,
		`DROP TRIGGER reject_rollback_sn_delete`,
		`DROP TRIGGER reject_rollback_uid_add`,
		`DROP TRIGGER reject_rollback_entry_delete`,
		`UPDATE ldap_oc_mappings SET delete_proc='DELETE FROM domains WHERE id=?' WHERE id=1`,
		`UPDATE ldap_oc_mappings SET delete_proc='DELETE FROM organizational_units WHERE id=?' WHERE id=2`,
	} {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("enable Tree Delete SQL mapping: %v\n%s", err, statement)
		}
	}
}

func openLDAPTreeDeleteRollbackACL() string {
	return `access to attrs=userPassword
    by anonymous auth
    by self write
    by * none
access to dn.exact="dc=example,dc=com" attrs=children
    by dn.exact="uid=alice,ou=people,dc=example,dc=com" write
    by * read
access to dn.exact="uid=bob,ou=people,dc=example,dc=com" attrs=entry,children
    by dn.exact="uid=alice,ou=people,dc=example,dc=com" disclose stop
    by * read
access to dn.subtree="ou=people,dc=example,dc=com"
    by dn.exact="uid=alice,ou=people,dc=example,dc=com" write
    by * read`
}

func defaultOpenLDAPTreeDeleteACL() string {
	return `access to attrs=userPassword
    by anonymous auth
    by self write
    by * none
access to *
    by * read`
}

func startOpenLDAPTreeDeleteSQLServer(
	t *testing.T,
	tools openLDAPReferenceTools,
	driver,
	databaseName,
	access string,
) string {
	t.Helper()
	if access == "" {
		access = defaultOpenLDAPTreeDeleteACL()
	}
	root := t.TempDir()
	odbcinstPath := filepath.Join(root, "odbcinst.ini")
	odbcPath := filepath.Join(root, "odbc.ini")
	configPath := filepath.Join(root, "slapd.conf")
	if err := os.WriteFile(odbcinstPath, []byte(fmt.Sprintf(
		"[SQLite3]\nDescription=SQLite3 ODBC Driver\nDriver=%s\nSetup=%s\nThreading=2\n",
		driver,
		driver,
	)), 0o600); err != nil {
		t.Fatalf("write Tree Delete odbcinst.ini: %v", err)
	}
	if err := os.WriteFile(odbcPath, []byte(fmt.Sprintf(
		"[ldap-go-tree-delete]\nDriver=SQLite3\nDatabase=%s\nTimeout=5000\nNoWCHAR=1\n",
		databaseName,
	)), 0o600); err != nil {
		t.Fatalf("write Tree Delete odbc.ini: %v", err)
	}
	config := fmt.Sprintf(`include %s
include %s
include %s
pidfile %s
argsfile %s

%s

database sql
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw admin-secret
dbname ldap-go-tree-delete
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
		access,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write Tree Delete slapd.conf: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Tree Delete reference port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release Tree Delete reference port: %v", err)
	}
	uri := "ldap://" + address
	var logs bytes.Buffer
	debugLevel := os.Getenv(openLDAPSlapdDebugEnv)
	if debugLevel == "" {
		debugLevel = "0"
	}
	command := exec.Command(tools.slapd, "-f", configPath, "-h", uri, "-d", debugLevel)
	command.Env = append(os.Environ(),
		"ODBCSYSINI="+root,
		"ODBCINSTINI=odbcinst.ini",
		"ODBCINI="+odbcPath,
	)
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		t.Fatalf("start OpenLDAP Tree Delete SQL reference: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		defer func() {
			if t.Failed() && logs.Len() > 0 {
				t.Logf("OpenLDAP Tree Delete SQL log tail:\n%s", openLDAPReferenceLogTail(logs.Bytes()))
			}
		}()
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
				"OpenLDAP Tree Delete SQL reference exited during startup: %v\nslapd.conf:\n%s\nlog:\n%s",
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
			t.Fatalf("OpenLDAP Tree Delete SQL reference did not start: %v\n%s", dialErr, logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return uri
}

func startLDAPGoTreeDeleteSQLServer(t *testing.T, databaseName, access string) string {
	t.Helper()
	if access == "" {
		access = defaultOpenLDAPTreeDeleteACL()
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
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
			{Description: "olcAccess", Values: treeDeleteACLValues(access)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed ldap-go Tree Delete SQL configuration: %v", err)
	}
	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	t.Cleanup(stop)
	return "ldap://" + address
}

func treeDeleteACLValues(access string) [][]byte {
	lines := strings.Split(access, "\n")
	var rules []string
	var current string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "access to ") {
			if current != "" {
				rules = append(rules, current)
			}
			current = strings.TrimPrefix(trimmed, "access ")
			continue
		}
		current += " " + trimmed
	}
	if current != "" {
		rules = append(rules, current)
	}
	values := make([]string, len(rules))
	for index, rule := range rules {
		values[index] = fmt.Sprintf("{%d}%s", index, rule)
	}
	return stringValues(values...)
}

func assertTreeDeleteSQLSubtreeRemoved(t *testing.T, state sqlDifferentialDatabaseState) {
	t.Helper()
	if len(state.Entries) != 1 ||
		len(state.EntryObjectClasses) != 1 ||
		len(state.Domains) != 1 ||
		len(state.OrganizationalUnits) != 0 ||
		len(state.Persons) != 0 {
		t.Fatalf("Tree Delete left subtree SQL rows: %#v", state)
	}
}

func assertOpenLDAPTreeDeleteACLPartialCommit(
	t *testing.T,
	state sqlDifferentialDatabaseState,
) {
	t.Helper()
	// The internal search collects the base and Alice before Bob's ACL denial.
	// OpenLDAP 2.6.13 loses the callback error, deletes those collected rows,
	// commits, and leaves Bob plus the later person rows orphaned.
	if len(state.Entries) != 5 ||
		len(state.EntryObjectClasses) != 13 ||
		len(state.Domains) != 1 ||
		len(state.OrganizationalUnits) != 0 ||
		len(state.Persons) != 4 {
		t.Fatalf("OpenLDAP ACL partial-commit shape changed: %#v", state)
	}
}
