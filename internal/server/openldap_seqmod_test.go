package server

import (
	"bytes"
	"crypto/sha256"
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
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPSeqmodVersion = "2.6.13"
	openLDAPSeqmodCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	openLDAPSeqmodFrontendDatabaseDN = "olcDatabase={-1}frontend,cn=config"
	openLDAPSeqmodDataDatabaseDN     = "olcDatabase={1}mdb,cn=config"
)

type openLDAPSeqmodBasicOutcome struct {
	codes       []uint16
	description string
}

func TestOpenLDAPReferenceSeqmodOverlay(t *testing.T) {
	tools := requireOpenLDAPSeqmodReferenceTools(t)

	t.Run("pinned source model", func(t *testing.T) {
		assertPinnedOpenLDAPSeqmodReference(t)
	})

	t.Run("startup configuration and cn=config shape", func(t *testing.T) {
		assertOpenLDAPSeqmodStartupConfiguration(t, tools)
		assertOpenLDAPSeqmodConfigurationShape(t, tools)
	})

	t.Run("online lifecycle disabled and restart", func(t *testing.T) {
		assertOpenLDAPSeqmodOnlineLifecycle(t, tools)
	})

	t.Run("basic operation results", func(t *testing.T) {
		assertOpenLDAPSeqmodBasicOperationResults(t, tools)
	})
}

func requireOpenLDAPSeqmodReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the pinned OpenLDAP seqmod reference test",
			openLDAPReferenceTestsEnv,
		)
	}

	requireTool := func(environment, name string) string {
		t.Helper()
		path := os.Getenv(environment)
		if path == "" {
			var err error
			path, err = exec.LookPath(name)
			if err != nil {
				t.Fatalf("pinned OpenLDAP fixture requires %s: %v", name, err)
			}
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			t.Fatalf("pinned OpenLDAP %s path %q is unavailable: %v", name, path, err)
		}
		return path
	}

	schemaDir := os.Getenv("OPENLDAP_SCHEMA_DIR")
	if schemaDir == "" {
		t.Fatal("pinned OpenLDAP fixture requires OPENLDAP_SCHEMA_DIR")
	}
	for _, name := range []string{"core.schema", "cosine.schema", "inetorgperson.schema"} {
		if _, err := os.Stat(filepath.Join(schemaDir, name)); err != nil {
			t.Fatalf("pinned OpenLDAP schema %s is unavailable: %v", name, err)
		}
	}
	return openLDAPReferenceTools{
		slapd:     requireTool("OPENLDAP_SLAPD", "slapd"),
		slapadd:   requireTool("OPENLDAP_SLAPADD", "slapadd"),
		schemaDir: schemaDir,
	}
}

func assertPinnedOpenLDAPSeqmodReference(t *testing.T) {
	t.Helper()
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OpenLDAP reference verified flag = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPSeqmodVersion {
		t.Fatalf("OpenLDAP reference version = %q, want %q", got, openLDAPSeqmodVersion)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPSeqmodCommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPSeqmodCommit)
	}

	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("pinned OpenLDAP seqmod fixture requires OPENLDAP_SOURCE")
	}
	sources := []struct {
		path string
		hash string
	}{
		{
			path: filepath.Join("servers", "slapd", "overlays", "seqmod.c"),
			hash: "16c56e2543a9759a5da4420aaef72e5e67e856bfd695a375495fdb70a22f975e",
		},
		{
			path: filepath.Join("servers", "slapd", "backover.c"),
			hash: "3ba5474f376096e9cbd7c6090c23a4227c93ee5b519d03f94396c9a968a2468c",
		},
		{
			path: filepath.Join("servers", "slapd", "bconfig.c"),
			hash: "901a7da3d3b0440ae09799da56682f9083c3b3e4a06117fcd79e02f217e1811b",
		},
		{
			path: filepath.Join("servers", "slapd", "extended.c"),
			hash: "e1deb19c7a9d3c952c5baba565c11e5eddced91e02c972ee1a9345612e50c4dc",
		},
		{
			path: filepath.Join("servers", "slapd", "passwd.c"),
			hash: "56bfb00af72d7802526b9253bef43aa633b2e01f0e6606b48fc88f343769cd4a",
		},
	}
	contents := make(map[string]string, len(sources))
	for _, source := range sources {
		path := filepath.Join(sourceRoot, source.path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", source.path, err)
		}
		got := fmt.Sprintf("%x", sha256.Sum256(data))
		if got != source.hash {
			t.Fatalf("pinned OpenLDAP source %s hash = %s, want %s", source.path, got, source.hash)
		}
		contents[source.path] = string(data)
	}

	seqmod := contents[filepath.Join("servers", "slapd", "overlays", "seqmod.c")]
	assertOpenLDAPSeqmodSourceContains(t, "seqmod.c", seqmod,
		"seqmod.on_bi.bi_flags = SLAPO_BFLAG_SINGLE;",
		"seqmod.on_bi.bi_op_modify = seqmod_op_mod;",
		"seqmod.on_bi.bi_op_modrdn = seqmod_op_mod;",
		"seqmod.on_bi.bi_extended = seqmod_op_extended;",
		"if ( exop_is_write( op )) return seqmod_op_mod( op, rs );",
		"mtp->mt_tail->mt_next = mt;",
		"while ( mtp != mt )",
		"ldap_pvt_thread_yield();",
		"av->avl_data = mt->mt_next;",
	)
	for _, absent := range []string{
		"bi_op_add",
		"bi_op_delete",
		"olcSeqmod",
		"ConfigTable",
		"ConfigOCs",
	} {
		if strings.Contains(seqmod, absent) {
			t.Fatalf("pinned seqmod.c unexpectedly contains %q", absent)
		}
	}

	backover := contents[filepath.Join("servers", "slapd", "backover.c")]
	assertOpenLDAPSeqmodSourceContains(t, "backover.c", backover,
		"if ( on->on_bi.bi_flags & SLAPO_BFLAG_SINGLE )",
		`overlay \"%s\" already in list`,
		"added to head of list and executed in LIFO order",
		"if ( on->on_bi.bi_flags & SLAPO_BFLAG_DISABLED )",
	)

	extended := contents[filepath.Join("servers", "slapd", "extended.c")]
	assertOpenLDAPSeqmodSourceContains(t, "extended.c", extended,
		"op->o_bd = frontendDB;",
		"rs->sr_err = frontendDB->be_extended( op, rs );",
		"op->ore_flags = ext->flags;",
	)
	password := contents[filepath.Join("servers", "slapd", "passwd.c")]
	assertOpenLDAPSeqmodSourceContains(t, "passwd.c", password,
		"rs->sr_err = op->o_bd->be_extended( op, rs );",
		"op->o_tag = LDAP_REQ_MODIFY;",
		"rs->sr_err = op->o_bd->be_modify( op, rs );",
	)

	bconfig := contents[filepath.Join("servers", "slapd", "bconfig.c")]
	assertOpenLDAPSeqmodSourceContains(t, "bconfig.c", bconfig,
		"c->bi->bi_db_close( c->be, &c->reply );",
		"c->bi->bi_flags |= SLAPO_BFLAG_DISABLED;",
		"c->bi->bi_flags &= ~SLAPO_BFLAG_DISABLED;",
		"if ( c->bi->bi_flags & SLAP_DBFLAG_DISABLED )",
	)
	if !strings.Contains(bconfig, "} else {\n\t\t\t\t\tc->bi->bi_flags &= ~SLAPO_BFLAG_DISABLED;\n\t\t\t\t}") {
		t.Fatal("pinned bconfig.c no longer has the seqmod re-enable-without-open risk")
	}
}

func assertOpenLDAPSeqmodSourceContains(
	t *testing.T,
	name,
	contents string,
	expected ...string,
) {
	t.Helper()
	for _, value := range expected {
		if !strings.Contains(contents, value) {
			t.Fatalf("pinned %s lacks %q", name, value)
		}
	}
}

func assertOpenLDAPSeqmodStartupConfiguration(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	for _, test := range []struct {
		name             string
		frontendOverlays []string
		databaseOverlays []string
		wantOK           bool
	}{
		{
			name:             "frontend and database",
			frontendOverlays: []string{"seqmod"},
			databaseOverlays: []string{"seqmod"},
			wantOK:           true,
		},
		{
			name:             "second frontend instance",
			frontendOverlays: []string{"seqmod", "seqmod"},
		},
		{
			name:             "second database instance",
			databaseOverlays: []string{"seqmod", "seqmod"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			databaseDir := filepath.Join(root, "db")
			if err := os.Mkdir(databaseDir, 0o700); err != nil {
				t.Fatalf("create seqmod startup database: %v", err)
			}
			config := openLDAPSeqmodConfiguration(
				tools,
				root,
				databaseDir,
				test.frontendOverlays,
				test.databaseOverlays,
			)
			path := filepath.Join(root, "slapd.conf")
			if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
				t.Fatalf("write seqmod startup configuration: %v", err)
			}
			command := exec.Command(tools.slapd, "-Ttest", "-u", "-f", path)
			output, err := command.CombinedOutput()
			if test.wantOK {
				if err != nil {
					t.Fatalf("valid seqmod startup configuration: %v\n%s", err, output)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), "already in list") {
				t.Fatalf("duplicate seqmod configuration error=%v output=%q", err, output)
			}
		})
	}
}

func assertOpenLDAPSeqmodConfigurationShape(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	server := startOpenLDAPSeqmodDynamicReference(
		t,
		tools,
		[]string{"seqmod"},
		[]string{"seqmod"},
	)
	configuration := bindOverlayReferenceClientWithDN(
		t,
		server.uri,
		"cn=config",
		"configpw",
	)
	defer configuration.Close()

	frontend := openLDAPSeqmodConfigurationEntries(
		t,
		configuration,
		openLDAPSeqmodFrontendDatabaseDN,
	)
	database := openLDAPSeqmodConfigurationEntries(
		t,
		configuration,
		openLDAPSeqmodDataDatabaseDN,
	)
	if len(frontend) != 1 || len(database) != 1 {
		t.Fatalf("startup seqmod entries: frontend=%d database=%d", len(frontend), len(database))
	}
	assertOpenLDAPSeqmodEntryShape(t, frontend[0])
	assertOpenLDAPSeqmodEntryShape(t, database[0])
	assertOpenLDAPSeqmodSchemaHasNoPrivateTypes(t, configuration)

	for _, parent := range []string{
		openLDAPSeqmodFrontendDatabaseDN,
		openLDAPSeqmodDataDatabaseDN,
	} {
		errorCode := overlayLDAPResultCode(
			t,
			configuration.Add(openLDAPSeqmodAddRequest(parent)),
		)
		if errorCode != ldap.LDAPResultOther {
			t.Fatalf("Add(second seqmod under %s) = %d, want %d", parent, errorCode, ldap.LDAPResultOther)
		}
		if entries := openLDAPSeqmodConfigurationEntries(t, configuration, parent); len(entries) != 1 {
			t.Fatalf("failed duplicate under %s left %d seqmod entries", parent, len(entries))
		}
	}
}

func assertOpenLDAPSeqmodOnlineLifecycle(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	server := startOpenLDAPSeqmodDynamicReference(t, tools, nil, nil)
	configuration := bindOverlayReferenceClientWithDN(
		t,
		server.uri,
		"cn=config",
		"configpw",
	)

	databaseDN := addOpenLDAPSeqmodOverlay(
		t,
		configuration,
		openLDAPSeqmodDataDatabaseDN,
	)
	frontendDN := addOpenLDAPSeqmodOverlay(
		t,
		configuration,
		openLDAPSeqmodFrontendDatabaseDN,
	)

	if err := configuration.Del(ldap.NewDelRequest(databaseDN, nil)); err != nil {
		t.Fatalf("Delete(database seqmod): %v", err)
	}
	databaseDN = addOpenLDAPSeqmodOverlay(
		t,
		configuration,
		openLDAPSeqmodDataDatabaseDN,
	)
	if err := configuration.Del(ldap.NewDelRequest(frontendDN, nil)); err != nil {
		t.Fatalf("Delete(frontend seqmod): %v", err)
	}
	frontendDN = addOpenLDAPSeqmodOverlay(
		t,
		configuration,
		openLDAPSeqmodFrontendDatabaseDN,
	)
	if frontendDN == "" {
		t.Fatal("re-added frontend seqmod has an empty DN")
	}

	disable := ldap.NewModifyRequest(databaseDN, nil)
	disable.Replace("olcDisabled", []string{"TRUE"})
	if err := configuration.Modify(disable); err != nil {
		t.Fatalf("disable database seqmod: %v", err)
	}
	assertOpenLDAPSeqmodDisabled(t, configuration, databaseDN, true)

	configuration.Close()
	server.restart(t)
	configuration = bindOverlayReferenceClientWithDN(
		t,
		server.uri,
		"cn=config",
		"configpw",
	)
	defer configuration.Close()

	databaseEntries := openLDAPSeqmodConfigurationEntries(
		t,
		configuration,
		openLDAPSeqmodDataDatabaseDN,
	)
	frontendEntries := openLDAPSeqmodConfigurationEntries(
		t,
		configuration,
		openLDAPSeqmodFrontendDatabaseDN,
	)
	if len(databaseEntries) != 1 || len(frontendEntries) != 1 {
		t.Fatalf("restarted seqmod entries: frontend=%d database=%d", len(frontendEntries), len(databaseEntries))
	}
	databaseDN = databaseEntries[0].DN
	assertOpenLDAPSeqmodDisabled(t, configuration, databaseDN, true)
	assertOpenLDAPSeqmodDisabled(t, configuration, frontendEntries[0].DN, false)

	// OpenLDAP 2.6.13 can clear the disabled flag without reopening seqmod's
	// private state. Delete and re-add is the safe lifecycle path to exercise.
	if err := configuration.Del(ldap.NewDelRequest(databaseDN, nil)); err != nil {
		t.Fatalf("Delete(disabled database seqmod): %v", err)
	}
	databaseDN = addOpenLDAPSeqmodOverlay(
		t,
		configuration,
		openLDAPSeqmodDataDatabaseDN,
	)
	assertOpenLDAPSeqmodDisabled(t, configuration, databaseDN, false)
}

func assertOpenLDAPSeqmodBasicOperationResults(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{"seqmod"},
		"database frontend\noverlay seqmod",
		"",
		"",
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSeqmodDirectory(t, store, true, true, false)
	_, ldapGoAddress, stopLDAPGo := startSeqmodServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopLDAPGo()
	ldapGo := dialLDAPRoot(t, ldapGoAddress)
	defer ldapGo.Close()

	openLDAPOutcome := runOpenLDAPSeqmodBasicOperations(t, openLDAP, openLDAPURI)
	ldapGoOutcome := runOpenLDAPSeqmodBasicOperations(
		t,
		ldapGo,
		"ldap://"+ldapGoAddress,
	)
	if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
		t.Fatalf(
			"seqmod basic operation mismatch:\nOpenLDAP: %#v\nldap-go:  %#v",
			openLDAPOutcome,
			ldapGoOutcome,
		)
	}
	for index, code := range openLDAPOutcome.codes {
		if code != ldap.LDAPResultSuccess {
			t.Fatalf("seqmod basic operation %d result = %d, want success", index, code)
		}
	}
	if openLDAPOutcome.description != "seqmod-basic" {
		t.Fatalf("seqmod basic description = %q", openLDAPOutcome.description)
	}
}

func runOpenLDAPSeqmodBasicOperations(
	t *testing.T,
	client *ldap.Conn,
	uri string,
) openLDAPSeqmodBasicOutcome {
	t.Helper()
	const (
		aliceDN   = "uid=alice,ou=people,dc=example,dc=com"
		addedDN   = "uid=seqmod-basic,ou=people,dc=example,dc=com"
		renamedDN = "uid=seqmod-renamed,ou=people,dc=example,dc=com"
		password  = "seqmod-basic-password"
	)
	var outcome openLDAPSeqmodBasicOutcome

	modify := ldap.NewModifyRequest(aliceDN, nil)
	modify.Replace("description", []string{"seqmod-basic"})
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, client.Modify(modify)))

	_, passwordErr := client.PasswordModify(ldap.NewPasswordModifyRequest(
		aliceDN,
		"",
		password,
	))
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, passwordErr))

	add := ldap.NewAddRequest(addedDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"seqmod-basic"})
	add.Attribute("cn", []string{"Seqmod Basic"})
	add.Attribute("sn", []string{"Basic"})
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, client.Add(add)))
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, client.ModifyDN(
		ldap.NewModifyDNRequest(addedDN, "uid=seqmod-renamed", true, ""),
	)))
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, client.Del(
		ldap.NewDelRequest(renamedDN, nil),
	)))

	search, err := client.Search(ldap.NewSearchRequest(
		aliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, err))
	if err == nil && len(search.Entries) == 1 {
		outcome.description = search.Entries[0].GetAttributeValue("description")
	}

	passwordClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(seqmod password verification): %v", err)
	}
	defer passwordClient.Close()
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(
		t,
		passwordClient.Bind(aliceDN, password),
	))
	return outcome
}

func openLDAPSeqmodConfiguration(
	tools openLDAPReferenceTools,
	root,
	databaseDir string,
	frontendOverlays,
	databaseOverlays []string,
) string {
	lines := []string{
		"include " + filepath.Join(tools.schemaDir, "core.schema"),
		"include " + filepath.Join(tools.schemaDir, "cosine.schema"),
		"include " + filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		"pidfile " + filepath.Join(root, "slapd.pid"),
		"argsfile " + filepath.Join(root, "slapd.args"),
		"",
		"database frontend",
	}
	for _, overlay := range frontendOverlays {
		lines = append(lines, "overlay "+overlay)
	}
	lines = append(lines,
		"",
		"database config",
		`rootdn "cn=config"`,
		"rootpw configpw",
		`access to * by dn.exact="cn=config" manage by * none`,
		"",
		"database mdb",
		"maxsize 1073741824",
		`suffix "dc=example,dc=com"`,
		`rootdn "cn=admin,dc=example,dc=com"`,
		"rootpw secret",
		"directory "+databaseDir,
		"index objectClass eq",
		"access to * by * read",
	)
	for _, overlay := range databaseOverlays {
		lines = append(lines, "overlay "+overlay)
	}
	return strings.Join(lines, "\n") + "\n"
}

type openLDAPSeqmodDynamicReference struct {
	tools     openLDAPReferenceTools
	configDir string
	uri       string
	address   string
	logs      bytes.Buffer
	command   *exec.Cmd
	wait      chan error
}

func startOpenLDAPSeqmodDynamicReference(
	t *testing.T,
	tools openLDAPReferenceTools,
	frontendOverlays,
	databaseOverlays []string,
) *openLDAPSeqmodDynamicReference {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "slapd.d")
	databaseDir := filepath.Join(root, "db")
	for _, path := range []string{configDir, databaseDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create dynamic seqmod path %s: %v", path, err)
		}
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := openLDAPSeqmodConfiguration(
		tools,
		root,
		databaseDir,
		frontendOverlays,
		databaseOverlays,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write dynamic seqmod configuration: %v", err)
	}
	emptyLDIF := filepath.Join(root, "empty.ldif")
	if err := os.WriteFile(emptyLDIF, nil, 0o600); err != nil {
		t.Fatalf("write dynamic seqmod empty LDIF: %v", err)
	}
	command := exec.Command(
		tools.slapadd,
		"-q",
		"-f",
		configPath,
		"-n",
		"1",
		"-l",
		emptyLDIF,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("initialize dynamic seqmod database: %v\n%s", err, output)
	}
	command = exec.Command(
		tools.slapd,
		"-Ttest",
		"-f",
		configPath,
		"-F",
		configDir,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("convert dynamic seqmod configuration: %v\n%s", err, output)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dynamic seqmod port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release dynamic seqmod port: %v", err)
	}
	server := &openLDAPSeqmodDynamicReference{
		tools:     tools,
		configDir: configDir,
		uri:       "ldap://" + address,
		address:   address,
	}
	server.start(t)
	t.Cleanup(func() { server.stop(t) })
	return server
}

func (server *openLDAPSeqmodDynamicReference) start(t *testing.T) {
	t.Helper()
	if server.command != nil {
		t.Fatal("dynamic OpenLDAP seqmod server is already running")
	}
	server.command = exec.Command(
		server.tools.slapd,
		"-F",
		server.configDir,
		"-h",
		server.uri,
		"-d",
		"0",
	)
	server.command.Stdout = &server.logs
	server.command.Stderr = &server.logs
	if err := server.command.Start(); err != nil {
		server.command = nil
		t.Fatalf("start dynamic OpenLDAP seqmod server: %v", err)
	}
	server.wait = make(chan error, 1)
	go func(command *exec.Cmd, wait chan<- error) {
		wait <- command.Wait()
	}(server.command, server.wait)

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-server.wait:
			server.command = nil
			server.wait = nil
			t.Fatalf("dynamic OpenLDAP seqmod server exited: %v\n%s", err, openLDAPReferenceLogTail(server.logs.Bytes()))
		default:
		}
		connection, err := net.DialTimeout("tcp", server.address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if time.Now().After(deadline) {
			server.stop(t)
			t.Fatalf("dynamic OpenLDAP seqmod server did not start: %v\n%s", err, openLDAPReferenceLogTail(server.logs.Bytes()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (server *openLDAPSeqmodDynamicReference) stop(t *testing.T) {
	t.Helper()
	if server.command == nil {
		return
	}
	command := server.command
	wait := server.wait
	server.command = nil
	server.wait = nil
	if command.Process != nil {
		_ = command.Process.Signal(os.Interrupt)
	}
	select {
	case <-wait:
		return
	case <-time.After(5 * time.Second):
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		<-wait
		t.Errorf("dynamic OpenLDAP seqmod server required forced shutdown\n%s", openLDAPReferenceLogTail(server.logs.Bytes()))
	}
}

func (server *openLDAPSeqmodDynamicReference) restart(t *testing.T) {
	t.Helper()
	server.stop(t)
	server.logs.WriteString("\n--- restart ---\n")
	server.start(t)
}

func openLDAPSeqmodAddRequest(parent string) *ldap.AddRequest {
	request := ldap.NewAddRequest("olcOverlay=seqmod,"+parent, nil)
	request.Attribute("objectClass", []string{"olcOverlayConfig"})
	request.Attribute("olcOverlay", []string{"seqmod"})
	return request
}

func addOpenLDAPSeqmodOverlay(
	t *testing.T,
	configuration *ldap.Conn,
	parent string,
) string {
	t.Helper()
	if err := configuration.Add(openLDAPSeqmodAddRequest(parent)); err != nil {
		t.Fatalf("Add(seqmod under %s): %v", parent, err)
	}
	entries := openLDAPSeqmodConfigurationEntries(t, configuration, parent)
	if len(entries) != 1 {
		t.Fatalf("seqmod entries under %s = %d, want 1", parent, len(entries))
	}
	assertOpenLDAPSeqmodEntryShape(t, entries[0])
	return entries[0].DN
}

func openLDAPSeqmodConfigurationEntries(
	t *testing.T,
	configuration *ldap.Conn,
	parent string,
) []*ldap.Entry {
	t.Helper()
	result, err := configuration.Search(ldap.NewSearchRequest(
		parent,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olcOverlayConfig)",
		[]string{"*", "+"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(seqmod configuration under %s): %v", parent, err)
	}
	entries := make([]*ldap.Entry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		values := entry.GetAttributeValues("olcOverlay")
		if len(values) == 1 && openLDAPSeqmodOverlayType(values[0]) == "seqmod" {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].DN < entries[right].DN
	})
	return entries
}

func openLDAPSeqmodOverlayType(value string) string {
	if strings.HasPrefix(value, "{") {
		if end := strings.IndexByte(value, '}'); end >= 0 {
			value = value[end+1:]
		}
	}
	return strings.ToLower(value)
}

func assertOpenLDAPSeqmodEntryShape(t *testing.T, entry *ldap.Entry) {
	t.Helper()
	if values := entry.GetAttributeValues("olcOverlay"); len(values) != 1 || openLDAPSeqmodOverlayType(values[0]) != "seqmod" {
		t.Fatalf("seqmod entry %s olcOverlay = %q", entry.DN, values)
	}
	if !openLDAPSeqmodContainsFold(entry.GetAttributeValues("objectClass"), "olcOverlayConfig") {
		t.Fatalf("seqmod entry %s objectClass = %q", entry.DN, entry.GetAttributeValues("objectClass"))
	}
	for _, attribute := range entry.Attributes {
		if strings.HasPrefix(strings.ToLower(attribute.Name), "olcseqmod") {
			t.Fatalf("seqmod entry %s exposes private attribute %s", entry.DN, attribute.Name)
		}
	}
}

func assertOpenLDAPSeqmodSchemaHasNoPrivateTypes(
	t *testing.T,
	configuration *ldap.Conn,
) {
	t.Helper()
	result, err := configuration.Search(ldap.NewSearchRequest(
		"cn=schema,cn=config",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olcSchemaConfig)",
		[]string{"olcAttributeTypes", "olcObjectClasses"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(seqmod private schema): %v", err)
	}
	for _, entry := range result.Entries {
		for _, attribute := range entry.Attributes {
			for _, value := range attribute.Values {
				if strings.Contains(strings.ToLower(value), "olcseqmod") {
					t.Fatalf("OpenLDAP config schema exposes seqmod private type: %s", value)
				}
			}
		}
	}
}

func assertOpenLDAPSeqmodDisabled(
	t *testing.T,
	configuration *ldap.Conn,
	dn string,
	want bool,
) {
	t.Helper()
	result, err := configuration.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcDisabled"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search(olcDisabled on %s) entries=%d err=%v", dn, len(result.Entries), err)
	}
	values := result.Entries[0].GetAttributeValues("olcDisabled")
	if want {
		if len(values) != 1 || !strings.EqualFold(values[0], "TRUE") {
			t.Fatalf("olcDisabled on %s = %q, want TRUE", dn, values)
		}
		return
	}
	if len(values) != 0 && !(len(values) == 1 && strings.EqualFold(values[0], "FALSE")) {
		t.Fatalf("olcDisabled on %s = %q, want absent or FALSE", dn, values)
	}
}

func openLDAPSeqmodContainsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
