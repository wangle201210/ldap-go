package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPGoDeltaSyncreplConsumesOpenLDAPAccesslog(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	providerURI, stopProvider := startOpenLDAPAccesslogProvider(t, tools)
	defer stopProvider()
	provider, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("dial OpenLDAP accesslog provider: %v", err)
	}
	defer provider.Close()
	if err := provider.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		t.Fatalf("bind OpenLDAP accesslog provider: %v", err)
	}
	seedOpenLDAPAccesslogData(t, provider)

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedOpenLDAPAccesslogConsumer(
		t,
		consumerStore,
		strings.TrimPrefix(providerURI, "ldap://"),
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer func() {
		if stopConsumer != nil {
			stopConsumer()
		}
	}()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice",
	)

	online := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	online.Replace("cn", []string{"Alice Delta"})
	if err := provider.Modify(online); err != nil {
		t.Fatalf("modify OpenLDAP provider online: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Delta",
	)

	consumer.Close()
	stopConsumer()
	stopConsumer = nil
	deleteConsumerEntry(
		t,
		consumerStore,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	offline := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	offline.Replace("cn", []string{"Alice Recovered"})
	if err := provider.Modify(offline); err != nil {
		t.Fatalf("modify OpenLDAP provider offline: %v", err)
	}
	if err := provider.Add(newPersonAddRequest("bob")); err != nil {
		t.Fatalf("add OpenLDAP provider bob: %v", err)
	}

	consumerAddress, stopConsumer = startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	consumer = dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Recovered",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"uid",
		"bob",
	)

	rename := ldap.NewModifyDNRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"uid=renamed",
		true,
		"",
	)
	if err := provider.ModifyDN(rename); err != nil {
		t.Fatalf("rename OpenLDAP provider bob: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=renamed,ou=people,dc=example,dc=com",
		"uid",
		"renamed",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
	)
	if err := provider.Del(ldap.NewDelRequest(
		"uid=renamed,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("delete OpenLDAP provider renamed: %v", err)
	}
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=renamed,ou=people,dc=example,dc=com",
	)
}

func TestSyncConsumerAccesslogAppliesOperationsAtomically(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values:      stringValues("top", "domain"),
				},
				{Description: "dc", Values: stringValues("example")},
				{
					Description: "entryUUID",
					Values: stringValues(
						"00000000-0000-0000-0000-000000000001",
					),
				},
			},
		},
		{
			DN: "ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values: stringValues(
						"top",
						"organizationalUnit",
					),
				},
				{Description: "ou", Values: stringValues("people")},
				{
					Description: "entryUUID",
					Values: stringValues(
						"00000000-0000-0000-0000-000000000002",
					),
				},
			},
		},
	})

	addCSN := "20260730020101.000001Z#000000#001#000000"
	addCookie := syncConsumerAccesslogTestCookie(addCSN)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260730020101.000001Z,cn=log",
			"uid=alice,ou=people,dc=example,dc=com",
			"add",
			addCSN,
			[]string{
				"objectClass:+ top",
				"objectClass:+ person",
				"objectClass:+ organizationalPerson",
				"objectClass:+ inetOrgPerson",
				"uid:+ alice",
				"cn:+ Alice",
				"sn:+ Example",
				"uidNumber:+ 10",
				"entryUUID:+ 11111111-2222-3333-4444-555555555555",
				"entryCSN:+ " + addCSN,
			},
			nil,
		),
		addCookie,
	); err != nil {
		t.Fatalf("apply accesslog add: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice",
	)
	assertSyncConsumerCookie(t, store, config, addCookie)

	modifyCSN := "20260730020102.000001Z#000000#001#000000"
	modifyCookie := syncConsumerAccesslogTestCookie(modifyCSN)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260730020102.000001Z,cn=log",
			"uid=alice,ou=people,dc=example,dc=com",
			"modify",
			modifyCSN,
			[]string{
				"cn:= Alice Delta",
				"description:+ first",
				":",
				"description:+ second",
				"uidNumber:# 5",
				"entryCSN:= " + modifyCSN,
			},
			nil,
		),
		modifyCookie,
	); err != nil {
		t.Fatalf("apply accesslog modify: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice Delta",
	)
	assertSyncConsumerEntryValues(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"description",
		[]string{"first", "second"},
	)
	assertSyncConsumerEntryValues(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"uidNumber",
		[]string{"15"},
	)

	renameCSN := "20260730020103.000001Z#000000#001#000000"
	renameCookie := syncConsumerAccesslogTestCookie(renameCSN)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260730020103.000001Z,cn=log",
			"uid=alice,ou=people,dc=example,dc=com",
			"modrdn",
			renameCSN,
			[]string{"entryCSN:= " + renameCSN},
			map[string][]string{
				"reqNewRDN":       {"uid=renamed"},
				"reqDeleteOldRDN": {"TRUE"},
			},
		),
		renameCookie,
	); err != nil {
		t.Fatalf("apply accesslog modrdn: %v", err)
	}
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=renamed,ou=people,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice Delta",
	)

	deleteCSN := "20260730020104.000001Z#000000#001#000000"
	deleteCookie := syncConsumerAccesslogTestCookie(deleteCSN)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260730020104.000001Z,cn=log",
			"uid=renamed,ou=people,dc=example,dc=com",
			"delete",
			deleteCSN,
			nil,
			nil,
		),
		deleteCookie,
	); err != nil {
		t.Fatalf("apply accesslog delete: %v", err)
	}
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=renamed,ou=people,dc=example,dc=com",
	)
	assertSyncConsumerCookie(t, store, config, deleteCookie)
}

func TestSyncConsumerAccesslogGapRollsBackOperationAndCookie(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	initialCSN := "20260730020201.000001Z#000000#001#000000"
	initialCookie := syncConsumerAccesslogTestCookie(initialCSN)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return updateSyncConsumerCookie(writer, config, initialCookie)
	}); err != nil {
		t.Fatalf("seed accesslog cookie: %v", err)
	}

	nextCSN := "20260730020202.000001Z#000000#001#000000"
	err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260730020202.000001Z,cn=log",
			"uid=missing,dc=example,dc=com",
			"modify",
			nextCSN,
			[]string{"cn:= Missing", "entryCSN:= " + nextCSN},
			nil,
		),
		syncConsumerAccesslogTestCookie(nextCSN),
	)
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("missing target error = %v", err)
	}
	assertSyncConsumerCookie(t, store, config, initialCookie)
}

func TestSyncConsumerAccesslogSkipsAlreadyAppliedCSN(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	csn := "20260730020301.000001Z#000000#001#000000"
	cookie := syncConsumerAccesslogTestCookie(csn)
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		syncConsumerTestEntry(
			"uid=alice,dc=example,dc=com",
			"11111111-2222-3333-4444-555555555555",
			"Current",
		),
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return updateSyncConsumerCookie(writer, config, cookie)
	}); err != nil {
		t.Fatalf("seed accesslog cookie: %v", err)
	}

	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		config,
		syncConsumerAccesslogTestEntry(
			"reqStart=20260730020301.000001Z,cn=log",
			"uid=alice,dc=example,dc=com",
			"modify",
			csn,
			[]string{"cn:= Stale Replay"},
			nil,
		),
		cookie,
	); err != nil {
		t.Fatalf("replay accesslog operation: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Current",
	)
}

func syncConsumerAccesslogTestEntry(
	dn,
	targetDN,
	requestType,
	csn string,
	modifications []string,
	extra map[string][]string,
) *ldap.Entry {
	attributes := map[string][]string{
		"objectClass": {"auditWriteObject"},
		"reqDN":       {targetDN},
		"reqType":     {requestType},
		"reqResult":   {"0"},
		"entryCSN":    {csn},
	}
	if len(modifications) > 0 {
		attributes["reqMod"] = modifications
	}
	for description, values := range extra {
		attributes[description] = values
	}
	return ldap.NewEntry(dn, attributes)
}

func syncConsumerAccesslogTestCookie(csn string) []byte {
	return []byte("rid=001,csn=" + csn)
}

func assertSyncConsumerEntryValues(
	t *testing.T,
	store storage.Store,
	partition,
	rawDN,
	description string,
	want []string,
) {
	t.Helper()
	dn := mustSyncConsumerDN(t, rawDN)
	var values [][]byte
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(partition, dn)
		if err != nil {
			return err
		}
		values = entry.Values(description)
		return nil
	}); err != nil {
		t.Fatalf("read %s: %v", rawDN, err)
	}
	got := make([]string, len(values))
	for index := range values {
		got[index] = string(values[index])
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s %s = %q, want %q", rawDN, description, got, want)
	}
}

func startOpenLDAPAccesslogProvider(
	t *testing.T,
	tools openLDAPReferenceTools,
) (string, func()) {
	t.Helper()
	return startOpenLDAPAccesslogProviderWithOptions(t, tools, "")
}

func startOpenLDAPAccesslogProviderWithOptions(
	t *testing.T,
	tools openLDAPReferenceTools,
	options string,
) (string, func()) {
	t.Helper()
	return startOpenLDAPAccesslogProviderWithConfiguration(
		t,
		tools,
		"writes",
		true,
		options,
	)
}

func startOpenLDAPAccesslogProviderWithConfiguration(
	t *testing.T,
	tools openLDAPReferenceTools,
	operations string,
	successOnly bool,
	options string,
) (string, func()) {
	t.Helper()
	root := t.TempDir()
	logDirectory := filepath.Join(root, "log")
	dataDirectory := filepath.Join(root, "data")
	for _, directory := range []string{logDirectory, dataDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create OpenLDAP accesslog directory: %v", err)
		}
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
include %s
include %s
include %s
pidfile %s
argsfile %s

database mdb
maxsize 1073741824
suffix "cn=log"
rootdn "%s"
directory %s
index objectClass,entryCSN,reqResult,reqDN eq
access to *
    by dn.exact="%s" manage
    by * none

overlay syncprov
syncprov-reloadhint true
syncprov-nopresent true

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "%s"
rootpw %s
directory %s
index objectClass,entryUUID,entryCSN eq

access to *
    by * read

overlay syncprov

overlay accesslog
logdb "cn=log"
logops %s
logsuccess %t
%s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(tools.schemaDir, "nis.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		syncTestRootDN,
		logDirectory,
		syncTestRootDN,
		syncTestRootDN,
		syncTestRootPassword,
		dataDirectory,
		operations,
		successOnly,
		options,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP accesslog config: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve OpenLDAP accesslog port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release OpenLDAP accesslog port: %v", err)
	}
	uri := "ldap://" + address
	var logs bytes.Buffer
	command := exec.Command(
		tools.slapd,
		"-f",
		configPath,
		"-h",
		uri,
		"-d",
		"0",
	)
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		t.Fatalf("start OpenLDAP accesslog provider: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- command.Wait()
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if command.Process != nil {
				_ = command.Process.Signal(os.Interrupt)
			}
			select {
			case <-waitDone:
			case <-time.After(5 * time.Second):
				if command.Process != nil {
					_ = command.Process.Kill()
				}
				<-waitDone
			}
		})
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, dialErr := net.DialTimeout(
			"tcp",
			address,
			100*time.Millisecond,
		)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case waitErr := <-waitDone:
			stopOnce.Do(func() {})
			t.Fatalf(
				"OpenLDAP accesslog provider exited during startup: %v\n%s",
				waitErr,
				logs.Bytes(),
			)
		default:
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf(
				"OpenLDAP accesslog provider did not start: %v\n%s",
				dialErr,
				logs.Bytes(),
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return uri, stop
}

func seedOpenLDAPAccesslogData(t *testing.T, provider *ldap.Conn) {
	t.Helper()
	root := ldap.NewAddRequest("dc=example,dc=com", nil)
	root.Attribute("objectClass", []string{"top", "domain"})
	root.Attribute("dc", []string{"example"})
	if err := provider.Add(root); err != nil {
		t.Fatalf("add OpenLDAP accesslog suffix: %v", err)
	}
	people := ldap.NewAddRequest("ou=people,dc=example,dc=com", nil)
	people.Attribute(
		"objectClass",
		[]string{"top", "organizationalUnit"},
	)
	people.Attribute("ou", []string{"people"})
	if err := provider.Add(people); err != nil {
		t.Fatalf("add OpenLDAP accesslog people: %v", err)
	}
	alice := newPersonAddRequest("alice")
	for index := range alice.Attributes {
		if strings.EqualFold(alice.Attributes[index].Type, "cn") {
			alice.Attributes[index].Vals = []string{"Alice"}
		}
	}
	if err := provider.Add(alice); err != nil {
		t.Fatalf("add OpenLDAP accesslog alice: %v", err)
	}
}

func seedOpenLDAPAccesslogConsumer(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	config := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{
				Description: "olcSuffix",
				Values:      stringValues("dc=example,dc=com"),
			},
			{
				Description: "olcSyncrepl",
				Values: stringValues(
					`{0}rid=001 provider=ldap://` + providerAddress +
						` bindmethod=simple binddn="` + syncTestRootDN +
						`" credentials="` + syncTestRootPassword +
						`" searchbase="dc=example,dc=com"` +
						` filter="(objectClass=*)" scope=sub attrs="*,+"` +
						` logbase="cn=log"` +
						` logfilter="(&(objectClass=auditWriteObject)` +
						`(reqResult=0))"` +
						` syncdata=accesslog schemachecking=off` +
						` type=refreshAndPersist retry="1 +"`,
				),
			},
			{
				Description: "olcUpdateRef",
				Values:      stringValues("ldap://" + providerAddress),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(config, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed OpenLDAP accesslog consumer: %v", err)
	}
}

func deleteConsumerEntry(
	t *testing.T,
	store storage.Store,
	rawDN string,
) {
	t.Helper()
	dn := mustSyncConsumerDN(t, rawDN)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Delete(dn)
	}); err != nil {
		t.Fatalf("delete consumer entry %s: %v", rawDN, err)
	}
}
