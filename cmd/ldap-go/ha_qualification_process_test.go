package main

import (
	"context"
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
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	haQualificationChildEnvironment  = "LDAP_GO_TEST_HA_QUALIFICATION_CHILD"
	haQualificationDBEnvironment     = "LDAP_GO_TEST_HA_QUALIFICATION_DB"
	haQualificationListenEnvironment = "LDAP_GO_TEST_HA_QUALIFICATION_LISTEN"
	haQualificationHeavyEnvironment  = "LDAP_GO_HA_QUALIFICATION_HEAVY"
	haQualificationRootDN            = "cn=admin,dc=ha,dc=test"
	haQualificationRootPassword      = "ha-qualification-secret"
	haQualificationBaseDN            = "dc=ha,dc=test"
	haQualificationPeopleDN          = "ou=people,dc=ha,dc=test"
)

// TestRealProcessHAQualification deliberately uses the test binary as a
// launcher so every node is an independent ldap-go OS process with its own
// bbolt file, sockets, replication worker, and crash boundary.
func TestRealProcessHAQualification(t *testing.T) {
	if os.Getenv(haQualificationChildEnvironment) == "1" {
		exitCode := runMain(
			[]string{
				"serve",
				"-db", os.Getenv(haQualificationDBEnvironment),
				"-listen", os.Getenv(haQualificationListenEnvironment),
				"-root-dn", haQualificationRootDN,
				"-shutdown-timeout", "2s",
				"-log-level", "warn",
			},
			os.Stdin,
			os.Stdout,
			os.Stderr,
			os.Getenv,
		)
		if exitCode != 0 {
			t.Fatalf("HA qualification child exit code = %d", exitCode)
		}
		return
	}

	testDir := t.TempDir()
	providerDB := filepath.Join(testDir, "provider.db")
	consumerDB := filepath.Join(testDir, "consumer.db")
	providerAddress := reserveHAQualificationAddress(t)
	consumerAddress := reserveHAQualificationAddress(t)
	seedHAQualificationProvider(t, providerDB, 2)
	seedHAQualificationConsumer(t, consumerDB, providerAddress)

	provider := startHAQualificationProcess(
		t, "provider-1", providerDB, providerAddress,
	)
	consumer := startHAQualificationProcess(
		t, "consumer-1", consumerDB, consumerAddress,
	)
	consumerClient := dialHAQualificationRoot(t, consumerAddress)
	waitHAQualificationReplicationState(t, consumerClient, "healthy")
	waitHAQualificationAttribute(
		t,
		consumerClient,
		"uid=alice,"+haQualificationPeopleDN,
		"cn",
		"Alice Initial",
	)
	waitHAQualificationAttribute(
		t,
		consumerClient,
		"ou=archive,"+haQualificationBaseDN,
		"ou",
		"archive",
	)
	consumerClient.Close()

	// A hard consumer crash must leave both replicated entries and its cookie
	// durable. The cookie is inspected only after Wait releases the bbolt lock.
	consumer.kill(t)
	initialCookie := readHAQualificationCookie(t, consumerDB)
	if len(initialCookie) == 0 {
		t.Fatal("initial syncrepl cookie is empty after consumer SIGKILL")
	}

	providerClient := dialHAQualificationRoot(t, providerAddress)
	gapWrites := 4
	if os.Getenv(haQualificationHeavyEnvironment) == "1" {
		gapWrites = 128
	}
	for index := 0; index < gapWrites; index++ {
		value := fmt.Sprintf("Alice gap write %03d", index)
		modifyHAQualificationAttribute(
			t,
			providerClient,
			"uid=alice,"+haQualificationPeopleDN,
			"description",
			value,
		)
	}
	modifyHAQualificationAttribute(
		t,
		providerClient,
		"ou=archive,"+haQualificationBaseDN,
		"description",
		"modified before delete",
	)
	if err := providerClient.Del(ldap.NewDelRequest(
		"ou=archive,"+haQualificationBaseDN,
		nil,
	)); err != nil {
		t.Fatalf("provider Delete(archive): %v", err)
	}
	bob := ldap.NewAddRequest("uid=bob,"+haQualificationPeopleDN, nil)
	bob.Attribute("objectClass", []string{"inetOrgPerson"})
	bob.Attribute("uid", []string{"bob"})
	bob.Attribute("cn", []string{"Bob After Gap"})
	bob.Attribute("sn", []string{"Gap"})
	if err := providerClient.Add(bob); err != nil {
		t.Fatalf("provider Add(bob): %v", err)
	}
	providerClient.Close()

	// Restarting the provider after overflowing its in-memory session log makes
	// the consumer's persisted cookie older than the provider's replay window.
	// Keep the consumer online while the provider is unavailable to prove retry
	// and reconnect behavior instead of merely testing startup ordering.
	provider.kill(t)
	consumer = startHAQualificationProcess(
		t, "consumer-provider-outage", consumerDB, consumerAddress,
	)
	consumerClient = dialHAQualificationRoot(t, consumerAddress)
	waitHAQualificationReplicationState(t, consumerClient, "retrying")
	assertHAQualificationAttribute(
		t,
		consumerClient,
		"uid=alice,"+haQualificationPeopleDN,
		"cn",
		"Alice Initial",
	)
	assertHAQualificationAttribute(
		t,
		consumerClient,
		"ou=archive,"+haQualificationBaseDN,
		"ou",
		"archive",
	)

	provider = startHAQualificationProcess(
		t, "provider-2", providerDB, providerAddress,
	)
	waitHAQualificationReplicationState(t, consumerClient, "healthy")
	finalDescription := fmt.Sprintf("Alice gap write %03d", gapWrites-1)
	waitHAQualificationAttribute(
		t,
		consumerClient,
		"uid=alice,"+haQualificationPeopleDN,
		"description",
		finalDescription,
	)
	waitHAQualificationAttribute(
		t,
		consumerClient,
		"uid=bob,"+haQualificationPeopleDN,
		"cn",
		"Bob After Gap",
	)
	waitHAQualificationMissing(
		t,
		consumerClient,
		"ou=archive,"+haQualificationBaseDN,
	)

	providerClient = dialHAQualificationRoot(t, providerAddress)
	providerSnapshot := readHAQualificationSnapshot(t, providerClient)
	consumerSnapshot := readHAQualificationSnapshot(t, consumerClient)
	providerClient.Close()
	consumerClient.Close()
	if !reflect.DeepEqual(consumerSnapshot, providerSnapshot) {
		t.Fatalf(
			"provider/consumer did not converge\nprovider: %#v\nconsumer: %#v",
			providerSnapshot,
			consumerSnapshot,
		)
	}

	consumer.kill(t)
	convergedCookie := readHAQualificationCookie(t, consumerDB)
	if len(convergedCookie) == 0 || reflect.DeepEqual(convergedCookie, initialCookie) {
		t.Fatalf(
			"consumer cookie did not durably advance: initial=%q converged=%q",
			initialCookie,
			convergedCookie,
		)
	}
	provider.kill(t)
}

type haQualificationProcess struct {
	command *exec.Cmd
	done    chan error
	logPath string
	stopped bool
}

func startHAQualificationProcess(
	t *testing.T,
	name,
	databasePath,
	listenAddress string,
) *haQualificationProcess {
	t.Helper()
	logPath := filepath.Join(filepath.Dir(databasePath), name+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open %s log: %v", name, err)
	}
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestRealProcessHAQualification$",
		"-test.count=1",
	)
	command.Env = haQualificationEnvironment(map[string]string{
		haQualificationChildEnvironment:  "1",
		haQualificationDBEnvironment:     databasePath,
		haQualificationListenEnvironment: listenAddress,
		rootPasswordEnvironment:          haQualificationRootPassword,
	})
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	if err := logFile.Close(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("close %s parent log: %v", name, err)
	}
	process := &haQualificationProcess{
		command: command,
		done:    make(chan error, 1),
		logPath: logPath,
	}
	go func() {
		process.done <- command.Wait()
	}()
	t.Cleanup(func() { process.cleanup() })
	waitHAQualificationReady(t, process, listenAddress)
	return process
}

func (process *haQualificationProcess) kill(t *testing.T) {
	t.Helper()
	if process == nil || process.stopped {
		return
	}
	if err := process.command.Process.Kill(); err != nil {
		select {
		case <-process.done:
			process.stopped = true
			return
		default:
			t.Fatalf("SIGKILL process: %v; log:\n%s", err, process.log())
		}
	}
	select {
	case <-process.done:
		process.stopped = true
	case <-time.After(5 * time.Second):
		t.Fatalf("process did not exit after SIGKILL; log:\n%s", process.log())
	}
}

func (process *haQualificationProcess) cleanup() {
	if process == nil || process.stopped || process.command.Process == nil {
		return
	}
	_ = process.command.Process.Kill()
	select {
	case <-process.done:
	case <-time.After(5 * time.Second):
	}
	process.stopped = true
}

func (process *haQualificationProcess) log() string {
	encoded, err := os.ReadFile(process.logPath)
	if err != nil {
		return err.Error()
	}
	return string(encoded)
}

func waitHAQualificationReady(
	t *testing.T,
	process *haQualificationProcess,
	address string,
) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
		select {
		case err := <-process.done:
			process.stopped = true
			t.Fatalf(
				"HA process exited before readiness: %v; log:\n%s",
				err,
				process.log(),
			)
		default:
		}
		client, err := dialHAQualification(address)
		if err == nil {
			err = client.Bind(haQualificationRootDN, haQualificationRootPassword)
			client.Close()
		}
		if err == nil {
			return
		}
		lastError = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf(
		"HA process did not become ready at %s: %v; log:\n%s",
		address,
		lastError,
		process.log(),
	)
}

func reserveHAQualificationAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve HA address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release HA address: %v", err)
	}
	return address
}

func haQualificationEnvironment(overrides map[string]string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for key := range overrides {
		keys[key] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if _, replaced := keys[key]; !replaced {
			environment = append(environment, value)
		}
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func seedHAQualificationProvider(t *testing.T, path string, sessionLogSize int) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("open provider database: %v", err)
	}
	defer store.Close()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcServerID", Values: haQualificationValues("1")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: haQualificationValues("{1}mdb")},
				{Description: "olcSuffix", Values: haQualificationValues(haQualificationBaseDN)},
				{Description: "olcLastMod", Values: haQualificationValues("TRUE")},
			},
		},
		{
			DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: haQualificationValues("{0}syncprov")},
				{Description: "olcSpSessionlog", Values: haQualificationValues(fmt.Sprint(sessionLogSize))},
			},
		},
		haQualificationDataEntry(
			haQualificationBaseDN,
			"10000000-0000-4000-8000-000000000001",
			"20260801010101.000001Z#000000#001#000000",
			[]directory.Attribute{
				{Description: "objectClass", Values: haQualificationValues("domain")},
				{Description: "dc", Values: haQualificationValues("ha")},
				{Description: "contextCSN", Values: haQualificationValues("20260801010101.000004Z#000000#001#000000")},
			},
		),
		haQualificationDataEntry(
			haQualificationPeopleDN,
			"10000000-0000-4000-8000-000000000002",
			"20260801010101.000002Z#000000#001#000000",
			[]directory.Attribute{
				{Description: "objectClass", Values: haQualificationValues("organizationalUnit")},
				{Description: "ou", Values: haQualificationValues("people")},
			},
		),
		haQualificationDataEntry(
			"ou=archive,"+haQualificationBaseDN,
			"10000000-0000-4000-8000-000000000003",
			"20260801010101.000003Z#000000#001#000000",
			[]directory.Attribute{
				{Description: "objectClass", Values: haQualificationValues("organizationalUnit")},
				{Description: "ou", Values: haQualificationValues("archive")},
			},
		),
		haQualificationDataEntry(
			"uid=alice,"+haQualificationPeopleDN,
			"10000000-0000-4000-8000-000000000004",
			"20260801010101.000004Z#000000#001#000000",
			[]directory.Attribute{
				{Description: "objectClass", Values: haQualificationValues("inetOrgPerson")},
				{Description: "uid", Values: haQualificationValues("alice")},
				{Description: "cn", Values: haQualificationValues("Alice Initial")},
				{Description: "sn", Values: haQualificationValues("Initial")},
			},
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{haQualificationBaseDN})
	}); err != nil {
		t.Fatalf("seed provider database: %v", err)
	}
}

func seedHAQualificationConsumer(t *testing.T, path, providerAddress string) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("open consumer database: %v", err)
	}
	defer store.Close()
	syncrepl := fmt.Sprintf(
		`{0}rid=001 provider=ldap://%s bindmethod=simple binddn=%q credentials=%q `+
			`searchbase=%q scope=sub filter=%q attrs=%q schemachecking=off `+
			`type=refreshAndPersist retry=%q network-timeout=1 timeout=2`,
		providerAddress,
		haQualificationRootDN,
		haQualificationRootPassword,
		haQualificationBaseDN,
		"(objectClass=*)",
		"*,+",
		"1 +",
	)
	entries := []directory.Entry{
		{DN: "cn=config"},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: haQualificationValues("{1}mdb")},
				{Description: "olcSuffix", Values: haQualificationValues(haQualificationBaseDN)},
				{Description: "olcSyncrepl", Values: haQualificationValues(syncrepl)},
				{Description: "olcUpdateRef", Values: haQualificationValues("ldap://" + providerAddress)},
			},
		},
		{
			DN: "olcDatabase={2}monitor,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: haQualificationValues("olcMonitorConfig")},
				{Description: "olcDatabase", Values: haQualificationValues("{2}monitor")},
				{Description: "olcAccess", Values: haQualificationValues("{0}to * by * read")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{haQualificationBaseDN})
	}); err != nil {
		t.Fatalf("seed consumer database: %v", err)
	}
}

func haQualificationDataEntry(
	dn,
	uuid,
	csn string,
	attributes []directory.Attribute,
) directory.Entry {
	attributes = append(attributes,
		directory.Attribute{Description: "entryUUID", Values: haQualificationValues(uuid)},
		directory.Attribute{Description: "entryCSN", Values: haQualificationValues(csn)},
	)
	return directory.Entry{DN: dn, Attributes: attributes}
}

func haQualificationValues(values ...string) [][]byte {
	encoded := make([][]byte, len(values))
	for index := range values {
		encoded[index] = []byte(values[index])
	}
	return encoded
}

func dialHAQualification(address string) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 250 * time.Millisecond}
	client, err := ldap.DialURL(
		"ldap://"+address,
		ldap.DialWithDialer(dialer),
	)
	if err != nil {
		return nil, err
	}
	client.SetTimeout(2 * time.Second)
	return client, nil
}

func dialHAQualificationRoot(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := dialHAQualification(address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	if err := client.Bind(haQualificationRootDN, haQualificationRootPassword); err != nil {
		client.Close()
		t.Fatalf("bind %s: %v", address, err)
	}
	return client
}

func waitHAQualificationReplicationState(
	t *testing.T,
	client *ldap.Conn,
	want string,
) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	var last []string
	var lastError error
	for time.Now().Before(deadline) {
		result, err := client.Search(ldap.NewSearchRequest(
			"cn=Replication,cn=Monitor",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=monitoredObject)",
			[]string{"monitoredInfo"},
			nil,
		))
		if err == nil && len(result.Entries) == 1 {
			last = result.Entries[0].GetAttributeValues("monitoredInfo")
			for _, value := range last {
				if value == "state="+want {
					return
				}
			}
		} else {
			lastError = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("replication state did not become %q: info=%q error=%v", want, last, lastError)
}

func modifyHAQualificationAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	value string,
) {
	t.Helper()
	request := ldap.NewModifyRequest(dn, nil)
	request.Replace(attribute, []string{value})
	if err := client.Modify(request); err != nil {
		t.Fatalf("Modify(%s, %s): %v", dn, attribute, err)
	}
}

func waitHAQualificationAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	want string,
) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	var value string
	var lastError error
	for time.Now().Before(deadline) {
		value, lastError = readHAQualificationAttribute(client, dn, attribute)
		if lastError == nil && value == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s %s = %q, want %q: %v", dn, attribute, value, want, lastError)
}

func assertHAQualificationAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	want string,
) {
	t.Helper()
	value, err := readHAQualificationAttribute(client, dn, attribute)
	if err != nil || value != want {
		t.Fatalf("%s %s = %q, want %q: %v", dn, attribute, value, want, err)
	}
}

func readHAQualificationAttribute(
	client *ldap.Conn,
	dn,
	attribute string,
) (string, error) {
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{attribute},
		nil,
	))
	if err != nil {
		return "", err
	}
	if len(result.Entries) != 1 {
		return "", fmt.Errorf("search returned %d entries", len(result.Entries))
	}
	return result.Entries[0].GetAttributeValue(attribute), nil
}

func waitHAQualificationMissing(t *testing.T, client *ldap.Conn, dn string) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
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
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) ||
			(err == nil && len(result.Entries) == 0) {
			return
		}
		lastError = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s remained present after convergence: %v", dn, lastError)
}

type haQualificationSnapshotEntry struct {
	DN          string
	UUID        string
	ObjectClass []string
	DC          []string
	OU          []string
	UID         []string
	CN          []string
	SN          []string
	Description []string
}

func readHAQualificationSnapshot(
	t *testing.T,
	client *ldap.Conn,
) []haQualificationSnapshotEntry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		haQualificationBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"entryUUID", "objectClass", "dc", "ou", "uid", "cn", "sn", "description"},
		nil,
	))
	if err != nil {
		t.Fatalf("read HA snapshot: %v", err)
	}
	snapshot := make([]haQualificationSnapshotEntry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		candidate := haQualificationSnapshotEntry{
			DN:          strings.ToLower(entry.DN),
			UUID:        entry.GetAttributeValue("entryUUID"),
			ObjectClass: entry.GetAttributeValues("objectClass"),
			DC:          entry.GetAttributeValues("dc"),
			OU:          entry.GetAttributeValues("ou"),
			UID:         entry.GetAttributeValues("uid"),
			CN:          entry.GetAttributeValues("cn"),
			SN:          entry.GetAttributeValues("sn"),
			Description: entry.GetAttributeValues("description"),
		}
		sort.Strings(candidate.ObjectClass)
		sort.Strings(candidate.DC)
		sort.Strings(candidate.OU)
		sort.Strings(candidate.UID)
		sort.Strings(candidate.CN)
		sort.Strings(candidate.SN)
		sort.Strings(candidate.Description)
		snapshot = append(snapshot, candidate)
	}
	sort.Slice(snapshot, func(left, right int) bool {
		return snapshot[left].DN < snapshot[right].DN
	})
	return snapshot
}

func readHAQualificationCookie(t *testing.T, databasePath string) []byte {
	t.Helper()
	store, err := storage.OpenBoltReadOnly(databasePath)
	if err != nil {
		t.Fatalf("open stopped consumer database: %v", err)
	}
	defer store.Close()
	partition := storage.OpenLDAPDatabasePartition("{1}mdb", nil)
	key := "openldap/syncrepl/cookie/" +
		base64.RawURLEncoding.EncodeToString([]byte(partition)) + "/001"
	var cookie []byte
	err = store.View(context.Background(), func(reader storage.Reader) error {
		var readErr error
		cookie, readErr = reader.Metadata(key)
		return readErr
	})
	if err != nil {
		if errors.Is(err, storage.ErrMetadataNotFound) {
			t.Fatalf("consumer cookie %q was not persisted", key)
		}
		t.Fatalf("read consumer cookie: %v", err)
	}
	return cookie
}
