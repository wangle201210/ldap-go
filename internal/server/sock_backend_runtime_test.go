package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	sockRuntimeBaseDN       = "dc=sock-runtime,dc=example"
	sockRuntimeDatabaseDN   = "olcDatabase={1}sock,cn=config"
	sockRuntimeConfigDN     = "cn=config"
	sockRuntimeConfigSecret = "config-secret"
)

func TestSockBackendRuntimeMissingSocket(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	missingPath := filepath.Join(t.TempDir(), "missing.sock")
	seedSockRuntimeConfiguration(t, store, sockRuntimeDatabaseSeed{
		order:  1,
		suffix: sockRuntimeBaseDN,
		path:   missingPath,
	})

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialSockRuntimeClient(t, address)
	defer client.Close()

	_, err := client.Search(sockRuntimeSearchRequest(sockRuntimeBaseDN, "dc"))
	assertSockRuntimeLDAPError(
		t,
		err,
		ldap.LDAPResultOther,
		sockBackendOpenDiagnostic,
	)
}

func TestSockBackendRuntimeRejectsInvalidResponses(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "malformed result",
			response: "RESULT\ncode: invalid\nmatched:\ninfo:\n\n",
		},
		{
			name:     "early EOF",
			response: "RESULT\ncode: 0\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := startSockRuntimeFixture(t, func(
				connection net.Conn,
				request sockRuntimeCapturedRequest,
			) error {
				if request.command == "UNBIND" {
					return nil
				}
				return writeAll(connection, []byte(test.response))
			})
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedSockRuntimeConfiguration(t, store, sockRuntimeDatabaseSeed{
				order:  1,
				suffix: sockRuntimeBaseDN,
				path:   fixture.path,
			})

			address, stop := startServer(t, store, Config{})
			defer stop()
			client := dialSockRuntimeClient(t, address)
			defer client.Close()

			_, err := client.Search(sockRuntimeSearchRequest(sockRuntimeBaseDN, "dc"))
			assertSockRuntimeLDAPError(
				t,
				err,
				ldap.LDAPResultOther,
				sockBackendFailureDiagnostic,
			)
			if request := fixture.take(t); request.command != "SEARCH" {
				t.Fatalf("socket command = %q, want SEARCH", request.command)
			}
		})
	}
}

func TestSockBackendRuntimeSearchAppliesACLProjection(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	allowedDN := "uid=allowed," + sockRuntimeBaseDN
	deniedDN := "uid=denied," + sockRuntimeBaseDN
	response := fmt.Sprintf(`dn: %s
objectClass: inetOrgPerson
uid: allowed
cn: Allowed User
sn: User
description: private value

dn: %s
objectClass: inetOrgPerson
uid: denied
cn: Denied User
sn: User
description: must not escape

RESULT
code: 0
matched:
info:

`, allowedDN, deniedDN)
	fixture := startSockRuntimeFixture(t, sockRuntimeResponseHandler(response))
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockRuntimeConfiguration(t, store, sockRuntimeDatabaseSeed{
		order:  1,
		suffix: sockRuntimeBaseDN,
		path:   fixture.path,
		access: []string{
			`{0}to dn.exact="` + deniedDN + `" by * none`,
			`{1}to attrs=description by * none`,
			`{2}to * by * read`,
		},
	})

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialSockRuntimeClient(t, address)
	defer client.Close()

	result, err := client.Search(sockRuntimeSearchRequest(
		sockRuntimeBaseDN,
		"uid",
		"description",
	))
	if err != nil {
		t.Fatalf("Search(): %v", err)
	}
	if request := fixture.take(t); request.command != "SEARCH" {
		t.Fatalf("socket command = %q, want SEARCH", request.command)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search entries = %d, want 1: %#v", len(result.Entries), result.Entries)
	}
	entry := result.Entries[0]
	if !strings.EqualFold(entry.DN, allowedDN) {
		t.Fatalf("Search entry DN = %q, want %q", entry.DN, allowedDN)
	}
	if got := entry.GetAttributeValue("uid"); got != "allowed" {
		t.Fatalf("uid = %q, want allowed", got)
	}
	if values := entry.GetAttributeValues("description"); len(values) != 0 {
		t.Fatalf("ACL-hidden description values = %q, want none", values)
	}
	if len(entry.Attributes) != 1 {
		t.Fatalf("projected attributes = %#v, want only uid", entry.Attributes)
	}
}

func TestSockBackendRuntimeCancellationClosesSocketAndKeepsLDAPConnection(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	blocked := make(chan chan error, 2)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command == "UNBIND" {
			return nil
		}
		if request.command != "SEARCH" {
			return fmt.Errorf("unexpected blocked socket command %q", request.command)
		}
		closed := make(chan error, 1)
		blocked <- closed
		var buffer [1]byte
		count, err := connection.Read(buffer[:])
		if count != 0 || err == nil {
			return fmt.Errorf("blocked socket Read() = %d, %v; want closure", count, err)
		}
		closed <- err
		return nil
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockRuntimeConfiguration(t, store, sockRuntimeDatabaseSeed{
		order:  1,
		suffix: "dc=example,dc=com",
		path:   fixture.path,
	})

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, "", "")
	defer connection.Close()

	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	assertSockRuntimeCommand(t, fixture.take(t), "SEARCH")
	firstClosed := takeSockRuntimeBlockedConnection(t, fixture, blocked)
	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(cancelOID, ldapwire.EncodeCancelRequestValue(2), true),
		nil,
	)
	waitForSockRuntimeClosure(t, firstClosed)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		2,
		ldapwire.ApplicationSearchResultDone,
		int64(ldap.LDAPResultCanceled),
	)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		3,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
	writeRawLDAPRequest(t, connection, 4, rawExtendedRequest(whoAmIOID, nil, false), nil)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		4,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)

	writeRawLDAPRequest(t, connection, 5, rawCancellationSearch(t), nil)
	assertSockRuntimeCommand(t, fixture.take(t), "SEARCH")
	secondClosed := takeSockRuntimeBlockedConnection(t, fixture, blocked)
	writeRawLDAPRequest(t, connection, 6, rawAbandonRequest(5), nil)
	waitForSockRuntimeClosure(t, secondClosed)
	writeRawLDAPRequest(t, connection, 7, rawExtendedRequest(whoAmIOID, nil, false), nil)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		7,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestSockBackendRuntimeUnbindNotifiesEveryDatabase(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	first := startSockRuntimeFixture(t, sockRuntimeResponseHandler(""))
	second := startSockRuntimeFixture(t, sockRuntimeResponseHandler(""))
	firstSuffix := "dc=first," + sockRuntimeBaseDN
	secondSuffix := "dc=second," + sockRuntimeBaseDN
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockRuntimeConfiguration(
		t,
		store,
		sockRuntimeDatabaseSeed{order: 1, suffix: firstSuffix, path: first.path},
		sockRuntimeDatabaseSeed{order: 2, suffix: secondSuffix, path: second.path},
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialSockRuntimeClient(t, address)
	if err := client.Unbind(); err != nil {
		t.Fatalf("Unbind(): %v", err)
	}

	firstRequest := first.take(t)
	assertSockRuntimeCommand(t, firstRequest, "UNBIND")
	assertSockRuntimeField(t, firstRequest, "suffix", firstSuffix)
	secondRequest := second.take(t)
	assertSockRuntimeCommand(t, secondRequest, "UNBIND")
	assertSockRuntimeField(t, secondRequest, "suffix", secondSuffix)
}

func TestSockBackendRuntimeOnlineConfigurationIsAtomic(t *testing.T) {
	requireSockRuntimeUnix(t)
	t.Parallel()

	response := fmt.Sprintf(`dn: %s
objectClass: domain
dc: sock-runtime

RESULT
code: 0
matched:
info:

`, sockRuntimeBaseDN)
	first := startSockRuntimeFixture(t, sockRuntimeResponseHandler(response))
	second := startSockRuntimeFixture(t, sockRuntimeResponseHandler(response))
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockRuntimeConfiguration(t, store, sockRuntimeDatabaseSeed{
		order:  1,
		suffix: sockRuntimeBaseDN,
		path:   first.path,
	})

	address, stop := startServer(t, store, Config{})
	defer stop()
	dataClient := dialSockRuntimeClient(t, address)
	defer dataClient.Close()
	configClient := dialSockRuntimeClient(t, address)
	defer configClient.Close()
	if err := configClient.Bind(sockRuntimeConfigDN, sockRuntimeConfigSecret); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	if _, err := dataClient.Search(sockRuntimeSearchRequest(sockRuntimeBaseDN, "dc")); err != nil {
		t.Fatalf("Search(initial path): %v", err)
	}
	initial := first.take(t)
	assertSockRuntimeCommand(t, initial, "SEARCH")
	if _, found := initial.fields["connid"]; found {
		t.Fatalf("initial request unexpectedly contains connid: %#v", initial.fields)
	}

	update := ldap.NewModifyRequest(sockRuntimeDatabaseDN, nil)
	update.Replace("olcDbSocketPath", []string{second.path})
	update.Replace("olcDbSocketExtensions", []string{"connid"})
	if err := configClient.Modify(update); err != nil {
		t.Fatalf("Modify(valid back-sock configuration): %v", err)
	}
	if _, err := dataClient.Search(sockRuntimeSearchRequest(sockRuntimeBaseDN, "dc")); err != nil {
		t.Fatalf("Search(updated path): %v", err)
	}
	updated := second.take(t)
	assertSockRuntimeCommand(t, updated, "SEARCH")
	if values := updated.fields["connid"]; len(values) != 1 || values[0] == "" {
		t.Fatalf("updated connid = %q, want one non-empty value", values)
	}

	invalid := ldap.NewModifyRequest(sockRuntimeDatabaseDN, nil)
	invalid.Replace("olcDbSocketPath", []string{first.path})
	invalid.Replace("olcDbSocketExtensions", []string{"unsupported"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	stored := readStoredEntry(t, store, sockRuntimeDatabaseDN)
	assertSockRuntimeStoredValue(t, stored, "olcDbSocketPath", second.path)
	assertSockRuntimeStoredValue(t, stored, "olcDbSocketExtensions", "connid")

	if _, err := dataClient.Search(sockRuntimeSearchRequest(sockRuntimeBaseDN, "dc")); err != nil {
		t.Fatalf("Search(after invalid configuration rollback): %v", err)
	}
	rolledBack := second.take(t)
	assertSockRuntimeCommand(t, rolledBack, "SEARCH")
	if values := rolledBack.fields["connid"]; len(values) != 1 || values[0] == "" {
		t.Fatalf("rolled-back connid = %q, want one non-empty value", values)
	}
}

type sockRuntimeDatabaseSeed struct {
	order      int
	suffix     string
	path       string
	extensions []string
	access     []string
}

func seedSockRuntimeConfiguration(
	t *testing.T,
	store storage.Store,
	databases ...sockRuntimeDatabaseSeed,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues(sockRuntimeConfigDN)},
				{Description: "olcRootPW", Values: stringValues(sockRuntimeConfigSecret)},
				{Description: "olcAccess", Values: stringValues("{0}to * by * none")},
			},
		},
	}
	namingContexts := make([]string, 0, len(databases)+1)
	for _, database := range databases {
		name := fmt.Sprintf("{%d}sock", database.order)
		access := database.access
		if len(access) == 0 {
			access = []string{"{0}to * by * read"}
		}
		attributes := []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("olcDatabaseConfig", "olcDbSocketConfig"),
			},
			{Description: "olcDatabase", Values: stringValues(name)},
			{Description: "olcSuffix", Values: stringValues(database.suffix)},
			{Description: "olcDbSocketPath", Values: stringValues(database.path)},
			{Description: "olcAccess", Values: stringValues(access...)},
		}
		if len(database.extensions) != 0 {
			attributes = append(attributes, directory.Attribute{
				Description: "olcDbSocketExtensions",
				Values:      stringValues(database.extensions...),
			})
		}
		entries = append(entries, directory.Entry{
			DN:         "olcDatabase=" + name + ",cn=config",
			Attributes: attributes,
		})
		namingContexts = append(namingContexts, database.suffix)
	}
	namingContexts = append(namingContexts, "cn=config")
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts(namingContexts)
	}); err != nil {
		t.Fatalf("seed back-sock configuration: %v", err)
	}
}

func dialSockRuntimeClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	client.SetTimeout(3 * time.Second)
	return client
}

func sockRuntimeSearchRequest(baseDN string, attributes ...string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		attributes,
		nil,
	)
}

func assertSockRuntimeLDAPError(
	t *testing.T,
	err error,
	code uint16,
	diagnostic string,
) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("LDAP error = %v, want result code %d", err, code)
	}
	if ldapErr.ResultCode != code {
		t.Fatalf("LDAP result code = %d, want %d: %v", ldapErr.ResultCode, code, err)
	}
	if ldapErr.Err == nil || ldapErr.Err.Error() != diagnostic {
		t.Fatalf("LDAP diagnostic = %v, want %q", ldapErr.Err, diagnostic)
	}
}

func assertSockRuntimeStoredValue(
	t *testing.T,
	entry directory.Entry,
	attribute, want string,
) {
	t.Helper()
	values := entry.Values(attribute)
	if len(values) != 1 || string(values[0]) != want {
		t.Fatalf("stored %s = %q, want %q", attribute, values, want)
	}
}

func requireSockRuntimeUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("back-sock requires Unix-domain sockets")
	}
}

type sockRuntimeCapturedRequest struct {
	command string
	fields  map[string][]string
}

type sockRuntimeFixture struct {
	path        string
	directory   string
	listener    net.Listener
	handler     func(net.Conn, sockRuntimeCapturedRequest) error
	requests    chan sockRuntimeCapturedRequest
	failures    chan error
	acceptDone  chan struct{}
	handlers    sync.WaitGroup
	connections sync.Map
	closeOnce   sync.Once
}

func startSockRuntimeFixture(
	t *testing.T,
	handler func(net.Conn, sockRuntimeCapturedRequest) error,
) *sockRuntimeFixture {
	t.Helper()
	directoryPath, err := os.MkdirTemp("", "ldap-go-sock-runtime-")
	if err != nil {
		t.Fatalf("create socket fixture directory: %v", err)
	}
	path := filepath.Join(directoryPath, "backend.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		_ = os.RemoveAll(directoryPath)
		t.Fatalf("listen on Unix socket %s: %v", path, err)
	}
	fixture := &sockRuntimeFixture{
		path:       path,
		directory:  directoryPath,
		listener:   listener,
		handler:    handler,
		requests:   make(chan sockRuntimeCapturedRequest, 64),
		failures:   make(chan error, 8),
		acceptDone: make(chan struct{}),
	}
	go fixture.serve()
	t.Cleanup(func() {
		fixture.close()
		_ = os.RemoveAll(directoryPath)
	})
	return fixture
}

func (fixture *sockRuntimeFixture) serve() {
	defer close(fixture.acceptDone)
	for {
		connection, err := fixture.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				fixture.report(fmt.Errorf("accept socket request: %w", err))
			}
			return
		}
		fixture.connections.Store(connection, struct{}{})
		fixture.handlers.Add(1)
		go fixture.handle(connection)
	}
}

func (fixture *sockRuntimeFixture) handle(connection net.Conn) {
	defer fixture.handlers.Done()
	defer fixture.connections.Delete(connection)
	defer connection.Close()
	request, err := readSockRuntimeRequest(connection)
	if err != nil {
		fixture.report(err)
		return
	}
	fixture.requests <- request
	if fixture.handler != nil {
		if err := fixture.handler(connection, request); err != nil {
			fixture.report(err)
		}
	}
}

func (fixture *sockRuntimeFixture) report(err error) {
	select {
	case fixture.failures <- err:
	default:
	}
}

func (fixture *sockRuntimeFixture) take(t *testing.T) sockRuntimeCapturedRequest {
	t.Helper()
	select {
	case request := <-fixture.requests:
		return request
	case err := <-fixture.failures:
		t.Fatalf("socket fixture failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for socket request")
	}
	return sockRuntimeCapturedRequest{}
}

func (fixture *sockRuntimeFixture) close() {
	fixture.closeOnce.Do(func() {
		_ = fixture.listener.Close()
		<-fixture.acceptDone
		fixture.connections.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		fixture.handlers.Wait()
	})
}

func readSockRuntimeRequest(connection net.Conn) (sockRuntimeCapturedRequest, error) {
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	physicalLines := make([]string, 0, 32)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			break
		}
		physicalLines = append(physicalLines, line)
	}
	if err := scanner.Err(); err != nil {
		return sockRuntimeCapturedRequest{}, fmt.Errorf("read socket request: %w", err)
	}
	if len(physicalLines) == 0 {
		return sockRuntimeCapturedRequest{}, io.ErrUnexpectedEOF
	}
	logicalLines := make([]string, 0, len(physicalLines))
	for _, line := range physicalLines {
		if strings.HasPrefix(line, " ") {
			if len(logicalLines) == 0 {
				return sockRuntimeCapturedRequest{}, errors.New("orphan socket LDIF continuation")
			}
			logicalLines[len(logicalLines)-1] += strings.TrimPrefix(line, " ")
			continue
		}
		logicalLines = append(logicalLines, line)
	}
	request := sockRuntimeCapturedRequest{
		command: strings.ToUpper(logicalLines[0]),
		fields:  make(map[string][]string),
	}
	for _, line := range logicalLines[1:] {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(name))
		request.fields[key] = append(
			request.fields[key],
			strings.TrimPrefix(value, " "),
		)
	}
	return request, nil
}

func sockRuntimeResponseHandler(
	response string,
) func(net.Conn, sockRuntimeCapturedRequest) error {
	return func(connection net.Conn, request sockRuntimeCapturedRequest) error {
		if request.command == "UNBIND" || response == "" {
			return nil
		}
		return writeAll(connection, []byte(response))
	}
}

func assertSockRuntimeCommand(
	t *testing.T,
	request sockRuntimeCapturedRequest,
	want string,
) {
	t.Helper()
	if request.command != want {
		t.Fatalf("socket command = %q, want %q", request.command, want)
	}
}

func assertSockRuntimeField(
	t *testing.T,
	request sockRuntimeCapturedRequest,
	name, want string,
) {
	t.Helper()
	values := request.fields[name]
	if len(values) != 1 || values[0] != want {
		t.Fatalf("socket field %s = %q, want %q", name, values, want)
	}
}

func takeSockRuntimeBlockedConnection(
	t *testing.T,
	fixture *sockRuntimeFixture,
	blocked <-chan chan error,
) <-chan error {
	t.Helper()
	select {
	case closed := <-blocked:
		return closed
	case err := <-fixture.failures:
		t.Fatalf("socket fixture failed before blocking: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for blocked socket connection")
	}
	return nil
}

func waitForSockRuntimeClosure(t *testing.T, closed <-chan error) {
	t.Helper()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("blocked socket closed without a read error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not close the blocked Unix socket")
	}
}
