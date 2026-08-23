package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const sockOverlayRuntimeDN = "olcOverlay={0}sock,olcDatabase={1}mdb,cn=config"

func TestSockOverlayCallbackTimeoutFailsClosedAndConnectionRecovers(t *testing.T) {
	requireSockRuntimeUnix(t)
	var entryCallbacks atomic.Int32
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		switch request.command {
		case "SEARCH":
			return writeAll(connection, []byte("CONTINUE\n\n"))
		case "ENTRY":
			if entryCallbacks.Add(1) == 1 {
				close(blocked)
				<-release
			}
		}
		return nil
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockOverlayRuntimeConfigurationWithTimeout(
		t,
		store,
		fixture.path,
		[]string{"search"},
		[]string{"search", "result"},
		"40ms",
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialSockRuntimeClient(t, address)
	defer client.Close()
	request := ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	)

	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Search(request)
		firstDone <- err
	}()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for blocked ENTRY callback")
	}
	select {
	case err := <-firstDone:
		assertSockRuntimeLDAPError(
			t,
			err,
			ldap.LDAPResultOther,
			sockOverlayFailureDiagnostic,
		)
	case <-time.After(time.Second):
		t.Fatal("callback timeout did not fail the LDAP operation")
	}
	releaseOnce.Do(func() { close(release) })

	result, err := client.Search(request)
	if err != nil {
		t.Fatalf("Search(after callback timeout): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "alice" {
		t.Fatalf("Search(after callback timeout) entries = %#v", result.Entries)
	}
	if got := entryCallbacks.Load(); got != 2 {
		t.Fatalf("ENTRY callbacks = %d, want 2", got)
	}
}

func TestSockOverlayMultipleInstancesPreserveCallbackOrder(t *testing.T) {
	requireSockRuntimeUnix(t)
	events := make(chan string, 16)
	start := func(label string) *sockRuntimeFixture {
		return startSockRuntimeFixture(t, func(
			connection net.Conn,
			request sockRuntimeCapturedRequest,
		) error {
			events <- label + ":" + request.command
			if request.command == "SEARCH" {
				return writeAll(connection, []byte("CONTINUE\n\n"))
			}
			return nil
		})
	}
	first := start("first")
	second := start("second")
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for order, path := range []string{first.path, second.path} {
			if err := writer.Put(sockOverlayRuntimeEntry(
				order,
				path,
				[]string{"search"},
				[]string{"search", "result"},
				"2s",
			), false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed multiple socket overlays: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialSockRuntimeClient(t, address)
	defer client.Close()
	_, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(): %v", err)
	}
	want := []string{
		"first:SEARCH", "second:SEARCH",
		"first:ENTRY", "second:ENTRY",
		"first:RESULT", "second:RESULT",
	}
	for index, expected := range want {
		select {
		case got := <-events:
			if got != expected {
				t.Fatalf("event %d = %q, want %q", index, got, expected)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for event %d (%s)", index, expected)
		}
	}
}

func TestSockOverlayRuntimeContinueAndSearchCallbacks(t *testing.T) {
	requireSockRuntimeUnix(t)
	entryConsumed := make(chan struct{})
	entryReleased := false
	defer func() {
		if !entryReleased {
			close(entryConsumed)
		}
	}()
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		switch request.command {
		case "SEARCH":
			return writeAll(connection, []byte("CONTINUE\n\n"))
		case "ENTRY":
			<-entryConsumed
		}
		return nil
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockOverlayRuntimeConfiguration(
		t,
		store,
		fixture.path,
		[]string{"search"},
		[]string{"search", "result"},
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialSockRuntimeClient(t, address)
	defer client.Close()
	type searchOutcome struct {
		result *ldap.SearchResult
		err    error
	}
	searchDone := make(chan searchOutcome, 1)
	go func() {
		result, err := client.Search(ldap.NewSearchRequest(
			"uid=alice,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"uid"},
			nil,
		))
		searchDone <- searchOutcome{result: result, err: err}
	}()

	request := fixture.take(t)
	assertSockRuntimeCommand(t, request, "SEARCH")
	assertSockRuntimeField(t, request, "base", "uid=alice,ou=people,dc=example,dc=com")
	entry := fixture.take(t)
	assertSockRuntimeCommand(t, entry, "ENTRY")
	assertSockRuntimeField(t, entry, "dn", "uid=alice,ou=people,dc=example,dc=com")
	assertNoSockRuntimeRequest(t, fixture)
	close(entryConsumed)
	entryReleased = true
	final := fixture.take(t)
	assertSockRuntimeCommand(t, final, "RESULT")
	assertSockRuntimeField(t, final, "code", "0")
	outcome := <-searchDone
	if outcome.err != nil {
		t.Fatalf("Search(): %v", outcome.err)
	}
	if len(outcome.result.Entries) != 1 ||
		outcome.result.Entries[0].GetAttributeValue("uid") != "alice" {
		t.Fatalf("Search entries = %#v", outcome.result.Entries)
	}
}

func TestSockOverlayRuntimeResultShortCircuitsLocalBackend(t *testing.T) {
	requireSockRuntimeUnix(t)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command != "COMPARE" {
			return nil
		}
		return writeAll(connection, []byte("RESULT\ncode: 5\nmatched:\ninfo: external decision\n\n"))
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockOverlayRuntimeConfiguration(t, store, fixture.path, []string{"compare"}, nil)
	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialSockRuntimeClient(t, address)
	defer client.Close()

	matched, err := client.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid",
		"alice",
	)
	if err != nil {
		t.Fatalf("Compare(): %v", err)
	}
	if matched {
		t.Fatal("Compare() = true, want socket overlay false result")
	}
	assertSockRuntimeCommand(t, fixture.take(t), "COMPARE")
}

func TestSockOverlayRejectsSASLBindBeforeUnixSocket(t *testing.T) {
	requireSockRuntimeUnix(t)
	fixture := startSockRuntimeFixture(t, func(
		net.Conn,
		sockRuntimeCapturedRequest,
	) error {
		return errors.New("SASL Bind reached socket overlay service")
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
					{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				},
			},
			{
				DN: "olcOverlay={0}sock,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcOvSocketConfig")},
					{Description: "olcOverlay", Values: stringValues("{0}sock")},
					{Description: "olcDbSocketPath", Values: stringValues(fixture.path)},
					{Description: "olcOvSocketOps", Values: stringValues("bind")},
				},
			},
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed frontend socket overlay: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(%s): %v", address, err)
	}
	defer connection.Close()
	request := rawSASLBindRequest("DIGEST-MD5", nil)
	response := sendRawLDAPOperation(t, connection, 1, request)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultAuthMethodNotSupported))
	assertNoSockRuntimeRequest(t, fixture)
}

func TestSockOverlayRuntimeFailClosedAndRejectsTransactions(t *testing.T) {
	requireSockRuntimeUnix(t)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		return writeAll(connection, []byte("CONTINUE\n\n"))
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockOverlayRuntimeConfiguration(
		t,
		store,
		fixture.path,
		[]string{"search", "add"},
		nil,
	)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	client := dialSockRuntimeClient(t, address)
	request := ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		[]ldap.Control{ldap.NewControlPaging(1)},
	)
	_, err := client.Search(request)
	assertSockRuntimeLDAPError(
		t,
		err,
		ldap.LDAPResultUnwillingToPerform,
		"socket overlay protocol cannot represent LDAP controls",
	)
	assertNoSockRuntimeRequest(t, fixture)
	client.Close()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(transactionTestPerson("sock-overlay-transaction")),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultUnwillingToPerform))
	assertNoSockRuntimeRequest(t, fixture)
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 4, false, identifier),
		int64(ldapwire.ResultSuccess),
	)

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	observed := &sockOverlayResponseConnection{
		Conn:      left,
		ctx:       context.Background(),
		server:    &Server{},
		state:     &connectionState{},
		messageID: 7,
		configurations: []sockOverlayRuntimeConfiguration{{
			responses: sockOverlayResponseSearch,
		}},
	}
	encoded := ldapwire.EncodeSearchResultReference(
		7,
		[]string{"ldap://other.example/dc=example"},
		nil,
	)
	writeDone := make(chan error, 1)
	go func() {
		_, err := observed.Write(encoded)
		writeDone <- err
	}()
	failure, err := ber.ReadPacket(right)
	if err != nil {
		t.Fatalf("read fail-closed SearchResultReference response: %v", err)
	}
	assertRawLDAPResult(t, failure, int64(ldapwire.ResultOther))
	if err := <-writeDone; err != nil {
		t.Fatalf("write fail-closed SearchResultReference response: %v", err)
	}
}

func TestSockOverlayOnlineLoadReloadAndRollback(t *testing.T) {
	requireSockRuntimeUnix(t)
	first := startSockRuntimeFixture(t, sockOverlayCompareHandler(ldapwire.ResultCompareFalse))
	second := startSockRuntimeFixture(t, sockOverlayCompareHandler(ldapwire.ResultCompareTrue))
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	configClient := dialSockRuntimeClient(t, address)
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	add := ldap.NewAddRequest(sockOverlayRuntimeDN, nil)
	add.Attribute("objectClass", []string{"olcOverlayConfig", "olcOvSocketConfig"})
	add.Attribute("olcOverlay", []string{"{0}sock"})
	add.Attribute("olcDbSocketPath", []string{first.path})
	add.Attribute("olcOvSocketOps", []string{"compare"})
	if err := configClient.Add(add); err != nil {
		t.Fatalf("Add(sock overlay): %v", err)
	}

	dataClient := dialSockRuntimeClient(t, address)
	defer dataClient.Close()
	matched, err := dataClient.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid",
		"alice",
	)
	if err != nil || matched {
		t.Fatalf("Compare(first overlay) = %t, %v", matched, err)
	}
	assertSockRuntimeCommand(t, first.take(t), "COMPARE")

	modify := ldap.NewModifyRequest(sockOverlayRuntimeDN, nil)
	modify.Replace("olcDbSocketPath", []string{second.path})
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("Modify(sock overlay path): %v", err)
	}
	matched, err = dataClient.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid",
		"alice",
	)
	if err != nil || !matched {
		t.Fatalf("Compare(reloaded overlay) = %t, %v", matched, err)
	}
	assertSockRuntimeCommand(t, second.take(t), "COMPARE")

	invalid := ldap.NewModifyRequest(sockOverlayRuntimeDN, nil)
	invalid.Replace("olcDbSocketPath", []string{first.path})
	invalid.Replace("olcOvSocketDNpat", []string{"["})
	assertLDAPResultCode(t, configClient.Modify(invalid), ldap.LDAPResultConstraintViolation)
	stored := readStoredEntry(t, store, sockOverlayRuntimeDN)
	assertSockRuntimeStoredValue(t, stored, "olcDbSocketPath", second.path)
	if values := stored.Values("olcOvSocketDNpat"); len(values) != 0 {
		t.Fatalf("rolled-back olcOvSocketDNpat = %q", values)
	}
	matched, err = dataClient.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid",
		"alice",
	)
	if err != nil || !matched {
		t.Fatalf("Compare(after rollback) = %t, %v", matched, err)
	}
	assertSockRuntimeCommand(t, second.take(t), "COMPARE")
}

func TestSockOverlayPinnedOpenLDAPSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	if commit := os.Getenv("OPENLDAP_COMMIT"); commit != "" && commit != openLDAPSockReferenceCommit {
		t.Fatalf("OPENLDAP_COMMIT = %q, want %q", commit, openLDAPSockReferenceCommit)
	}
	content, err := os.ReadFile(filepath.Join(
		sourceRoot,
		"servers",
		"slapd",
		"back-sock",
		"config.c",
	))
	if err != nil {
		t.Fatalf("read pinned back-sock/config.c: %v", err)
	}
	source := string(content)
	for _, anchor := range []string{
		"NAME 'olcOvSocketConfig'",
		"NAME 'olcOvSocketOps'",
		"NAME 'olcOvSocketResps'",
		"NAME 'olcOvSocketDNpat'",
		"return SLAP_CB_CONTINUE;",
		`fprintf( fp, "RESULT\n" );`,
		`fprintf( fp, "ENTRY\n" );`,
	} {
		if !strings.Contains(source, anchor) {
			t.Fatalf("pinned OpenLDAP socket overlay source lacks %q", anchor)
		}
	}
}

func seedSockOverlayRuntimeConfiguration(
	t *testing.T,
	store storage.Store,
	path string,
	operations, responses []string,
) {
	seedSockOverlayRuntimeConfigurationWithTimeout(
		t,
		store,
		path,
		operations,
		responses,
		"",
	)
}

func seedSockOverlayRuntimeConfigurationWithTimeout(
	t *testing.T,
	store storage.Store,
	path string,
	operations, responses []string,
	timeout string,
) {
	t.Helper()
	seedOnlineConfiguration(t, store)
	overlay := sockOverlayRuntimeEntry(0, path, operations, responses, timeout)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(overlay, false)
	}); err != nil {
		t.Fatalf("seed socket overlay configuration: %v", err)
	}
}

func sockOverlayRuntimeEntry(
	order int,
	path string,
	operations, responses []string,
	timeout string,
) directory.Entry {
	orderedOverlay := fmt.Sprintf("{%d}sock", order)
	overlay := directory.Entry{
		DN: fmt.Sprintf(
			"olcOverlay=%s,olcDatabase={1}mdb,cn=config",
			orderedOverlay,
		),
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("olcOverlayConfig", "olcOvSocketConfig"),
			},
			{Description: "olcOverlay", Values: stringValues(orderedOverlay)},
			{Description: "olcDbSocketPath", Values: stringValues(path)},
		},
	}
	if len(operations) != 0 {
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcOvSocketOps",
			Values:      stringValues(operations...),
		})
	}
	if len(responses) != 0 {
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcOvSocketResps",
			Values:      stringValues(responses...),
		})
	}
	if timeout != "" {
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcOvSocketCallbackTimeout",
			Values:      stringValues(timeout),
		})
	}
	return overlay
}

func sockOverlayCompareHandler(
	code ldapwire.ResultCode,
) func(net.Conn, sockRuntimeCapturedRequest) error {
	return func(connection net.Conn, request sockRuntimeCapturedRequest) error {
		if request.command != "COMPARE" {
			return errors.New("socket overlay expected COMPARE")
		}
		response := "RESULT\ncode: " + string(rune('0'+code)) + "\nmatched:\ninfo:\n\n"
		return writeAll(connection, []byte(response))
	}
}
