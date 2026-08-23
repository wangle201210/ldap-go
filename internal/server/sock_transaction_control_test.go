package server

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const sockSuccessResponse = "RESULT\ncode: 0\nmatched:\ninfo:\n\n"

func TestSockBackendTransactionQueueRejectsBeforeUnixSocket(t *testing.T) {
	requireSockRuntimeUnix(t)
	fixture := startSockRuntimeFixture(t, sockRuntimeResponseHandler(sockSuccessResponse))
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoSockReferenceConfiguration(t, store, fixture.path)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		openLDAPSockBindDN,
		openLDAPSockPassword,
	)
	defer connection.Close()
	assertSockRuntimeCommand(t, fixture.take(t), "BIND")

	identifier := startRawLDAPTransaction(t, connection, 2)
	assertNoSockRuntimeRequest(t, fixture)
	entry := sockTransactionTestEntry("queued")
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(entry),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultUnwillingToPerform))
	assertNoSockRuntimeRequest(t, fixture)

	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 4, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
	assertNoSockRuntimeRequest(t, fixture)

	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(t, connection, 5, rawAddRequest(entry)),
		int64(ldapwire.ResultSuccess),
	)
	assertSockRuntimeCommand(t, fixture.take(t), "ADD")
}

func TestSockBackendTransactionCommitGuardRejectsWholeQueue(t *testing.T) {
	suffix, err := directory.ParseDN(openLDAPSockBaseDN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	runtime := &runtimeState{databases: []runtimeDatabase{{
		name:        "{1}sock",
		suffixes:    []directory.DN{suffix},
		sockBackend: &sockBackendRuntimeConfiguration{path: "/must-not-open"},
	}}}
	transaction := &ldapTransaction{
		runtime: runtime,
		operations: []ldapTransactionOperation{
			{
				message: ldapwire.Message{
					ID:      41,
					Request: ldapwire.AddRequest{Entry: sockTransactionTestEntry("first")},
				},
			},
			{
				message: ldapwire.Message{
					ID:      42,
					Request: ldapwire.DeleteRequest{DN: "uid=second," + openLDAPSockBaseDN},
				},
			},
		},
	}
	failure := sockBackendTransactionCommitFailure(transaction)
	if failure == nil || failure.messageID != 41 ||
		failure.result.Code != ldapwire.ResultUnwillingToPerform ||
		failure.result.DiagnosticMessage != sockBackendTransactionDiagnostic {
		t.Fatalf("commit guard failure = %#v", failure)
	}
}

func TestSockBackendCriticalGlobalControlsRejectBeforeUnixSocket(t *testing.T) {
	requireSockRuntimeUnix(t)

	t.Run("critical chaining update", func(t *testing.T) {
		fixture, connection, stop := startSockControlTest(t)
		defer stop()
		defer connection.Close()

		critical := sendRawLDAPOperation(
			t,
			connection,
			2,
			rawAddRequest(sockTransactionTestEntry("critical-chain")),
			rawOIDControl(chainingBehaviorControlOID, true),
		)
		assertRawLDAPResult(
			t,
			critical,
			int64(ldapwire.ResultUnavailableCriticalExtension),
		)
		assertNoSockRuntimeRequest(t, fixture)

		noncritical := sendRawLDAPOperation(
			t,
			connection,
			3,
			rawAddRequest(sockTransactionTestEntry("noncritical-chain")),
			rawOIDControl(chainingBehaviorControlOID, false),
		)
		assertRawLDAPResult(t, noncritical, int64(ldapwire.ResultSuccess))
		request := fixture.take(t)
		assertSockRuntimeCommand(t, request, "ADD")
		if _, found := request.fields["control"]; found {
			t.Fatalf("unsupported control leaked to socket request: %#v", request.fields)
		}
	})

	t.Run("critical password policy Bind", func(t *testing.T) {
		fixture := startSockRuntimeFixture(t, sockRuntimeResponseHandler(sockSuccessResponse))
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedLDAPGoSockReferenceConfiguration(t, store, fixture.path)
		address, stop := startServer(t, store, Config{})
		defer stop()

		connection, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatalf("Dial(): %v", err)
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetDeadline(): %v", err)
		}
		response := sendRawLDAPOperation(
			t,
			connection,
			1,
			rawSimpleBindRequest(openLDAPSockBindDN, openLDAPSockPassword),
			rawOIDControl(passwordPolicyControlOID, true),
		)
		assertRawLDAPResult(
			t,
			response,
			int64(ldapwire.ResultUnavailableCriticalExtension),
		)
		assertNoSockRuntimeRequest(t, fixture)

		assertRawLDAPResult(
			t,
			sendRawLDAPOperation(
				t,
				connection,
				2,
				rawSimpleBindRequest(openLDAPSockBindDN, openLDAPSockPassword),
			),
			int64(ldapwire.ResultSuccess),
		)
		assertSockRuntimeCommand(t, fixture.take(t), "BIND")
	})
}

func TestSockOverlayProtocolReliableSubsetOverUnixSocket(t *testing.T) {
	requireSockRuntimeUnix(t)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command == "ADD" {
			return writeAll(connection, []byte("CONTINUE\n\n"))
		}
		return nil
	})

	connection, err := net.Dial("unix", fixture.path)
	if err != nil {
		t.Fatalf("Dial(unix): %v", err)
	}
	request := SockRequest{
		MessageID: 9,
		Suffixes:  []string{openLDAPSockBaseDN},
		Operation: SockAddRequest{Entry: sockTransactionTestEntry("overlay")},
	}
	if err := WriteSockRequest(connection, request, SockProtocolLimits{}); err != nil {
		connection.Close()
		t.Fatalf("WriteSockRequest(): %v", err)
	}
	response, err := ParseSockOverlayOperationResponse(connection, SockProtocolLimits{})
	_ = connection.Close()
	if err != nil || !response.Continue || len(response.Response.Entries) != 0 {
		t.Fatalf("overlay response = %#v, %v", response, err)
	}
	assertSockRuntimeCommand(t, fixture.take(t), "ADD")

	if _, err := ParseSockResponse(
		strings.NewReader("CONTINUE\n\n"),
		SockProtocolLimits{},
	); err == nil || !strings.Contains(err.Error(), "only valid for a socket overlay") {
		t.Fatalf("database CONTINUE error = %v", err)
	}

	notification := SockRequest{
		MessageID: 10,
		Suffixes:  []string{"must-not-be-emitted"},
		Operation: SockOverlayResultNotification{Result: ldapwire.Result{
			Code:              ldapwire.ResultUnwillingToPerform,
			MatchedDN:         openLDAPSockBaseDN,
			DiagnosticMessage: "blocked",
		}},
	}
	connection, err = net.Dial("unix", fixture.path)
	if err != nil {
		t.Fatalf("Dial(unix notification): %v", err)
	}
	if err := WriteSockRequest(connection, notification, SockProtocolLimits{}); err != nil {
		connection.Close()
		t.Fatalf("WriteSockRequest(notification): %v", err)
	}
	_ = connection.Close()
	captured := fixture.take(t)
	assertSockRuntimeCommand(t, captured, "RESULT")
	if _, found := captured.fields["suffix"]; found {
		t.Fatalf("overlay notification contains database suffix: %#v", captured.fields)
	}
	assertSockRuntimeField(t, captured, "code", "53")
}

func startSockControlTest(
	t *testing.T,
) (*sockRuntimeFixture, net.Conn, func()) {
	t.Helper()
	fixture := startSockRuntimeFixture(t, sockRuntimeResponseHandler(sockSuccessResponse))
	store := storage.NewMemory()
	seedLDAPGoSockReferenceConfiguration(t, store, fixture.path)
	address, stopServer := startServer(t, store, Config{})
	connection := dialAndBindRawLDAP(
		t,
		address,
		openLDAPSockBindDN,
		openLDAPSockPassword,
	)
	assertSockRuntimeCommand(t, fixture.take(t), "BIND")
	stop := func() {
		stopServer()
		_ = store.Close()
	}
	return fixture, connection, stop
}

func sockTransactionTestEntry(name string) directory.Entry {
	return directory.Entry{
		DN: "uid=" + name + "," + openLDAPSockBaseDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(name)},
			{Description: "cn", Values: stringValues(name)},
			{Description: "sn", Values: stringValues(name)},
		},
	}
}

func assertNoSockRuntimeRequest(t *testing.T, fixture *sockRuntimeFixture) {
	t.Helper()
	select {
	case request := <-fixture.requests:
		t.Fatalf("unexpected socket request: %s %#v", request.command, request.fields)
	case err := <-fixture.failures:
		t.Fatalf("socket fixture failed: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
}
