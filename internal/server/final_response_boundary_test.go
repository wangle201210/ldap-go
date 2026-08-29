package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestExtendedTerminalResponsesBeginTrackedFinalResponse(t *testing.T) {
	server := &Server{}
	runtime := &runtimeState{}
	tests := []struct {
		name    string
		request ldapwire.ExtendedRequest
		handle  func(net.Conn, *connectionState, ldapwire.Message, ldapwire.ExtendedRequest) error
	}{
		{
			name:    "unsupported extended operation",
			request: ldapwire.ExtendedRequest{Name: "1.3.6.1.4.1.4203.666.99"},
			handle: func(connection net.Conn, state *connectionState, message ldapwire.Message, request ldapwire.ExtendedRequest) error {
				return server.handleExtended(t.Context(), connection, state, message, request)
			},
		},
		{
			name: "StartTLS protocol rejection",
			request: ldapwire.ExtendedRequest{
				Name:     startTLSOID,
				HasValue: true,
			},
			handle: func(connection net.Conn, state *connectionState, message ldapwire.Message, request ldapwire.ExtendedRequest) error {
				return server.handleStartTLS(t.Context(), connection, state, message, request)
			},
		},
		{
			name:    "Who Am I success",
			request: ldapwire.ExtendedRequest{Name: whoAmIOID},
			handle:  server.handleWhoAmI,
		},
		{
			name:    "online backup unavailable",
			request: ldapwire.ExtendedRequest{Name: onlineBackupOID},
			handle: func(connection net.Conn, state *connectionState, message ldapwire.Message, request ldapwire.ExtendedRequest) error {
				return server.handleOnlineBackup(t.Context(), connection, state, message, request)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := ldapwire.Message{ID: 7, Request: test.request}
			connection, operation, transport := newFinalResponseBoundaryConnection(t, message)
			defer operation.finish()

			err := test.handle(connection, &connectionState{runtime: runtime}, message, test.request)
			if err != nil {
				t.Fatalf("terminal response: %v", err)
			}
			if transport.Len() == 0 {
				t.Fatal("terminal response was not written")
			}
			assertOperationPhase(t, operation, operationFinalizing)
		})
	}
}

func TestRetcodeSyntheticSearchDoneBeginsTrackedFinalResponse(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	server := &Server{config: Config{Store: store}}
	message := ldapwire.Message{ID: 9, Request: ldapwire.SearchRequest{}}
	connection, operation, transport := newFinalResponseBoundaryConnection(t, message)
	defer operation.finish()

	err := server.writeRetcodeSyntheticSearch(
		t.Context(),
		connection,
		&connectionState{runtime: &runtimeState{}},
		message.ID,
		message.Request.(ldapwire.SearchRequest),
		retcodeRuntimeConfiguration{},
	)
	if err != nil {
		t.Fatalf("writeRetcodeSyntheticSearch(): %v", err)
	}
	if transport.Len() == 0 {
		t.Fatal("SearchResultDone was not written")
	}
	assertOperationPhase(t, operation, operationFinalizing)
}

func TestStartTLSSuccessFinalizesBeforeHandshake(t *testing.T) {
	message := ldapwire.Message{
		ID:      11,
		Request: ldapwire.ExtendedRequest{Name: startTLSOID},
	}
	connection, operation, transport := newFinalResponseBoundaryConnection(t, message)
	defer operation.finish()
	secureTransport := &finalResponseBoundarySecureTransport{
		operation: operation,
		response:  transport,
	}
	server := &Server{
		secureTransport:  secureTransport,
		handshakeLimiter: newResourceLimiter(1),
	}
	state := &connectionState{
		connection: transport,
		runtime:    &runtimeState{},
	}

	err := server.handleStartTLS(
		t.Context(),
		connection,
		state,
		message,
		message.Request.(ldapwire.ExtendedRequest),
	)
	if err != nil {
		t.Fatalf("handleStartTLS(): %v", err)
	}
	if !secureTransport.called {
		t.Fatal("secure handshake was not called")
	}
	if !state.secure {
		t.Fatal("connection was not marked secure")
	}
}

func TestOnlineBackupTerminalResponseUsesResultCapture(t *testing.T) {
	server := &Server{}
	capture := &transactionResultCapture{}
	message := ldapwire.Message{
		ID:      13,
		Request: ldapwire.ExtendedRequest{Name: onlineBackupOID},
	}
	err := server.handleOnlineBackup(
		t.Context(),
		capture,
		&connectionState{runtime: &runtimeState{}},
		message,
		message.Request.(ldapwire.ExtendedRequest),
	)
	if err != nil {
		t.Fatalf("handleOnlineBackup(): %v", err)
	}
	if capture.response == nil {
		t.Fatal("online backup response was not captured")
	}
	if capture.response.responseTag != ldapwire.ApplicationExtendedResponse ||
		capture.response.responseName != onlineBackupOID ||
		capture.response.result.Code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf("captured online backup response = %#v", capture.response)
	}
}

type finalResponseBoundaryConnection struct {
	bytes.Buffer
	operation *trackedOperation
}

func newFinalResponseBoundaryConnection(
	t *testing.T,
	message ldapwire.Message,
) (*operationResponseConnection, *trackedOperation, *finalResponseBoundaryConnection) {
	t.Helper()
	operation := newTrackedOperation(context.Background(), message)
	if !operation.start() {
		t.Fatal("start tracked operation failed")
	}
	transport := &finalResponseBoundaryConnection{operation: operation}
	return &operationResponseConnection{
		Conn:      transport,
		operation: operation,
	}, operation, transport
}

func (connection *finalResponseBoundaryConnection) Write(value []byte) (int, error) {
	connection.operation.mu.Lock()
	phase := connection.operation.phase
	connection.operation.mu.Unlock()
	if phase != operationFinalizing {
		return 0, errors.New("terminal response reached transport before finalization")
	}
	return connection.Buffer.Write(value)
}

func (*finalResponseBoundaryConnection) Read([]byte) (int, error) { return 0, io.EOF }
func (*finalResponseBoundaryConnection) Close() error             { return nil }
func (*finalResponseBoundaryConnection) LocalAddr() net.Addr {
	return finalResponseBoundaryAddress("local")
}
func (*finalResponseBoundaryConnection) RemoteAddr() net.Addr {
	return finalResponseBoundaryAddress("remote")
}
func (*finalResponseBoundaryConnection) SetDeadline(time.Time) error      { return nil }
func (*finalResponseBoundaryConnection) SetReadDeadline(time.Time) error  { return nil }
func (*finalResponseBoundaryConnection) SetWriteDeadline(time.Time) error { return nil }

type finalResponseBoundaryAddress string

func (address finalResponseBoundaryAddress) Network() string { return "tcp" }
func (address finalResponseBoundaryAddress) String() string  { return string(address) }

type finalResponseBoundarySecureTransport struct {
	operation *trackedOperation
	response  *finalResponseBoundaryConnection
	called    bool
}

func (transport *finalResponseBoundarySecureTransport) ServerHandshake(
	_ context.Context,
	connection net.Conn,
) (net.Conn, error) {
	if transport.response.Len() == 0 {
		return nil, errors.New("StartTLS handshake began before the success response")
	}
	transport.operation.mu.Lock()
	phase := transport.operation.phase
	transport.operation.mu.Unlock()
	if phase != operationFinalizing {
		return nil, errors.New("StartTLS handshake began before operation finalization")
	}
	transport.called = true
	return connection, nil
}

func assertOperationPhase(t *testing.T, operation *trackedOperation, want operationPhase) {
	t.Helper()
	operation.mu.Lock()
	got := operation.phase
	operation.mu.Unlock()
	if got != want {
		t.Fatalf("tracked operation phase = %d, want %d", got, want)
	}
}
