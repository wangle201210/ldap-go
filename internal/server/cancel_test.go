package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPAbandonStopsSearchWithoutResponse(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)

	writeRawLDAPRequest(t, connection, 3, rawAbandonRequest(2), nil)
	writeRawLDAPRequest(t, connection, 4, rawExtendedRequest(whoAmIOID, nil, false), nil)

	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		4,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestLDAPCancelStopsSearchWithRFC3909Responses(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)
	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(
			cancelOID,
			ldapwire.EncodeCancelRequestValue(2),
			true,
		),
		nil,
	)

	searchResponse := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		searchResponse,
		2,
		ldapwire.ApplicationSearchResultDone,
		int64(ldap.LDAPResultCanceled),
	)
	if diagnostic := rawLDAPDiagnostic(searchResponse); diagnostic != "" {
		t.Fatalf("canceled Search diagnostic = %q, want empty", diagnostic)
	}
	cancelResponse := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		cancelResponse,
		3,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
	if len(cancelResponse.Children[1].Children) != 3 {
		t.Fatalf(
			"Cancel response has responseName or responseValue: %#v",
			cancelResponse.Children[1],
		)
	}

	writeRawLDAPRequest(t, connection, 4, rawExtendedRequest(whoAmIOID, nil, false), nil)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		4,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestLDAPCancelRequestFailures(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, "", "")
	defer connection.Close()

	tests := []struct {
		name       string
		messageID  int64
		value      []byte
		hasValue   bool
		want       int64
		diagnostic string
	}{
		{
			name:       "missing request value",
			messageID:  2,
			want:       int64(ldap.LDAPResultProtocolError),
			diagnostic: "no message ID supplied",
		},
		{
			name:       "empty request value",
			messageID:  3,
			value:      []byte{},
			hasValue:   true,
			want:       int64(ldap.LDAPResultProtocolError),
			diagnostic: "empty request data field",
		},
		{
			name:       "malformed request value",
			messageID:  4,
			value:      []byte{0x30, 0x00},
			hasValue:   true,
			want:       int64(ldap.LDAPResultProtocolError),
			diagnostic: "message ID parse failed",
		},
		{
			name:       "unknown operation",
			messageID:  5,
			value:      ldapwire.EncodeCancelRequestValue(99),
			hasValue:   true,
			want:       int64(ldap.LDAPResultNoSuchOperation),
			diagnostic: "message ID not found",
		},
		{
			name:       "Cancel itself",
			messageID:  6,
			value:      ldapwire.EncodeCancelRequestValue(6),
			hasValue:   true,
			want:       int64(ldap.LDAPResultCannotCancel),
			diagnostic: "Cancel operations cannot be canceled",
		},
	}
	for _, test := range tests {
		response := sendRawLDAPOperation(
			t,
			connection,
			test.messageID,
			rawExtendedRequest(cancelOID, test.value, test.hasValue),
		)
		assertRawLDAPEnvelope(
			t,
			response,
			test.messageID,
			ldapwire.ApplicationExtendedResponse,
			test.want,
		)
		if len(response.Children[1].Children) != 3 {
			t.Fatalf("%s response has optional fields: %#v", test.name, response)
		}
		if diagnostic := rawLDAPDiagnostic(response); diagnostic != test.diagnostic {
			t.Fatalf(
				"%s diagnostic = %q, want %q",
				test.name,
				diagnostic,
				test.diagnostic,
			)
		}
	}
}

func TestLDAPCancelCannotCrossConnections(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	searchConnection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer searchConnection.Close()
	cancelConnection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer cancelConnection.Close()

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, searchConnection, 2, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)

	response := sendRawLDAPOperation(
		t,
		cancelConnection,
		3,
		rawExtendedRequest(
			cancelOID,
			ldapwire.EncodeCancelRequestValue(2),
			true,
		),
	)
	assertRawLDAPEnvelope(
		t,
		response,
		3,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultNoSuchOperation),
	)

	writeRawLDAPRequest(t, searchConnection, 3, rawAbandonRequest(2), nil)
	writeRawLDAPRequest(
		t,
		searchConnection,
		4,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, searchConnection),
		4,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestLDAPCancelRejectsPendingSearch(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:                     "cn=admin,dc=example,dc=com",
		RootPassword:               []byte("admin-secret"),
		MaxOperationsPerConnection: 1,
	})
	defer stop()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)
	writeRawLDAPRequest(t, connection, 3, rawCancellationSearch(t), nil)
	writeRawLDAPRequest(
		t,
		connection,
		4,
		rawExtendedRequest(
			cancelOID,
			ldapwire.EncodeCancelRequestValue(3),
			true,
		),
		nil,
	)

	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		4,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultCannotCancel),
	)
	if diagnostic := rawLDAPDiagnostic(response); diagnostic !=
		"too busy for Cancel, try Abandon instead" {
		t.Fatalf("pending Search Cancel diagnostic = %q", diagnostic)
	}

	// Remove the pending Search before releasing the running Search's gate.
	writeRawLDAPRequest(t, connection, 5, rawAbandonRequest(3), nil)
	writeRawLDAPRequest(t, connection, 6, rawAbandonRequest(2), nil)
	writeRawLDAPRequest(t, connection, 7, rawExtendedRequest(whoAmIOID, nil, false), nil)
	assertRawLDAPEnvelope(
		t,
		readRawLDAPPacket(t, connection),
		7,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestTrackedOperationCancelBoundaries(t *testing.T) {
	t.Parallel()

	operations := newOperationRegistry()
	search, ok := operations.register(context.Background(), ldapwire.Message{
		ID:      2,
		Request: ldapwire.SearchRequest{},
	})
	if !ok || !search.start() {
		t.Fatal("register or start Search operation failed")
	}
	if err := search.beginFinalResponse(); err != nil {
		t.Fatalf("beginFinalResponse(): %v", err)
	}
	if _, result := operations.cancel(2); result.Code != ldapwire.ResultTooLate {
		t.Fatalf("finalizing Search Cancel result = %d, want tooLate", result.Code)
	}
	operations.finish(search)

	pendingSearch, ok := operations.register(context.Background(), ldapwire.Message{
		ID:      3,
		Request: ldapwire.SearchRequest{},
	})
	if !ok {
		t.Fatal("register pending Search operation failed")
	}
	if _, result := operations.cancel(3); result.Code != ldapwire.ResultCannotCancel {
		t.Fatalf("pending Search Cancel result = %d, want cannotCancel", result.Code)
	}
	operations.finish(pendingSearch)

	add, ok := operations.register(context.Background(), ldapwire.Message{
		ID:      4,
		Request: ldapwire.AddRequest{},
	})
	if !ok {
		t.Fatal("register Add operation failed")
	}
	if !add.start() {
		t.Fatal("start Add operation failed")
	}
	if _, result := operations.cancel(4); result.Code != ldapwire.ResultSuccess {
		t.Fatalf("Add Cancel result = %d, want success", result.Code)
	}
	operations.finish(add)
}

func TestAbandonSuppressesResponsesAfterInFlightPDU(t *testing.T) {
	t.Parallel()

	client, serverConnection := net.Pipe()
	defer client.Close()
	defer serverConnection.Close()

	underlying := &blockedWriteConnection{
		Conn:    serverConnection,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	operation := newTrackedOperation(context.Background(), ldapwire.Message{
		ID:      2,
		Request: ldapwire.SearchRequest{},
	})
	if !operation.start() {
		t.Fatal("start Search operation failed")
	}
	connection := &operationResponseConnection{
		Conn: &serializedResponseConnection{
			Conn: underlying,
			mu:   &sync.Mutex{},
		},
		operation: operation,
	}

	firstWrite := make(chan error, 1)
	go func() {
		_, err := connection.Write([]byte("complete BER PDU"))
		firstWrite <- err
	}()
	select {
	case <-underlying.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first response did not reach the transport")
	}

	operation.requestAbandon()
	close(underlying.release)
	if err := <-firstWrite; err != nil {
		t.Fatalf("in-flight response Write(): %v", err)
	}
	if _, err := connection.Write([]byte("next entry")); !errors.Is(
		err,
		errOperationStopped,
	) {
		t.Fatalf("next response Write() error = %v, want errOperationStopped", err)
	}
	if err := connection.beginFinalResponse(); !errors.Is(err, errOperationStopped) {
		t.Fatalf("beginFinalResponse() error = %v, want errOperationStopped", err)
	}
	operation.finish()
}

func TestAbandonSuppressesPDUWaitingForConnectionWriteLock(t *testing.T) {
	t.Parallel()

	client, serverConnection := net.Pipe()
	defer client.Close()
	defer serverConnection.Close()
	writeMutex := &sync.Mutex{}
	writeMutex.Lock()
	operation := newTrackedOperation(context.Background(), ldapwire.Message{
		ID:      2,
		Request: ldapwire.SearchRequest{},
	})
	if !operation.start() {
		t.Fatal("start Search operation failed")
	}
	connection := &operationResponseConnection{
		Conn: &serializedResponseConnection{
			Conn: serverConnection,
			mu:   writeMutex,
		},
		operation: operation,
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := connection.Write([]byte("must not be written"))
		done <- err
	}()
	<-started
	time.Sleep(10 * time.Millisecond)
	operation.requestAbandon()
	writeMutex.Unlock()
	if err := <-done; !errors.Is(err, errOperationStopped) {
		t.Fatalf("waiting Write() error = %v, want errOperationStopped", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("PDU waiting on the write lock leaked after Abandon")
	}
	operation.finish()
}

func TestStoppedSearchRemovesOnlyNewVirtualListViews(t *testing.T) {
	t.Parallel()

	existing := &virtualListViewState{contextID: []byte("existing-context")}
	state := connectionState{
		virtualListViews: map[string]*virtualListViewState{
			string(existing.contextID): existing,
		},
	}
	message := ldapwire.Message{
		ID:      2,
		Request: ldapwire.SearchRequest{},
		Controls: []ldapwire.Control{{
			OID: vlvRequestControlOID,
		}},
	}
	snapshot := snapshotSearchSessions(&state, message)
	created := &virtualListViewState{contextID: []byte("created-context")}
	state.virtualListViews[string(created.contextID)] = created

	(&Server{}).clearStoppedSearchState(&state, message, snapshot)
	if len(state.virtualListViews) != 1 ||
		state.virtualListViews[string(existing.contextID)] != existing {
		t.Fatalf("remaining VLV contexts = %#v", state.virtualListViews)
	}
}

func rawCancellationSearch(t *testing.T) *ber.Packet {
	t.Helper()

	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationSearchRequest,
		nil,
		"SearchRequest",
	)
	request.AppendChild(rawOctetString([]byte("dc=example,dc=com")))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(ldap.ScopeWholeSubtree),
		"scope",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(ldap.NeverDerefAliases),
		"derefAliases",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"sizeLimit",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"timeLimit",
	))
	request.AppendChild(ber.NewBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		false,
		"typesOnly",
	))
	filter, err := ldap.CompileFilter("(objectClass=*)")
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	request.AppendChild(filter)
	attributes := ber.NewSequence("attributes")
	attributes.AppendChild(rawOctetString([]byte("dn")))
	request.AppendChild(attributes)
	return request
}

func rawAbandonRequest(messageID int64) *ber.Packet {
	return ber.NewInteger(
		ber.ClassApplication,
		ber.TypePrimitive,
		ldapwire.ApplicationAbandonRequest,
		messageID,
		"AbandonRequest",
	)
}

func rawExtendedRequest(oid string, value []byte, hasValue bool) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationExtendedRequest,
		nil,
		"ExtendedRequest",
	)
	name := ber.Encode(ber.ClassContext, ber.TypePrimitive, 0, nil, "requestName")
	_, _ = name.Data.Write([]byte(oid))
	request.AppendChild(name)
	if hasValue {
		encodedValue := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			1,
			nil,
			"requestValue",
		)
		_, _ = encodedValue.Data.Write(value)
		request.AppendChild(encodedValue)
	}
	return request
}

func readRawLDAPPacket(t *testing.T, connection net.Conn) *ber.Packet {
	t.Helper()
	response, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("read LDAP response: %v", err)
	}
	return response
}

func assertRawLDAPEnvelope(
	t *testing.T,
	response *ber.Packet,
	messageID int64,
	applicationTag uint64,
	resultCode int64,
) {
	t.Helper()
	if response == nil || len(response.Children) < 2 {
		t.Fatalf("malformed LDAP response: %#v", response)
	}
	gotMessageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse response message ID: %v", err)
	}
	operation := response.Children[1]
	if gotMessageID != messageID ||
		operation.ClassType != ber.ClassApplication ||
		uint64(operation.Tag) != applicationTag ||
		len(operation.Children) < 1 {
		t.Fatalf(
			"LDAP response envelope = id %d, operation %#v; want id %d, tag %d",
			gotMessageID,
			operation,
			messageID,
			applicationTag,
		)
	}
	gotResult, err := ber.ParseInt64(operation.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAP result code: %v", err)
	}
	if gotResult != resultCode {
		t.Fatalf("LDAP result code = %d, want %d", gotResult, resultCode)
	}
}

func rawLDAPDiagnostic(response *ber.Packet) string {
	if response == nil ||
		len(response.Children) < 2 ||
		len(response.Children[1].Children) < 3 {
		return ""
	}
	return string(response.Children[1].Children[2].Data.Bytes())
}

type cancelSearchGate struct {
	started chan struct{}
	release chan struct{}
	resumed chan struct{}
	once    sync.Once
	claimed bool
}

func (gate *cancelSearchGate) waitUntilBlocked(t *testing.T) {
	t.Helper()
	select {
	case <-gate.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Search did not reach the storage scan")
	}
}

func (gate *cancelSearchGate) unblock() {
	gate.once.Do(func() {
		close(gate.release)
	})
}

type cancelBlockingStore struct {
	storage.Store

	mu   sync.Mutex
	gate *cancelSearchGate
}

func newCancelBlockingStore(store storage.Store) *cancelBlockingStore {
	return &cancelBlockingStore{Store: store}
}

func (store *cancelBlockingStore) blockNextSearch() *cancelSearchGate {
	store.mu.Lock()
	defer store.mu.Unlock()
	gate := &cancelSearchGate{
		started: make(chan struct{}),
		release: make(chan struct{}),
		resumed: make(chan struct{}),
	}
	store.gate = gate
	return gate
}

func (store *cancelBlockingStore) View(
	ctx context.Context,
	fn func(storage.Reader) error,
) error {
	return store.Store.View(ctx, func(reader storage.Reader) error {
		return fn(&cancelBlockingReader{
			Reader: reader,
			ctx:    ctx,
			store:  store,
		})
	})
}

func (store *cancelBlockingStore) pauseSearch(ctx context.Context) error {
	store.mu.Lock()
	gate := store.gate
	if gate == nil || gate.claimed {
		store.mu.Unlock()
		return nil
	}
	gate.claimed = true
	close(gate.started)
	store.mu.Unlock()

	var err error
	select {
	case <-gate.release:
	case <-ctx.Done():
		err = ctx.Err()
	}

	store.mu.Lock()
	if store.gate == gate {
		store.gate = nil
	}
	close(gate.resumed)
	store.mu.Unlock()
	return err
}

type cancelBlockingReader struct {
	storage.Reader
	ctx   context.Context
	store *cancelBlockingStore
}

func (reader *cancelBlockingReader) ForEach(
	fn func(directory.Entry) error,
) error {
	if err := reader.store.pauseSearch(reader.ctx); err != nil {
		return err
	}
	return reader.Reader.ForEach(fn)
}

func (reader *cancelBlockingReader) ForEachIn(
	partition string,
	fn func(directory.Entry) error,
) error {
	if err := reader.store.pauseSearch(reader.ctx); err != nil {
		return err
	}
	return reader.Reader.ForEachIn(partition, fn)
}

type blockedWriteConnection struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (connection *blockedWriteConnection) Write(value []byte) (int, error) {
	connection.once.Do(func() {
		close(connection.started)
	})
	<-connection.release
	return len(value), nil
}
