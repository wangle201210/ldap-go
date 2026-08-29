package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestSearchResponseBudgetSerializesReservationWithWrite(t *testing.T) {
	t.Parallel()

	transport := &responseBudgetGateConnection{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	operation := newTrackedOperation(context.Background(), ldapwire.Message{
		ID:      1,
		Request: ldapwire.SearchRequest{},
	})
	if !operation.start() {
		t.Fatal("start Search operation failed")
	}
	connection := &operationResponseConnection{
		Conn: &serializedResponseConnection{
			Conn: transport,
			mu:   &sync.Mutex{},
		},
		operation:            operation,
		maximumResponseBytes: 10,
	}

	results := make(chan error, 2)
	go func() {
		_, err := connection.Write(make([]byte, 6))
		results <- err
	}()
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("first response did not reach the transport")
	}
	go func() {
		_, err := connection.Write(make([]byte, 6))
		results <- err
	}()

	// The second writer must reserve its budget before it can wait on the
	// serialized transport lock. Give it a deterministic scheduling window.
	time.Sleep(25 * time.Millisecond)
	close(transport.release)

	var succeeded, limited int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, errSearchResponseLimit):
			limited++
		default:
			t.Fatalf("response Write() error = %v", err)
		}
	}
	if succeeded != 1 || limited != 1 || connection.responseBytes > 10 {
		t.Fatalf(
			"response budget admitted success=%d limited=%d bytes=%d, want 1/1 and <=10",
			succeeded,
			limited,
			connection.responseBytes,
		)
	}
	operation.finish()
}

func TestSearchResponseProcessInFlightBudget(t *testing.T) {
	t.Parallel()

	limiter := newResourceByteLimiter(10)
	reserve := func(size int64) (func(), bool) {
		if !limiter.tryAcquire(size) {
			return nil, false
		}
		return func() { limiter.release(size) }, true
	}
	transport := &responseBudgetGateConnection{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	firstOperation := newTrackedOperation(context.Background(), ldapwire.Message{
		ID: 1, Request: ldapwire.SearchRequest{},
	})
	secondOperation := newTrackedOperation(context.Background(), ldapwire.Message{
		ID: 2, Request: ldapwire.SearchRequest{},
	})
	if !firstOperation.start() || !secondOperation.start() {
		t.Fatal("start Search operations failed")
	}
	first := &operationResponseConnection{
		Conn:      &serializedResponseConnection{Conn: transport, mu: &sync.Mutex{}},
		operation: firstOperation, reserveResponseBytes: reserve,
	}
	secondClient, secondServer := net.Pipe()
	defer secondClient.Close()
	defer secondServer.Close()
	second := &operationResponseConnection{
		Conn:      &serializedResponseConnection{Conn: secondServer, mu: &sync.Mutex{}},
		operation: secondOperation, reserveResponseBytes: reserve,
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := first.Write(make([]byte, 6))
		firstDone <- err
	}()
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("first Search response did not reserve process bytes")
	}
	if _, err := second.Write(make([]byte, 6)); !errors.Is(err, errSearchResponseLimit) {
		t.Fatalf("second Search response error = %v, want limit", err)
	}
	close(transport.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Search response: %v", err)
	}
	if limiter.active.Load() != 0 || limiter.rejected.Load() != 1 {
		t.Fatalf("response limiter active=%d rejected=%d", limiter.active.Load(), limiter.rejected.Load())
	}
	firstOperation.finish()
	secondOperation.finish()
}

func TestPersistentSyncOnlyExemptsCumulativeResponseBudget(t *testing.T) {
	t.Parallel()

	message := ldapwire.Message{
		ID:      1,
		Request: ldapwire.SearchRequest{},
		Controls: []ldapwire.Control{{
			OID:      syncRequestControlOID,
			HasValue: true,
			Value: ldapwire.EncodeSyncRequestValue(ldapwire.SyncRequestValue{
				Mode: ldapwire.SyncRefreshAndPersist,
			}),
		}},
	}
	queued := &queuedOperation{
		message:   message,
		operation: newTrackedOperation(context.Background(), message),
	}
	server := &Server{config: Config{
		MaxSearchResponseBytes: 32,
		MaxResponsePDUBytes:    16,
	}}
	if got := server.searchResponseByteLimit(queued); got != 0 {
		t.Fatalf("persistent Sync cumulative response limit = %d, want unlimited", got)
	}
	if got := server.searchResponsePDULimit(queued); got != 16 {
		t.Fatalf("persistent Sync PDU limit = %d, want 16", got)
	}
	queued.operation.finish()
}

func TestPendingResourceReleaseIsFullyIdempotent(t *testing.T) {
	t.Parallel()

	limiter := newResourceByteLimiter(32)
	if !limiter.tryAcquire(7) {
		t.Fatal("acquire pending bytes failed")
	}
	queue := newOperationQueue(1)
	queued := &queuedOperation{
		retainedBytes: 7,
		releaseRetained: func() {
			limiter.release(7)
		},
	}
	if result := queue.push(queued, 1); result != operationQueuePushed {
		t.Fatalf("queue push = %d", result)
	}
	if popped, ok := queue.pop(); !ok || popped != queued {
		t.Fatalf("queue pop = %#v, %v", popped, ok)
	}
	queue.complete(queued)
	queue.complete(queued)
	if queue.retainedBytes != 0 || limiter.active.Load() != 0 {
		t.Fatalf(
			"idempotent release left queue bytes=%d process bytes=%d",
			queue.retainedBytes,
			limiter.active.Load(),
		)
	}
	queue.close()
}

func TestSearchCandidateAccountingIncludesStructuralMemory(t *testing.T) {
	t.Parallel()

	candidate := searchCandidate{}
	minimum := int64(unsafe.Sizeof(candidate))
	if got := searchCandidateRetainedBytes(candidate); got < minimum {
		t.Fatalf(
			"empty candidate accounting = %d bytes, want at least structural size %d",
			got,
			minimum,
		)
	}
}

func TestSearchEntryReservesBeforeEncoding(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "uid=large,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "description",
			Values:      [][]byte{make([]byte, 4096)},
		}},
	}
	size := ldapwire.SearchResultEntryEncodedSize(1, entry, nil)
	transport := &responseBudgetBufferConnection{}
	server := &Server{
		config:              Config{MaxResponsePDUBytes: size},
		responseByteLimiter: newResourceByteLimiter(size),
	}
	if err := server.writeSearchEntry(transport, 1, entry, nil); err != nil {
		t.Fatalf("writeSearchEntry(exact budget): %v", err)
	}
	if int64(transport.Len()) != size || server.responseByteLimiter.active.Load() != 0 {
		t.Fatalf("encoded=%d retained=%d, want %d/0", transport.Len(), server.responseByteLimiter.active.Load(), size)
	}

	transport.Reset()
	server.responseByteLimiter.maximum = size - 1
	if err := server.writeSearchEntry(transport, 1, entry, nil); !errors.Is(err, errSearchResponseLimit) {
		t.Fatalf("writeSearchEntry(process limit) = %v", err)
	}
	if transport.Len() != 0 || server.responseByteLimiter.active.Load() != 0 {
		t.Fatalf("rejected entry encoded=%d retained=%d", transport.Len(), server.responseByteLimiter.active.Load())
	}
}

func TestPendingMessageAccountingIncludesDecodedHeap(t *testing.T) {
	t.Parallel()

	message := ldapwire.Message{
		ID: 1,
		Request: ldapwire.AddRequest{Entry: directory.Entry{
			DN: "uid=many,dc=example,dc=com",
			Attributes: []directory.Attribute{{
				Description: "description",
				Values:      make([][]byte, 128),
			}},
		}},
		Controls: make([]ldapwire.Control, 64),
	}
	encoded, err := ldapwire.EncodeRequestMessage(message)
	if err != nil {
		t.Fatalf("EncodeRequestMessage(): %v", err)
	}
	if got := ldapMessageRetainedBytes(message, int64(len(encoded))); got <= int64(len(encoded)) {
		t.Fatalf("retained bytes = %d, BER bytes = %d", got, len(encoded))
	}
}

type responseBudgetGateConnection struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type responseBudgetBufferConnection struct{ bytes.Buffer }

func (*responseBudgetBufferConnection) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (*responseBudgetBufferConnection) Close() error             { return nil }
func (*responseBudgetBufferConnection) LocalAddr() net.Addr {
	return responseBudgetTestAddr("local")
}
func (*responseBudgetBufferConnection) RemoteAddr() net.Addr {
	return responseBudgetTestAddr("remote")
}
func (*responseBudgetBufferConnection) SetDeadline(time.Time) error      { return nil }
func (*responseBudgetBufferConnection) SetReadDeadline(time.Time) error  { return nil }
func (*responseBudgetBufferConnection) SetWriteDeadline(time.Time) error { return nil }

func (connection *responseBudgetGateConnection) Read([]byte) (int, error) {
	return 0, net.ErrClosed
}

func (connection *responseBudgetGateConnection) Write(value []byte) (int, error) {
	connection.once.Do(func() {
		close(connection.entered)
		<-connection.release
	})
	return len(value), nil
}

func (connection *responseBudgetGateConnection) Close() error { return nil }
func (connection *responseBudgetGateConnection) LocalAddr() net.Addr {
	return responseBudgetTestAddr("local")
}
func (connection *responseBudgetGateConnection) RemoteAddr() net.Addr {
	return responseBudgetTestAddr("remote")
}
func (connection *responseBudgetGateConnection) SetDeadline(time.Time) error      { return nil }
func (connection *responseBudgetGateConnection) SetReadDeadline(time.Time) error  { return nil }
func (connection *responseBudgetGateConnection) SetWriteDeadline(time.Time) error { return nil }

type responseBudgetTestAddr string

func (address responseBudgetTestAddr) Network() string { return "review" }
func (address responseBudgetTestAddr) String() string  { return string(address) }
