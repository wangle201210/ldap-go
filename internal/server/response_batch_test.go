package server

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestSerializedResponseConnectionWritesBatchOnce(t *testing.T) {
	t.Parallel()

	transport := &responseBatchRecordingConn{}
	connection := &serializedResponseConnection{
		Conn: transport,
		mu:   &sync.Mutex{},
	}
	operation := newTrackedOperation(context.Background(), ldapwire.Message{
		ID: 1,
		Request: ldapwire.SearchRequest{
			BaseDN: "dc=example,dc=com",
		},
	})
	written, err := connection.writeOperationResponseBatch(
		operation,
		[][]byte{[]byte("entry"), []byte("done")},
	)
	if err != nil {
		t.Fatalf("writeOperationResponseBatch(): %v", err)
	}
	if written != 9 || transport.writes != 1 || transport.String() != "entrydone" {
		t.Fatalf(
			"batch write = (%d, %d, %q), want (9, 1, entrydone)",
			written,
			transport.writes,
			transport.String(),
		)
	}
}

func TestLDAPResponseBatchConnectionFlushesAtPDULimit(t *testing.T) {
	t.Parallel()

	recorder := &responseBatchWriterRecorder{}
	connection := newLDAPResponseBatchConnection(recorder)
	for index := 0; index < maximumLDAPResponseBatchPDUs+1; index++ {
		if _, err := connection.Write([]byte{byte(index)}); err != nil {
			t.Fatalf("Write(%d): %v", index, err)
		}
	}
	if err := connection.Flush(); err != nil {
		t.Fatalf("Flush(): %v", err)
	}
	if len(recorder.batches) != 2 ||
		len(recorder.batches[0]) != maximumLDAPResponseBatchPDUs ||
		len(recorder.batches[1]) != 1 {
		t.Fatalf("batch PDU counts = %v", recorder.batchLengths())
	}
}

type responseBatchRecordingConn struct {
	bytes.Buffer
	writes int
}

func (connection *responseBatchRecordingConn) Write(value []byte) (int, error) {
	connection.writes++
	return connection.Buffer.Write(value)
}

func (connection *responseBatchRecordingConn) Read([]byte) (int, error) {
	return 0, net.ErrClosed
}

func (connection *responseBatchRecordingConn) Close() error { return nil }
func (connection *responseBatchRecordingConn) LocalAddr() net.Addr {
	return responseBatchAddress("local")
}
func (connection *responseBatchRecordingConn) RemoteAddr() net.Addr {
	return responseBatchAddress("remote")
}
func (connection *responseBatchRecordingConn) SetDeadline(time.Time) error      { return nil }
func (connection *responseBatchRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *responseBatchRecordingConn) SetWriteDeadline(time.Time) error { return nil }

type responseBatchAddress string

func (address responseBatchAddress) Network() string { return "test" }
func (address responseBatchAddress) String() string  { return string(address) }

type responseBatchWriterRecorder struct {
	net.Conn
	batches [][][]byte
}

func (recorder *responseBatchWriterRecorder) writeLDAPResponseBatch(
	values [][]byte,
) (int, error) {
	batch := make([][]byte, len(values))
	total := 0
	for index, value := range values {
		batch[index] = bytes.Clone(value)
		total += len(value)
	}
	recorder.batches = append(recorder.batches, batch)
	return total, nil
}

func (recorder *responseBatchWriterRecorder) batchLengths() []int {
	lengths := make([]int, len(recorder.batches))
	for index := range recorder.batches {
		lengths[index] = len(recorder.batches[index])
	}
	return lengths
}
