package saslkrb5

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestNegotiationEncoding(t *testing.T) {
	encoded, err := EncodeNegotiation(SecurityIntegrity, 0x010203, "u:alice")
	if err != nil {
		t.Fatalf("EncodeNegotiation: %v", err)
	}
	if got := hex.EncodeToString(encoded); got != "02010203753a616c696365" {
		t.Fatalf("negotiation = %s", got)
	}
	layer, maximum, authzid, err := DecodeNegotiation(encoded)
	if err != nil || layer != SecurityIntegrity || maximum != 0x010203 || authzid != "u:alice" {
		t.Fatalf("DecodeNegotiation = %d, %x, %q, %v", layer, maximum, authzid, err)
	}
	offerLayers, offerMaximum, err := DecodeOffer([]byte{SecurityNone | SecurityIntegrity, 1, 0, 0})
	if err != nil || offerLayers != SecurityNone|SecurityIntegrity || offerMaximum != 65536 {
		t.Fatalf("DecodeOffer = %d, %d, %v", offerLayers, offerMaximum, err)
	}
	confidential, err := EncodeNegotiation(SecurityConfidentiality, 65536, "")
	if err != nil {
		t.Fatalf("EncodeNegotiation confidentiality: %v", err)
	}
	if layer, maximum, _, err := DecodeNegotiation(confidential); err != nil ||
		layer != SecurityConfidentiality || maximum != 65536 {
		t.Fatalf("DecodeNegotiation confidentiality = %d, %d, %v", layer, maximum, err)
	}

	invalidNegotiations := [][]byte{
		nil,
		{SecurityNone, 0, 0, 1},
		{SecurityNone | SecurityIntegrity, 0, 0, 0},
		{SecurityIntegrity, 0, 0, 0},
	}
	for _, invalid := range invalidNegotiations {
		if _, _, _, err := DecodeNegotiation(invalid); err == nil {
			t.Fatalf("DecodeNegotiation(%x) succeeded", invalid)
		}
	}
	invalidOffers := [][]byte{
		{0, 0, 0, 0},
		{SecurityNone, 0, 0, 1},
		{SecurityIntegrity, 0, 0, 0},
		{0x80, 0, 0, 0},
	}
	for _, invalid := range invalidOffers {
		if _, _, err := DecodeOffer(invalid); err == nil {
			t.Fatalf("DecodeOffer(%x) succeeded", invalid)
		}
	}
}

func TestConfidentialWrapAndConnection(t *testing.T) {
	key := testIntegrityKey()
	payload := bytes.Repeat([]byte("private-gssapi-message-"), 7)
	for _, fromAcceptor := range []bool{false, true} {
		encoded, err := WrapConfidential(payload, key, fromAcceptor, false, 19)
		if err != nil {
			t.Fatalf("WrapConfidential(%t): %v", fromAcceptor, err)
		}
		if bytes.Contains(encoded[16:], payload) {
			t.Fatal("confidential token exposes its plaintext")
		}
		decoded, err := UnwrapConfidential(encoded, key, fromAcceptor, false, 19)
		if err != nil {
			t.Fatalf("UnwrapConfidential(%t): %v", fromAcceptor, err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatal("confidential token payload mismatch")
		}
		clear(decoded)
		encoded[len(encoded)-1] ^= 0x40
		if _, err := UnwrapConfidential(encoded, key, fromAcceptor, false, 19); err == nil {
			t.Fatal("tampered confidential token was accepted")
		}
	}

	clientRaw, serverRaw := net.Pipe()
	clientState := SecurityState{SendSequence: 41, ReceiveSequence: 73}
	serverState := SecurityState{SendSequence: 73, ReceiveSequence: 41}
	client, err := NewConfidentialityConnection(clientRaw, key, false, clientState, 128, 128)
	if err != nil {
		t.Fatalf("new client confidentiality layer: %v", err)
	}
	server, err := NewConfidentialityConnection(serverRaw, key, true, serverState, 128, 128)
	if err != nil {
		t.Fatalf("new server confidentiality layer: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	want := bytes.Repeat([]byte("confidential-frame-"), 20)
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(want)
		writeDone <- err
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read confidential frames: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write confidential frames: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("confidential connection payload mismatch")
	}
}

func TestWrapRFC4121Vectors(t *testing.T) {
	key := testIntegrityKey()
	tests := []struct {
		name         string
		fromAcceptor bool
		sequence     uint64
		payload      []byte
		wantHex      string
	}{
		{
			name:     "initiator selection",
			sequence: 1,
			payload:  []byte{SecurityIntegrity, 0, 1, 0, 'u', ':', 'a'},
			wantHex:  "050400ff000c0000000000000000000102000100753a6115fb275e71d1f4912e1bd4f5",
		},
		{
			name:         "acceptor offer rotation",
			fromAcceptor: true,
			payload:      []byte{SecurityNone | SecurityIntegrity, 1, 0, 0},
			wantHex:      "050401ff000c000c0000000000000000606b364476b9d35eccedc2cc03010000",
		},
		{
			name:         "acceptor subkey flag",
			fromAcceptor: true,
			sequence:     0x1020304,
			payload:      []byte("subkey-token"),
			wantHex:      "050405ff000c000c0000000001020304a805ade24685f90977ec050e7375626b65792d746f6b656e",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceptorSubkey := test.name == "acceptor subkey flag"
			encoded, err := Wrap(
				test.payload,
				key,
				test.fromAcceptor,
				acceptorSubkey,
				test.sequence,
			)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if got := hex.EncodeToString(encoded); got != test.wantHex {
				t.Fatalf("Wrap vector = %s, want %s", got, test.wantHex)
			}
			decoded, err := Unwrap(
				encoded,
				key,
				test.fromAcceptor,
				acceptorSubkey,
				test.sequence,
			)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(decoded, test.payload) {
				t.Fatalf("Unwrap = %x, want %x", decoded, test.payload)
			}
			clear(decoded)
			encoded[len(encoded)-1] ^= 0x80
			if _, err := Unwrap(
				encoded,
				key,
				test.fromAcceptor,
				acceptorSubkey,
				test.sequence,
			); err == nil {
				t.Fatal("tampered token was accepted")
			}
		})
	}
	encoded, err := Wrap([]byte("sequence"), key, false, false, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(encoded, key, false, false, 8); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("wrong sequence error = %v", err)
	}
	if _, err := Unwrap(encoded, key, true, false, 7); err == nil || !strings.Contains(err.Error(), "direction") {
		t.Fatalf("wrong direction error = %v", err)
	}
	subkeyToken, err := Wrap([]byte("subkey"), key, true, true, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(subkeyToken, key, true, false, 9); err == nil ||
		!strings.Contains(err.Error(), "subkey") {
		t.Fatalf("missing acceptor-subkey state error = %v", err)
	}
}

func TestSecurityConnectionConcurrentCloseClearsKey(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		name := "integrity"
		if confidential {
			name = "confidentiality"
		}
		t.Run(name, func(t *testing.T) {
			transport := newBlockingSecurityConnection()
			state := SecurityState{
				SendSequence:    71,
				ReceiveSequence: 93,
				AcceptorSubkey:  true,
			}
			var layer *IntegrityConnection
			var err error
			if confidential {
				layer, err = NewConfidentialityConnection(
					transport, testIntegrityKey(), false, state, 128, 128,
				)
			} else {
				layer, err = NewIntegrityConnection(
					transport, testIntegrityKey(), false, state, 128, 128,
				)
			}
			if err != nil {
				t.Fatalf("new security connection: %v", err)
			}

			readDone := make(chan error, 1)
			writeDone := make(chan error, 1)
			go func() {
				_, err := layer.Read(make([]byte, 1))
				readDone <- err
			}()
			go func() {
				_, err := layer.Write([]byte("blocked-write"))
				writeDone <- err
			}()
			<-transport.readStarted
			<-transport.writeStarted

			var closers sync.WaitGroup
			closers.Add(4)
			for range 4 {
				go func() {
					defer closers.Done()
					_ = layer.Close()
				}()
			}
			closers.Wait()
			if err := <-readDone; err == nil {
				t.Fatal("blocked Read succeeded after Close")
			}
			if err := <-writeDone; err == nil {
				t.Fatal("blocked Write succeeded after Close")
			}
			if len(layer.key.KeyValue) != 0 || layer.readPending != nil {
				t.Fatalf("Close retained GSSAPI secrets: %#v", layer)
			}
		})
	}
}

type blockingSecurityConnection struct {
	closed       chan struct{}
	readStarted  chan struct{}
	writeStarted chan struct{}
	closeOnce    sync.Once
	readOnce     sync.Once
	writeOnce    sync.Once
}

func newBlockingSecurityConnection() *blockingSecurityConnection {
	return &blockingSecurityConnection{
		closed:       make(chan struct{}),
		readStarted:  make(chan struct{}),
		writeStarted: make(chan struct{}),
	}
}

func (connection *blockingSecurityConnection) Read([]byte) (int, error) {
	connection.readOnce.Do(func() { close(connection.readStarted) })
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *blockingSecurityConnection) Write([]byte) (int, error) {
	connection.writeOnce.Do(func() { close(connection.writeStarted) })
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *blockingSecurityConnection) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*blockingSecurityConnection) LocalAddr() net.Addr              { return nil }
func (*blockingSecurityConnection) RemoteAddr() net.Addr             { return nil }
func (*blockingSecurityConnection) SetDeadline(time.Time) error      { return nil }
func (*blockingSecurityConnection) SetReadDeadline(time.Time) error  { return nil }
func (*blockingSecurityConnection) SetWriteDeadline(time.Time) error { return nil }

func TestIntegrityConnectionBidirectionalAndConcurrent(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	clientState := SecurityState{SendSequence: 101, ReceiveSequence: 211}
	serverState := SecurityState{SendSequence: 211, ReceiveSequence: 101}
	client, err := NewIntegrityConnection(clientRaw, testIntegrityKey(), false, clientState, 96, 96)
	if err != nil {
		t.Fatalf("new client layer: %v", err)
	}
	server, err := NewIntegrityConnection(serverRaw, testIntegrityKey(), true, serverState, 96, 96)
	if err != nil {
		t.Fatalf("new server layer: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))

	clientMessages := [][]byte{
		bytes.Repeat([]byte("client-one-"), 20),
		bytes.Repeat([]byte("client-two-"), 17),
	}
	serverMessage := bytes.Repeat([]byte("server-response-"), 19)
	var writers sync.WaitGroup
	writers.Add(3)
	for _, message := range clientMessages {
		message := message
		go func() {
			defer writers.Done()
			if _, err := client.Write(message); err != nil {
				t.Errorf("client Write: %v", err)
			}
		}()
	}
	go func() {
		defer writers.Done()
		if _, err := server.Write(serverMessage); err != nil {
			t.Errorf("server Write: %v", err)
		}
	}()

	wantClientBytes := len(clientMessages[0]) + len(clientMessages[1])
	serverReceived := make([]byte, wantClientBytes)
	clientReceived := make([]byte, len(serverMessage))
	reads := make(chan error, 2)
	go func() {
		_, err := io.ReadFull(server, serverReceived)
		reads <- err
	}()
	go func() {
		_, err := io.ReadFull(client, clientReceived)
		reads <- err
	}()
	writers.Wait()
	for range 2 {
		if err := <-reads; err != nil {
			t.Fatalf("integrity Read: %v", err)
		}
	}
	if !bytes.Equal(clientReceived, serverMessage) {
		t.Fatal("client did not receive the server payload")
	}
	firstThenSecond := append(append([]byte(nil), clientMessages[0]...), clientMessages[1]...)
	secondThenFirst := append(append([]byte(nil), clientMessages[1]...), clientMessages[0]...)
	if !bytes.Equal(serverReceived, firstThenSecond) && !bytes.Equal(serverReceived, secondThenFirst) {
		t.Fatal("concurrent client messages were interleaved")
	}
}

func testIntegrityKey() types.EncryptionKey {
	return types.EncryptionKey{
		KeyType: etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
	}
}
