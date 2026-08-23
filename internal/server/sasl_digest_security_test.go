package server

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

func TestSASLDigestMD5SigningKeysAndIntegrityRoundTrip(t *testing.T) {
	t.Parallel()

	sessionKey := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	clientKey := saslDigestMD5SigningKey(
		sessionKey,
		saslDigestMD5SigningClientServer,
	)
	serverKey := saslDigestMD5SigningKey(
		sessionKey,
		saslDigestMD5SigningServerClient,
	)
	if got := hex.EncodeToString(clientKey[:]); got != "bf27ca0b3a5f2e02a31ccb488ee84b8e" {
		t.Fatalf("client signing key = %s", got)
	}
	if got := hex.EncodeToString(serverKey[:]); got != "444a3d699a08f6921fdc91b90df3db05" {
		t.Fatalf("server signing key = %s", got)
	}

	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	serverLayer, err := newSASLDigestMD5ServerIntegrityConnection(
		serverRaw,
		sessionKey,
		24,
		24,
	)
	if err != nil {
		t.Fatalf("create server integrity layer: %v", err)
	}
	clientLayer, err := newSASLDigestMD5IntegrityConnection(
		clientRaw,
		saslDigestMD5SigningClientServer,
		saslDigestMD5SigningServerClient,
		sessionKey,
		24,
		24,
	)
	if err != nil {
		t.Fatalf("create client integrity layer: %v", err)
	}

	written := make(chan error, 1)
	go func() {
		_, writeErr := clientLayer.Write([]byte("0123456789"))
		written <- writeErr
	}()
	message, err := io.ReadAll(io.LimitReader(serverLayer, 10))
	if err != nil {
		t.Fatalf("read fragmented integrity data: %v", err)
	}
	if string(message) != "0123456789" {
		t.Fatalf("integrity plaintext = %q", message)
	}
	if err := <-written; err != nil {
		t.Fatalf("write fragmented integrity data: %v", err)
	}
}

func TestSASLDigestMD5RC4CyrusVectors(t *testing.T) {
	t.Parallel()

	sessionKey := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	tests := []struct {
		cipher    saslDigestMD5Cipher
		wantKey   string
		wantFrame string
	}{
		{orderedSASLDigestMD5Ciphers()[0], "ecc53f4413aa95a182a81c10bc4e7c5c", "000000148cf95a62db8a34229b2da13fd88e000100000000"},
		{orderedSASLDigestMD5Ciphers()[1], "5ed782a05a7b13da55e2241ecf718aac", "00000014c7db262ee6ea3f1ead9073f0e57f000100000000"},
		{orderedSASLDigestMD5Ciphers()[2], "ff7d44f943d8da51df617c0e5b348b27", "000000144e1442fc610a6a431586547ab84e000100000000"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.cipher.name, func(t *testing.T) {
			t.Parallel()
			key, err := saslDigestMD5SealingKey(
				sessionKey,
				test.cipher.keyPrefix,
				saslDigestMD5SealingClientServer,
			)
			if err != nil {
				t.Fatalf("derive sealing key: %v", err)
			}
			if got := hex.EncodeToString(key[:]); got != test.wantKey {
				t.Fatalf("sealing key = %s, want %s", got, test.wantKey)
			}
			clear(key[:])

			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			defer clientRaw.Close()
			client, err := newSASLDigestMD5PrivacyConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				saslDigestMD5SealingClientServer,
				saslDigestMD5SealingServerClient,
				sessionKey,
				test.cipher,
				saslDigestMD5DefaultMaxBuffer,
				saslDigestMD5DefaultMaxBuffer,
			)
			if err != nil {
				t.Fatalf("create privacy layer: %v", err)
			}
			frame := client.encodeFrame([]byte("test"), 0)
			defer clear(frame)
			if got := hex.EncodeToString(frame); got != test.wantFrame {
				t.Fatalf("Cyrus-compatible first frame = %s, want %s", got, test.wantFrame)
			}
		})
	}
}

func TestSASLDigestMD5RC4PrivacyRoundTripAndConcurrency(t *testing.T) {
	for _, cipher := range orderedSASLDigestMD5Ciphers() {
		cipher := cipher
		t.Run(cipher.name, func(t *testing.T) {
			t.Parallel()
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			defer clientRaw.Close()
			sessionKey := []byte("0123456789abcdef")
			serverLayer, err := newSASLDigestMD5ServerPrivacyConnection(
				serverRaw, sessionKey, cipher, 64, 64,
			)
			if err != nil {
				t.Fatalf("create server privacy layer: %v", err)
			}
			clientLayer, err := newSASLDigestMD5PrivacyConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				saslDigestMD5SealingClientServer,
				saslDigestMD5SealingServerClient,
				sessionKey, cipher, 64, 64,
			)
			if err != nil {
				t.Fatalf("create client privacy layer: %v", err)
			}

			const writers = 12
			var group sync.WaitGroup
			writeErrors := make(chan error, writers)
			for index := range writers {
				group.Add(1)
				go func(value byte) {
					defer group.Done()
					_, writeErr := clientLayer.Write([]byte{value})
					writeErrors <- writeErr
				}(byte(index))
			}
			received := make(map[byte]int, writers)
			for range writers {
				var value [1]byte
				if _, err := io.ReadFull(serverLayer, value[:]); err != nil {
					t.Fatalf("read privacy frame: %v", err)
				}
				received[value[0]]++
			}
			group.Wait()
			close(writeErrors)
			for err := range writeErrors {
				if err != nil {
					t.Fatalf("write privacy frame: %v", err)
				}
			}
			for index := range writers {
				if received[byte(index)] != 1 {
					t.Fatalf("value %d count = %d", index, received[byte(index)])
				}
			}

			writeDone := make(chan error, 1)
			go func() {
				_, writeErr := serverLayer.Write([]byte("server reply"))
				writeDone <- writeErr
			}()
			message := make([]byte, len("server reply"))
			if _, err := io.ReadFull(clientLayer, message); err != nil || string(message) != "server reply" {
				t.Fatalf("read server privacy reply = %q, %v", message, err)
			}
			if err := <-writeDone; err != nil {
				t.Fatalf("write server privacy reply: %v", err)
			}
		})
	}
}

func TestSASLDigestMD5RC4PrivacyRejectsTamperAndReplay(t *testing.T) {
	for _, name := range []string{"tamper", "replay"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			defer clientRaw.Close()
			cipher := orderedSASLDigestMD5Ciphers()[2]
			sessionKey := []byte("0123456789abcdef")
			receiver, err := newSASLDigestMD5ServerPrivacyConnection(
				serverRaw, sessionKey, cipher,
				saslDigestMD5DefaultMaxBuffer, saslDigestMD5DefaultMaxBuffer,
			)
			if err != nil {
				t.Fatalf("create receiver: %v", err)
			}
			sender, err := newSASLDigestMD5PrivacyConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				saslDigestMD5SealingClientServer,
				saslDigestMD5SealingServerClient,
				sessionKey, cipher,
				saslDigestMD5DefaultMaxBuffer, saslDigestMD5DefaultMaxBuffer,
			)
			if err != nil {
				t.Fatalf("create sender: %v", err)
			}
			frame := sender.encodeFrame([]byte("protected"), 0)
			if name == "tamper" {
				frame[5] ^= 0x80
				writeFrameAsync(clientRaw, frame)
				buffer := make([]byte, 32)
				count, readErr := receiver.Read(buffer)
				if count != 0 || !errors.Is(readErr, errSASLDigestMD5Integrity) {
					t.Fatalf("tampered privacy frame read = %d, %v", count, readErr)
				}
				return
			}
			writeFrameAsync(clientRaw, append(frame, frame...))
			buffer := make([]byte, 32)
			count, readErr := receiver.Read(buffer)
			if readErr != nil || string(buffer[:count]) != "protected" {
				t.Fatalf("first privacy frame = %q, %v", buffer[:count], readErr)
			}
			count, readErr = receiver.Read(buffer)
			if count != 0 || !errors.Is(readErr, errSASLDigestMD5Sequence) {
				t.Fatalf("replayed privacy frame read = %d, %v", count, readErr)
			}
		})
	}
}

func TestSASLDigestMD5IntegrityRejectsTamperAndReplay(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		run  func(*testing.T, net.Conn, *saslDigestMD5IntegrityConnection)
	}{
		{
			name: "tamper",
			run: func(t *testing.T, raw net.Conn, sender *saslDigestMD5IntegrityConnection) {
				frame := sender.encodeFrame([]byte("protected"), 0)
				frame[len(frame)-7] ^= 0x80
				writeFrameAsync(raw, frame)
			},
		},
		{
			name: "replay",
			run: func(t *testing.T, raw net.Conn, sender *saslDigestMD5IntegrityConnection) {
				frame := sender.encodeFrame([]byte("protected"), 0)
				writeFrameAsync(raw, append(frame, frame...))
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sessionKey := []byte("0123456789abcdef")
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			defer clientRaw.Close()
			receiver, err := newSASLDigestMD5ServerIntegrityConnection(
				serverRaw,
				sessionKey,
				saslDigestMD5DefaultMaxBuffer,
				saslDigestMD5DefaultMaxBuffer,
			)
			if err != nil {
				t.Fatalf("create receiver: %v", err)
			}
			sender, err := newSASLDigestMD5IntegrityConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				sessionKey,
				saslDigestMD5DefaultMaxBuffer,
				saslDigestMD5DefaultMaxBuffer,
			)
			if err != nil {
				t.Fatalf("create sender: %v", err)
			}
			test.run(t, clientRaw, sender)

			buffer := make([]byte, 32)
			count, firstErr := receiver.Read(buffer)
			if test.name == "tamper" {
				if count != 0 || !errors.Is(firstErr, errSASLDigestMD5Integrity) {
					t.Fatalf("tampered frame read = %d, %v", count, firstErr)
				}
				return
			}
			if firstErr != nil || string(buffer[:count]) != "protected" {
				t.Fatalf("first replay frame = %q, %v", buffer[:count], firstErr)
			}
			count, replayErr := receiver.Read(buffer)
			if count != 0 || !errors.Is(replayErr, errSASLDigestMD5Sequence) {
				t.Fatalf("replayed frame read = %d, %v", count, replayErr)
			}
		})
	}
}

func TestSASLDigestMD5IntegritySerializesConcurrentWrites(t *testing.T) {
	t.Parallel()

	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	sessionKey := []byte("0123456789abcdef")
	serverLayer, err := newSASLDigestMD5ServerIntegrityConnection(
		serverRaw,
		sessionKey,
		saslDigestMD5DefaultMaxBuffer,
		saslDigestMD5DefaultMaxBuffer,
	)
	if err != nil {
		t.Fatalf("create server layer: %v", err)
	}
	clientLayer, err := newSASLDigestMD5IntegrityConnection(
		clientRaw,
		saslDigestMD5SigningClientServer,
		saslDigestMD5SigningServerClient,
		sessionKey,
		saslDigestMD5DefaultMaxBuffer,
		saslDigestMD5DefaultMaxBuffer,
	)
	if err != nil {
		t.Fatalf("create client layer: %v", err)
	}

	const writers = 16
	var group sync.WaitGroup
	errorsSeen := make(chan error, writers)
	for index := range writers {
		group.Add(1)
		go func(value byte) {
			defer group.Done()
			_, writeErr := clientLayer.Write([]byte{value})
			errorsSeen <- writeErr
		}(byte(index))
	}
	received := make(map[byte]int, writers)
	for range writers {
		var value [1]byte
		if _, err := io.ReadFull(serverLayer, value[:]); err != nil {
			t.Fatalf("read concurrent integrity frame: %v", err)
		}
		received[value[0]]++
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent integrity write: %v", err)
		}
	}
	for index := range writers {
		if received[byte(index)] != 1 {
			t.Fatalf("concurrent value %d count = %d", index, received[byte(index)])
		}
	}
}

func writeFrameAsync(connection net.Conn, frame []byte) {
	go func() {
		defer clear(frame)
		_ = writeSASLDigestMD5Frame(connection, frame)
	}()
}
