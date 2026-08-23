package server

import (
	"encoding/binary"
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

func TestSASLDigestMD5PrivacyCyrusVectors(t *testing.T) {
	t.Parallel()

	sessionKey := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	tests := []struct {
		cipher        saslDigestMD5Cipher
		wantKey       string
		wantBlockKey  string
		wantFrame     string
		wantNextFrame string
	}{
		{
			cipher:    orderedSASLDigestMD5Ciphers()[0],
			wantKey:   "ecc53f4413aa95a182a81c10bc4e7c5c",
			wantFrame: "000000148cf95a62db8a34229b2da13fd88e000100000000",
		},
		{
			cipher:    orderedSASLDigestMD5Ciphers()[1],
			wantKey:   "5ed782a05a7b13da55e2241ecf718aac",
			wantFrame: "00000014c7db262ee6ea3f1ead9073f0e57f000100000000",
		},
		{
			cipher:    orderedSASLDigestMD5Ciphers()[2],
			wantKey:   "ff7d44f943d8da51df617c0e5b348b27",
			wantFrame: "000000144e1442fc610a6a431586547ab84e000100000000",
		},
		{
			cipher:        orderedSASLDigestMD5Ciphers()[3],
			wantKey:       "ff7d44f943d8da51df617c0e5b348b27",
			wantBlockKey:  "ffbe519f941e63b4",
			wantFrame:     "00000016dfb9262892363c8c17fc5cc9451269f4000100000000",
			wantNextFrame: "00000016727f6b0ac2ee3abb2d2b58d33bebdcd3000100000001",
		},
		{
			cipher:        orderedSASLDigestMD5Ciphers()[4],
			wantKey:       "ff7d44f943d8da51df617c0e5b348b27",
			wantBlockKey:  "ffbe519f941e63b451efd82fc0726c68ffbe519f941e63b4",
			wantFrame:     "00000016a63804e5d03b37403f7597642c9753cb000100000000",
			wantNextFrame: "00000016328afa13977524c701b78c95c4a8eae4000100000001",
		},
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
			if test.wantBlockKey != "" {
				if got := hex.EncodeToString(client.sendBlockKey[:client.blockKeySize]); got != test.wantBlockKey {
					t.Fatalf("Cyrus DES key = %s, want %s", got, test.wantBlockKey)
				}
				if got := hex.EncodeToString(client.sendIV[:]); got != "df617c0e5b348b27" {
					t.Fatalf("Cyrus DES IV = %s", got)
				}
			}
			frame := client.encodeFrame([]byte("test"), 0)
			defer clear(frame)
			if got := hex.EncodeToString(frame); got != test.wantFrame {
				t.Fatalf("Cyrus-compatible first frame = %s, want %s", got, test.wantFrame)
			}
			if test.wantNextFrame != "" {
				next := client.encodeFrame([]byte("next"), 1)
				defer clear(next)
				if got := hex.EncodeToString(next); got != test.wantNextFrame {
					t.Fatalf("Cyrus-compatible chained frame = %s, want %s", got, test.wantNextFrame)
				}
			}
		})
	}
}

func TestSASLDigestMD5PrivacyRoundTripAndConcurrency(t *testing.T) {
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

func TestSASLDigestMD5BlockPrivacyRejectsPaddingTruncationAndReplay(t *testing.T) {
	for _, cipher := range orderedSASLDigestMD5Ciphers()[3:] {
		cipher := cipher
		for _, failure := range []string{"padding", "truncated-block", "replay"} {
			failure := failure
			t.Run(cipher.name+"/"+failure, func(t *testing.T) {
				t.Parallel()
				serverRaw, clientRaw := net.Pipe()
				defer serverRaw.Close()
				defer clientRaw.Close()
				sessionKey := []byte("0123456789abcdef")
				receiver, err := newSASLDigestMD5ServerPrivacyConnection(
					serverRaw,
					sessionKey,
					cipher,
					saslDigestMD5DefaultMaxBuffer,
					saslDigestMD5DefaultMaxBuffer,
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
					sessionKey,
					cipher,
					saslDigestMD5DefaultMaxBuffer,
					saslDigestMD5DefaultMaxBuffer,
				)
				if err != nil {
					t.Fatalf("create sender: %v", err)
				}

				frame := sender.encodeFrame([]byte("protected"), 0)
				switch failure {
				case "padding":
					plaintext := make([]byte, 2*8)
					copy(plaintext, "test")
					plaintext[4], plaintext[5] = 2, 3
					mac := saslDigestMD5MAC(sender.sendKey[:], 0, []byte("test"))
					copy(plaintext[6:], mac)
					clear(mac)
					iv := sender.sendIV
					saslDigestMD5CBC(
						sender.sendBlockKey[:sender.blockKeySize],
						&iv,
						plaintext,
						true,
					)
					frame = make([]byte, 4+len(plaintext)+6)
					binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)-4))
					copy(frame[4:], plaintext)
					offset := len(frame) - 6
					binary.BigEndian.PutUint16(frame[offset:offset+2], saslDigestMD5MessageType)
					clear(plaintext)
				case "truncated-block":
					typeAndSequence := frame[len(frame)-6:]
					malformed := make([]byte, len(frame)-1)
					copy(malformed, frame[:len(frame)-7])
					copy(malformed[len(malformed)-6:], typeAndSequence)
					binary.BigEndian.PutUint32(malformed[:4], uint32(len(malformed)-4))
					clear(frame)
					frame = malformed
				case "replay":
					frame = append(frame, frame...)
				}
				writeFrameAsync(clientRaw, frame)

				buffer := make([]byte, 64)
				count, readErr := receiver.Read(buffer)
				switch failure {
				case "padding":
					if count != 0 || !errors.Is(readErr, errSASLDigestMD5Integrity) {
						t.Fatalf("invalid padding read = %d, %v", count, readErr)
					}
				case "truncated-block":
					if count != 0 || !errors.Is(readErr, errSASLDigestMD5SecurityFrame) {
						t.Fatalf("truncated block read = %d, %v", count, readErr)
					}
				case "replay":
					if readErr != nil || string(buffer[:count]) != "protected" {
						t.Fatalf("first replay frame = %q, %v", buffer[:count], readErr)
					}
					count, readErr = receiver.Read(buffer)
					if count != 0 || !errors.Is(readErr, errSASLDigestMD5Sequence) {
						t.Fatalf("replayed block frame = %d, %v", count, readErr)
					}
				}
			})
		}
	}
}

func TestSASLDigestMD5BlockPrivacyCloseClearsKeys(t *testing.T) {
	for _, cipher := range orderedSASLDigestMD5Ciphers()[3:] {
		cipher := cipher
		t.Run(cipher.name, func(t *testing.T) {
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			layer, err := newSASLDigestMD5PrivacyConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				saslDigestMD5SealingClientServer,
				saslDigestMD5SealingServerClient,
				[]byte("0123456789abcdef"),
				cipher,
				64,
				64,
			)
			if err != nil {
				t.Fatalf("create block privacy layer: %v", err)
			}
			if err := layer.Close(); err != nil {
				t.Fatalf("close block privacy layer: %v", err)
			}
			if layer.blockKeySize != 0 ||
				!allZeroSASLDigestMD5Bytes(layer.sendBlockKey[:]) ||
				!allZeroSASLDigestMD5Bytes(layer.receiveBlockKey[:]) ||
				!allZeroSASLDigestMD5Bytes(layer.sendIV[:]) ||
				!allZeroSASLDigestMD5Bytes(layer.receiveIV[:]) {
				t.Fatal("block privacy Close retained key material")
			}
		})
	}
}

func TestSASLDigestMD5PrivacyMaxBufferBoundaries(t *testing.T) {
	for _, test := range []struct {
		cipher       saslDigestMD5Cipher
		peerBuffer   uint32
		localBuffer  uint32
		wantMaxSend  uint32
		wantFrameMax int
	}{
		{
			cipher:       orderedSASLDigestMD5Ciphers()[2],
			peerBuffer:   26,
			localBuffer:  21,
			wantMaxSend:  1,
			wantFrameMax: 26,
		},
		{
			cipher:       orderedSASLDigestMD5Ciphers()[3],
			peerBuffer:   30,
			localBuffer:  26,
			wantMaxSend:  1,
			wantFrameMax: 30,
		},
		{
			cipher:       orderedSASLDigestMD5Ciphers()[4],
			peerBuffer:   30,
			localBuffer:  26,
			wantMaxSend:  1,
			wantFrameMax: 30,
		},
	} {
		test := test
		t.Run(test.cipher.name, func(t *testing.T) {
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			defer clientRaw.Close()
			if _, err := newSASLDigestMD5PrivacyConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				saslDigestMD5SealingClientServer,
				saslDigestMD5SealingServerClient,
				[]byte("0123456789abcdef"),
				test.cipher,
				test.peerBuffer-1,
				test.localBuffer,
			); err == nil {
				t.Fatal("accepted privacy peer maxbuf without payload space")
			}
			if _, err := newSASLDigestMD5PrivacyConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				saslDigestMD5SealingClientServer,
				saslDigestMD5SealingServerClient,
				[]byte("0123456789abcdef"),
				test.cipher,
				test.peerBuffer,
				test.localBuffer-1,
			); err == nil {
				t.Fatal("accepted privacy local maxbuf smaller than one frame")
			}
			layer, err := newSASLDigestMD5PrivacyConnection(
				clientRaw,
				saslDigestMD5SigningClientServer,
				saslDigestMD5SigningServerClient,
				saslDigestMD5SealingClientServer,
				saslDigestMD5SealingServerClient,
				[]byte("0123456789abcdef"),
				test.cipher,
				test.peerBuffer,
				test.localBuffer,
			)
			if err != nil {
				t.Fatalf("create minimum maxbuf privacy layer: %v", err)
			}
			if layer.maxSend != test.wantMaxSend {
				t.Fatalf("maxSend = %d, want %d", layer.maxSend, test.wantMaxSend)
			}
			frame := layer.encodeFrame([]byte{'x'}, 0)
			defer clear(frame)
			if len(frame) > test.wantFrameMax {
				t.Fatalf("minimum maxbuf frame length = %d, limit %d", len(frame), test.wantFrameMax)
			}
		})
	}
}

func allZeroSASLDigestMD5Bytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
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
