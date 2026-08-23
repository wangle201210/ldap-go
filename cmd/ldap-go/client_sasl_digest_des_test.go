package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
)

func TestLDAPClientDigestMD5BlockCyrusVectors(t *testing.T) {
	sessionKey := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	for _, test := range []struct {
		cipher        string
		wantBlockKey  string
		wantFrame     string
		wantNextFrame string
		peerFrame     string
	}{
		{
			cipher:        ldapClientDigestMD5DESCipher,
			wantBlockKey:  "ffbe519f941e63b4",
			wantFrame:     "00000016dfb9262892363c8c17fc5cc9451269f4000100000000",
			wantNextFrame: "00000016727f6b0ac2ee3abb2d2b58d33bebdcd3000100000001",
			peerFrame:     "000000165b383e566a84f3b843ad890de40306f2000100000000",
		},
		{
			cipher:        ldapClientDigestMD53DESCipher,
			wantBlockKey:  "ffbe519f941e63b451efd82fc0726c68ffbe519f941e63b4",
			wantFrame:     "00000016a63804e5d03b37403f7597642c9753cb000100000000",
			wantNextFrame: "00000016328afa13977524c701b78c95c4a8eae4000100000001",
			peerFrame:     "00000016084f077ab4969ded3c0ef0a757ad40ed000100000000",
		},
	} {
		test := test
		t.Run(test.cipher, func(t *testing.T) {
			t.Parallel()
			clientRaw, peerRaw := net.Pipe()
			defer clientRaw.Close()
			defer peerRaw.Close()
			selected, ok := ldapClientDigestMD5CipherByName(test.cipher)
			if !ok {
				t.Fatalf("cipher %s is unavailable", test.cipher)
			}
			layer, err := newLDAPClientDigestMD5PrivacyConnection(
				clientRaw,
				sessionKey,
				selected,
				ldapClientDigestMD5MaxBuffer,
				ldapClientDigestMD5MaxBuffer,
			)
			if err != nil {
				t.Fatalf("create privacy layer: %v", err)
			}
			if got := hex.EncodeToString(layer.sendBlockKey[:layer.blockKeySize]); got != test.wantBlockKey {
				t.Fatalf("Cyrus DES key = %s, want %s", got, test.wantBlockKey)
			}
			if got := hex.EncodeToString(layer.sendIV[:]); got != "df617c0e5b348b27" {
				t.Fatalf("Cyrus DES IV = %s", got)
			}

			frame := layer.encodeDigestMD5Frame([]byte("test"), 0)
			defer clear(frame)
			if got := hex.EncodeToString(frame); got != test.wantFrame {
				t.Fatalf("Cyrus-compatible first frame = %s, want %s", got, test.wantFrame)
			}
			next := layer.encodeDigestMD5Frame([]byte("next"), 1)
			defer clear(next)
			if got := hex.EncodeToString(next); got != test.wantNextFrame {
				t.Fatalf("Cyrus-compatible chained frame = %s, want %s", got, test.wantNextFrame)
			}

			peerFrame, err := hex.DecodeString(test.peerFrame)
			if err != nil {
				t.Fatalf("decode peer vector: %v", err)
			}
			go func() {
				defer clear(peerFrame)
				_ = ldapClientWriteDigestMD5Frame(peerRaw, peerFrame)
			}()
			message := make([]byte, 4)
			if _, err := io.ReadFull(layer, message); err != nil || string(message) != "test" {
				t.Fatalf("read Cyrus-compatible peer frame = %q, %v", message, err)
			}
		})
	}
}

func TestLDAPClientDigestMD5BlockRejectsPaddingTruncationAndReplay(t *testing.T) {
	for _, cipherName := range []string{
		ldapClientDigestMD5DESCipher,
		ldapClientDigestMD53DESCipher,
	} {
		cipherName := cipherName
		for _, failure := range []string{"padding", "truncated-block", "replay"} {
			failure := failure
			t.Run(cipherName+"/"+failure, func(t *testing.T) {
				t.Parallel()
				clientRaw, peerRaw := net.Pipe()
				defer clientRaw.Close()
				defer peerRaw.Close()
				selected, _ := ldapClientDigestMD5CipherByName(cipherName)
				layer, err := newLDAPClientDigestMD5PrivacyConnection(
					clientRaw,
					[]byte("0123456789abcdef"),
					selected,
					ldapClientDigestMD5MaxBuffer,
					ldapClientDigestMD5MaxBuffer,
				)
				if err != nil {
					t.Fatalf("create privacy layer: %v", err)
				}
				frame := ldapClientDigestMD5ServerBlockFrame(
					t,
					[]byte("0123456789abcdef"),
					selected,
					failure == "padding",
				)
				if failure == "truncated-block" {
					typeAndSequence := frame[len(frame)-6:]
					malformed := make([]byte, len(frame)-1)
					copy(malformed, frame[:len(frame)-7])
					copy(malformed[len(malformed)-6:], typeAndSequence)
					binary.BigEndian.PutUint32(malformed[:4], uint32(len(malformed)-4))
					clear(frame)
					frame = malformed
				} else if failure == "replay" {
					frame = append(frame, frame...)
				}
				go func() {
					defer clear(frame)
					_ = ldapClientWriteDigestMD5Frame(peerRaw, frame)
				}()

				buffer := make([]byte, 16)
				count, readErr := layer.Read(buffer)
				switch failure {
				case "padding":
					if count != 0 || !errors.Is(readErr, errLDAPClientDigestMD5Integrity) {
						t.Fatalf("invalid padding read = %d, %v", count, readErr)
					}
				case "truncated-block":
					if count != 0 || !errors.Is(readErr, errLDAPClientDigestMD5Frame) {
						t.Fatalf("truncated block read = %d, %v", count, readErr)
					}
				case "replay":
					if readErr != nil || string(buffer[:count]) != "test" {
						t.Fatalf("first replay frame = %q, %v", buffer[:count], readErr)
					}
					count, readErr = layer.Read(buffer)
					if count != 0 || !errors.Is(readErr, errLDAPClientDigestMD5Sequence) {
						t.Fatalf("replayed block frame = %d, %v", count, readErr)
					}
				}
			})
		}
	}
}

func TestLDAPClientDigestMD5BlockCloseClearsKeys(t *testing.T) {
	for _, cipherName := range []string{
		ldapClientDigestMD5DESCipher,
		ldapClientDigestMD53DESCipher,
	} {
		t.Run(cipherName, func(t *testing.T) {
			clientRaw, peerRaw := net.Pipe()
			defer peerRaw.Close()
			selected, _ := ldapClientDigestMD5CipherByName(cipherName)
			layer, err := newLDAPClientDigestMD5PrivacyConnection(
				clientRaw,
				[]byte("0123456789abcdef"),
				selected,
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
				!allZeroBytes(layer.sendBlockKey[:]) ||
				!allZeroBytes(layer.receiveBlockKey[:]) ||
				!allZeroBytes(layer.sendIV[:]) ||
				!allZeroBytes(layer.receiveIV[:]) {
				t.Fatal("block privacy Close retained key material")
			}
		})
	}
}

func TestLDAPClientDigestMD5PrivacyMaxBufferBoundaries(t *testing.T) {
	for _, test := range []struct {
		cipher      string
		peerBuffer  uint32
		localBuffer uint32
	}{
		{cipher: ldapClientDigestMD5RC4Cipher, peerBuffer: 26, localBuffer: 21},
		{cipher: ldapClientDigestMD5DESCipher, peerBuffer: 30, localBuffer: 26},
		{cipher: ldapClientDigestMD53DESCipher, peerBuffer: 30, localBuffer: 26},
	} {
		test := test
		t.Run(test.cipher, func(t *testing.T) {
			clientRaw, peerRaw := net.Pipe()
			defer clientRaw.Close()
			defer peerRaw.Close()
			selected, _ := ldapClientDigestMD5CipherByName(test.cipher)
			if _, err := newLDAPClientDigestMD5PrivacyConnection(
				clientRaw,
				[]byte("0123456789abcdef"),
				selected,
				test.peerBuffer-1,
				test.localBuffer,
			); err == nil {
				t.Fatal("accepted privacy peer maxbuf without payload space")
			}
			if _, err := newLDAPClientDigestMD5PrivacyConnection(
				clientRaw,
				[]byte("0123456789abcdef"),
				selected,
				test.peerBuffer,
				test.localBuffer-1,
			); err == nil {
				t.Fatal("accepted privacy local maxbuf smaller than one frame")
			}
			layer, err := newLDAPClientDigestMD5PrivacyConnection(
				clientRaw,
				[]byte("0123456789abcdef"),
				selected,
				test.peerBuffer,
				test.localBuffer,
			)
			if err != nil {
				t.Fatalf("create minimum maxbuf privacy layer: %v", err)
			}
			if layer.maxSend != 1 {
				t.Fatalf("maxSend = %d, want 1", layer.maxSend)
			}
			frame := layer.encodeDigestMD5Frame([]byte{'x'}, 0)
			defer clear(frame)
			if len(frame) > int(test.peerBuffer) {
				t.Fatalf("minimum maxbuf frame length = %d, limit %d", len(frame), test.peerBuffer)
			}
		})
	}
}

func ldapClientDigestMD5ServerBlockFrame(
	t *testing.T,
	sessionKey []byte,
	cipher ldapClientDigestMD5Cipher,
	invalidPadding bool,
) []byte {
	t.Helper()
	seal, err := ldapClientDigestMD5SealingKey(
		sessionKey,
		cipher.keyPrefix,
		ldapClientDigestMD5SealingServerClient,
	)
	if err != nil {
		t.Fatalf("derive server sealing key: %v", err)
	}
	defer clear(seal[:])
	var key [24]byte
	var iv [8]byte
	keySize := ldapClientDigestMD5BlockKey(
		key[:],
		iv[:],
		seal[:],
		cipher.mode == ldapClientDigestMD5CipherMode3DES,
	)
	defer clear(key[:])
	defer clear(iv[:])

	message := []byte("test")
	plaintext := make([]byte, 16)
	copy(plaintext, message)
	plaintext[4], plaintext[5] = 2, 2
	if invalidPadding {
		plaintext[5] = 3
	}
	signingKey := ldapClientDigestMD5SigningKey(
		sessionKey,
		ldapClientDigestMD5SigningServerClient,
	)
	mac := ldapClientDigestMD5MAC(signingKey[:], 0, message)
	clear(signingKey[:])
	copy(plaintext[6:], mac)
	clear(mac)
	ldapClientDigestMD5CBC(key[:keySize], &iv, plaintext, true)

	frame := make([]byte, 4+len(plaintext)+6)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)-4))
	copy(frame[4:], plaintext)
	clear(plaintext)
	offset := len(frame) - 6
	binary.BigEndian.PutUint16(frame[offset:offset+2], ldapClientDigestMD5MessageType)
	return frame
}
