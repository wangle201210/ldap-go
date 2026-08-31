package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // RFC 2831 mandates DES and two-key 3DES for DIGEST-MD5.
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // DIGEST-MD5 is required for OpenLDAP CLI interoperability.
	"crypto/rand"
	"crypto/rc4" //nolint:gosec // RFC 2831 requires RC4 for DIGEST-MD5 auth-conf interoperability.
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/xdg-go/scram"
	"github.com/xdg-go/stringprep"
)

const (
	ldapClientSASLMaxChallengeSize   = 64 << 10
	ldapClientCRAMMaxChallengeSize   = 1024
	ldapClientSCRAMMinIterations     = 4096
	ldapClientSCRAMMaxIterations     = 10_000_000
	ldapClientSCRAMMaxSaltSize       = 1024
	ldapClientSCRAMTLSEndpointPrefix = "tls-server-end-point:"
	ldapClientDigestMD5MaxBuffer     = 65536
	ldapClientDigestMD5MaxRFCBuffer  = 0xFFFFFF
	ldapClientDigestMD5Overhead      = 4 + 10 + 2 + 4
)

type ldapClientSASLResult struct {
	code                 uint16
	matchedDN            string
	serverCredentials    []byte
	hasServerCredentials bool
	packet               *ber.Packet
}

const (
	ldapClientDigestMD5SigningClientServer = "Digest session key to client-to-server signing key magic constant"
	ldapClientDigestMD5SigningServerClient = "Digest session key to server-to-client signing key magic constant"
	ldapClientDigestMD5SealingClientServer = "Digest H(A1) to client-to-server sealing key magic constant"
	ldapClientDigestMD5SealingServerClient = "Digest H(A1) to server-to-client sealing key magic constant"
	ldapClientDigestMD5MessageType         = 1
	ldapClientDigestMD5MACSize             = 10
)

const (
	ldapClientDigestMD5RC440Cipher = "rc4-40"
	ldapClientDigestMD5RC456Cipher = "rc4-56"
	ldapClientDigestMD5RC4Cipher   = "rc4"
	ldapClientDigestMD5DESCipher   = "des"
	ldapClientDigestMD53DESCipher  = "3des"
)

type ldapClientDigestMD5CipherMode uint8

const (
	ldapClientDigestMD5CipherModeRC4 ldapClientDigestMD5CipherMode = iota
	ldapClientDigestMD5CipherModeDES
	ldapClientDigestMD5CipherMode3DES
)

type ldapClientDigestMD5Cipher struct {
	name      string
	ssf       uint32
	keyPrefix int
	mode      ldapClientDigestMD5CipherMode
}

func ldapClientDigestMD5Ciphers() []ldapClientDigestMD5Cipher {
	return []ldapClientDigestMD5Cipher{
		{name: ldapClientDigestMD5RC440Cipher, ssf: 40, keyPrefix: 5, mode: ldapClientDigestMD5CipherModeRC4},
		{name: ldapClientDigestMD5RC456Cipher, ssf: 56, keyPrefix: 7, mode: ldapClientDigestMD5CipherModeRC4},
		{name: ldapClientDigestMD5RC4Cipher, ssf: 128, keyPrefix: md5.Size, mode: ldapClientDigestMD5CipherModeRC4},
		{name: ldapClientDigestMD5DESCipher, ssf: 55, keyPrefix: md5.Size, mode: ldapClientDigestMD5CipherModeDES},
		{name: ldapClientDigestMD53DESCipher, ssf: 112, keyPrefix: md5.Size, mode: ldapClientDigestMD5CipherMode3DES},
	}
}

var (
	errLDAPClientDigestMD5Integrity = errors.New("DIGEST-MD5 integrity check failed")
	errLDAPClientDigestMD5Sequence  = errors.New("DIGEST-MD5 sequence number is invalid")
	errLDAPClientDigestMD5Frame     = errors.New("DIGEST-MD5 security frame is invalid")
)

type ldapClientSASLSwitchConnection struct {
	mu         sync.RWMutex
	connection net.Conn
}

func (connection *ldapClientSASLSwitchConnection) Read(value []byte) (int, error) {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.Read(value)
}

func (connection *ldapClientSASLSwitchConnection) Write(value []byte) (int, error) {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.Write(value)
}

func (connection *ldapClientSASLSwitchConnection) Close() error {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.Close()
}

func (connection *ldapClientSASLSwitchConnection) LocalAddr() net.Addr {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.LocalAddr()
}

func (connection *ldapClientSASLSwitchConnection) RemoteAddr() net.Addr {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.RemoteAddr()
}

func (connection *ldapClientSASLSwitchConnection) SetDeadline(value time.Time) error {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.SetDeadline(value)
}

func (connection *ldapClientSASLSwitchConnection) SetReadDeadline(value time.Time) error {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.SetReadDeadline(value)
}

func (connection *ldapClientSASLSwitchConnection) SetWriteDeadline(value time.Time) error {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.connection.SetWriteDeadline(value)
}

func (connection *ldapClientSASLSwitchConnection) gssapiChannelBinding() ([]byte, error) {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	secured, ok := connection.connection.(interface {
		ConnectionState() tls.ConnectionState
	})
	if !ok {
		return nil, nil
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return nil, errors.New("TLS server certificate is unavailable for GSSAPI channel binding")
	}
	return saslkrb5.TLSServerEndpoint(state.PeerCertificates[0])
}

func (connection *ldapClientSASLSwitchConnection) scramChannelBinding() (
	scram.ChannelBinding,
	error,
) {
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	secured, ok := connection.connection.(interface {
		ConnectionState() tls.ConnectionState
	})
	if !ok {
		return scram.ChannelBinding{}, errors.New(
			"SCRAM-PLUS requires TLS with a verified server certificate",
		)
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 ||
		len(state.VerifiedChains) == 0 {
		return scram.ChannelBinding{}, errors.New(
			"SCRAM-PLUS requires TLS with a verified server certificate",
		)
	}
	applicationData, err := saslkrb5.TLSServerEndpoint(state.PeerCertificates[0])
	if err != nil {
		return scram.ChannelBinding{}, fmt.Errorf(
			"compute SCRAM tls-server-end-point channel binding: %w",
			err,
		)
	}
	defer clear(applicationData)
	prefix := []byte(ldapClientSCRAMTLSEndpointPrefix)
	if !bytes.HasPrefix(applicationData, prefix) || len(applicationData) == len(prefix) {
		return scram.ChannelBinding{}, errors.New(
			"TLS server certificate produced an invalid SCRAM channel binding",
		)
	}
	return scram.ChannelBinding{
		Type: scram.ChannelBindingTLSServerEndpoint,
		Data: bytes.Clone(applicationData[len(prefix):]),
	}, nil
}

func (connection *ldapClientSASLSwitchConnection) installDigestMD5Security(
	qop string,
	cipher ldapClientDigestMD5Cipher,
	sessionKey []byte,
	peerMaxBuffer,
	localMaxBuffer uint32,
) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	transport := connection.connection
	switch previous := transport.(type) {
	case *ldapClientDigestMD5IntegrityConnection:
		transport = previous.Conn
	case *ldapClientDigestMD5PrivacyConnection:
		transport = previous.Conn
	}
	var layer net.Conn
	var err error
	switch qop {
	case "auth-int":
		layer, err = newLDAPClientDigestMD5IntegrityConnection(
			transport,
			sessionKey,
			peerMaxBuffer,
			localMaxBuffer,
		)
	case "auth-conf":
		layer, err = newLDAPClientDigestMD5PrivacyConnection(
			transport,
			sessionKey,
			cipher,
			peerMaxBuffer,
			localMaxBuffer,
		)
	default:
		return fmt.Errorf("DIGEST-MD5 security qop %q is invalid", qop)
	}
	if err != nil {
		return err
	}
	connection.connection = layer
	return nil
}

func (connection *ldapClientSASLSwitchConnection) installGSSAPISecurity(
	key types.EncryptionKey,
	confidential bool,
	state saslkrb5.SecurityState,
	peerMaxBuffer,
	localMaxBuffer uint32,
) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	var layer net.Conn
	var err error
	if confidential {
		layer, err = saslkrb5.NewConfidentialityConnection(
			connection.connection,
			key,
			false,
			state,
			peerMaxBuffer,
			localMaxBuffer,
		)
	} else {
		layer, err = saslkrb5.NewIntegrityConnection(
			connection.connection,
			key,
			false,
			state,
			peerMaxBuffer,
			localMaxBuffer,
		)
	}
	if err != nil {
		return err
	}
	connection.connection = layer
	return nil
}

type ldapClientDigestMD5PrivacyConnection struct {
	net.Conn

	sendKey         [md5.Size]byte
	receiveKey      [md5.Size]byte
	sendCipher      *rc4.Cipher
	recvCipher      *rc4.Cipher
	sendBlockKey    [des.BlockSize * 3]byte
	receiveBlockKey [des.BlockSize * 3]byte
	blockKeySize    int
	sendIV          [des.BlockSize]byte
	receiveIV       [des.BlockSize]byte
	maxSend         uint32
	maxReceive      uint32

	writeMu     sync.Mutex
	readMu      sync.Mutex
	sendSeq     uint64
	receiveSeq  uint64
	readPending []byte
	closeOnce   sync.Once
	closeErr    error
}

func newLDAPClientDigestMD5PrivacyConnection(
	connection net.Conn,
	sessionKey []byte,
	cipher ldapClientDigestMD5Cipher,
	peerMaxBuffer,
	localMaxBuffer uint32,
) (*ldapClientDigestMD5PrivacyConnection, error) {
	if connection == nil {
		return nil, errors.New("DIGEST-MD5 security layer has no transport")
	}
	if len(sessionKey) != md5.Size {
		return nil, errors.New("DIGEST-MD5 session key has an invalid size")
	}
	knownCipher, ok := ldapClientDigestMD5CipherByName(cipher.name)
	if !ok || knownCipher != cipher {
		return nil, errors.New("DIGEST-MD5 confidentiality cipher is not supported")
	}
	if peerMaxBuffer == 0 {
		peerMaxBuffer = ldapClientDigestMD5MaxBuffer
	}
	if localMaxBuffer == 0 {
		localMaxBuffer = ldapClientDigestMD5MaxBuffer
	}
	privacyOverhead := uint32(25)
	if cipher.mode != ldapClientDigestMD5CipherModeRC4 {
		privacyOverhead = 29
	}
	invalidReceiveBuffer := localMaxBuffer <= ldapClientDigestMD5Overhead
	if cipher.mode != ldapClientDigestMD5CipherModeRC4 {
		invalidReceiveBuffer = localMaxBuffer < 4+2*des.BlockSize+2+4
	}
	if peerMaxBuffer <= privacyOverhead ||
		invalidReceiveBuffer ||
		peerMaxBuffer > ldapClientDigestMD5MaxRFCBuffer ||
		localMaxBuffer > ldapClientDigestMD5MaxRFCBuffer {
		return nil, errors.New("DIGEST-MD5 security maxbuf is invalid")
	}
	sendSeal, err := ldapClientDigestMD5SealingKey(
		sessionKey,
		cipher.keyPrefix,
		ldapClientDigestMD5SealingClientServer,
	)
	if err != nil {
		return nil, err
	}
	receiveSeal, err := ldapClientDigestMD5SealingKey(
		sessionKey,
		cipher.keyPrefix,
		ldapClientDigestMD5SealingServerClient,
	)
	if err != nil {
		clear(sendSeal[:])
		return nil, err
	}
	layer := &ldapClientDigestMD5PrivacyConnection{
		Conn:       connection,
		maxSend:    peerMaxBuffer - privacyOverhead,
		maxReceive: localMaxBuffer - 4,
	}
	switch cipher.mode {
	case ldapClientDigestMD5CipherModeRC4:
		layer.sendCipher, err = rc4.NewCipher(sendSeal[:]) //nolint:gosec // Required by RFC 2831.
		if err == nil {
			layer.recvCipher, err = rc4.NewCipher(receiveSeal[:]) //nolint:gosec // Required by RFC 2831.
		}
	case ldapClientDigestMD5CipherModeDES, ldapClientDigestMD5CipherMode3DES:
		layer.blockKeySize = ldapClientDigestMD5BlockKey(
			layer.sendBlockKey[:],
			layer.sendIV[:],
			sendSeal[:],
			cipher.mode == ldapClientDigestMD5CipherMode3DES,
		)
		_ = ldapClientDigestMD5BlockKey(
			layer.receiveBlockKey[:],
			layer.receiveIV[:],
			receiveSeal[:],
			cipher.mode == ldapClientDigestMD5CipherMode3DES,
		)
	default:
		err = errors.New("DIGEST-MD5 confidentiality cipher is not supported")
	}
	clear(sendSeal[:])
	clear(receiveSeal[:])
	if err != nil {
		clear(layer.sendBlockKey[:])
		clear(layer.receiveBlockKey[:])
		clear(layer.sendIV[:])
		clear(layer.receiveIV[:])
		return nil, err
	}
	layer.sendKey = ldapClientDigestMD5SigningKey(
		sessionKey,
		ldapClientDigestMD5SigningClientServer,
	)
	layer.receiveKey = ldapClientDigestMD5SigningKey(
		sessionKey,
		ldapClientDigestMD5SigningServerClient,
	)
	return layer, nil
}

func ldapClientDigestMD5BlockKey(
	destination,
	iv,
	sealingKey []byte,
	triple bool,
) int {
	first := ldapClientDigestMD5SlideDESKey(sealingKey[:7])
	copy(destination, first[:])
	clear(first[:])
	copy(iv, sealingKey[8:])
	if !triple {
		return des.BlockSize
	}
	second := ldapClientDigestMD5SlideDESKey(sealingKey[7:14])
	copy(destination[des.BlockSize:], second[:])
	copy(destination[2*des.BlockSize:], destination[:des.BlockSize])
	clear(second[:])
	return des.BlockSize * 3
}

func ldapClientDigestMD5SlideDESKey(value []byte) [des.BlockSize]byte {
	return [des.BlockSize]byte{
		value[0],
		value[0]<<7 | value[1]>>1,
		value[1]<<6 | value[2]>>2,
		value[2]<<5 | value[3]>>3,
		value[3]<<4 | value[4]>>4,
		value[4]<<3 | value[5]>>5,
		value[5]<<2 | value[6]>>6,
		value[6] << 1,
	}
}

func ldapClientDigestMD5CBC(
	key []byte,
	iv *[des.BlockSize]byte,
	value []byte,
	encrypt bool,
) {
	var block cipher.Block
	if len(key) == des.BlockSize {
		block, _ = des.NewCipher(key) //nolint:gosec // Required by RFC 2831.
	} else {
		block, _ = des.NewTripleDESCipher(key) //nolint:gosec // RFC 2831 specifies EDE2 as K1,K2,K1.
	}
	if encrypt {
		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(value, value)
		copy(iv[:], value[len(value)-des.BlockSize:])
		return
	}
	var nextIV [des.BlockSize]byte
	copy(nextIV[:], value[len(value)-des.BlockSize:])
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(value, value)
	copy(iv[:], nextIV[:])
	clear(nextIV[:])
}

func ldapClientDigestMD5CipherByName(name string) (ldapClientDigestMD5Cipher, bool) {
	for _, cipher := range ldapClientDigestMD5Ciphers() {
		if cipher.name == name {
			return cipher, true
		}
	}
	return ldapClientDigestMD5Cipher{}, false
}

func ldapClientDigestMD5SealingKey(
	sessionKey []byte,
	keyPrefix int,
	magic string,
) ([md5.Size]byte, error) {
	if len(sessionKey) != md5.Size || keyPrefix < 1 || keyPrefix > len(sessionKey) {
		return [md5.Size]byte{}, errors.New("DIGEST-MD5 sealing key parameters are invalid")
	}
	digest := md5.New() //nolint:gosec // Required by DIGEST-MD5.
	_, _ = digest.Write(sessionKey[:keyPrefix])
	_, _ = digest.Write([]byte(magic))
	var key [md5.Size]byte
	copy(key[:], digest.Sum(nil))
	return key, nil
}

func (connection *ldapClientDigestMD5PrivacyConnection) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	written := 0
	for written < len(value) {
		if connection.sendSeq > math.MaxUint32 {
			return written, errors.New("DIGEST-MD5 sequence space is exhausted")
		}
		chunkSize := len(value) - written
		if uint64(chunkSize) > uint64(connection.maxSend) {
			chunkSize = int(connection.maxSend)
		}
		frame := connection.encodeDigestMD5Frame(value[written:written+chunkSize], uint32(connection.sendSeq))
		err := ldapClientWriteDigestMD5Frame(connection.Conn, frame)
		clear(frame)
		if err != nil {
			return written, err
		}
		connection.sendSeq++
		written += chunkSize
	}
	return written, nil
}

func (connection *ldapClientDigestMD5PrivacyConnection) encodeDigestMD5Frame(
	message []byte,
	sequence uint32,
) []byte {
	paddingLength := 0
	if connection.blockKeySize != 0 {
		paddingLength = des.BlockSize - (len(message)+ldapClientDigestMD5MACSize)%des.BlockSize
	}
	encryptedLength := len(message) + paddingLength + ldapClientDigestMD5MACSize
	payloadLength := encryptedLength + 6
	frame := make([]byte, 4+payloadLength)
	binary.BigEndian.PutUint32(frame[:4], uint32(payloadLength))
	plaintext := make([]byte, encryptedLength)
	copy(plaintext, message)
	if paddingLength != 0 {
		for index := len(message); index < len(message)+paddingLength; index++ {
			plaintext[index] = byte(paddingLength)
		}
	}
	mac := ldapClientDigestMD5MAC(connection.sendKey[:], sequence, message)
	copy(plaintext[len(message)+paddingLength:], mac)
	clear(mac)
	copy(frame[4:4+encryptedLength], plaintext)
	if connection.blockKeySize != 0 {
		ldapClientDigestMD5CBC(
			connection.sendBlockKey[:connection.blockKeySize],
			&connection.sendIV,
			frame[4:4+encryptedLength],
			true,
		)
	} else {
		connection.sendCipher.XORKeyStream(frame[4:4+encryptedLength], plaintext)
	}
	clear(plaintext)
	offset := 4 + encryptedLength
	binary.BigEndian.PutUint16(frame[offset:offset+2], ldapClientDigestMD5MessageType)
	binary.BigEndian.PutUint32(frame[offset+2:offset+6], sequence)
	return frame
}

func (connection *ldapClientDigestMD5PrivacyConnection) Read(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	for len(connection.readPending) == 0 {
		message, err := connection.readDigestMD5Frame()
		if err != nil {
			return 0, err
		}
		connection.readPending = message
	}
	written := copy(value, connection.readPending)
	clear(connection.readPending[:written])
	connection.readPending = connection.readPending[written:]
	if len(connection.readPending) == 0 {
		connection.readPending = nil
	}
	return written, nil
}

func (connection *ldapClientDigestMD5PrivacyConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		connection.writeMu.Lock()
		connection.readMu.Lock()
		clear(connection.sendKey[:])
		clear(connection.receiveKey[:])
		if connection.sendCipher != nil {
			//lint:ignore SA1019 Reset is retained as best-effort cleanup for the legacy DIGEST-MD5 RC4 state.
			connection.sendCipher.Reset()
			connection.sendCipher = nil
		}
		if connection.recvCipher != nil {
			//lint:ignore SA1019 Reset is retained as best-effort cleanup for the legacy DIGEST-MD5 RC4 state.
			connection.recvCipher.Reset()
			connection.recvCipher = nil
		}
		clear(connection.sendBlockKey[:])
		clear(connection.receiveBlockKey[:])
		connection.blockKeySize = 0
		clear(connection.sendIV[:])
		clear(connection.receiveIV[:])
		clear(connection.readPending)
		connection.readPending = nil
		connection.readMu.Unlock()
		connection.writeMu.Unlock()
	})
	return connection.closeErr
}

func (connection *ldapClientDigestMD5PrivacyConnection) readDigestMD5Frame() ([]byte, error) {
	if connection.receiveSeq > math.MaxUint32 {
		return nil, errors.New("DIGEST-MD5 sequence space is exhausted")
	}
	var header [4]byte
	if _, err := io.ReadFull(connection.Conn, header[:]); err != nil {
		return nil, err
	}
	payloadLength := binary.BigEndian.Uint32(header[:])
	if payloadLength < ldapClientDigestMD5MACSize+6 || payloadLength > connection.maxReceive {
		return nil, fmt.Errorf("%w: payload length %d", errLDAPClientDigestMD5Frame, payloadLength)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(connection.Conn, payload); err != nil {
		clear(payload)
		return nil, err
	}
	typeOffset := len(payload) - 6
	messageType := binary.BigEndian.Uint16(payload[typeOffset : typeOffset+2])
	sequence := binary.BigEndian.Uint32(payload[typeOffset+2 : typeOffset+6])
	if messageType != ldapClientDigestMD5MessageType {
		clear(payload)
		return nil, fmt.Errorf("%w: message type %d", errLDAPClientDigestMD5Frame, messageType)
	}
	if uint64(sequence) != connection.receiveSeq {
		clear(payload)
		return nil, fmt.Errorf("%w: received %d, expected %d", errLDAPClientDigestMD5Sequence, sequence, connection.receiveSeq)
	}
	encryptedLength := typeOffset
	if connection.blockKeySize != 0 &&
		(encryptedLength < 2*des.BlockSize || encryptedLength%des.BlockSize != 0) {
		clear(payload)
		return nil, fmt.Errorf(
			"%w: encrypted payload length %d",
			errLDAPClientDigestMD5Frame,
			encryptedLength,
		)
	}
	plaintext := make([]byte, typeOffset)
	copy(plaintext, payload[:typeOffset])
	if connection.blockKeySize != 0 {
		ldapClientDigestMD5CBC(
			connection.receiveBlockKey[:connection.blockKeySize],
			&connection.receiveIV,
			plaintext,
			false,
		)
	} else {
		connection.recvCipher.XORKeyStream(plaintext, payload[:typeOffset])
	}
	clear(payload)
	messageLength := len(plaintext) - ldapClientDigestMD5MACSize
	validPadding := true
	if connection.blockKeySize != 0 {
		paddingLength, valid := ldapClientDigestMD5CBCPaddingLength(plaintext)
		validPadding = valid
		if valid {
			messageLength -= paddingLength
		}
	}
	expected := ldapClientDigestMD5MAC(connection.receiveKey[:], sequence, plaintext[:messageLength])
	receivedMAC := plaintext[len(plaintext)-ldapClientDigestMD5MACSize:]
	validMAC := subtle.ConstantTimeCompare(expected, receivedMAC) == 1
	valid := validPadding && validMAC
	clear(expected)
	if !valid {
		clear(plaintext)
		return nil, errLDAPClientDigestMD5Integrity
	}
	message := bytes.Clone(plaintext[:messageLength])
	clear(plaintext)
	connection.receiveSeq++
	return message, nil
}

func ldapClientDigestMD5CBCPaddingLength(plaintext []byte) (int, bool) {
	paddingBytes := len(plaintext) - ldapClientDigestMD5MACSize
	if paddingBytes < 1 {
		return 0, false
	}
	paddingLength := int(plaintext[len(plaintext)-ldapClientDigestMD5MACSize-1])
	valid := subtle.ConstantTimeLessOrEq(1, paddingLength) &
		subtle.ConstantTimeLessOrEq(paddingLength, des.BlockSize) &
		subtle.ConstantTimeLessOrEq(paddingLength, paddingBytes)
	checked := min(des.BlockSize, paddingBytes)
	for offset := 1; offset <= checked; offset++ {
		required := subtle.ConstantTimeLessOrEq(offset, paddingLength)
		equal := subtle.ConstantTimeByteEq(
			plaintext[len(plaintext)-ldapClientDigestMD5MACSize-offset],
			byte(paddingLength),
		)
		valid &= subtle.ConstantTimeSelect(required, equal, 1)
	}
	return paddingLength, valid == 1
}

type ldapClientDigestMD5IntegrityConnection struct {
	net.Conn

	sendKey    [md5.Size]byte
	receiveKey [md5.Size]byte
	maxSend    uint32
	maxReceive uint32

	writeMu     sync.Mutex
	readMu      sync.Mutex
	sendSeq     uint64
	receiveSeq  uint64
	readPending []byte
	closeOnce   sync.Once
	closeErr    error
}

func newLDAPClientDigestMD5IntegrityConnection(
	connection net.Conn,
	sessionKey []byte,
	peerMaxBuffer,
	localMaxBuffer uint32,
) (*ldapClientDigestMD5IntegrityConnection, error) {
	if connection == nil {
		return nil, errors.New("DIGEST-MD5 security layer has no transport")
	}
	if len(sessionKey) != md5.Size {
		return nil, errors.New("DIGEST-MD5 session key has an invalid size")
	}
	if peerMaxBuffer == 0 {
		peerMaxBuffer = ldapClientDigestMD5MaxBuffer
	}
	if localMaxBuffer == 0 {
		localMaxBuffer = ldapClientDigestMD5MaxBuffer
	}
	if peerMaxBuffer <= ldapClientDigestMD5Overhead ||
		localMaxBuffer <= ldapClientDigestMD5Overhead ||
		peerMaxBuffer > ldapClientDigestMD5MaxRFCBuffer ||
		localMaxBuffer > ldapClientDigestMD5MaxRFCBuffer {
		return nil, errors.New("DIGEST-MD5 security maxbuf is invalid")
	}
	layer := &ldapClientDigestMD5IntegrityConnection{
		Conn:       connection,
		maxSend:    peerMaxBuffer - ldapClientDigestMD5Overhead,
		maxReceive: localMaxBuffer - 4,
	}
	layer.sendKey = ldapClientDigestMD5SigningKey(
		sessionKey,
		ldapClientDigestMD5SigningClientServer,
	)
	layer.receiveKey = ldapClientDigestMD5SigningKey(
		sessionKey,
		ldapClientDigestMD5SigningServerClient,
	)
	return layer, nil
}

func ldapClientDigestMD5SigningKey(
	sessionKey []byte,
	magic string,
) [md5.Size]byte {
	digest := md5.New() //nolint:gosec // Required by DIGEST-MD5.
	_, _ = digest.Write(sessionKey)
	_, _ = digest.Write([]byte(magic))
	var key [md5.Size]byte
	copy(key[:], digest.Sum(nil))
	return key
}

func (connection *ldapClientDigestMD5IntegrityConnection) Write(
	value []byte,
) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	written := 0
	for written < len(value) {
		if connection.sendSeq > math.MaxUint32 {
			return written, errors.New("DIGEST-MD5 sequence space is exhausted")
		}
		chunkSize := len(value) - written
		if uint64(chunkSize) > uint64(connection.maxSend) {
			chunkSize = int(connection.maxSend)
		}
		frame := connection.encodeDigestMD5Frame(
			value[written:written+chunkSize],
			uint32(connection.sendSeq),
		)
		err := ldapClientWriteDigestMD5Frame(connection.Conn, frame)
		clear(frame)
		if err != nil {
			return written, err
		}
		connection.sendSeq++
		written += chunkSize
	}
	return written, nil
}

func (connection *ldapClientDigestMD5IntegrityConnection) encodeDigestMD5Frame(
	message []byte,
	sequence uint32,
) []byte {
	payloadLength := len(message) + ldapClientDigestMD5Overhead - 4
	frame := make([]byte, payloadLength+4)
	binary.BigEndian.PutUint32(frame[:4], uint32(payloadLength))
	copy(frame[4:], message)
	mac := ldapClientDigestMD5MAC(connection.sendKey[:], sequence, message)
	copy(frame[4+len(message):], mac)
	clear(mac)
	offset := 4 + len(message) + ldapClientDigestMD5MACSize
	binary.BigEndian.PutUint16(
		frame[offset:offset+2],
		ldapClientDigestMD5MessageType,
	)
	binary.BigEndian.PutUint32(frame[offset+2:offset+6], sequence)
	return frame
}

func ldapClientWriteDigestMD5Frame(writer io.Writer, frame []byte) error {
	for len(frame) != 0 {
		written, err := writer.Write(frame)
		if written > 0 {
			frame = frame[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (connection *ldapClientDigestMD5IntegrityConnection) Read(
	value []byte,
) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	for len(connection.readPending) == 0 {
		message, err := connection.readDigestMD5Frame()
		if err != nil {
			return 0, err
		}
		connection.readPending = message
	}
	written := copy(value, connection.readPending)
	clear(connection.readPending[:written])
	connection.readPending = connection.readPending[written:]
	if len(connection.readPending) == 0 {
		connection.readPending = nil
	}
	return written, nil
}

func (connection *ldapClientDigestMD5IntegrityConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		connection.writeMu.Lock()
		connection.readMu.Lock()
		clear(connection.sendKey[:])
		clear(connection.receiveKey[:])
		clear(connection.readPending)
		connection.readPending = nil
		connection.readMu.Unlock()
		connection.writeMu.Unlock()
	})
	return connection.closeErr
}

func (connection *ldapClientDigestMD5IntegrityConnection) readDigestMD5Frame() (
	[]byte,
	error,
) {
	if connection.receiveSeq > math.MaxUint32 {
		return nil, errors.New("DIGEST-MD5 sequence space is exhausted")
	}
	var header [4]byte
	if _, err := io.ReadFull(connection.Conn, header[:]); err != nil {
		return nil, err
	}
	payloadLength := binary.BigEndian.Uint32(header[:])
	if payloadLength < ldapClientDigestMD5Overhead-4 ||
		payloadLength > connection.maxReceive {
		return nil, fmt.Errorf(
			"%w: payload length %d",
			errLDAPClientDigestMD5Frame,
			payloadLength,
		)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(connection.Conn, payload); err != nil {
		clear(payload)
		return nil, err
	}
	messageLength := len(payload) - (ldapClientDigestMD5Overhead - 4)
	typeOffset := messageLength + ldapClientDigestMD5MACSize
	messageType := binary.BigEndian.Uint16(payload[typeOffset : typeOffset+2])
	sequence := binary.BigEndian.Uint32(payload[typeOffset+2 : typeOffset+6])
	if messageType != ldapClientDigestMD5MessageType {
		clear(payload)
		return nil, fmt.Errorf(
			"%w: message type %d",
			errLDAPClientDigestMD5Frame,
			messageType,
		)
	}
	if uint64(sequence) != connection.receiveSeq {
		clear(payload)
		return nil, fmt.Errorf(
			"%w: received %d, expected %d",
			errLDAPClientDigestMD5Sequence,
			sequence,
			connection.receiveSeq,
		)
	}
	expected := ldapClientDigestMD5MAC(
		connection.receiveKey[:],
		sequence,
		payload[:messageLength],
	)
	received := payload[messageLength : messageLength+ldapClientDigestMD5MACSize]
	valid := subtle.ConstantTimeCompare(expected, received) == 1
	clear(expected)
	if !valid {
		clear(payload)
		return nil, errLDAPClientDigestMD5Integrity
	}
	message := bytes.Clone(payload[:messageLength])
	clear(payload)
	connection.receiveSeq++
	return message, nil
}

func ldapClientDigestMD5MAC(
	key []byte,
	sequence uint32,
	message []byte,
) []byte {
	digest := hmac.New(md5.New, key) //nolint:gosec // Required by DIGEST-MD5.
	var encodedSequence [4]byte
	binary.BigEndian.PutUint32(encodedSequence[:], sequence)
	_, _ = digest.Write(encodedSequence[:])
	_, _ = digest.Write(message)
	result := digest.Sum(nil)
	mac := bytes.Clone(result[:ldapClientDigestMD5MACSize])
	clear(result)
	return mac
}

func (result ldapClientSASLResult) err() error {
	if result.code == ldap.LDAPResultSuccess {
		return nil
	}
	message := ldap.LDAPResultCodeMap[result.code]
	if message == "" {
		message = "LDAP SASL bind failed"
	}
	return &ldap.Error{
		ResultCode: result.code,
		MatchedDN:  result.matchedDN,
		Err:        errors.New(message),
		Packet:     result.packet,
	}
}

func (options *ldapClientOptions) validateSASL(
	flags *flag.FlagSet,
	passwordSources int,
) error {
	if !flagWasSet(flags, "Y") || strings.TrimSpace(options.saslMechanism) == "" {
		return errors.New("SASL authentication requires -Y with an explicit mechanism")
	}
	options.saslMechanism = strings.ToUpper(strings.TrimSpace(options.saslMechanism))
	for name, value := range map[string]string{
		"-U": options.saslAuthentication,
		"-X": options.saslAuthorization,
		"-R": options.saslRealm,
	} {
		if strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
			return fmt.Errorf("%s must be valid UTF-8 without NUL", name)
		}
	}

	switch options.saslMechanism {
	case "PLAIN":
		if options.saslAuthentication == "" {
			return errors.New("SASL PLAIN requires a non-empty -U authentication identity")
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources == 0 {
			return errors.New("SASL PLAIN requires one of -w, -W, or -y")
		}
	case "DIGEST-MD5":
		if options.saslAuthentication == "" {
			return errors.New("SASL DIGEST-MD5 requires a non-empty -U authentication identity")
		}
		if flagWasSet(flags, "R") && options.saslRealm == "" {
			return errors.New("-R requires a non-empty SASL realm")
		}
		if passwordSources == 0 {
			return errors.New("SASL DIGEST-MD5 requires one of -w, -W, or -y")
		}
		if _, err := parseLDAPClientDigestMD5SecurityProperties(options.saslSecurity); err != nil {
			return fmt.Errorf("invalid DIGEST-MD5 -O security properties: %w", err)
		}
	case "CRAM-MD5":
		if options.saslAuthentication == "" {
			return errors.New("SASL CRAM-MD5 requires a non-empty -U authentication identity")
		}
		if strings.ContainsAny(options.saslAuthentication, " \t\r\n") {
			return errors.New("SASL CRAM-MD5 -U authentication identity must not contain whitespace")
		}
		if flagWasSet(flags, "X") {
			return errors.New("SASL CRAM-MD5 does not support -X authorization identities")
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources == 0 {
			return errors.New("SASL CRAM-MD5 requires one of -w, -W, or -y")
		}
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512",
		"SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS":
		if options.saslAuthentication == "" {
			return fmt.Errorf(
				"SASL %s requires a non-empty -U authentication identity",
				options.saslMechanism,
			)
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources == 0 {
			return fmt.Errorf(
				"SASL %s requires one of -w, -W, or -y",
				options.saslMechanism,
			)
		}
		if ldapClientSCRAMIsPlus(options.saslMechanism) {
			parsed, err := url.Parse(options.uri)
			if err != nil || (!strings.EqualFold(parsed.Scheme, "ldaps") &&
				!options.tryStartTLS && !options.requireStartTLS) {
				return errors.New(
					"SCRAM-PLUS requires verified TLS; use ldaps:// or StartTLS",
				)
			}
		}
	case "EXTERNAL":
		if flagWasSet(flags, "U") {
			return errors.New("SASL EXTERNAL obtains its authentication identity from TLS; do not use -U")
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources != 0 {
			return errors.New("SASL EXTERNAL does not use -w, -W, or -y")
		}
		if !ldapClientURIUsesLDAPI(options.uri) &&
			(options.tlsCertificateFile == "" || options.tlsPrivateKeyFile == "") {
			return errors.New("SASL EXTERNAL requires -tls-cert and -tls-key or an ldapi:// URI")
		}
	case "GSSAPI":
		if passwordSources > 0 && options.saslAuthentication == "" {
			return errors.New("SASL GSSAPI password credentials require a non-empty -U authentication identity")
		}
		if flagWasSet(flags, "R") && options.saslRealm == "" {
			return errors.New("-R requires a non-empty SASL realm")
		}
		if _, err := parseLDAPClientDigestMD5SecurityProperties(options.saslSecurity); err != nil {
			return fmt.Errorf("invalid GSSAPI -O security properties: %w", err)
		}
		channelBinding, err := saslkrb5.NormalizeChannelBinding(
			options.gssapiChannelBinding,
		)
		if err != nil {
			return err
		}
		options.gssapiChannelBinding = channelBinding
	default:
		return fmt.Errorf(
			"unsupported SASL mechanism %q; supported mechanisms are PLAIN, CRAM-MD5, DIGEST-MD5, GSSAPI, SCRAM-SHA-1, SCRAM-SHA-256, SCRAM-SHA-512, their SCRAM-PLUS variants, and EXTERNAL",
			options.saslMechanism,
		)
	}
	if flagWasSet(flags, "O") && options.saslMechanism != "DIGEST-MD5" &&
		options.saslMechanism != "GSSAPI" {
		return errors.New("-O is only supported with SASL DIGEST-MD5 or GSSAPI")
	}
	if flagWasSet(flags, "gssapi-channel-binding") &&
		options.saslMechanism != "GSSAPI" {
		return errors.New("-gssapi-channel-binding is only supported with SASL GSSAPI")
	}
	if flagWasSet(flags, "X") && options.saslAuthorization == "" {
		return errors.New("-X requires a non-empty SASL authorization identity")
	}
	return nil
}

func (options *ldapClientOptions) connectAndBindSASL(
	parsedURI *url.URL,
	dialURI string,
	tlsConfig *tls.Config,
	password []byte,
	hasPassword bool,
	stderr io.Writer,
) (*ldap.Conn, error) {
	network := "tcp"
	address := parsedURI.Host
	serverName := parsedURI.Hostname()
	if parsedURI.Scheme == "ldapi" {
		network = "unix"
		address = parsedURI.Path
		if address == "" || address == "/" {
			address = "/var/run/slapd/ldapi"
		}
		serverName, _ = os.Hostname()
	} else if parsedURI.Port() == "" {
		port := "389"
		if parsedURI.Scheme == "ldaps" {
			port = "636"
		}
		address = net.JoinHostPort(parsedURI.Hostname(), port)
	}
	dial := func(useTLS bool) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: options.timeout}
		if useTLS {
			connection, err := tls.DialWithDialer(
				dialer,
				"tcp",
				address,
				tlsConfig.Clone(),
			)
			if err != nil {
				return nil, err
			}
			return connection, nil
		}
		return dialer.Dial(network, address)
	}

	connection, err := dial(parsedURI.Scheme == "ldaps")
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", dialURI, err)
	}
	closeOnError := func(err error) (*ldap.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	secure := parsedURI.Scheme == "ldaps"
	messageID := int64(1)
	if options.tryStartTLS || options.requireStartTLS {
		upgraded, startTLSErr := ldapClientSASLStartTLS(
			connection,
			tlsConfig,
			options.timeout,
			messageID,
		)
		messageID++
		if startTLSErr != nil {
			if options.requireStartTLS {
				return closeOnError(fmt.Errorf("StartTLS with %s: %w", dialURI, startTLSErr))
			}
			_ = connection.Close()
			if _, writeErr := fmt.Fprintf(
				stderr,
				"warning: StartTLS with %s failed; continuing over cleartext LDAP: %v\n",
				dialURI,
				startTLSErr,
			); writeErr != nil {
				return nil, writeErr
			}
			connection, err = dial(false)
			if err != nil {
				return nil, fmt.Errorf(
					"reconnect to %s after StartTLS failure: %w",
					dialURI,
					err,
				)
			}
			messageID = 1
		} else {
			connection = upgraded
			secure = true
		}
	}
	connection = &ldapClientSASLSwitchConnection{connection: connection}

	if !hasPassword && options.saslMechanism != "EXTERNAL" &&
		options.saslMechanism != "GSSAPI" {
		return closeOnError(fmt.Errorf("SASL %s password was not loaded", options.saslMechanism))
	}
	if err := connection.SetDeadline(time.Now().Add(options.timeout)); err != nil {
		return closeOnError(fmt.Errorf("set SASL bind deadline: %w", err))
	}
	if err := options.bindSASL(
		connection,
		serverName,
		password,
		hasPassword,
		&messageID,
	); err != nil {
		return closeOnError(err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return closeOnError(fmt.Errorf("clear SASL bind deadline: %w", err))
	}
	if options.observeSearch {
		observer := &ldapSearchResponseObserver{
			responses: make(map[int64][]ldapSearchWireResponse),
		}
		options.searchObserver = observer
		connection = &ldapSearchObservedConn{Conn: connection, observer: observer}
	}

	client := ldap.NewConn(connection, secure)
	client.SetTimeout(options.timeout)
	client.Start()
	return client, nil
}

func ldapClientSASLStartTLS(
	connection net.Conn,
	config *tls.Config,
	timeout time.Duration,
	messageID int64,
) (net.Conn, error) {
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name: ldapStartTLSOID,
		},
	})
	if err != nil {
		return nil, err
	}
	if err := ldapwire.Write(connection, request); err != nil {
		return nil, err
	}
	result, err := readLDAPClientSASLResult(
		connection,
		messageID,
		ldap.ApplicationExtendedResponse,
	)
	if err != nil {
		return nil, err
	}
	if err := result.err(); err != nil {
		return nil, err
	}
	upgraded := tls.Client(connection, config.Clone())
	if err := upgraded.Handshake(); err != nil {
		return nil, err
	}
	return upgraded, nil
}

func (options *ldapClientOptions) bindSASL(
	connection net.Conn,
	host string,
	password []byte,
	hasPassword bool,
	messageID *int64,
) error {
	switch options.saslMechanism {
	case "PLAIN":
		return options.bindSASLPlain(connection, password, messageID)
	case "DIGEST-MD5":
		return options.bindSASLDigestMD5(connection, host, password, messageID)
	case "CRAM-MD5":
		return options.bindSASLCRAMMD5(connection, password, messageID)
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512",
		"SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS":
		return options.bindSASLSCRAM(connection, password, messageID)
	case "EXTERNAL":
		return options.bindSASLExternal(connection, messageID)
	case "GSSAPI":
		return options.bindSASLGSSAPI(connection, host, password, hasPassword, messageID)
	default:
		return fmt.Errorf("unsupported SASL mechanism %q", options.saslMechanism)
	}
}

func (options *ldapClientOptions) bindSASLPlain(
	connection net.Conn,
	password []byte,
	messageID *int64,
) error {
	credentials := make([]byte, 0, len(options.saslAuthorization)+
		len(options.saslAuthentication)+len(password)+2)
	credentials = append(credentials, options.saslAuthorization...)
	credentials = append(credentials, 0)
	credentials = append(credentials, options.saslAuthentication...)
	credentials = append(credentials, 0)
	credentials = append(credentials, password...)
	defer clear(credentials)

	for round := 0; round < 2; round++ {
		result, err := exchangeLDAPClientSASLBind(
			connection,
			takeLDAPClientMessageID(messageID),
			"PLAIN",
			credentials,
			true,
		)
		if err != nil {
			return fmt.Errorf("SASL PLAIN bind: %w", err)
		}
		switch result.code {
		case ldap.LDAPResultSuccess:
			if result.hasServerCredentials {
				return errors.New("SASL PLAIN server returned unexpected credentials")
			}
			return nil
		case ldap.LDAPResultSaslBindInProgress:
			if round != 0 || len(result.serverCredentials) != 0 {
				return errors.New("SASL PLAIN server returned an unexpected challenge")
			}
		default:
			return fmt.Errorf("SASL PLAIN bind: %w", result.err())
		}
	}
	return errors.New("SASL PLAIN bind exceeded the challenge limit")
}

func (options *ldapClientOptions) bindSASLExternal(
	connection net.Conn,
	messageID *int64,
) error {
	hasCredentials := options.saslAuthorization != ""
	result, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"EXTERNAL",
		[]byte(options.saslAuthorization),
		hasCredentials,
	)
	if err != nil {
		return fmt.Errorf("SASL EXTERNAL bind: %w", err)
	}
	if result.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("SASL EXTERNAL bind: %w", result.err())
	}
	if result.hasServerCredentials {
		return errors.New("SASL EXTERNAL server returned unexpected credentials")
	}
	return nil
}

func (options *ldapClientOptions) bindSASLCRAMMD5(
	connection net.Conn,
	password []byte,
	messageID *int64,
) error {
	first, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"CRAM-MD5",
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("SASL CRAM-MD5 bind: %w", err)
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		if resultErr := first.err(); resultErr != nil {
			return fmt.Errorf("SASL CRAM-MD5 bind: %w", resultErr)
		}
		return errors.New("SASL CRAM-MD5 server completed without a challenge")
	}
	if err := validateLDAPClientCRAMMD5Challenge(
		first.serverCredentials,
		first.hasServerCredentials,
	); err != nil {
		return err
	}
	authenticationID, err := stringprep.SASLprep.Prepare(
		options.saslAuthentication,
	)
	if err != nil || authenticationID == "" ||
		strings.ContainsAny(authenticationID, " \t\r\n") {
		return errors.New("SASL CRAM-MD5 authentication identity is not a valid SASLprep value")
	}
	mac := hmac.New(md5.New, password) //nolint:gosec // CRAM-MD5 requires HMAC-MD5.
	_, _ = mac.Write(first.serverCredentials)
	macSum := mac.Sum(nil)
	digest := make([]byte, hex.EncodedLen(md5.Size))
	hex.Encode(digest, macSum)
	clear(macSum)
	response := make([]byte, 0, len(authenticationID)+1+len(digest))
	response = append(response, authenticationID...)
	response = append(response, ' ')
	response = append(response, digest...)
	clear(digest)
	defer clear(response)

	final, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"CRAM-MD5",
		response,
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL CRAM-MD5 bind: %w", err)
	}
	if final.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("SASL CRAM-MD5 bind: %w", final.err())
	}
	if final.hasServerCredentials {
		return errors.New("SASL CRAM-MD5 server returned unexpected final credentials")
	}
	return nil
}

func validateLDAPClientCRAMMD5Challenge(challenge []byte, present bool) error {
	if !present || len(challenge) < 5 || len(challenge) > ldapClientCRAMMaxChallengeSize ||
		challenge[0] != '<' || challenge[len(challenge)-1] != '>' {
		return errors.New("SASL CRAM-MD5 server returned a malformed challenge")
	}
	at := bytes.LastIndexByte(challenge, '@')
	if at <= 1 || at >= len(challenge)-2 || bytes.IndexByte(challenge[1:at], '@') >= 0 {
		return errors.New("SASL CRAM-MD5 challenge is not a valid message ID")
	}
	for _, value := range challenge[1 : len(challenge)-1] {
		if value <= 0x20 || value >= 0x7f || value == '<' || value == '>' {
			return errors.New("SASL CRAM-MD5 challenge contains invalid bytes")
		}
	}
	return nil
}

func (options *ldapClientOptions) bindSASLSCRAM(
	connection net.Conn,
	password []byte,
	messageID *int64,
) error {
	generator, ok := ldapClientSCRAMGenerator(options.saslMechanism)
	if !ok {
		return fmt.Errorf("unsupported SCRAM mechanism %q", options.saslMechanism)
	}
	client, err := generator.NewClient(
		options.saslAuthentication,
		string(password),
		options.saslAuthorization,
	)
	if err != nil {
		return fmt.Errorf("SASL %s credentials are not valid SASLprep values", options.saslMechanism)
	}
	client.WithMinIterations(ldapClientSCRAMMinIterations)
	var conversation *scram.ClientConversation
	if ldapClientSCRAMIsPlus(options.saslMechanism) {
		switchable, ok := connection.(*ldapClientSASLSwitchConnection)
		if !ok {
			return errors.New("SCRAM-PLUS requires a switchable TLS connection")
		}
		binding, err := switchable.scramChannelBinding()
		if err != nil {
			return err
		}
		defer clear(binding.Data)
		conversation = client.NewConversationWithChannelBinding(binding)
	} else {
		conversation = client.NewConversation()
	}
	clientFirst, err := conversation.Step("")
	if err != nil {
		return fmt.Errorf("initialize SASL %s conversation", options.saslMechanism)
	}
	clientNonce, err := ldapClientSCRAMClientNonce(clientFirst)
	if err != nil {
		return fmt.Errorf("initialize SASL %s nonce: %w", options.saslMechanism, err)
	}

	first, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		options.saslMechanism,
		[]byte(clientFirst),
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, err)
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		if resultErr := first.err(); resultErr != nil {
			return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, resultErr)
		}
		return fmt.Errorf("SASL %s server completed before sending server-first", options.saslMechanism)
	}
	serverFirst := first.serverCredentials
	if !first.hasServerCredentials {
		return fmt.Errorf("SASL %s server omitted server-first", options.saslMechanism)
	}
	if err := validateLDAPClientSCRAMServerFirst(serverFirst, clientNonce); err != nil {
		return fmt.Errorf("SASL %s server-first: %w", options.saslMechanism, err)
	}
	clientFinal, err := conversation.Step(string(serverFirst))
	if err != nil {
		return fmt.Errorf("SASL %s server-first was rejected", options.saslMechanism)
	}

	clientFinalBytes := []byte(clientFinal)
	defer clear(clientFinalBytes)
	final, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		options.saslMechanism,
		clientFinalBytes,
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, err)
	}
	if final.code != ldap.LDAPResultSuccess &&
		final.code != ldap.LDAPResultSaslBindInProgress {
		return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, final.err())
	}
	if !final.hasServerCredentials {
		return fmt.Errorf("SASL %s server omitted server-final proof", options.saslMechanism)
	}
	if err := validateLDAPClientSCRAMServerFinal(
		final.serverCredentials,
		generator().Size(),
	); err != nil {
		return fmt.Errorf("SASL %s server-final: %w", options.saslMechanism, err)
	}
	if response, err := conversation.Step(string(final.serverCredentials)); err != nil || response != "" || !conversation.Done() || !conversation.Valid() {
		return fmt.Errorf("SASL %s server signature is invalid", options.saslMechanism)
	}
	if final.code == ldap.LDAPResultSuccess {
		return nil
	}

	completed, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		options.saslMechanism,
		[]byte{},
		true,
	)
	if err != nil {
		return fmt.Errorf("complete SASL %s bind: %w", options.saslMechanism, err)
	}
	if completed.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("complete SASL %s bind: %w", options.saslMechanism, completed.err())
	}
	if completed.hasServerCredentials {
		return fmt.Errorf("SASL %s server returned unexpected completion data", options.saslMechanism)
	}
	return nil
}

func ldapClientSCRAMGenerator(mechanism string) (scram.HashGeneratorFcn, bool) {
	switch strings.TrimSuffix(mechanism, "-PLUS") {
	case "SCRAM-SHA-1":
		return scram.SHA1, true
	case "SCRAM-SHA-256":
		return scram.SHA256, true
	case "SCRAM-SHA-512":
		return scram.SHA512, true
	default:
		return nil, false
	}
}

func ldapClientSCRAMIsPlus(mechanism string) bool {
	return strings.HasSuffix(mechanism, "-PLUS")
}

func ldapClientSCRAMClientNonce(clientFirst string) (string, error) {
	fields := strings.Split(clientFirst, ",")
	validGS2Flag := fields[0] == "n" || fields[0] == "y" ||
		fields[0] == "p=tls-server-end-point"
	if len(fields) != 4 || !validGS2Flag ||
		(fields[1] != "" && !strings.HasPrefix(fields[1], "a=")) ||
		!strings.HasPrefix(fields[2], "n=") || !strings.HasPrefix(fields[3], "r=") {
		return "", errors.New("SCRAM client-first message is malformed")
	}
	nonce := strings.TrimPrefix(fields[3], "r=")
	if !ldapClientSCRAMNonceValid(nonce) {
		return "", errors.New("SCRAM client nonce is malformed")
	}
	return nonce, nil
}

func validateLDAPClientSCRAMServerFirst(serverFirst []byte, clientNonce string) error {
	if len(serverFirst) == 0 || len(serverFirst) > ldapClientSASLMaxChallengeSize ||
		!utf8.Valid(serverFirst) || bytes.IndexByte(serverFirst, 0) >= 0 {
		return errors.New("server-first has invalid encoding or size")
	}
	fields := strings.Split(string(serverFirst), ",")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "r=") ||
		!strings.HasPrefix(fields[1], "s=") || !strings.HasPrefix(fields[2], "i=") {
		return errors.New("server-first must contain only canonical r, s, and i fields")
	}
	nonce := strings.TrimPrefix(fields[0], "r=")
	if len(nonce) <= len(clientNonce) || !strings.HasPrefix(nonce, clientNonce) ||
		!ldapClientSCRAMNonceValid(nonce) {
		return errors.New("server nonce did not strictly extend the client nonce")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(fields[1], "s="))
	if err != nil || len(salt) == 0 || len(salt) > ldapClientSCRAMMaxSaltSize {
		clear(salt)
		return errors.New("server salt is malformed")
	}
	clear(salt)
	rawIterations := strings.TrimPrefix(fields[2], "i=")
	if rawIterations == "" || (len(rawIterations) > 1 && rawIterations[0] == '0') {
		return errors.New("server iteration count is not canonical")
	}
	for _, value := range rawIterations {
		if value < '0' || value > '9' {
			return errors.New("server iteration count is malformed")
		}
	}
	iterations, err := strconv.ParseUint(rawIterations, 10, 32)
	if err != nil || iterations < ldapClientSCRAMMinIterations ||
		iterations > ldapClientSCRAMMaxIterations {
		return fmt.Errorf(
			"server iteration count must be between %d and %d",
			ldapClientSCRAMMinIterations,
			ldapClientSCRAMMaxIterations,
		)
	}
	return nil
}

func validateLDAPClientSCRAMServerFinal(serverFinal []byte, hashSize int) error {
	if len(serverFinal) == 0 || len(serverFinal) > ldapClientSASLMaxChallengeSize ||
		!utf8.Valid(serverFinal) || bytes.IndexByte(serverFinal, 0) >= 0 {
		return errors.New("server-final has invalid encoding or size")
	}
	text := string(serverFinal)
	if strings.Contains(text, ",") || !strings.HasPrefix(text, "v=") {
		return errors.New("server-final must contain only a verifier")
	}
	verifier, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(text, "v="))
	if err != nil || len(verifier) != hashSize {
		clear(verifier)
		return errors.New("server-final verifier is malformed")
	}
	clear(verifier)
	return nil
}

func ldapClientSCRAMNonceValid(nonce string) bool {
	if nonce == "" {
		return false
	}
	for _, value := range []byte(nonce) {
		if value < 0x21 || value > 0x7e || value == ',' {
			return false
		}
	}
	return true
}

func (options *ldapClientOptions) bindSASLDigestMD5(
	connection net.Conn,
	host string,
	password []byte,
	messageID *int64,
) error {
	first, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"DIGEST-MD5",
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("SASL DIGEST-MD5 bind: %w", err)
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		if resultErr := first.err(); resultErr != nil {
			return fmt.Errorf("SASL DIGEST-MD5 bind: %w", resultErr)
		}
		return errors.New("SASL DIGEST-MD5 server completed without a challenge")
	}
	if !first.hasServerCredentials {
		return errors.New("SASL DIGEST-MD5 server omitted its challenge")
	}
	_, canInstallSecurity := connection.(*ldapClientSASLSwitchConnection)
	response, expectedRspauth, negotiated, err := options.digestMD5Response(
		first.serverCredentials,
		host,
		password,
		canInstallSecurity,
	)
	if err != nil {
		return fmt.Errorf("process SASL DIGEST-MD5 challenge: %w", err)
	}
	defer clear(response)
	defer clear(expectedRspauth)
	if negotiated != nil {
		defer negotiated.clear()
	}

	second, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"DIGEST-MD5",
		response,
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL DIGEST-MD5 bind: %w", err)
	}
	if second.code != ldap.LDAPResultSuccess &&
		second.code != ldap.LDAPResultSaslBindInProgress {
		return fmt.Errorf("SASL DIGEST-MD5 bind: %w", second.err())
	}
	if err := verifyLDAPClientDigestMD5Rspauth(
		second.serverCredentials,
		second.hasServerCredentials,
		expectedRspauth,
	); err != nil {
		return err
	}
	if second.code == ldap.LDAPResultSuccess {
		return installLDAPClientDigestMD5SecurityLayer(
			connection,
			negotiated,
		)
	}

	final, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"DIGEST-MD5",
		[]byte{},
		true,
	)
	if err != nil {
		return fmt.Errorf("complete SASL DIGEST-MD5 bind: %w", err)
	}
	if final.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("complete SASL DIGEST-MD5 bind: %w", final.err())
	}
	if final.hasServerCredentials {
		return errors.New("SASL DIGEST-MD5 server returned unexpected final credentials")
	}
	return installLDAPClientDigestMD5SecurityLayer(connection, negotiated)
}

func installLDAPClientDigestMD5SecurityLayer(
	connection net.Conn,
	negotiated *ldapClientDigestMD5NegotiatedSecurity,
) error {
	if negotiated == nil {
		return nil
	}
	switching, ok := connection.(*ldapClientSASLSwitchConnection)
	if !ok {
		return errors.New("SASL DIGEST-MD5 security layer requires a switchable connection")
	}
	if err := switching.installDigestMD5Security(
		negotiated.qop,
		negotiated.cipher,
		negotiated.sessionKey,
		negotiated.peerMaxBuffer,
		negotiated.localMaxBuffer,
	); err != nil {
		return fmt.Errorf("install SASL DIGEST-MD5 %s layer: %w", negotiated.qop, err)
	}
	return nil
}

func takeLDAPClientMessageID(next *int64) int64 {
	messageID := *next
	*next = messageID + 1
	return messageID
}

func exchangeLDAPClientSASLBind(
	connection net.Conn,
	messageID int64,
	mechanism string,
	credentials []byte,
	hasCredentials bool,
) (ldapClientSASLResult, error) {
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.BindRequest{
			Version: 3,
			Authentication: ldapwire.Authentication{
				IsSASL:             true,
				SASLMechanism:      mechanism,
				SASLCredentials:    credentials,
				HasSASLCredentials: hasCredentials,
			},
		},
	})
	if err != nil {
		return ldapClientSASLResult{}, err
	}
	defer clear(request)
	if err := ldapwire.Write(connection, request); err != nil {
		return ldapClientSASLResult{}, err
	}
	return readLDAPClientSASLResult(
		connection,
		messageID,
		ldap.ApplicationBindResponse,
	)
}

func readLDAPClientSASLResult(
	reader io.Reader,
	messageID int64,
	responseTag uint64,
) (ldapClientSASLResult, error) {
	packet, err := ber.ReadPacket(io.LimitReader(reader, ldapClientSASLMaxChallengeSize))
	if err != nil {
		return ldapClientSASLResult{}, fmt.Errorf("read LDAP response: %w", err)
	}
	if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypeConstructed, uint64(ber.TagSequence)) ||
		len(packet.Children) < 2 || len(packet.Children) > 3 {
		return ldapClientSASLResult{}, errors.New("malformed LDAP response envelope")
	}
	if len(packet.Children) == 3 &&
		!ldapClientPacketIs(packet.Children[2], ber.ClassContext, ber.TypeConstructed, 0) {
		return ldapClientSASLResult{}, errors.New("malformed LDAP response controls")
	}
	id, ok := ldapClientPacketInteger(packet.Children[0])
	if !ok || id != messageID {
		return ldapClientSASLResult{}, errors.New("LDAP response has an unexpected message ID")
	}
	operation := packet.Children[1]
	if !ldapClientPacketIs(operation, ber.ClassApplication, ber.TypeConstructed, responseTag) ||
		len(operation.Children) < 3 {
		return ldapClientSASLResult{}, errors.New("malformed LDAP result response")
	}
	code, ok := ldapClientPacketInteger(operation.Children[0])
	if !ok || code < 0 || code > 65535 {
		return ldapClientSASLResult{}, errors.New("malformed LDAP result code")
	}
	matchedDN, ok := ldapClientPacketBytes(operation.Children[1])
	if !ok {
		return ldapClientSASLResult{}, errors.New("malformed LDAP matched DN")
	}
	_, ok = ldapClientPacketBytes(operation.Children[2])
	if !ok {
		return ldapClientSASLResult{}, errors.New("malformed LDAP diagnostic message")
	}
	result := ldapClientSASLResult{
		code:      uint16(code),
		matchedDN: string(matchedDN),
		packet:    packet,
	}
	for _, child := range operation.Children[3:] {
		if responseTag == ldap.ApplicationBindResponse &&
			ldapClientPacketIs(child, ber.ClassContext, ber.TypePrimitive, 7) {
			if result.hasServerCredentials {
				return ldapClientSASLResult{}, errors.New("duplicate server SASL credentials")
			}
			result.serverCredentials = bytes.Clone(child.Data.Bytes())
			result.hasServerCredentials = true
			continue
		}
		if ldapClientPacketIs(child, ber.ClassContext, ber.TypeConstructed, 3) {
			for _, referral := range child.Children {
				if _, ok := ldapClientPacketBytes(referral); !ok {
					return ldapClientSASLResult{}, errors.New("malformed LDAP referral")
				}
			}
			continue
		}
		if responseTag == ldap.ApplicationExtendedResponse &&
			child.ClassType == ber.ClassContext && child.TagType == ber.TypePrimitive &&
			(child.Tag == 10 || child.Tag == 11) {
			continue
		}
		return ldapClientSASLResult{}, errors.New("LDAP response contains an unexpected element")
	}
	return result, nil
}

func ldapClientPacketIs(packet *ber.Packet, class ber.Class, kind ber.Type, tag uint64) bool {
	return packet != nil && packet.ClassType == class && packet.TagType == kind &&
		uint64(packet.Tag) == tag
}

func ldapClientPacketInteger(packet *ber.Packet) (int64, bool) {
	if packet == nil || packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypePrimitive ||
		(packet.Tag != ber.TagInteger && packet.Tag != ber.TagEnumerated) {
		return 0, false
	}
	value, ok := packet.Value.(int64)
	return value, ok
}

func ldapClientPacketBytes(packet *ber.Packet) ([]byte, bool) {
	if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypePrimitive, uint64(ber.TagOctetString)) ||
		packet.Data == nil {
		return nil, false
	}
	return bytes.Clone(packet.Data.Bytes()), true
}

func bytesContainNUL(value []byte) bool {
	return bytes.IndexByte(value, 0) >= 0
}

type ldapClientDigestMD5Values struct {
	username      string
	realm         string
	nonce         string
	cnonce        string
	digestURI     string
	authorization string
	qop           string
	convertLatin1 bool
}

type ldapClientDigestMD5NegotiatedSecurity struct {
	sessionKey     []byte
	peerMaxBuffer  uint32
	localMaxBuffer uint32
	qop            string
	cipher         ldapClientDigestMD5Cipher
}

type ldapClientDigestMD5SecurityProperties struct {
	minimumSSF    uint32
	maximumSSF    uint32
	maxBufferSize uint32
}

func parseLDAPClientDigestMD5SecurityProperties(
	value string,
) (ldapClientDigestMD5SecurityProperties, error) {
	properties := ldapClientDigestMD5SecurityProperties{
		maximumSSF:    math.MaxInt32,
		maxBufferSize: ldapClientDigestMD5MaxBuffer,
	}
	if strings.TrimSpace(value) == "" {
		return properties, nil
	}
	for _, raw := range strings.Split(value, ",") {
		part := strings.ToLower(strings.TrimSpace(raw))
		if part == "" {
			return ldapClientDigestMD5SecurityProperties{}, errors.New("empty property")
		}
		if part == "none" {
			continue
		}
		name, encoded, ok := strings.Cut(part, "=")
		if !ok || encoded == "" {
			return ldapClientDigestMD5SecurityProperties{}, fmt.Errorf("unsupported property %q", raw)
		}
		parsed, err := strconv.ParseUint(encoded, 10, 31)
		if err != nil {
			return ldapClientDigestMD5SecurityProperties{}, fmt.Errorf("invalid %s value", name)
		}
		switch name {
		case "minssf":
			properties.minimumSSF = uint32(parsed)
		case "maxssf":
			properties.maximumSSF = uint32(parsed)
		case "maxbufsize":
			if parsed > ldapClientDigestMD5MaxRFCBuffer {
				return ldapClientDigestMD5SecurityProperties{}, errors.New("maxbufsize exceeds RFC limit")
			}
			properties.maxBufferSize = uint32(parsed)
		default:
			return ldapClientDigestMD5SecurityProperties{}, fmt.Errorf("unsupported property %q", name)
		}
	}
	if properties.minimumSSF > properties.maximumSSF {
		return ldapClientDigestMD5SecurityProperties{}, errors.New("minssf exceeds maxssf")
	}
	return properties, nil
}

func (security *ldapClientDigestMD5NegotiatedSecurity) clear() {
	if security == nil {
		return
	}
	clear(security.sessionKey)
	security.sessionKey = nil
}

func (options *ldapClientOptions) digestMD5Response(
	challenge []byte,
	host string,
	password []byte,
	canInstallSecurity bool,
) ([]byte, []byte, *ldapClientDigestMD5NegotiatedSecurity, error) {
	directives, realms, err := parseLDAPClientDigestMD5Directives(challenge, true)
	if err != nil {
		return nil, nil, nil, err
	}
	if !strings.EqualFold(directives["algorithm"], "md5-sess") {
		return nil, nil, nil, errors.New("DIGEST-MD5 challenge does not use md5-sess")
	}
	if charset, present := directives["charset"]; present &&
		!strings.EqualFold(charset, "utf-8") {
		return nil, nil, nil, errors.New("DIGEST-MD5 challenge uses an unsupported charset")
	}
	if _, utf8Offered := directives["charset"]; utf8Offered && !utf8.Valid(password) {
		return nil, nil, nil, errors.New("DIGEST-MD5 password is not valid UTF-8")
	}
	if stale, present := directives["stale"]; present && strings.EqualFold(stale, "true") {
		return nil, nil, nil, errors.New("DIGEST-MD5 server marked its nonce stale")
	}
	nonce := directives["nonce"]
	if nonce == "" {
		return nil, nil, nil, errors.New("DIGEST-MD5 challenge has no nonce")
	}
	offeredQOP := directives["qop"]
	if offeredQOP == "" {
		offeredQOP = "auth"
	}
	properties, err := parseLDAPClientDigestMD5SecurityProperties(options.saslSecurity)
	if err != nil {
		return nil, nil, nil, err
	}
	qop := ""
	var selectedCipher ldapClientDigestMD5Cipher
	if canInstallSecurity && properties.maxBufferSize != 0 &&
		ldapClientDigestMD5ListContains(offeredQOP, "auth-conf") {
		offeredCiphers := directives["cipher"]
		for _, cipher := range ldapClientDigestMD5Ciphers() {
			if cipher.ssf >= properties.minimumSSF && cipher.ssf <= properties.maximumSSF &&
				ldapClientDigestMD5ListContains(offeredCiphers, cipher.name) &&
				(qop == "" || cipher.ssf > selectedCipher.ssf) {
				selectedCipher = cipher
				qop = "auth-conf"
			}
		}
	}
	if qop == "" && canInstallSecurity && properties.maxBufferSize != 0 &&
		properties.minimumSSF <= 1 && properties.maximumSSF >= 1 &&
		ldapClientDigestMD5ListContains(offeredQOP, "auth-int") {
		qop = "auth-int"
	}
	if qop == "" && properties.minimumSSF == 0 &&
		ldapClientDigestMD5ListContains(offeredQOP, "auth") {
		qop = "auth"
	}
	if qop == "" {
		if !canInstallSecurity &&
			(ldapClientDigestMD5ListContains(offeredQOP, "auth-int") ||
				ldapClientDigestMD5ListContains(offeredQOP, "auth-conf")) {
			return nil, nil, nil, errors.New(
				"DIGEST-MD5 server requires a security layer but this transport cannot install it",
			)
		}
		return nil, nil, nil, errors.New("DIGEST-MD5 challenge offers no acceptable qop or cipher")
	}
	peerMaxBuffer := uint32(ldapClientDigestMD5MaxBuffer)
	if rawMaximum, present := directives["maxbuf"]; present {
		maximum, parseErr := strconv.ParseUint(rawMaximum, 10, 24)
		if parseErr != nil || maximum <= 16 ||
			maximum > ldapClientDigestMD5MaxRFCBuffer {
			return nil, nil, nil, errors.New("DIGEST-MD5 challenge has invalid maxbuf")
		}
		peerMaxBuffer = uint32(maximum)
	}
	minimumPeerBuffer := uint32(ldapClientDigestMD5Overhead)
	if qop == "auth-conf" {
		minimumPeerBuffer = 25
	}
	if qop != "auth" && peerMaxBuffer <= minimumPeerBuffer {
		return nil, nil, nil, errors.New(
			"DIGEST-MD5 challenge maxbuf is too small for the selected security layer",
		)
	}
	realm := options.saslRealm
	if realm == "" && len(realms) > 0 {
		realm = realms[0]
	}
	if options.saslRealm != "" && len(realms) > 0 &&
		!ldapClientStringSliceContains(realms, options.saslRealm) {
		return nil, nil, nil, errors.New("requested DIGEST-MD5 realm was not offered by the server")
	}
	entropy := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, nil, nil, fmt.Errorf("generate DIGEST-MD5 cnonce: %w", err)
	}
	cnonce := base64.RawStdEncoding.EncodeToString(entropy)
	clear(entropy)
	values := ldapClientDigestMD5Values{
		username:      options.saslAuthentication,
		realm:         realm,
		nonce:         nonce,
		cnonce:        cnonce,
		digestURI:     "ldap/" + strings.ToLower(host),
		authorization: options.saslAuthorization,
		qop:           qop,
	}
	if _, utf8Offered := directives["charset"]; utf8Offered {
		values.convertLatin1 = ldapClientDigestMD5CanUseLatin1(
			[]byte(values.username),
		) && ldapClientDigestMD5CanUseLatin1(
			[]byte(values.realm),
		) && ldapClientDigestMD5CanUseLatin1(password)
	}
	responseDigest, rspauth := ldapClientDigestMD5Exchange(values, password)
	response := fmt.Sprintf(
		`username="%s",realm="%s",nonce="%s",cnonce="%s",nc=00000001,`+
			`qop=%s,digest-uri="%s",response=%s`,
		ldapClientDigestMD5Quote(values.username),
		ldapClientDigestMD5Quote(values.realm),
		ldapClientDigestMD5Quote(values.nonce),
		ldapClientDigestMD5Quote(values.cnonce),
		values.qop,
		ldapClientDigestMD5Quote(values.digestURI),
		responseDigest,
	)
	if values.authorization != "" {
		response += `,authzid="` + ldapClientDigestMD5Quote(values.authorization) + `"`
	}
	if _, present := directives["charset"]; present {
		response += ",charset=utf-8"
	}
	var negotiated *ldapClientDigestMD5NegotiatedSecurity
	if qop == "auth-conf" {
		response += ",cipher=" + selectedCipher.name
	}
	if qop == "auth-int" || qop == "auth-conf" {
		response += ",maxbuf=" + strconv.FormatUint(
			uint64(properties.maxBufferSize),
			10,
		)
		negotiated = &ldapClientDigestMD5NegotiatedSecurity{
			sessionKey:     ldapClientDigestMD5SessionKey(values, password),
			peerMaxBuffer:  peerMaxBuffer,
			localMaxBuffer: properties.maxBufferSize,
			qop:            qop,
			cipher:         selectedCipher,
		}
	}
	return []byte(response), []byte(rspauth), negotiated, nil
}

func ldapClientDigestMD5Exchange(
	values ldapClientDigestMD5Values,
	password []byte,
) (string, string) {
	qop := values.qop
	if qop == "" {
		qop = "auth"
	}
	binarySessionKey := ldapClientDigestMD5SessionKey(values, password)
	defer clear(binarySessionKey)
	sessionKey := hex.EncodeToString(binarySessionKey)
	calculate := func(method string) string {
		a2Value := method + ":" + values.digestURI
		if qop == "auth-int" || qop == "auth-conf" {
			a2Value += ":00000000000000000000000000000000"
		}
		a2 := md5.Sum([]byte(a2Value)) //nolint:gosec
		material := strings.Join([]string{
			sessionKey,
			values.nonce,
			"00000001",
			values.cnonce,
			qop,
			hex.EncodeToString(a2[:]),
		}, ":")
		digest := md5.Sum([]byte(material)) //nolint:gosec
		return hex.EncodeToString(digest[:])
	}
	return calculate("AUTHENTICATE"), calculate("")
}

func ldapClientDigestMD5SessionKey(
	values ldapClientDigestMD5Values,
	password []byte,
) []byte {
	secretHash := md5.New() //nolint:gosec // Required by DIGEST-MD5.
	ldapClientWriteDigestMD5Secret(
		secretHash,
		[]byte(values.username),
		values.convertLatin1,
	)
	_, _ = secretHash.Write([]byte{':'})
	ldapClientWriteDigestMD5Secret(
		secretHash,
		[]byte(values.realm),
		values.convertLatin1,
	)
	_, _ = secretHash.Write([]byte{':'})
	ldapClientWriteDigestMD5Secret(
		secretHash,
		password,
		values.convertLatin1,
	)
	secret := secretHash.Sum(nil)
	a1 := md5.New() //nolint:gosec // Required by DIGEST-MD5.
	_, _ = a1.Write(secret)
	clear(secret)
	_, _ = a1.Write([]byte(":" + values.nonce + ":" + values.cnonce))
	if values.authorization != "" {
		_, _ = a1.Write([]byte(":" + values.authorization))
	}
	return a1.Sum(nil)
}

func ldapClientWriteDigestMD5Secret(
	digest hash.Hash,
	value []byte,
	convertLatin1 bool,
) {
	if convertLatin1 {
		converted, ok := ldapClientDigestMD5Latin1(value)
		if ok {
			_, _ = digest.Write(converted)
			clear(converted)
			return
		}
	}
	_, _ = digest.Write(value)
}

func ldapClientDigestMD5CanUseLatin1(value []byte) bool {
	if !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if character > 0xff {
			return false
		}
	}
	return true
}

func ldapClientDigestMD5Latin1(value []byte) ([]byte, bool) {
	if !ldapClientDigestMD5CanUseLatin1(value) {
		return nil, false
	}
	converted := make([]byte, 0, len(value))
	for _, character := range string(value) {
		converted = append(converted, byte(character))
	}
	return converted, true
}

func verifyLDAPClientDigestMD5Rspauth(
	credentials []byte,
	hasCredentials bool,
	expected []byte,
) error {
	if !hasCredentials {
		return errors.New("SASL DIGEST-MD5 server omitted rspauth")
	}
	directives, _, err := parseLDAPClientDigestMD5Directives(credentials, false)
	if err != nil || len(directives) != 1 {
		return errors.New("SASL DIGEST-MD5 server returned malformed rspauth")
	}
	rspauth, present := directives["rspauth"]
	if !present || len(rspauth) != len(expected) ||
		subtle.ConstantTimeCompare([]byte(rspauth), expected) != 1 {
		return errors.New("SASL DIGEST-MD5 server proof is invalid")
	}
	return nil
}

func parseLDAPClientDigestMD5Directives(
	input []byte,
	allowRepeatedRealm bool,
) (map[string]string, []string, error) {
	if len(input) == 0 || len(input) > ldapClientSASLMaxChallengeSize {
		return nil, nil, errors.New("DIGEST-MD5 directive list has invalid size")
	}
	directives := make(map[string]string)
	var realms []string
	for offset := 0; offset < len(input); {
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		start := offset
		for offset < len(input) && ldapClientDigestMD5TokenByte(input[offset]) {
			offset++
		}
		if start == offset {
			return nil, nil, errors.New("DIGEST-MD5 directive name is invalid")
		}
		name := strings.ToLower(string(input[start:offset]))
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		if offset >= len(input) || input[offset] != '=' {
			return nil, nil, errors.New("DIGEST-MD5 directive has no value")
		}
		offset++
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		var value strings.Builder
		if offset < len(input) && input[offset] == '"' {
			offset++
			closed := false
			for offset < len(input) {
				character := input[offset]
				offset++
				if character == '\\' {
					if offset >= len(input) {
						return nil, nil, errors.New("DIGEST-MD5 quoted pair is incomplete")
					}
					value.WriteByte(input[offset])
					offset++
					continue
				}
				if character == '"' {
					closed = true
					break
				}
				if character < 0x20 || character == 0x7f {
					return nil, nil, errors.New("DIGEST-MD5 quoted value is invalid")
				}
				value.WriteByte(character)
			}
			if !closed {
				return nil, nil, errors.New("DIGEST-MD5 quoted value is incomplete")
			}
		} else {
			start = offset
			for offset < len(input) && input[offset] != ',' &&
				input[offset] != ' ' && input[offset] != '\t' {
				if !ldapClientDigestMD5TokenByte(input[offset]) {
					return nil, nil, errors.New("DIGEST-MD5 token value is invalid")
				}
				offset++
			}
			if start == offset {
				return nil, nil, errors.New("DIGEST-MD5 directive value is empty")
			}
			value.Write(input[start:offset])
		}
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		if name == "realm" && allowRepeatedRealm {
			realms = append(realms, value.String())
		} else {
			if _, duplicate := directives[name]; duplicate {
				return nil, nil, errors.New("DIGEST-MD5 directive is duplicated")
			}
			directives[name] = value.String()
		}
		if offset == len(input) {
			break
		}
		if input[offset] != ',' {
			return nil, nil, errors.New("DIGEST-MD5 directives are not comma separated")
		}
		offset++
		if offset == len(input) {
			return nil, nil, errors.New("DIGEST-MD5 directive list has a trailing comma")
		}
	}
	return directives, realms, nil
}

func ldapClientDigestMD5TokenByte(value byte) bool {
	if value <= 0x20 || value >= 0x7f {
		return false
	}
	switch value {
	case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=':
		return false
	default:
		return true
	}
}

func ldapClientDigestMD5Quote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func ldapClientDigestMD5ListContains(values, wanted string) bool {
	for _, value := range strings.Split(values, ",") {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}

func ldapClientStringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
