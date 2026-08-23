package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4" //nolint:gosec // RFC 2831 requires RC4 for DIGEST-MD5 auth-conf interoperability.
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
)

const (
	saslDigestMD5IntegrityOverhead = 4 + 10 + 2 + 4
	saslDigestMD5MACSize           = 10
	saslDigestMD5MessageType       = 1
	saslDigestMD5DefaultMaxBuffer  = 65536
)

const (
	saslDigestMD5SigningClientServer = "Digest session key to client-to-server signing key magic constant"
	saslDigestMD5SigningServerClient = "Digest session key to server-to-client signing key magic constant"
	saslDigestMD5SealingClientServer = "Digest H(A1) to client-to-server sealing key magic constant"
	saslDigestMD5SealingServerClient = "Digest H(A1) to server-to-client sealing key magic constant"
)

const (
	saslDigestMD5RC440Cipher = "rc4-40"
	saslDigestMD5RC456Cipher = "rc4-56"
	saslDigestMD5RC4Cipher   = "rc4"
	saslDigestMD5RC440SSF    = 40
	saslDigestMD5RC456SSF    = 56
	saslDigestMD5RC4SSF      = 128
)

type saslDigestMD5Cipher struct {
	name      string
	ssf       uint32
	keyPrefix int
}

func orderedSASLDigestMD5Ciphers() []saslDigestMD5Cipher {
	return []saslDigestMD5Cipher{
		{name: saslDigestMD5RC440Cipher, ssf: saslDigestMD5RC440SSF, keyPrefix: 5},
		{name: saslDigestMD5RC456Cipher, ssf: saslDigestMD5RC456SSF, keyPrefix: 7},
		{name: saslDigestMD5RC4Cipher, ssf: saslDigestMD5RC4SSF, keyPrefix: md5.Size},
	}
}

func availableSASLDigestMD5Ciphers(minimum, maximum uint32) map[string]saslDigestMD5Cipher {
	available := make(map[string]saslDigestMD5Cipher)
	for _, cipher := range orderedSASLDigestMD5Ciphers() {
		if cipher.ssf >= minimum && cipher.ssf <= maximum {
			available[cipher.name] = cipher
		}
	}
	return available
}

var (
	errSASLDigestMD5Integrity       = errors.New("DIGEST-MD5 integrity check failed")
	errSASLDigestMD5Sequence        = errors.New("DIGEST-MD5 sequence number is invalid")
	errSASLDigestMD5SecurityFrame   = errors.New("DIGEST-MD5 security frame is invalid")
	errSASLDigestMD5SequenceExhaust = errors.New("DIGEST-MD5 sequence space is exhausted")
)

type saslDigestMD5IntegrityConnection struct {
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

func newSASLDigestMD5ServerIntegrityConnection(
	connection net.Conn,
	sessionKey []byte,
	peerMaxBuffer,
	localMaxBuffer uint32,
) (*saslDigestMD5IntegrityConnection, error) {
	if previous, ok := connection.(*saslDigestMD5IntegrityConnection); ok {
		connection = previous.Conn
	}
	return newSASLDigestMD5IntegrityConnection(
		connection,
		saslDigestMD5SigningServerClient,
		saslDigestMD5SigningClientServer,
		sessionKey,
		peerMaxBuffer,
		localMaxBuffer,
	)
}

func newSASLDigestMD5IntegrityConnection(
	connection net.Conn,
	sendMagic,
	receiveMagic string,
	sessionKey []byte,
	peerMaxBuffer,
	localMaxBuffer uint32,
) (*saslDigestMD5IntegrityConnection, error) {
	if connection == nil {
		return nil, errors.New("DIGEST-MD5 security layer has no transport")
	}
	if len(sessionKey) != md5.Size {
		return nil, errors.New("DIGEST-MD5 session key has an invalid size")
	}
	if peerMaxBuffer == 0 {
		peerMaxBuffer = saslDigestMD5DefaultMaxBuffer
	}
	if localMaxBuffer == 0 {
		localMaxBuffer = saslDigestMD5DefaultMaxBuffer
	}
	if peerMaxBuffer <= saslDigestMD5IntegrityOverhead ||
		localMaxBuffer <= saslDigestMD5IntegrityOverhead ||
		peerMaxBuffer > maxSASLDigestMD5BufferSize ||
		localMaxBuffer > maxSASLDigestMD5BufferSize {
		return nil, errors.New("DIGEST-MD5 security maxbuf is invalid")
	}

	layer := &saslDigestMD5IntegrityConnection{
		Conn:       connection,
		maxSend:    peerMaxBuffer - saslDigestMD5IntegrityOverhead,
		maxReceive: localMaxBuffer - 4,
	}
	layer.sendKey = saslDigestMD5SigningKey(sessionKey, sendMagic)
	layer.receiveKey = saslDigestMD5SigningKey(sessionKey, receiveMagic)
	return layer, nil
}

func saslDigestMD5SigningKey(sessionKey []byte, magic string) [md5.Size]byte {
	digest := md5.New()
	_, _ = digest.Write(sessionKey)
	_, _ = digest.Write([]byte(magic))
	var key [md5.Size]byte
	copy(key[:], digest.Sum(nil))
	return key
}

func saslDigestMD5SealingKey(
	sessionKey []byte,
	keyPrefix int,
	magic string,
) ([md5.Size]byte, error) {
	if len(sessionKey) != md5.Size || keyPrefix < 1 || keyPrefix > len(sessionKey) {
		return [md5.Size]byte{}, errors.New("DIGEST-MD5 sealing key parameters are invalid")
	}
	digest := md5.New()
	_, _ = digest.Write(sessionKey[:keyPrefix])
	_, _ = digest.Write([]byte(magic))
	var key [md5.Size]byte
	copy(key[:], digest.Sum(nil))
	return key, nil
}

func (connection *saslDigestMD5IntegrityConnection) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()

	written := 0
	for written < len(value) {
		if connection.sendSeq > math.MaxUint32 {
			return written, errSASLDigestMD5SequenceExhaust
		}
		chunkSize := len(value) - written
		if uint64(chunkSize) > uint64(connection.maxSend) {
			chunkSize = int(connection.maxSend)
		}
		frame := connection.encodeFrame(
			value[written:written+chunkSize],
			uint32(connection.sendSeq),
		)
		err := writeSASLDigestMD5Frame(connection.Conn, frame)
		clear(frame)
		if err != nil {
			return written, err
		}
		connection.sendSeq++
		written += chunkSize
	}
	return written, nil
}

func (connection *saslDigestMD5IntegrityConnection) encodeFrame(
	message []byte,
	sequence uint32,
) []byte {
	payloadLength := len(message) + saslDigestMD5IntegrityOverhead - 4
	frame := make([]byte, 4+payloadLength)
	binary.BigEndian.PutUint32(frame[:4], uint32(payloadLength))
	copy(frame[4:], message)
	mac := saslDigestMD5MAC(connection.sendKey[:], sequence, message)
	copy(frame[4+len(message):], mac)
	clear(mac)
	offset := 4 + len(message) + saslDigestMD5MACSize
	binary.BigEndian.PutUint16(frame[offset:offset+2], saslDigestMD5MessageType)
	binary.BigEndian.PutUint32(frame[offset+2:offset+6], sequence)
	return frame
}

func writeSASLDigestMD5Frame(writer io.Writer, frame []byte) error {
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

func (connection *saslDigestMD5IntegrityConnection) Read(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.readMu.Lock()
	defer connection.readMu.Unlock()

	for len(connection.readPending) == 0 {
		message, err := connection.readFrame()
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

func (connection *saslDigestMD5IntegrityConnection) Close() error {
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

func (connection *saslDigestMD5IntegrityConnection) readFrame() ([]byte, error) {
	if connection.receiveSeq > math.MaxUint32 {
		return nil, errSASLDigestMD5SequenceExhaust
	}
	var header [4]byte
	if _, err := io.ReadFull(connection.Conn, header[:]); err != nil {
		return nil, err
	}
	payloadLength := binary.BigEndian.Uint32(header[:])
	if payloadLength < saslDigestMD5IntegrityOverhead-4 ||
		payloadLength > connection.maxReceive {
		return nil, fmt.Errorf(
			"%w: payload length %d",
			errSASLDigestMD5SecurityFrame,
			payloadLength,
		)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(connection.Conn, payload); err != nil {
		clear(payload)
		return nil, err
	}
	messageLength := len(payload) - (saslDigestMD5IntegrityOverhead - 4)
	typeOffset := messageLength + saslDigestMD5MACSize
	messageType := binary.BigEndian.Uint16(payload[typeOffset : typeOffset+2])
	sequence := binary.BigEndian.Uint32(payload[typeOffset+2 : typeOffset+6])
	if messageType != saslDigestMD5MessageType {
		clear(payload)
		return nil, fmt.Errorf(
			"%w: message type %d",
			errSASLDigestMD5SecurityFrame,
			messageType,
		)
	}
	if uint64(sequence) != connection.receiveSeq {
		clear(payload)
		return nil, fmt.Errorf(
			"%w: received %d, expected %d",
			errSASLDigestMD5Sequence,
			sequence,
			connection.receiveSeq,
		)
	}
	expected := saslDigestMD5MAC(
		connection.receiveKey[:],
		sequence,
		payload[:messageLength],
	)
	received := payload[messageLength : messageLength+saslDigestMD5MACSize]
	valid := subtle.ConstantTimeCompare(expected, received) == 1
	clear(expected)
	if !valid {
		clear(payload)
		return nil, errSASLDigestMD5Integrity
	}
	message := bytes.Clone(payload[:messageLength])
	clear(payload)
	connection.receiveSeq++
	return message, nil
}

func saslDigestMD5MAC(key []byte, sequence uint32, message []byte) []byte {
	digest := hmac.New(md5.New, key)
	var encodedSequence [4]byte
	binary.BigEndian.PutUint32(encodedSequence[:], sequence)
	_, _ = digest.Write(encodedSequence[:])
	_, _ = digest.Write(message)
	result := digest.Sum(nil)
	mac := bytes.Clone(result[:saslDigestMD5MACSize])
	clear(result)
	return mac
}

type saslDigestMD5PrivacyConnection struct {
	net.Conn

	sendKey    [md5.Size]byte
	receiveKey [md5.Size]byte
	sendCipher *rc4.Cipher
	recvCipher *rc4.Cipher
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

func newSASLDigestMD5ServerPrivacyConnection(
	connection net.Conn,
	sessionKey []byte,
	cipher saslDigestMD5Cipher,
	peerMaxBuffer,
	localMaxBuffer uint32,
) (*saslDigestMD5PrivacyConnection, error) {
	return newSASLDigestMD5PrivacyConnection(
		connection,
		saslDigestMD5SigningServerClient,
		saslDigestMD5SigningClientServer,
		saslDigestMD5SealingServerClient,
		saslDigestMD5SealingClientServer,
		sessionKey,
		cipher,
		peerMaxBuffer,
		localMaxBuffer,
	)
}

func newSASLDigestMD5PrivacyConnection(
	connection net.Conn,
	sendSigningMagic,
	receiveSigningMagic,
	sendSealingMagic,
	receiveSealingMagic string,
	sessionKey []byte,
	cipher saslDigestMD5Cipher,
	peerMaxBuffer,
	localMaxBuffer uint32,
) (*saslDigestMD5PrivacyConnection, error) {
	if connection == nil {
		return nil, errors.New("DIGEST-MD5 security layer has no transport")
	}
	if len(sessionKey) != md5.Size {
		return nil, errors.New("DIGEST-MD5 session key has an invalid size")
	}
	known, ok := availableSASLDigestMD5Ciphers(0, saslDigestMD5RC4SSF)[cipher.name]
	if !ok || known != cipher {
		return nil, errors.New("DIGEST-MD5 confidentiality cipher is not supported")
	}
	if peerMaxBuffer == 0 {
		peerMaxBuffer = saslDigestMD5DefaultMaxBuffer
	}
	if localMaxBuffer == 0 {
		localMaxBuffer = saslDigestMD5DefaultMaxBuffer
	}
	// Cyrus reserves 25 bytes for every privacy layer, including stream ciphers.
	const cyrusPrivacyOverhead = 25
	if peerMaxBuffer <= cyrusPrivacyOverhead ||
		localMaxBuffer <= saslDigestMD5IntegrityOverhead ||
		peerMaxBuffer > maxSASLDigestMD5BufferSize ||
		localMaxBuffer > maxSASLDigestMD5BufferSize {
		return nil, errors.New("DIGEST-MD5 security maxbuf is invalid")
	}
	sendSeal, err := saslDigestMD5SealingKey(sessionKey, cipher.keyPrefix, sendSealingMagic)
	if err != nil {
		return nil, err
	}
	receiveSeal, err := saslDigestMD5SealingKey(sessionKey, cipher.keyPrefix, receiveSealingMagic)
	if err != nil {
		clear(sendSeal[:])
		return nil, err
	}
	sendCipher, err := rc4.NewCipher(sendSeal[:]) //nolint:gosec // Required by RFC 2831.
	clear(sendSeal[:])
	if err != nil {
		clear(receiveSeal[:])
		return nil, err
	}
	receiveCipher, err := rc4.NewCipher(receiveSeal[:]) //nolint:gosec // Required by RFC 2831.
	clear(receiveSeal[:])
	if err != nil {
		return nil, err
	}
	layer := &saslDigestMD5PrivacyConnection{
		Conn:       connection,
		sendCipher: sendCipher,
		recvCipher: receiveCipher,
		maxSend:    peerMaxBuffer - cyrusPrivacyOverhead,
		maxReceive: localMaxBuffer - 4,
	}
	layer.sendKey = saslDigestMD5SigningKey(sessionKey, sendSigningMagic)
	layer.receiveKey = saslDigestMD5SigningKey(sessionKey, receiveSigningMagic)
	return layer, nil
}

func (connection *saslDigestMD5PrivacyConnection) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	written := 0
	for written < len(value) {
		if connection.sendSeq > math.MaxUint32 {
			return written, errSASLDigestMD5SequenceExhaust
		}
		chunkSize := len(value) - written
		if uint64(chunkSize) > uint64(connection.maxSend) {
			chunkSize = int(connection.maxSend)
		}
		frame := connection.encodeFrame(value[written:written+chunkSize], uint32(connection.sendSeq))
		err := writeSASLDigestMD5Frame(connection.Conn, frame)
		clear(frame)
		if err != nil {
			return written, err
		}
		connection.sendSeq++
		written += chunkSize
	}
	return written, nil
}

func (connection *saslDigestMD5PrivacyConnection) encodeFrame(
	message []byte,
	sequence uint32,
) []byte {
	encryptedLength := len(message) + saslDigestMD5MACSize
	payloadLength := encryptedLength + 2 + 4
	frame := make([]byte, 4+payloadLength)
	binary.BigEndian.PutUint32(frame[:4], uint32(payloadLength))
	plaintext := make([]byte, encryptedLength)
	copy(plaintext, message)
	mac := saslDigestMD5MAC(connection.sendKey[:], sequence, message)
	copy(plaintext[len(message):], mac)
	clear(mac)
	connection.sendCipher.XORKeyStream(frame[4:4+encryptedLength], plaintext)
	clear(plaintext)
	offset := 4 + encryptedLength
	binary.BigEndian.PutUint16(frame[offset:offset+2], saslDigestMD5MessageType)
	binary.BigEndian.PutUint32(frame[offset+2:offset+6], sequence)
	return frame
}

func (connection *saslDigestMD5PrivacyConnection) Read(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	for len(connection.readPending) == 0 {
		message, err := connection.readFrame()
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

func (connection *saslDigestMD5PrivacyConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		connection.writeMu.Lock()
		connection.readMu.Lock()
		clear(connection.sendKey[:])
		clear(connection.receiveKey[:])
		if connection.sendCipher != nil {
			connection.sendCipher.Reset()
			connection.sendCipher = nil
		}
		if connection.recvCipher != nil {
			connection.recvCipher.Reset()
			connection.recvCipher = nil
		}
		clear(connection.readPending)
		connection.readPending = nil
		connection.readMu.Unlock()
		connection.writeMu.Unlock()
	})
	return connection.closeErr
}

func (connection *saslDigestMD5PrivacyConnection) readFrame() ([]byte, error) {
	if connection.receiveSeq > math.MaxUint32 {
		return nil, errSASLDigestMD5SequenceExhaust
	}
	var header [4]byte
	if _, err := io.ReadFull(connection.Conn, header[:]); err != nil {
		return nil, err
	}
	payloadLength := binary.BigEndian.Uint32(header[:])
	if payloadLength < saslDigestMD5MACSize+2+4 || payloadLength > connection.maxReceive {
		return nil, fmt.Errorf("%w: payload length %d", errSASLDigestMD5SecurityFrame, payloadLength)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(connection.Conn, payload); err != nil {
		clear(payload)
		return nil, err
	}
	typeOffset := len(payload) - 6
	messageType := binary.BigEndian.Uint16(payload[typeOffset : typeOffset+2])
	sequence := binary.BigEndian.Uint32(payload[typeOffset+2 : typeOffset+6])
	if messageType != saslDigestMD5MessageType {
		clear(payload)
		return nil, fmt.Errorf("%w: message type %d", errSASLDigestMD5SecurityFrame, messageType)
	}
	if uint64(sequence) != connection.receiveSeq {
		clear(payload)
		return nil, fmt.Errorf("%w: received %d, expected %d", errSASLDigestMD5Sequence, sequence, connection.receiveSeq)
	}
	encryptedLength := typeOffset
	plaintext := make([]byte, encryptedLength)
	connection.recvCipher.XORKeyStream(plaintext, payload[:encryptedLength])
	clear(payload)
	messageLength := len(plaintext) - saslDigestMD5MACSize
	expected := saslDigestMD5MAC(connection.receiveKey[:], sequence, plaintext[:messageLength])
	valid := subtle.ConstantTimeCompare(expected, plaintext[messageLength:]) == 1
	clear(expected)
	if !valid {
		clear(plaintext)
		return nil, errSASLDigestMD5Integrity
	}
	message := bytes.Clone(plaintext[:messageLength])
	clear(plaintext)
	connection.receiveSeq++
	return message, nil
}
