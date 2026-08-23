package saslkrb5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	SecurityNone            byte = 0x01
	SecurityIntegrity       byte = 0x02
	SecurityConfidentiality byte = 0x04
	MaxBufferSize                = (1 << 24) - 1
	defaultBufferSize            = 64 << 10
)

// SecurityState carries the RFC 4121 per-message sequence numbers and key
// provenance from context establishment into the SASL negotiation and data
// security layer.
type SecurityState struct {
	SendSequence    uint64
	ReceiveSequence uint64
	AcceptorSubkey  bool
}

func EncodeNegotiation(selection byte, maximum uint32, authorizationID string) ([]byte, error) {
	if selection != SecurityNone && selection != SecurityIntegrity &&
		selection != SecurityConfidentiality {
		return nil, errors.New("GSSAPI security layer selection is invalid")
	}
	if selection == SecurityNone {
		maximum = 0
	} else if maximum == 0 {
		return nil, errors.New("GSSAPI integrity selection requires a nonzero maximum buffer")
	}
	if maximum > MaxBufferSize {
		return nil, errors.New("GSSAPI maximum buffer exceeds the RFC 4752 limit")
	}
	value := make([]byte, 4, 4+len(authorizationID))
	value[0] = selection
	value[1] = byte(maximum >> 16)
	value[2] = byte(maximum >> 8)
	value[3] = byte(maximum)
	value = append(value, authorizationID...)
	return value, nil
}

func DecodeNegotiation(value []byte) (byte, uint32, string, error) {
	if len(value) < 4 {
		return 0, 0, "", errors.New("GSSAPI security negotiation token is too short")
	}
	selection := value[0]
	if selection != SecurityNone && selection != SecurityIntegrity &&
		selection != SecurityConfidentiality {
		return 0, 0, "", errors.New("GSSAPI security negotiation selected an unsupported layer")
	}
	maximum := uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	if selection == SecurityNone && maximum != 0 {
		return 0, 0, "", errors.New("GSSAPI no-security selection has a nonzero maximum buffer")
	}
	if selection != SecurityNone && maximum == 0 {
		return 0, 0, "", errors.New("GSSAPI security-layer selection has a zero maximum buffer")
	}
	return selection, maximum, string(value[4:]), nil
}

func DecodeOffer(value []byte) (byte, uint32, error) {
	if len(value) != 4 {
		return 0, 0, errors.New("GSSAPI security offer must contain four octets")
	}
	layers := value[0]
	if layers == 0 || layers&^(SecurityNone|SecurityIntegrity|SecurityConfidentiality) != 0 {
		return 0, 0, errors.New("GSSAPI security offer contains unsupported layers")
	}
	maximum := uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	if layers&(SecurityIntegrity|SecurityConfidentiality) == 0 && maximum != 0 {
		return 0, 0, errors.New("GSSAPI auth-only offer has a nonzero maximum buffer")
	}
	if layers&(SecurityIntegrity|SecurityConfidentiality) != 0 && maximum == 0 {
		return 0, 0, errors.New("GSSAPI security-layer offer has a zero maximum buffer")
	}
	return layers, maximum, nil
}

func SecurityStrength(key types.EncryptionKey) (uint32, error) {
	etype, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return 0, err
	}
	bits := etype.GetKeySeedBitLength()
	if bits <= 0 {
		bits = etype.GetKeyByteSize() * 8
	}
	if bits <= 0 {
		return 0, errors.New("GSSAPI context key has no security strength")
	}
	return uint32(bits), nil
}

func Wrap(
	payload []byte,
	key types.EncryptionKey,
	fromAcceptor bool,
	acceptorSubkey bool,
	sequence uint64,
) ([]byte, error) {
	etype, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	flags := byte(0)
	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if fromAcceptor {
		flags = krbgssapi.MICTokenFlagSentByAcceptor
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	if acceptorSubkey {
		flags |= krbgssapi.MICTokenFlagAcceptorSubkey
	}
	token := krbgssapi.WrapToken{
		Flags:     flags,
		EC:        uint16(etype.GetHMACBitLength() / 8),
		SndSeqNum: sequence,
		Payload:   bytes.Clone(payload),
	}
	if err := token.SetCheckSum(key, usage); err != nil {
		clear(token.Payload)
		return nil, err
	}
	encoded, err := token.Marshal()
	clear(token.Payload)
	clear(token.CheckSum)
	if err != nil {
		return nil, err
	}
	if fromAcceptor && token.EC != 0 {
		binary.BigEndian.PutUint16(encoded[6:8], token.EC)
		rotateRight(encoded[krbgssapi.HdrLen:], int(token.EC))
	}
	return encoded, nil
}

func Unwrap(
	encoded []byte,
	key types.EncryptionKey,
	fromAcceptor bool,
	acceptorSubkey bool,
	sequence uint64,
) ([]byte, error) {
	if len(encoded) < krbgssapi.HdrLen {
		return nil, errors.New("GSSAPI wrap token is shorter than its header")
	}
	if encoded[0] != 0x05 || encoded[1] != 0x04 || encoded[3] != 0xff {
		return nil, errors.New("GSSAPI wrap token header is invalid")
	}
	acceptor := encoded[2]&krbgssapi.MICTokenFlagSentByAcceptor != 0
	if acceptor != fromAcceptor {
		return nil, errors.New("GSSAPI wrap token direction is invalid")
	}
	usesAcceptorSubkey := encoded[2]&krbgssapi.MICTokenFlagAcceptorSubkey != 0
	if usesAcceptorSubkey != acceptorSubkey {
		return nil, errors.New("GSSAPI wrap token acceptor-subkey flag is invalid")
	}
	if encoded[2]&krbgssapi.MICTokenFlagSealed != 0 {
		return nil, errors.New("GSSAPI confidentiality tokens are not supported")
	}
	ec := int(binary.BigEndian.Uint16(encoded[4:6]))
	rrc := int(binary.BigEndian.Uint16(encoded[6:8]))
	body := bytes.Clone(encoded[krbgssapi.HdrLen:])
	if len(body) < ec {
		return nil, errors.New("GSSAPI wrap token checksum length is invalid")
	}
	if len(body) != 0 {
		rotateLeft(body, rrc%len(body))
	}
	payloadLength := len(body) - ec
	token := krbgssapi.WrapToken{
		Flags:     encoded[2],
		EC:        uint16(ec),
		RRC:       0,
		SndSeqNum: binary.BigEndian.Uint64(encoded[8:16]),
		Payload:   body[:payloadLength],
		CheckSum:  body[payloadLength:],
	}
	if token.SndSeqNum != sequence {
		clear(body)
		return nil, fmt.Errorf("GSSAPI sequence number is %d, expected %d", token.SndSeqNum, sequence)
	}
	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if fromAcceptor {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	valid, err := token.Verify(key, usage)
	if err != nil || !valid {
		clear(body)
		if err == nil {
			err = errors.New("checksum mismatch")
		}
		return nil, fmt.Errorf("verify GSSAPI integrity token: %w", err)
	}
	payload := bytes.Clone(token.Payload)
	clear(body)
	return payload, nil
}

// WrapConfidential creates an RFC 4121 Wrap token with the Sealed flag set.
// The encrypted plaintext includes a copy of the token header, binding the
// direction, sequence number, and filler count to the ciphertext.
func WrapConfidential(
	payload []byte,
	key types.EncryptionKey,
	fromAcceptor bool,
	acceptorSubkey bool,
	sequence uint64,
) ([]byte, error) {
	flags := byte(krbgssapi.MICTokenFlagSealed)
	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if fromAcceptor {
		flags |= krbgssapi.MICTokenFlagSentByAcceptor
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	if acceptorSubkey {
		flags |= krbgssapi.MICTokenFlagAcceptorSubkey
	}
	header := wrapTokenHeader(flags, 0, 0, sequence)
	plaintext := make([]byte, 0, len(payload)+len(header))
	plaintext = append(plaintext, payload...)
	plaintext = append(plaintext, header...)
	encrypted, err := krbcrypto.GetEncryptedData(plaintext, key, usage, 0)
	clear(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt GSSAPI confidentiality token: %w", err)
	}
	encoded := make([]byte, 0, len(header)+len(encrypted.Cipher))
	encoded = append(encoded, header...)
	encoded = append(encoded, encrypted.Cipher...)
	clear(encrypted.Cipher)
	return encoded, nil
}

// UnwrapConfidential verifies and decrypts an RFC 4121 sealed Wrap token.
func UnwrapConfidential(
	encoded []byte,
	key types.EncryptionKey,
	fromAcceptor bool,
	acceptorSubkey bool,
	sequence uint64,
) ([]byte, error) {
	if len(encoded) < krbgssapi.HdrLen {
		return nil, errors.New("GSSAPI wrap token is shorter than its header")
	}
	if encoded[0] != 0x05 || encoded[1] != 0x04 || encoded[3] != 0xff {
		return nil, errors.New("GSSAPI wrap token header is invalid")
	}
	flags := encoded[2]
	if flags&krbgssapi.MICTokenFlagSealed == 0 {
		return nil, errors.New("GSSAPI confidentiality token is not sealed")
	}
	acceptor := flags&krbgssapi.MICTokenFlagSentByAcceptor != 0
	if acceptor != fromAcceptor {
		return nil, errors.New("GSSAPI wrap token direction is invalid")
	}
	usesAcceptorSubkey := flags&krbgssapi.MICTokenFlagAcceptorSubkey != 0
	if usesAcceptorSubkey != acceptorSubkey {
		return nil, errors.New("GSSAPI wrap token acceptor-subkey flag is invalid")
	}
	gotSequence := binary.BigEndian.Uint64(encoded[8:16])
	if gotSequence != sequence {
		return nil, fmt.Errorf("GSSAPI sequence number is %d, expected %d", gotSequence, sequence)
	}
	etype, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	minimumCiphertext := etype.GetConfounderByteSize() + etype.GetHMACBitLength()/8 + krbgssapi.HdrLen
	if len(encoded)-krbgssapi.HdrLen < minimumCiphertext {
		return nil, errors.New("GSSAPI confidentiality ciphertext is too short")
	}
	body := bytes.Clone(encoded[krbgssapi.HdrLen:])
	rrc := int(binary.BigEndian.Uint16(encoded[6:8]))
	if len(body) != 0 {
		rotateLeft(body, rrc%len(body))
	}
	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if fromAcceptor {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	plaintext, err := krbcrypto.DecryptMessage(body, key, usage)
	clear(body)
	if err != nil {
		return nil, fmt.Errorf("decrypt GSSAPI confidentiality token: %w", err)
	}
	ec := int(binary.BigEndian.Uint16(encoded[4:6]))
	if len(plaintext) < ec+krbgssapi.HdrLen {
		clear(plaintext)
		return nil, errors.New("GSSAPI confidentiality plaintext is too short")
	}
	headerOffset := len(plaintext) - krbgssapi.HdrLen
	wantHeader := wrapTokenHeader(flags, uint16(ec), 0, sequence)
	if !bytes.Equal(plaintext[headerOffset:], wantHeader) {
		clear(plaintext)
		return nil, errors.New("GSSAPI confidentiality token header mismatch")
	}
	payloadLength := headerOffset - ec
	payload := bytes.Clone(plaintext[:payloadLength])
	clear(plaintext)
	return payload, nil
}

func wrapTokenHeader(flags byte, ec, rrc uint16, sequence uint64) []byte {
	header := make([]byte, krbgssapi.HdrLen)
	header[0] = 0x05
	header[1] = 0x04
	header[2] = flags
	header[3] = 0xff
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], rrc)
	binary.BigEndian.PutUint64(header[8:16], sequence)
	return header
}

func rotateRight(value []byte, count int) {
	if len(value) == 0 || count%len(value) == 0 {
		return
	}
	count %= len(value)
	temporary := append([]byte(nil), value[len(value)-count:]...)
	copy(value[count:], value[:len(value)-count])
	copy(value[:count], temporary)
	clear(temporary)
}

func rotateLeft(value []byte, count int) {
	if len(value) == 0 || count%len(value) == 0 {
		return
	}
	count %= len(value)
	temporary := append([]byte(nil), value[:count]...)
	copy(value, value[count:])
	copy(value[len(value)-count:], temporary)
	clear(temporary)
}

type IntegrityConnection struct {
	net.Conn
	key            types.EncryptionKey
	fromAcceptor   bool
	maxSend        uint32
	maxReceive     uint32
	sendSequence   uint64
	recvSequence   uint64
	writeMu        sync.Mutex
	readMu         sync.Mutex
	readPending    []byte
	confidential   bool
	acceptorSubkey bool
	closeOnce      sync.Once
	closeErr       error
}

func NewIntegrityConnection(
	connection net.Conn,
	key types.EncryptionKey,
	acceptor bool,
	state SecurityState,
	peerMaximum,
	localMaximum uint32,
) (*IntegrityConnection, error) {
	return newSecurityConnection(connection, key, acceptor, state, peerMaximum, localMaximum, false)
}

func NewConfidentialityConnection(
	connection net.Conn,
	key types.EncryptionKey,
	acceptor bool,
	state SecurityState,
	peerMaximum,
	localMaximum uint32,
) (*IntegrityConnection, error) {
	return newSecurityConnection(connection, key, acceptor, state, peerMaximum, localMaximum, true)
}

func newSecurityConnection(
	connection net.Conn,
	key types.EncryptionKey,
	acceptor bool,
	state SecurityState,
	peerMaximum,
	localMaximum uint32,
	confidential bool,
) (*IntegrityConnection, error) {
	if connection == nil || len(key.KeyValue) == 0 {
		return nil, errors.New("GSSAPI integrity connection parameters are incomplete")
	}
	if peerMaximum == 0 {
		peerMaximum = defaultBufferSize
	}
	if localMaximum == 0 {
		localMaximum = defaultBufferSize
	}
	if peerMaximum > MaxBufferSize || localMaximum > MaxBufferSize {
		return nil, errors.New("GSSAPI integrity buffer exceeds the RFC 4752 limit")
	}
	etype, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	overhead := uint32(krbgssapi.HdrLen + etype.GetHMACBitLength()/8)
	if confidential {
		overhead += uint32(etype.GetConfounderByteSize() + krbgssapi.HdrLen)
	}
	if peerMaximum <= overhead || localMaximum <= overhead {
		return nil, errors.New("GSSAPI integrity buffer is too small")
	}
	layer := &IntegrityConnection{
		Conn:           connection,
		key:            cloneKey(key),
		fromAcceptor:   acceptor,
		maxSend:        peerMaximum - overhead,
		maxReceive:     localMaximum,
		confidential:   confidential,
		acceptorSubkey: state.AcceptorSubkey,
		sendSequence:   state.SendSequence,
		recvSequence:   state.ReceiveSequence,
	}
	return layer, nil
}

func (connection *IntegrityConnection) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if len(connection.key.KeyValue) == 0 {
		return 0, net.ErrClosed
	}
	written := 0
	for written < len(value) {
		if connection.sendSequence == math.MaxUint64 {
			return written, errors.New("GSSAPI sequence space is exhausted")
		}
		length := len(value) - written
		if uint64(length) > uint64(connection.maxSend) {
			length = int(connection.maxSend)
		}
		var token []byte
		var err error
		if connection.confidential {
			token, err = WrapConfidential(value[written:written+length], connection.key, connection.fromAcceptor, connection.acceptorSubkey, connection.sendSequence)
		} else {
			token, err = Wrap(value[written:written+length], connection.key, connection.fromAcceptor, connection.acceptorSubkey, connection.sendSequence)
		}
		if err != nil {
			return written, err
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(token)))
		err = writeAll(connection.Conn, header[:])
		if err == nil {
			err = writeAll(connection.Conn, token)
		}
		clear(token)
		if err != nil {
			return written, err
		}
		connection.sendSequence++
		written += length
	}
	return written, nil
}

func (connection *IntegrityConnection) Read(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	if len(connection.key.KeyValue) == 0 {
		return 0, net.ErrClosed
	}
	for len(connection.readPending) == 0 {
		if connection.recvSequence == math.MaxUint64 {
			return 0, errors.New("GSSAPI sequence space is exhausted")
		}
		var header [4]byte
		if _, err := io.ReadFull(connection.Conn, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 || length > connection.maxReceive {
			return 0, errors.New("GSSAPI integrity frame length is invalid")
		}
		token := make([]byte, length)
		if _, err := io.ReadFull(connection.Conn, token); err != nil {
			clear(token)
			return 0, err
		}
		var message []byte
		var err error
		if connection.confidential {
			message, err = UnwrapConfidential(token, connection.key, !connection.fromAcceptor, connection.acceptorSubkey, connection.recvSequence)
		} else {
			message, err = Unwrap(token, connection.key, !connection.fromAcceptor, connection.acceptorSubkey, connection.recvSequence)
		}
		clear(token)
		if err != nil {
			return 0, err
		}
		connection.recvSequence++
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

func (connection *IntegrityConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		connection.writeMu.Lock()
		connection.readMu.Lock()
		clear(connection.key.KeyValue)
		connection.key = types.EncryptionKey{}
		clear(connection.readPending)
		connection.readPending = nil
		connection.readMu.Unlock()
		connection.writeMu.Unlock()
	})
	return connection.closeErr
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrNoProgress
		}
		value = value[written:]
	}
	return nil
}

func (connection *IntegrityConnection) SetDeadline(value time.Time) error {
	return connection.Conn.SetDeadline(value)
}
