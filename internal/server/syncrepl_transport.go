package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const (
	syncConsumerStartTLSOID       = "1.3.6.1.4.1.1466.20037"
	syncConsumerMaxLDAPPacketSize = 16 << 20
	syncConsumerLocalSSF          = defaultLocalSecurityStrengthFactor
)

type syncConsumerTransport struct {
	connectionMu     sync.RWMutex
	connection       net.Conn
	messageMu        sync.Mutex
	writeMu          sync.Mutex
	multiplexerMu    sync.Mutex
	multiplexer      *syncConsumerMultiplexer
	context          context.Context
	operationTimeout time.Duration
	secure           bool
	ssf              uint32
	messageID        int64
}

type syncConsumerLDAPResult struct {
	code               uint16
	matchedDN          string
	diagnosticMessage  string
	saslCredentials    []byte
	hasSASLCredentials bool
	responseName       string
	responseValue      []byte
	packet             *ber.Packet
}

type syncConsumerResultPolling struct {
	initial  time.Duration
	interval time.Duration
	retries  int
}

func dialSyncConsumer(
	ctx context.Context,
	config syncConsumerConfig,
	provider string,
) (*syncConsumerTransport, error) {
	parsed, err := parseSyncConsumerProviderURL(provider)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(parsed.Scheme, "ldap+tlcp") {
		return dialSyncConsumerTLCP(ctx, config, parsed)
	}
	tlsConfig, err := buildSyncConsumerTLSConfig(config, parsed)
	if err != nil {
		return nil, err
	}

	timeout := config.networkTimeout
	if timeout <= 0 {
		timeout = ldap.DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	if err := configureSyncConsumerDialer(dialer, config); err != nil {
		return nil, err
	}

	var (
		raw net.Conn
		ssf uint32
	)
	switch strings.ToLower(parsed.Scheme) {
	case "ldapi":
		socket := parsed.Host
		if socket == "" {
			socket = parsed.Path
		}
		if socket == "" || socket == "/" {
			socket = "/var/run/slapd/ldapi"
		}
		raw, err = dialer.DialContext(ctx, "unix", socket)
		ssf = syncConsumerLocalSSF
	case "ldap", "ldaps":
		port := parsed.Port()
		if port == "" {
			port = ldap.DefaultLdapPort
			if strings.EqualFold(parsed.Scheme, "ldaps") {
				port = ldap.DefaultLdapsPort
			}
		}
		raw, err = dialer.DialContext(
			ctx,
			"tcp",
			net.JoinHostPort(parsed.Hostname(), port),
		)
	default:
		return nil, fmt.Errorf(
			"provider %q uses unsupported scheme %q",
			provider,
			parsed.Scheme,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", provider, err)
	}

	transport := &syncConsumerTransport{
		connection:       raw,
		context:          ctx,
		operationTimeout: config.operationTimeout,
		ssf:              ssf,
	}
	if !strings.EqualFold(parsed.Scheme, "ldaps") {
		return transport, nil
	}

	secured := tls.Client(raw, tlsConfig)
	handshakeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := secured.HandshakeContext(handshakeContext); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf(
			"TLS handshake with %s: %w",
			provider,
			err,
		)
	}
	state := secured.ConnectionState()
	transport.replaceConnection(secured)
	transport.secure = true
	transport.ssf = syncConsumerTLSStateSSF(state)
	return transport, nil
}

func performSyncConsumerStartTLS(
	transport *syncConsumerTransport,
	config syncConsumerConfig,
	provider *url.URL,
	polling ...syncConsumerResultPolling,
) error {
	messageID := transport.nextMessageID()
	request := ber.NewSequence("LDAPMessage")
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	operation := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationExtendedRequest,
		nil,
		"StartTLS",
	)
	operation.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		syncConsumerStartTLSOID,
		"requestName",
	))
	request.AppendChild(operation)

	var result syncConsumerLDAPResult
	var err error
	if len(polling) > 0 {
		result, err = transport.exchangeLDAPResultPolling(
			messageID,
			request,
			ldap.ApplicationExtendedResponse,
			polling[0],
		)
	} else {
		result, err = transport.exchangeLDAPResult(
			messageID,
			request,
			ldap.ApplicationExtendedResponse,
		)
	}
	if err != nil {
		return fmt.Errorf("StartTLS protocol exchange: %w", err)
	}
	if result.code != ldap.LDAPResultSuccess {
		return result.err()
	}
	if result.responseName != "" &&
		result.responseName != syncConsumerStartTLSOID {
		return fmt.Errorf(
			"StartTLS response name is %q",
			result.responseName,
		)
	}
	if err := transport.clearDeadline(); err != nil {
		return fmt.Errorf("clear StartTLS protocol deadline: %w", err)
	}

	tlsConfig, err := buildSyncConsumerTLSConfig(config, provider)
	if err != nil {
		return err
	}
	secured := tls.Client(transport.currentConnection(), tlsConfig)
	timeout := config.networkTimeout
	if timeout <= 0 {
		timeout = ldap.DefaultTimeout
	}
	handshakeContext, cancel := context.WithTimeout(
		transport.context,
		timeout,
	)
	defer cancel()
	if err := secured.HandshakeContext(handshakeContext); err != nil {
		return fmt.Errorf("StartTLS handshake: %w", err)
	}
	state := secured.ConnectionState()
	transport.replaceConnection(secured)
	transport.secure = true
	transport.ssf = syncConsumerTLSStateSSF(state)
	return nil
}

func parseSyncConsumerProviderURL(value string) (*url.URL, error) {
	const prefix = "ldapi://"
	if !strings.HasPrefix(strings.ToLower(value), prefix) {
		return url.Parse(value)
	}
	rest := value[len(prefix):]
	host, suffix := rest, ""
	if index := strings.IndexAny(rest, "/?#"); index >= 0 {
		host = rest[:index]
		suffix = rest[index:]
	}
	decodedHost, err := url.PathUnescape(host)
	if err != nil {
		return nil, fmt.Errorf("ldapi provider host %q: %w", host, err)
	}
	relative, err := url.Parse(suffix)
	if err != nil {
		return nil, fmt.Errorf("ldapi provider URL %q: %w", value, err)
	}
	return &url.URL{
		Scheme:     "ldapi",
		Host:       decodedHost,
		Path:       relative.Path,
		RawPath:    relative.RawPath,
		ForceQuery: relative.ForceQuery,
		RawQuery:   relative.RawQuery,
		Fragment:   relative.Fragment,
	}, nil
}

func (transport *syncConsumerTransport) nextMessageID() int64 {
	transport.messageMu.Lock()
	defer transport.messageMu.Unlock()
	transport.messageID++
	return transport.messageID
}

func (transport *syncConsumerTransport) writePacket(encoded []byte) error {
	transport.writeMu.Lock()
	defer transport.writeMu.Unlock()
	return writeSyncConsumerPacket(transport.currentConnection(), encoded)
}

func (transport *syncConsumerTransport) currentConnection() net.Conn {
	transport.connectionMu.RLock()
	defer transport.connectionMu.RUnlock()
	return transport.connection
}

func (transport *syncConsumerTransport) replaceConnection(connection net.Conn) {
	transport.connectionMu.Lock()
	defer transport.connectionMu.Unlock()
	transport.connection = connection
}

func (transport *syncConsumerTransport) close() error {
	return transport.currentConnection().Close()
}

func (transport *syncConsumerTransport) exchangeLDAPResult(
	messageID int64,
	request *ber.Packet,
	responseTag uint64,
) (syncConsumerLDAPResult, error) {
	if err := transport.setOperationDeadline(); err != nil {
		return syncConsumerLDAPResult{}, err
	}
	connection := transport.currentConnection()
	if err := writeSyncConsumerPacket(connection, request.Bytes()); err != nil {
		return syncConsumerLDAPResult{}, err
	}
	response, err := readSyncConsumerPacket(connection)
	if err != nil {
		return syncConsumerLDAPResult{}, err
	}
	return parseSyncConsumerLDAPResult(response, messageID, responseTag)
}

func (transport *syncConsumerTransport) exchangeLDAPResultPolling(
	messageID int64,
	request *ber.Packet,
	responseTag uint64,
	polling syncConsumerResultPolling,
) (syncConsumerLDAPResult, error) {
	deadline := transport.resultPollingDeadline(polling)
	if err := transport.currentConnection().SetDeadline(deadline); err != nil {
		return syncConsumerLDAPResult{}, err
	}
	connection := transport.currentConnection()
	if err := writeSyncConsumerPacket(connection, request.Bytes()); err != nil {
		return syncConsumerLDAPResult{}, err
	}

	type outcome struct {
		result syncConsumerLDAPResult
		err    error
	}
	result := make(chan outcome, 1)
	go func() {
		packet, err := readSyncConsumerPacket(connection)
		if err == nil {
			var parsed syncConsumerLDAPResult
			parsed, err = parseSyncConsumerLDAPResult(
				packet,
				messageID,
				responseTag,
			)
			result <- outcome{result: parsed, err: err}
			return
		}
		result <- outcome{err: err}
	}()

	var timeout <-chan time.Time
	var timer *time.Timer
	if !deadline.IsZero() {
		duration := time.Until(deadline)
		if duration < 0 {
			duration = 0
		}
		timer = time.NewTimer(duration)
		timeout = timer.C
		defer timer.Stop()
	}
	select {
	case completed := <-result:
		return completed.result, completed.err
	case <-transport.context.Done():
		return syncConsumerLDAPResult{}, transport.context.Err()
	case <-timeout:
		return syncConsumerLDAPResult{}, context.DeadlineExceeded
	}
}

func (transport *syncConsumerTransport) resultPollingDeadline(
	polling syncConsumerResultPolling,
) time.Time {
	var deadline time.Time
	if polling.retries >= 0 {
		budget := polling.initial
		if polling.retries > 0 && polling.interval > 0 {
			maximumBudget := time.Duration(^uint64(0) >> 1)
			if budget >= maximumBudget ||
				time.Duration(polling.retries) >
					(maximumBudget-budget)/polling.interval {
				budget = maximumBudget
			} else {
				budget += time.Duration(polling.retries) * polling.interval
			}
		}
		if transport.operationTimeout > budget {
			budget = transport.operationTimeout
		}
		deadline = time.Now().Add(budget)
	}
	if contextDeadline, ok := transport.context.Deadline(); ok &&
		(deadline.IsZero() || contextDeadline.Before(deadline)) {
		deadline = contextDeadline
	}
	return deadline
}

func (transport *syncConsumerTransport) setOperationDeadline() error {
	var deadline time.Time
	if transport.operationTimeout > 0 {
		deadline = time.Now().Add(transport.operationTimeout)
	}
	if contextDeadline, ok := transport.context.Deadline(); ok &&
		(deadline.IsZero() || contextDeadline.Before(deadline)) {
		deadline = contextDeadline
	}
	return transport.currentConnection().SetDeadline(deadline)
}

func (transport *syncConsumerTransport) clearDeadline() error {
	return transport.currentConnection().SetDeadline(time.Time{})
}

func readSyncConsumerPacket(reader io.Reader) (*ber.Packet, error) {
	header := []byte{0, 0}
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("read LDAP response header: %w", err)
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf(
			"LDAP response starts with BER identifier 0x%02x",
			header[0],
		)
	}

	contentLength := uint64(header[1])
	if header[1]&0x80 != 0 {
		lengthBytes := int(header[1] & 0x7f)
		if lengthBytes == 0 {
			return nil, errors.New(
				"indefinite-length LDAP messages are not supported",
			)
		}
		if lengthBytes > 8 {
			return nil, errors.New("LDAP response length overflows uint64")
		}
		encodedLength := make([]byte, lengthBytes)
		if _, err := io.ReadFull(reader, encodedLength); err != nil {
			return nil, fmt.Errorf("read LDAP response length: %w", err)
		}
		if encodedLength[0] == 0 {
			return nil, errors.New(
				"LDAP response length is not minimally encoded",
			)
		}
		header = append(header, encodedLength...)
		contentLength = 0
		for _, value := range encodedLength {
			contentLength = contentLength<<8 | uint64(value)
		}
		if contentLength < 128 {
			return nil, errors.New(
				"LDAP response long-form length is not minimal",
			)
		}
	}
	if contentLength > syncConsumerMaxLDAPPacketSize ||
		uint64(len(header)) >
			syncConsumerMaxLDAPPacketSize-contentLength {
		return nil, fmt.Errorf(
			"LDAP response length %d exceeds maximum %d",
			contentLength,
			syncConsumerMaxLDAPPacketSize,
		)
	}

	encoded := make([]byte, len(header)+int(contentLength))
	copy(encoded, header)
	if _, err := io.ReadFull(reader, encoded[len(header):]); err != nil {
		return nil, fmt.Errorf("read LDAP response body: %w", err)
	}
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode LDAP response: %w", err)
	}
	return packet, nil
}

func writeSyncConsumerPacket(writer io.Writer, encoded []byte) error {
	for len(encoded) > 0 {
		written, err := writer.Write(encoded)
		if err != nil {
			return fmt.Errorf("write LDAP request: %w", err)
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[written:]
	}
	return nil
}

func parseSyncConsumerLDAPResult(
	packet *ber.Packet,
	messageID int64,
	responseTag uint64,
) (syncConsumerLDAPResult, error) {
	if !syncConsumerPacketIs(
		packet,
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
	) || (len(packet.Children) != 2 && len(packet.Children) != 3) {
		return syncConsumerLDAPResult{}, errors.New(
			"malformed LDAP response envelope",
		)
	}
	responseID, err := syncConsumerPacketInteger(packet.Children[0])
	if err != nil || responseID != messageID {
		return syncConsumerLDAPResult{}, fmt.Errorf(
			"LDAP response message ID is %d, want %d",
			responseID,
			messageID,
		)
	}
	if len(packet.Children) == 3 &&
		!syncConsumerPacketIs(
			packet.Children[2],
			ber.ClassContext,
			ber.TypeConstructed,
			0,
		) {
		return syncConsumerLDAPResult{}, errors.New(
			"malformed LDAP response controls",
		)
	}

	operation := packet.Children[1]
	if !syncConsumerPacketIs(
		operation,
		ber.ClassApplication,
		ber.TypeConstructed,
		ber.Tag(responseTag),
	) || len(operation.Children) < 3 {
		return syncConsumerLDAPResult{}, fmt.Errorf(
			"malformed LDAP response operation %d",
			responseTag,
		)
	}
	code, err := syncConsumerPacketInteger(operation.Children[0])
	if err != nil || code < 0 || code > 65535 {
		return syncConsumerLDAPResult{}, errors.New(
			"malformed LDAP result code",
		)
	}
	matchedDN, err := syncConsumerPacketBytes(operation.Children[1])
	if err != nil {
		return syncConsumerLDAPResult{}, errors.New(
			"malformed LDAP matched DN",
		)
	}
	diagnostic, err := syncConsumerPacketBytes(operation.Children[2])
	if err != nil {
		return syncConsumerLDAPResult{}, errors.New(
			"malformed LDAP diagnostic message",
		)
	}
	result := syncConsumerLDAPResult{
		code:              uint16(code),
		matchedDN:         string(matchedDN),
		diagnosticMessage: string(diagnostic),
		packet:            packet,
	}

	for _, child := range operation.Children[3:] {
		switch {
		case syncConsumerPacketIs(
			child,
			ber.ClassContext,
			ber.TypeConstructed,
			3,
		):
			for _, referral := range child.Children {
				if _, err := syncConsumerPacketBytes(referral); err != nil {
					return syncConsumerLDAPResult{}, errors.New(
						"malformed LDAP referral",
					)
				}
			}
		case responseTag == ldap.ApplicationBindResponse &&
			syncConsumerPacketIs(
				child,
				ber.ClassContext,
				ber.TypePrimitive,
				7,
			):
			if result.hasSASLCredentials {
				return syncConsumerLDAPResult{}, errors.New(
					"duplicate server SASL credentials",
				)
			}
			result.saslCredentials = bytes.Clone(child.Data.Bytes())
			result.hasSASLCredentials = true
		case responseTag == ldap.ApplicationExtendedResponse &&
			syncConsumerPacketIs(
				child,
				ber.ClassContext,
				ber.TypePrimitive,
				10,
			):
			if result.responseName != "" {
				return syncConsumerLDAPResult{}, errors.New(
					"duplicate LDAP extended response name",
				)
			}
			result.responseName = child.Data.String()
		case responseTag == ldap.ApplicationExtendedResponse &&
			syncConsumerPacketIs(
				child,
				ber.ClassContext,
				ber.TypePrimitive,
				11,
			):
			if result.responseValue != nil {
				return syncConsumerLDAPResult{}, errors.New(
					"duplicate LDAP extended response value",
				)
			}
			result.responseValue = bytes.Clone(child.Data.Bytes())
		default:
			return syncConsumerLDAPResult{}, fmt.Errorf(
				"unexpected LDAP result element class=%d tag=%d",
				child.ClassType,
				child.Tag,
			)
		}
	}
	return result, nil
}

func (result syncConsumerLDAPResult) err() error {
	message := result.diagnosticMessage
	if message == "" {
		message = ldap.LDAPResultCodeMap[result.code]
	}
	if message == "" {
		message = "LDAP operation failed"
	}
	return &ldap.Error{
		Err:        errors.New(message),
		ResultCode: result.code,
		MatchedDN:  result.matchedDN,
		Packet:     result.packet,
	}
}

func syncConsumerPacketInteger(packet *ber.Packet) (int64, error) {
	if packet == nil ||
		packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypePrimitive ||
		(packet.Tag != ber.TagInteger && packet.Tag != ber.TagEnumerated) ||
		packet.Data == nil ||
		packet.Data.Len() == 0 {
		return 0, errors.New("not a BER integer")
	}
	return ber.ParseInt64(packet.Data.Bytes())
}

func syncConsumerPacketBytes(packet *ber.Packet) ([]byte, error) {
	if !syncConsumerPacketIs(
		packet,
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
	) || packet.Data == nil {
		return nil, errors.New("not a BER octet string")
	}
	return bytes.Clone(packet.Data.Bytes()), nil
}

func syncConsumerPacketIs(
	packet *ber.Packet,
	class ber.Class,
	tagType ber.Type,
	tag ber.Tag,
) bool {
	return packet != nil &&
		packet.ClassType == class &&
		packet.TagType == tagType &&
		packet.Tag == tag
}

func syncConsumerOctetString(value []byte, description string) *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		description,
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}

func syncConsumerTLSStateSSF(state tls.ConnectionState) uint32 {
	return tlsConnectionSecurityStrength(state)
}
