package server

import (
	"context"
	"errors"
	"fmt"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	syncConsumerResponseStreamPacketLimit = 256
	syncConsumerResponseStreamByteLimit   = 16 << 20
)

var errSyncConsumerResponseStreamOverflow = errors.New(
	"LDAP response stream queue limit exceeded",
)

type syncConsumerQueuedPacket struct {
	packet *ber.Packet
	bytes  int
}

type syncConsumerResponseStream struct {
	mu          sync.Mutex
	packets     []syncConsumerQueuedPacket
	queuedBytes int
	packetLimit int
	byteLimit   int
	err         error
	notify      chan struct{}
}

func newSyncConsumerResponseStream() *syncConsumerResponseStream {
	return newSyncConsumerResponseStreamWithLimits(
		syncConsumerResponseStreamPacketLimit,
		syncConsumerResponseStreamByteLimit,
	)
}

func newSyncConsumerResponseStreamWithLimits(
	packetLimit int,
	byteLimit int,
) *syncConsumerResponseStream {
	if packetLimit < 1 || byteLimit < 1 {
		panic("LDAP response stream queue limits must be positive")
	}
	return &syncConsumerResponseStream{
		packetLimit: packetLimit,
		byteLimit:   byteLimit,
		notify:      make(chan struct{}),
	}
}

func (stream *syncConsumerResponseStream) push(packet *ber.Packet) error {
	if packet == nil || packet.Data == nil {
		return errors.New("cannot queue malformed LDAP response packet")
	}
	packetBytes := len(packet.Bytes())
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.err != nil {
		return stream.err
	}
	if len(stream.packets) >= stream.packetLimit ||
		packetBytes > stream.byteLimit-stream.queuedBytes {
		err := fmt.Errorf(
			"%w: queued packets=%d/%d queued bytes=%d/%d incoming bytes=%d",
			errSyncConsumerResponseStreamOverflow,
			len(stream.packets),
			stream.packetLimit,
			stream.queuedBytes,
			stream.byteLimit,
			packetBytes,
		)
		stream.failLocked(err)
		return err
	}
	stream.packets = append(stream.packets, syncConsumerQueuedPacket{
		packet: packet,
		bytes:  packetBytes,
	})
	stream.queuedBytes += packetBytes
	stream.signalLocked()
	return nil
}

func (stream *syncConsumerResponseStream) fail(err error) {
	if err == nil {
		err = errors.New("LDAP response stream closed")
	}
	stream.mu.Lock()
	if stream.err == nil {
		stream.failLocked(err)
	} else {
		stream.releasePacketsLocked()
	}
	stream.mu.Unlock()
}

func (stream *syncConsumerResponseStream) next(
	ctx context.Context,
) (*ber.Packet, error) {
	for {
		stream.mu.Lock()
		if len(stream.packets) > 0 {
			queued := stream.packets[0]
			stream.packets[0] = syncConsumerQueuedPacket{}
			if len(stream.packets) == 1 {
				stream.packets = nil
			} else {
				stream.packets = stream.packets[1:]
			}
			stream.queuedBytes -= queued.bytes
			stream.mu.Unlock()
			return queued.packet, nil
		}
		if stream.err != nil {
			err := stream.err
			stream.mu.Unlock()
			return nil, err
		}
		notify := stream.notify
		stream.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notify:
		}
	}
}

func (stream *syncConsumerResponseStream) failLocked(err error) {
	stream.err = err
	stream.releasePacketsLocked()
	stream.signalLocked()
}

func (stream *syncConsumerResponseStream) releasePacketsLocked() {
	stream.packets = nil
	stream.queuedBytes = 0
}

func (stream *syncConsumerResponseStream) signalLocked() {
	close(stream.notify)
	stream.notify = make(chan struct{})
}

type syncConsumerMultiplexer struct {
	transport *syncConsumerTransport

	mu      sync.Mutex
	streams map[int64]*syncConsumerResponseStream
	err     error
}

func (transport *syncConsumerTransport) enableMultiplexing() error {
	transport.multiplexerMu.Lock()
	defer transport.multiplexerMu.Unlock()
	if transport.multiplexer != nil {
		return transport.multiplexer.failure()
	}
	multiplexer := &syncConsumerMultiplexer{
		transport: transport,
		streams:   make(map[int64]*syncConsumerResponseStream),
	}
	transport.multiplexer = multiplexer
	go multiplexer.read()
	return nil
}

func (transport *syncConsumerTransport) multiplexedResponse(
	messageID int64,
) (*syncConsumerResponseStream, func(), error) {
	transport.multiplexerMu.Lock()
	multiplexer := transport.multiplexer
	transport.multiplexerMu.Unlock()
	if multiplexer == nil {
		return nil, nil, errors.New("LDAP transport multiplexing is not enabled")
	}
	return multiplexer.register(messageID)
}

func (multiplexer *syncConsumerMultiplexer) failure() error {
	multiplexer.mu.Lock()
	defer multiplexer.mu.Unlock()
	return multiplexer.err
}

func (multiplexer *syncConsumerMultiplexer) register(
	messageID int64,
) (*syncConsumerResponseStream, func(), error) {
	stream := newSyncConsumerResponseStream()
	multiplexer.mu.Lock()
	if multiplexer.err != nil {
		err := multiplexer.err
		multiplexer.mu.Unlock()
		return nil, nil, err
	}
	if _, exists := multiplexer.streams[messageID]; exists {
		multiplexer.mu.Unlock()
		return nil, nil, fmt.Errorf("duplicate LDAP message ID %d", messageID)
	}
	multiplexer.streams[messageID] = stream
	multiplexer.mu.Unlock()
	var once sync.Once
	unregister := func() {
		once.Do(func() {
			multiplexer.mu.Lock()
			if multiplexer.streams[messageID] == stream {
				delete(multiplexer.streams, messageID)
			}
			multiplexer.mu.Unlock()
		})
	}
	return stream, unregister, nil
}

func (multiplexer *syncConsumerMultiplexer) read() {
	for {
		packet, err := readSyncConsumerPacket(
			multiplexer.transport.currentConnection(),
		)
		if err != nil {
			multiplexer.fail(err)
			return
		}
		messageID, err := multiplexedLDAPMessageID(packet)
		if err != nil {
			multiplexer.fail(err)
			return
		}
		multiplexer.mu.Lock()
		stream := multiplexer.streams[messageID]
		multiplexer.mu.Unlock()
		if stream != nil {
			if err := stream.push(packet); err != nil {
				// Dropping one stream would leave its remaining responses on
				// the shared connection, so an overflow invalidates the mux.
				multiplexer.fail(fmt.Errorf(
					"multiplexed LDAP response stream %d: %w",
					messageID,
					err,
				))
				return
			}
		}
	}
}

func (multiplexer *syncConsumerMultiplexer) fail(err error) {
	multiplexer.mu.Lock()
	if multiplexer.err != nil {
		multiplexer.mu.Unlock()
		return
	}
	multiplexer.err = err
	streams := make([]*syncConsumerResponseStream, 0, len(multiplexer.streams))
	for _, stream := range multiplexer.streams {
		streams = append(streams, stream)
	}
	multiplexer.streams = nil
	multiplexer.mu.Unlock()
	for _, stream := range streams {
		stream.fail(err)
	}
	_ = multiplexer.transport.close()
}

func multiplexedLDAPMessageID(packet *ber.Packet) (int64, error) {
	if packet == nil || packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypeConstructed || packet.Tag != ber.TagSequence ||
		len(packet.Children) < 2 {
		return 0, errors.New("malformed multiplexed LDAP response envelope")
	}
	messageID := packet.Children[0]
	if messageID.ClassType != ber.ClassUniversal ||
		messageID.TagType != ber.TypePrimitive || messageID.Tag != ber.TagInteger {
		return 0, errors.New("multiplexed LDAP response has invalid message ID")
	}
	value, ok := messageID.Value.(int64)
	if !ok || value < 0 {
		return 0, fmt.Errorf(
			"multiplexed LDAP response message ID = %#v",
			messageID.Value,
		)
	}
	return value, nil
}
