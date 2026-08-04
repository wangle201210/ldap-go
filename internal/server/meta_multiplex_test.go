package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestSyncConsumerResponseStreamQueueLimits(t *testing.T) {
	packet := metaMultiplexTestPacketWithPayload(1, 4, []byte("bounded response"))
	packetBytes := len(packet.Bytes())

	t.Run("packet boundary", func(t *testing.T) {
		stream := newSyncConsumerResponseStreamWithLimits(2, packetBytes*3)
		if err := stream.push(packet); err != nil {
			t.Fatalf("push first packet: %v", err)
		}
		if err := stream.push(packet); err != nil {
			t.Fatalf("push packet at count boundary: %v", err)
		}
		if err := stream.push(packet); !errors.Is(err, errSyncConsumerResponseStreamOverflow) {
			t.Fatalf("push over packet boundary error = %v, want queue overflow", err)
		}
		assertMetaMultiplexStreamReleased(t, stream)
	})

	t.Run("byte boundary and dequeue accounting", func(t *testing.T) {
		stream := newSyncConsumerResponseStreamWithLimits(3, packetBytes*2)
		if err := stream.push(packet); err != nil {
			t.Fatalf("push first packet: %v", err)
		}
		if err := stream.push(packet); err != nil {
			t.Fatalf("push packet at byte boundary: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := stream.next(ctx); err != nil {
			t.Fatalf("dequeue packet: %v", err)
		}
		if err := stream.push(packet); err != nil {
			t.Fatalf("reuse released byte capacity: %v", err)
		}
		if err := stream.push(packet); !errors.Is(err, errSyncConsumerResponseStreamOverflow) {
			t.Fatalf("push over byte boundary error = %v, want queue overflow", err)
		}
		assertMetaMultiplexStreamReleased(t, stream)
	})

	t.Run("single packet over byte limit", func(t *testing.T) {
		stream := newSyncConsumerResponseStreamWithLimits(2, packetBytes-1)
		if err := stream.push(packet); !errors.Is(err, errSyncConsumerResponseStreamOverflow) {
			t.Fatalf("push oversized packet error = %v, want queue overflow", err)
		}
		assertMetaMultiplexStreamReleased(t, stream)
	})
}

func TestSyncConsumerMultiplexerOverflowFailsAllStreamsAndClosesConnection(t *testing.T) {
	client, peer := net.Pipe()
	trackedClient := &metaMultiplexCloseTrackingConn{
		Conn:   client,
		closed: make(chan struct{}),
	}
	deadline := time.Now().Add(10 * time.Second)
	if err := trackedClient.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatalf("set peer deadline: %v", err)
	}
	t.Cleanup(func() {
		_ = trackedClient.Close()
		_ = peer.Close()
	})

	transport := &syncConsumerTransport{
		connection: trackedClient,
		context:    context.Background(),
	}
	if err := transport.enableMultiplexing(); err != nil {
		t.Fatalf("enable multiplexing: %v", err)
	}

	const (
		overflowID int64 = 101
		queuedID   int64 = 102
		waitingID  int64 = 103
	)
	overflow, unregisterOverflow, err := transport.multiplexedResponse(overflowID)
	if err != nil {
		t.Fatalf("register overflow stream: %v", err)
	}
	t.Cleanup(unregisterOverflow)
	queued, unregisterQueued, err := transport.multiplexedResponse(queuedID)
	if err != nil {
		t.Fatalf("register queued stream: %v", err)
	}
	t.Cleanup(unregisterQueued)
	waiting, unregisterWaiting, err := transport.multiplexedResponse(waitingID)
	if err != nil {
		t.Fatalf("register waiting stream: %v", err)
	}
	t.Cleanup(unregisterWaiting)

	writeMetaMultiplexTestPacket(t, peer, metaMultiplexTestPacket(queuedID, 1))
	waitForMetaMultiplexQueueLength(t, queued, 1)

	waitResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := waiting.next(ctx)
		waitResult <- err
	}()

	for index := range syncConsumerResponseStreamPacketLimit {
		writeMetaMultiplexTestPacket(
			t,
			peer,
			metaMultiplexTestPacket(overflowID, uint64(index%20+1)),
		)
	}
	waitForMetaMultiplexQueueLength(
		t,
		overflow,
		syncConsumerResponseStreamPacketLimit,
	)
	writeMetaMultiplexTestPacket(t, peer, metaMultiplexTestPacket(overflowID, 21))

	select {
	case err := <-waitResult:
		if !errors.Is(err, errSyncConsumerResponseStreamOverflow) {
			t.Fatalf("waiting stream error = %v, want queue overflow", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waiting stream was not woken after queue overflow")
	}
	select {
	case <-trackedClient.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("shared connection was not closed after queue overflow")
	}

	assertMetaMultiplexStreamReleased(t, overflow)
	assertMetaMultiplexStreamReleased(t, queued)
	assertMetaMultiplexStreamReleased(t, waiting)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := queued.next(ctx); !errors.Is(err, errSyncConsumerResponseStreamOverflow) {
		t.Fatalf("queued stream error = %v, want queue overflow", err)
	}
	if _, _, err := transport.multiplexedResponse(104); !errors.Is(
		err,
		errSyncConsumerResponseStreamOverflow,
	) {
		t.Fatalf("register after overflow error = %v, want queue overflow", err)
	}
}

func TestSyncConsumerMultiplexerIgnoresUnregisteredResponses(t *testing.T) {
	client, peer := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatalf("set peer deadline: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})

	transport := &syncConsumerTransport{
		connection: client,
		context:    context.Background(),
	}
	if err := transport.enableMultiplexing(); err != nil {
		t.Fatalf("enable multiplexing: %v", err)
	}

	ignored, unregisterIgnored, err := transport.multiplexedResponse(201)
	if err != nil {
		t.Fatalf("register ignored stream: %v", err)
	}
	unregisterIgnored()
	active, unregisterActive, err := transport.multiplexedResponse(202)
	if err != nil {
		t.Fatalf("register active stream: %v", err)
	}
	t.Cleanup(unregisterActive)

	writeMetaMultiplexTestPacket(t, peer, metaMultiplexTestPacket(201, 1))
	writeMetaMultiplexTestPacket(t, peer, metaMultiplexTestPacket(202, 2))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assertMetaMultiplexPackets(t, ctx, active, 202, []uint64{2})
	if err := transport.multiplexer.failure(); err != nil {
		t.Fatalf("multiplexer failed on unregistered response: %v", err)
	}

	ignored.mu.Lock()
	ignoredPackets := len(ignored.packets)
	ignored.mu.Unlock()
	if ignoredPackets != 0 {
		t.Fatalf("unregistered stream retained %d packets, want 0", ignoredPackets)
	}
}

func TestSyncConsumerMultiplexerRoutesOutOfOrderResponses(t *testing.T) {
	client, peer := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatalf("set peer deadline: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})

	transport := &syncConsumerTransport{
		connection: client,
		context:    context.Background(),
	}
	if err := transport.enableMultiplexing(); err != nil {
		t.Fatalf("enable multiplexing: %v", err)
	}

	const firstID int64 = 41
	const secondID int64 = 73
	first, unregisterFirst, err := transport.multiplexedResponse(firstID)
	if err != nil {
		t.Fatalf("register first response stream: %v", err)
	}
	t.Cleanup(unregisterFirst)
	second, unregisterSecond, err := transport.multiplexedResponse(secondID)
	if err != nil {
		t.Fatalf("register second response stream: %v", err)
	}
	t.Cleanup(unregisterSecond)

	responses := []*ber.Packet{
		metaMultiplexTestPacket(secondID, 21),
		metaMultiplexTestPacket(firstID, 11),
		metaMultiplexTestPacket(secondID, 22),
		metaMultiplexTestPacket(firstID, 12),
	}
	for index, response := range responses {
		if err := writeSyncConsumerPacket(peer, response.Bytes()); err != nil {
			t.Fatalf("write response %d: %v", index, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assertMetaMultiplexPackets(t, ctx, first, firstID, []uint64{11, 12})
	assertMetaMultiplexPackets(t, ctx, second, secondID, []uint64{21, 22})
}

func TestSyncConsumerTransportConcurrentMessageIDsAndWrites(t *testing.T) {
	const operations = 128

	client, peer := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatalf("set peer deadline: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})

	transport := &syncConsumerTransport{
		connection: &metaMultiplexShortWriteConn{Conn: client},
		context:    context.Background(),
	}
	received := make(chan []int64, 1)
	readErr := make(chan error, 1)
	go func() {
		messageIDs := make([]int64, 0, operations)
		for range operations {
			packet, err := readSyncConsumerPacket(peer)
			if err != nil {
				readErr <- err
				return
			}
			messageID, err := multiplexedLDAPMessageID(packet)
			if err != nil {
				readErr <- err
				return
			}
			messageIDs = append(messageIDs, messageID)
		}
		received <- messageIDs
	}()

	start := make(chan struct{})
	var ready sync.WaitGroup
	var writers sync.WaitGroup
	ready.Add(operations)
	writers.Add(operations)
	writeErrs := make(chan error, operations)
	generated := make(chan int64, operations)
	for range operations {
		go func() {
			defer writers.Done()
			ready.Done()
			<-start
			messageID := transport.nextMessageID()
			generated <- messageID
			packet := metaMultiplexTestPacket(messageID, 1)
			if err := transport.writePacket(packet.Bytes()); err != nil {
				writeErrs <- err
			}
		}()
	}
	ready.Wait()
	close(start)
	writers.Wait()
	close(writeErrs)
	close(generated)
	for err := range writeErrs {
		t.Errorf("concurrent write: %v", err)
	}

	var messageIDs []int64
	select {
	case err := <-readErr:
		t.Fatalf("read concurrent writes: %v", err)
	case messageIDs = <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out reading concurrent writes")
	}

	assertMetaMultiplexIDSet(t, generated, operations, "generated")
	receivedIDs := make(chan int64, operations)
	for _, messageID := range messageIDs {
		receivedIDs <- messageID
	}
	close(receivedIDs)
	assertMetaMultiplexIDSet(t, receivedIDs, operations, "received")
}

type metaMultiplexShortWriteConn struct {
	net.Conn
}

func (connection *metaMultiplexShortWriteConn) Write(encoded []byte) (int, error) {
	if len(encoded) > 1 {
		encoded = encoded[:1]
	}
	return connection.Conn.Write(encoded)
}

type metaMultiplexCloseTrackingConn struct {
	net.Conn
	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

func (connection *metaMultiplexCloseTrackingConn) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		close(connection.closed)
	})
	return connection.closeErr
}

func metaMultiplexTestPacket(messageID int64, operationTag uint64) *ber.Packet {
	return metaMultiplexTestPacketWithPayload(
		messageID,
		operationTag,
		[]byte{byte(operationTag)},
	)
}

func metaMultiplexTestPacketWithPayload(
	messageID int64,
	operationTag uint64,
	payload []byte,
) *ber.Packet {
	packet := ber.NewSequence("LDAPMessage")
	packet.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	packet.AppendChild(ber.Encode(
		ber.ClassApplication,
		ber.TypePrimitive,
		ber.Tag(operationTag),
		payload,
		"operation",
	))
	return packet
}

func writeMetaMultiplexTestPacket(
	t *testing.T,
	connection net.Conn,
	packet *ber.Packet,
) {
	t.Helper()
	if err := writeSyncConsumerPacket(connection, packet.Bytes()); err != nil {
		t.Fatalf("write response packet: %v", err)
	}
}

func waitForMetaMultiplexQueueLength(
	t *testing.T,
	stream *syncConsumerResponseStream,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		stream.mu.Lock()
		got := len(stream.packets)
		err := stream.err
		stream.mu.Unlock()
		if err != nil {
			t.Fatalf("response stream failed with %d queued packets: %v", got, err)
		}
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	stream.mu.Lock()
	got := len(stream.packets)
	stream.mu.Unlock()
	t.Fatalf("queued packets = %d, want %d", got, want)
}

func assertMetaMultiplexStreamReleased(
	t *testing.T,
	stream *syncConsumerResponseStream,
) {
	t.Helper()
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if got := len(stream.packets); got != 0 {
		t.Errorf("retained packets = %d, want 0", got)
	}
	if stream.queuedBytes != 0 {
		t.Errorf("retained packet bytes = %d, want 0", stream.queuedBytes)
	}
	if !errors.Is(stream.err, errSyncConsumerResponseStreamOverflow) {
		t.Errorf("stream error = %v, want queue overflow", stream.err)
	}
}

func assertMetaMultiplexPackets(
	t *testing.T,
	ctx context.Context,
	stream *syncConsumerResponseStream,
	wantMessageID int64,
	wantTags []uint64,
) {
	t.Helper()
	for index, wantTag := range wantTags {
		packet, err := stream.next(ctx)
		if err != nil {
			t.Fatalf("response %d for message %d: %v", index, wantMessageID, err)
		}
		messageID, err := multiplexedLDAPMessageID(packet)
		if err != nil {
			t.Fatalf("parse response %d for message %d: %v", index, wantMessageID, err)
		}
		if messageID != wantMessageID {
			t.Fatalf(
				"response %d message ID = %d, want %d",
				index,
				messageID,
				wantMessageID,
			)
		}
		if got := uint64(packet.Children[1].Tag); got != wantTag {
			t.Fatalf(
				"response %d operation tag = %d, want %d",
				index,
				got,
				wantTag,
			)
		}
	}
}

func assertMetaMultiplexIDSet(
	t *testing.T,
	messageIDs <-chan int64,
	want int,
	description string,
) {
	t.Helper()
	seen := make(map[int64]struct{}, want)
	for messageID := range messageIDs {
		if messageID < 1 || messageID > int64(want) {
			t.Errorf("%s message ID = %d, want 1..%d", description, messageID, want)
			continue
		}
		if _, exists := seen[messageID]; exists {
			t.Errorf("duplicate %s message ID %d", description, messageID)
		}
		seen[messageID] = struct{}{}
	}
	if len(seen) != want {
		t.Errorf("%s message ID count = %d, want %d", description, len(seen), want)
	}
}
