package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestBackMetaSharedTransportCancellationPreservesConcurrentSearch(t *testing.T) {
	pool, chain, remote, peer := newBackMetaSafetyTransport(t, nil)
	server := &Server{}
	state := &connectionState{protocolVersion: 3}
	firstRequest := makeBackMetaSafetySearch(1, "dc=first,dc=example")
	secondRequest := makeBackMetaSafetySearch(2, "dc=second,dc=example")

	firstSearch := make(chan int64, 1)
	secondSearch := make(chan int64, 1)
	abandonSeen := make(chan struct{})
	allowSecondResponse := make(chan struct{})
	providerDone := make(chan error, 1)
	go func() {
		first, err := readBackMetaSafetyRequest(peer, ldapwire.ApplicationSearchRequest)
		if err != nil {
			providerDone <- err
			return
		}
		firstSearch <- first
		second, err := readBackMetaSafetyRequest(peer, ldapwire.ApplicationSearchRequest)
		if err != nil {
			providerDone <- err
			return
		}
		secondSearch <- second
		if _, err := readBackMetaSafetyRequest(peer, ldapwire.ApplicationAbandonRequest); err != nil {
			providerDone <- err
			return
		}
		close(abandonSeen)
		<-allowSecondResponse
		providerDone <- ldapwire.Write(peer, ldapwire.EncodeSearchResultDone(
			second,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}()

	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan chainAttempt, 1)
	go func() {
		firstDone <- server.executeChainTarget(
			firstContext,
			state,
			chain,
			remote,
			firstRequest,
			0,
		)
	}()
	awaitBackMetaSafetyMessageID(t, firstSearch, "first Search")

	secondDone := make(chan chainAttempt, 1)
	go func() {
		secondDone <- server.executeChainTarget(
			context.Background(),
			state,
			chain,
			remote,
			secondRequest,
			0,
		)
	}()
	awaitBackMetaSafetyMessageID(t, secondSearch, "second Search")
	waitBackMetaSafetyReferences(t, pool, chain.transportKey, 2)

	cancelFirst()
	awaitBackMetaSafetySignal(t, abandonSeen, "upstream Abandon")
	first := awaitBackMetaSafetyAttempt(t, firstDone, "canceled Search")
	if !errors.Is(first.transportErr, context.Canceled) {
		t.Fatalf("canceled Search error = %v, want context.Canceled", first.transportErr)
	}
	close(allowSecondResponse)

	second := awaitBackMetaSafetyAttempt(t, secondDone, "concurrent Search")
	if second.transportErr != nil || !second.hasResult ||
		second.result.Code != ldapwire.ResultSuccess {
		t.Fatalf("concurrent Search attempt = %#v, want successful result", second)
	}
	if err := awaitBackMetaSafetyError(t, providerDone, "provider completion"); err != nil {
		t.Fatalf("provider completion: %v", err)
	}
}

func TestBackMetaPooledWriteTimeoutDoesNotPoisonNextWriter(t *testing.T) {
	writeStarted := make(chan struct{})
	pool, chain, remote, peer := newBackMetaSafetyTransport(
		t,
		func(connection net.Conn) net.Conn {
			return &backMetaSafetyObservedWriteConn{
				Conn:    connection,
				started: writeStarted,
			}
		},
	)
	server := &Server{}
	state := &connectionState{protocolVersion: 3}
	firstRemote := remote.clone()
	firstRemote.operationTimeouts[ldapwire.ApplicationSearchRequest] = 250 * time.Millisecond

	firstDone := make(chan chainAttempt, 1)
	go func() {
		firstDone <- server.executeChainTarget(
			context.Background(),
			state,
			chain,
			firstRemote,
			makeBackMetaSafetySearch(1, "dc=blocked,dc=example"),
			0,
		)
	}()
	awaitBackMetaSafetySignal(t, writeStarted, "blocked pooled write")

	secondContext, cancelSecond := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSecond()
	secondDone := make(chan chainAttempt, 1)
	go func() {
		secondDone <- server.executeChainTarget(
			secondContext,
			state,
			chain,
			remote,
			makeBackMetaSafetySearch(2, "dc=next,dc=example"),
			0,
		)
	}()
	waitBackMetaSafetyReferences(t, pool, chain.transportKey, 2)

	first := awaitBackMetaSafetyAttempt(t, firstDone, "timed-out pooled write")
	if first.transportErr == nil {
		t.Fatalf("timed-out pooled write attempt = %#v, want an error", first)
	}
	if first.requestSent {
		t.Fatal("timed-out zero-byte pooled write was marked as sent")
	}

	providerDone := make(chan error, 1)
	go func() {
		messageID, err := readBackMetaSafetyRequest(peer, ldapwire.ApplicationSearchRequest)
		if err != nil {
			providerDone <- err
			return
		}
		providerDone <- ldapwire.Write(peer, ldapwire.EncodeSearchResultDone(
			messageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}()

	second := awaitBackMetaSafetyAttempt(t, secondDone, "write after timeout")
	if second.transportErr != nil || !second.hasResult ||
		second.result.Code != ldapwire.ResultSuccess {
		t.Fatalf("write after timeout attempt = %#v, want successful result", second)
	}
	if err := awaitBackMetaSafetyError(t, providerDone, "provider completion"); err != nil {
		t.Fatalf("provider completion: %v", err)
	}
}

func TestBackMetaSharedTransportProtocolFailureEvictsConnection(t *testing.T) {
	pool, chain, remote, peer := newBackMetaSafetyTransport(t, nil)
	server := &Server{}
	state := &connectionState{protocolVersion: 3}
	firstSearch := make(chan int64, 1)
	secondSearch := make(chan int64, 1)
	sendMalformedResponse := make(chan struct{})
	providerDone := make(chan error, 1)
	go func() {
		first, err := readBackMetaSafetyRequest(peer, ldapwire.ApplicationSearchRequest)
		if err != nil {
			providerDone <- err
			return
		}
		firstSearch <- first
		second, err := readBackMetaSafetyRequest(peer, ldapwire.ApplicationSearchRequest)
		if err != nil {
			providerDone <- err
			return
		}
		secondSearch <- second
		<-sendMalformedResponse
		providerDone <- ldapwire.Write(peer, ldapwire.EncodeResultResponse(
			first,
			ldapwire.ApplicationModifyResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}()

	firstDone := make(chan chainAttempt, 1)
	go func() {
		firstDone <- server.executeChainTarget(
			context.Background(),
			state,
			chain,
			remote,
			makeBackMetaSafetySearch(1, "dc=malformed,dc=example"),
			0,
		)
	}()
	awaitBackMetaSafetyMessageID(t, firstSearch, "first protocol-failure Search")

	secondDone := make(chan chainAttempt, 1)
	go func() {
		secondDone <- server.executeChainTarget(
			context.Background(),
			state,
			chain,
			remote,
			makeBackMetaSafetySearch(2, "dc=concurrent,dc=example"),
			0,
		)
	}()
	awaitBackMetaSafetyMessageID(t, secondSearch, "second protocol-failure Search")
	waitBackMetaSafetyReferences(t, pool, chain.transportKey, 2)
	close(sendMalformedResponse)

	first := awaitBackMetaSafetyAttempt(t, firstDone, "protocol-failure Search")
	if first.transportErr == nil {
		t.Fatalf("protocol-failure Search attempt = %#v, want an error", first)
	}
	second := awaitBackMetaSafetyAttempt(t, secondDone, "Search sharing failed transport")
	if second.transportErr == nil {
		t.Fatalf("Search sharing failed transport = %#v, want an error", second)
	}
	if err := awaitBackMetaSafetyError(t, providerDone, "provider completion"); err != nil {
		t.Fatalf("provider completion: %v", err)
	}

	pool.mu.Lock()
	group := pool.groups[chain.transportKey]
	entries := 0
	if group != nil {
		entries = len(group.entries)
	}
	pool.mu.Unlock()
	if entries != 0 {
		t.Fatalf("pooled entries after protocol failure = %d, want 0", entries)
	}
}

type backMetaSafetyObservedWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (connection *backMetaSafetyObservedWriteConn) Write(encoded []byte) (int, error) {
	connection.once.Do(func() { close(connection.started) })
	return connection.Conn.Write(encoded)
}

func newBackMetaSafetyTransport(
	t *testing.T,
	wrap func(net.Conn) net.Conn,
) (*metaTransportPool, chainRuntimeConfiguration, chainRemoteConfiguration, net.Conn) {
	t.Helper()
	client, peer := net.Pipe()
	if wrap != nil {
		client = wrap(client)
	}
	transport := &syncConsumerTransport{
		connection: client,
		context:    context.Background(),
	}
	pool := newMetaTransportPool(nil)
	remote := defaultChainRemoteConfiguration()
	remote.uri = "ldap://back-meta-safety.test"
	remote.endpointKey = remote.uri
	remote.cancelMode = "abandon"
	chain := chainRuntimeConfiguration{
		transportPool:    pool,
		transportKey:     "back-meta-safety",
		transportPoolMax: 1,
	}

	pooled, lease, err := pool.acquire(
		context.Background(),
		chain.transportKey,
		remote,
		chain.transportPoolMax,
		false,
	)
	if err != nil {
		t.Fatalf("reserve safety transport: %v", err)
	}
	if pooled != nil || lease == nil || !lease.reserved {
		t.Fatalf("safety reservation = (%p, %#v)", pooled, lease)
	}
	if !pool.publish(lease, transport) {
		t.Fatal("publish safety transport = false")
	}
	pool.release(lease, remote, transport, true)

	t.Cleanup(func() {
		pool.close()
		_ = peer.Close()
	})
	return pool, chain, remote, peer
}

func makeBackMetaSafetySearch(messageID int64, baseDN string) ldapwire.Message {
	return ldapwire.Message{
		ID: messageID,
		Request: ldapwire.SearchRequest{
			BaseDN: baseDN,
			Scope:  directory.ScopeBase,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
		},
	}
}

func readBackMetaSafetyRequest(connection net.Conn, wantTag uint64) (int64, error) {
	packet, err := readSyncConsumerPacket(connection)
	if err != nil {
		return 0, err
	}
	messageID, err := multiplexedLDAPMessageID(packet)
	if err != nil {
		return 0, err
	}
	if len(packet.Children) < 2 || uint64(packet.Children[1].Tag) != wantTag {
		return 0, fmt.Errorf(
			"LDAP request tag = %d, want %d",
			packet.Children[1].Tag,
			wantTag,
		)
	}
	return messageID, nil
}

func waitBackMetaSafetyReferences(
	t *testing.T,
	pool *metaTransportPool,
	key string,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		group := pool.groups[key]
		got := 0
		if group != nil && len(group.entries) == 1 {
			got = group.entries[0].references
		}
		pool.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pooled transport references did not reach %d", want)
}

func awaitBackMetaSafetyMessageID(
	t *testing.T,
	messages <-chan int64,
	description string,
) int64 {
	t.Helper()
	select {
	case messageID := <-messages:
		return messageID
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
		return 0
	}
}

func awaitBackMetaSafetySignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitBackMetaSafetyAttempt(
	t *testing.T,
	attempts <-chan chainAttempt,
	description string,
) chainAttempt {
	t.Helper()
	select {
	case attempt := <-attempts:
		return attempt
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
		return chainAttempt{}
	}
}

func awaitBackMetaSafetyError(
	t *testing.T,
	errors <-chan error,
	description string,
) error {
	t.Helper()
	select {
	case err := <-errors:
		return err
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
		return nil
	}
}
