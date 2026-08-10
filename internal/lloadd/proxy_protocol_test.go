package lloadd

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestProxyClosesClientOnDuplicatePendingMessageID(t *testing.T) {
	searches := make(chan Frame, 2)
	abandons := make(chan Frame, 1)
	upstream := startProxyTestUpstream(t, "unused", func(_ net.Conn, frame Frame) bool {
		switch frame.ProtocolTag {
		case TagSearchRequest:
			searches <- frame
			return true
		case TagAbandonRequest:
			abandons <- frame
			return true
		default:
			return false
		}
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	if err := ldapwire.Write(connection, proxySearchRequest(t, 7)); err != nil {
		t.Fatalf("write first Search: %v", err)
	}
	var first Frame
	select {
	case first = <-searches:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive first Search")
	}
	waitForProxyOperationSent(t, proxy, 7)

	if err := ldapwire.Write(connection, proxySearchRequest(t, 7)); err != nil {
		t.Fatalf("write duplicate Search: %v", err)
	}
	expectProxyProtocolTestConnectionClosed(t, connection)

	select {
	case abandon := <-abandons:
		if abandon.AbandonTarget != first.MessageID {
			t.Fatalf("upstream Abandon target = %d, want %d", abandon.AbandonTarget, first.MessageID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("duplicate MessageID disconnect did not abandon the original operation")
	}
	select {
	case duplicate := <-searches:
		t.Fatalf("duplicate MessageID reached upstream: %s", duplicate)
	default:
	}
}

func TestProxyRetiresUpstreamOnUnsolicitedResponse(t *testing.T) {
	var notices atomic.Int64
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		notices.Add(1)
		_ = ldapwire.Write(connection, ldapwire.EncodeNoticeOfDisconnection(ldapwire.Result{
			Code:              ldapwire.ResultUnavailable,
			DiagnosticMessage: "upstream is shutting down",
		}))
		return true
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	if err := ldapwire.Write(connection, proxySearchRequest(t, 8)); err != nil {
		t.Fatalf("write Search: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read generated Search response: %v", err)
	}
	if response.MessageID != 8 || response.ProtocolTag != TagSearchResultDone ||
		response.ResultCode == nil || *response.ResultCode != ResultOther {
		t.Fatalf("generated Search response = %s", response)
	}
	if notices.Load() != 1 {
		t.Fatalf("upstream notices written = %d, want 1", notices.Load())
	}
}

func TestProxyClosesBindAssociationOnUnexpectedResponseType(t *testing.T) {
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagBindRequest {
			return false
		}
		_ = ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
			frame.MessageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
		return true
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolBind, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	request := encodeFrame(
		9,
		testSimpleBind("uid=alice,dc=example,dc=com", []byte("password")),
		nil,
	)
	if err := ldapwire.Write(connection, request); err != nil {
		t.Fatalf("write Bind: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read generated Bind response: %v", err)
	}
	if response.MessageID != 9 || response.ProtocolTag != TagBindResponse ||
		response.ResultCode == nil || *response.ResultCode != ResultOther {
		t.Fatalf("generated Bind response = %s", response)
	}
	expectProxyProtocolTestConnectionClosed(t, connection)
}

func TestProxyClosesConnectionAffinityClientWhenUpstreamIsLost(t *testing.T) {
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		writeProxyTestSearchResult(connection, frame.MessageID, "affinity")
		_ = connection.Close()
		return true
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		RestrictControls: map[string]RuntimeRestriction{
			"1.2.3.4": RuntimeRestrictionConnection,
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	if err := ldapwire.Write(connection, proxyControlledSearchRequest(t, 10, "1.2.3.4")); err != nil {
		t.Fatalf("write connection-affinity Search: %v", err)
	}
	entry, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Search entry: %v", err)
	}
	if entry.MessageID != 10 || entry.ProtocolTag != TagSearchResultEntry {
		t.Fatalf("Search entry = %s", entry)
	}
	done, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Search done: %v", err)
	}
	if done.MessageID != 10 || done.ProtocolTag != TagSearchResultDone ||
		done.ResultCode == nil || *done.ResultCode != ResultSuccess {
		t.Fatalf("Search done = %s", done)
	}
	expectProxyProtocolTestConnectionClosed(t, connection)
}

func TestProxyDoesNotReserveReplacementForStaleConnectionAffinity(t *testing.T) {
	proxy, err := NewProxy(RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldap://127.0.0.1:1",
				RegularConnections: 1,
				BindConnections:    1,
				Weight:             1,
			}},
		}},
	})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	backend := proxy.tiers[0].backends[0]
	connectionID := backendConnectionID(backend.id, false, 0)
	stale := &upstreamConnection{
		backend: backend,
		id:      connectionID,
		closed:  true,
		pending: make(map[int64]*proxyOperation),
		done:    make(chan struct{}),
	}
	replacement := &upstreamConnection{
		backend: backend,
		id:      connectionID,
		pending: make(map[int64]*proxyOperation),
		done:    make(chan struct{}),
	}
	proxy.upstreams[connectionID] = replacement
	if err := proxy.scheduler.SetConnectionState(connectionID, ConnectionReady); err != nil {
		t.Fatalf("mark replacement ready: %v", err)
	}
	client := &clientConnection{
		proxy:            proxy,
		done:             make(chan struct{}),
		ops:              make(map[int64]*proxyOperation),
		upstreamAffinity: stale,
		restriction:      RuntimeRestrictionConnection,
	}
	operation := &proxyOperation{
		client:      client,
		clientID:    15,
		requestTag:  TagSearchRequest,
		restriction: RuntimeRestrictionConnection,
		started:     time.Now(),
	}

	selected, result := proxy.selectUpstream(client, operation, false)
	if selected != nil || result != reserveUnavailable {
		t.Fatalf("select stale affinity = (%p, %d), want (nil, unavailable)", selected, result)
	}
	snapshot := proxy.scheduler.Snapshot()
	for _, connection := range snapshot.Connections {
		if connection.ID != connectionID {
			continue
		}
		if connection.State != ConnectionReady || connection.Pending != 0 {
			t.Fatalf("replacement scheduler state = %#v", connection)
		}
		return
	}
	t.Fatalf("replacement connection %q missing from scheduler", connectionID)
}

func TestProxyClientMaxPendingMatchesOpenLDAPThreshold(t *testing.T) {
	t.Run("one rejects first non-Bind operation but permits Bind", func(t *testing.T) {
		var searches atomic.Int64
		upstream := startProxyTestUpstream(t, "unused", func(_ net.Conn, frame Frame) bool {
			if frame.ProtocolTag == TagSearchRequest {
				searches.Add(1)
				return true
			}
			return false
		})
		proxy, address := startRuntimeProxy(t, RuntimeConfig{
			ClientMaxPending: 1,
			Tiers: []RuntimeTierConfig{{
				Strategy: "roundrobin",
				Backends: []RuntimeBackendConfig{
					proxyTestBackend(upstream.listener.Addr().String()),
				},
			}},
		})
		waitForReadyConnections(t, proxy, PoolRegular, 1)
		waitForReadyConnections(t, proxy, PoolBind, 1)

		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		if err := ldapwire.Write(connection, proxySearchRequest(t, 11)); err != nil {
			t.Fatalf("write Search: %v", err)
		}
		response, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read busy response: %v", err)
		}
		if response.MessageID != 11 || response.ResultCode == nil ||
			*response.ResultCode != ResultBusy {
			t.Fatalf("busy response = %s", response)
		}
		if searches.Load() != 0 {
			t.Fatalf("rejected Search reached upstream %d times", searches.Load())
		}

		bind := encodeFrame(12, testSimpleBind("", nil), nil)
		if err := ldapwire.Write(connection, bind); err != nil {
			t.Fatalf("write Bind: %v", err)
		}
		response, err = ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read Bind response: %v", err)
		}
		if response.MessageID != 12 || response.ProtocolTag != TagBindResponse ||
			response.ResultCode == nil || *response.ResultCode != ResultSuccess {
			t.Fatalf("Bind response = %s", response)
		}
	})

	t.Run("two permits one pending non-Bind operation", func(t *testing.T) {
		searches := make(chan Frame, 2)
		upstream := startProxyTestUpstream(t, "unused", func(_ net.Conn, frame Frame) bool {
			if frame.ProtocolTag != TagSearchRequest {
				return false
			}
			searches <- frame
			return true
		})
		proxy, address := startRuntimeProxy(t, RuntimeConfig{
			ClientMaxPending: 2,
			Tiers: []RuntimeTierConfig{{
				Strategy: "roundrobin",
				Backends: []RuntimeBackendConfig{
					proxyTestBackend(upstream.listener.Addr().String()),
				},
			}},
		})
		waitForReadyConnections(t, proxy, PoolRegular, 1)

		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		if err := ldapwire.Write(connection, proxySearchRequest(t, 13)); err != nil {
			t.Fatalf("write first Search: %v", err)
		}
		select {
		case <-searches:
		case <-time.After(2 * time.Second):
			t.Fatal("first Search did not reach upstream")
		}
		if err := ldapwire.Write(connection, proxySearchRequest(t, 14)); err != nil {
			t.Fatalf("write second Search: %v", err)
		}
		response, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read busy response: %v", err)
		}
		if response.MessageID != 14 || response.ResultCode == nil ||
			*response.ResultCode != ResultBusy {
			t.Fatalf("busy response = %s", response)
		}
		select {
		case second := <-searches:
			t.Fatalf("second Search reached upstream: %s", second)
		default:
		}
	})
}

func TestUpstreamMessageIDAllocationSkipsPendingIDsAcrossWrap(t *testing.T) {
	upstream := &upstreamConnection{
		nextID: MaxMessageID,
		pending: map[int64]*proxyOperation{
			MaxMessageID: {},
			1:            {},
		},
	}
	messageID, ok := upstream.allocateMessageID()
	if !ok || messageID != 2 {
		t.Fatalf("allocateMessageID() = (%d, %t), want (2, true)", messageID, ok)
	}
	messageID, ok = upstream.allocateMessageID()
	if !ok || messageID != 3 {
		t.Fatalf("second allocateMessageID() = (%d, %t), want (3, true)", messageID, ok)
	}
}

func dialProxyProtocolTestClient(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	return connection
}

func expectProxyProtocolTestConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err == nil {
		t.Fatal("proxy returned an LDAP response instead of closing the association")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatal("proxy left the client association open")
	}
}

func waitForProxyOperationSent(t *testing.T, proxy *Proxy, messageID int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		proxy.mu.Lock()
		clients := make([]*clientConnection, 0, len(proxy.clients))
		for client := range proxy.clients {
			clients = append(clients, client)
		}
		proxy.mu.Unlock()
		for _, client := range clients {
			client.mu.Lock()
			operation := client.ops[messageID]
			client.mu.Unlock()
			if operation == nil {
				continue
			}
			operation.mu.Lock()
			sent := operation.requestSent
			operation.mu.Unlock()
			if sent {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("client operation %d was not marked sent", messageID)
}

func proxyControlledSearchRequest(t *testing.T, messageID int64, oid string) []byte {
	t.Helper()
	search, err := ParseFrame(proxySearchRequest(t, messageID), DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("parse Search: %v", err)
	}
	return encodeFrame(
		messageID,
		search.ProtocolOp,
		encodeTLV(0xa0, testControl(oid, false, false, nil)),
	)
}
