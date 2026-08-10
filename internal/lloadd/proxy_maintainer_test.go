package lloadd

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type serviceBindPeerResult struct {
	request  Frame
	readErr  error
	writeErr error
	closeErr error
}

type maintainerReadSignalConn struct {
	net.Conn
	once        sync.Once
	readStarted chan struct{}
}

func (connection *maintainerReadSignalConn) Read(buffer []byte) (int, error) {
	connection.once.Do(func() { close(connection.readStarted) })
	return connection.Conn.Read(buffer)
}

func TestServiceBindRejectsWrongResponseMessageID(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	peerResult := make(chan serviceBindPeerResult, 1)
	go func() {
		result := serviceBindPeerResult{}
		result.request, result.readErr = ReadFrame(peer, DefaultMaxFrameSize)
		if result.readErr == nil {
			result.writeErr = ldapwire.Write(peer, ldapwire.EncodeBindResponse(
				serviceBindMessageID+1,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			))
		}
		if result.readErr == nil && result.writeErr == nil {
			var buffer [1]byte
			_, result.closeErr = peer.Read(buffer[:])
		}
		peerResult <- result
	}()

	proxy, err := NewProxy(RuntimeConfig{
		ProxyAuthz: true,
		Bind: RuntimeBindConfig{
			Method:      "simple",
			DN:          "cn=Manager,dc=example,dc=com",
			Credentials: []byte("secret"),
			Timeout:     time.Second,
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return local, nil
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldap://ldap.example.com:389",
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	upstream, connectErr := backend.connect(
		ctx,
		backendConnectionID(backend.id, false, 0),
		false,
	)
	if upstream != nil {
		_ = upstream.conn.Close()
	} else {
		_ = local.Close()
	}
	if connectErr == nil {
		t.Fatal("backend.connect() accepted a service Bind response with the wrong message ID")
	}
	if !strings.Contains(connectErr.Error(), "message ID 2 does not match request 1") {
		t.Fatalf("backend.connect() error = %v", connectErr)
	}

	select {
	case result := <-peerResult:
		if result.readErr != nil {
			t.Fatalf("read service Bind request: %v", result.readErr)
		}
		if result.writeErr != nil {
			t.Fatalf("write service Bind response: %v", result.writeErr)
		}
		if result.request.MessageID != serviceBindMessageID ||
			result.request.ProtocolTag != TagBindRequest {
			t.Fatalf(
				"service Bind request = messageID %d tag %d",
				result.request.MessageID,
				result.request.ProtocolTag,
			)
		}
		if !errors.Is(result.closeErr, io.EOF) && !errors.Is(result.closeErr, net.ErrClosed) {
			t.Fatalf("service Bind connection remained open: %v", result.closeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service Bind peer did not observe connection closure")
	}
}

func TestBackendMaintainerFailingRegularSlotDoesNotStarveOtherSlots(t *testing.T) {
	proxy, err := NewProxy(RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldap://ldap.example.com:389",
				RegularConnections: 2,
				BindConnections:    1,
				Retry:              5 * time.Millisecond,
				Weight:             1,
			}},
		}},
	})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	backend := proxy.tiers[0].backends[0]
	failedID := backendConnectionID(backend.id, false, 0)
	regularID := backendConnectionID(backend.id, false, 1)
	bindID := backendConnectionID(backend.id, true, 0)
	failedAttempts := []chan struct{}{
		make(chan struct{}),
		make(chan struct{}),
		make(chan struct{}),
	}
	regularRead := make(chan struct{})
	bindRead := make(chan struct{})
	unexpected := make(chan error, 1)

	var attemptsMu sync.Mutex
	attempts := make(map[string]int)
	var peersMu sync.Mutex
	var peers []net.Conn
	connect := func(
		ctx context.Context,
		connectionID string,
		bind bool,
	) (*upstreamConnection, error) {
		attemptsMu.Lock()
		attempts[connectionID]++
		attempt := attempts[connectionID]
		attemptsMu.Unlock()
		if connectionID == failedID {
			if bind {
				select {
				case unexpected <- errors.New("regular-0 was marked as a Bind connection"):
				default:
				}
			}
			if attempt <= len(failedAttempts) {
				close(failedAttempts[attempt-1])
			}
			if attempt == len(failedAttempts) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, errors.New("forced regular-0 connection failure")
		}

		var readStarted chan struct{}
		switch connectionID {
		case regularID:
			readStarted = regularRead
			if bind {
				select {
				case unexpected <- errors.New("regular-1 was marked as a Bind connection"):
				default:
				}
			}
		case bindID:
			readStarted = bindRead
			if !bind {
				select {
				case unexpected <- errors.New("bind-0 was marked as a regular connection"):
				default:
				}
			}
		default:
			return nil, errors.New("maintainer requested an unconfigured connection slot")
		}

		local, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		return &upstreamConnection{
			backend: backend,
			id:      connectionID,
			bind:    bind,
			conn: &maintainerReadSignalConn{
				Conn:        local,
				readStarted: readStarted,
			},
			pending: make(map[int64]*proxyOperation),
			nextID:  serviceBindMessageID,
			done:    make(chan struct{}),
			retired: make(chan struct{}),
		}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	maintainerDone := make(chan struct{})
	go func() {
		backend.maintainConnections(ctx, connect)
		close(maintainerDone)
	}()
	waitForMaintainerSignal(t, failedAttempts[0], "first regular-0 failure")
	waitForMaintainerSignal(t, regularRead, "regular-1 connection")
	waitForMaintainerSignal(t, bindRead, "bind-0 connection")
	waitForMaintainerSignal(t, failedAttempts[1], "second regular-0 failure")
	waitForMaintainerSignal(t, failedAttempts[2], "third regular-0 attempt")
	select {
	case err := <-unexpected:
		t.Fatal(err)
	default:
	}

	backend.mu.RLock()
	regular := append([]*upstreamConnection(nil), backend.regular...)
	bind := append([]*upstreamConnection(nil), backend.bind...)
	backend.mu.RUnlock()
	if len(regular) != 1 || regular[0].id != regularID {
		t.Fatalf("regular connections = %#v, want only %s", connectionIDs(regular), regularID)
	}
	if len(bind) != 1 || bind[0].id != bindID {
		t.Fatalf("Bind connections = %#v, want only %s", connectionIDs(bind), bindID)
	}

	states := make(map[string]ConnectionState)
	for _, connection := range proxy.scheduler.Snapshot().Connections {
		states[connection.ID] = connection.State
	}
	if states[failedID] != ConnectionUnavailable {
		t.Fatalf("regular-0 state = %v, want unavailable", states[failedID])
	}
	if states[regularID] != ConnectionReady || states[bindID] != ConnectionReady {
		t.Fatalf(
			"healthy slot states = regular-1 %v, bind-0 %v",
			states[regularID],
			states[bindID],
		)
	}

	attemptsMu.Lock()
	gotAttempts := make(map[string]int, len(attempts))
	for connectionID, count := range attempts {
		gotAttempts[connectionID] = count
	}
	attemptsMu.Unlock()
	if gotAttempts[failedID] != 3 {
		t.Fatalf("connection attempts for %s = %d, want 3", failedID, gotAttempts[failedID])
	}
	for _, connectionID := range []string{regularID, bindID} {
		if gotAttempts[connectionID] != 1 {
			t.Fatalf("connection attempts for %s = %d, want 1", connectionID, gotAttempts[connectionID])
		}
	}

	backend.close()
	select {
	case <-maintainerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("backend maintainer did not stop after backend closure")
	}
	peersMu.Lock()
	for _, peer := range peers {
		_ = peer.Close()
	}
	peersMu.Unlock()
}

func TestBackendMaintainerBlockedDialDoesNotStarveOtherSlots(t *testing.T) {
	dialEntered := make(chan int, 3)
	healthyReadStarted := make(chan (<-chan struct{}), 2)
	releaseBlockedDial := make(chan struct{})
	blockedDialReturned := make(chan struct{})
	var releaseOnce sync.Once
	var callsMu sync.Mutex
	dialCalls := 0
	var peersMu sync.Mutex
	var peers []net.Conn

	proxy, err := NewProxy(RuntimeConfig{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "ldap.example.com:389" {
				return nil, errors.New("backend dial used an unexpected network address")
			}
			callsMu.Lock()
			dialCalls++
			call := dialCalls
			callsMu.Unlock()
			dialEntered <- call
			if call == 1 {
				defer close(blockedDialReturned)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-releaseBlockedDial:
					return nil, errors.New("released blocked dial")
				}
			}

			local, peer := net.Pipe()
			readStarted := make(chan struct{})
			healthyReadStarted <- readStarted
			peersMu.Lock()
			peers = append(peers, peer)
			peersMu.Unlock()
			return &maintainerReadSignalConn{
				Conn:        local,
				readStarted: readStarted,
			}, nil
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldap://ldap.example.com:389",
				RegularConnections: 2,
				BindConnections:    1,
				Retry:              time.Hour,
				Weight:             1,
			}},
		}},
	})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	backend := proxy.tiers[0].backends[0]
	ctx, cancel := context.WithCancel(context.Background())
	maintainerDone := make(chan struct{})
	go func() {
		backend.maintain(ctx)
		close(maintainerDone)
	}()
	defer func() {
		releaseOnce.Do(func() { close(releaseBlockedDial) })
		cancel()
		backend.close()
		peersMu.Lock()
		for _, peer := range peers {
			_ = peer.Close()
		}
		peersMu.Unlock()
		select {
		case <-maintainerDone:
		case <-time.After(2 * time.Second):
			t.Error("backend maintainer did not stop during cleanup")
		}
	}()

	seenCalls := make(map[int]struct{}, 3)
	for len(seenCalls) < 3 {
		select {
		case call := <-dialEntered:
			seenCalls[call] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf(
				"only %d backend DialContext calls entered while the first was blocked",
				len(seenCalls),
			)
		}
	}
	for index := 0; index < 2; index++ {
		var readStarted <-chan struct{}
		select {
		case readStarted = <-healthyReadStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("healthy backend dial did not return a connection")
		}
		waitForMaintainerSignal(t, readStarted, "healthy connection read loop")
	}
	select {
	case <-blockedDialReturned:
		t.Fatal("blocked DialContext returned before its release barrier")
	default:
	}

	releaseOnce.Do(func() { close(releaseBlockedDial) })
	waitForMaintainerSignal(t, blockedDialReturned, "blocked DialContext return")
	callsMu.Lock()
	gotDialCalls := dialCalls
	callsMu.Unlock()
	if gotDialCalls != 3 {
		t.Fatalf("DialContext calls = %d, want exactly one per configured slot", gotDialCalls)
	}

	backend.close()
	select {
	case <-maintainerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("backend maintainer did not stop after backend closure")
	}
}

func waitForMaintainerSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func connectionIDs(connections []*upstreamConnection) []string {
	ids := make([]string, 0, len(connections))
	for _, connection := range connections {
		ids = append(ids, connection.id)
	}
	return ids
}
