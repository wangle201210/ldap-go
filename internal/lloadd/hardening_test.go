package lloadd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestClientIdleTimeoutSendsNoticeAndCloses(t *testing.T) {
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ClientIdleTimeout: 40 * time.Millisecond,
	})
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	response, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read idle disconnect: %v", err)
	}
	if !bytes.Contains(response, []byte("connection idle timeout")) {
		t.Fatalf("idle disconnect response = %x", response)
	}
	waitForProxyClientCount(t, proxy, 0)
}

func TestDaemonPrepareConcurrencyDoesNotBlockAccept(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	topology := DaemonTopology{Runtime: RuntimeConfig{}, ListenURLs: []string{"127.0.0.1:0"}}
	daemon, err := NewDaemon(DaemonOptions{
		Load:        func(context.Context) (DaemonTopology, error) { return topology, nil },
		ListenerKey: func(raw string) (string, error) { return raw, nil },
		Listen: func(raw string) (net.Listener, string, error) {
			listener, listenErr := net.Listen("tcp", raw)
			if listenErr != nil {
				return nil, "", listenErr
			}
			return listener, listener.Addr().String(), nil
		},
		Prepare: func(_ string, _ RuntimeConfig, connection net.Conn) (net.Conn, error) {
			entered <- struct{}{}
			<-release
			return connection, nil
		},
		PrepareConcurrency: 1,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewDaemon(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := daemon.Start(ctx)
	if err != nil {
		t.Fatalf("Daemon.Start(): %v", err)
	}
	defer func() {
		close(release)
		_ = daemon.Close()
	}()

	first, err := net.Dial("tcp", result.Listeners[0])
	if err != nil {
		t.Fatalf("dial slow prepare client: %v", err)
	}
	defer first.Close()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first connection did not enter Prepare")
	}

	second, err := net.Dial("tcp", result.Listeners[0])
	if err != nil {
		t.Fatalf("dial saturated prepare client: %v", err)
	}
	defer second.Close()
	if err := second.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("set saturated client deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := second.Read(buffer); err == nil {
		t.Fatal("saturated preparation connection remained open")
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("accept loop was blocked by the slow preparation")
	}
}

func TestProxyDrainSendsNotice(t *testing.T) {
	proxy, address := startRuntimeProxy(t, RuntimeConfig{})
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	waitForProxyClientCount(t, proxy, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := proxy.Drain(ctx); err != nil {
		t.Fatalf("Proxy.Drain(): %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	response, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read drain notice: %v", err)
	}
	if !bytes.Contains(response, []byte("connection closing")) {
		t.Fatalf("drain response = %x", response)
	}
}

func TestMonitorSnapshotConcurrentCloseAndActiveExpiry(t *testing.T) {
	proxy := monitorHardeningProxy(t)
	serverSide, clientSide := net.Pipe()
	client := monitorHardeningClient(proxy, serverSide)
	proxy.clients[client] = struct{}{}

	snapshot := &monitorSnapshot{
		entries: []directory.Entry{{DN: MonitorBaseDN}},
		expires: time.Now().Add(time.Hour),
	}
	if result := client.storeMonitorSnapshot(snapshot); result != nil {
		t.Fatalf("store monitor snapshot: %#v", result)
	}
	client.mu.Lock()
	snapshot.expires = time.Now().Add(-time.Second)
	client.mu.Unlock()
	go client.runMonitorSnapshotJanitor(time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		remaining := len(client.monitorSnapshots)
		client.mu.Unlock()
		if remaining == 0 && proxy.monitorSnapshotBytes.Load() == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if proxy.monitorSnapshotBytes.Load() != 0 {
		t.Fatalf("expired monitor snapshot bytes = %d", proxy.monitorSnapshotBytes.Load())
	}

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for range 100 {
			candidate := &monitorSnapshot{entries: []directory.Entry{{DN: MonitorBaseDN}}}
			if result := client.storeMonitorSnapshot(candidate); result == nil {
				client.removeMonitorSnapshot(candidate)
			}
		}
	}()
	go func() {
		defer workers.Done()
		client.close()
	}()
	workers.Wait()
	_ = clientSide.Close()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.monitorSnapshots == nil || len(client.monitorSnapshots) != 0 {
		t.Fatalf("closed monitor snapshots = %#v", client.monitorSnapshots)
	}
}

func TestMonitorSnapshotRejectsConnectionAndProxyMemoryExhaustion(t *testing.T) {
	proxy := monitorHardeningProxy(t)
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	client := monitorHardeningClient(proxy, serverSide)
	proxy.clients[client] = struct{}{}
	defer client.close()

	large := &monitorSnapshot{entries: []directory.Entry{{
		DN: MonitorBaseDN,
		Attributes: []directory.Attribute{{
			Description: "description",
			Values:      [][]byte{bytes.Repeat([]byte("x"), int(monitorSnapshotByteLimit))},
		}},
	}}}
	if result := client.storeMonitorSnapshot(large); result == nil ||
		result.Code != ldapwire.ResultAdminLimitExceeded {
		t.Fatalf("large monitor snapshot result = %#v", result)
	}

	proxy.monitorSnapshotBytes.Store(monitorProxySnapshotLimit)
	if result := client.storeMonitorSnapshot(&monitorSnapshot{
		entries: []directory.Entry{{DN: MonitorBaseDN}},
	}); result == nil || result.Code != ldapwire.ResultBusy {
		t.Fatalf("proxy monitor snapshot limit result = %#v", result)
	}
	proxy.monitorSnapshotBytes.Store(0)
}

func TestMonitorWriteFailureIsCountedAsFailed(t *testing.T) {
	proxy := monitorHardeningProxy(t)
	serverSide, clientSide := net.Pipe()
	client := monitorHardeningClient(proxy, serverSide)
	proxy.clients[client] = struct{}{}
	_ = clientSide.Close()

	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 1,
		Request: ldapwire.SearchRequest{
			BaseDN:       MonitorBaseDN,
			Scope:        directory.ScopeBase,
			DerefAliases: ldapwire.NeverDerefAliases,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{"cn"},
		},
	})
	if err != nil {
		t.Fatalf("encode monitor Search: %v", err)
	}
	frame, err := proxy.codec.Read(bytes.NewReader(encoded), DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("parse monitor Search: %v", err)
	}
	if !client.handleFrame(context.Background(), frame) {
		t.Fatal("monitor Search unexpectedly closed before handling")
	}
	if completed := client.monitor.completed.Load(); completed != 0 {
		t.Fatalf("completed monitor writes = %d", completed)
	}
	if failed := client.monitor.failed.Load(); failed != 1 {
		t.Fatalf("failed monitor writes = %d", failed)
	}
}

func TestMonitorACLSubjectIncludesTransportAndSASLSSF(t *testing.T) {
	proxy := monitorHardeningProxy(t)
	client := &clientConnection{
		proxy: proxy,
		metadata: ConnectionMetadata{
			SourceAddress:          &net.UnixAddr{Name: "/tmp/client.sock", Net: "unix"},
			DestinationAddress:     &net.UnixAddr{Name: "/tmp/lloadd.sock", Net: "unix"},
			TransportSourceAddress: &net.UnixAddr{Name: "/tmp/client.sock", Net: "unix"},
		},
		transportSSF: 71,
		saslSSF:      128,
	}
	subject := client.monitorACLSubject()
	if subject.TransportSSF != 71 || subject.SASLSSF != 128 || subject.SSF != 128 {
		t.Fatalf("monitor ACL subject = %#v", subject)
	}
}

func monitorHardeningProxy(t *testing.T) *Proxy {
	t.Helper()
	proxy, err := NewProxy(RuntimeConfig{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	proxy.started = true
	proxy.ctx = context.Background()
	return proxy
}

func monitorHardeningClient(proxy *Proxy, connection net.Conn) *clientConnection {
	return &clientConnection{
		proxy:            proxy,
		conn:             connection,
		monitorSnapshots: make(map[string]*monitorSnapshot),
		ops:              make(map[int64]*proxyOperation),
		done:             make(chan struct{}),
		readWake:         make(chan struct{}),
		protocolVersion:  3,
	}
}

func waitForProxyClientCount(t *testing.T, proxy *Proxy, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		proxy.mu.Lock()
		got := len(proxy.clients)
		proxy.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	proxy.mu.Lock()
	got := len(proxy.clients)
	proxy.mu.Unlock()
	t.Fatalf("proxy client count = %d, want %d", got, want)
}

func TestConnectionTransportSSF(t *testing.T) {
	if got := connectionTransportSSF(&net.UnixAddr{Name: "/tmp/lloadd", Net: "unix"}); got != 71 {
		t.Fatalf("unix transport SSF = %d", got)
	}
	if got := connectionTransportSSF(&net.TCPAddr{}); got != 0 {
		t.Fatalf("TCP transport SSF = %d", got)
	}
}
