package lloadd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestRuntimeConfigMapsUpstreamSocketOptions(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(`
bindconf bindmethod=none keepalive=30:4:10 tcp-user-timeout=1500
tier roundrobin
backend-server uri=ldap://127.0.0.1:389 numconns=1 bindconns=1
`))
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	converted, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	keepalive := converted.UpstreamKeepAlive
	if !converted.UpstreamKeepAliveSet || !keepalive.Enable ||
		keepalive.Idle != 30*time.Second || keepalive.Count != 4 ||
		keepalive.Interval != 10*time.Second ||
		converted.UpstreamTCPUserTimeout != 1500*time.Millisecond {
		t.Fatalf("runtime socket options = %#v, timeout %s", keepalive, converted.UpstreamTCPUserTimeout)
	}

	config, err = Parse(strings.NewReader(`
bindconf bindmethod=none keepalive=0:0:0
tier roundrobin
backend-server uri=ldap://127.0.0.1:389 numconns=1 bindconns=1
`))
	if err != nil {
		t.Fatalf("Parse(zero defaults): %v", err)
	}
	converted, err = config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(zero defaults): %v", err)
	}
	keepalive = converted.UpstreamKeepAlive
	if !converted.UpstreamKeepAliveSet || keepalive.Idle != -1 ||
		keepalive.Interval != -1 || keepalive.Count != -1 {
		t.Fatalf("zero keepalive mapping = %#v", keepalive)
	}
}

func TestBackendKeepAliveAppliedToTCPAndWrappedConnections(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		wrapped := wrapped
		name := "TCPConn"
		if wrapped {
			name = "wrapped"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			listener := listenSocketOptionTest(t)
			accepted := acceptSocketOptionTest(t, listener)
			var captured *net.TCPConn
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				captured = connection.(*net.TCPConn)
				if wrapped {
					return &socketOptionUnwrapConn{Conn: connection}, nil
				}
				return connection, nil
			}
			proxy := newSocketOptionTestProxy(t, RuntimeConfig{
				DialContext:            dial,
				UpstreamKeepAliveSet:   true,
				UpstreamKeepAlive:      socketOptionTestKeepAlive(),
				UpstreamTCPUserTimeout: 0,
				Tiers: []RuntimeTierConfig{{
					Strategy: "roundrobin",
					Backends: []RuntimeBackendConfig{proxyTestBackend(listener.Addr().String())},
				}},
			})
			connection, err := proxy.tiers[0].backends[0].dial(context.Background())
			if err != nil {
				t.Fatalf("backend.dial(): %v", err)
			}
			defer connection.Close()
			peer := <-accepted
			defer peer.Close()
			assertSocketOptionKeepAlive(t, captured, 30, 4, 10)
		})
	}
}

func TestBackendSocketOptionsPrecedeLDAPSAndStartTLS(t *testing.T) {
	for _, mode := range []string{"ldaps", "starttls"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			pki := newBackendTLSTestPKI(t)
			backendTLS, err := buildBackendTLSConfig(BindTLSConfig{
				CACertificate: pki.caFile,
				RequireCert:   "demand",
			})
			if err != nil {
				t.Fatalf("buildBackendTLSConfig(): %v", err)
			}
			listener := listenSocketOptionTest(t)
			serverDone := serveSocketOptionTLS(t, listener, pki.serverCertificate, mode == "starttls")
			var ordered *socketOptionOrderingConn
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				ordered = &socketOptionOrderingConn{Conn: connection}
				return ordered, nil
			}
			backend := proxyTestBackend(listener.Addr().String())
			if mode == "ldaps" {
				backend.URI = "ldaps://" + listener.Addr().String()
			} else {
				backend.StartTLS = true
				backend.StartTLSCritical = true
			}
			proxy := newSocketOptionTestProxy(t, RuntimeConfig{
				DialContext:          dial,
				BackendTLS:           backendTLS,
				UpstreamKeepAliveSet: true,
				UpstreamKeepAlive:    socketOptionTestKeepAlive(),
				IOTimeout:            2 * time.Second,
				Tiers: []RuntimeTierConfig{{
					Strategy: "roundrobin",
					Backends: []RuntimeBackendConfig{backend},
				}},
			})
			connection, err := proxy.tiers[0].backends[0].dial(context.Background())
			if err != nil {
				t.Fatalf("%s backend.dial(): %v", mode, err)
			}
			_ = connection.Close()
			if ordered == nil || !ordered.unwrapped.Load() {
				t.Fatalf("%s handshake started before socket options were applied", mode)
			}
			if err := <-serverDone; err != nil {
				t.Fatalf("%s test server: %v", mode, err)
			}
		})
	}
}

func TestBackendSocketOptionsSkipLDAPI(t *testing.T) {
	t.Parallel()

	client, peer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	proxy := newSocketOptionTestProxy(t, RuntimeConfig{
		DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			if network != "unix" {
				return nil, fmt.Errorf("network = %q, want unix", network)
			}
			return client, nil
		},
		UpstreamKeepAliveSet:   true,
		UpstreamKeepAlive:      socketOptionTestKeepAlive(),
		UpstreamTCPUserTimeout: 1500 * time.Millisecond,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldapi://%2Ftmp%2Fsocket-options.sock/",
				RegularConnections: 1,
				BindConnections:    1,
				Weight:             1,
			}},
		}},
	})
	connection, err := proxy.tiers[0].backends[0].dial(context.Background())
	if err != nil {
		t.Fatalf("ldapi backend.dial(): %v", err)
	}
	if connection != client {
		t.Fatal("ldapi dial replaced the original connection")
	}
}

func TestBackendSocketOptionErrorsFailClosed(t *testing.T) {
	t.Parallel()

	_, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	proxy := newSocketOptionTestProxy(t, RuntimeConfig{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, _ := net.Pipe()
			return client, nil
		},
		UpstreamKeepAliveSet: true,
		UpstreamKeepAlive:    socketOptionTestKeepAlive(),
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldap://127.0.0.1:389",
				RegularConnections: 1,
				BindConnections:    1,
				Weight:             1,
			}},
		}},
	})
	if _, err := proxy.tiers[0].backends[0].dial(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "does not expose an underlying *net.TCPConn") {
		t.Fatalf("wrapped socket error = %v", err)
	}

	invalid := RuntimeConfig{
		UpstreamTCPUserTimeout: 500 * time.Microsecond,
	}
	if _, err := NewProxy(invalid); err == nil || !strings.Contains(err.Error(), "whole number of milliseconds") {
		t.Fatalf("sub-millisecond TCP user timeout error = %v", err)
	}

	tcpConfig := RuntimeConfig{
		UpstreamTCPUserTimeout: 1500 * time.Millisecond,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldap://127.0.0.1:389",
				RegularConnections: 1,
				BindConnections:    1,
				Weight:             1,
			}},
		}},
	}
	if runtime.GOOS != "linux" {
		if _, err := NewProxy(tcpConfig); err == nil || !strings.Contains(err.Error(), "TCP_USER_TIMEOUT is not supported") {
			t.Fatalf("unsupported TCP_USER_TIMEOUT error = %v", err)
		}
	}
}

func TestBackendTCPUserTimeoutLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TCP_USER_TIMEOUT is a Linux socket option")
	}

	listener := listenSocketOptionTest(t)
	accepted := acceptSocketOptionTest(t, listener)
	proxy := newSocketOptionTestProxy(t, RuntimeConfig{
		UpstreamTCPUserTimeout: 1500 * time.Millisecond,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{proxyTestBackend(listener.Addr().String())},
		}},
	})
	connection, err := proxy.tiers[0].backends[0].dial(context.Background())
	if err != nil {
		t.Fatalf("backend.dial(): %v", err)
	}
	defer connection.Close()
	peer := <-accepted
	defer peer.Close()
	tcpConnection, err := unwrapTCPConnection(connection)
	if err != nil {
		t.Fatalf("unwrapTCPConnection(): %v", err)
	}
	if value := socketOptionValue(t, tcpConnection, 6, 18); value != 1500 {
		t.Fatalf("TCP_USER_TIMEOUT = %d, want 1500", value)
	}
}

type socketOptionUnwrapConn struct {
	net.Conn
}

func (connection *socketOptionUnwrapConn) Unwrap() net.Conn {
	return connection.Conn
}

type socketOptionOrderingConn struct {
	net.Conn
	unwrapped atomic.Bool
}

func (connection *socketOptionOrderingConn) Unwrap() net.Conn {
	connection.unwrapped.Store(true)
	return connection.Conn
}

func (connection *socketOptionOrderingConn) Write(value []byte) (int, error) {
	if !connection.unwrapped.Load() {
		return 0, errors.New("network write occurred before socket option configuration")
	}
	return connection.Conn.Write(value)
}

func socketOptionTestKeepAlive() net.KeepAliveConfig {
	return net.KeepAliveConfig{
		Enable:   true,
		Idle:     30 * time.Second,
		Interval: 10 * time.Second,
		Count:    4,
	}
}

func newSocketOptionTestProxy(t *testing.T, config RuntimeConfig) *Proxy {
	t.Helper()
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func listenSocketOptionTest(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func acceptSocketOptionTest(t *testing.T, listener net.Listener) <-chan net.Conn {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
		close(accepted)
	}()
	return accepted
}

func serveSocketOptionTLS(
	t *testing.T,
	listener net.Listener,
	certificate tls.Certificate,
	startTLS bool,
) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		if startTLS {
			request, err := ReadFrame(connection, DefaultMaxFrameSize)
			if err != nil {
				done <- err
				return
			}
			if request.ProtocolTag != TagExtendedRequest || request.ExtendedOID != upstreamStartTLSOID {
				done <- fmt.Errorf("unexpected StartTLS request: %s", request)
				return
			}
			if err := ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
				request.MessageID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				upstreamStartTLSOID,
				nil,
				nil,
			)); err != nil {
				done <- err
				return
			}
		}
		secured := tls.Server(connection, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
		done <- secured.Handshake()
	}()
	return done
}

func assertSocketOptionKeepAlive(
	t *testing.T,
	connection *net.TCPConn,
	idle,
	count,
	interval int,
) {
	t.Helper()
	if value := socketOptionValue(t, connection, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE); value == 0 {
		t.Fatal("SO_KEEPALIVE is disabled")
	}
	var idleOption, countOption, intervalOption int
	switch runtime.GOOS {
	case "darwin":
		idleOption, countOption, intervalOption = 0x10, 0x102, 0x101
	case "linux":
		idleOption, countOption, intervalOption = 0x4, 0x6, 0x5
	default:
		t.Skipf("detailed keepalive socket options are not known for %s", runtime.GOOS)
	}
	if value := socketOptionValue(t, connection, 6, idleOption); value != idle {
		t.Fatalf("keepalive idle = %d, want %d", value, idle)
	}
	if value := socketOptionValue(t, connection, 6, countOption); value != count {
		t.Fatalf("keepalive probes = %d, want %d", value, count)
	}
	if value := socketOptionValue(t, connection, 6, intervalOption); value != interval {
		t.Fatalf("keepalive interval = %d, want %d", value, interval)
	}
}

func socketOptionValue(t *testing.T, connection *net.TCPConn, level, option int) int {
	t.Helper()
	getter, ok := any(syscall.GetsockoptInt).(func(int, int, int) (int, error))
	if !ok {
		t.Skip("platform getsockopt ABI is not supported by this test")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn(): %v", err)
	}
	value := 0
	var optionErr error
	if err := raw.Control(func(fileDescriptor uintptr) {
		value, optionErr = getter(int(fileDescriptor), level, option)
	}); err != nil {
		t.Fatalf("socket control: %v", err)
	}
	if optionErr != nil {
		t.Fatalf("getsockopt(%d): %v", option, optionErr)
	}
	return value
}
