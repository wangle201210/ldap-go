package lloadd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type proxyTestUpstream struct {
	listener net.Listener
	marker   string
	handler  func(net.Conn, Frame) bool

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	wg          sync.WaitGroup
	searches    atomic.Int64
	readErrors  chan error
}

type writeSignalingConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
	writes  chan int
	count   atomic.Int64
}

type delayedErrorListener struct {
	net.Listener
	release <-chan struct{}
	err     error
}

type blockingRewriteCodec struct {
	berFrameCodec
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (codec *blockingRewriteCodec) RewriteMessageID(
	frame proxyFrame,
	messageID int64,
) ([]byte, error) {
	codec.once.Do(func() { close(codec.started) })
	<-codec.release
	return codec.berFrameCodec.RewriteMessageID(frame, messageID)
}

func (listener *delayedErrorListener) Accept() (net.Conn, error) {
	<-listener.release
	return nil, listener.err
}

func (connection *writeSignalingConn) Write(encoded []byte) (int, error) {
	count := int(connection.count.Add(1))
	if connection.writes != nil {
		connection.writes <- count
	}
	connection.once.Do(func() { close(connection.started) })
	return connection.Conn.Write(encoded)
}

func startProxyTestUpstream(
	t *testing.T,
	marker string,
	handler func(net.Conn, Frame) bool,
) *proxyTestUpstream {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for test upstream: %v", err)
	}
	return startProxyTestUpstreamOn(t, listener, marker, handler)
}

func startProxyTestUpstreamOn(
	t *testing.T,
	listener net.Listener,
	marker string,
	handler func(net.Conn, Frame) bool,
) *proxyTestUpstream {
	t.Helper()
	upstream := &proxyTestUpstream{
		listener:    listener,
		marker:      marker,
		handler:     handler,
		connections: make(map[net.Conn]struct{}),
		readErrors:  make(chan error, 16),
	}
	upstream.wg.Add(1)
	go func() {
		defer upstream.wg.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			upstream.mu.Lock()
			if upstream.closed {
				upstream.mu.Unlock()
				_ = connection.Close()
				return
			}
			upstream.connections[connection] = struct{}{}
			upstream.mu.Unlock()
			upstream.wg.Add(1)
			go func() {
				defer upstream.wg.Done()
				defer func() {
					upstream.mu.Lock()
					delete(upstream.connections, connection)
					upstream.mu.Unlock()
					_ = connection.Close()
				}()
				upstream.serve(connection)
			}()
		}
	}()
	t.Cleanup(upstream.close)
	return upstream
}

func (upstream *proxyTestUpstream) serve(connection net.Conn) {
	for {
		frame, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			select {
			case upstream.readErrors <- err:
			default:
			}
			return
		}
		if upstream.handler != nil && upstream.handler(connection, frame) {
			continue
		}
		switch frame.ProtocolTag {
		case TagBindRequest:
			_ = ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				frame.MessageID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			))
		case TagSearchRequest:
			upstream.searches.Add(1)
			_ = ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
				frame.MessageID,
				directory.Entry{
					DN: "dc=example,dc=com",
					Attributes: []directory.Attribute{{
						Description: "description",
						Values:      [][]byte{[]byte(upstream.marker)},
					}},
				},
				nil,
			))
			_ = ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
				frame.MessageID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			))
		}
	}
}

func (upstream *proxyTestUpstream) readError() error {
	select {
	case err := <-upstream.readErrors:
		return err
	default:
		return nil
	}
}

func (upstream *proxyTestUpstream) close() {
	upstream.mu.Lock()
	if upstream.closed {
		upstream.mu.Unlock()
		return
	}
	upstream.closed = true
	connections := make([]net.Conn, 0, len(upstream.connections))
	for connection := range upstream.connections {
		connections = append(connections, connection)
	}
	upstream.mu.Unlock()
	_ = upstream.listener.Close()
	for _, connection := range connections {
		_ = connection.Close()
	}
	upstream.wg.Wait()
}

func TestProxyRoundRobinRoutesEachOperation(t *testing.T) {
	first := startProxyTestUpstream(t, "first", nil)
	second := startProxyTestUpstream(t, "second", nil)
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(first.listener.Addr().String()),
				proxyTestBackend(second.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 2)

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	for index, want := range []string{"first", "second", "first", "second"} {
		result, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"description"},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(%d): %v", index, err)
		}
		if len(result.Entries) != 1 ||
			result.Entries[0].GetAttributeValue("description") != want {
			t.Fatalf("Search(%d) marker = %#v, want %q", index, result.Entries, want)
		}
	}
}

func TestNewProxyLDAPSRequiresAndClonesTLSConfig(t *testing.T) {
	config := RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldaps://ldap.example.com:636",
				RegularConnections: 1,
				BindConnections:    1,
				Weight:             1,
			}},
		}},
	}
	if _, err := NewProxy(config); err == nil {
		t.Fatal("NewProxy() accepted LDAPS without a backend TLS configuration")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "ldap.example.com",
	}
	config.BackendTLS = tlsConfig
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatalf("NewProxy(with TLS): %v", err)
	}
	tlsConfig.ServerName = "mutated.example.com"
	if proxy.config.BackendTLS == tlsConfig ||
		proxy.config.BackendTLS.ServerName != "ldap.example.com" {
		t.Fatal("NewProxy() retained caller-owned TLS configuration")
	}
	config.Tiers[0].Backends[0].URI = "ldap://ldap.example.com:389"
	config.Tiers[0].Backends[0].StartTLS = true
	if _, err := NewProxy(config); err != nil {
		t.Fatalf("NewProxy() rejected backend StartTLS: %v", err)
	}
	config.BackendTLS = nil
	if _, err := NewProxy(config); err == nil {
		t.Fatal("NewProxy() accepted backend StartTLS without a TLS configuration")
	}
}

func TestNewProxyRejectsServiceBindWithoutProxyAuthz(t *testing.T) {
	_, err := NewProxy(RuntimeConfig{
		Bind: RuntimeBindConfig{
			Method:      "simple",
			DN:          "cn=Manager,dc=example,dc=com",
			Credentials: []byte("secret"),
		},
	})
	if err == nil {
		t.Fatal("NewProxy() accepted a service Bind without ProxyAuthz")
	}
}

func TestBackendDialUsesEscapedLDAPIAddress(t *testing.T) {
	var gotNetwork, gotAddress string
	var peer net.Conn
	proxy, err := NewProxy(RuntimeConfig{
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			gotNetwork, gotAddress = network, address
			server, remote := net.Pipe()
			peer = remote
			return server, nil
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{{
				URI:                "ldapi://%2Ftmp%2Fldap-go.sock/",
				RegularConnections: 1,
				BindConnections:    1,
				Weight:             1,
			}},
		}},
	})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	connection, err := proxy.tiers[0].backends[0].dial(context.Background())
	if err != nil {
		t.Fatalf("backend.dial(): %v", err)
	}
	defer connection.Close()
	defer peer.Close()
	if gotNetwork != "unix" || gotAddress != "/tmp/ldap-go.sock" {
		t.Fatalf("DialContext() = %q, %q", gotNetwork, gotAddress)
	}
}

func TestProxyMultiplexesDuplicateClientMessageIDs(t *testing.T) {
	firstReceived := make(chan struct{})
	upstreamIDs := make(chan [2]int64, 1)
	var first Frame
	var requestCount int
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		requestCount++
		if requestCount == 1 {
			first = frame
			close(firstReceived)
			return true
		}
		upstreamIDs <- [2]int64{first.MessageID, frame.MessageID}
		writeProxyTestSearchResult(connection, frame.MessageID, "client-two")
		writeProxyTestSearchResult(connection, first.MessageID, "client-one")
		return true
	})
	backend := proxyTestBackend(upstream.listener.Addr().String())
	backend.ConnectionMaxPending = 2
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{backend},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	firstClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial first client: %v", err)
	}
	defer firstClient.Close()
	secondClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial second client: %v", err)
	}
	defer secondClient.Close()
	type searchResult struct {
		marker string
		err    error
	}
	firstResult := make(chan searchResult, 1)
	go func() {
		marker, err := proxySearchMarkerResult(firstClient)
		firstResult <- searchResult{marker: marker, err: err}
	}()
	select {
	case <-firstReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive first client Search")
	}
	secondMarker, err := proxySearchMarkerResult(secondClient)
	if err != nil {
		t.Fatalf("second Search: %v", err)
	}
	if secondMarker != "client-two" {
		t.Fatalf("second Search marker = %q", secondMarker)
	}
	select {
	case result := <-firstResult:
		if result.err != nil {
			t.Fatalf("first Search: %v", result.err)
		}
		if result.marker != "client-one" {
			t.Fatalf("first Search marker = %q", result.marker)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Search did not complete")
	}
	ids := <-upstreamIDs
	if ids[0] == ids[1] {
		t.Fatalf("two client message IDs were mapped to the same upstream ID %d", ids[0])
	}
	if requestCount != 2 {
		t.Fatalf("upstream request count = %d", requestCount)
	}
}

func TestProxyRejectRestrictionDoesNotReachUpstream(t *testing.T) {
	upstream := startProxyTestUpstream(t, "unused", nil)
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		RestrictControls: map[string]RuntimeRestriction{
			"1.2.3.4": RuntimeRestrictionReject,
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		[]ldap.Control{ldap.NewControlString("1.2.3.4", true, "")},
	))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("Search(rejected control) = %v", err)
	}
	if upstream.searches.Load() != 0 {
		t.Fatalf("rejected Search reached upstream %d times", upstream.searches.Load())
	}
}

func TestProxyReturnsUnavailableForUnconfiguredLocalStartTLS(t *testing.T) {
	var extendedRequests atomic.Int64
	upstream := startProxyTestUpstream(t, "unused", func(_ net.Conn, frame Frame) bool {
		if frame.ProtocolTag == TagExtendedRequest {
			extendedRequests.Add(1)
			return true
		}
		return false
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
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	const messageID = int64(12)
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name: clientStartTLSOID,
		},
	})
	if err != nil {
		t.Fatalf("encode StartTLS: %v", err)
	}
	if err := ldapwire.Write(connection, request); err != nil {
		t.Fatalf("write StartTLS: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read StartTLS response: %v", err)
	}
	if response.MessageID != messageID || response.ResultCode == nil ||
		*response.ResultCode != ResultCode(ldapwire.ResultUnavailable) {
		t.Fatalf("StartTLS response = %s", response)
	}
	if extendedRequests.Load() != 0 {
		t.Fatalf("unsupported local extended operations reached upstream %d times", extendedRequests.Load())
	}
}

func TestProxyClosesOnInvalidClientMessageEnvelope(t *testing.T) {
	var upstreamFrames atomic.Int64
	upstream := startProxyTestUpstream(t, "unused", func(_ net.Conn, _ Frame) bool {
		upstreamFrames.Add(1)
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
	validSearch, err := ParseFrame(proxySearchRequest(t, 1), DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("parse Search: %v", err)
	}
	tests := map[string][]byte{
		"zero message ID": encodeFrame(0, validSearch.ProtocolOp, nil),
		"response PDU": encodeFrame(
			2,
			testLDAPResultOperation(TagSearchResultDone, ResultSuccess, ""),
			nil,
		),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			connection, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer connection.Close()
			if err := ldapwire.Write(connection, request); err != nil {
				t.Fatalf("write invalid frame: %v", err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = ReadFrame(connection, DefaultMaxFrameSize)
			if err == nil {
				t.Fatal("proxy returned an LDAP response instead of closing")
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				t.Fatal("proxy left the invalid client association open")
			}
		})
	}
	if upstreamFrames.Load() != 0 {
		t.Fatalf("invalid client frames reached upstream %d times", upstreamFrames.Load())
	}
}

func TestProxyWithoutBackendsReturnsUnavailable(t *testing.T) {
	_, address := startRuntimeProxy(t, RuntimeConfig{})
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, proxySearchRequest(t, 9)); err != nil {
		t.Fatalf("write Search: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read unavailable response: %v", err)
	}
	if response.MessageID != 9 || response.ResultCode == nil ||
		*response.ResultCode != ResultUnavailable {
		t.Fatalf("unavailable response = %s", response)
	}
}

func TestProxySimpleBindAddsProxyAuthorization(t *testing.T) {
	authz := make(chan string, 1)
	upstream := startProxyTestUpstream(t, "proxied", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		if len(frame.Controls) == 0 || frame.Controls[0].OID != ProxyAuthzControlOID {
			authz <- "missing"
		} else if !bytes.Contains(frame.Controls[0].Raw, []byte("dn:uid=alice,dc=example,dc=com")) {
			authz <- "wrong"
		} else {
			authz <- "ok"
		}
		return false
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ProxyAuthz: true,
		Bind: RuntimeBindConfig{
			Method:      "simple",
			DN:          "cn=Manager,dc=example,dc=com",
			Credentials: []byte("secret"),
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	waitForReadyConnections(t, proxy, PoolBind, 1)

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,dc=example,dc=com", "password"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	if _, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	)); err != nil {
		t.Fatalf("Search(): %v", err)
	}
	select {
	case got := <-authz:
		if got != "ok" {
			t.Fatalf("ProxyAuthz control = %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe proxied Search")
	}
}

func TestProxyNewBindReusesSASLBindPin(t *testing.T) {
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagBindRequest || frame.Bind == nil {
			return false
		}
		code := ldapwire.ResultSuccess
		if frame.Bind.Authentication == BindAuthenticationSASL {
			code = ldapwire.ResultSASLBindInProgress
		}
		_ = ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			frame.MessageID,
			ldapwire.Result{Code: code},
			nil,
		))
		return true
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ProxyAuthz: true,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolBind, 1)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, encodeFrame(
		20,
		testSASLBind("", "PLAIN", true, []byte("credentials")),
		nil,
	)); err != nil {
		t.Fatalf("write SASL Bind: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read SASL Bind response: %v", err)
	}
	if response.ResultCode == nil || *response.ResultCode != ResultSASLBindInProgress {
		t.Fatalf("SASL Bind response = %s", response)
	}
	if err := ldapwire.Write(connection, encodeFrame(
		21,
		testSimpleBind("uid=alice,dc=example,dc=com", []byte("password")),
		nil,
	)); err != nil {
		t.Fatalf("write replacement Simple Bind: %v", err)
	}
	response, err = ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read replacement Simple Bind response: %v", err)
	}
	if response.MessageID != 21 || response.ResultCode == nil ||
		*response.ResultCode != ResultSuccess {
		t.Fatalf("replacement Simple Bind response = %s", response)
	}
	waitForReadyConnections(t, proxy, PoolBind, 1)
}

func TestProxyRejectsClientSASLExternalLocally(t *testing.T) {
	var upstreamBinds atomic.Int64
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagBindRequest || frame.Bind == nil {
			return false
		}
		upstreamBinds.Add(1)
		_ = ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			frame.MessageID,
			ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
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
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, encodeFrame(
		22,
		testSASLBind("", "PLAIN", true, []byte("credentials")),
		nil,
	)); err != nil {
		t.Fatalf("write initial SASL Bind: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read initial SASL response: %v", err)
	}
	if response.ResultCode == nil || *response.ResultCode != ResultSASLBindInProgress {
		t.Fatalf("initial SASL response = %s", response)
	}
	if err := ldapwire.Write(connection, encodeFrame(
		23,
		testSASLBind("", "EXTERNAL", false, nil),
		nil,
	)); err != nil {
		t.Fatalf("write SASL EXTERNAL Bind: %v", err)
	}
	response, err = ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read SASL EXTERNAL response: %v", err)
	}
	if response.MessageID != 23 || response.ResultCode == nil ||
		*response.ResultCode != ResultCode(ldapwire.ResultAuthMethodNotSupported) {
		t.Fatalf("SASL EXTERNAL response = %s", response)
	}
	if upstreamBinds.Load() != 1 {
		t.Fatalf("upstream Bind count = %d, want only the initial PLAIN Bind", upstreamBinds.Load())
	}
	waitForReadyConnections(t, proxy, PoolBind, 1)
}

func TestProxySASLBoundConnectionDoesNotAddEmptyProxyAuthz(t *testing.T) {
	observed := make(chan string, 1)
	var mu sync.Mutex
	var boundConnection net.Conn
	upstream := startProxyTestUpstream(t, "sasl", func(connection net.Conn, frame Frame) bool {
		switch frame.ProtocolTag {
		case TagBindRequest:
			if frame.Bind == nil || frame.Bind.Authentication != BindAuthenticationSASL {
				return false
			}
			mu.Lock()
			boundConnection = connection
			mu.Unlock()
			_ = ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				frame.MessageID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			))
			return true
		case TagSearchRequest:
			mu.Lock()
			sameConnection := boundConnection == connection
			mu.Unlock()
			hasProxyAuthz := false
			for _, control := range frame.Controls {
				hasProxyAuthz = hasProxyAuthz || control.OID == ProxyAuthzControlOID
			}
			observed <- fmt.Sprintf("same=%t proxyauthz=%t", sameConnection, hasProxyAuthz)
			return false
		default:
			return false
		}
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ProxyAuthz: true,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	waitForReadyConnections(t, proxy, PoolBind, 1)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, encodeFrame(
		23,
		testSASLBind("", "PLAIN", true, []byte("credentials")),
		nil,
	)); err != nil {
		t.Fatalf("write SASL Bind: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read SASL Bind response: %v", err)
	}
	if response.ResultCode == nil || *response.ResultCode != ResultSuccess {
		t.Fatalf("SASL Bind response = %s", response)
	}
	if err := ldapwire.Write(connection, proxySearchRequest(t, 24)); err != nil {
		t.Fatalf("write Search: %v", err)
	}
	if _, err := ReadFrame(connection, DefaultMaxFrameSize); err != nil {
		t.Fatalf("read Search entry: %v", err)
	}
	if _, err := ReadFrame(connection, DefaultMaxFrameSize); err != nil {
		t.Fatalf("read Search done: %v", err)
	}
	select {
	case got := <-observed:
		if got != "same=true proxyauthz=false" {
			t.Fatalf("SASL Search routing = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe SASL-bound Search")
	}
}

func TestProxyCommitsBindStateBeforeWritingResponse(t *testing.T) {
	proxy, err := NewProxy(RuntimeConfig{
		ProxyAuthz: true,
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
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	signaling := &writeSignalingConn{
		Conn:    server,
		started: make(chan struct{}),
	}
	client := &clientConnection{
		proxy:   proxy,
		conn:    signaling,
		done:    make(chan struct{}),
		binding: true,
		ops:     make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, true, 0),
		bind:    true,
		pending: make(map[int64]*proxyOperation),
		owner:   client,
		done:    make(chan struct{}),
	}
	client.bindPin = upstream
	operation := &proxyOperation{
		client:     client,
		clientID:   30,
		requestTag: TagBindRequest,
		upstream:   upstream,
		upstreamID: 7,
		bind:       true,
		bindDN:     "uid=alice,dc=example,dc=com",
		started:    time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	parsed, err := ParseFrame(ldapwire.EncodeBindResponse(
		operation.upstreamID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	), DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("parse Bind response: %v", err)
	}
	done := make(chan struct{})
	go func() {
		upstream.handleResponse(projectProxyFrame(parsed))
		close(done)
	}()
	select {
	case <-signaling.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Bind response write did not start")
	}
	client.mu.Lock()
	binding := client.binding
	authzID := string(client.authzID)
	client.mu.Unlock()
	if binding || authzID != "dn:uid=alice,dc=example,dc=com" {
		t.Fatalf("state during Bind response write = binding %t, authzID %q", binding, authzID)
	}
	response, err := ReadFrame(peer, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read downstream Bind response: %v", err)
	}
	if response.MessageID != operation.clientID {
		t.Fatalf("downstream Bind message ID = %d", response.MessageID)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Bind response handling did not complete")
	}
}

func TestBindSuccessOnLostUpstreamClosesClient(t *testing.T) {
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
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	client := &clientConnection{
		proxy:   proxy,
		conn:    server,
		done:    make(chan struct{}),
		binding: true,
		ops:     make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, true, 0),
		bind:    true,
		closed:  true,
		pending: make(map[int64]*proxyOperation),
		done:    make(chan struct{}),
	}
	client.bindPin = upstream
	operation := &proxyOperation{
		client:     client,
		clientID:   32,
		requestTag: TagBindRequest,
		upstream:   upstream,
		upstreamID: 9,
		bind:       true,
		bindDN:     "uid=alice,dc=example,dc=com",
		started:    time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	publish, closeClient, closeUpstream := upstream.handleBindResponse(operation, proxyFrame{
		ProtocolTag:   TagBindResponse,
		ResultCode:    ldapwire.ResultSuccess,
		HasResultCode: true,
	})
	if publish {
		t.Fatal("lost upstream published Bind success")
	}
	if closeUpstream {
		t.Fatal("already-lost upstream requested another close")
	}
	if closeClient {
		client.close()
	}
	client.mu.Lock()
	closed := client.closed
	authzID := string(client.authzID)
	client.mu.Unlock()
	if !closed || authzID != "" {
		t.Fatalf("client after lost Bind upstream = closed %t, authzID %q", closed, authzID)
	}
	for _, connection := range proxy.scheduler.Snapshot().Connections {
		if connection.ID == upstream.id && connection.State != ConnectionUnavailable {
			t.Fatalf("lost Bind upstream state = %d", connection.State)
		}
	}
}

func TestProxyReleasesOperationBeforeWritingFinalResponse(t *testing.T) {
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
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	signaling := &writeSignalingConn{
		Conn:    server,
		started: make(chan struct{}),
	}
	client := &clientConnection{
		proxy: proxy,
		conn:  signaling,
		done:  make(chan struct{}),
		ops:   make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstreamSocket, upstreamPeer := net.Pipe()
	defer upstreamSocket.Close()
	defer upstreamPeer.Close()
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, false, 0),
		conn:    upstreamSocket,
		pending: make(map[int64]*proxyOperation),
		done:    make(chan struct{}),
	}
	operation := &proxyOperation{
		client:     client,
		clientID:   31,
		requestTag: TagSearchRequest,
		upstream:   upstream,
		upstreamID: 8,
		started:    time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	parsed, err := ParseFrame(ldapwire.EncodeSearchResultDone(
		operation.upstreamID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	), DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("parse Search result: %v", err)
	}
	done := make(chan struct{})
	go func() {
		upstream.handleResponse(projectProxyFrame(parsed))
		close(done)
	}()
	select {
	case <-signaling.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Search result write did not start")
	}
	client.mu.Lock()
	registered := client.ops[operation.clientID] != nil
	client.mu.Unlock()
	upstream.mu.Lock()
	pending := upstream.pending[operation.upstreamID] != nil
	upstream.mu.Unlock()
	if registered || pending || !operation.finished.Load() {
		t.Fatalf(
			"operation state during final response write = registered %t, pending %t, finished %t",
			registered,
			pending,
			operation.finished.Load(),
		)
	}
	upstream.closeWithError(errors.New("response/close race"))
	response, err := ReadFrame(peer, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read downstream Search result: %v", err)
	}
	if response.MessageID != operation.clientID {
		t.Fatalf("downstream Search message ID = %d", response.MessageID)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Search result handling did not complete")
	}
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if duplicate, err := ReadFrame(peer, DefaultMaxFrameSize); err == nil {
		t.Fatalf("received duplicate terminal response: %s", duplicate)
	} else {
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("second response read = %v, want timeout", err)
		}
	}
}

func TestOperationFinishRacesAttachmentWithoutLeaking(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
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
		client := &clientConnection{
			proxy: proxy,
			done:  make(chan struct{}),
			ops:   make(map[int64]*proxyOperation),
		}
		backend := proxy.tiers[0].backends[0]
		upstream := &upstreamConnection{
			backend: backend,
			id:      backendConnectionID(backend.id, false, 0),
			pending: make(map[int64]*proxyOperation),
			done:    make(chan struct{}),
		}
		operation := &proxyOperation{
			client:      client,
			clientID:    1,
			requestTag:  TagSearchRequest,
			restriction: RuntimeRestrictionWrite,
			started:     time.Now(),
		}
		client.ops[operation.clientID] = operation
		start := make(chan struct{})
		var attached bool
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			attached = upstream.attach(operation, false, nil, RuntimeRestrictionNone)
		}()
		go func() {
			defer wait.Done()
			<-start
			operation.finish(false)
		}()
		close(start)
		wait.Wait()
		if !operation.finished.Load() {
			t.Fatalf("iteration %d: operation did not finish", iteration)
		}
		upstream.mu.Lock()
		pending := len(upstream.pending)
		upstream.mu.Unlock()
		if pending != 0 {
			t.Fatalf(
				"iteration %d: attached=%t left %d pending operations",
				iteration,
				attached,
				pending,
			)
		}
		client.mu.Lock()
		writeInflight := client.writeInflight
		client.mu.Unlock()
		if writeInflight != 0 {
			t.Fatalf(
				"iteration %d: attached=%t left %d writes in flight",
				iteration,
				attached,
				writeInflight,
			)
		}
	}
}

func TestClosedClientCannotAttachBindOwner(t *testing.T) {
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
	client := &clientConnection{
		proxy:          proxy,
		done:           make(chan struct{}),
		closed:         true,
		bindGeneration: 1,
		ops:            make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, true, 0),
		bind:    true,
		pending: make(map[int64]*proxyOperation),
		done:    make(chan struct{}),
	}
	operation := &proxyOperation{
		client:         client,
		clientID:       2,
		requestTag:     TagBindRequest,
		bind:           true,
		bindGeneration: 1,
		started:        time.Now(),
	}
	client.ops[operation.clientID] = operation
	if upstream.attach(operation, true, nil, RuntimeRestrictionNone) {
		t.Fatal("Bind attached after client close")
	}
	upstream.mu.Lock()
	owner := upstream.owner
	pending := len(upstream.pending)
	upstream.mu.Unlock()
	client.mu.Lock()
	bindPin := client.bindPin
	client.mu.Unlock()
	if owner != nil || pending != 0 || bindPin != nil {
		t.Fatalf("closed-client attach left owner=%p pending=%d bindPin=%p", owner, pending, bindPin)
	}
}

func TestOldBindCannotReleaseNewOwnerGeneration(t *testing.T) {
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
	client := &clientConnection{proxy: proxy}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend:         backend,
		id:              backendConnectionID(backend.id, true, 0),
		bind:            true,
		owner:           client,
		ownerGeneration: 2,
		pending:         make(map[int64]*proxyOperation),
		done:            make(chan struct{}),
	}
	old := &proxyOperation{client: client, bind: true, bindGeneration: 1}
	upstream.releaseOwner(old)
	upstream.mu.Lock()
	owner := upstream.owner
	generation := upstream.ownerGeneration
	upstream.mu.Unlock()
	if owner != client || generation != 2 {
		t.Fatalf("old Bind released owner=%p generation=%d", owner, generation)
	}
	current := &proxyOperation{client: client, bind: true, bindGeneration: 2}
	upstream.releaseOwner(current)
	upstream.mu.Lock()
	owner = upstream.owner
	generation = upstream.ownerGeneration
	upstream.mu.Unlock()
	if owner != nil || generation != 0 {
		t.Fatalf("current Bind left owner=%p generation=%d", owner, generation)
	}
}

func TestReleaseOwnerPublishesReadyBeforeNewBindAttach(t *testing.T) {
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
	client := &clientConnection{
		proxy:          proxy,
		done:           make(chan struct{}),
		bindGeneration: 2,
		ops:            make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend:         backend,
		id:              backendConnectionID(backend.id, true, 0),
		bind:            true,
		owner:           client,
		ownerGeneration: 1,
		pending:         make(map[int64]*proxyOperation),
		done:            make(chan struct{}),
	}
	if err := proxy.scheduler.SetConnectionState(upstream.id, ConnectionBusy); err != nil {
		t.Fatalf("set initial scheduler state: %v", err)
	}
	old := &proxyOperation{client: client, bind: true, bindGeneration: 1}
	proxy.scheduler.mu.Lock()
	released := make(chan struct{})
	go func() {
		upstream.releaseOwner(old)
		close(released)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for upstream.mu.TryLock() {
		upstream.mu.Unlock()
		if time.Now().After(deadline) {
			proxy.scheduler.mu.Unlock()
			t.Fatal("releaseOwner did not reach scheduler publication")
		}
		time.Sleep(time.Millisecond)
	}
	newOperation := &proxyOperation{
		client:         client,
		clientID:       5,
		requestTag:     TagBindRequest,
		bind:           true,
		bindGeneration: 2,
		started:        time.Now(),
	}
	client.ops[newOperation.clientID] = newOperation
	attached := make(chan bool, 1)
	go func() {
		attached <- upstream.attach(
			newOperation,
			true,
			nil,
			RuntimeRestrictionNone,
		)
	}()
	select {
	case <-attached:
		proxy.scheduler.mu.Unlock()
		t.Fatal("new Bind attached before old owner published Ready")
	case <-time.After(25 * time.Millisecond):
	}
	proxy.scheduler.mu.Unlock()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("old owner release did not complete")
	}
	select {
	case ok := <-attached:
		if !ok {
			t.Fatal("new Bind did not attach after owner release")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new Bind attach did not complete")
	}
	if err := proxy.scheduler.SetConnectionState(upstream.id, ConnectionBusy); err != nil {
		t.Fatalf("publish new owner Busy state: %v", err)
	}
	for _, connection := range proxy.scheduler.Snapshot().Connections {
		if connection.ID == upstream.id && connection.State != ConnectionBusy {
			t.Fatalf("new owner scheduler state = %d", connection.State)
		}
	}
}

func TestStaleBindRetiresUnclaimedOwner(t *testing.T) {
	for _, test := range []struct {
		name            string
		proxyAuthz      bool
		alreadyFinished bool
		wantClose       bool
	}{
		{name: "releasable response", proxyAuthz: true},
		{name: "releasable response after reset", proxyAuthz: true, alreadyFinished: true},
		{name: "pinned response", wantClose: true},
		{name: "pinned response after reset", alreadyFinished: true, wantClose: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy, err := NewProxy(RuntimeConfig{
				ProxyAuthz: test.proxyAuthz,
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
			client := &clientConnection{
				proxy:          proxy,
				done:           make(chan struct{}),
				binding:        true,
				bindGeneration: 2,
				authzID:        []byte("dn:uid=new,dc=example,dc=com"),
				ops:            make(map[int64]*proxyOperation),
			}
			backend := proxy.tiers[0].backends[0]
			upstream := &upstreamConnection{
				backend:         backend,
				id:              backendConnectionID(backend.id, true, 0),
				bind:            true,
				pending:         make(map[int64]*proxyOperation),
				owner:           client,
				ownerGeneration: 1,
				done:            make(chan struct{}),
			}
			client.bindPin = upstream
			operation := &proxyOperation{
				client:         client,
				clientID:       3,
				requestTag:     TagBindRequest,
				upstream:       upstream,
				upstreamID:     4,
				bind:           true,
				bindGeneration: 1,
				started:        time.Now(),
			}
			if test.alreadyFinished {
				operation.finished.Store(true)
			} else {
				client.ops[operation.clientID] = operation
				upstream.pending[operation.upstreamID] = operation
			}
			publish, closeClient, closeUpstream := upstream.handleBindResponse(
				operation,
				proxyFrame{
					ProtocolTag:   TagBindResponse,
					ResultCode:    ldapwire.ResultSuccess,
					HasResultCode: true,
				},
			)
			if publish || closeClient || closeUpstream != test.wantClose {
				t.Fatalf(
					"stale response disposition = publish %t, close client %t, close upstream %t",
					publish,
					closeClient,
					closeUpstream,
				)
			}
			upstream.mu.Lock()
			owner := upstream.owner
			generation := upstream.ownerGeneration
			upstreamClosed := upstream.closed
			upstream.mu.Unlock()
			if test.wantClose {
				if owner != client || generation != 1 || !upstreamClosed {
					t.Fatalf(
						"pinned stale owner=%p generation=%d closed=%t",
						owner,
						generation,
						upstreamClosed,
					)
				}
			} else if owner != nil || generation != 0 || upstreamClosed {
				t.Fatalf(
					"releasable stale owner=%p generation=%d closed=%t",
					owner,
					generation,
					upstreamClosed,
				)
			}
			client.mu.Lock()
			binding := client.binding
			authzID := string(client.authzID)
			client.mu.Unlock()
			if !binding || authzID != "dn:uid=new,dc=example,dc=com" {
				t.Fatalf("new Bind state = binding %t, authzID %q", binding, authzID)
			}
		})
	}
}

func TestOperationRequestWritePrecedesGeneratedAbandon(t *testing.T) {
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
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	signaling := &writeSignalingConn{
		Conn:    server,
		started: make(chan struct{}),
		writes:  make(chan int, 2),
	}
	client := &clientConnection{
		proxy: proxy,
		done:  make(chan struct{}),
		ops:   make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, false, 0),
		conn:    signaling,
		pending: make(map[int64]*proxyOperation),
		nextID:  8,
		done:    make(chan struct{}),
	}
	operation := &proxyOperation{
		client:     client,
		clientID:   70,
		requestTag: TagSearchRequest,
		upstream:   upstream,
		upstreamID: 7,
		started:    time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	writeDone := make(chan error, 1)
	go func() { writeDone <- operation.writeRequest(proxySearchRequest(t, 7)) }()
	select {
	case <-signaling.started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request write did not start")
	}
	if write := <-signaling.writes; write != 1 {
		t.Fatalf("first upstream write number = %d", write)
	}
	abandonDone := make(chan struct{})
	go func() {
		client.abandonOperation(operation, nil, true)
		close(abandonDone)
	}()
	time.Sleep(25 * time.Millisecond)
	if operation.finished.Load() {
		t.Fatal("operation finished before its request write completed")
	}
	first, err := ReadFrame(peer, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read upstream request: %v", err)
	}
	if first.ProtocolTag != TagSearchRequest || first.MessageID != operation.upstreamID {
		t.Fatalf("first upstream frame = %s", first)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("writeRequest(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request write did not complete")
	}
	select {
	case write := <-signaling.writes:
		if write != 2 {
			t.Fatalf("generated Abandon write number = %d", write)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("generated Abandon write did not start")
	}
	if !operation.finished.Load() {
		t.Fatal("operation remained active while generated Abandon write was blocked")
	}
	client.mu.Lock()
	registered := client.ops[operation.clientID]
	client.mu.Unlock()
	if registered != nil {
		t.Fatal("client operation mapping remained during generated Abandon write")
	}
	upstream.mu.Lock()
	pending := upstream.pending[operation.upstreamID]
	upstream.mu.Unlock()
	if pending != nil {
		t.Fatal("upstream operation mapping remained during generated Abandon write")
	}
	second, err := ReadFrame(peer, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read generated Abandon: %v", err)
	}
	if second.ProtocolTag != TagAbandonRequest ||
		second.AbandonTarget != operation.upstreamID {
		t.Fatalf("second upstream frame = %s", second)
	}
	select {
	case <-abandonDone:
	case <-time.After(2 * time.Second):
		t.Fatal("generated Abandon did not complete")
	}
	if !operation.finished.Load() {
		t.Fatal("operation remained active after generated Abandon")
	}
}

func TestNonFinalResponsePrecedesDisconnectResult(t *testing.T) {
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
	codec := &blockingRewriteCodec{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	proxy.codec = codec
	clientSocket, clientPeer := net.Pipe()
	defer clientSocket.Close()
	defer clientPeer.Close()
	upstreamSocket, upstreamPeer := net.Pipe()
	defer upstreamSocket.Close()
	defer upstreamPeer.Close()
	client := &clientConnection{
		proxy: proxy,
		conn:  clientSocket,
		done:  make(chan struct{}),
		ops:   make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, false, 0),
		conn:    upstreamSocket,
		pending: make(map[int64]*proxyOperation),
		done:    make(chan struct{}),
	}
	operation := &proxyOperation{
		client:     client,
		clientID:   71,
		requestTag: TagSearchRequest,
		upstream:   upstream,
		upstreamID: 10,
		started:    time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	entry, err := ParseFrame(ldapwire.EncodeSearchResultEntry(
		operation.upstreamID,
		directory.Entry{DN: "dc=example,dc=com"},
		nil,
	), DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("parse Search entry: %v", err)
	}
	responseDone := make(chan struct{})
	go func() {
		upstream.handleResponse(projectProxyFrame(entry))
		close(responseDone)
	}()
	select {
	case <-codec.started:
	case <-time.After(2 * time.Second):
		t.Fatal("response rewrite did not start")
	}
	closeDone := make(chan struct{})
	go func() {
		upstream.closeWithError(errors.New("forced disconnect"))
		close(closeDone)
	}()
	_ = clientPeer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if early, err := ReadFrame(clientPeer, DefaultMaxFrameSize); err == nil {
		t.Fatalf("disconnect result overtook Search entry: %s", early)
	} else {
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("early response read = %v, want timeout", err)
		}
	}
	_ = clientPeer.SetReadDeadline(time.Time{})
	close(codec.release)
	first, err := ReadFrame(clientPeer, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Search entry: %v", err)
	}
	if first.ProtocolTag != TagSearchResultEntry || first.MessageID != operation.clientID {
		t.Fatalf("first downstream frame = %s", first)
	}
	second, err := ReadFrame(clientPeer, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read disconnect result: %v", err)
	}
	if second.ProtocolTag != TagSearchResultDone || second.ResultCode == nil ||
		*second.ResultCode != ResultOther {
		t.Fatalf("second downstream frame = %s", second)
	}
	select {
	case <-responseDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Search entry response did not complete")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream close did not complete")
	}
}

func TestNonFinalResponseWriteFailureDoesNotDeadlock(t *testing.T) {
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
	clientSocket, clientPeer := net.Pipe()
	_ = clientPeer.Close()
	defer clientSocket.Close()
	upstreamSocket, upstreamPeer := net.Pipe()
	defer upstreamSocket.Close()
	defer upstreamPeer.Close()
	client := &clientConnection{
		proxy: proxy,
		conn:  clientSocket,
		done:  make(chan struct{}),
		ops:   make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, false, 0),
		conn:    upstreamSocket,
		pending: make(map[int64]*proxyOperation),
		done:    make(chan struct{}),
	}
	operation := &proxyOperation{
		client:     client,
		clientID:   73,
		requestTag: TagSearchRequest,
		upstream:   upstream,
		upstreamID: 12,
		started:    time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	entry, err := ParseFrame(ldapwire.EncodeSearchResultEntry(
		operation.upstreamID,
		directory.Entry{DN: "dc=example,dc=com"},
		nil,
	), DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("parse Search entry: %v", err)
	}
	done := make(chan struct{})
	go func() {
		upstream.handleResponse(projectProxyFrame(entry))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("downstream write failure deadlocked response handling")
	}
	client.mu.Lock()
	closed := client.closed
	client.mu.Unlock()
	if !closed || !operation.finished.Load() {
		t.Fatalf("write failure = client closed %t, operation finished %t", closed, operation.finished.Load())
	}
}

func TestMalformedBindResponseCloseDoesNotDeadlock(t *testing.T) {
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
	clientSocket, clientPeer := net.Pipe()
	_ = clientPeer.Close()
	defer clientSocket.Close()
	upstreamSocket, upstreamPeer := net.Pipe()
	defer upstreamSocket.Close()
	defer upstreamPeer.Close()
	client := &clientConnection{
		proxy:          proxy,
		conn:           clientSocket,
		done:           make(chan struct{}),
		binding:        true,
		bindGeneration: 1,
		ops:            make(map[int64]*proxyOperation),
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend: backend,
		id:      backendConnectionID(backend.id, true, 0),
		bind:    true,
		conn:    upstreamSocket,
		pending: make(map[int64]*proxyOperation),
		owner:   client,
		done:    make(chan struct{}),
	}
	client.bindPin = upstream
	operation := &proxyOperation{
		client:         client,
		clientID:       74,
		requestTag:     TagBindRequest,
		upstream:       upstream,
		upstreamID:     13,
		bind:           true,
		bindGeneration: 1,
		started:        time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	done := make(chan struct{})
	go func() {
		upstream.handleResponse(proxyFrame{
			MessageID:   operation.upstreamID,
			ProtocolTag: TagBindResponse,
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("malformed Bind response deadlocked upstream close")
	}
	upstream.mu.Lock()
	closed := upstream.closed
	upstream.mu.Unlock()
	if !closed || !operation.finished.Load() {
		t.Fatalf("malformed Bind = upstream closed %t, operation finished %t", closed, operation.finished.Load())
	}
}

func TestStaleBindGenerationCannotOverwriteClientState(t *testing.T) {
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
	client := &clientConnection{
		proxy:          proxy,
		done:           make(chan struct{}),
		ops:            make(map[int64]*proxyOperation),
		binding:        true,
		bindGeneration: 1,
	}
	backend := proxy.tiers[0].backends[0]
	upstream := &upstreamConnection{
		backend:         backend,
		id:              backendConnectionID(backend.id, true, 0),
		bind:            true,
		pending:         make(map[int64]*proxyOperation),
		owner:           client,
		ownerGeneration: 1,
		done:            make(chan struct{}),
	}
	client.bindPin = upstream
	operation := &proxyOperation{
		client:         client,
		clientID:       72,
		requestTag:     TagBindRequest,
		upstream:       upstream,
		upstreamID:     11,
		bind:           true,
		bindDN:         "uid=old,dc=example,dc=com",
		bindGeneration: 1,
		started:        time.Now(),
	}
	client.ops[operation.clientID] = operation
	upstream.pending[operation.upstreamID] = operation
	upstream.mu.Lock()
	type bindDisposition struct {
		publish       bool
		closeClient   bool
		closeUpstream bool
	}
	done := make(chan bindDisposition, 1)
	go func() {
		publish, closeClient, closeUpstream := upstream.handleBindResponse(operation, proxyFrame{
			ProtocolTag:   TagBindResponse,
			ResultCode:    ldapwire.ResultSuccess,
			HasResultCode: true,
		})
		done <- bindDisposition{
			publish: publish, closeClient: closeClient, closeUpstream: closeUpstream,
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !operation.finished.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !operation.finished.Load() {
		upstream.mu.Unlock()
		t.Fatal("old Bind response did not claim completion")
	}
	client.mu.Lock()
	client.bindGeneration = 2
	client.binding = true
	client.authzID = []byte("dn:uid=new,dc=example,dc=com")
	client.mu.Unlock()
	upstream.closed = true
	upstream.mu.Unlock()
	select {
	case disposition := <-done:
		if disposition.publish || disposition.closeClient || disposition.closeUpstream {
			t.Fatal("stale Bind response was published")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale Bind response handling did not complete")
	}
	client.mu.Lock()
	binding := client.binding
	authzID := string(client.authzID)
	closed := client.closed
	client.mu.Unlock()
	if !binding || closed || authzID != "dn:uid=new,dc=example,dc=com" {
		t.Fatalf("new Bind state = binding %t, closed %t, authzID %q", binding, closed, authzID)
	}
}

func TestProxyBusyTierDoesNotFallBack(t *testing.T) {
	firstStarted := make(chan struct{}, 1)
	releaseFirst := make(chan struct{})
	first := startProxyTestUpstream(t, "first", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		select {
		case firstStarted <- struct{}{}:
		default:
		}
		<-releaseFirst
		return false
	})
	second := startProxyTestUpstream(t, "fallback", nil)
	firstBackend := proxyTestBackend(first.listener.Addr().String())
	firstBackend.ConnectionMaxPending = 1
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{
			{Strategy: "roundrobin", Backends: []RuntimeBackendConfig{firstBackend}},
			{Strategy: "roundrobin", Backends: []RuntimeBackendConfig{
				proxyTestBackend(second.listener.Addr().String()),
			}},
		},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 2)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, proxySearchRequest(t, 1)); err != nil {
		t.Fatalf("write first Search: %v", err)
	}
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first tier did not receive Search")
	}
	if err := ldapwire.Write(connection, proxySearchRequest(t, 2)); err != nil {
		t.Fatalf("write second Search: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read busy response: %v", err)
	}
	if response.MessageID != 2 || response.ResultCode == nil ||
		*response.ResultCode != ResultBusy {
		t.Fatalf("busy response = %s", response)
	}
	if second.searches.Load() != 0 {
		t.Fatalf("fallback tier received %d Search operations", second.searches.Load())
	}
	close(releaseFirst)
}

func TestProxyBoundConnectionHonorsBackendPendingLimit(t *testing.T) {
	firstStarted := make(chan struct{}, 1)
	releaseFirst := make(chan struct{})
	upstream := startProxyTestUpstream(t, "bound", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		select {
		case firstStarted <- struct{}{}:
		default:
		}
		<-releaseFirst
		writeProxyTestSearchResult(connection, frame.MessageID, "bound")
		return true
	})
	backend := proxyTestBackend(upstream.listener.Addr().String())
	backend.MaxPendingOperations = 1
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{backend},
		}},
	})
	waitForReadyConnections(t, proxy, PoolBind, 1)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, encodeFrame(
		40,
		testSimpleBind("uid=alice,dc=example,dc=com", []byte("password")),
		nil,
	)); err != nil {
		t.Fatalf("write Bind: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Bind response: %v", err)
	}
	if response.ResultCode == nil || *response.ResultCode != ResultSuccess {
		t.Fatalf("Bind response = %s", response)
	}
	if err := ldapwire.Write(connection, proxySearchRequest(t, 41)); err != nil {
		t.Fatalf("write first Search: %v", err)
	}
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("bound upstream did not receive first Search")
	}
	if err := ldapwire.Write(connection, proxySearchRequest(t, 42)); err != nil {
		t.Fatalf("write second Search: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err = ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read busy response: %v", err)
	}
	if response.MessageID != 42 || response.ResultCode == nil ||
		*response.ResultCode != ResultBusy {
		t.Fatalf("busy response = %s", response)
	}
	close(releaseFirst)
	response, err = ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read first Search entry: %v", err)
	}
	if response.MessageID != 41 || response.ProtocolTag != TagSearchResultEntry {
		t.Fatalf("first Search entry = %s", response)
	}
	response, err = ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read first Search done: %v", err)
	}
	if response.MessageID != 41 || response.ResultCode == nil ||
		*response.ResultCode != ResultSuccess {
		t.Fatalf("first Search done = %s", response)
	}
}

func TestProxyRewritesAbandonTarget(t *testing.T) {
	searches := make(chan Frame, 1)
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
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, proxySearchRequest(t, 100)); err != nil {
		t.Fatalf("write Search: %v", err)
	}
	var upstreamSearch Frame
	select {
	case upstreamSearch = <-searches:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive Search")
	}
	abandon := encodeFrame(101, encodeTLV(0x50, encodeNonnegativeInteger(100)), nil)
	if err := ldapwire.Write(connection, abandon); err != nil {
		t.Fatalf("write Abandon: %v", err)
	}
	select {
	case got := <-abandons:
		if got.MessageID == 101 {
			t.Fatalf("upstream Abandon retained client message ID %d", got.MessageID)
		}
		if got.AbandonTarget != upstreamSearch.MessageID {
			t.Fatalf("upstream Abandon target = %d, want %d", got.AbandonTarget, upstreamSearch.MessageID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive Abandon")
	}
}

func TestProxyDisconnectAndRebindForwardAbandon(t *testing.T) {
	searches := make(chan Frame, 4)
	abandons := make(chan Frame, 4)
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
	waitForReadyConnections(t, proxy, PoolBind, 1)

	t.Run("disconnect", func(t *testing.T) {
		connection, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		if err := ldapwire.Write(connection, proxySearchRequest(t, 50)); err != nil {
			t.Fatalf("write Search: %v", err)
		}
		var search Frame
		select {
		case search = <-searches:
		case <-time.After(2 * time.Second):
			t.Fatal("upstream did not receive Search")
		}
		_ = connection.Close()
		select {
		case abandon := <-abandons:
			if abandon.AbandonTarget != search.MessageID {
				t.Fatalf("disconnect Abandon target = %d, want %d", abandon.AbandonTarget, search.MessageID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("disconnect did not forward Abandon")
		}
	})

	t.Run("replacement Bind", func(t *testing.T) {
		connection, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer connection.Close()
		if err := ldapwire.Write(connection, proxySearchRequest(t, 51)); err != nil {
			t.Fatalf("write Search: %v", err)
		}
		var search Frame
		select {
		case search = <-searches:
		case <-time.After(2 * time.Second):
			t.Fatal("upstream did not receive Search")
		}
		if err := ldapwire.Write(connection, encodeFrame(
			52,
			testSimpleBind("uid=alice,dc=example,dc=com", []byte("password")),
			nil,
		)); err != nil {
			t.Fatalf("write replacement Bind: %v", err)
		}
		response, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read replacement Bind response: %v", err)
		}
		if response.MessageID != 52 || response.ResultCode == nil ||
			*response.ResultCode != ResultSuccess {
			t.Fatalf("replacement Bind response = %s", response)
		}
		select {
		case abandon := <-abandons:
			if abandon.AbandonTarget != search.MessageID {
				t.Fatalf("Bind reset Abandon target = %d, want %d", abandon.AbandonTarget, search.MessageID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("replacement Bind did not forward Abandon")
		}
	})
}

func TestProxyAbandonDoesNotTerminateBind(t *testing.T) {
	type bindAttempt struct {
		connection net.Conn
		frame      Frame
	}
	binds := make(chan bindAttempt, 1)
	abandons := make(chan Frame, 1)
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		switch frame.ProtocolTag {
		case TagBindRequest:
			binds <- bindAttempt{connection: connection, frame: frame}
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
	waitForReadyConnections(t, proxy, PoolBind, 1)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, encodeFrame(
		60,
		testSimpleBind("uid=alice,dc=example,dc=com", []byte("password")),
		nil,
	)); err != nil {
		t.Fatalf("write Bind: %v", err)
	}
	var attempt bindAttempt
	select {
	case attempt = <-binds:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive Bind")
	}
	abandon := encodeFrame(61, encodeTLV(0x50, encodeNonnegativeInteger(60)), nil)
	if err := ldapwire.Write(connection, abandon); err != nil {
		t.Fatalf("write Bind Abandon: %v", err)
	}
	select {
	case got := <-abandons:
		t.Fatalf("Bind was abandoned upstream: %s", got)
	case <-time.After(50 * time.Millisecond):
	}
	if err := ldapwire.Write(attempt.connection, ldapwire.EncodeBindResponse(
		attempt.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		t.Fatalf("write delayed Bind response: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read delayed Bind response: %v", err)
	}
	if response.MessageID != 60 || response.ResultCode == nil ||
		*response.ResultCode != ResultSuccess {
		t.Fatalf("delayed Bind response = %s", response)
	}
}

func TestProxyBackendRecoveryReentersRoundRobin(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve recovering backend address: %v", err)
	}
	recoveringAddress := reserved.Addr().String()
	_ = reserved.Close()
	stable := startProxyTestUpstream(t, "stable", nil)
	recoveringConfig := proxyTestBackend(recoveringAddress)
	recoveringConfig.Retry = 20 * time.Millisecond
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		NetworkTimeout: 100 * time.Millisecond,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				recoveringConfig,
				proxyTestBackend(stable.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	if got := proxySearchMarker(t, client); got != "stable" {
		t.Fatalf("initial Search marker = %q, want stable", got)
	}
	recoveringListener, err := net.Listen("tcp", recoveringAddress)
	if err != nil {
		t.Fatalf("start recovering backend: %v", err)
	}
	startProxyTestUpstreamOn(t, recoveringListener, "recovered", nil)
	waitForBackendConnection(t, proxy, "tier-0-backend-0", PoolRegular)
	if got := proxySearchMarker(t, client); got != "recovered" {
		t.Fatalf("recovered Search marker = %q, want recovered", got)
	}
}

func TestProxyShutdownCancelsStalledServiceBind(t *testing.T) {
	bindReceived := make(chan struct{}, 1)
	upstream := startProxyTestUpstream(t, "unused", func(_ net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagBindRequest {
			return false
		}
		select {
		case bindReceived <- struct{}{}:
		default:
		}
		return true
	})
	proxy, err := NewProxy(RuntimeConfig{
		ProxyAuthz: true,
		Bind: RuntimeBindConfig{
			Method:      "simple",
			DN:          "cn=Manager,dc=example,dc=com",
			Credentials: []byte("secret"),
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(ctx, listener) }()
	defer func() {
		cancel()
		_ = proxy.Close()
	}()
	select {
	case <-bindReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive service Bind")
	}
	cancel()
	_ = proxy.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Proxy.Serve() = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Proxy.Serve() did not stop while service Bind was stalled")
	}
}

func TestProxyAcceptFailureCancelsBackendContext(t *testing.T) {
	dialStarted := make(chan struct{})
	var dialStartedOnce sync.Once
	proxy, err := NewProxy(RuntimeConfig{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialStartedOnce.Do(func() { close(dialStarted) })
			<-ctx.Done()
			return nil, ctx.Err()
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
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for proxy: %v", err)
	}
	defer baseListener.Close()
	releaseAccept := make(chan struct{})
	listener := &delayedErrorListener{
		Listener: baseListener,
		release:  releaseAccept,
		err:      errors.New("forced Accept failure"),
	}
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(context.Background(), listener) }()
	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("backend dial did not start")
	}
	close(releaseAccept)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "forced Accept failure") {
			t.Fatalf("Proxy.Serve() = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closed-listener shutdown did not cancel backend dial")
	}
}

func TestBackendServiceBindTimeout(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	bindReceived := make(chan struct{})
	go func() {
		if _, err := ReadFrame(peer, DefaultMaxFrameSize); err == nil {
			close(bindReceived)
		}
	}()
	proxy, err := NewProxy(RuntimeConfig{
		ProxyAuthz: true,
		Bind: RuntimeBindConfig{
			Method:      "simple",
			DN:          "cn=Manager,dc=example,dc=com",
			Credentials: []byte("secret"),
			Timeout:     25 * time.Millisecond,
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return server, nil
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
	started := time.Now()
	if _, err := backend.connect(
		context.Background(),
		backendConnectionID(backend.id, false, 0),
		false,
	); err == nil {
		t.Fatal("backend.connect() succeeded without a service Bind response")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("service Bind timeout took %s", elapsed)
	}
	select {
	case <-bindReceived:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive the service Bind before timeout")
	}
}

func startRuntimeProxy(t *testing.T, config RuntimeConfig) (*Proxy, string) {
	t.Helper()
	if config.IOTimeout == 0 {
		config.IOTimeout = 2 * time.Second
	}
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- proxy.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		_ = proxy.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Proxy.Serve() = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Proxy.Serve() did not stop")
		}
	})
	return proxy, listener.Addr().String()
}

func proxyTestBackend(address string) RuntimeBackendConfig {
	return RuntimeBackendConfig{
		URI:                "ldap://" + address,
		RegularConnections: 1,
		BindConnections:    1,
		Retry:              20 * time.Millisecond,
		Weight:             1,
	}
}

func waitForReadyConnections(t *testing.T, proxy *Proxy, pool Pool, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ready := 0
		for _, connection := range proxy.scheduler.Snapshot().Connections {
			if connection.Pool == pool && connection.State == ConnectionReady {
				ready++
			}
		}
		if ready >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ready %v connections did not reach %d: %#v", pool, count, proxy.scheduler.Snapshot())
}

func waitForBackendConnection(t *testing.T, proxy *Proxy, backendID string, pool Pool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, connection := range proxy.scheduler.Snapshot().Connections {
			if connection.BackendID == backendID && connection.Pool == pool &&
				connection.State == ConnectionReady {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend %s did not recover: %#v", backendID, proxy.scheduler.Snapshot())
}

func proxySearchRequest(t *testing.T, messageID int64) []byte {
	t.Helper()
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.SearchRequest{
			BaseDN:       "dc=example,dc=com",
			Scope:        directory.ScopeBase,
			DerefAliases: ldapwire.NeverDerefAliases,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{"description"},
		},
	})
	if err != nil {
		t.Fatalf("encode Search: %v", err)
	}
	return encoded
}

func proxySearchMarker(t *testing.T, client *ldap.Conn) string {
	t.Helper()
	marker, err := proxySearchMarkerResult(client)
	if err != nil {
		t.Fatalf("Search(): %v", err)
	}
	return marker
}

func proxySearchMarkerResult(client *ldap.Conn) (string, error) {
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	if err != nil {
		return "", err
	}
	if len(result.Entries) != 1 {
		return "", fmt.Errorf("Search() entries = %d, want 1", len(result.Entries))
	}
	return result.Entries[0].GetAttributeValue("description"), nil
}

func writeProxyTestSearchResult(connection net.Conn, messageID int64, marker string) {
	_ = ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
		messageID,
		directory.Entry{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{{
				Description: "description",
				Values:      [][]byte{[]byte(marker)},
			}},
		},
		nil,
	))
	_ = ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	))
}

func (pool Pool) String() string {
	if pool == PoolBind {
		return "bind"
	}
	return fmt.Sprintf("regular(%d)", pool)
}
