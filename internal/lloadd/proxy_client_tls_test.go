package lloadd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestNewProxyClonesAndValidatesClientTLS(t *testing.T) {
	if _, err := NewProxy(RuntimeConfig{ClientTLS: &tls.Config{}}); err == nil {
		t.Fatal("NewProxy() accepted client TLS without a server certificate")
	}
	if _, err := NewProxy(RuntimeConfig{ClientTLS: &tls.Config{
		Certificates: []tls.Certificate{{PrivateKey: struct{}{}}},
	}}); err == nil {
		t.Fatal("NewProxy() accepted an incomplete client TLS certificate")
	}

	serverTLS, _ := clientStartTLSTestConfigs(t)
	serverTLS.MinVersion = tls.VersionTLS12
	serverTLS.MaxVersion = tls.VersionTLS13
	proxy, err := NewProxy(RuntimeConfig{ClientTLS: serverTLS})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	serverTLS.MinVersion = tls.VersionTLS13
	serverTLS.Certificates = nil
	if proxy.config.ClientTLS == serverTLS ||
		proxy.config.ClientTLS.MinVersion != tls.VersionTLS12 ||
		len(proxy.config.ClientTLS.Certificates) != 1 {
		t.Fatal("NewProxy() retained caller-owned client TLS configuration")
	}

	invalidVersions := []*tls.Config{
		{
			Certificates: proxy.config.ClientTLS.Certificates,
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS12,
		},
		{
			Certificates: proxy.config.ClientTLS.Certificates,
			MinVersion:   0x0200,
		},
	}
	for _, config := range invalidVersions {
		if _, err := NewProxy(RuntimeConfig{ClientTLS: config}); err == nil {
			t.Fatalf("NewProxy() accepted invalid TLS versions %#v", config)
		}
	}
}

func TestClientStartTLSRoutesBindAndSearchAfterUpgrade(t *testing.T) {
	serverTLS, clientTLS := clientStartTLSTestConfigs(t)
	var upstreamExtended atomic.Int64
	upstream := startProxyTestUpstream(t, "secured", func(_ net.Conn, frame Frame) bool {
		if frame.ProtocolTag == TagExtendedRequest {
			upstreamExtended.Add(1)
			return true
		}
		return false
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ClientTLS: serverTLS,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	waitForReadyConnections(t, proxy, PoolBind, 1)

	secured := dialAndStartClientTLS(t, address, clientTLS, 1)
	if !secured.ConnectionState().HandshakeComplete {
		t.Fatal("client TLS handshake did not complete")
	}

	writeClientStartTLSRequest(t, secured, 2, false)
	assertClientStartTLSResult(t, secured, 2, ldapwire.ResultOperationsError)

	client := ldap.NewConn(secured, true)
	client.Start()
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("uid=alice,dc=example,dc=com", "password"); err != nil {
		t.Fatalf("Bind after StartTLS: %v", err)
	}
	if marker := proxySearchMarker(t, client); marker != "secured" {
		t.Fatalf("Search marker = %q, want secured", marker)
	}
	if upstreamExtended.Load() != 0 {
		t.Fatalf("client StartTLS reached upstream %d times", upstreamExtended.Load())
	}
}

func TestClientStartTLSRejectsOutstandingSearchAndThenRecovers(t *testing.T) {
	serverTLS, clientTLS := clientStartTLSTestConfigs(t)
	searchStarted := make(chan struct{}, 1)
	releaseSearch := make(chan struct{})
	upstream := startProxyTestUpstream(t, "after-search", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagSearchRequest {
			return false
		}
		searchStarted <- struct{}{}
		<-releaseSearch
		writeProxyTestSearchResult(connection, frame.MessageID, "after-search")
		return true
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ClientTLS: serverTLS,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialClientStartTLSTest(t, address)
	if err := ldapwire.Write(connection, proxySearchRequest(t, 10)); err != nil {
		t.Fatalf("write Search: %v", err)
	}
	select {
	case <-searchStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream Search did not start")
	}
	writeClientStartTLSRequest(t, connection, 11, false)
	assertClientStartTLSResult(t, connection, 11, ldapwire.ResultOperationsError)
	close(releaseSearch)
	assertClientSearchResult(t, connection, 10)

	writeClientStartTLSRequest(t, connection, 12, false)
	assertClientStartTLSResult(t, connection, 12, ldapwire.ResultSuccess)
	secured := tls.Client(connection, clientTLS.Clone())
	if err := secured.Handshake(); err != nil {
		t.Fatalf("TLS handshake after Search completed: %v", err)
	}
	if err := ldapwire.Write(secured, proxySearchRequest(t, 13)); err != nil {
		t.Fatalf("write secured Search: %v", err)
	}
	assertClientSearchResult(t, secured, 13)
}

func TestClientStartTLSRejectsBindInProgress(t *testing.T) {
	serverTLS, _ := clientStartTLSTestConfigs(t)
	bindStarted := make(chan struct{}, 1)
	releaseBind := make(chan struct{})
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag != TagBindRequest {
			return false
		}
		bindStarted <- struct{}{}
		<-releaseBind
		_ = ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			frame.MessageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
		return true
	})
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ClientTLS: serverTLS,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolBind, 1)

	connection := dialClientStartTLSTest(t, address)
	bindRequest, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 20,
		Request: ldapwire.BindRequest{
			Version: 3,
			Name:    "uid=alice,dc=example,dc=com",
			Authentication: ldapwire.Authentication{
				Simple: []byte("password"),
			},
		},
	})
	if err != nil {
		t.Fatalf("encode Bind: %v", err)
	}
	if err := ldapwire.Write(connection, bindRequest); err != nil {
		t.Fatalf("write Bind: %v", err)
	}
	select {
	case <-bindStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream Bind did not start")
	}
	writeClientStartTLSRequest(t, connection, 21, false)
	assertClientStartTLSResult(t, connection, 21, ldapwire.ResultOperationsError)
	close(releaseBind)
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Bind response: %v", err)
	}
	if response.MessageID != 20 || response.ProtocolTag != TagBindResponse ||
		response.ResultCode == nil || *response.ResultCode != ResultSuccess {
		t.Fatalf("Bind response = %s", response)
	}
}

func TestClientStartTLSRequiresLDAPv3AndNoRequestValue(t *testing.T) {
	serverTLS, _ := clientStartTLSTestConfigs(t)
	_, address := startRuntimeProxy(t, RuntimeConfig{ClientTLS: serverTLS})
	connection := dialClientStartTLSTest(t, address)

	bindRequest, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 30,
		Request: ldapwire.BindRequest{
			Version:        2,
			Authentication: ldapwire.Authentication{Simple: []byte("password")},
		},
	})
	if err != nil {
		t.Fatalf("encode LDAPv2 Bind: %v", err)
	}
	if err := ldapwire.Write(connection, bindRequest); err != nil {
		t.Fatalf("write LDAPv2 Bind: %v", err)
	}
	assertClientLDAPResult(t, connection, 30, TagBindResponse, ldapwire.ResultProtocolError)
	writeClientStartTLSRequest(t, connection, 31, false)
	assertClientStartTLSResult(t, connection, 31, ldapwire.ResultProtocolError)

	bindRequest, err = ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 32,
		Request: ldapwire.BindRequest{
			Version:        3,
			Authentication: ldapwire.Authentication{Simple: nil},
		},
	})
	if err != nil {
		t.Fatalf("encode LDAPv3 Bind: %v", err)
	}
	if err := ldapwire.Write(connection, bindRequest); err != nil {
		t.Fatalf("write LDAPv3 Bind: %v", err)
	}
	assertClientLDAPResult(t, connection, 32, TagBindResponse, ldapwire.ResultUnavailable)
	writeClientStartTLSRequest(t, connection, 33, true)
	assertClientStartTLSResult(t, connection, 33, ldapwire.ResultProtocolError)
}

func TestClientStartTLSWithoutConfigurationIsUnavailable(t *testing.T) {
	_, address := startRuntimeProxy(t, RuntimeConfig{})
	connection := dialClientStartTLSTest(t, address)
	writeClientStartTLSRequest(t, connection, 40, false)
	assertClientStartTLSResult(t, connection, 40, ldapwire.ResultUnavailable)
}

func TestClientStartTLSHandshakeFailureClosesConnection(t *testing.T) {
	serverTLS, _ := clientStartTLSTestConfigs(t)
	_, address := startRuntimeProxy(t, RuntimeConfig{
		ClientTLS: serverTLS,
		IOTimeout: 500 * time.Millisecond,
	})
	connection := dialClientStartTLSTest(t, address)
	writeClientStartTLSRequest(t, connection, 50, false)
	assertClientStartTLSResult(t, connection, 50, ldapwire.ResultSuccess)
	if _, err := connection.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x00}); err != nil {
		t.Fatalf("write malformed TLS record: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	_, err := connection.Read(buffer)
	if err == nil {
		t.Fatal("connection remained open after TLS handshake failure")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatal("TLS handshake failure did not close the connection")
	}
}

func clientStartTLSTestConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	pki := newBackendTLSTestPKI(t)
	contents, err := os.ReadFile(pki.caFile)
	if err != nil {
		t.Fatalf("read test CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		t.Fatal("load test CA")
	}
	return &tls.Config{
			Certificates: []tls.Certificate{pki.serverCertificate},
			MinVersion:   tls.VersionTLS12,
		}, &tls.Config{
			RootCAs:    roots,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		}
}

func dialAndStartClientTLS(
	t *testing.T,
	address string,
	config *tls.Config,
	messageID int64,
) *tls.Conn {
	t.Helper()
	connection := dialClientStartTLSTest(t, address)
	writeClientStartTLSRequest(t, connection, messageID, false)
	assertClientStartTLSResult(t, connection, messageID, ldapwire.ResultSuccess)
	secured := tls.Client(connection, config.Clone())
	if err := secured.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	return secured
}

func dialClientStartTLSTest(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func writeClientStartTLSRequest(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	withValue bool,
) {
	t.Helper()
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name:     clientStartTLSOID,
			Value:    []byte("invalid"),
			HasValue: withValue,
		},
	})
	if err != nil {
		t.Fatalf("encode StartTLS: %v", err)
	}
	if err := ldapwire.Write(connection, request); err != nil {
		t.Fatalf("write StartTLS: %v", err)
	}
}

func assertClientStartTLSResult(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	code ldapwire.ResultCode,
) {
	t.Helper()
	assertClientLDAPResult(t, connection, messageID, TagExtendedResponse, code)
}

func assertClientLDAPResult(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	protocolTag uint64,
	code ldapwire.ResultCode,
) {
	t.Helper()
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read LDAP result: %v", err)
	}
	if response.MessageID != messageID || response.ProtocolTag != protocolTag ||
		response.ResultCode == nil || *response.ResultCode != ResultCode(code) {
		t.Fatalf("LDAP result = %s, want message %d tag %d result %d", response, messageID, protocolTag, code)
	}
}

func assertClientSearchResult(t *testing.T, connection net.Conn, messageID int64) {
	t.Helper()
	entry, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Search entry: %v", err)
	}
	if entry.MessageID != messageID || entry.ProtocolTag != TagSearchResultEntry {
		t.Fatalf("Search entry = %s", entry)
	}
	done, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Search result: %v", err)
	}
	if done.MessageID != messageID || done.ProtocolTag != TagSearchResultDone ||
		done.ResultCode == nil || *done.ResultCode != ResultSuccess {
		t.Fatalf("Search result = %s", done)
	}
}
