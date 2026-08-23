package lloadd

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestExperimentalFeaturesRuntimeConfiguration(t *testing.T) {
	config := DefaultConfig()
	config.Features = []Feature{FeatureProxyAuthz, FeatureVerifyCredentials, FeatureReadPause}
	config.ProxyAuthz = true
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	if !runtime.ProxyAuthz || !runtime.VerifyCredentials || !runtime.ReadPause {
		t.Fatalf("runtime features = %#v", runtime)
	}

	config.Features = []Feature{FeatureVerifyCredentials}
	config.ProxyAuthz = false
	if _, err := config.RuntimeConfig(); err == nil || !strings.Contains(err.Error(), "requires feature \"proxyauthz\"") {
		t.Fatalf("RuntimeConfig() error = %v", err)
	}
	if _, err := NewProxy(RuntimeConfig{VerifyCredentials: true}); err == nil ||
		!strings.Contains(err.Error(), "requires ProxyAuthz") {
		t.Fatalf("NewProxy() error = %v", err)
	}
}

func TestVerifyCredentialsSimpleBindTopology(t *testing.T) {
	type observedBind struct {
		dn       string
		password string
		controls int
	}
	binds := make(chan observedBind, 1)
	upstream := startProxyTestUpstream(t, "vc", func(connection net.Conn, frame Frame) bool {
		switch frame.ProtocolTag {
		case TagExtendedRequest:
			if frame.ExtendedOID != verifyCredentialsOID || !frame.HasExtendedValue {
				return false
			}
			dn, password, controls, err := decodeSimpleVerifyCredentialsRequest(frame.ExtendedValue)
			if err != nil {
				t.Errorf("decode Verify Credentials request: %v", err)
				return true
			}
			binds <- observedBind{dn: dn, password: password, controls: controls}
			responseControls := encodeTLV(0xa2, encodeTLV(
				0x30,
				encodeTLV(0x04, []byte("1.3.6.1.4.1.4203.666.11.5")),
			))
			value := encodeTLV(0x30, joinBER(
				encodeTLV(0x02, encodeNonnegativeInteger(int64(ldapwire.ResultSuccess))),
				encodeTLV(0x04, nil),
				responseControls,
			))
			_ = ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
				frame.MessageID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				"",
				value,
				nil,
			))
			return true
		case TagSearchRequest:
			hasProxyAuthz := false
			for _, control := range frame.Controls {
				hasProxyAuthz = hasProxyAuthz || control.OID == ProxyAuthzControlOID
			}
			if !hasProxyAuthz {
				t.Error("search after VC Bind has no proxyAuthz control")
			}
			writeProxyTestSearchResult(connection, frame.MessageID, "vc")
			return true
		default:
			return false
		}
	})
	backend := proxyTestBackend(upstream.listener.Addr().String())
	backend.BindConnections = 3
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ProxyAuthz:        true,
		VerifyCredentials: true,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{backend},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	for _, connection := range proxy.scheduler.Snapshot().Connections {
		if connection.Pool == PoolBind {
			t.Fatalf("VC runtime created Bind-pool connection %#v", connection)
		}
	}

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	bindRequest, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 41,
		Request: ldapwire.BindRequest{
			Version: 3,
			Name:    "uid=alice,dc=example,dc=com",
			Authentication: ldapwire.Authentication{
				Simple: []byte("secret"),
			},
		},
		Controls: []ldapwire.Control{{OID: "1.2.3.4"}},
	})
	if err != nil {
		t.Fatalf("encode Bind: %v", err)
	}
	if err := ldapwire.Write(connection, bindRequest); err != nil {
		t.Fatalf("write Bind: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("read Bind response: %v", err)
	}
	if response.ProtocolTag != TagBindResponse || response.ResultCode == nil ||
		*response.ResultCode != ResultSuccess || len(response.Controls) != 1 {
		t.Fatalf("Bind response = %s", response)
	}
	select {
	case observed := <-binds:
		if observed.dn != "uid=alice,dc=example,dc=com" || observed.password != "secret" || observed.controls != 1 {
			t.Fatalf("Verify Credentials request = %#v", observed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive Verify Credentials")
	}

	if err := ldapwire.Write(connection, proxySearchRequest(t, 42)); err != nil {
		t.Fatalf("write Search: %v", err)
	}
	assertSearchResponseCompletes(t, connection, 42)
}

func TestVerifyCredentialsExplicitCompatibilityBoundaries(t *testing.T) {
	t.Run("plugin unavailable", func(t *testing.T) {
		upstream := startProxyTestUpstream(t, "vc", func(connection net.Conn, frame Frame) bool {
			if frame.ProtocolTag != TagExtendedRequest || frame.ExtendedOID != verifyCredentialsOID {
				return false
			}
			_ = ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
				frame.MessageID,
				ldapwire.Result{Code: ldapwire.ResultProtocolError, DiagnosticMessage: "unsupported extended operation"},
				"",
				nil,
				nil,
			))
			return true
		})
		proxy, address := startVerifyCredentialsProxy(t, upstream)
		waitForReadyConnections(t, proxy, PoolRegular, 1)
		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		if err := ldapwire.Write(connection, encodeFrame(51, testSimpleBind("uid=alice", []byte("secret")), nil)); err != nil {
			t.Fatalf("write Bind: %v", err)
		}
		response, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read Bind response: %v", err)
		}
		if response.ProtocolTag != TagBindResponse || response.ResultCode == nil ||
			*response.ResultCode != ResultProtocolError {
			t.Fatalf("plugin-unavailable response = %s", response)
		}
	})

	t.Run("SASL is rejected locally", func(t *testing.T) {
		var requests atomic.Int64
		upstream := startProxyTestUpstream(t, "vc", func(_ net.Conn, frame Frame) bool {
			if frame.ProtocolTag == TagExtendedRequest && frame.ExtendedOID == verifyCredentialsOID {
				requests.Add(1)
			}
			return false
		})
		proxy, address := startVerifyCredentialsProxy(t, upstream)
		waitForReadyConnections(t, proxy, PoolRegular, 1)
		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		if err := ldapwire.Write(connection, encodeFrame(
			52,
			testSASLBind("", "PLAIN", true, []byte("credentials")),
			nil,
		)); err != nil {
			t.Fatalf("write SASL Bind: %v", err)
		}
		response, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read SASL Bind response: %v", err)
		}
		if response.ProtocolTag != TagBindResponse || response.ResultCode == nil ||
			*response.ResultCode != ResultCode(ldapwire.ResultAuthMethodNotSupported) || requests.Load() != 0 {
			t.Fatalf("SASL boundary response = %s, upstream requests = %d", response, requests.Load())
		}
	})
}

func TestReadPauseCapacityAndRecovery(t *testing.T) {
	tests := []struct {
		name             string
		clientMaxPending int
		connectionMax    int
	}{
		{name: "upstream capacity", connectionMax: 1},
		{name: "client capacity", clientMaxPending: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan struct {
				connection net.Conn
				messageID  int64
			}, 3)
			upstream := startProxyTestUpstream(t, "pause", func(connection net.Conn, frame Frame) bool {
				if frame.ProtocolTag != TagSearchRequest {
					return false
				}
				requests <- struct {
					connection net.Conn
					messageID  int64
				}{connection: connection, messageID: frame.MessageID}
				return true
			})
			backend := proxyTestBackend(upstream.listener.Addr().String())
			backend.ConnectionMaxPending = test.connectionMax
			proxy, address := startRuntimeProxy(t, RuntimeConfig{
				ReadPause:        true,
				ClientMaxPending: test.clientMaxPending,
				Tiers: []RuntimeTierConfig{{
					Strategy: "roundrobin",
					Backends: []RuntimeBackendConfig{backend},
				}},
			})
			waitForReadyConnections(t, proxy, PoolRegular, 1)
			connection := dialProxyProtocolTestClient(t, address)
			defer connection.Close()
			if err := ldapwire.Write(connection, proxySearchRequest(t, 61)); err != nil {
				t.Fatalf("write first Search: %v", err)
			}
			first := awaitPausedSearch(t, requests)
			if err := ldapwire.Write(connection, proxySearchRequest(t, 62)); err != nil {
				t.Fatalf("write second Search: %v", err)
			}
			select {
			case second := <-requests:
				t.Fatalf("second Search reached upstream before capacity recovered: %d", second.messageID)
			case <-time.After(150 * time.Millisecond):
			}
			writeProxyTestSearchResult(first.connection, first.messageID, "first")
			second := awaitPausedSearch(t, requests)
			writeProxyTestSearchResult(second.connection, second.messageID, "second")
			assertSearchResponseCompletes(t, connection, 61)
			assertSearchResponseCompletes(t, connection, 62)
		})
	}
}

func TestReadPauseWakesOnUpstreamDisconnect(t *testing.T) {
	requests := make(chan struct {
		connection net.Conn
		messageID  int64
	}, 2)
	upstream := startProxyTestUpstream(t, "pause", func(connection net.Conn, frame Frame) bool {
		if frame.ProtocolTag == TagSearchRequest {
			requests <- struct {
				connection net.Conn
				messageID  int64
			}{connection: connection, messageID: frame.MessageID}
			return true
		}
		return false
	})
	backend := proxyTestBackend(upstream.listener.Addr().String())
	backend.ConnectionMaxPending = 1
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		ReadPause: true,
		Tiers:     []RuntimeTierConfig{{Strategy: "roundrobin", Backends: []RuntimeBackendConfig{backend}}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	if err := ldapwire.Write(connection, proxySearchRequest(t, 71)); err != nil {
		t.Fatalf("write first Search: %v", err)
	}
	_ = awaitPausedSearch(t, requests)
	if err := ldapwire.Write(connection, proxySearchRequest(t, 72)); err != nil {
		t.Fatalf("write second Search: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	upstream.close()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	seen := map[int64]ResultCode{}
	for len(seen) < 2 {
		response, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read disconnect response: %v", err)
		}
		if response.ResultCode != nil {
			seen[response.MessageID] = *response.ResultCode
		}
	}
	if seen[71] != ResultOther || seen[72] != ResultUnavailable {
		t.Fatalf("disconnect results = %#v", seen)
	}
}

func TestExperimentalFeatureOpenLDAPSourceAnchors(t *testing.T) {
	checks := map[string][]string{
		"servers/lloadd/connection.c": {
			"c->c_io_state |= LLOAD_C_READ_PAUSE;",
			"c->c_io_state ^= LLOAD_C_READ_PAUSE;",
		},
		"servers/lloadd/bind.c": {
			"client_bind_as_vc(",
			"LDAP_EXOP_VERIFY_CREDENTIALS",
			"handle_vc_bind_response(",
		},
		"servers/lloadd/backend.c": {
			"!(lload_features & LLOAD_FEATURE_VC)",
		},
		"contrib/slapd-modules/vc/vc.c": {
			"empty request data field in VerifyCredentials exop",
			"vc_create_response(",
		},
	}
	for path, anchors := range checks {
		contents, ok := pinnedOpenLDAPSource(t, path)
		if !ok {
			return
		}
		for _, anchor := range anchors {
			if !strings.Contains(string(contents), anchor) {
				t.Fatalf("OpenLDAP %s lacks source anchor %q", path, anchor)
			}
		}
	}
}

func startVerifyCredentialsProxy(t *testing.T, upstream *proxyTestUpstream) (*Proxy, string) {
	t.Helper()
	return startRuntimeProxy(t, RuntimeConfig{
		ProxyAuthz:        true,
		VerifyCredentials: true,
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{proxyTestBackend(upstream.listener.Addr().String())},
		}},
	})
}

func decodeSimpleVerifyCredentialsRequest(value []byte) (string, string, int, error) {
	sequence, next, err := parseElement(value, 0)
	if err != nil || next != len(value) || !elementIs(sequence, berClassUniversal, true, berTagSequence) {
		return "", "", 0, errors.New("requestValue is not a sequence")
	}
	dn, next, err := parseElement(value, sequence.contentStart)
	if err != nil || !elementIs(dn, berClassUniversal, false, berTagOctetString) {
		return "", "", 0, errors.New("requestValue has no DN")
	}
	authentication, next, err := parseElement(value, next)
	if err != nil || !elementIs(authentication, berClassContext, false, 0) {
		return "", "", 0, errors.New("requestValue is not a simple Bind")
	}
	controlCount := 0
	if next < sequence.end {
		controls, controlsEnd, controlsErr := parseElement(value, next)
		if controlsErr != nil || controlsEnd != sequence.end ||
			!elementIs(controls, berClassContext, true, 2) {
			return "", "", 0, errors.New("requestValue has malformed controls")
		}
		for cursor := controls.contentStart; cursor < controls.end; controlCount++ {
			_, cursor, err = parseElement(value, cursor)
			if err != nil {
				return "", "", 0, err
			}
		}
	} else if next != sequence.end {
		return "", "", 0, errors.New("requestValue is truncated")
	}
	return string(value[dn.contentStart:dn.end]),
		string(value[authentication.contentStart:authentication.end]), controlCount, nil
}

func awaitPausedSearch(t *testing.T, requests <-chan struct {
	connection net.Conn
	messageID  int64
}) struct {
	connection net.Conn
	messageID  int64
} {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(2 * time.Second):
		t.Fatal("Search did not reach upstream")
		return struct {
			connection net.Conn
			messageID  int64
		}{}
	}
}

func assertSearchResponseCompletes(t *testing.T, connection net.Conn, messageID int64) {
	t.Helper()
	for {
		response, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read Search response: %v", err)
		}
		if response.MessageID != messageID {
			t.Fatalf("Search response message ID = %d, want %d", response.MessageID, messageID)
		}
		if response.ProtocolTag == TagSearchResultDone {
			if response.ResultCode == nil || *response.ResultCode != ResultSuccess {
				t.Fatalf("Search result = %s", response)
			}
			return
		}
	}
}
