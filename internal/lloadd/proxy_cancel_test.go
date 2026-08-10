package lloadd

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestProxyCancelRewritesTargetAndRestoresMessageIDs(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()

	const (
		targetClientID = int64(41)
		cancelClientID = int64(42)
	)
	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, targetClientID))
	target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)

	writeProxyCancelTestRequest(
		t,
		connection,
		proxyCancelRequest(t, cancelClientID, targetClientID),
	)
	cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
	assertProxyCancelForwarding(t, target, cancel)

	completeProxyCancelUpstream(t, target, cancel)
	assertProxyCancelResponse(
		t,
		connection,
		targetClientID,
		TagSearchResultDone,
		ldapwire.ResultCanceled,
	)
	assertProxyCancelResponse(
		t,
		connection,
		cancelClientID,
		TagExtendedResponse,
		ldapwire.ResultSuccess,
	)
}

func TestProxyCancelBypassesPendingLimits(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*RuntimeConfig, *RuntimeBackendConfig)
	}{
		{
			name: "client",
			configure: func(config *RuntimeConfig, _ *RuntimeBackendConfig) {
				// OpenLDAP counts the newly received operation before applying this
				// threshold, so a value of two permits exactly one pending request.
				config.ClientMaxPending = 2
			},
		},
		{
			name: "backend",
			configure: func(_ *RuntimeConfig, backend *RuntimeBackendConfig) {
				backend.MaxPendingOperations = 1
			},
		},
		{
			name: "connection",
			configure: func(_ *RuntimeConfig, backend *RuntimeBackendConfig) {
				backend.ConnectionMaxPending = 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream, requests := startProxyCancelRecordingUpstream(t)
			backend := proxyTestBackend(upstream.listener.Addr().String())
			config := RuntimeConfig{}
			test.configure(&config, &backend)
			config.Tiers = []RuntimeTierConfig{{
				Strategy: "roundrobin",
				Backends: []RuntimeBackendConfig{backend},
			}}
			proxy, address := startRuntimeProxy(t, config)
			waitForReadyConnections(t, proxy, PoolRegular, 1)

			connection := dialProxyProtocolTestClient(t, address)
			defer connection.Close()

			const (
				targetClientID = int64(51)
				cancelClientID = int64(52)
			)
			writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, targetClientID))
			target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
			writeProxyCancelTestRequest(
				t,
				connection,
				proxyCancelRequest(t, cancelClientID, targetClientID),
			)
			cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
			assertProxyCancelForwarding(t, target, cancel)

			completeProxyCancelUpstream(t, target, cancel)
			assertProxyCancelResponse(
				t,
				connection,
				targetClientID,
				TagSearchResultDone,
				ldapwire.ResultCanceled,
			)
			assertProxyCancelResponse(
				t,
				connection,
				cancelClientID,
				TagExtendedResponse,
				ldapwire.ResultSuccess,
			)
		})
	}
}

func TestProxyCancelSignalingLeaseRemainsAccounted(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	backend := proxyTestBackend(upstream.listener.Addr().String())
	backend.MaxPendingOperations = 1
	backend.ConnectionMaxPending = 1
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{backend},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 151))
	target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
	assertProxyCancelRuntimePending(t, proxy, 1)
	writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 152, 151))
	cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
	assertProxyCancelRuntimePending(t, proxy, 2)

	if err := ldapwire.Write(target.connection, ldapwire.EncodeSearchResultDone(
		target.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultCanceled},
		nil,
	)); err != nil {
		t.Fatalf("write canceled target response: %v", err)
	}
	assertProxyCancelResponse(t, connection, 151, TagSearchResultDone, ldapwire.ResultCanceled)
	assertProxyCancelRuntimePending(t, proxy, 1)

	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 153))
	assertProxyCancelResponse(t, connection, 153, TagSearchResultDone, ldapwire.ResultBusy)
	select {
	case event := <-requests:
		t.Fatalf("capacity-hidden Search reached upstream: %s", event.frame)
	default:
	}

	if err := ldapwire.Write(cancel.connection, ldapwire.EncodeExtendedResponse(
		cancel.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		"",
		nil,
		nil,
	)); err != nil {
		t.Fatalf("write successful Cancel response: %v", err)
	}
	assertProxyCancelResponse(t, connection, 152, TagExtendedResponse, ldapwire.ResultSuccess)
	assertProxyCancelRuntimePending(t, proxy, 0)
}

func TestProxyCancelRejectsConcurrentRetryAndReleasesTarget(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 131))
	target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
	writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 132, 131))
	firstCancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)

	writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 133, 131))
	assertProxyCancelResponse(t, connection, 133, TagExtendedResponse, ldapwire.ResultOperationsError)
	proxyCancelBarrierSearch(t, connection, requests, 135)

	if err := ldapwire.Write(firstCancel.connection, ldapwire.EncodeExtendedResponse(
		firstCancel.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultCannotCancel},
		"",
		nil,
		nil,
	)); err != nil {
		t.Fatalf("write unsuccessful Cancel response: %v", err)
	}
	assertProxyCancelResponse(t, connection, 132, TagExtendedResponse, ldapwire.ResultCannotCancel)

	writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 134, 131))
	retry := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
	assertProxyCancelForwarding(t, target, retry)
	completeProxyCancelUpstream(t, target, retry)
	assertProxyCancelResponse(t, connection, 131, TagSearchResultDone, ldapwire.ResultCanceled)
	assertProxyCancelResponse(t, connection, 134, TagExtendedResponse, ldapwire.ResultSuccess)
}

func TestProxyCancelCannotBeAbandoned(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 141))
	target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
	writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 142, 141))
	cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)

	abandon := encodeFrame(143, encodeTLV(0x50, encodeNonnegativeInteger(142)), nil)
	writeProxyCancelTestRequest(t, connection, abandon)
	proxyCancelBarrierSearch(t, connection, requests, 144)

	completeProxyCancelUpstream(t, target, cancel)
	assertProxyCancelResponse(t, connection, 141, TagSearchResultDone, ldapwire.ResultCanceled)
	assertProxyCancelResponse(t, connection, 142, TagExtendedResponse, ldapwire.ResultSuccess)
}

func TestProxyCancelPreservesProxyAuthorizationIdentity(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	config := proxyCancelRuntimeConfig(upstream)
	config.ProxyAuthz = true
	proxy, address := startRuntimeProxy(t, config)
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	waitForReadyConnections(t, proxy, PoolBind, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	const bindDN = "uid=alice,dc=example,dc=com"
	writeProxyCancelTestRequest(
		t,
		connection,
		encodeFrame(161, testSimpleBind(bindDN, []byte("secret")), nil),
	)
	bind := awaitProxyCancelUpstreamRequest(t, requests, TagBindRequest)
	if err := ldapwire.Write(bind.connection, ldapwire.EncodeBindResponse(
		bind.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		t.Fatalf("write upstream Bind response: %v", err)
	}
	assertProxyCancelResponse(t, connection, 161, TagBindResponse, ldapwire.ResultSuccess)

	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 162))
	target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
	assertProxyCancelAuthzControl(t, target.message, "dn:"+bindDN)
	writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 163, 162))
	cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
	assertProxyCancelAuthzControl(t, cancel.message, "dn:"+bindDN)
	completeProxyCancelUpstream(t, target, cancel)
	assertProxyCancelResponse(t, connection, 162, TagSearchResultDone, ldapwire.ResultCanceled)
	assertProxyCancelResponse(t, connection, 163, TagExtendedResponse, ldapwire.ResultSuccess)
}

func TestProxyCancelUnexpectedResponseTypeRetiresUpstream(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 171))
	_ = awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
	writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 172, 171))
	cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
	if err := ldapwire.Write(cancel.connection, ldapwire.EncodeSearchResultDone(
		cancel.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		t.Fatalf("write invalid Cancel response: %v", err)
	}

	responses := make(map[int64]Frame, 2)
	for range 2 {
		response := assertProxyCancelAnyResponse(t, connection)
		responses[response.MessageID] = response
	}
	for messageID, tag := range map[int64]uint64{
		171: TagSearchResultDone,
		172: TagExtendedResponse,
	} {
		response, ok := responses[messageID]
		if !ok || response.ProtocolTag != tag || response.ResultCode == nil ||
			ldapwire.ResultCode(*response.ResultCode) != ldapwire.ResultOther {
			t.Fatalf("response for message ID %d = %#v", messageID, response)
		}
	}
}

func TestProxyCancelRejectsUnknownAndCompletedTargets(t *testing.T) {
	// RFC 3909 reserves tooLate for an operation the server still knows but can
	// no longer stop. Once the operation has left lloadd's registry, it is
	// indistinguishable from an unknown ID and therefore returns noSuchOperation.
	t.Run("unknown target", func(t *testing.T) {
		upstream, requests := startProxyCancelRecordingUpstream(t)
		proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
		waitForReadyConnections(t, proxy, PoolRegular, 1)

		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 62, 61))
		assertProxyCancelResponse(
			t,
			connection,
			62,
			TagExtendedResponse,
			ldapwire.ResultNoSuchOperation,
		)
		proxyCancelBarrierSearch(t, connection, requests, 63)
	})

	t.Run("completed target", func(t *testing.T) {
		upstream, requests := startProxyCancelRecordingUpstream(t)
		proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
		waitForReadyConnections(t, proxy, PoolRegular, 1)

		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 64))
		completed := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
		completeProxyCancelSearch(
			t,
			connection,
			completed,
			64,
			ldapwire.ResultSuccess,
		)

		writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 65, 64))
		assertProxyCancelResponse(
			t,
			connection,
			65,
			TagExtendedResponse,
			ldapwire.ResultNoSuchOperation,
		)
		proxyCancelBarrierSearch(t, connection, requests, 66)
	})
}

func TestProxyCancelRejectsBindAndCancelTargets(t *testing.T) {
	t.Run("Bind target", func(t *testing.T) {
		upstream, requests := startProxyCancelRecordingUpstream(t)
		proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
		waitForReadyConnections(t, proxy, PoolRegular, 1)
		waitForReadyConnections(t, proxy, PoolBind, 1)

		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		writeProxyCancelTestRequest(
			t,
			connection,
			encodeFrame(71, testSimpleBind("uid=alice,dc=example,dc=com", []byte("secret")), nil),
		)
		bind := awaitProxyCancelUpstreamRequest(t, requests, TagBindRequest)

		writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 72, 71))
		// RFC 3909 classifies Bind as non-cancelable, but RFC 4511 section
		// 4.2.1 forbids any further PDU before BindResponse. OpenLDAP 2.6.13
		// applies that association-level rule first and returns protocolError.
		assertProxyCancelResponse(
			t,
			connection,
			72,
			TagExtendedResponse,
			ldapwire.ResultProtocolError,
		)

		if err := ldapwire.Write(bind.connection, ldapwire.EncodeBindResponse(
			bind.frame.MessageID,
			ldapwire.Result{Code: ldapwire.ResultInvalidCredentials},
			nil,
		)); err != nil {
			t.Fatalf("write upstream Bind response: %v", err)
		}
		assertProxyCancelResponse(
			t,
			connection,
			71,
			TagBindResponse,
			ldapwire.ResultInvalidCredentials,
		)
		proxyCancelBarrierSearch(t, connection, requests, 73)
	})

	t.Run("Cancel target", func(t *testing.T) {
		upstream, requests := startProxyCancelRecordingUpstream(t)
		proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
		waitForReadyConnections(t, proxy, PoolRegular, 1)

		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 81))
		target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
		writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 82, 81))
		firstCancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
		assertProxyCancelForwarding(t, target, firstCancel)

		writeProxyCancelTestRequest(t, connection, proxyCancelRequest(t, 83, 82))
		assertProxyCancelResponse(
			t,
			connection,
			83,
			TagExtendedResponse,
			ldapwire.ResultCannotCancel,
		)

		completeProxyCancelUpstream(t, target, firstCancel)
		assertProxyCancelResponse(
			t,
			connection,
			81,
			TagSearchResultDone,
			ldapwire.ResultCanceled,
		)
		assertProxyCancelResponse(
			t,
			connection,
			82,
			TagExtendedResponse,
			ldapwire.ResultSuccess,
		)
		proxyCancelBarrierSearch(t, connection, requests, 84)
	})
}

func TestProxyCancelDuplicateBindMessageIDClosesAssociation(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	waitForReadyConnections(t, proxy, PoolBind, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	const messageID = int64(74)
	writeProxyCancelTestRequest(
		t,
		connection,
		encodeFrame(
			messageID,
			testSimpleBind("uid=alice,dc=example,dc=com", []byte("secret")),
			nil,
		),
	)
	_ = awaitProxyCancelUpstreamRequest(t, requests, TagBindRequest)

	writeProxyCancelTestRequest(
		t,
		connection,
		proxyCancelRequest(t, messageID, messageID),
	)
	expectProxyProtocolTestConnectionClosed(t, connection)
	waitForProxyCancelClientRemoval(t, proxy)

	select {
	case event := <-requests:
		if event.err == nil && event.frame.ProtocolTag == TagExtendedRequest {
			t.Fatalf("duplicate-ID Cancel reached upstream: %s", event.frame)
		}
	case <-time.After(50 * time.Millisecond):
	}
}

func TestProxyCancelIsScopedToClientAssociation(t *testing.T) {
	t.Run("foreign-only target is unknown", func(t *testing.T) {
		upstream, requests := startProxyCancelRecordingUpstream(t)
		proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
		waitForReadyConnections(t, proxy, PoolRegular, 1)

		owner := dialProxyProtocolTestClient(t, address)
		defer owner.Close()
		other := dialProxyProtocolTestClient(t, address)
		defer other.Close()

		writeProxyCancelTestRequest(t, owner, proxySearchRequest(t, 91))
		foreignTarget := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
		writeProxyCancelTestRequest(t, other, proxyCancelRequest(t, 92, 91))
		assertProxyCancelResponse(
			t,
			other,
			92,
			TagExtendedResponse,
			ldapwire.ResultNoSuchOperation,
		)

		completeProxyCancelSearch(
			t,
			owner,
			foreignTarget,
			91,
			ldapwire.ResultSuccess,
		)
		proxyCancelBarrierSearch(t, other, requests, 93)
	})

	t.Run("same client IDs select the issuing client's operation", func(t *testing.T) {
		upstream, requests := startProxyCancelRecordingUpstream(t)
		proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
		waitForReadyConnections(t, proxy, PoolRegular, 1)

		firstClient := dialProxyProtocolTestClient(t, address)
		defer firstClient.Close()
		secondClient := dialProxyProtocolTestClient(t, address)
		defer secondClient.Close()

		const sharedClientID = int64(101)
		writeProxyCancelTestRequest(t, firstClient, proxySearchRequest(t, sharedClientID))
		firstTarget := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
		writeProxyCancelTestRequest(t, secondClient, proxySearchRequest(t, sharedClientID))
		secondTarget := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)

		writeProxyCancelTestRequest(
			t,
			secondClient,
			proxyCancelRequest(t, 102, sharedClientID),
		)
		cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
		rewrittenTarget := assertProxyCancelForwarding(t, secondTarget, cancel)
		if rewrittenTarget == firstTarget.frame.MessageID {
			t.Fatalf(
				"Cancel targeted first client's upstream message ID %d",
				rewrittenTarget,
			)
		}

		completeProxyCancelUpstream(t, secondTarget, cancel)
		assertProxyCancelResponse(
			t,
			secondClient,
			sharedClientID,
			TagSearchResultDone,
			ldapwire.ResultCanceled,
		)
		assertProxyCancelResponse(
			t,
			secondClient,
			102,
			TagExtendedResponse,
			ldapwire.ResultSuccess,
		)
		completeProxyCancelSearch(
			t,
			firstClient,
			firstTarget,
			sharedClientID,
			ldapwire.ResultSuccess,
		)
	})
}

func TestProxyCancelRejectsMalformedRequestValuesWithoutClosingAssociation(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		hasValue bool
	}{
		{name: "missing requestValue"},
		{name: "empty requestValue", value: []byte{}, hasValue: true},
		{name: "empty sequence", value: []byte{0x30, 0x00}, hasValue: true},
		{name: "zero cancelID", value: ldapwire.EncodeCancelRequestValue(0), hasValue: true},
		{
			name:     "trailing BER",
			value:    append(ldapwire.EncodeCancelRequestValue(1), 0x00),
			hasValue: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream, requests := startProxyCancelRecordingUpstream(t)
			proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
			waitForReadyConnections(t, proxy, PoolRegular, 1)

			connection := dialProxyProtocolTestClient(t, address)
			defer connection.Close()
			writeProxyCancelTestRequest(
				t,
				connection,
				proxyCancelRequestValue(t, 111, test.value, test.hasValue),
			)
			assertProxyCancelResponse(
				t,
				connection,
				111,
				TagExtendedResponse,
				ldapwire.ResultProtocolError,
			)

			// RFC 3909 specifies protocolError, not association termination. The
			// Search is also a deterministic ordering barrier proving that the bad
			// Cancel was not forwarded before the next request.
			proxyCancelBarrierSearch(t, connection, requests, 112)
		})
	}
}

func TestProxyCancelDuplicateMessageIDClosesAssociation(t *testing.T) {
	upstream, requests := startProxyCancelRecordingUpstream(t)
	proxy, address := startRuntimeProxy(t, proxyCancelRuntimeConfig(upstream))
	waitForReadyConnections(t, proxy, PoolRegular, 1)

	connection := dialProxyProtocolTestClient(t, address)
	defer connection.Close()
	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, 121))
	target := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
	cancelRequest := proxyCancelRequest(t, 122, 121)
	writeProxyCancelTestRequest(t, connection, cancelRequest)
	cancel := awaitProxyCancelUpstreamRequest(t, requests, TagExtendedRequest)
	assertProxyCancelForwarding(t, target, cancel)

	// OpenLDAP 2.6.13 operation_init treats every duplicate in-flight client
	// MessageID as a fatal association error. Returning a protocolError under the
	// duplicate ID would be ambiguous with the still-pending first Cancel.
	writeProxyCancelTestRequest(t, connection, cancelRequest)
	expectProxyProtocolTestConnectionClosed(t, connection)
	waitForProxyCancelClientRemoval(t, proxy)

	select {
	case event := <-requests:
		if event.err != nil {
			t.Fatalf("decode request after duplicate Cancel: %v", event.err)
		}
		if event.frame.ProtocolTag == TagExtendedRequest {
			t.Fatalf("duplicate Cancel reached upstream: %s", event.frame)
		}
		if event.frame.ProtocolTag != TagAbandonRequest ||
			event.frame.AbandonTarget != target.frame.MessageID {
			t.Fatalf("request after duplicate Cancel = %s", event.frame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("duplicate Cancel disconnect did not abandon the target operation")
	}

	// RFC 3909 says a Cancel operation itself cannot be abandoned. Any already
	// queued follow-up request must therefore neither duplicate nor abandon it.
	select {
	case event := <-requests:
		if event.err != nil {
			t.Fatalf("decode extra request after duplicate Cancel: %v", event.err)
		}
		if event.frame.ProtocolTag == TagExtendedRequest ||
			(event.frame.ProtocolTag == TagAbandonRequest &&
				event.frame.AbandonTarget == cancel.frame.MessageID) {
			t.Fatalf("unexpected request after duplicate Cancel: %s", event.frame)
		}
	case <-time.After(50 * time.Millisecond):
	}
}

type proxyCancelUpstreamEvent struct {
	connection net.Conn
	frame      Frame
	message    ldapwire.Message
	err        error
}

func startProxyCancelRecordingUpstream(
	t *testing.T,
) (*proxyTestUpstream, <-chan proxyCancelUpstreamEvent) {
	t.Helper()
	requests := make(chan proxyCancelUpstreamEvent, 32)
	upstream := startProxyTestUpstream(t, "unused", func(connection net.Conn, frame Frame) bool {
		message, err := ldapwire.ReadMessage(
			bytes.NewReader(frame.Raw),
			int64(len(frame.Raw)),
		)
		requests <- proxyCancelUpstreamEvent{
			connection: connection,
			frame:      frame,
			message:    message,
			err:        err,
		}
		return true
	})
	return upstream, requests
}

func proxyCancelRuntimeConfig(upstream *proxyTestUpstream) RuntimeConfig {
	return RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	}
}

func awaitProxyCancelUpstreamRequest(
	t *testing.T,
	requests <-chan proxyCancelUpstreamEvent,
	wantTag uint64,
) proxyCancelUpstreamEvent {
	t.Helper()
	select {
	case event := <-requests:
		if event.err != nil {
			t.Fatalf("decode upstream request: %v", event.err)
		}
		if event.frame.ProtocolTag != wantTag {
			t.Fatalf(
				"upstream request = %s, want application tag %d",
				event.frame,
				wantTag,
			)
		}
		return event
	case <-time.After(2 * time.Second):
		t.Fatalf("upstream did not receive application tag %d", wantTag)
		return proxyCancelUpstreamEvent{}
	}
}

func proxyCancelRequest(t *testing.T, messageID, targetMessageID int64) []byte {
	t.Helper()
	return proxyCancelRequestValue(
		t,
		messageID,
		ldapwire.EncodeCancelRequestValue(targetMessageID),
		true,
	)
}

func proxyCancelRequestValue(
	t *testing.T,
	messageID int64,
	value []byte,
	hasValue bool,
) []byte {
	t.Helper()
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name:     clientCancelOID,
			Value:    value,
			HasValue: hasValue,
		},
	})
	if err != nil {
		t.Fatalf("encode Cancel request: %v", err)
	}
	return encoded
}

func writeProxyCancelTestRequest(t *testing.T, connection net.Conn, encoded []byte) {
	t.Helper()
	if err := ldapwire.Write(connection, encoded); err != nil {
		t.Fatalf("write LDAP request: %v", err)
	}
}

func assertProxyCancelForwarding(
	t *testing.T,
	target proxyCancelUpstreamEvent,
	cancel proxyCancelUpstreamEvent,
) int64 {
	t.Helper()
	if cancel.connection != target.connection {
		t.Fatal("Cancel was not forwarded on the target operation's upstream connection")
	}
	if cancel.frame.MessageID == target.frame.MessageID {
		t.Fatalf(
			"Cancel reused target upstream message ID %d",
			cancel.frame.MessageID,
		)
	}
	request, ok := cancel.message.Request.(ldapwire.ExtendedRequest)
	if !ok {
		t.Fatalf("upstream Cancel request type = %T", cancel.message.Request)
	}
	if request.Name != clientCancelOID || !request.HasValue {
		t.Fatalf("upstream ExtendedRequest = %#v", request)
	}
	rewrittenTarget, err := ldapwire.DecodeCancelRequestValue(request.Value)
	if err != nil {
		t.Fatalf("decode rewritten cancelRequestValue: %v", err)
	}
	if rewrittenTarget != target.frame.MessageID {
		t.Fatalf(
			"rewritten cancelID = %d, want target upstream message ID %d",
			rewrittenTarget,
			target.frame.MessageID,
		)
	}
	return rewrittenTarget
}

func completeProxyCancelUpstream(
	t *testing.T,
	target proxyCancelUpstreamEvent,
	cancel proxyCancelUpstreamEvent,
) {
	t.Helper()
	if cancel.connection != target.connection {
		t.Fatal("Cancel and target use different upstream connections")
	}
	if err := ldapwire.Write(target.connection, ldapwire.EncodeSearchResultDone(
		target.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultCanceled},
		nil,
	)); err != nil {
		t.Fatalf("write canceled target response: %v", err)
	}
	if err := ldapwire.Write(cancel.connection, ldapwire.EncodeExtendedResponse(
		cancel.frame.MessageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		"",
		nil,
		nil,
	)); err != nil {
		t.Fatalf("write successful Cancel response: %v", err)
	}
}

func completeProxyCancelSearch(
	t *testing.T,
	client net.Conn,
	request proxyCancelUpstreamEvent,
	clientMessageID int64,
	code ldapwire.ResultCode,
) {
	t.Helper()
	if err := ldapwire.Write(request.connection, ldapwire.EncodeSearchResultDone(
		request.frame.MessageID,
		ldapwire.Result{Code: code},
		nil,
	)); err != nil {
		t.Fatalf("write upstream Search response: %v", err)
	}
	assertProxyCancelResponse(
		t,
		client,
		clientMessageID,
		TagSearchResultDone,
		code,
	)
}

func assertProxyCancelResponse(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	tag uint64,
	code ldapwire.ResultCode,
) Frame {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	_ = connection.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatalf("read LDAP response: %v", err)
	}
	if response.MessageID != messageID || response.ProtocolTag != tag ||
		response.ResultCode == nil ||
		ldapwire.ResultCode(*response.ResultCode) != code {
		t.Errorf(
			"LDAP response = %s code=%v, want id=%d tag=%d code=%d",
			response,
			response.ResultCode,
			messageID,
			tag,
			code,
		)
	}
	return response
}

func assertProxyCancelAnyResponse(t *testing.T, connection net.Conn) Frame {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}
	response, err := ReadFrame(connection, DefaultMaxFrameSize)
	_ = connection.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatalf("read LDAP response: %v", err)
	}
	return response
}

func proxyCancelBarrierSearch(
	t *testing.T,
	connection net.Conn,
	requests <-chan proxyCancelUpstreamEvent,
	messageID int64,
) {
	t.Helper()
	writeProxyCancelTestRequest(t, connection, proxySearchRequest(t, messageID))
	barrier := awaitProxyCancelUpstreamRequest(t, requests, TagSearchRequest)
	completeProxyCancelSearch(
		t,
		connection,
		barrier,
		messageID,
		ldapwire.ResultSuccess,
	)
}

func waitForProxyCancelClientRemoval(t *testing.T, proxy *Proxy) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		proxy.mu.Lock()
		clients := len(proxy.clients)
		proxy.mu.Unlock()
		if clients == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("duplicate Cancel client was not removed from the proxy")
}

func assertProxyCancelRuntimePending(t *testing.T, proxy *Proxy, want int) {
	t.Helper()
	snapshot := proxy.scheduler.Snapshot()
	if len(snapshot.Backends) != 1 || snapshot.Backends[0].Pending != want {
		t.Fatalf("backend pending snapshot = %#v, want %d", snapshot.Backends, want)
	}
	for _, connection := range snapshot.Connections {
		if connection.Pool == PoolRegular {
			if connection.Pending != want {
				t.Fatalf("regular connection pending = %d, want %d", connection.Pending, want)
			}
			return
		}
	}
	t.Fatal("regular connection missing from scheduler snapshot")
}

func assertProxyCancelAuthzControl(t *testing.T, message ldapwire.Message, want string) {
	t.Helper()
	if len(message.Controls) == 0 || message.Controls[0].OID != ProxyAuthzControlOID ||
		!message.Controls[0].HasValue || string(message.Controls[0].Value) != want {
		t.Fatalf("ProxyAuthz controls = %#v, want identity %q", message.Controls, want)
	}
}
