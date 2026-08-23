package lloadd

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestMonitorCounterTerminalInvariant(t *testing.T) {
	var counters monitorCounters
	for range 3 {
		counters.begin()
	}
	counters.forwardedOperation()
	counters.complete(true)
	counters.fail()
	counters.reject()

	snapshot := counters.snapshot()
	terminal := snapshot.Completed + snapshot.Failed + snapshot.Rejected + snapshot.Pending
	if snapshot.Received != terminal {
		t.Fatalf("received = %d, terminal + pending = %d: %#v", snapshot.Received, terminal, snapshot)
	}
	if snapshot.Pending != 0 || snapshot.Forwarded != 1 || counters.abandonedCount() != 1 {
		t.Fatalf("terminal counter snapshot = %#v, abandoned=%d", snapshot, counters.abandonedCount())
	}
}

func TestMonitorObservabilitySchemaAndOperationalSelection(t *testing.T) {
	proxy, address := startRuntimeProxy(t, RuntimeConfig{})
	client := dialDaemonTestClient(t, address)
	defer client.Close()

	for name, oid := range map[string]string{
		"olmAbandonedOps": "1.3.6.1.4.1.4203.666.100.14",
		"olmGeneration":   "1.3.6.1.4.1.4203.666.100.15",
		"olmUptime":       "1.3.6.1.4.1.4203.666.100.16",
	} {
		attribute, ok := proxy.monitorSchema.AttributeType(name)
		if !ok || attribute.OID != oid || !attribute.NoUserModification {
			t.Fatalf("monitor attribute %s = %#v, present=%t", name, attribute, ok)
		}
	}
	for objectClass, attributes := range map[string][]string{
		"olmBalancer":           {"olmGeneration", "olmUptime"},
		"olmBalancerServer":     {"olmAbandonedOps"},
		"olmBalancerOperation":  {"olmPendingOps", "olmAbandonedOps"},
		"olmBalancerConnection": {"olmAbandonedOps"},
	} {
		for _, attribute := range attributes {
			allowed, known := proxy.monitorSchema.ObjectClassAllowsAttribute(
				objectClass,
				attribute,
			)
			if !known || !allowed {
				t.Fatalf("monitor objectClass %s does not allow %s", objectClass, attribute)
			}
		}
	}

	ordinary, err := client.Search(ldap.NewSearchRequest(
		MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancer)",
		[]string{"*"},
		nil,
	))
	if err != nil || len(ordinary.Entries) != 1 {
		t.Fatalf("ordinary monitor selection = %#v, %v", ordinary, err)
	}
	if ordinary.Entries[0].GetAttributeValue("olmGeneration") != "" {
		t.Fatal("ordinary attribute selection exposed operational telemetry")
	}

	operational, err := client.Search(ldap.NewSearchRequest(
		MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancer)",
		[]string{"+"},
		nil,
	))
	if err != nil || len(operational.Entries) != 1 {
		t.Fatalf("operational monitor selection = %#v, %v", operational, err)
	}
	generation, err := strconv.ParseUint(
		operational.Entries[0].GetAttributeValue("olmGeneration"),
		10,
		64,
	)
	if err != nil || generation == 0 || generation != proxy.MonitorSnapshot().Generation {
		t.Fatalf("monitor generation = %d, %v", generation, err)
	}
	if _, err := strconv.ParseUint(operational.Entries[0].GetAttributeValue("olmUptime"), 10, 64); err != nil {
		t.Fatalf("monitor uptime is not an integer: %v", err)
	}
	if proxy.MonitorSnapshot().StartedAt.IsZero() || proxy.MonitorSnapshot().Uptime < 0 {
		t.Fatalf("monitor runtime snapshot = %#v", proxy.MonitorSnapshot())
	}

	operationResult, err := client.Search(ldap.NewSearchRequest(
		"cn=Other,"+monitorOperationsDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"+"},
		nil,
	))
	if err != nil || len(operationResult.Entries) != 1 {
		t.Fatalf("operation telemetry selection = %#v, %v", operationResult, err)
	}
	entry := operationResult.Entries[0]
	received := monitorTestUint(t, entry, "olmReceivedOps")
	terminal := monitorTestUint(t, entry, "olmCompletedOps") +
		monitorTestUint(t, entry, "olmFailedOps") +
		monitorTestUint(t, entry, "olmRejectedOps") +
		monitorTestUint(t, entry, "olmPendingOps")
	if received != terminal {
		t.Fatalf("wire terminal invariant: received=%d terminal+pending=%d", received, terminal)
	}
}

func TestMonitorRuntimeGenerationIsStableAndDistinct(t *testing.T) {
	first, err := NewProxy(RuntimeConfig{})
	if err != nil {
		t.Fatalf("first NewProxy: %v", err)
	}
	time.Sleep(time.Millisecond)
	second, err := NewProxy(RuntimeConfig{})
	if err != nil {
		t.Fatalf("second NewProxy: %v", err)
	}
	firstSnapshot := first.MonitorSnapshot()
	if firstSnapshot.Generation == 0 || second.MonitorSnapshot().Generation <= firstSnapshot.Generation {
		t.Fatalf("monitor generations: first=%d second=%d", firstSnapshot.Generation, second.MonitorSnapshot().Generation)
	}
	if got := first.MonitorSnapshot().Generation; got != firstSnapshot.Generation {
		t.Fatalf("first monitor generation changed from %d to %d", firstSnapshot.Generation, got)
	}
	first.monitorSchema = nil
	if got := first.MonitorSnapshot().Generation; got != firstSnapshot.Generation {
		t.Fatalf("monitor generation depends on schema registry lifetime: got %d, want %d", got, firstSnapshot.Generation)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first proxy: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second proxy: %v", err)
	}
}

func TestMonitorLocallyRejectedBindsReachTerminalState(t *testing.T) {
	tests := []struct {
		name    string
		config  RuntimeConfig
		request ldapwire.BindRequest
		code    ldapwire.ResultCode
	}{
		{
			name: "LDAP version 2",
			request: ldapwire.BindRequest{
				Version: 2,
				Authentication: ldapwire.Authentication{
					Simple: []byte("secret"),
				},
			},
			code: ldapwire.ResultProtocolError,
		},
		{
			name:   "Verify Credentials SASL",
			config: RuntimeConfig{ProxyAuthz: true, VerifyCredentials: true},
			request: ldapwire.BindRequest{
				Version: 3,
				Authentication: ldapwire.Authentication{
					IsSASL:             true,
					SASLMechanism:      "PLAIN",
					HasSASLCredentials: true,
					SASLCredentials:    []byte("credentials"),
				},
			},
			code: ldapwire.ResultAuthMethodNotSupported,
		},
		{
			name: "SASL EXTERNAL",
			request: ldapwire.BindRequest{
				Version: 3,
				Authentication: ldapwire.Authentication{
					IsSASL:        true,
					SASLMechanism: "EXTERNAL",
				},
			},
			code: ldapwire.ResultAuthMethodNotSupported,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy, address := startRuntimeProxy(t, test.config)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer connection.Close()
			request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
				ID:      1,
				Request: test.request,
			})
			if err != nil {
				t.Fatalf("encode Bind: %v", err)
			}
			if err := ldapwire.Write(connection, request); err != nil {
				t.Fatalf("write Bind: %v", err)
			}
			response, err := ReadFrame(connection, DefaultMaxFrameSize)
			if err != nil {
				t.Fatalf("read Bind response: %v", err)
			}
			if response.ResultCode == nil ||
				*response.ResultCode != ResultCode(test.code) {
				t.Fatalf("Bind response = %s, want LDAP result %d", response, test.code)
			}

			snapshot := proxy.MonitorSnapshot()
			var bind ProxyMonitorOperation
			for _, operation := range snapshot.Operations {
				if operation.Name == "Bind" {
					bind = operation
				}
			}
			if bind.Counters.Received != 1 || bind.Counters.Rejected != 1 ||
				bind.Counters.Pending != 0 || bind.Counters.Completed != 0 ||
				bind.Counters.Failed != 0 {
				t.Fatalf("global Bind counters = %#v", bind.Counters)
			}
			if len(snapshot.Incoming) != 1 ||
				snapshot.Incoming[0].Counters.Received != 1 ||
				snapshot.Incoming[0].Counters.Failed != 1 ||
				snapshot.Incoming[0].Counters.Pending != 0 {
				t.Fatalf("incoming Bind counters = %#v", snapshot.Incoming)
			}
		})
	}
}

func TestMonitorAbandonedOperationWireCounting(t *testing.T) {
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
	proxy, address := startRuntimeProxy(t, monitorTestRuntime(upstream.listener.Addr().String()))
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer connection.Close()
	if err := ldapwire.Write(connection, proxySearchRequest(t, 501)); err != nil {
		t.Fatalf("write Search: %v", err)
	}
	var upstreamSearch Frame
	select {
	case upstreamSearch = <-searches:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive Search")
	}
	if err := ldapwire.Write(connection, encodeFrame(
		502,
		encodeTLV(0x50, encodeNonnegativeInteger(501)),
		nil,
	)); err != nil {
		t.Fatalf("write Abandon: %v", err)
	}
	select {
	case abandon := <-abandons:
		if abandon.AbandonTarget != upstreamSearch.MessageID {
			t.Fatalf("upstream Abandon target = %d, want %d", abandon.AbandonTarget, upstreamSearch.MessageID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive Abandon")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot := proxy.MonitorSnapshot()
		if len(snapshot.Backends) == 1 && snapshot.Backends[0].Abandoned == 1 {
			var other ProxyMonitorOperation
			for _, operation := range snapshot.Operations {
				if operation.Name == "Other" {
					other = operation
				}
			}
			if other.Abandoned == 1 && other.Counters.Pending == 0 &&
				other.Counters.Received == other.Counters.Completed+other.Counters.Failed+other.Counters.Rejected {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("abandoned monitor snapshot = %#v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}

	monitorClient := dialDaemonTestClient(t, address)
	defer monitorClient.Close()
	result, err := monitorClient.Search(ldap.NewSearchRequest(
		"cn=Other,"+monitorOperationsDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"olmAbandonedOps"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("olmAbandonedOps") != "1" {
		t.Fatalf("wire abandoned telemetry = %#v, %v", result, err)
	}
}

func TestOpenLDAPReferenceLloaddMonitorObservabilityContract(t *testing.T) {
	root := requirePinnedOpenLDAPLloaddSource(t)
	contents, err := os.ReadFile(filepath.Join(root, "servers", "lloadd", "monitor.c"))
	if err != nil {
		t.Fatalf("read pinned lloadd monitor.c: %v", err)
	}
	source := string(contents)
	for _, anchor := range []string{
		"pending = (ldap_pvt_mp_t)c->c_n_ops_executing;",
		"received = c->c_counters.lc_ops_received;",
		"completed = c->c_counters.lc_ops_completed;",
		"failed = c->c_counters.lc_ops_failed;",
		"NAME ( 'olmConnectionState' )",
		"NAME ( 'olmBalancerConnection' )",
	} {
		if !strings.Contains(source, anchor) {
			t.Fatalf("pinned lloadd monitor.c lacks %q", anchor)
		}
	}
}

func monitorTestUint(t *testing.T, entry *ldap.Entry, attribute string) uint64 {
	t.Helper()
	value, err := strconv.ParseUint(entry.GetAttributeValue(attribute), 10, 64)
	if err != nil {
		t.Fatalf("%s = %q: %v", attribute, entry.GetAttributeValue(attribute), err)
	}
	return value
}
