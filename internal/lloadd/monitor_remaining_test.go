package lloadd

import (
	"bytes"
	"net"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestMonitorLocalOperationTerminalCounters(t *testing.T) {
	t.Run("unbind", func(t *testing.T) {
		proxy, address := startRuntimeProxy(t, RuntimeConfig{})
		connection := dialProxyProtocolTestClient(t, address)
		waitForProxyClientCount(t, proxy, 1)
		if err := ldapwire.Write(connection, encodeFrame(
			1,
			encodeTLV(0x42, nil),
			nil,
		)); err != nil {
			t.Fatalf("write Unbind: %v", err)
		}
		waitForProxyClientCount(t, proxy, 0)
		assertMonitorOperationCounters(t, proxy, "Other", ProxyMonitorCounters{
			Received:  1,
			Completed: 1,
		})
	})

	t.Run("abandon unknown operation", func(t *testing.T) {
		proxy, address := startRuntimeProxy(t, RuntimeConfig{})
		connection := dialProxyProtocolTestClient(t, address)
		defer connection.Close()
		if err := ldapwire.Write(connection, encodeFrame(
			2,
			encodeTLV(0x50, encodeNonnegativeInteger(999)),
			nil,
		)); err != nil {
			t.Fatalf("write Abandon: %v", err)
		}
		waitForMonitorOperationCounters(t, proxy, "Other", ProxyMonitorCounters{
			Received:  1,
			Completed: 1,
		})
	})

	t.Run("StartTLS unavailable", func(t *testing.T) {
		proxy, address := startRuntimeProxy(t, RuntimeConfig{})
		connection := dialClientStartTLSTest(t, address)
		writeClientStartTLSRequest(t, connection, 3, false)
		assertClientStartTLSResult(t, connection, 3, ldapwire.ResultUnavailable)
		waitForMonitorOperationCounters(t, proxy, "Other", ProxyMonitorCounters{
			Received: 1,
			Rejected: 1,
		})
	})

	t.Run("StartTLS success", func(t *testing.T) {
		serverTLS, clientTLS := clientStartTLSTestConfigs(t)
		proxy, address := startRuntimeProxy(t, RuntimeConfig{ClientTLS: serverTLS})
		secured := dialAndStartClientTLS(t, address, clientTLS, 4)
		defer secured.Close()
		waitForMonitorOperationCounters(t, proxy, "Other", ProxyMonitorCounters{
			Received:  1,
			Completed: 1,
		})
	})

	t.Run("StartTLS handshake failure", func(t *testing.T) {
		serverTLS, _ := clientStartTLSTestConfigs(t)
		proxy, address := startRuntimeProxy(t, RuntimeConfig{
			ClientTLS: serverTLS,
			IOTimeout: 250 * time.Millisecond,
		})
		connection := dialClientStartTLSTest(t, address)
		writeClientStartTLSRequest(t, connection, 5, false)
		assertClientStartTLSResult(t, connection, 5, ldapwire.ResultSuccess)
		if _, err := connection.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x00}); err != nil {
			t.Fatalf("write malformed TLS record: %v", err)
		}
		waitForProxyClientCount(t, proxy, 0)
		assertMonitorOperationCounters(t, proxy, "Other", ProxyMonitorCounters{
			Received: 1,
			Failed:   1,
		})
	})
}

func TestMonitorNoncriticalSortFailureAndVLVControls(t *testing.T) {
	upstream := startProxyTestUpstream(t, "sort-errors", nil)
	_, address := startRuntimeProxy(t, monitorTestRuntime(upstream.listener.Addr().String()))
	client := dialDaemonTestClient(t, address)
	defer client.Close()

	noncriticalSort := ldap.NewControlServerSideSortingWithSortKeys([]*ldap.SortKey{{
		AttributeType: "cn",
		MatchingRule:  "1.2.3",
	}})
	keys, decodeErr := ldapwire.DecodeSortRequestValue(
		testControlValue(t, noncriticalSort.Encode().Bytes()),
	)
	if decodeErr != nil || len(keys) != 1 || keys[0].OrderingRule != "1.2.3" {
		t.Fatalf("decode noncritical sort fixture = %#v, %v", keys, decodeErr)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		monitorOperationsDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"cn"},
		[]ldap.Control{noncriticalSort},
	))
	if err != nil {
		t.Fatalf("noncritical failed sort: %v", err)
	}
	if got := monitorEntryCNs(result); !equalStrings(got, []string{"Bind", "Other"}) {
		t.Fatalf("noncritical failed sort entries = %q", got)
	}
	if ldap.FindControl(result.Controls, monitorSortResponseOID) == nil {
		t.Fatalf("noncritical failed sort omitted response control: %#v", result.Controls)
	}
	if code := rawMonitorSortResult(t, address, keys); code != ldapwire.ResultInappropriateMatching {
		t.Fatalf("noncritical failed sort wire response = %d", code)
	}

	noncriticalVLV := ldap.NewControlString(
		monitorVLVRequestOID,
		false,
		string(ldapwire.EncodeVirtualListViewRequestValue(
			ldapwire.VirtualListViewRequest{ByOffset: true, Offset: 1},
		)),
	)
	_, err = client.Search(ldap.NewSearchRequest(
		monitorOperationsDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"cn"},
		[]ldap.Control{noncriticalVLV},
	))
	assertMonitorLDAPResult(t, err, uint16(ldapwire.ResultVirtualListViewError))
	response, resultCode := rawMonitorVLVError(t, address)
	if resultCode != ldapwire.ResultVirtualListViewError {
		t.Fatalf("noncritical VLV wire result = %d", resultCode)
	}
	if response.Result != monitorVLVSortControlMissing {
		t.Fatalf("noncritical VLV response = %#v", response)
	}
}

func rawMonitorSortResult(
	t *testing.T,
	address string,
	keys []ldapwire.SortKey,
) ldapwire.ResultCode {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial raw monitor client: %v", err)
	}
	defer connection.Close()
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 77,
		Request: ldapwire.SearchRequest{
			BaseDN:       monitorOperationsDN,
			Scope:        directory.ScopeSingleLevel,
			DerefAliases: ldapwire.NeverDerefAliases,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{"cn"},
		},
		Controls: []ldapwire.Control{{
			OID:      monitorSortRequestOID,
			Value:    ldapwire.EncodeSortRequestValue(keys),
			HasValue: true,
		}},
	})
	if err != nil {
		t.Fatalf("encode raw monitor sort Search: %v", err)
	}
	if err := ldapwire.Write(connection, request); err != nil {
		t.Fatalf("write raw monitor sort Search: %v", err)
	}
	for {
		frame, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read raw monitor sort response: %v", err)
		}
		if frame.ProtocolTag != TagSearchResultDone {
			continue
		}
		if frame.ResultCode == nil || *frame.ResultCode != ResultSuccess {
			t.Fatalf("raw monitor sort Search result = %s", frame)
		}
		for _, control := range frame.Controls {
			if control.OID != monitorSortResponseOID {
				continue
			}
			code, _, err := ldapwire.DecodeSortResultValue(testControlValue(t, control.Raw))
			if err != nil {
				t.Fatalf("decode raw monitor sort response: %v", err)
			}
			return code
		}
		t.Fatal("raw monitor sort Search omitted response control")
	}
}

func rawMonitorVLVError(
	t *testing.T,
	address string,
) (ldapwire.VirtualListViewResponse, ldapwire.ResultCode) {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial raw monitor VLV client: %v", err)
	}
	defer connection.Close()
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 78,
		Request: ldapwire.SearchRequest{
			BaseDN:       monitorOperationsDN,
			Scope:        directory.ScopeSingleLevel,
			DerefAliases: ldapwire.NeverDerefAliases,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{"cn"},
		},
		Controls: []ldapwire.Control{{
			OID: monitorVLVRequestOID,
			Value: ldapwire.EncodeVirtualListViewRequestValue(
				ldapwire.VirtualListViewRequest{ByOffset: true, Offset: 1},
			),
			HasValue: true,
		}},
	})
	if err != nil {
		t.Fatalf("encode raw monitor VLV Search: %v", err)
	}
	if err := ldapwire.Write(connection, request); err != nil {
		t.Fatalf("write raw monitor VLV Search: %v", err)
	}
	for {
		frame, err := ReadFrame(connection, DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("read raw monitor VLV response: %v", err)
		}
		if frame.ProtocolTag != TagSearchResultDone {
			continue
		}
		if frame.ResultCode == nil {
			t.Fatalf("raw monitor VLV Search omitted LDAP result: %s", frame)
		}
		for _, control := range frame.Controls {
			if control.OID != monitorVLVResponseOID {
				continue
			}
			response, err := ldapwire.DecodeVirtualListViewResponseValue(
				testControlValue(t, control.Raw),
			)
			if err != nil {
				t.Fatalf("decode raw monitor VLV response: %v", err)
			}
			return response, ldapwire.ResultCode(*frame.ResultCode)
		}
		t.Fatal("raw monitor VLV Search omitted response control")
	}
}

func TestMonitorSnapshotConnectionAndExpirySemantics(t *testing.T) {
	proxy := monitorHardeningProxy(t)
	firstServer, firstPeer := net.Pipe()
	defer firstPeer.Close()
	first := monitorHardeningClient(proxy, firstServer)
	proxy.clients[first] = struct{}{}
	defer first.close()

	secondServer, secondPeer := net.Pipe()
	defer secondPeer.Close()
	second := monitorHardeningClient(proxy, secondServer)
	proxy.clients[second] = struct{}{}
	defer second.close()

	fingerprint := monitorSearchFingerprint(
		first.monitorACLSubject(),
		ldapwire.SearchRequest{
			BaseDN: MonitorBaseDN,
			Scope:  directory.ScopeWholeSubtree,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
		},
		nil,
	)
	snapshot := &monitorSnapshot{
		fingerprint: fingerprint,
		entries:     []directory.Entry{{DN: MonitorBaseDN}},
	}
	if result := first.storeMonitorSnapshot(snapshot); result != nil {
		t.Fatalf("store monitor snapshot: %#v", result)
	}
	if got, result := first.lookupMonitorSnapshot(snapshot.id, fingerprint); result != nil || got != snapshot {
		t.Fatalf("same-connection lookup = %#v, %#v", got, result)
	}
	if got, result := second.lookupMonitorSnapshot(snapshot.id, fingerprint); got != nil ||
		result == nil || result.Code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf("cross-connection lookup = %#v, %#v", got, result)
	}

	first.mu.Lock()
	snapshot.expires = time.Now().Add(-time.Nanosecond)
	first.mu.Unlock()
	if got, result := first.lookupMonitorSnapshot(snapshot.id, fingerprint); got != nil ||
		result == nil || result.Code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf("expired snapshot lookup = %#v, %#v", got, result)
	}
	if first.monitorSnapshotBytes != 0 || proxy.monitorSnapshotBytes.Load() != 0 {
		t.Fatalf(
			"expired snapshot retained bytes: connection=%d proxy=%d",
			first.monitorSnapshotBytes,
			proxy.monitorSnapshotBytes.Load(),
		)
	}
}

func TestMonitorACLGSSAPIAndServiceSASLSubjects(t *testing.T) {
	proxy := monitorHardeningProxy(t)
	proxy.config.Bind = RuntimeBindConfig{
		Method:             "sasl",
		SASLMechanism:      "SCRAM-SHA-256",
		AuthenticationID:   "lloadd-service",
		AuthorizationID:    "u:lloadd-service",
		Credentials:        []byte("hidden"),
		SecurityProperties: "none",
	}
	client := &clientConnection{
		proxy:    proxy,
		authcID:  []byte("u:alice@EXAMPLE.COM"),
		authzID:  []byte("u:directory-admin"),
		saslMech: "GSSAPI",
		saslSSF:  256,
	}
	subject := client.monitorACLSubject()
	if subject.DN != "uid=directory-admin,cn=gssapi,cn=auth" ||
		subject.RealDN != "uid=alice@EXAMPLE.COM,cn=gssapi,cn=auth" ||
		subject.SASLSSF != 256 {
		t.Fatalf("GSSAPI monitor ACL subject = %#v", subject)
	}

	client.authcID = nil
	client.authzID = nil
	client.saslMech = ""
	subject = client.monitorACLSubject()
	if subject.DN != "" || subject.RealDN != "" {
		t.Fatalf("service SASL identity leaked into anonymous client subject: %#v", subject)
	}
	if bytes.Contains([]byte(subject.DN+subject.RealDN), []byte("lloadd-service")) {
		t.Fatalf("service SASL identity leaked into monitor ACL subject: %#v", subject)
	}
}

func waitForMonitorOperationCounters(
	t *testing.T,
	proxy *Proxy,
	name string,
	want ProxyMonitorCounters,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := monitorOperationCounters(proxy, name); ok && got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	assertMonitorOperationCounters(t, proxy, name, want)
}

func assertMonitorOperationCounters(
	t *testing.T,
	proxy *Proxy,
	name string,
	want ProxyMonitorCounters,
) {
	t.Helper()
	got, ok := monitorOperationCounters(proxy, name)
	if !ok || got != want {
		t.Fatalf("monitor %s counters = %#v, want %#v", name, got, want)
	}
}

func monitorOperationCounters(proxy *Proxy, name string) (ProxyMonitorCounters, bool) {
	for _, operation := range proxy.MonitorSnapshot().Operations {
		if operation.Name == name {
			return operation.Counters, true
		}
	}
	return ProxyMonitorCounters{}, false
}
