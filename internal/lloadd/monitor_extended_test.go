package lloadd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLloaddMonitorAssertionControl(t *testing.T) {
	upstream := startProxyTestUpstream(t, "assertion", nil)
	_, address := startRuntimeProxy(t, monitorTestRuntime(upstream.listener.Addr().String()))
	client := dialDaemonTestClient(t, address)
	defer client.Close()

	matching := monitorAssertionControl(t, "(objectClass=olmBalancer)")
	result, err := client.Search(ldap.NewSearchRequest(
		MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		[]ldap.Control{matching},
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("matching monitor assertion = %#v, %v", result, err)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		[]ldap.Control{monitorAssertionControl(t, "(cn=not-the-balancer)")},
	))
	assertMonitorLDAPResult(t, err, ldap.LDAPResultAssertionFailed)
}

func TestLloaddMonitorServerSideSortAndVLV(t *testing.T) {
	upstream := startProxyTestUpstream(t, "sort-vlv", nil)
	_, address := startRuntimeProxy(t, monitorTestRuntime(upstream.listener.Addr().String()))
	client := dialDaemonTestClient(t, address)
	defer client.Close()

	reverseSort := ldap.NewControlServerSideSortingWithSortKeys([]*ldap.SortKey{{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
		Reverse:       true,
	}})
	result, err := client.Search(ldap.NewSearchRequest(
		monitorOperationsDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"cn"},
		[]ldap.Control{reverseSort},
	))
	if err != nil {
		t.Fatalf("sorted monitor Search: %v", err)
	}
	if got := monitorEntryCNs(result); !equalStrings(got, []string{"Other", "Bind"}) {
		t.Fatalf("reverse sorted monitor cn = %q", got)
	}
	sortResult, ok := ldap.FindControl(
		result.Controls,
		monitorSortResponseOID,
	).(*ldap.ControlServerSideSortingResult)
	if !ok || sortResult.Result != ldap.ControlServerSideSortingCodeSuccess {
		t.Fatalf("monitor sort response = %#v", result.Controls)
	}

	ascendingSort := ldap.NewControlServerSideSortingWithSortKeys([]*ldap.SortKey{{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	}})
	vlv := monitorVLVControl(ldapwire.VirtualListViewRequest{
		BeforeCount:  0,
		AfterCount:   0,
		ByOffset:     true,
		Offset:       2,
		ContentCount: 2,
	})
	result, err = client.Search(ldap.NewSearchRequest(
		monitorOperationsDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"cn"},
		[]ldap.Control{ascendingSort, vlv},
	))
	if err != nil {
		t.Fatalf("monitor VLV Search: %v", err)
	}
	if got := monitorEntryCNs(result); !equalStrings(got, []string{"Other"}) {
		t.Fatalf("monitor VLV window cn = %q", got)
	}
	response := decodeMonitorVLVResponse(t, result.Controls)
	if response.TargetPosition != 2 || response.ContentCount != 2 ||
		response.Result != ldapwire.ResultSuccess ||
		!response.HasContextID || len(response.ContextID) != monitorSnapshotIDLength {
		t.Fatalf("monitor VLV response = %#v", response)
	}
	result, err = client.Search(ldap.NewSearchRequest(
		monitorOperationsDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"cn"},
		[]ldap.Control{ascendingSort, monitorVLVControl(ldapwire.VirtualListViewRequest{
			BeforeCount:  0,
			AfterCount:   0,
			ByOffset:     true,
			Offset:       1,
			ContentCount: 2,
			ContextID:    response.ContextID,
			HasContextID: true,
		})},
	))
	if err != nil || !equalStrings(monitorEntryCNs(result), []string{"Bind"}) {
		t.Fatalf("continued monitor VLV = %#v, %v", result, err)
	}
	continued := decodeMonitorVLVResponse(t, result.Controls)
	if continued.TargetPosition != 1 ||
		!bytes.Equal(continued.ContextID, response.ContextID) {
		t.Fatalf("continued monitor VLV response = %#v", continued)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		monitorOperationsDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		[]ldap.Control{monitorVLVControl(ldapwire.VirtualListViewRequest{
			ByOffset: true,
			Offset:   1,
		})},
	))
	assertMonitorLDAPResult(t, err, uint16(ldapwire.ResultVirtualListViewError))
}

func TestLloaddMonitorOpenLDAPACL(t *testing.T) {
	upstream := startProxyTestUpstream(t, "acl", nil)
	config := monitorTestRuntime(upstream.listener.Addr().String())
	config.MonitorAccess = []string{
		`{0}to dn.subtree="` + monitorIncomingDN + `" by * none`,
		`{1}to attrs=olmServerURI by * none`,
		`{2}to * by * read`,
	}
	_, address := startRuntimeProxy(t, config)
	client := dialDaemonTestClient(t, address)
	defer client.Close()

	result, err := client.Search(ldap.NewSearchRequest(
		monitorBackendTiersDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "olmServerURI"},
		nil,
	))
	if err != nil {
		t.Fatalf("ACL-filtered monitor Search: %v", err)
	}
	for _, entry := range result.Entries {
		if values := entry.GetAttributeValues("olmServerURI"); len(values) != 0 {
			t.Fatalf("ACL exposed olmServerURI on %s: %q", entry.DN, values)
		}
	}
	filtered, err := client.Search(ldap.NewSearchRequest(
		monitorBackendTiersDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(olmServerURI=*)",
		[]string{"cn"},
		nil,
	))
	if err != nil || len(filtered.Entries) != 0 {
		t.Fatalf("ACL-protected monitor filter = %#v, %v", filtered, err)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		monitorIncomingDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	assertMonitorLDAPResult(t, err, ldap.LDAPResultNoSuchObject)

	parsed, err := Parse(strings.NewReader(
		"access to attrs=olmServerURI by * none\n" +
			"access to * by * read\n",
	))
	if err != nil || len(parsed.Access) != 2 {
		t.Fatalf("parse lloadd access directives = %#v, %v", parsed.Access, err)
	}
	if _, err := NewProxy(RuntimeConfig{MonitorAccess: []string{"invalid"}}); err == nil {
		t.Fatal("NewProxy accepted an invalid monitor ACL")
	}
}

func TestLloaddMonitorStablePagingAndSnapshotCleanup(t *testing.T) {
	upstream := startProxyTestUpstream(t, "paging", nil)
	proxy, address := startRuntimeProxy(t, monitorTestRuntime(upstream.listener.Addr().String()))
	client := dialDaemonTestClient(t, address)

	paging := ldap.NewControlPaging(1)
	result, err := client.Search(monitorPagedConnectionSearch(paging))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("first monitor page = %#v, %v", result, err)
	}
	response := monitorPagingResponse(t, result)
	if len(response.Cookie) != monitorPagingCookieLength || response.PagingSize < 2 {
		t.Fatalf("first monitor paging response = %#v", response)
	}
	wantTotal := int(response.PagingSize)
	if got := monitorSnapshotCount(proxy); got != 1 {
		t.Fatalf("active monitor snapshots after first page = %d", got)
	}

	newClient := dialDaemonTestClient(t, address)
	defer newClient.Close()
	seen := len(result.Entries)
	for len(response.Cookie) != 0 {
		paging.SetCookie(response.Cookie)
		result, err = client.Search(monitorPagedConnectionSearch(paging))
		if err != nil {
			t.Fatalf("continue monitor paging: %v", err)
		}
		seen += len(result.Entries)
		response = monitorPagingResponse(t, result)
	}
	if seen != wantTotal {
		t.Fatalf("stable monitor snapshot returned %d entries, want %d", seen, wantTotal)
	}
	if got := monitorSnapshotCount(proxy); got != 0 {
		t.Fatalf("active monitor snapshots after final page = %d", got)
	}

	paging = ldap.NewControlPaging(1)
	result, err = client.Search(monitorPagedConnectionSearch(paging))
	if err != nil || len(monitorPagingResponse(t, result).Cookie) == 0 {
		t.Fatalf("monitor page before Bind cleanup = %#v, %v", result, err)
	}
	if got := monitorSnapshotCount(proxy); got != 1 {
		t.Fatalf("active monitor snapshots before Bind = %d", got)
	}
	if err := client.Bind("cn=monitor-test", "secret"); err != nil {
		t.Fatalf("Bind for monitor cleanup: %v", err)
	}
	if got := monitorSnapshotCount(proxy); got != 0 {
		t.Fatalf("active monitor snapshots after Bind = %d", got)
	}

	paging = ldap.NewControlPaging(1)
	result, err = client.Search(monitorPagedConnectionSearch(paging))
	if err != nil || len(monitorPagingResponse(t, result).Cookie) == 0 {
		t.Fatalf("monitor page before close cleanup = %#v, %v", result, err)
	}
	owners := monitorSnapshotOwners(proxy)
	if len(owners) != 1 {
		t.Fatalf("monitor snapshot owners before close = %d", len(owners))
	}
	_ = client.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		owners[0].mu.Lock()
		closed := owners[0].closed
		remaining := len(owners[0].monitorSnapshots)
		owners[0].mu.Unlock()
		if closed && remaining == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("monitor snapshots were not cleared when the connection closed")
}

func monitorTestRuntime(upstream string) RuntimeConfig {
	return RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{proxyTestBackend(upstream)},
		}},
	}
}

func monitorAssertionControl(t *testing.T, filter string) ldap.Control {
	t.Helper()
	packet, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", filter, err)
	}
	return ldap.NewControlString(monitorAssertionOID, true, string(packet.Bytes()))
}

func monitorVLVControl(request ldapwire.VirtualListViewRequest) ldap.Control {
	return ldap.NewControlString(
		monitorVLVRequestOID,
		true,
		string(ldapwire.EncodeVirtualListViewRequestValue(request)),
	)
}

func decodeMonitorVLVResponse(
	t *testing.T,
	controls []ldap.Control,
) ldapwire.VirtualListViewResponse {
	t.Helper()
	control, ok := ldap.FindControl(controls, monitorVLVResponseOID).(*ldap.ControlString)
	if !ok {
		t.Fatalf("monitor VLV response control = %#v", controls)
	}
	response, err := ldapwire.DecodeVirtualListViewResponseValue(
		[]byte(control.ControlValue),
	)
	if err != nil {
		t.Fatalf("decode monitor VLV response: %v", err)
	}
	return response
}

func monitorEntryCNs(result *ldap.SearchResult) []string {
	values := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		values = append(values, entry.GetAttributeValue("cn"))
	}
	return values
}

func equalStrings(left, right []string) bool {
	return len(left) == len(right) && bytes.Equal(
		[]byte(strings.Join(left, "\x00")),
		[]byte(strings.Join(right, "\x00")),
	)
}

func assertMonitorLDAPResult(t *testing.T, err error, code uint16) {
	t.Helper()
	ldapErr, ok := err.(*ldap.Error)
	if !ok || ldapErr.ResultCode != code {
		t.Fatalf("LDAP result = %v, want %d", err, code)
	}
}

func monitorPagedConnectionSearch(paging ldap.Control) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		monitorIncomingDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		[]ldap.Control{paging},
	)
}

func monitorPagingResponse(
	t *testing.T,
	result *ldap.SearchResult,
) *ldap.ControlPaging {
	t.Helper()
	control, ok := ldap.FindControl(
		result.Controls,
		ldap.ControlTypePaging,
	).(*ldap.ControlPaging)
	if !ok {
		t.Fatalf("monitor paging response = %#v", result.Controls)
	}
	return control
}

func monitorSnapshotCount(proxy *Proxy) int {
	return len(monitorSnapshotOwners(proxy))
}

func monitorSnapshotOwners(proxy *Proxy) []*clientConnection {
	proxy.mu.Lock()
	clients := make([]*clientConnection, 0, len(proxy.clients))
	for client := range proxy.clients {
		clients = append(clients, client)
	}
	proxy.mu.Unlock()
	owners := make([]*clientConnection, 0, len(clients))
	for _, client := range clients {
		client.mu.Lock()
		count := len(client.monitorSnapshots)
		client.mu.Unlock()
		if count != 0 {
			owners = append(owners, client)
		}
	}
	return owners
}
