package lloadd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestDaemonReloadDrainsExistingConnectionsAndRollsBack(t *testing.T) {
	oldUpstream := startProxyTestUpstream(t, "old", nil)
	newUpstream := startProxyTestUpstream(t, "new", nil)

	var topologyMu sync.Mutex
	topology := daemonTestTopology(oldUpstream.listener.Addr().String(), []string{"127.0.0.1:0"})
	var loadErr error
	daemon, err := NewDaemon(DaemonOptions{
		Load: func(context.Context) (DaemonTopology, error) {
			topologyMu.Lock()
			defer topologyMu.Unlock()
			if loadErr != nil {
				return DaemonTopology{}, loadErr
			}
			return topology, nil
		},
		ListenerKey: func(raw string) (string, error) { return raw, nil },
		Listen: func(raw string) (net.Listener, string, error) {
			listener, err := net.Listen("tcp", raw)
			if err != nil {
				return nil, "", err
			}
			return listener, listener.Addr().String(), nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	t.Cleanup(func() { _ = daemon.Close() })
	address := result.Listeners[0]
	waitForDaemonOutgoing(t, daemon, 1)

	oldClient := dialDaemonTestClient(t, address)
	defer oldClient.Close()
	if marker := proxySearchMarker(t, oldClient); marker != "old" {
		t.Fatalf("old client marker = %q", marker)
	}

	topologyMu.Lock()
	topology = daemonTestTopology(newUpstream.listener.Addr().String(), []string{"127.0.0.1:0"})
	topologyMu.Unlock()
	result, err = daemon.Reload(ctx)
	if err != nil {
		t.Fatalf("Daemon.Reload(): %v", err)
	}
	if result.Generation != 2 || result.Listeners[0] != address {
		t.Fatalf("reload result = %#v, original listener %q", result, address)
	}
	waitForDaemonOutgoing(t, daemon, 1)

	if _, err := proxySearchMarkerResult(oldClient); err == nil {
		t.Fatal("retired generation client remained usable after reload")
	}
	newClient := dialDaemonTestClient(t, address)
	if marker := proxySearchMarker(t, newClient); marker != "new" {
		t.Fatalf("new client marker = %q, want new", marker)
	}
	_ = newClient.Close()

	topologyMu.Lock()
	loadErr = errors.New("invalid replacement")
	topologyMu.Unlock()
	if _, err := daemon.Reload(ctx); err == nil || !strings.Contains(err.Error(), "invalid replacement") {
		t.Fatalf("failed Reload() = %v", err)
	}
	afterFailure := dialDaemonTestClient(t, address)
	defer afterFailure.Close()
	if marker := proxySearchMarker(t, afterFailure); marker != "new" {
		t.Fatalf("rollback client marker = %q, want new", marker)
	}
	snapshot := daemon.Snapshot()
	if snapshot.Generation != 2 || snapshot.SuccessfulLoads != 2 || snapshot.FailedLoads != 1 {
		t.Fatalf("daemon snapshot after rollback = %#v", snapshot)
	}
}

func TestDaemonReloadAddsAndRemovesListenersAtomically(t *testing.T) {
	upstream := startProxyTestUpstream(t, "topology", nil)
	firstAddress := reserveDaemonTestAddress(t)
	secondAddress := reserveDaemonTestAddress(t)

	var mu sync.Mutex
	listeners := []string{firstAddress}
	daemon, err := NewDaemon(DaemonOptions{
		Load: func(context.Context) (DaemonTopology, error) {
			mu.Lock()
			defer mu.Unlock()
			return daemonTestTopology(upstream.listener.Addr().String(), append([]string(nil), listeners...)), nil
		},
		ListenerKey: func(raw string) (string, error) { return raw, nil },
		Listen: func(raw string) (net.Listener, string, error) {
			listener, err := net.Listen("tcp", raw)
			return listener, raw, err
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewDaemon(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := daemon.Start(ctx); err != nil {
		t.Fatalf("Daemon.Start(): %v", err)
	}
	t.Cleanup(func() { _ = daemon.Close() })
	waitForDaemonOutgoing(t, daemon, 1)
	mu.Lock()
	listeners = []string{firstAddress, secondAddress}
	mu.Unlock()
	if _, err := daemon.Reload(ctx); err != nil {
		t.Fatalf("add listener Reload(): %v", err)
	}
	waitForDaemonOutgoing(t, daemon, 1)
	waitForDaemonDial(t, secondAddress)
	retired := dialDaemonTestClient(t, firstAddress)
	defer retired.Close()

	mu.Lock()
	listeners = []string{secondAddress}
	mu.Unlock()
	if _, err := daemon.Reload(ctx); err != nil {
		t.Fatalf("remove listener Reload(): %v", err)
	}
	waitForDaemonOutgoing(t, daemon, 1)
	if _, err := proxySearchMarkerResult(retired); err == nil {
		t.Fatal("retired generation client remained usable after listener reload")
	}
	waitForDaemonDialFailure(t, firstAddress)
	client := dialDaemonTestClient(t, secondAddress)
	defer client.Close()
	if marker := proxySearchMarker(t, client); marker != "topology" {
		t.Fatalf("remaining listener marker = %q", marker)
	}
}

func TestDaemonReloadForcesRetiredGenerationAfterTimeout(t *testing.T) {
	upstream := startProxyTestUpstream(t, "drain", nil)
	topology := daemonTestTopology(upstream.listener.Addr().String(), []string{"127.0.0.1:0"})
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
		DrainTimeout: 75 * time.Millisecond,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	t.Cleanup(func() { _ = daemon.Close() })
	client := dialDaemonTestClient(t, result.Listeners[0])
	defer client.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && daemon.Snapshot().Current.IncomingConnections == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if daemon.Snapshot().Current.IncomingConnections == 0 {
		t.Fatal("client was not assigned to the initial generation")
	}
	if _, err := daemon.Reload(ctx); err != nil {
		t.Fatalf("Daemon.Reload(): %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && daemon.Snapshot().Retired != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if daemon.Snapshot().Retired != 0 {
		t.Fatalf("retired generation did not drain: %#v", daemon.Snapshot())
	}
	if _, err := client.Search(ldap.NewSearchRequest(
		MonitorBaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)); err == nil {
		t.Fatal("retired client remained usable after drain timeout")
	}
}

func TestLloaddMonitorLDAPView(t *testing.T) {
	upstream := startProxyTestUpstream(t, "directory", nil)
	proxy, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{
				proxyTestBackend(upstream.listener.Addr().String()),
			},
		}},
	})
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	client := dialDaemonTestClient(t, address)
	defer client.Close()

	result, err := client.Search(ldap.NewSearchRequest(
		MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancer)",
		[]string{"cn", "+"},
		nil,
	))
	if err != nil {
		t.Fatalf("monitor base Search(): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("olmIncomingConnections") != "1" ||
		result.Entries[0].GetAttributeValue("olmOutgoingConnections") != "2" {
		t.Fatalf("monitor balancer entry = %#v", result.Entries)
	}

	result, err = client.Search(ldap.NewSearchRequest(
		monitorBackendTiersDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "olmServerURI", "olmActiveConnections"},
		nil,
	))
	if err != nil {
		t.Fatalf("monitor subtree Search(): %v", err)
	}
	var backend *ldap.Entry
	for _, entry := range result.Entries {
		if entry.GetAttributeValue("olmServerURI") != "" {
			backend = entry
		}
	}
	if backend == nil || backend.GetAttributeValue("olmServerURI") != "ldap://"+upstream.listener.Addr().String() {
		t.Fatalf("monitor backend entries = %#v", result.Entries)
	}
	if marker := proxySearchMarker(t, client); marker != "directory" {
		t.Fatalf("ordinary proxied Search marker = %q", marker)
	}

	operations, err := client.Search(ldap.NewSearchRequest(
		monitorOperationsDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancerOperation)",
		[]string{"cn", "+"},
		nil,
	))
	if err != nil || len(operations.Entries) != 2 {
		t.Fatalf("monitor operations = %#v, %v", operations, err)
	}
	var other *ldap.Entry
	for _, entry := range operations.Entries {
		if entry.GetAttributeValue("cn") == "Other" {
			other = entry
		}
	}
	if other == nil || other.GetAttributeValue("olmReceivedOps") == "0" ||
		other.GetAttributeValue("olmForwardedOps") == "0" ||
		other.GetAttributeValue("olmCompletedOps") == "0" {
		t.Fatalf("monitor Other counters = %#v", other)
	}
}

func TestLloaddMonitorControls(t *testing.T) {
	upstream := startProxyTestUpstream(t, "controls", nil)
	_, address := startRuntimeProxy(t, RuntimeConfig{
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{proxyTestBackend(upstream.listener.Addr().String())},
		}},
	})
	client := dialDaemonTestClient(t, address)
	defer client.Close()

	manage := ldap.NewControlString(monitorManageDsaITOID, true, "")
	if _, err := client.Search(ldap.NewSearchRequest(
		MonitorBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"cn"}, []ldap.Control{manage},
	)); err != nil {
		t.Fatalf("ManageDsaIT monitor Search: %v", err)
	}

	paging := ldap.NewControlPaging(2)
	total := 0
	for {
		result, err := client.Search(ldap.NewSearchRequest(
			MonitorLoadBalancerDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"cn"}, []ldap.Control{paging},
		))
		if err != nil {
			t.Fatalf("paged monitor Search: %v", err)
		}
		total += len(result.Entries)
		response, ok := ldap.FindControl(result.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok {
			t.Fatalf("paged response control = %#v", result.Controls)
		}
		if len(response.Cookie) == 0 {
			break
		}
		paging.SetCookie(response.Cookie)
	}
	if total <= 2 {
		t.Fatalf("paged monitor returned only %d entries", total)
	}

	_, err := client.Search(ldap.NewSearchRequest(
		MonitorBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"cn"},
		[]ldap.Control{ldap.NewControlString("1.2.3.4.5", true, "")},
	))
	ldapErr, ok := err.(*ldap.Error)
	if !ok || ldapErr.ResultCode != ldap.LDAPResultUnavailableCriticalExtension {
		t.Fatalf("unknown critical monitor control error = %v", err)
	}
}

func TestOpenLDAPReferenceLloaddManagementSourceContract(t *testing.T) {
	root := requirePinnedOpenLDAPLloaddSource(t)
	mainSource, err := os.ReadFile(filepath.Join(root, "servers", "lloadd", "main.c"))
	if err != nil {
		t.Fatalf("read lloadd main.c: %v", err)
	}
	daemonSource, err := os.ReadFile(filepath.Join(root, "servers", "lloadd", "daemon.c"))
	if err != nil {
		t.Fatalf("read lloadd daemon.c: %v", err)
	}
	monitorSource, err := os.ReadFile(filepath.Join(root, "servers", "lloadd", "monitor.c"))
	if err != nil {
		t.Fatalf("read lloadd monitor.c: %v", err)
	}
	for _, anchor := range []string{
		"{ SIGHUP, lload_sig_shutdown }",
		"if ( sig == SIGHUP && global_gentlehup",
		"slapd_shutdown = 1;",
	} {
		combined := string(mainSource) + string(daemonSource)
		if !strings.Contains(combined, anchor) {
			t.Fatalf("pinned lloadd signal sources lack %q", anchor)
		}
	}
	for _, anchor := range []string{
		`#define LLOAD_MONITOR_BALANCER_NAME "Load Balancer"`,
		`#define LLOAD_MONITOR_INCOMING_NAME "Incoming Connections"`,
		`#define LLOAD_MONITOR_TIERS_NAME "Backend Tiers"`,
		`NAME ( 'olmServerURI' )`,
		`NAME ( 'olmBalancerServer' )`,
	} {
		if !strings.Contains(string(monitorSource), anchor) {
			t.Fatalf("pinned lloadd monitor source lacks %q", anchor)
		}
	}
}

func daemonTestTopology(upstream string, listeners []string) DaemonTopology {
	return DaemonTopology{
		Runtime: RuntimeConfig{
			IOTimeout: 2 * time.Second,
			Tiers: []RuntimeTierConfig{{
				Strategy: "roundrobin",
				Backends: []RuntimeBackendConfig{proxyTestBackend(upstream)},
			}},
		},
		ListenURLs: listeners,
	}
}

func dialDaemonTestClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial daemon %s: %v", address, err)
	}
	return client
}

func waitForDaemonOutgoing(t *testing.T, daemon *Daemon, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if daemon.Snapshot().Current.OutgoingConnections >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("daemon outgoing connections = %#v, want at least %d", daemon.Snapshot(), count)
}

func reserveDaemonTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve daemon address: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitForDaemonDial(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s did not become available", address)
}

func waitForDaemonDialFailure(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err != nil {
			return
		}
		_ = connection.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("removed listener %s still accepts connections", address)
}
