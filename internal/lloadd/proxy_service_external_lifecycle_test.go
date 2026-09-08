package lloadd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// This peer records physical TLS connections and enforces the regular/bind
// distinction on the wire, independently of the proxy's scheduler bookkeeping.
type externalLifecyclePeer struct {
	t         *testing.T
	listener  net.Listener
	uri       string
	transport string
	tls       *tls.Config
	mu        sync.Mutex
	next      int
	offline   bool
	conns     map[int]net.Conn
	events    []externalLifecycleEvent
	denied    string
	wg        sync.WaitGroup
}

type externalLifecycleEvent struct {
	Connection int
	Kind       string
	Cert       string
	Resumed    bool
	Identity   string
}

func newExternalLifecyclePeer(t *testing.T, pki externalTestPKI, transport string) *externalLifecyclePeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := &externalLifecyclePeer{t: t, listener: listener, transport: transport,
		tls: pki.serverTLS, conns: make(map[int]net.Conn)}
	peer.uri = "ldaps://" + listener.Addr().String()
	if transport == "StartTLS" {
		peer.uri = "ldap://" + listener.Addr().String()
	}
	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			peer.mu.Lock()
			if peer.offline {
				peer.mu.Unlock()
				_ = conn.Close()
				continue
			}
			peer.next++
			id := peer.next
			peer.conns[id] = conn
			peer.wg.Add(1)
			peer.mu.Unlock()
			go peer.serve(conn, id)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		peer.setOffline(true)
		peer.wg.Wait()
	})
	return peer
}

func (peer *externalLifecyclePeer) record(event externalLifecycleEvent) {
	peer.mu.Lock()
	peer.events = append(peer.events, event)
	peer.mu.Unlock()
}

func (peer *externalLifecyclePeer) snapshot() []externalLifecycleEvent {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	return append([]externalLifecycleEvent(nil), peer.events...)
}

func (peer *externalLifecyclePeer) setOffline(offline bool) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.offline = offline
	if offline {
		for _, conn := range peer.conns {
			_ = conn.Close()
		}
	}
}

func (peer *externalLifecyclePeer) serve(raw net.Conn, id int) {
	defer peer.wg.Done()
	defer raw.Close()
	defer func() {
		peer.mu.Lock()
		delete(peer.conns, id)
		peer.events = append(peer.events, externalLifecycleEvent{Connection: id, Kind: "closed"})
		peer.mu.Unlock()
	}()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if peer.transport == "StartTLS" {
		message, err := ldapwire.ReadMessage(raw, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			return
		}
		request, ok := message.Request.(ldapwire.ExtendedRequest)
		if !ok || request.Name != upstreamStartTLSOID || len(message.Controls) != 0 {
			peer.t.Errorf("connection %d before TLS: %#v", id, message)
			return
		}
		if err := ldapwire.Write(raw, ldapwire.EncodeResultResponse(message.ID,
			ldapwire.ApplicationExtendedResponse, ldapwire.Result{}, nil)); err != nil {
			return
		}
	}
	conn := tls.Server(raw, peer.tls)
	if err := conn.Handshake(); err != nil {
		peer.record(externalLifecycleEvent{Connection: id, Kind: "TLS rejected"})
		return
	}
	state := conn.ConnectionState()
	event := externalLifecycleEvent{Connection: id, Kind: "TLS", Resumed: state.DidResume}
	if len(state.PeerCertificates) != 0 {
		event.Cert = fmt.Sprintf("%x", sha256.Sum256(state.PeerCertificates[0].Raw))
	}
	peer.record(event)
	service, bound := false, ""
	for {
		message, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			return
		}
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			if len(message.Controls) != 0 {
				peer.t.Errorf("ProxyAuthz/control leaked into Bind on physical connection %d", id)
			}
			code := ldapwire.ResultSuccess
			if request.Authentication.IsSASL {
				if service || bound != "" || request.Name != "" || request.Version != 3 ||
					request.Authentication.SASLMechanism != "EXTERNAL" || !request.Authentication.HasSASLCredentials {
					peer.t.Errorf("invalid service Bind on connection %d: %#v", id, request)
				}
				event.Kind, event.Identity = "EXTERNAL", string(request.Authentication.SASLCredentials)
				peer.mu.Lock()
				denied := peer.denied
				peer.mu.Unlock()
				if event.Cert == "" || event.Cert == denied || event.Identity == "dn:cn=denied" {
					code = ldapwire.ResultInvalidCredentials
					event.Kind = "EXTERNAL rejected"
				} else {
					service = true
				}
			} else {
				if service {
					peer.t.Errorf("client Bind entered regular pool connection %d", id)
				}
				bound = ""
				if request.Name != "" && string(request.Authentication.Simple) == "secret" {
					bound = "dn:" + request.Name
				} else if request.Name != "" {
					code = ldapwire.ResultInvalidCredentials
				}
				event.Kind, event.Identity = "Bind", bound
			}
			peer.record(event)
			if err := ldapwire.Write(conn, ldapwire.EncodeResultResponse(message.ID,
				ldapwire.ApplicationBindResponse, ldapwire.Result{Code: code}, nil)); err != nil {
				return
			}
		case ldapwire.SearchRequest:
			if !service || len(message.Controls) != 1 ||
				message.Controls[0].OID != ProxyAuthzControlOID || !message.Controls[0].Critical {
				peer.t.Errorf("Search escaped service pool/ProxyAuthz on connection %d: bound=%q controls=%#v", id, bound, message.Controls)
				return
			}
			event.Kind, event.Identity = "Search", string(message.Controls[0].Value)
			peer.record(event)
			entry := directory.Entry{DN: "cn=observation", Attributes: []directory.Attribute{
				{Description: "cn", Values: [][]byte{[]byte(strconv.Itoa(id))}},
				{Description: "description", Values: [][]byte{[]byte(event.Cert)}},
				{Description: "uid", Values: [][]byte{[]byte(event.Identity)}},
			}}
			if err := ldapwire.Write(conn, ldapwire.EncodeSearchResultEntry(message.ID, entry, nil)); err != nil {
				return
			}
			if err := ldapwire.Write(conn, ldapwire.EncodeSearchResultDone(message.ID, ldapwire.Result{}, nil)); err != nil {
				return
			}
		case ldapwire.UnbindRequest:
			return
		default:
			peer.t.Errorf("unexpected request on physical connection %d: %T", id, request)
			return
		}
	}
}

func externalLifecycleSearch(client *ldap.Conn) (externalLifecycleEvent, error) {
	result, err := client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"cn", "description", "uid"}, nil))
	if err != nil {
		return externalLifecycleEvent{}, err
	}
	if len(result.Entries) != 1 {
		return externalLifecycleEvent{}, fmt.Errorf("got %d observation entries", len(result.Entries))
	}
	entry := result.Entries[0]
	id, err := strconv.Atoi(entry.GetAttributeValue("cn"))
	return externalLifecycleEvent{Connection: id, Cert: entry.GetAttributeValue("description"),
		Identity: entry.GetAttributeValue("uid")}, err
}

func externalLifecycleAssertSearch(t *testing.T, client *ldap.Conn, identity, cert string) externalLifecycleEvent {
	t.Helper()
	event, err := externalLifecycleSearch(client)
	if err != nil || event.Identity != identity || event.Cert != cert {
		t.Fatalf("Search = %+v, %v; want identity=%q cert=%q", event, err, identity, cert)
	}
	return event
}

func externalLifecycleWait(t *testing.T, label string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out: " + label)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func externalLifecycleRotationPKI(t *testing.T) (externalTestPKI, externalTestPKI) {
	t.Helper()
	old, next := newExternalTestPKI(t), newExternalTestPKI(t)
	ca, err := os.ReadFile(next.caFile)
	if err != nil {
		t.Fatal(err)
	}
	old.serverTLS.ClientCAs = old.serverTLS.ClientCAs.Clone()
	if !old.serverTLS.ClientCAs.AppendCertsFromPEM(ca) {
		t.Fatal("append rotation CA")
	}
	next.clientTLS.RootCAs = old.clientTLS.RootCAs
	return old, next
}

func externalLifecycleFingerprint(pki externalTestPKI) string {
	return fmt.Sprintf("%x", sha256.Sum256(pki.clientTLS.Certificates[0].Certificate[0]))
}

func TestServiceSASLExternalRotationSessionCache(t *testing.T) {
	for _, transport := range []string{"LDAPS", "StartTLS"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("%s/%x", transport, version), func(t *testing.T) {
				old, next := externalLifecycleRotationPKI(t)
				old.serverTLS.MinVersion, old.serverTLS.MaxVersion = version, version
				old.clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(4)
				peer := newExternalLifecyclePeer(t, old, transport)
				config := externalTestRuntimeConfig(peer.uri, transport, old)
				first, err := NewProxy(config)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				connect := func(proxy *Proxy) {
					t.Helper()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					upstream, err := proxy.tiers[0].backends[0].connect(ctx, "rotation-probe", false)
					if err != nil {
						t.Fatal(err)
					}
					_ = upstream.conn.Close()
				}
				connect(first)
				connect(first) // Prove the fixture actually issues usable session tickets.
				rotated := config.BackendTLS.Clone()
				rotated.Certificates = next.clientTLS.Certificates
				config.BackendTLS = rotated
				config.Bind.AuthorizationID = "dn:cn=rotated-service"
				second, err := NewProxy(config)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
				connect(second)
				var binds []externalLifecycleEvent
				for _, event := range peer.snapshot() {
					if event.Kind == "EXTERNAL" {
						binds = append(binds, event)
					}
				}
				if len(binds) != 3 || !binds[1].Resumed {
					t.Fatalf("fixture did not exercise resumption and per-connection EXTERNAL: %+v", binds)
				}
				if binds[2].Resumed || binds[2].Cert != externalLifecycleFingerprint(next) ||
					binds[2].Identity != config.Bind.AuthorizationID || binds[2].Connection == binds[1].Connection {
					t.Fatalf("new generation reused retired TLS identity: %+v", binds)
				}
			})
		}
	}
}

func TestServiceSASLExternalDaemonRotationAndFailureIsolation(t *testing.T) {
	old, next := externalLifecycleRotationPKI(t)
	old.clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	peer := newExternalLifecyclePeer(t, old, "LDAPS")
	oldConfig := externalTestRuntimeConfig(peer.uri, "LDAPS", old)

	var topologyMu sync.Mutex
	topology := DaemonTopology{Runtime: oldConfig, ListenURLs: []string{"127.0.0.1:0"}}
	var certificateFile, keyFile string
	daemon, err := NewDaemon(DaemonOptions{
		Load: func(context.Context) (DaemonTopology, error) {
			topologyMu.Lock()
			defer topologyMu.Unlock()
			candidate := topology
			if certificateFile != "" {
				certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
				if err != nil {
					return DaemonTopology{}, fmt.Errorf("load rotated tls_cert/tls_key: %w", err)
				}
				candidate.Runtime.BackendTLS = candidate.Runtime.BackendTLS.Clone()
				candidate.Runtime.BackendTLS.Certificates = []tls.Certificate{certificate}
			}
			return candidate, nil
		},
		ListenerKey: func(raw string) (string, error) { return raw, nil },
		Listen: func(raw string) (net.Listener, string, error) {
			listener, err := net.Listen("tcp", raw)
			if err != nil {
				return nil, "", err
			}
			return listener, listener.Addr().String(), nil
		},
		DrainTimeout: time.Second,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, err := daemon.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = daemon.Close() })
	currentProxy := func() *Proxy {
		daemon.mu.Lock()
		defer daemon.mu.Unlock()
		return daemon.current.proxy
	}
	waitForReadyConnections(t, currentProxy(), PoolRegular, 1)
	waitForReadyConnections(t, currentProxy(), PoolBind, 1)

	const firstIdentity = "dn:uid=first,dc=example,dc=com"
	oldClient := dialDaemonTestClient(t, started.Listeners[0])
	defer oldClient.Close()
	if err := oldClient.Bind(strings.TrimPrefix(firstIdentity, "dn:"), "secret"); err != nil {
		t.Fatal(err)
	}
	oldSearch := externalLifecycleAssertSearch(t, oldClient, firstIdentity, externalLifecycleFingerprint(old))
	oldBindConnection := 0
	for _, event := range peer.snapshot() {
		if event.Kind == "Bind" && event.Identity == firstIdentity {
			oldBindConnection = event.Connection
		}
	}
	if oldBindConnection == 0 || oldBindConnection == oldSearch.Connection {
		t.Fatalf("initial regular/bind pools were not distinct: bind=%d search=%+v", oldBindConnection, oldSearch)
	}

	rotatedConfig := oldConfig
	rotatedConfig.BackendTLS = oldConfig.BackendTLS.Clone()
	rotatedConfig.BackendTLS.Certificates = next.clientTLS.Certificates
	rotatedConfig.Bind.AuthorizationID = "dn:cn=rotated-service"
	topologyMu.Lock()
	topology.Runtime = rotatedConfig
	certificateFile, keyFile = next.clientCert, next.clientKey
	topologyMu.Unlock()
	reloaded, err := daemon.Reload(ctx)
	if err != nil || reloaded.Generation != 2 || reloaded.Listeners[0] != started.Listeners[0] {
		t.Fatalf("rotated Reload = %#v, %v", reloaded, err)
	}
	waitForReadyConnections(t, currentProxy(), PoolRegular, 1)
	waitForReadyConnections(t, currentProxy(), PoolBind, 1)
	externalLifecycleWait(t, "retired physical connections to close", func() bool {
		closed := make(map[int]bool)
		for _, event := range peer.snapshot() {
			if event.Kind == "closed" {
				closed[event.Connection] = true
			}
		}
		return closed[oldSearch.Connection] && closed[oldBindConnection]
	})
	if _, err := externalLifecycleSearch(oldClient); err == nil {
		t.Fatal("client attached to retired generation remained usable")
	}

	rotatedClient := dialDaemonTestClient(t, started.Listeners[0])
	defer rotatedClient.Close()
	if err := rotatedClient.Bind(strings.TrimPrefix(firstIdentity, "dn:"), "secret"); err != nil {
		t.Fatal(err)
	}
	rotatedSearch := externalLifecycleAssertSearch(t, rotatedClient, firstIdentity, externalLifecycleFingerprint(next))
	if rotatedSearch.Connection == oldSearch.Connection {
		t.Fatalf("new generation reused retired regular connection %d", oldSearch.Connection)
	}

	topologyMu.Lock()
	certificateFile, keyFile = next.clientCert, old.clientKey
	topologyMu.Unlock()
	if _, err := daemon.Reload(ctx); err == nil || !strings.Contains(err.Error(), "private key does not match") {
		t.Fatalf("invalid certificate Reload = %v", err)
	}
	const secondIdentity = "dn:uid=second,dc=example,dc=com"
	rollbackClient := dialDaemonTestClient(t, started.Listeners[0])
	defer rollbackClient.Close()
	if err := rollbackClient.Bind(strings.TrimPrefix(secondIdentity, "dn:"), "secret"); err != nil {
		t.Fatal(err)
	}
	rollbackSearch := externalLifecycleAssertSearch(t, rollbackClient, secondIdentity, externalLifecycleFingerprint(next))
	if rollbackSearch.Connection != rotatedSearch.Connection {
		t.Fatalf("failed rotation replaced current regular connection: before=%d after=%d",
			rotatedSearch.Connection, rollbackSearch.Connection)
	}
	if snapshot := daemon.Snapshot(); snapshot.Generation != 2 || snapshot.FailedLoads != 1 {
		t.Fatalf("snapshot after failed rotation = %#v", snapshot)
	}

	topologyMu.Lock()
	certificateFile, keyFile = next.clientCert, next.clientKey
	topology.Runtime = rotatedConfig
	topology.Runtime.Bind.AuthorizationID = "dn:cn=denied"
	topologyMu.Unlock()
	isolation, err := daemon.Reload(ctx)
	if err != nil || isolation.Generation != 3 {
		t.Fatalf("denied rotation Reload = %#v, %v", isolation, err)
	}
	isolationProxy := currentProxy()
	waitForReadyConnections(t, isolationProxy, PoolBind, 1)
	externalLifecycleWait(t, "denied EXTERNAL attempt", func() bool {
		for _, event := range peer.snapshot() {
			if event.Kind == "EXTERNAL rejected" && event.Identity == "dn:cn=denied" {
				return true
			}
		}
		return false
	})
	if readyServiceSASLConnections(isolationProxy, PoolRegular) != 0 {
		t.Fatal("denied replacement admitted an EXTERNAL connection to the regular pool")
	}
	isolationClient := dialDaemonTestClient(t, started.Listeners[0])
	defer isolationClient.Close()
	if err := isolationClient.Bind(strings.TrimPrefix(firstIdentity, "dn:"), "secret"); err != nil {
		t.Fatalf("denied service rotation also poisoned bind pool: %v", err)
	}
	if _, err := externalLifecycleSearch(isolationClient); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) {
		t.Fatalf("Search through isolated generation = %v, want unavailable", err)
	}
}

func TestServiceSASLExternalMultiUserOrderedFailoverPoolIsolation(t *testing.T) {
	pki := newExternalTestPKI(t)
	primary := newExternalLifecyclePeer(t, pki, "StartTLS")
	fallback := newExternalLifecyclePeer(t, pki, "StartTLS")
	config := externalTestRuntimeConfig(primary.uri, "StartTLS", pki)
	config.Tiers = append(config.Tiers, RuntimeTierConfig{Strategy: "roundrobin", Backends: []RuntimeBackendConfig{{
		URI: fallback.uri, RegularConnections: 1, BindConnections: 1, Retry: 20 * time.Millisecond,
		StartTLS: true, StartTLSCritical: true,
	}}})
	proxy, address := startRuntimeProxy(t, config)
	for _, backendID := range []string{"tier-0-backend-0", "tier-1-backend-0"} {
		waitForBackendConnection(t, proxy, backendID, PoolRegular)
		waitForBackendConnection(t, proxy, backendID, PoolBind)
	}

	identities := []string{"dn:uid=alice,dc=example,dc=com", "dn:uid=bob,dc=example,dc=com"}
	clients := make([]*ldap.Conn, 0, len(identities))
	for _, identity := range identities {
		client := dialDaemonTestClient(t, address)
		defer client.Close()
		if err := client.Bind(strings.TrimPrefix(identity, "dn:"), "secret"); err != nil {
			t.Fatalf("primary Bind %q: %v", identity, err)
		}
		event := externalLifecycleAssertSearch(t, client, identity, externalLifecycleFingerprint(pki))
		if event.Connection == 0 {
			t.Fatalf("primary Search %q has no physical connection", identity)
		}
		clients = append(clients, client)
	}
	assertPools := func(label string, peer *externalLifecyclePeer) {
		t.Helper()
		var binds, searches []externalLifecycleEvent
		for _, event := range peer.snapshot() {
			switch event.Kind {
			case "Bind":
				binds = append(binds, event)
			case "Search":
				searches = append(searches, event)
			}
		}
		if len(binds) != 2 || len(searches) != 2 {
			t.Fatalf("%s events: binds=%+v searches=%+v", label, binds, searches)
		}
		for index, identity := range identities {
			if binds[index].Identity != identity || searches[index].Identity != identity {
				t.Fatalf("%s identity %d leaked: bind=%+v search=%+v want=%q",
					label, index, binds[index], searches[index], identity)
			}
			if binds[index].Connection == searches[index].Connection {
				t.Fatalf("%s reused physical connection %d across bind and regular pools",
					label, binds[index].Connection)
			}
		}
		if binds[0].Connection != binds[1].Connection || searches[0].Connection != searches[1].Connection {
			t.Fatalf("%s did not exercise multi-user pool reuse: binds=%+v searches=%+v", label, binds, searches)
		}
	}
	assertPools("primary", primary)

	primary.setOffline(true)
	externalLifecycleWait(t, "primary pools to become unavailable", func() bool {
		for _, connection := range proxy.scheduler.Snapshot().Connections {
			if connection.BackendID == "tier-0-backend-0" && connection.State == ConnectionReady {
				return false
			}
		}
		return true
	})
	for index, client := range clients {
		if err := client.Bind(strings.TrimPrefix(identities[index], "dn:"), "secret"); err != nil {
			t.Fatalf("fallback Bind %q: %v", identities[index], err)
		}
		externalLifecycleAssertSearch(t, client, identities[index], externalLifecycleFingerprint(pki))
	}
	assertPools("fallback", fallback)

	primary.setOffline(false)
	waitForBackendConnection(t, proxy, "tier-0-backend-0", PoolRegular)
	waitForBackendConnection(t, proxy, "tier-0-backend-0", PoolBind)
	if err := clients[1].Bind(strings.TrimPrefix(identities[1], "dn:"), "secret"); err != nil {
		t.Fatalf("recovered primary Bind: %v", err)
	}
	recovered := externalLifecycleAssertSearch(t, clients[1], identities[1], externalLifecycleFingerprint(pki))
	var originalPrimary int
	for _, event := range primary.snapshot() {
		if event.Kind == "Search" {
			originalPrimary = event.Connection
			break
		}
	}
	if recovered.Connection == originalPrimary {
		t.Fatalf("recovered primary reused retired physical connection %d", originalPrimary)
	}
}
