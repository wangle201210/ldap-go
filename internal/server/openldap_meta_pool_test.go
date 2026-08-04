package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaPoolBindTimeoutMicros = 1000000
	openLDAPMetaPoolNretries          = "1"
	openLDAPMetaPoolWaitTimeout       = 10 * time.Second
)

type openLDAPMetaPoolCase struct {
	name                    string
	poolMax                 int
	useTemporary            bool
	clientCount             int
	concurrent              bool
	requireOverflowDispatch bool
	wantConnections         int64
}

type openLDAPMetaPoolClientResult struct {
	bindCode   uint16
	searchCode uint16
	entries    []string
}

type openLDAPMetaPoolObservation struct {
	clients             []openLDAPMetaPoolClientResult
	dispatchConnections int64
	connections         int64
	upstreamBinds       int
	upstreamSearches    int
}

type openLDAPMetaPoolGateSnapshot struct {
	binds    int
	searches int
}

func TestOpenLDAPReferenceMetaPrivilegedConnectionPool(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []openLDAPMetaPoolCase{
		{
			name:            "pool max 1 sequential cross-frontend reuse",
			poolMax:         1,
			clientCount:     3,
			wantConnections: 1,
		},
		{
			name:            "pool max 2 sequential cross-frontend reuse",
			poolMax:         2,
			clientCount:     3,
			wantConnections: 1,
		},
		{
			name:            "pool max 1 reuses busy privileged connection",
			poolMax:         1,
			clientCount:     2,
			concurrent:      true,
			wantConnections: 1,
		},
		{
			name:            "pool max 2 caps busy privileged connections",
			poolMax:         2,
			clientCount:     3,
			concurrent:      true,
			wantConnections: 2,
		},
		{
			name:                    "pool max 1 temporary connection for busy overflow",
			poolMax:                 1,
			useTemporary:            true,
			clientCount:             2,
			concurrent:              true,
			requireOverflowDispatch: true,
			wantConnections:         2,
		},
		{
			name:                    "pool max 2 temporary connection for busy overflow",
			poolMax:                 2,
			useTemporary:            true,
			clientCount:             3,
			concurrent:              true,
			requireOverflowDispatch: true,
			wantConnections:         3,
		},
	}

	reference := make(map[string]openLDAPMetaPoolObservation, len(tests))
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got := runOpenLDAPMetaPoolScenario(t, tools, test, false)
				assertOpenLDAPMetaPoolReference(t, got, test)
				reference[test.name] = got
				logOpenLDAPMetaPoolObservation(t, "OpenLDAP", test, got)
			})
		}
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go comparison", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got := runOpenLDAPMetaPoolScenario(t, tools, test, true)
				logOpenLDAPMetaPoolObservation(t, "ldap-go", test, got)
				if !reflect.DeepEqual(got, reference[test.name]) {
					t.Fatalf(
						"ldap-go back-meta privileged connection pool differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
						reference[test.name],
						got,
					)
				}
			})
		}
	})
}

func runOpenLDAPMetaPoolScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	test openLDAPMetaPoolCase,
	ldapGo bool,
) openLDAPMetaPoolObservation {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaConnectionUID,
		"pool-provider",
	)
	defer stopProvider()

	gate := startOpenLDAPMetaPoolGate(t, providerURI)
	defer gate.stop()
	forwarder := startOpenLDAPMetaCountingForwarder(t, gate.uri(), 0)
	defer forwarder.stop()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaPoolProxy(t, forwarder.uri(), test)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaPoolProxy(
			t,
			tools,
			forwarder.uri(),
			test,
		)
	}
	defer stopProxy()

	clients, results := openLDAPMetaPoolClients(t, proxyURI, test.clientCount)
	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()

	observation := openLDAPMetaPoolObservation{clients: results}
	if test.concurrent {
		starts := make([]chan struct{}, len(clients))
		var wait sync.WaitGroup
		wait.Add(len(clients))
		for index, client := range clients {
			starts[index] = make(chan struct{})
			go func(index int, client *ldap.Conn) {
				defer wait.Done()
				<-starts[index]
				observation.clients[index] = openLDAPMetaPoolSearch(client)
				observation.clients[index].bindCode = results[index].bindCode
			}(index, client)
		}
		initial := test.poolMax
		if initial > len(clients) {
			initial = len(clients)
		}
		for index := 0; index < initial; index++ {
			close(starts[index])
			gate.waitForSearches(t, index+1)
		}
		for index := initial; index < len(clients); index++ {
			close(starts[index])
		}
		if test.requireOverflowDispatch {
			gate.waitForSearches(t, len(clients))
		}
		observation.dispatchConnections = forwarder.accepted()
		gate.releaseSearches()
		openLDAPMetaPoolWait(t, &wait)
	} else {
		gate.releaseSearches()
		for index, client := range clients {
			search := openLDAPMetaPoolSearch(client)
			search.bindCode = results[index].bindCode
			observation.clients[index] = search
		}
		observation.dispatchConnections = forwarder.accepted()
	}

	snapshot := gate.snapshot()
	observation.connections = forwarder.accepted()
	observation.upstreamBinds = snapshot.binds
	observation.upstreamSearches = snapshot.searches
	return observation
}

func openLDAPMetaPoolClients(
	t *testing.T,
	proxyURI string,
	count int,
) ([]*ldap.Conn, []openLDAPMetaPoolClientResult) {
	t.Helper()
	clients := make([]*ldap.Conn, 0, count)
	results := make([]openLDAPMetaPoolClientResult, count)
	for index := 0; index < count; index++ {
		client, err := ldap.DialURL(proxyURI)
		if err != nil {
			for _, opened := range clients {
				opened.Close()
			}
			t.Fatalf("dial back-meta pool fixture client %d: %v", index, err)
		}
		client.SetTimeout(openLDAPMetaPoolWaitTimeout)
		clients = append(clients, client)
		results[index].bindCode = monitorLDAPResultCode(client.Bind(
			"cn=admin,"+openLDAPMetaBaseDN,
			"secret",
		))
	}
	return clients, results
}

func openLDAPMetaPoolSearch(client *ldap.Conn) openLDAPMetaPoolClientResult {
	result, err := client.Search(ldap.NewSearchRequest(
		openLDAPMetaConnectionLocalDN(),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	observation := openLDAPMetaPoolClientResult{
		searchCode: monitorLDAPResultCode(err),
	}
	if result != nil {
		for _, entry := range result.Entries {
			observation.entries = append(
				observation.entries,
				strings.ToLower(entry.DN)+"|"+entry.GetAttributeValue("uid"),
			)
		}
		sort.Strings(observation.entries)
	}
	return observation
}

func openLDAPMetaPoolWait(t *testing.T, wait *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(openLDAPMetaPoolWaitTimeout):
		t.Fatal("timed out waiting for concurrent back-meta pool searches")
	}
}

func assertOpenLDAPMetaPoolReference(
	t *testing.T,
	got openLDAPMetaPoolObservation,
	test openLDAPMetaPoolCase,
) {
	t.Helper()
	wantClient := openLDAPMetaPoolClientResult{
		bindCode:   ldap.LDAPResultSuccess,
		searchCode: ldap.LDAPResultSuccess,
		entries: []string{
			openLDAPMetaConnectionLocalDN() + "|" + openLDAPMetaConnectionUID,
		},
	}
	wantClients := make([]openLDAPMetaPoolClientResult, test.clientCount)
	for index := range wantClients {
		wantClients[index] = wantClient
	}
	want := openLDAPMetaPoolObservation{
		clients:             wantClients,
		dispatchConnections: test.wantConnections,
		connections:         test.wantConnections,
		upstreamBinds:       int(test.wantConnections),
		upstreamSearches:    test.clientCount,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP 2.6.13 back-meta privileged pool fixture drifted:\n got: %#v\nwant: %#v",
			got,
			want,
		)
	}
}

func logOpenLDAPMetaPoolObservation(
	t *testing.T,
	implementation string,
	test openLDAPMetaPoolCase,
	got openLDAPMetaPoolObservation,
) {
	t.Helper()
	t.Logf(
		"%s pool-max=%d use-temporary=%t concurrent=%t: dispatch-tcp=%d final-tcp=%d upstream-binds=%d upstream-searches=%d LDAP=%#v",
		implementation,
		test.poolMax,
		test.useTemporary,
		test.concurrent,
		got.dispatchConnections,
		got.connections,
		got.upstreamBinds,
		got.upstreamSearches,
		got.clients,
	)
}

func startOpenLDAPMetaPoolProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	test openLDAPMetaPoolCase,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout %d
nretries %s
chase-referrals no
onerr stop
pseudoroot-bind-defer yes
use-temporary-conn %s
conn-pool-max %d

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		openLDAPMetaPoolBindTimeoutMicros,
		openLDAPMetaPoolNretries,
		strconv.FormatBool(test.useTemporary),
		test.poolMax,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
	)
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		configuration,
		"",
	)
}

func startLDAPGoMetaPoolProxy(
	t *testing.T,
	providerURI string,
	test openLDAPMetaPoolCase,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaPoolConfiguration(t, store, providerURI, test)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaPoolConfiguration(
	t *testing.T,
	store storage.Store,
	providerURI string,
	test openLDAPMetaPoolCase,
) {
	t.Helper()
	databaseDN := "olcDatabase={1}meta,cn=config"
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}meta")},
				{Description: "olcSuffix", Values: stringValues(openLDAPMetaBaseDN)},
				{Description: "olcRootDN", Values: stringValues("cn=admin," + openLDAPMetaBaseDN)},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbBindTimeout", Values: stringValues(strconv.Itoa(openLDAPMetaPoolBindTimeoutMicros))},
				{Description: "olcDbNretries", Values: stringValues(openLDAPMetaPoolNretries)},
				{Description: "olcDbChaseReferrals", Values: stringValues("FALSE")},
				{Description: "olcDbOnErr", Values: stringValues("stop")},
				{Description: "olcDbPseudoRootBindDefer", Values: stringValues("TRUE")},
				{Description: "olcDbUseTemporaryConn", Values: stringValues(strconv.FormatBool(test.useTemporary))},
				{Description: "olcDbConnectionPoolMax", Values: stringValues(strconv.Itoa(test.poolMax))},
			},
		},
		{
			DN: "olcMetaSub={0}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(providerURI + "/" + openLDAPMetaBaseDN)},
				{Description: "olcDbRewrite", Values: stringValues(
					"suffixmassage \"" + openLDAPMetaBaseDN + "\" \"dc=example,dc=com\"",
				)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
				)},
				{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta privileged pool configuration: %v", err)
	}
}

type openLDAPMetaPoolGateFrame struct {
	encoded        []byte
	searchResponse bool
}

type openLDAPMetaPoolGate struct {
	listener net.Listener
	upstream string

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	binds       int
	searches    int
	stopped     bool
	changes     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	stopOnce    sync.Once
	wait        sync.WaitGroup
}

func startOpenLDAPMetaPoolGate(
	t *testing.T,
	providerURI string,
) *openLDAPMetaPoolGate {
	t.Helper()
	parsed, err := url.Parse(providerURI)
	if err != nil || parsed.Host == "" {
		t.Fatalf("parse back-meta pool provider URI %q: %v", providerURI, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta pool gate: %v", err)
	}
	gate := &openLDAPMetaPoolGate{
		listener:    listener,
		upstream:    parsed.Host,
		connections: make(map[net.Conn]struct{}),
		changes:     make(chan struct{}, 1),
		release:     make(chan struct{}),
	}
	gate.wait.Add(1)
	go gate.serve()
	return gate
}

func (gate *openLDAPMetaPoolGate) uri() string {
	return "ldap://" + gate.listener.Addr().String()
}

func (gate *openLDAPMetaPoolGate) serve() {
	defer gate.wait.Done()
	for {
		connection, err := gate.listener.Accept()
		if err != nil {
			return
		}
		gate.track(connection, true)
		gate.wait.Add(1)
		go func(connection net.Conn) {
			defer gate.wait.Done()
			defer gate.track(connection, false)
			gate.forward(connection)
		}(connection)
	}
}

func (gate *openLDAPMetaPoolGate) forward(connection net.Conn) {
	upstream, err := net.DialTimeout("tcp", gate.upstream, time.Second)
	if err != nil {
		_ = connection.Close()
		return
	}
	gate.track(upstream, true)
	defer gate.track(upstream, false)
	defer upstream.Close()
	defer connection.Close()

	done := make(chan struct{}, 2)
	go func() {
		gate.forwardRequests(connection, upstream)
		done <- struct{}{}
	}()
	go func() {
		gate.forwardResponses(upstream, connection)
		done <- struct{}{}
	}()
	<-done
	_ = connection.Close()
	_ = upstream.Close()
	<-done
}

func (gate *openLDAPMetaPoolGate) forwardRequests(
	connection net.Conn,
	upstream net.Conn,
) {
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil {
			return
		}
		if len(packet.Children) < 2 || packet.Children[1].ClassType != ber.ClassApplication {
			return
		}
		tag := uint64(packet.Children[1].Tag)
		gate.record(tag)
		if err := ldapwire.Write(upstream, packet.Bytes()); err != nil {
			return
		}
	}
}

func (gate *openLDAPMetaPoolGate) forwardResponses(
	upstream net.Conn,
	connection net.Conn,
) {
	frames := make(chan openLDAPMetaPoolGateFrame, 64)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for frame := range frames {
			if frame.searchResponse {
				<-gate.release
			}
			if err := ldapwire.Write(connection, frame.encoded); err != nil {
				_ = upstream.Close()
				return
			}
		}
		if tcp, ok := connection.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	for {
		packet, err := ber.ReadPacket(upstream)
		if err != nil {
			break
		}
		if len(packet.Children) < 2 || packet.Children[1].ClassType != ber.ClassApplication {
			break
		}
		tag := uint64(packet.Children[1].Tag)
		frames <- openLDAPMetaPoolGateFrame{
			encoded: packet.Bytes(),
			searchResponse: tag == ldapwire.ApplicationSearchResultEntry ||
				tag == ldapwire.ApplicationSearchResultDone ||
				tag == ldapwire.ApplicationSearchResultReference,
		}
	}
	close(frames)
	<-writerDone
}

func (gate *openLDAPMetaPoolGate) record(tag uint64) {
	gate.mu.Lock()
	switch tag {
	case ldapwire.ApplicationBindRequest:
		gate.binds++
	case ldapwire.ApplicationSearchRequest:
		gate.searches++
	}
	gate.mu.Unlock()
	select {
	case gate.changes <- struct{}{}:
	default:
	}
}

func (gate *openLDAPMetaPoolGate) snapshot() openLDAPMetaPoolGateSnapshot {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return openLDAPMetaPoolGateSnapshot{
		binds:    gate.binds,
		searches: gate.searches,
	}
}

func (gate *openLDAPMetaPoolGate) waitForSearches(t *testing.T, want int) {
	t.Helper()
	timer := time.NewTimer(openLDAPMetaPoolWaitTimeout)
	defer timer.Stop()
	for {
		if got := gate.snapshot().searches; got >= want {
			return
		}
		select {
		case <-gate.changes:
		case <-timer.C:
			t.Fatalf(
				"timed out waiting for %d upstream back-meta searches; snapshot=%#v",
				want,
				gate.snapshot(),
			)
		}
	}
}

func (gate *openLDAPMetaPoolGate) releaseSearches() {
	gate.releaseOnce.Do(func() {
		close(gate.release)
	})
}

func (gate *openLDAPMetaPoolGate) track(connection net.Conn, add bool) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if add {
		if gate.stopped {
			_ = connection.Close()
			return
		}
		gate.connections[connection] = struct{}{}
	} else {
		delete(gate.connections, connection)
	}
}

func (gate *openLDAPMetaPoolGate) stop() {
	gate.stopOnce.Do(func() {
		gate.releaseSearches()
		_ = gate.listener.Close()
		gate.mu.Lock()
		gate.stopped = true
		for connection := range gate.connections {
			_ = connection.Close()
		}
		gate.mu.Unlock()
		gate.wait.Wait()
	})
}
