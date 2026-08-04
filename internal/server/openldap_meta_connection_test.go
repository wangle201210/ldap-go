package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaConnectionUID         = "route-one"
	openLDAPMetaConnectionDescription = "connection-modified"
	openLDAPMetaConnectionExpiry      = time.Second
)

type openLDAPMetaConnectionCase struct {
	name                  string
	openLDAPDirective     string
	ldapGoAttribute       string
	ldapGoValue           string
	waitAfterWarmup       time.Duration
	overlapOperations     bool
	providerResponseDelay time.Duration
	wantConnections       int64
	wantAdditional        bool
}

type openLDAPMetaConnectionSearch struct {
	code  uint16
	dn    string
	value string
}

type openLDAPMetaConnectionResult struct {
	warmup         openLDAPMetaConnectionSearch
	search         openLDAPMetaConnectionSearch
	compareCode    uint16
	compareMatched bool
	modifyCode     uint16
	verification   openLDAPMetaConnectionSearch
}

type openLDAPMetaConnectionObservation struct {
	result      openLDAPMetaConnectionResult
	connections int64
}

func TestOpenLDAPReferenceMetaConnectionReuse(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []openLDAPMetaConnectionCase{
		{
			name:            "sequential operations reuse one connection",
			wantConnections: 1,
		},
		{
			name:                  "use temporary connection under contention",
			openLDAPDirective:     "use-temporary-conn yes",
			ldapGoAttribute:       "olcDbUseTemporaryConn",
			ldapGoValue:           "TRUE",
			overlapOperations:     true,
			providerResponseDelay: 250 * time.Millisecond,
			wantAdditional:        true,
		},
		{
			name:              "idle timeout reconnects once",
			openLDAPDirective: "idle-timeout 1s",
			ldapGoAttribute:   "olcDbIdleTimeout",
			ldapGoValue:       "1s",
			waitAfterWarmup:   2*openLDAPMetaConnectionExpiry + 250*time.Millisecond,
			wantConnections:   2,
		},
		{
			name:              "connection ttl reconnects once",
			openLDAPDirective: "conn-ttl 1s",
			ldapGoAttribute:   "olcDbConnTtl",
			ldapGoValue:       "1s",
			waitAfterWarmup:   2*openLDAPMetaConnectionExpiry + 250*time.Millisecond,
			wantConnections:   2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reference := runOpenLDAPMetaConnectionScenario(t, tools, test, false)
			assertOpenLDAPMetaConnectionLDAPResult(t, reference.result)
			assertOpenLDAPMetaConnectionCount(t, "OpenLDAP", reference.connections, test)

			got := runOpenLDAPMetaConnectionScenario(t, tools, test, true)
			assertOpenLDAPMetaConnectionLDAPResult(t, got.result)
			assertOpenLDAPMetaConnectionCount(t, "ldap-go", got.connections, test)
			if !reflect.DeepEqual(got.result, reference.result) {
				t.Fatalf(
					"ldap-go back-meta LDAP results differ from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
					reference.result,
					got.result,
				)
			}

			t.Logf(
				"target TCP connections: OpenLDAP=%d ldap-go=%d",
				reference.connections,
				got.connections,
			)
		})
	}
}

func runOpenLDAPMetaConnectionScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	test openLDAPMetaConnectionCase,
	ldapGo bool,
) openLDAPMetaConnectionObservation {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaConnectionUID,
		"provider-one",
	)
	defer stopProvider()

	forwarder := startOpenLDAPMetaCountingForwarder(
		t,
		providerURI,
		test.providerResponseDelay,
	)
	defer forwarder.stop()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaConnectionProxy(t, forwarder.uri(), test)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaConnectionProxy(
			t,
			tools,
			forwarder.uri(),
			test,
		)
	}
	defer stopProxy()

	result := observeOpenLDAPMetaConnectionOperations(t, proxyURI, test)
	return openLDAPMetaConnectionObservation{
		result:      result,
		connections: forwarder.accepted(),
	}
}

func observeOpenLDAPMetaConnectionOperations(
	t *testing.T,
	proxyURI string,
	test openLDAPMetaConnectionCase,
) openLDAPMetaConnectionResult {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta connection fixture %s: %v", proxyURI, err)
	}
	client.SetTimeout(10 * time.Second)
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta connection fixture %s: %v", proxyURI, err)
	}

	result := openLDAPMetaConnectionResult{
		warmup: searchOpenLDAPMetaConnectionEntry(client, []string{"uid"}),
	}
	if test.waitAfterWarmup > 0 {
		time.Sleep(test.waitAfterWarmup)
	}

	if test.overlapOperations {
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(3)
		go func() {
			defer wait.Done()
			<-start
			result.search = searchOpenLDAPMetaConnectionEntry(client, []string{"uid"})
		}()
		go func() {
			defer wait.Done()
			<-start
			matched, compareErr := client.Compare(
				openLDAPMetaConnectionLocalDN(),
				"uid",
				openLDAPMetaConnectionUID,
			)
			result.compareMatched = matched
			result.compareCode = monitorLDAPResultCode(compareErr)
		}()
		go func() {
			defer wait.Done()
			<-start
			result.modifyCode = modifyOpenLDAPMetaConnectionEntry(client)
		}()
		close(start)
		wait.Wait()
	} else {
		result.search = searchOpenLDAPMetaConnectionEntry(client, []string{"uid"})
		matched, compareErr := client.Compare(
			openLDAPMetaConnectionLocalDN(),
			"uid",
			openLDAPMetaConnectionUID,
		)
		result.compareMatched = matched
		result.compareCode = monitorLDAPResultCode(compareErr)
		result.modifyCode = modifyOpenLDAPMetaConnectionEntry(client)
	}

	result.verification = searchOpenLDAPMetaConnectionEntry(client, []string{"description"})
	return result
}

func searchOpenLDAPMetaConnectionEntry(
	client *ldap.Conn,
	attributes []string,
) openLDAPMetaConnectionSearch {
	result, err := client.Search(ldap.NewSearchRequest(
		openLDAPMetaConnectionLocalDN(),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attributes,
		nil,
	))
	observation := openLDAPMetaConnectionSearch{code: monitorLDAPResultCode(err)}
	if result != nil && len(result.Entries) > 0 {
		observation.dn = strings.ToLower(result.Entries[0].DN)
		if len(attributes) == 1 {
			observation.value = result.Entries[0].GetAttributeValue(attributes[0])
		}
	}
	return observation
}

func modifyOpenLDAPMetaConnectionEntry(client *ldap.Conn) uint16 {
	request := ldap.NewModifyRequest(openLDAPMetaConnectionLocalDN(), nil)
	request.Replace("description", []string{openLDAPMetaConnectionDescription})
	return monitorLDAPResultCode(client.Modify(request))
}

func openLDAPMetaConnectionLocalDN() string {
	return "uid=" + openLDAPMetaConnectionUID + ",ou=people," + openLDAPMetaBaseDN
}

func assertOpenLDAPMetaConnectionLDAPResult(
	t *testing.T,
	got openLDAPMetaConnectionResult,
) {
	t.Helper()
	wantSearch := openLDAPMetaConnectionSearch{
		code:  ldap.LDAPResultSuccess,
		dn:    openLDAPMetaConnectionLocalDN(),
		value: openLDAPMetaConnectionUID,
	}
	want := openLDAPMetaConnectionResult{
		warmup:         wantSearch,
		search:         wantSearch,
		compareCode:    ldap.LDAPResultSuccess,
		compareMatched: true,
		modifyCode:     ldap.LDAPResultSuccess,
		verification: openLDAPMetaConnectionSearch{
			code:  ldap.LDAPResultSuccess,
			dn:    openLDAPMetaConnectionLocalDN(),
			value: openLDAPMetaConnectionDescription,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("back-meta connection LDAP result = %#v, want %#v", got, want)
	}
}

func assertOpenLDAPMetaConnectionCount(
	t *testing.T,
	implementation string,
	got int64,
	test openLDAPMetaConnectionCase,
) {
	t.Helper()
	if test.wantAdditional {
		if got <= 1 {
			t.Fatalf(
				"%s target TCP connections = %d, want more than one while the cached connection is busy",
				implementation,
				got,
			)
		}
		return
	}
	if got != test.wantConnections {
		t.Fatalf(
			"%s target TCP connections = %d, want %d",
			implementation,
			got,
			test.wantConnections,
		)
	}
}

func startOpenLDAPMetaConnectionProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	test openLDAPMetaConnectionCase,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no
%s

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		test.openLDAPDirective,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
	)
	return startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", configuration, "")
}

func startLDAPGoMetaConnectionProxy(
	t *testing.T,
	providerURI string,
	test openLDAPMetaConnectionCase,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaReferenceConfiguration(t, store, "", providerURI, providerURI)
	databaseDN, err := directory.ParseDN("olcDatabase={1}meta,cn=config")
	if err != nil {
		t.Fatalf("parse ldap-go back-meta connection database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, getErr := writer.Get(databaseDN)
		if getErr != nil {
			return getErr
		}
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcDbBindTimeout",
			Values:      stringValues("1000000"),
		})
		if test.ldapGoAttribute != "" {
			entry.Attributes = append(entry.Attributes, directory.Attribute{
				Description: test.ldapGoAttribute,
				Values:      stringValues(test.ldapGoValue),
			})
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure ldap-go back-meta connection lifecycle: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

type openLDAPMetaCountingForwarder struct {
	listener      net.Listener
	upstream      string
	responseDelay time.Duration

	acceptedCount atomic.Int64
	mu            sync.Mutex
	connections   map[net.Conn]struct{}
	stopOnce      sync.Once
	wait          sync.WaitGroup
}

func startOpenLDAPMetaCountingForwarder(
	t *testing.T,
	providerURI string,
	responseDelay time.Duration,
) *openLDAPMetaCountingForwarder {
	t.Helper()
	parsed, err := url.Parse(providerURI)
	if err != nil || parsed.Host == "" {
		t.Fatalf("parse back-meta connection provider URI %q: %v", providerURI, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta connection forwarder: %v", err)
	}
	forwarder := &openLDAPMetaCountingForwarder{
		listener:      listener,
		upstream:      parsed.Host,
		responseDelay: responseDelay,
		connections:   make(map[net.Conn]struct{}),
	}
	forwarder.wait.Add(1)
	go forwarder.serve()
	return forwarder
}

func (forwarder *openLDAPMetaCountingForwarder) uri() string {
	return "ldap://" + forwarder.listener.Addr().String()
}

func (forwarder *openLDAPMetaCountingForwarder) accepted() int64 {
	return forwarder.acceptedCount.Load()
}

func (forwarder *openLDAPMetaCountingForwarder) serve() {
	defer forwarder.wait.Done()
	for {
		connection, err := forwarder.listener.Accept()
		if err != nil {
			return
		}
		forwarder.acceptedCount.Add(1)
		forwarder.track(connection, true)
		forwarder.wait.Add(1)
		go func(connection net.Conn) {
			defer forwarder.wait.Done()
			defer forwarder.track(connection, false)
			forwarder.forward(connection)
		}(connection)
	}
}

func (forwarder *openLDAPMetaCountingForwarder) forward(connection net.Conn) {
	upstream, err := net.DialTimeout("tcp", forwarder.upstream, time.Second)
	if err != nil {
		_ = connection.Close()
		return
	}
	forwarder.track(upstream, true)
	defer forwarder.track(upstream, false)
	defer upstream.Close()
	defer connection.Close()

	requestCopied := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, connection)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		requestCopied <- struct{}{}
	}()
	_, _ = io.Copy(
		openLDAPMetaDelayedWriter{
			writer: connection,
			delay:  forwarder.responseDelay,
		},
		upstream,
	)
	if tcp, ok := connection.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-requestCopied
}

type openLDAPMetaDelayedWriter struct {
	writer io.Writer
	delay  time.Duration
}

func (writer openLDAPMetaDelayedWriter) Write(value []byte) (int, error) {
	if writer.delay > 0 {
		time.Sleep(writer.delay)
	}
	return writer.writer.Write(value)
}

func (forwarder *openLDAPMetaCountingForwarder) track(connection net.Conn, add bool) {
	forwarder.mu.Lock()
	defer forwarder.mu.Unlock()
	if add {
		forwarder.connections[connection] = struct{}{}
	} else {
		delete(forwarder.connections, connection)
	}
}

func (forwarder *openLDAPMetaCountingForwarder) stop() {
	forwarder.stopOnce.Do(func() {
		_ = forwarder.listener.Close()
		forwarder.mu.Lock()
		for connection := range forwarder.connections {
			_ = connection.Close()
		}
		forwarder.mu.Unlock()
		forwarder.wait.Wait()
	})
}
