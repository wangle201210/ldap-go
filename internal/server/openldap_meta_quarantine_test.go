package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaQuarantineRetry       = 2 * time.Second
	openLDAPMetaQuarantineUID         = "quarantine-live"
	openLDAPMetaQuarantineDescription = "quarantine-provider"
)

type openLDAPMetaQuarantineOutcome struct {
	firstCode                uint16
	firstReachedProvider     bool
	immediateCode            uint16
	immediateReachedProvider bool
	probeCode                uint16
	probeReachedProvider     bool
	postProbeCode            uint16
	postProbeReachedProvider bool
	recoveryCode             uint16
	recoveryEntries          []string
	postRecoveryCode         uint16
	postRecoveryEntries      []string
}

func TestOpenLDAPReferenceMetaQuarantine(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	var reference openLDAPMetaQuarantineOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		reference = runOpenLDAPMetaQuarantineScenario(t, tools, false)
		assertOpenLDAPMetaQuarantineOutcome(t, reference)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go comparison", func(t *testing.T) {
		got := runOpenLDAPMetaQuarantineScenario(t, tools, true)
		assertOpenLDAPMetaQuarantineOutcome(t, got)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go back-meta olcDbQuarantine differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func runOpenLDAPMetaQuarantineScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
) openLDAPMetaQuarantineOutcome {
	t.Helper()
	providerURI, stopProvider := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaQuarantineUID,
		openLDAPMetaQuarantineDescription,
	)
	defer stopProvider()

	gate := startOpenLDAPMetaQuarantineGate(t, providerURI)
	defer gate.stop()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaQuarantineFixture(t, gate.uri())
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaQuarantineProxy(t, tools, gate.uri())
	}
	defer stopProxy()

	first := observeOpenLDAPMetaQuarantineSearch(t, proxyURI)
	firstAttempts := gate.attempts()
	immediate := observeOpenLDAPMetaQuarantineSearch(t, proxyURI)
	immediateAttempts := gate.attempts() - firstAttempts

	time.Sleep(openLDAPMetaQuarantineRetry + 250*time.Millisecond)
	probeStart := gate.attempts()
	probe := observeOpenLDAPMetaQuarantineSearch(t, proxyURI)
	probeAttempts := gate.attempts() - probeStart
	postProbe := observeOpenLDAPMetaQuarantineSearch(t, proxyURI)
	postProbeAttempts := gate.attempts() - probeStart - probeAttempts

	time.Sleep(openLDAPMetaQuarantineRetry + 250*time.Millisecond)
	gate.forward()
	recovery := observeOpenLDAPMetaQuarantineSearch(t, proxyURI)
	postRecovery := observeOpenLDAPMetaQuarantineSearch(t, proxyURI)
	t.Logf(
		"back-meta quarantine TCP attempts: initial=%d backoff=%d probe=%d post-probe=%d",
		firstAttempts,
		immediateAttempts,
		probeAttempts,
		postProbeAttempts,
	)

	return openLDAPMetaQuarantineOutcome{
		firstCode:                first.code,
		firstReachedProvider:     firstAttempts > 0,
		immediateCode:            immediate.code,
		immediateReachedProvider: immediateAttempts > 0,
		probeCode:                probe.code,
		probeReachedProvider:     probeAttempts > 0,
		postProbeCode:            postProbe.code,
		postProbeReachedProvider: postProbeAttempts > 0,
		recoveryCode:             recovery.code,
		recoveryEntries:          metaQuarantineEntry(resultEntries(recovery)),
		postRecoveryCode:         postRecovery.code,
		postRecoveryEntries:      metaQuarantineEntry(resultEntries(postRecovery)),
	}
}

func assertOpenLDAPMetaQuarantineOutcome(
	t *testing.T,
	got openLDAPMetaQuarantineOutcome,
) {
	t.Helper()
	wantEntry := []string{
		"uid=" + openLDAPMetaQuarantineUID + ",ou=people," + openLDAPMetaBaseDN +
			"|" + openLDAPMetaQuarantineDescription,
	}
	if got.firstCode != ldap.LDAPResultUnavailable || !got.firstReachedProvider {
		t.Fatalf("initial quarantine observation = %#v, want an unavailable provider attempt", got)
	}
	if got.immediateCode != ldap.LDAPResultUnavailable || got.immediateReachedProvider {
		t.Fatalf("backoff quarantine observation = %#v, want rejection without provider attempt", got)
	}
	if got.probeCode != ldap.LDAPResultUnavailable || !got.probeReachedProvider {
		t.Fatalf("scheduled quarantine probe = %#v, want one unavailable logical probe", got)
	}
	if got.postProbeCode != ldap.LDAPResultUnavailable || got.postProbeReachedProvider {
		t.Fatalf("post-probe quarantine observation = %#v, want rejection without provider attempt", got)
	}
	if got.recoveryCode != ldap.LDAPResultSuccess ||
		!reflect.DeepEqual(got.recoveryEntries, wantEntry) {
		t.Fatalf("quarantine recovery observation = %#v, want successful provider entry %v", got, wantEntry)
	}
	if got.postRecoveryCode != ldap.LDAPResultSuccess ||
		!reflect.DeepEqual(got.postRecoveryEntries, wantEntry) {
		t.Fatalf("post-recovery observation = %#v, want an immediate successful provider attempt", got)
	}
}

func resultEntries(observation openLDAPMetaSearchObservation) []string {
	if observation.dn == "" {
		return nil
	}
	return []string{observation.dn + "|" + observation.description}
}

func metaQuarantineEntry(entries []string) []string {
	if entries == nil {
		return []string{}
	}
	return entries
}

func observeOpenLDAPMetaQuarantineSearch(
	t *testing.T,
	proxyURI string,
) openLDAPMetaSearchObservation {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Errorf("dial back-meta olcDbQuarantine fixture: %v", err)
		return openLDAPMetaSearchObservation{code: ldap.LDAPResultUnavailable}
	}
	client.SetTimeout(3 * time.Second)
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Errorf("bind back-meta olcDbQuarantine fixture: %v", err)
		return openLDAPMetaSearchObservation{code: monitorLDAPResultCode(err)}
	}
	result, searchErr := client.Search(ldap.NewSearchRequest(
		"uid="+openLDAPMetaQuarantineUID+",ou=people,"+openLDAPMetaBaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	observation := openLDAPMetaSearchObservation{code: monitorLDAPResultCode(searchErr)}
	if result != nil && len(result.Entries) > 0 {
		observation.dn = result.Entries[0].DN
		observation.description = result.Entries[0].GetAttributeValue("description")
	}
	return observation
}

func startOpenLDAPMetaQuarantineProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout 1000000
onerr stop

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"
nretries 0
quarantine 2s,+`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
	)
	return startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", configuration, "")
}

func startLDAPGoMetaQuarantineFixture(
	t *testing.T,
	providerURI string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	databaseDN := "olcDatabase={1}meta,cn=config"
	target := openLDAPMetaOnErrTargetEntry(databaseDN, 0, providerURI)
	target.Attributes = append(target.Attributes,
		directory.Attribute{Description: "olcDbNretries", Values: stringValues("0")},
		directory.Attribute{Description: "olcDbQuarantine", Values: stringValues("2s,+")},
	)
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
				{Description: "olcDbOnErr", Values: stringValues("stop")},
			},
		},
		target,
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta olcDbQuarantine configuration: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

type openLDAPMetaQuarantineGateMode uint8

const (
	openLDAPMetaQuarantineDrop openLDAPMetaQuarantineGateMode = iota
	openLDAPMetaQuarantineForward
)

type openLDAPMetaQuarantineGate struct {
	listener net.Listener
	upstream string

	mode      atomic.Uint32
	attemptsN atomic.Int64

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	stopOnce    sync.Once
	stopped     chan struct{}
	wait        sync.WaitGroup
}

func startOpenLDAPMetaQuarantineGate(
	t *testing.T,
	providerURI string,
) *openLDAPMetaQuarantineGate {
	t.Helper()
	parsed, err := url.Parse(providerURI)
	if err != nil || parsed.Host == "" {
		t.Fatalf("parse quarantine provider URI %q: %v", providerURI, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta quarantine gate: %v", err)
	}
	gate := &openLDAPMetaQuarantineGate{
		listener:    listener,
		upstream:    parsed.Host,
		connections: make(map[net.Conn]struct{}),
		stopped:     make(chan struct{}),
	}
	gate.wait.Add(1)
	go gate.serve()
	return gate
}

func (gate *openLDAPMetaQuarantineGate) uri() string {
	return "ldap://" + gate.listener.Addr().String()
}

func (gate *openLDAPMetaQuarantineGate) attempts() int64 {
	return gate.attemptsN.Load()
}

func (gate *openLDAPMetaQuarantineGate) forward() {
	gate.mode.Store(uint32(openLDAPMetaQuarantineForward))
}

func (gate *openLDAPMetaQuarantineGate) serve() {
	defer gate.wait.Done()
	for {
		connection, err := gate.listener.Accept()
		if err != nil {
			return
		}
		gate.attemptsN.Add(1)
		gate.track(connection, true)
		gate.wait.Add(1)
		go func() {
			defer gate.wait.Done()
			defer gate.track(connection, false)
			gate.handle(connection)
		}()
	}
}

func (gate *openLDAPMetaQuarantineGate) handle(connection net.Conn) {
	switch openLDAPMetaQuarantineGateMode(gate.mode.Load()) {
	case openLDAPMetaQuarantineForward:
		gate.proxy(connection)
	default:
		_ = connection.Close()
	}
}

func (gate *openLDAPMetaQuarantineGate) proxy(connection net.Conn) {
	upstream, err := net.DialTimeout("tcp", gate.upstream, time.Second)
	if err != nil {
		_ = connection.Close()
		return
	}
	gate.track(upstream, true)
	defer gate.track(upstream, false)
	defer upstream.Close()
	defer connection.Close()

	copied := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, connection)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		copied <- struct{}{}
	}()
	_, _ = io.Copy(connection, upstream)
	if tcp, ok := connection.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-copied
}

func (gate *openLDAPMetaQuarantineGate) track(connection net.Conn, add bool) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if add {
		gate.connections[connection] = struct{}{}
	} else {
		delete(gate.connections, connection)
	}
}

func (gate *openLDAPMetaQuarantineGate) stop() {
	gate.stopOnce.Do(func() {
		close(gate.stopped)
		_ = gate.listener.Close()
		gate.mu.Lock()
		for connection := range gate.connections {
			_ = connection.Close()
		}
		gate.mu.Unlock()
		gate.wait.Wait()
	})
}
