package server

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaPseudoRootPassword      = "meta-root-secret"
	openLDAPMetaPseudoRootProxyPassword = "target-proxy-secret"
	openLDAPMetaPseudoRootSpecificBase  = "ou=team," + openLDAPMetaBaseDN
)

type openLDAPMetaPseudoRootCase struct {
	name              string
	deferBind         bool
	unavailableTarget bool
}

type openLDAPMetaPseudoRootBind struct {
	dn       string
	password string
}

type openLDAPMetaPseudoRootUpstreamSnapshot struct {
	connections int
	binds       []openLDAPMetaPseudoRootBind
	searchBases []string
}

type openLDAPMetaPseudoRootOutcome struct {
	bindCode    uint16
	afterBind   [2]openLDAPMetaPseudoRootUpstreamSnapshot
	searchCode  uint16
	searchDNs   []string
	afterSearch [2]openLDAPMetaPseudoRootUpstreamSnapshot
}

type openLDAPMetaPseudoRootTarget struct {
	label      string
	localBase  string
	remoteBase string
	adminDN    string
	bindResult ldapwire.ResultCode
	listener   net.Listener

	mu          sync.Mutex
	connections int
	binds       []openLDAPMetaPseudoRootBind
	searchBases []string
	clients     map[net.Conn]struct{}
	stopped     bool
	stopOnce    sync.Once
	wait        sync.WaitGroup
}

func TestOpenLDAPReferenceMetaPseudoRootBindDefer(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []openLDAPMetaPseudoRootCase{
		{name: "immediate bind all targets", deferBind: false},
		{name: "deferred bind all targets", deferBind: true},
		{
			name:              "immediate bind with unavailable target",
			deferBind:         false,
			unavailableTarget: true,
		},
		{
			name:              "deferred bind with unavailable target",
			deferBind:         true,
			unavailableTarget: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := runOpenLDAPMetaPseudoRootScenario(t, tools, test, false)
			assertOpenLDAPMetaPseudoRootReference(t, test, want)
			t.Logf("OpenLDAP pseudoroot observation: %#v", want)

			got := runOpenLDAPMetaPseudoRootScenario(t, tools, test, true)
			t.Logf("ldap-go pseudoroot observation: %#v", got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf(
					"ldap-go pseudoroot bind behavior differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
					want,
					got,
				)
			}
		})
	}
}

func runOpenLDAPMetaPseudoRootScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	test openLDAPMetaPseudoRootCase,
	ldapGo bool,
) openLDAPMetaPseudoRootOutcome {
	t.Helper()
	targetOne := startOpenLDAPMetaPseudoRootTarget(
		t,
		"one",
		openLDAPMetaBaseDN,
		"dc=pseudoroot-one,dc=test",
		ldapwire.ResultSuccess,
	)
	defer targetOne.stop()
	targetTwoResult := ldapwire.ResultSuccess
	if test.unavailableTarget {
		targetTwoResult = ldapwire.ResultUnavailable
	}
	targetTwo := startOpenLDAPMetaPseudoRootTarget(
		t,
		"two",
		openLDAPMetaPseudoRootSpecificBase,
		"ou=people,dc=pseudoroot-two,dc=test",
		targetTwoResult,
	)
	defer targetTwo.stop()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaPseudoRootProxy(
			t,
			test.deferBind,
			targetOne,
			targetTwo,
		)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaPseudoRootProxy(
			t,
			tools,
			test.deferBind,
			targetOne,
			targetTwo,
		)
	}
	defer stopProxy()

	return observeOpenLDAPMetaPseudoRoot(t, proxyURI, targetOne, targetTwo)
}

func observeOpenLDAPMetaPseudoRoot(
	t *testing.T,
	proxyURI string,
	targetOne *openLDAPMetaPseudoRootTarget,
	targetTwo *openLDAPMetaPseudoRootTarget,
) openLDAPMetaPseudoRootOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta pseudoroot fixture %s: %v", proxyURI, err)
	}
	client.SetTimeout(10 * time.Second)
	defer client.Close()

	outcome := openLDAPMetaPseudoRootOutcome{}
	bindErr := client.Bind(
		"cn=admin,"+openLDAPMetaBaseDN,
		openLDAPMetaPseudoRootPassword,
	)
	outcome.bindCode = monitorLDAPResultCode(bindErr)
	outcome.afterBind = [2]openLDAPMetaPseudoRootUpstreamSnapshot{
		targetOne.snapshot(),
		targetTwo.snapshot(),
	}

	search, searchErr := client.Search(ldap.NewSearchRequest(
		openLDAPMetaBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	outcome.searchCode = monitorLDAPResultCode(searchErr)
	if search != nil {
		for _, entry := range search.Entries {
			outcome.searchDNs = append(outcome.searchDNs, entry.DN)
		}
		sort.Strings(outcome.searchDNs)
	}
	outcome.afterSearch = [2]openLDAPMetaPseudoRootUpstreamSnapshot{
		targetOne.snapshot(),
		targetTwo.snapshot(),
	}
	return outcome
}

func assertOpenLDAPMetaPseudoRootReference(
	t *testing.T,
	test openLDAPMetaPseudoRootCase,
	got openLDAPMetaPseudoRootOutcome,
) {
	t.Helper()
	wantBindCode := uint16(ldap.LDAPResultSuccess)
	if test.unavailableTarget && !test.deferBind {
		wantBindCode = ldap.LDAPResultUnavailable
	}
	wantAfterBindConnections := 1
	if test.deferBind {
		wantAfterBindConnections = 0
	}
	wantAfterSearchConnections := 2
	if test.deferBind {
		wantAfterSearchConnections = 1
	}
	wantDNs := []string{"uid=pseudoroot-one," + openLDAPMetaBaseDN}
	if !test.unavailableTarget {
		wantDNs = append(wantDNs, "uid=pseudoroot-two,"+openLDAPMetaPseudoRootSpecificBase)
		sort.Strings(wantDNs)
	}
	want := openLDAPMetaPseudoRootOutcome{
		bindCode:   wantBindCode,
		searchCode: ldap.LDAPResultSuccess,
		searchDNs:  wantDNs,
	}
	for index := range want.afterBind {
		want.afterBind[index] = openLDAPMetaPseudoRootExpectedSnapshot(
			index,
			wantAfterBindConnections,
			0,
		)
		searches := 1
		if index == 1 && test.unavailableTarget {
			searches = 0
		}
		want.afterSearch[index] = openLDAPMetaPseudoRootExpectedSnapshot(
			index,
			wantAfterSearchConnections,
			searches,
		)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP 2.6.13 pseudoroot fixture drifted:\n got: %#v\nwant: %#v",
			got,
			want,
		)
	}
}

func openLDAPMetaPseudoRootExpectedSnapshot(
	index int,
	connections int,
	searches int,
) openLDAPMetaPseudoRootUpstreamSnapshot {
	remoteBase := "dc=pseudoroot-one,dc=test"
	if index == 1 {
		remoteBase = "ou=people,dc=pseudoroot-two,dc=test"
	}
	snapshot := openLDAPMetaPseudoRootUpstreamSnapshot{connections: connections}
	for range connections {
		snapshot.binds = append(snapshot.binds, openLDAPMetaPseudoRootBind{
			dn:       "cn=proxy," + remoteBase,
			password: openLDAPMetaPseudoRootProxyPassword,
		})
	}
	for range searches {
		snapshot.searchBases = append(snapshot.searchBases, remoteBase)
	}
	return snapshot
}

func startOpenLDAPMetaPseudoRootProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	deferBind bool,
	targetOne *openLDAPMetaPseudoRootTarget,
	targetTwo *openLDAPMetaPseudoRootTarget,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw %s
access to * by * write
network-timeout 1
bind-timeout 1000000
nretries 0
chase-referrals no
onerr continue
pseudoroot-bind-defer %s

%s

%s`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		openLDAPMetaPseudoRootPassword,
		openLDAPMetaPseudoRootBoolean(deferBind),
		openLDAPMetaPseudoRootTargetConfiguration(targetOne),
		openLDAPMetaPseudoRootTargetConfiguration(targetTwo),
	)
	return startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", configuration, "")
}

func openLDAPMetaPseudoRootTargetConfiguration(
	target *openLDAPMetaPseudoRootTarget,
) string {
	return fmt.Sprintf(`uri "%s/%s"
suffixmassage "%s" "%s"
idassert-bind bindmethod=simple binddn="%s" credentials=%s mode=none
idassert-authzFrom "*"`,
		target.uri(),
		target.localBase,
		target.localBase,
		target.remoteBase,
		target.adminDN,
		openLDAPMetaPseudoRootProxyPassword,
	)
}

func startLDAPGoMetaPseudoRootProxy(
	t *testing.T,
	deferBind bool,
	targetOne *openLDAPMetaPseudoRootTarget,
	targetTwo *openLDAPMetaPseudoRootTarget,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaPseudoRootConfiguration(t, store, deferBind, targetOne, targetTwo)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaPseudoRootConfiguration(
	t *testing.T,
	store storage.Store,
	deferBind bool,
	targets ...*openLDAPMetaPseudoRootTarget,
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
				{Description: "olcRootPW", Values: stringValues(openLDAPMetaPseudoRootPassword)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbNretries", Values: stringValues("0")},
				{Description: "olcDbOnErr", Values: stringValues("continue")},
				{Description: "olcDbPseudoRootBindDefer", Values: stringValues(openLDAPMetaPseudoRootBoolean(deferBind))},
			},
		},
	}
	for index, target := range targets {
		entries = append(entries, directory.Entry{
			DN: fmt.Sprintf("olcMetaSub={%d}uri,%s", index, databaseDN),
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues(fmt.Sprintf("{%d}uri", index))},
				{Description: "olcDbURI", Values: stringValues(target.uri() + "/" + target.localBase)},
				{Description: "olcDbRewrite", Values: stringValues(
					"suffixmassage \"" + target.localBase + "\" \"" + target.remoteBase + "\"",
				)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="` + target.adminDN + `" credentials=` +
						openLDAPMetaPseudoRootProxyPassword + ` mode=none`,
				)},
				{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
			},
		})
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta pseudoroot configuration: %v", err)
	}
}

func openLDAPMetaPseudoRootBoolean(value bool) string {
	if value {
		return "TRUE"
	}
	return "FALSE"
}

func startOpenLDAPMetaPseudoRootTarget(
	t *testing.T,
	label string,
	localBase string,
	remoteBase string,
	bindResult ldapwire.ResultCode,
) *openLDAPMetaPseudoRootTarget {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta pseudoroot target %s: %v", label, err)
	}
	target := &openLDAPMetaPseudoRootTarget{
		label:      label,
		localBase:  localBase,
		remoteBase: remoteBase,
		adminDN:    "cn=proxy," + remoteBase,
		bindResult: bindResult,
		listener:   listener,
		clients:    make(map[net.Conn]struct{}),
	}
	target.wait.Add(1)
	go target.accept()
	return target
}

func (target *openLDAPMetaPseudoRootTarget) uri() string {
	return "ldap://" + target.listener.Addr().String()
}

func (target *openLDAPMetaPseudoRootTarget) accept() {
	defer target.wait.Done()
	for {
		connection, err := target.listener.Accept()
		if err != nil {
			return
		}
		target.mu.Lock()
		if target.stopped {
			target.mu.Unlock()
			_ = connection.Close()
			return
		}
		target.connections++
		target.clients[connection] = struct{}{}
		target.wait.Add(1)
		target.mu.Unlock()
		go target.serve(connection)
	}
}

func (target *openLDAPMetaPseudoRootTarget) serve(connection net.Conn) {
	defer target.wait.Done()
	defer func() {
		target.mu.Lock()
		delete(target.clients, connection)
		target.mu.Unlock()
		_ = connection.Close()
	}()

	for {
		message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			return
		}
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			target.mu.Lock()
			target.binds = append(target.binds, openLDAPMetaPseudoRootBind{
				dn:       request.Name,
				password: string(request.Authentication.Simple),
			})
			target.mu.Unlock()
			result := ldapwire.Result{Code: target.bindResult}
			if target.bindResult != ldapwire.ResultSuccess {
				result.DiagnosticMessage = "scripted target unavailable"
			}
			if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				result,
				nil,
			)); err != nil {
				return
			}
		case ldapwire.SearchRequest:
			target.mu.Lock()
			target.searchBases = append(target.searchBases, request.BaseDN)
			target.mu.Unlock()
			entry := directory.Entry{
				DN: "uid=pseudoroot-" + target.label + "," + target.remoteBase,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("pseudoroot-" + target.label)},
					{Description: "description", Values: stringValues("target-" + target.label)},
				},
			}
			if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
				message.ID,
				entry,
				nil,
			)); err != nil {
				return
			}
			if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)); err != nil {
				return
			}
		case ldapwire.UnbindRequest:
			return
		case ldapwire.AbandonRequest:
			continue
		default:
			return
		}
	}
}

func (target *openLDAPMetaPseudoRootTarget) snapshot() openLDAPMetaPseudoRootUpstreamSnapshot {
	target.mu.Lock()
	defer target.mu.Unlock()
	return openLDAPMetaPseudoRootUpstreamSnapshot{
		connections: target.connections,
		binds:       append([]openLDAPMetaPseudoRootBind(nil), target.binds...),
		searchBases: append([]string(nil), target.searchBases...),
	}
}

func (target *openLDAPMetaPseudoRootTarget) stop() {
	target.stopOnce.Do(func() {
		target.mu.Lock()
		target.stopped = true
		clients := make([]net.Conn, 0, len(target.clients))
		for connection := range target.clients {
			clients = append(clients, connection)
		}
		target.mu.Unlock()
		_ = target.listener.Close()
		for _, connection := range clients {
			_ = connection.Close()
		}
		target.wait.Wait()
	})
}
