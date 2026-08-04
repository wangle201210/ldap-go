package server

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaBindPollRemoteBase    = "dc=bindpoll,dc=test"
	openLDAPMetaBindPollProxyPassword = "bindpoll-proxy-secret"
	openLDAPMetaBindPollUserPassword  = "bindpoll-user-secret"
	openLDAPMetaBindPollResponseDelay = 600 * time.Millisecond
	openLDAPMetaBindPollSettleDelay   = 100 * time.Millisecond
)

type openLDAPMetaBindPollOperation string

const (
	openLDAPMetaBindPollSearch openLDAPMetaBindPollOperation = "idassert search"
	openLDAPMetaBindPollBind   openLDAPMetaBindPollOperation = "forwarded bind"
)

type openLDAPMetaBindPollCase struct {
	name               string
	nretries           string
	bindTimeoutMicros  int
	wantBindCode       uint16
	wantBindMinElapsed time.Duration
	wantBindMaxElapsed time.Duration
}

type openLDAPMetaBindPollRequest struct {
	dn       string
	password string
}

type openLDAPMetaBindPollSnapshot struct {
	binds    []openLDAPMetaBindPollRequest
	searches int
}

type openLDAPMetaBindPollOutcome struct {
	operation        openLDAPMetaBindPollOperation
	setupBind        bool
	setupBindCode    uint16
	setupBindBinds   int
	code             uint16
	entries          []string
	upstreamBinds    []openLDAPMetaBindPollRequest
	upstreamSearches int
	elapsed          time.Duration
}

type openLDAPMetaBindPollComparable struct {
	operation        openLDAPMetaBindPollOperation
	setupBind        bool
	setupBindCode    uint16
	setupBindBinds   int
	code             uint16
	entries          []string
	upstreamBinds    []openLDAPMetaBindPollRequest
	upstreamSearches int
}

type openLDAPMetaBindPollProvider struct {
	listener net.Listener
	delay    time.Duration

	mu       sync.Mutex
	binds    []openLDAPMetaBindPollRequest
	searches int
	clients  map[net.Conn]struct{}
	stopped  bool

	firstResponseAttempted chan struct{}
	firstResponseOnce      sync.Once
	stopOnce               sync.Once
	wait                   sync.WaitGroup
}

func TestOpenLDAPReferenceMetaBindPolling(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []openLDAPMetaBindPollCase{
		{
			name:               "never",
			nretries:           "never",
			bindTimeoutMicros:  700000,
			wantBindCode:       ldap.LDAPResultAdminLimitExceeded,
			wantBindMinElapsed: 40 * time.Millisecond,
			wantBindMaxElapsed: 450 * time.Millisecond,
		},
		{
			name:               "one short poll",
			nretries:           "1",
			bindTimeoutMicros:  350000,
			wantBindCode:       ldap.LDAPResultAdminLimitExceeded,
			wantBindMinElapsed: 250 * time.Millisecond,
			wantBindMaxElapsed: 575 * time.Millisecond,
		},
		{
			name:               "one long poll",
			nretries:           "1",
			bindTimeoutMicros:  700000,
			wantBindCode:       ldap.LDAPResultSuccess,
			wantBindMinElapsed: 450 * time.Millisecond,
			wantBindMaxElapsed: 2 * time.Second,
		},
		{
			name:               "two short polls",
			nretries:           "2",
			bindTimeoutMicros:  350000,
			wantBindCode:       ldap.LDAPResultSuccess,
			wantBindMinElapsed: 450 * time.Millisecond,
			wantBindMaxElapsed: 2 * time.Second,
		},
	}

	reference := make(map[string]openLDAPMetaBindPollComparable, len(tests)*2)
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		for _, operation := range []openLDAPMetaBindPollOperation{
			openLDAPMetaBindPollSearch,
			openLDAPMetaBindPollBind,
		} {
			for _, test := range tests {
				key := openLDAPMetaBindPollCaseKey(operation, test)
				t.Run(key, func(t *testing.T) {
					got := runOpenLDAPMetaBindPollScenario(
						t,
						tools,
						false,
						operation,
						test,
					)
					assertOpenLDAPMetaBindPollReference(t, got, operation, test)
					reference[key] = got.comparable()
					t.Logf(
						"OpenLDAP %s nretries=%s bind-timeout=%dus: code=%d elapsed=%s upstream-binds=%d",
						operation,
						test.nretries,
						test.bindTimeoutMicros,
						got.code,
						got.elapsed,
						len(got.upstreamBinds),
					)
				})
			}
		}
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go comparison", func(t *testing.T) {
		for _, operation := range []openLDAPMetaBindPollOperation{
			openLDAPMetaBindPollSearch,
			openLDAPMetaBindPollBind,
		} {
			for _, test := range tests {
				key := openLDAPMetaBindPollCaseKey(operation, test)
				t.Run(key, func(t *testing.T) {
					got := runOpenLDAPMetaBindPollScenario(
						t,
						tools,
						true,
						operation,
						test,
					)
					t.Logf(
						"ldap-go %s nretries=%s bind-timeout=%dus: code=%d elapsed=%s upstream-binds=%d",
						operation,
						test.nretries,
						test.bindTimeoutMicros,
						got.code,
						got.elapsed,
						len(got.upstreamBinds),
					)
					if !reflect.DeepEqual(got.comparable(), reference[key]) {
						t.Fatalf(
							"ldap-go back-meta bind polling differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
							reference[key],
							got.comparable(),
						)
					}
					assertOpenLDAPMetaBindPollTiming(t, got, operation, test)
				})
			}
		}
	})
}

func openLDAPMetaBindPollCaseKey(
	operation openLDAPMetaBindPollOperation,
	test openLDAPMetaBindPollCase,
) string {
	return string(operation) + "/" + test.name
}

func runOpenLDAPMetaBindPollScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
	operation openLDAPMetaBindPollOperation,
	test openLDAPMetaBindPollCase,
) openLDAPMetaBindPollOutcome {
	t.Helper()
	provider := startOpenLDAPMetaBindPollProvider(
		t,
		openLDAPMetaBindPollResponseDelay,
	)
	defer provider.stop()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaBindPollProxy(t, provider.uri(), test)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaBindPollProxy(
			t,
			tools,
			provider.uri(),
			test,
		)
	}
	defer stopProxy()

	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta bind-poll fixture %s: %v", proxyURI, err)
	}
	client.SetTimeout(5 * time.Second)
	defer client.Close()

	outcome := openLDAPMetaBindPollOutcome{operation: operation}
	switch operation {
	case openLDAPMetaBindPollSearch:
		outcome.setupBind = true
		setupStarted := time.Now()
		setupErr := client.Bind(
			"cn=admin,"+openLDAPMetaBaseDN,
			"secret",
		)
		setupElapsed := time.Since(setupStarted)
		outcome.setupBindCode = monitorLDAPResultCode(setupErr)
		outcome.setupBindBinds = len(provider.snapshot().binds)
		if setupElapsed > 2*time.Second {
			t.Fatalf("front-end root Bind took %s, want no more than 2s", setupElapsed)
		}

		started := time.Now()
		result, searchErr := client.Search(ldap.NewSearchRequest(
			openLDAPMetaBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"uid"},
			nil,
		))
		outcome.elapsed = time.Since(started)
		outcome.code = monitorLDAPResultCode(searchErr)
		if result != nil {
			for _, entry := range result.Entries {
				outcome.entries = append(outcome.entries, strings.ToLower(entry.DN))
			}
			sort.Strings(outcome.entries)
		}
	case openLDAPMetaBindPollBind:
		started := time.Now()
		bindErr := client.Bind(
			openLDAPMetaBindPollLocalUserDN(),
			openLDAPMetaBindPollUserPassword,
		)
		outcome.elapsed = time.Since(started)
		outcome.code = monitorLDAPResultCode(bindErr)
	default:
		t.Fatalf("unknown back-meta bind-poll operation %q", operation)
	}

	provider.waitForFirstResponseAttempt(t)
	time.Sleep(openLDAPMetaBindPollSettleDelay)
	snapshot := provider.snapshot()
	outcome.upstreamBinds = snapshot.binds
	outcome.upstreamSearches = snapshot.searches
	return outcome
}

func assertOpenLDAPMetaBindPollReference(
	t *testing.T,
	got openLDAPMetaBindPollOutcome,
	operation openLDAPMetaBindPollOperation,
	test openLDAPMetaBindPollCase,
) {
	t.Helper()
	assertOpenLDAPMetaBindPollTiming(t, got, operation, test)

	wantCode := test.wantBindCode
	wantSearches := 0
	wantEntries := []string(nil)
	wantBind := openLDAPMetaBindPollRequest{
		dn:       openLDAPMetaBindPollRemoteUserDN(),
		password: openLDAPMetaBindPollUserPassword,
	}
	wantSetupBind := false
	if operation == openLDAPMetaBindPollSearch {
		wantCode = ldap.LDAPResultSuccess
		wantSearches = 1
		wantEntries = []string{openLDAPMetaBindPollLocalUserDN()}
		wantBind = openLDAPMetaBindPollRequest{
			dn:       "cn=proxy," + openLDAPMetaBindPollRemoteBase,
			password: openLDAPMetaBindPollProxyPassword,
		}
		wantSetupBind = true
	}
	want := openLDAPMetaBindPollComparable{
		operation:        operation,
		setupBind:        wantSetupBind,
		setupBindCode:    ldap.LDAPResultSuccess,
		setupBindBinds:   0,
		code:             wantCode,
		entries:          wantEntries,
		upstreamBinds:    []openLDAPMetaBindPollRequest{wantBind},
		upstreamSearches: wantSearches,
	}
	if !reflect.DeepEqual(got.comparable(), want) {
		t.Fatalf(
			"OpenLDAP 2.6.13 back-meta bind-poll fixture drifted:\n got: %#v\nwant: %#v",
			got.comparable(),
			want,
		)
	}
}

func assertOpenLDAPMetaBindPollTiming(
	t *testing.T,
	got openLDAPMetaBindPollOutcome,
	operation openLDAPMetaBindPollOperation,
	test openLDAPMetaBindPollCase,
) {
	t.Helper()
	minimum := test.wantBindMinElapsed
	maximum := test.wantBindMaxElapsed
	if operation == openLDAPMetaBindPollSearch {
		minimum = 450 * time.Millisecond
		maximum = 2 * time.Second
	}
	if got.elapsed < minimum || got.elapsed > maximum {
		t.Fatalf(
			"%s nretries=%s bind-timeout=%dus elapsed=%s, want within [%s, %s]",
			operation,
			test.nretries,
			test.bindTimeoutMicros,
			got.elapsed,
			minimum,
			maximum,
		)
	}
}

func (outcome openLDAPMetaBindPollOutcome) comparable() openLDAPMetaBindPollComparable {
	return openLDAPMetaBindPollComparable{
		operation:        outcome.operation,
		setupBind:        outcome.setupBind,
		setupBindCode:    outcome.setupBindCode,
		setupBindBinds:   outcome.setupBindBinds,
		code:             outcome.code,
		entries:          outcome.entries,
		upstreamBinds:    outcome.upstreamBinds,
		upstreamSearches: outcome.upstreamSearches,
	}
}

func openLDAPMetaBindPollLocalUserDN() string {
	return "uid=bindpoll," + openLDAPMetaBaseDN
}

func openLDAPMetaBindPollRemoteUserDN() string {
	return "uid=bindpoll," + openLDAPMetaBindPollRemoteBase
}

func startOpenLDAPMetaBindPollProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	test openLDAPMetaBindPollCase,
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

uri "%s/%s"
suffixmassage "%s" "%s"
idassert-bind bindmethod=simple binddn="cn=proxy,%s" credentials=%s mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		test.bindTimeoutMicros,
		test.nretries,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		openLDAPMetaBindPollRemoteBase,
		openLDAPMetaBindPollRemoteBase,
		openLDAPMetaBindPollProxyPassword,
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

func startLDAPGoMetaBindPollProxy(
	t *testing.T,
	providerURI string,
	test openLDAPMetaBindPollCase,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaBindPollConfiguration(t, store, providerURI, test)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaBindPollConfiguration(
	t *testing.T,
	store storage.Store,
	providerURI string,
	test openLDAPMetaBindPollCase,
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
				{Description: "olcDbBindTimeout", Values: stringValues(strconv.Itoa(test.bindTimeoutMicros))},
				{Description: "olcDbNretries", Values: stringValues(test.nretries)},
				{Description: "olcDbOnErr", Values: stringValues("stop")},
				{Description: "olcDbPseudoRootBindDefer", Values: stringValues("TRUE")},
			},
		},
		{
			DN: "olcMetaSub={0}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(providerURI + "/" + openLDAPMetaBaseDN)},
				{Description: "olcDbRewrite", Values: stringValues(
					"suffixmassage \"" + openLDAPMetaBaseDN + "\" \"" +
						openLDAPMetaBindPollRemoteBase + "\"",
				)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=proxy,` + openLDAPMetaBindPollRemoteBase +
						`" credentials=` + openLDAPMetaBindPollProxyPassword + ` mode=none`,
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
		t.Fatalf("seed ldap-go back-meta bind-poll configuration: %v", err)
	}
}

func startOpenLDAPMetaBindPollProvider(
	t *testing.T,
	delay time.Duration,
) *openLDAPMetaBindPollProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta bind-poll provider: %v", err)
	}
	provider := &openLDAPMetaBindPollProvider{
		listener:               listener,
		delay:                  delay,
		clients:                make(map[net.Conn]struct{}),
		firstResponseAttempted: make(chan struct{}),
	}
	provider.wait.Add(1)
	go provider.accept()
	return provider
}

func (provider *openLDAPMetaBindPollProvider) uri() string {
	return "ldap://" + provider.listener.Addr().String()
}

func (provider *openLDAPMetaBindPollProvider) accept() {
	defer provider.wait.Done()
	for {
		connection, err := provider.listener.Accept()
		if err != nil {
			return
		}
		provider.mu.Lock()
		if provider.stopped {
			provider.mu.Unlock()
			_ = connection.Close()
			return
		}
		provider.clients[connection] = struct{}{}
		provider.wait.Add(1)
		provider.mu.Unlock()
		go provider.serve(connection)
	}
}

func (provider *openLDAPMetaBindPollProvider) serve(connection net.Conn) {
	defer provider.wait.Done()
	defer func() {
		provider.mu.Lock()
		delete(provider.clients, connection)
		provider.mu.Unlock()
		_ = connection.Close()
	}()

	for {
		message, err := ldapwire.ReadMessage(
			connection,
			ldapwire.DefaultMaxMessageSize,
		)
		if err != nil {
			return
		}
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			provider.mu.Lock()
			provider.binds = append(provider.binds, openLDAPMetaBindPollRequest{
				dn:       strings.ToLower(request.Name),
				password: string(request.Authentication.Simple),
			})
			first := len(provider.binds) == 1
			provider.mu.Unlock()

			time.Sleep(provider.delay)
			writeErr := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			))
			if first {
				provider.firstResponseOnce.Do(func() {
					close(provider.firstResponseAttempted)
				})
			}
			if writeErr != nil {
				return
			}
		case ldapwire.SearchRequest:
			provider.mu.Lock()
			provider.searches++
			provider.mu.Unlock()
			entry := directory.Entry{
				DN: openLDAPMetaBindPollRemoteUserDN(),
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("bindpoll")},
					{Description: "cn", Values: stringValues("Bind Poll")},
					{Description: "sn", Values: stringValues("Poll")},
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

func (provider *openLDAPMetaBindPollProvider) snapshot() openLDAPMetaBindPollSnapshot {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return openLDAPMetaBindPollSnapshot{
		binds:    append([]openLDAPMetaBindPollRequest(nil), provider.binds...),
		searches: provider.searches,
	}
}

func (provider *openLDAPMetaBindPollProvider) waitForFirstResponseAttempt(t *testing.T) {
	t.Helper()
	select {
	case <-provider.firstResponseAttempted:
	case <-time.After(provider.delay + 3*time.Second):
		t.Fatal("scripted bind-poll provider did not receive and answer a BindRequest")
	}
}

func (provider *openLDAPMetaBindPollProvider) stop() {
	provider.stopOnce.Do(func() {
		provider.mu.Lock()
		provider.stopped = true
		clients := make([]net.Conn, 0, len(provider.clients))
		for connection := range provider.clients {
			clients = append(clients, connection)
		}
		provider.mu.Unlock()
		_ = provider.listener.Close()
		for _, connection := range clients {
			_ = connection.Close()
		}
		provider.wait.Wait()
	})
}
