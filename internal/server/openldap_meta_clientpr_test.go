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

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaClientPRRemoteBase = "dc=example,dc=com"
	openLDAPMetaClientPRPageSize   = 2
	openLDAPMetaClientPREntryCount = 5
)

type openLDAPMetaClientPRUpstreamRequest struct {
	pagingControls int
	critical       bool
	hasValue       bool
	size           int
	cookie         string
	decodeError    string
}

type openLDAPMetaClientPROutcome struct {
	code           int64
	entries        []string
	responsePaging bool
	upstream       []openLDAPMetaClientPRUpstreamRequest
}

func TestOpenLDAPReferenceMetaClientPR(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []struct {
		name                       string
		configuration              string
		unsolicited                bool
		initialUnsolicitedPageSize int
		clientPaging               bool
		wantCode                   uint16
		wantEntryCount             int
		wantUpstreamCalls          []openLDAPMetaClientPRUpstreamRequest
	}{
		{
			name:           "positive page size aggregates and replaces client control",
			configuration:  "2",
			clientPaging:   true,
			wantCode:       ldap.LDAPResultSuccess,
			wantEntryCount: openLDAPMetaClientPREntryCount,
			wantUpstreamCalls: []openLDAPMetaClientPRUpstreamRequest{
				openLDAPMetaClientPRPagedCall(""),
				openLDAPMetaClientPRPagedCall("2"),
				openLDAPMetaClientPRPagedCall("4"),
			},
		},
		{
			name:                       "disable rejects unsolicited paged response",
			configuration:              "disable",
			unsolicited:                true,
			initialUnsolicitedPageSize: 0,
			wantCode:                   ldap.LDAPResultOther,
			wantEntryCount:             0,
			wantUpstreamCalls: []openLDAPMetaClientPRUpstreamRequest{
				{},
			},
		},
		{
			name:                       "accept unsolicited continues with returned cookie",
			configuration:              "accept-unsolicited",
			unsolicited:                true,
			initialUnsolicitedPageSize: openLDAPMetaClientPRPageSize,
			wantCode:                   ldap.LDAPResultSuccess,
			wantEntryCount:             openLDAPMetaClientPREntryCount,
			wantUpstreamCalls: []openLDAPMetaClientPRUpstreamRequest{
				{},
				openLDAPMetaClientPRPagedCall("2"),
				openLDAPMetaClientPRPagedCall("4"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := openLDAPMetaClientPROutcome{
				code:           int64(test.wantCode),
				entries:        openLDAPMetaClientPRLocalDNs(test.wantEntryCount),
				responsePaging: false,
				upstream:       test.wantUpstreamCalls,
			}
			reference := runOpenLDAPMetaClientPRScenario(
				t,
				tools,
				false,
				test.configuration,
				test.unsolicited,
				test.initialUnsolicitedPageSize,
				test.clientPaging,
			)
			if !reflect.DeepEqual(reference, want) {
				t.Fatalf(
					"OpenLDAP 2.6.13 back-meta client-pr fixture drifted:\n got: %#v\nwant: %#v",
					reference,
					want,
				)
			}

			got := runOpenLDAPMetaClientPRScenario(
				t,
				tools,
				true,
				test.configuration,
				test.unsolicited,
				test.initialUnsolicitedPageSize,
				test.clientPaging,
			)
			if !reflect.DeepEqual(got, reference) {
				t.Fatalf(
					"ldap-go back-meta olcDbClientPr differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
					reference,
					got,
				)
			}
		})
	}
}

func openLDAPMetaClientPRPagedCall(
	cookie string,
) openLDAPMetaClientPRUpstreamRequest {
	return openLDAPMetaClientPRUpstreamRequest{
		pagingControls: 1,
		critical:       true,
		hasValue:       true,
		size:           openLDAPMetaClientPRPageSize,
		cookie:         cookie,
	}
}

func openLDAPMetaClientPRLocalDNs(count int) []string {
	if count == 0 {
		return nil
	}
	dns := make([]string, count)
	for index := range count {
		dns[index] = fmt.Sprintf(
			"uid=client-pr-%d,%s",
			index,
			openLDAPMetaBaseDN,
		)
	}
	sort.Strings(dns)
	return dns
}

func runOpenLDAPMetaClientPRScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
	configuration string,
	unsolicited bool,
	initialUnsolicitedPageSize int,
	clientPaging bool,
) openLDAPMetaClientPROutcome {
	t.Helper()
	providerURI, provider, stopProvider := startOpenLDAPMetaClientPRProvider(
		t,
		unsolicited,
		initialUnsolicitedPageSize,
	)
	defer stopProvider()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaClientPRFixture(
			t,
			providerURI,
			configuration,
		)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaClientPRProxy(
			t,
			tools,
			providerURI,
			configuration,
		)
	}
	defer stopProxy()

	outcome := observeOpenLDAPMetaClientPR(t, proxyURI, clientPaging)
	outcome.upstream = provider.snapshot()
	return outcome
}

func startOpenLDAPMetaClientPRProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	configuration string,
) (string, func()) {
	t.Helper()
	proxyConfiguration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no
onerr stop

uri "%s/%s"
suffixmassage "%s" "%s"
client-pr %s
idassert-bind bindmethod=simple binddn="cn=admin,%s" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		openLDAPMetaClientPRRemoteBase,
		configuration,
		openLDAPMetaClientPRRemoteBase,
	)
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		proxyConfiguration,
		"",
	)
}

func startLDAPGoMetaClientPRFixture(
	t *testing.T,
	providerURI string,
	configuration string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaClientPRConfiguration(
		t,
		store,
		providerURI,
		configuration,
	)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaClientPRConfiguration(
	t *testing.T,
	store storage.Store,
	providerURI string,
	configuration string,
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
				{Description: "olcDbNretries", Values: stringValues("1")},
				{Description: "olcDbOnErr", Values: stringValues("stop")},
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
						openLDAPMetaClientPRRemoteBase + "\"",
				)},
				{Description: "olcDbClientPr", Values: stringValues(configuration)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=admin,` + openLDAPMetaClientPRRemoteBase +
						`" credentials=secret mode=none`,
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
		t.Fatalf("seed ldap-go back-meta client-pr configuration: %v", err)
	}
}

func observeOpenLDAPMetaClientPR(
	t *testing.T,
	proxyURI string,
	clientPaging bool,
) openLDAPMetaClientPROutcome {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(proxyURI, "ldap://"),
		"cn=admin,"+openLDAPMetaBaseDN,
		"secret",
	)
	defer connection.Close()

	request := rawChildrenScopeSearchRequest(
		t,
		openLDAPMetaBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		"(objectClass=*)",
		[]string{"uid"},
	)
	if clientPaging {
		writeRawLDAPRequest(
			t,
			connection,
			2,
			request,
			encodeRawLDAPControl(ldapwire.Control{
				OID:      pagedResultsControlOID,
				Critical: true,
				Value: ldapwire.EncodePagedResultsValue(
					99,
					[]byte("client-cookie"),
				),
				HasValue: true,
			}),
		)
	} else {
		writeRawLDAPRequest(t, connection, 2, request)
	}
	observation := readChildrenScopeSearchResponse(t, connection)
	outcome := openLDAPMetaClientPROutcome{
		code: int64(observation.resultCode),
	}
	for _, entry := range observation.entries {
		outcome.entries = append(outcome.entries, entry.dn)
	}
	sort.Strings(outcome.entries)
	_, outcome.responsePaging = observation.controls[pagedResultsControlOID]
	return outcome
}

type openLDAPMetaClientPRProvider struct {
	listener                   net.Listener
	unsolicited                bool
	initialUnsolicitedPageSize int
	entries                    []directory.Entry

	mu       sync.Mutex
	requests []openLDAPMetaClientPRUpstreamRequest
	clients  map[net.Conn]struct{}
	stopped  bool
	wg       sync.WaitGroup
}

func startOpenLDAPMetaClientPRProvider(
	t *testing.T,
	unsolicited bool,
	initialUnsolicitedPageSize int,
) (string, *openLDAPMetaClientPRProvider, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta client-pr provider: %v", err)
	}
	provider := &openLDAPMetaClientPRProvider{
		listener:                   listener,
		unsolicited:                unsolicited,
		initialUnsolicitedPageSize: initialUnsolicitedPageSize,
		entries:                    openLDAPMetaClientPRRemoteEntries(),
		clients:                    make(map[net.Conn]struct{}),
	}
	provider.wg.Add(1)
	go provider.accept()
	var once sync.Once
	stop := func() {
		once.Do(provider.stop)
	}
	return "ldap://" + listener.Addr().String(), provider, stop
}

func openLDAPMetaClientPRRemoteEntries() []directory.Entry {
	entries := make([]directory.Entry, openLDAPMetaClientPREntryCount)
	for index := range openLDAPMetaClientPREntryCount {
		uid := fmt.Sprintf("client-pr-%d", index)
		entries[index] = directory.Entry{
			DN: "uid=" + uid + "," + openLDAPMetaClientPRRemoteBase,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues(uid)},
				{Description: "cn", Values: stringValues(uid)},
				{Description: "sn", Values: stringValues(uid)},
			},
		}
	}
	return entries
}

func (provider *openLDAPMetaClientPRProvider) accept() {
	defer provider.wg.Done()
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
		provider.wg.Add(1)
		provider.mu.Unlock()
		go provider.serve(connection)
	}
}

func (provider *openLDAPMetaClientPRProvider) serve(connection net.Conn) {
	defer provider.wg.Done()
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
		switch message.Request.(type) {
		case ldapwire.BindRequest:
			if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)); err != nil {
				return
			}
		case ldapwire.SearchRequest:
			if err := provider.serveSearch(connection, message); err != nil {
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

func (provider *openLDAPMetaClientPRProvider) serveSearch(
	connection net.Conn,
	message ldapwire.Message,
) error {
	observation := openLDAPMetaClientPRUpstreamRequest{}
	var paging *ldapwire.Control
	for index := range message.Controls {
		control := &message.Controls[index]
		if control.OID != pagedResultsControlOID {
			continue
		}
		observation.pagingControls++
		if paging == nil {
			paging = control
		}
	}

	pageSize := len(provider.entries)
	offset := 0
	if paging != nil {
		observation.critical = paging.Critical
		observation.hasValue = paging.HasValue
		size, cookie, err := ldapwire.DecodePagedResultsValue(paging.Value)
		if err != nil {
			observation.decodeError = err.Error()
		} else {
			observation.size = size
			observation.cookie = string(cookie)
			if size > 0 {
				pageSize = size
			}
			if len(cookie) > 0 {
				if parsed, parseErr := strconv.Atoi(string(cookie)); parseErr == nil {
					offset = parsed
				}
			}
		}
	} else if provider.unsolicited {
		pageSize = provider.initialUnsolicitedPageSize
	}
	provider.mu.Lock()
	provider.requests = append(provider.requests, observation)
	provider.mu.Unlock()

	if observation.decodeError != "" {
		return ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultOther, observation.decodeError),
			nil,
		))
	}
	if offset < 0 || offset > len(provider.entries) {
		offset = len(provider.entries)
	}
	end := min(offset+pageSize, len(provider.entries))
	for _, entry := range provider.entries[offset:end] {
		if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
			message.ID,
			entry,
			nil,
		)); err != nil {
			return err
		}
	}

	var responseControls []ldapwire.Control
	if paging != nil || provider.unsolicited {
		var cookie []byte
		if end < len(provider.entries) {
			cookie = []byte(strconv.Itoa(end))
		}
		responseControls = []ldapwire.Control{{
			OID: pagedResultsControlOID,
			Value: ldapwire.EncodePagedResultsValue(
				openLDAPMetaClientPRPageSize,
				cookie,
			),
			HasValue: true,
		}}
	}
	return ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		responseControls,
	))
}

func (provider *openLDAPMetaClientPRProvider) snapshot() []openLDAPMetaClientPRUpstreamRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]openLDAPMetaClientPRUpstreamRequest(nil), provider.requests...)
}

func (provider *openLDAPMetaClientPRProvider) stop() {
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
	provider.wg.Wait()
}
