package server

import (
	"context"
	"fmt"
	"net"
	"reflect"
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
	openLDAPMetaCancelRemoteBase = "dc=example,dc=com"
	openLDAPMetaCancelWhoAmIOID  = "1.3.6.1.4.1.4203.1.11.3"
)

type openLDAPMetaCancelSignal string

const (
	openLDAPMetaCancelAbandon openLDAPMetaCancelSignal = "abandon"
	openLDAPMetaCancelRFC3909 openLDAPMetaCancelSignal = "rfc3909-cancel"
)

type openLDAPMetaCancelCase struct {
	name              string
	mode              string
	discoverExtension bool
	wantActionTag     uint64
	wantActionOID     string
	wantDiscovery     bool
}

type openLDAPMetaCancelUpstreamRequest struct {
	connectionID    int64
	messageID       int64
	tag             uint64
	oid             string
	targetMessageID int64
	baseDN          string
	scope           directory.Scope
	decodeError     string
}

type openLDAPMetaCancelAction struct {
	tag                 uint64
	oid                 string
	targetsLongSearch   bool
	messageIDIsDistinct bool
}

type openLDAPMetaCancelUpstreamObservation struct {
	actions           []openLDAPMetaCancelAction
	discoveryObserved bool
}

type openLDAPMetaCancelFrontendResponse struct {
	messageID int64
	tag       uint64
	code      int64
}

type openLDAPMetaCancelFrontendObservation struct {
	initialEntries      []string
	originalDone        bool
	originalCode        int64
	cancelResponse      bool
	cancelCode          int64
	followupDone        bool
	followupCode        int64
	followupEntries     []string
	whoAmIResponse      bool
	whoAmICode          int64
	unexpectedResponses []openLDAPMetaCancelFrontendResponse
}

type openLDAPMetaCancelOutcome struct {
	upstream openLDAPMetaCancelUpstreamObservation
	frontend openLDAPMetaCancelFrontendObservation
	trace    []openLDAPMetaCancelUpstreamRequest
}

func TestOpenLDAPReferenceMetaCancel(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	tests := []openLDAPMetaCancelCase{
		{
			name:          "abandon",
			mode:          "abandon",
			wantActionTag: ldapwire.ApplicationAbandonRequest,
		},
		{
			name:          "exop",
			mode:          "exop",
			wantActionTag: ldapwire.ApplicationExtendedRequest,
			wantActionOID: cancelOID,
		},
		{
			name: "ignore",
			mode: "ignore",
		},
		{
			name:              "exop-discover supported",
			mode:              "exop-discover",
			discoverExtension: true,
			wantActionTag:     ldapwire.ApplicationExtendedRequest,
			wantActionOID:     cancelOID,
			wantDiscovery:     true,
		},
		{
			name:          "exop-discover unsupported",
			mode:          "exop-discover",
			wantActionTag: ldapwire.ApplicationAbandonRequest,
			wantDiscovery: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, signal := range []openLDAPMetaCancelSignal{
				openLDAPMetaCancelAbandon,
				openLDAPMetaCancelRFC3909,
			} {
				t.Run(string(signal), func(t *testing.T) {
					var reference openLDAPMetaCancelOutcome
					t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
						reference = runOpenLDAPMetaCancelScenario(
							t,
							tools,
							test,
							signal,
							false,
						)
						assertOpenLDAPMetaCancelReference(t, test, signal, reference)
						t.Logf("OpenLDAP upstream trace: %#v", reference.trace)
					})
					if t.Failed() {
						return
					}

					t.Run("ldap-go differential", func(t *testing.T) {
						got := runOpenLDAPMetaCancelScenario(
							t,
							tools,
							test,
							signal,
							true,
						)
						t.Logf("ldap-go upstream trace: %#v", got.trace)
						if !reflect.DeepEqual(got.upstream, reference.upstream) ||
							!reflect.DeepEqual(got.frontend, reference.frontend) {
							t.Fatalf(
								"ldap-go back-meta olcDbCancel differs from OpenLDAP 2.6.13:\nOpenLDAP: upstream=%#v frontend=%#v trace=%#v\nldap-go:  upstream=%#v frontend=%#v trace=%#v",
								reference.upstream,
								reference.frontend,
								reference.trace,
								got.upstream,
								got.frontend,
								got.trace,
							)
						}
					})
				})
			}
		})
	}
}

func runOpenLDAPMetaCancelScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	test openLDAPMetaCancelCase,
	signal openLDAPMetaCancelSignal,
	ldapGo bool,
) openLDAPMetaCancelOutcome {
	t.Helper()
	providerURI, provider, stopProvider := startOpenLDAPMetaCancelProvider(
		t,
		test.discoverExtension,
	)
	defer stopProvider()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaCancelProxy(t, providerURI, test.mode)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaCancelProxy(
			t,
			tools,
			providerURI,
			test.mode,
		)
	}
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(stopProxy) }
	defer stop()

	frontend := observeOpenLDAPMetaCancellation(
		t,
		proxyURI,
		provider,
		signal,
	)
	if signal == openLDAPMetaCancelAbandon && test.wantActionTag != 0 {
		provider.waitForCancellationActionOrLongConnectionClose(t)
	}
	stop()
	provider.waitForNoClients(t)
	trace := provider.snapshot()
	return openLDAPMetaCancelOutcome{
		upstream: summarizeOpenLDAPMetaCancelUpstream(t, trace),
		frontend: frontend,
		trace:    trace,
	}
}

func startOpenLDAPMetaCancelProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	mode string,
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
onerr stop

uri "%s/%s"
suffixmassage "%s" "%s"
cancel %s
idassert-bind bindmethod=simple binddn="cn=admin,%s" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		openLDAPMetaCancelRemoteBase,
		mode,
		openLDAPMetaCancelRemoteBase,
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

func startLDAPGoMetaCancelProxy(
	t *testing.T,
	providerURI string,
	mode string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaCancelConfiguration(t, store, providerURI, mode)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaCancelConfiguration(
	t *testing.T,
	store storage.Store,
	providerURI string,
	mode string,
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
						openLDAPMetaCancelRemoteBase + "\"",
				)},
				{Description: "olcDbCancel", Values: stringValues(mode)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=admin,` + openLDAPMetaCancelRemoteBase +
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
		t.Fatalf("seed ldap-go back-meta cancel configuration: %v", err)
	}
}

func observeOpenLDAPMetaCancellation(
	t *testing.T,
	proxyURI string,
	provider *openLDAPMetaCancelProvider,
	signal openLDAPMetaCancelSignal,
) openLDAPMetaCancelFrontendObservation {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(proxyURI, "ldap://"),
		"cn=admin,"+openLDAPMetaBaseDN,
		"secret",
	)
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set back-meta cancel client deadline: %v", err)
	}

	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawChildrenScopeSearchRequest(
			t,
			openLDAPMetaBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			"(uid=never-completes)",
			[]string{"uid"},
		),
	)
	provider.waitForLongSearch(t)
	initialEntry := readOpenLDAPMetaCancelInitialEntry(t, connection)

	switch signal {
	case openLDAPMetaCancelAbandon:
		writeRawLDAPRequest(t, connection, 3, rawAbandonRequest(2))
	case openLDAPMetaCancelRFC3909:
		writeRawLDAPRequest(
			t,
			connection,
			3,
			rawExtendedRequest(
				cancelOID,
				ldapwire.EncodeCancelRequestValue(2),
				true,
			),
		)
	default:
		t.Fatalf("unknown back-meta cancellation signal %q", signal)
	}
	observation := readOpenLDAPMetaCancelCancellationResponses(
		t,
		connection,
		signal,
	)
	observation.initialEntries = []string{initialEntry}

	writeRawLDAPRequest(
		t,
		connection,
		4,
		rawChildrenScopeSearchRequest(
			t,
			openLDAPMetaBaseDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			"(objectClass=*)",
			[]string{"dc"},
		),
	)
	readOpenLDAPMetaCancelFollowupResponses(t, connection, &observation)

	writeRawLDAPRequest(
		t,
		connection,
		5,
		rawExtendedRequest(openLDAPMetaCancelWhoAmIOID, nil, false),
	)
	for !observation.whoAmIResponse {
		response := readOpenLDAPMetaCancelFrontendResponse(t, connection)
		if response.messageID == 5 &&
			response.tag == ldapwire.ApplicationExtendedResponse {
			observation.whoAmIResponse = true
			observation.whoAmICode = response.code
			continue
		}
		observation.unexpectedResponses = append(
			observation.unexpectedResponses,
			response,
		)
	}
	return observation
}

func readOpenLDAPMetaCancelInitialEntry(
	t *testing.T,
	connection net.Conn,
) string {
	t.Helper()
	packet := readRawLDAPPacket(t, connection)
	response := decodeOpenLDAPMetaCancelFrontendResponse(t, packet)
	if response.messageID != 2 ||
		response.tag != ldapwire.ApplicationSearchResultEntry ||
		len(packet.Children[1].Children) == 0 {
		t.Fatalf("initial back-meta long-search response = %#v", response)
	}
	return strings.ToLower(packet.Children[1].Children[0].Data.String())
}

func readOpenLDAPMetaCancelCancellationResponses(
	t *testing.T,
	connection net.Conn,
	signal openLDAPMetaCancelSignal,
) openLDAPMetaCancelFrontendObservation {
	t.Helper()
	observation := openLDAPMetaCancelFrontendObservation{
		originalCode: -1,
		cancelCode:   -1,
		followupCode: -1,
		whoAmICode:   -1,
	}
	if signal == openLDAPMetaCancelAbandon {
		return observation
	}
	for !observation.originalDone || !observation.cancelResponse {
		packet := readRawLDAPPacket(t, connection)
		response := decodeOpenLDAPMetaCancelFrontendResponse(t, packet)
		switch response.messageID {
		case 2:
			if response.tag == ldapwire.ApplicationSearchResultDone {
				observation.originalDone = true
				observation.originalCode = response.code
			} else {
				observation.unexpectedResponses = append(
					observation.unexpectedResponses,
					response,
				)
			}
		case 3:
			if response.tag == ldapwire.ApplicationExtendedResponse {
				observation.cancelResponse = true
				observation.cancelCode = response.code
			} else {
				observation.unexpectedResponses = append(
					observation.unexpectedResponses,
					response,
				)
			}
		default:
			observation.unexpectedResponses = append(
				observation.unexpectedResponses,
				response,
			)
		}
	}
	return observation
}

func readOpenLDAPMetaCancelFollowupResponses(
	t *testing.T,
	connection net.Conn,
	observation *openLDAPMetaCancelFrontendObservation,
) {
	t.Helper()
	for !observation.followupDone {
		packet := readRawLDAPPacket(t, connection)
		response := decodeOpenLDAPMetaCancelFrontendResponse(t, packet)
		if response.messageID != 4 {
			observation.unexpectedResponses = append(
				observation.unexpectedResponses,
				response,
			)
			continue
		}
		switch response.tag {
		case ldapwire.ApplicationSearchResultEntry:
			operation := packet.Children[1]
			if len(operation.Children) == 0 {
				t.Fatalf("back-meta follow-up entry has no DN: %#v", operation)
			}
			observation.followupEntries = append(
				observation.followupEntries,
				strings.ToLower(operation.Children[0].Data.String()),
			)
		case ldapwire.ApplicationSearchResultDone:
			observation.followupDone = true
			observation.followupCode = response.code
		default:
			observation.unexpectedResponses = append(
				observation.unexpectedResponses,
				response,
			)
		}
	}
}

func readOpenLDAPMetaCancelFrontendResponse(
	t *testing.T,
	connection net.Conn,
) openLDAPMetaCancelFrontendResponse {
	t.Helper()
	return decodeOpenLDAPMetaCancelFrontendResponse(
		t,
		readRawLDAPPacket(t, connection),
	)
}

func decodeOpenLDAPMetaCancelFrontendResponse(
	t *testing.T,
	packet *ber.Packet,
) openLDAPMetaCancelFrontendResponse {
	t.Helper()
	if packet == nil || len(packet.Children) < 2 {
		t.Fatalf("malformed back-meta cancel response: %#v", packet)
	}
	messageID, err := ber.ParseInt64(packet.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse back-meta cancel response message ID: %v", err)
	}
	operation := packet.Children[1]
	response := openLDAPMetaCancelFrontendResponse{
		messageID: messageID,
		tag:       uint64(operation.Tag),
		code:      -1,
	}
	switch response.tag {
	case ldapwire.ApplicationSearchResultDone,
		ldapwire.ApplicationExtendedResponse:
		response.code = rawLDAPResultCode(t, operation)
	}
	return response
}

func summarizeOpenLDAPMetaCancelUpstream(
	t *testing.T,
	trace []openLDAPMetaCancelUpstreamRequest,
) openLDAPMetaCancelUpstreamObservation {
	t.Helper()
	var longSearches []openLDAPMetaCancelUpstreamRequest
	var followups []openLDAPMetaCancelUpstreamRequest
	observation := openLDAPMetaCancelUpstreamObservation{}
	for _, request := range trace {
		if request.decodeError != "" {
			t.Fatalf("decode upstream back-meta request: %s; trace=%#v", request.decodeError, trace)
		}
		if request.tag == ldapwire.ApplicationSearchRequest {
			switch {
			case request.baseDN == "":
				observation.discoveryObserved = true
			case request.scope == directory.ScopeWholeSubtree:
				longSearches = append(longSearches, request)
			case request.scope == directory.ScopeBase:
				followups = append(followups, request)
			}
		}
	}
	if len(longSearches) != 1 || len(followups) != 1 {
		t.Fatalf(
			"upstream long/follow-up searches = %d/%d, want 1/1; trace=%#v",
			len(longSearches),
			len(followups),
			trace,
		)
	}
	longSearch := longSearches[0]
	for _, request := range trace {
		if request.tag != ldapwire.ApplicationAbandonRequest &&
			!(request.tag == ldapwire.ApplicationExtendedRequest &&
				request.oid == cancelOID) {
			continue
		}
		observation.actions = append(observation.actions, openLDAPMetaCancelAction{
			tag:                 request.tag,
			oid:                 request.oid,
			targetsLongSearch:   request.connectionID == longSearch.connectionID && request.targetMessageID == longSearch.messageID,
			messageIDIsDistinct: request.messageID != request.targetMessageID,
		})
	}
	return observation
}

func assertOpenLDAPMetaCancelReference(
	t *testing.T,
	test openLDAPMetaCancelCase,
	signal openLDAPMetaCancelSignal,
	got openLDAPMetaCancelOutcome,
) {
	t.Helper()
	wantActions := []openLDAPMetaCancelAction(nil)
	if test.wantActionTag != 0 {
		wantActions = []openLDAPMetaCancelAction{{
			tag:                 test.wantActionTag,
			oid:                 test.wantActionOID,
			targetsLongSearch:   true,
			messageIDIsDistinct: true,
		}}
	}
	wantUpstream := openLDAPMetaCancelUpstreamObservation{
		actions:           wantActions,
		discoveryObserved: test.wantDiscovery,
	}
	wantFrontend := openLDAPMetaCancelFrontendObservation{
		initialEntries: []string{
			"uid=never-completes," + openLDAPMetaBaseDN,
		},
		originalCode:    -1,
		cancelCode:      -1,
		followupDone:    true,
		followupCode:    int64(ldap.LDAPResultSuccess),
		followupEntries: []string{openLDAPMetaBaseDN},
		whoAmIResponse:  true,
		whoAmICode:      int64(ldap.LDAPResultSuccess),
	}
	if signal == openLDAPMetaCancelRFC3909 {
		// back-meta returns its aggregated Search result instead of
		// SLAPD_ABANDON, so slapd completes Cancel with LDAP_TOO_LATE.
		wantFrontend.originalDone = true
		wantFrontend.originalCode = int64(ldap.LDAPResultSuccess)
		wantFrontend.cancelResponse = true
		wantFrontend.cancelCode = int64(ldap.LDAPResultTooLate)
	}
	if !reflect.DeepEqual(got.upstream, wantUpstream) ||
		!reflect.DeepEqual(got.frontend, wantFrontend) {
		t.Fatalf(
			"OpenLDAP 2.6.13 back-meta cancel fixture drifted:\n got: upstream=%#v frontend=%#v trace=%#v\nwant: upstream=%#v frontend=%#v",
			got.upstream,
			got.frontend,
			got.trace,
			wantUpstream,
			wantFrontend,
		)
	}
}

type openLDAPMetaCancelProvider struct {
	listener          net.Listener
	discoverExtension bool
	longSearches      chan openLDAPMetaCancelUpstreamRequest
	changes           chan struct{}

	mu                sync.Mutex
	requests          []openLDAPMetaCancelUpstreamRequest
	clients           map[net.Conn]int64
	closedConnections map[int64]struct{}
	nextConnectionID  int64
	stopped           bool
	wg                sync.WaitGroup
	stopOnce          sync.Once
}

func startOpenLDAPMetaCancelProvider(
	t *testing.T,
	discoverExtension bool,
) (string, *openLDAPMetaCancelProvider, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta cancel provider: %v", err)
	}
	provider := &openLDAPMetaCancelProvider{
		listener:          listener,
		discoverExtension: discoverExtension,
		longSearches:      make(chan openLDAPMetaCancelUpstreamRequest, 1),
		changes:           make(chan struct{}, 1),
		clients:           make(map[net.Conn]int64),
		closedConnections: make(map[int64]struct{}),
	}
	provider.wg.Add(1)
	go provider.accept()
	return "ldap://" + listener.Addr().String(), provider, provider.stop
}

func (provider *openLDAPMetaCancelProvider) accept() {
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
		provider.nextConnectionID++
		connectionID := provider.nextConnectionID
		provider.clients[connection] = connectionID
		provider.wg.Add(1)
		provider.mu.Unlock()
		provider.notifyChange()
		go provider.serve(connection, connectionID)
	}
}

func (provider *openLDAPMetaCancelProvider) serve(
	connection net.Conn,
	connectionID int64,
) {
	defer provider.wg.Done()
	defer func() {
		provider.mu.Lock()
		delete(provider.clients, connection)
		provider.closedConnections[connectionID] = struct{}{}
		provider.mu.Unlock()
		provider.notifyChange()
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
		request := openLDAPMetaCancelUpstreamRequest{
			connectionID: connectionID,
			messageID:    message.ID,
			tag:          message.Request.ApplicationTag(),
		}
		switch value := message.Request.(type) {
		case ldapwire.SearchRequest:
			request.baseDN = strings.ToLower(value.BaseDN)
			request.scope = value.Scope
		case ldapwire.AbandonRequest:
			request.targetMessageID = value.MessageID
		case ldapwire.ExtendedRequest:
			request.oid = value.Name
			if value.Name == cancelOID {
				target, decodeErr := ldapwire.DecodeCancelRequestValue(value.Value)
				if decodeErr != nil {
					request.decodeError = decodeErr.Error()
				} else {
					request.targetMessageID = target
				}
			}
		}
		provider.record(request)

		switch value := message.Request.(type) {
		case ldapwire.BindRequest:
			if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)); err != nil {
				return
			}
		case ldapwire.SearchRequest:
			switch {
			case value.BaseDN == "":
				if err := provider.serveRootDSE(connection, message.ID); err != nil {
					return
				}
			case value.Scope == directory.ScopeWholeSubtree:
				if err := provider.serveLongSearchEntry(
					connection,
					message.ID,
				); err != nil {
					return
				}
				select {
				case provider.longSearches <- request:
				default:
				}
			case value.Scope == directory.ScopeBase:
				if err := provider.serveFollowupSearch(
					connection,
					message.ID,
					value.BaseDN,
				); err != nil {
					return
				}
			}
		case ldapwire.ExtendedRequest:
			if value.Name != cancelOID || request.decodeError != "" {
				return
			}
			if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
				request.targetMessageID,
				ldapwire.Result{Code: ldapwire.ResultCanceled},
				nil,
			)); err != nil {
				return
			}
			if err := ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				"",
				nil,
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

func (provider *openLDAPMetaCancelProvider) serveLongSearchEntry(
	connection net.Conn,
	messageID int64,
) error {
	uid := "never-completes"
	return ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
		messageID,
		directory.Entry{
			DN: "uid=" + uid + "," + openLDAPMetaCancelRemoteBase,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues(uid)},
				{Description: "cn", Values: stringValues(uid)},
				{Description: "sn", Values: stringValues(uid)},
			},
		},
		nil,
	))
}

func (provider *openLDAPMetaCancelProvider) serveRootDSE(
	connection net.Conn,
	messageID int64,
) error {
	entry := directory.Entry{DN: ""}
	if provider.discoverExtension {
		entry.Attributes = []directory.Attribute{{
			Description: "supportedExtension",
			Values:      stringValues(cancelOID),
		}}
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
		messageID,
		entry,
		nil,
	)); err != nil {
		return err
	}
	return ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	))
}

func (provider *openLDAPMetaCancelProvider) serveFollowupSearch(
	connection net.Conn,
	messageID int64,
	baseDN string,
) error {
	entry := directory.Entry{
		DN: baseDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "domain")},
			{Description: "dc", Values: stringValues("example")},
		},
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
		messageID,
		entry,
		nil,
	)); err != nil {
		return err
	}
	return ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	))
}

func (provider *openLDAPMetaCancelProvider) record(
	request openLDAPMetaCancelUpstreamRequest,
) {
	provider.mu.Lock()
	provider.requests = append(provider.requests, request)
	provider.mu.Unlock()
	provider.notifyChange()
}

func (provider *openLDAPMetaCancelProvider) notifyChange() {
	select {
	case provider.changes <- struct{}{}:
	default:
	}
}

func (provider *openLDAPMetaCancelProvider) waitForLongSearch(t *testing.T) {
	t.Helper()
	select {
	case <-provider.longSearches:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for upstream back-meta long search; trace=%#v", provider.snapshot())
	}
}

func (provider *openLDAPMetaCancelProvider) waitForNoClients(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		provider.mu.Lock()
		clients := len(provider.clients)
		provider.mu.Unlock()
		if clients == 0 {
			return
		}
		select {
		case <-provider.changes:
		case <-deadline.C:
			t.Fatalf(
				"timed out waiting for back-meta upstream connections to close; clients=%d trace=%#v",
				clients,
				provider.snapshot(),
			)
		}
	}
}

func (provider *openLDAPMetaCancelProvider) waitForCancellationActionOrLongConnectionClose(
	t *testing.T,
) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		provider.mu.Lock()
		var longSearch *openLDAPMetaCancelUpstreamRequest
		for index := range provider.requests {
			request := &provider.requests[index]
			if request.tag == ldapwire.ApplicationSearchRequest &&
				request.scope == directory.ScopeWholeSubtree {
				longSearch = request
				break
			}
		}
		progressed := false
		if longSearch != nil {
			_, progressed = provider.closedConnections[longSearch.connectionID]
			if !progressed {
				for _, request := range provider.requests {
					if request.connectionID == longSearch.connectionID &&
						request.targetMessageID == longSearch.messageID &&
						(request.tag == ldapwire.ApplicationAbandonRequest ||
							(request.tag == ldapwire.ApplicationExtendedRequest &&
								request.oid == cancelOID)) {
						progressed = true
						break
					}
				}
			}
		}
		provider.mu.Unlock()
		if progressed {
			return
		}
		select {
		case <-provider.changes:
		case <-deadline.C:
			t.Fatalf(
				"timed out waiting for upstream cancellation action or transport close; trace=%#v",
				provider.snapshot(),
			)
		}
	}
}

func (provider *openLDAPMetaCancelProvider) snapshot() []openLDAPMetaCancelUpstreamRequest {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]openLDAPMetaCancelUpstreamRequest(nil), provider.requests...)
}

func (provider *openLDAPMetaCancelProvider) stop() {
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
		provider.wg.Wait()
	})
}
