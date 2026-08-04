package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	openLDAPMetaProtocolUserDN        = "uid=protocol," + openLDAPMetaBaseDN
	openLDAPMetaProtocolUserPassword  = "protocol-user-secret"
	openLDAPMetaProtocolLocalUserDN   = "uid=protocol-client,dc=example,dc=com"
	openLDAPMetaProtocolLocalPassword = "protocol-client-secret"
	openLDAPMetaProtocolProxyDN       = "cn=proxy," + openLDAPMetaBaseDN
	openLDAPMetaProtocolProxyPassword = "protocol-proxy-secret"
)

type openLDAPMetaProtocolSetup uint8

const (
	openLDAPMetaProtocolNoSetup openLDAPMetaProtocolSetup = iota
	openLDAPMetaProtocolUserSetup
	openLDAPMetaProtocolLocalSetup
)

type openLDAPMetaProtocolCase struct {
	name              string
	targetVersion     int
	frontendVersion   int
	setup             openLDAPMetaProtocolSetup
	sessionTracking   bool
	identityAssertion bool
	requestControl    bool
	controlCritical   bool
	want              openLDAPMetaProtocolOutcome
}

type openLDAPMetaProtocolControl struct {
	oid       string
	critical  bool
	hasValue  bool
	textValue string
}

type openLDAPMetaProtocolRequest struct {
	operation   string
	bindVersion int
	bindDN      string
	controls    []openLDAPMetaProtocolControl
}

type openLDAPMetaProtocolOutcome struct {
	setupBind     bool
	setupBindCode uint16
	operationCode uint16
	upstream      []openLDAPMetaProtocolRequest
	providerError string
}

type openLDAPMetaProtocolProvider struct {
	listener net.Listener

	mu          sync.Mutex
	requests    []openLDAPMetaProtocolRequest
	providerErr string
	clients     map[net.Conn]struct{}
	stopped     bool
	wg          sync.WaitGroup
	stopOnce    sync.Once
}

func TestOpenLDAPReferenceMetaProtocolVersion(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)
	assertPinnedOpenLDAPMetaProtocolSource(t)

	success := uint16(ldap.LDAPResultSuccess)
	unwilling := uint16(ldap.LDAPResultUnwillingToPerform)
	noSuchObject := uint16(ldap.LDAPResultNoSuchObject)
	session := openLDAPMetaProtocolExpectedControl(
		sessionTrackingControlOID,
		false,
		true,
		"",
	)
	manageNoncritical := openLDAPMetaProtocolExpectedControl(
		manageDsaITControlOID,
		false,
		false,
		"",
	)
	manageCritical := openLDAPMetaProtocolExpectedControl(
		manageDsaITControlOID,
		true,
		false,
		"",
	)
	proxyAuthz := openLDAPMetaProtocolExpectedControl(
		proxyAuthorizationControlOID,
		false,
		true,
		"dn:"+openLDAPMetaProtocolLocalUserDN,
	)

	tests := []openLDAPMetaProtocolCase{
		{
			name:            "bind/inherit LDAPv2",
			targetVersion:   0,
			frontendVersion: 2,
			want: openLDAPMetaProtocolBindOutcome(
				success,
				2,
			),
		},
		{
			name:            "bind/inherit LDAPv3",
			targetVersion:   0,
			frontendVersion: 3,
			want: openLDAPMetaProtocolBindOutcome(
				success,
				3,
			),
		},
		{
			name:            "bind/force LDAPv2 from LDAPv3",
			targetVersion:   2,
			frontendVersion: 3,
			want: openLDAPMetaProtocolBindOutcome(
				success,
				2,
			),
		},
		{
			name:            "bind/force LDAPv3 from LDAPv2",
			targetVersion:   3,
			frontendVersion: 2,
			want: openLDAPMetaProtocolBindOutcome(
				success,
				3,
			),
		},
		{
			name:            "controls/inherit LDAPv2 suppresses session tracking",
			targetVersion:   0,
			frontendVersion: 2,
			setup:           openLDAPMetaProtocolUserSetup,
			sessionTracking: true,
			want: openLDAPMetaProtocolSearchOutcome(
				success,
				2,
				true,
				nil,
			),
		},
		{
			name:            "controls/inherit LDAPv3 forwards client and session controls",
			targetVersion:   0,
			frontendVersion: 3,
			setup:           openLDAPMetaProtocolUserSetup,
			sessionTracking: true,
			requestControl:  true,
			controlCritical: false,
			want: openLDAPMetaProtocolSearchOutcome(
				success,
				3,
				true,
				[]openLDAPMetaProtocolControl{manageNoncritical, session},
			),
		},
		{
			name:            "controls/LDAPv2 strips noncritical client and session controls",
			targetVersion:   2,
			frontendVersion: 3,
			setup:           openLDAPMetaProtocolUserSetup,
			sessionTracking: true,
			requestControl:  true,
			controlCritical: false,
			want: openLDAPMetaProtocolSearchOutcome(
				success,
				2,
				true,
				nil,
			),
		},
		{
			name:            "controls/LDAPv2 rejects critical client control",
			targetVersion:   2,
			frontendVersion: 3,
			setup:           openLDAPMetaProtocolUserSetup,
			sessionTracking: true,
			requestControl:  true,
			controlCritical: true,
			want: openLDAPMetaProtocolSearchOutcome(
				noSuchObject,
				2,
				false,
				nil,
			),
		},
		{
			name:            "controls/forced LDAPv3 adds session tracking for LDAPv2 frontend",
			targetVersion:   3,
			frontendVersion: 2,
			setup:           openLDAPMetaProtocolUserSetup,
			sessionTracking: true,
			want: openLDAPMetaProtocolSearchOutcome(
				success,
				3,
				true,
				[]openLDAPMetaProtocolControl{session},
			),
		},
		{
			name:            "controls/LDAPv3 forwards critical client and session controls",
			targetVersion:   3,
			frontendVersion: 3,
			setup:           openLDAPMetaProtocolUserSetup,
			sessionTracking: true,
			requestControl:  true,
			controlCritical: true,
			want: openLDAPMetaProtocolSearchOutcome(
				success,
				3,
				true,
				[]openLDAPMetaProtocolControl{manageCritical, session},
			),
		},
		{
			name:              "proxyAuthz/inherit LDAPv2 refuses identity assertion",
			targetVersion:     0,
			frontendVersion:   2,
			setup:             openLDAPMetaProtocolLocalSetup,
			sessionTracking:   true,
			identityAssertion: true,
			want: openLDAPMetaProtocolLocalSearchOutcome(
				unwilling,
				nil,
			),
		},
		{
			name:              "proxyAuthz/inherit LDAPv3 adds proxy and session controls",
			targetVersion:     0,
			frontendVersion:   3,
			setup:             openLDAPMetaProtocolLocalSetup,
			sessionTracking:   true,
			identityAssertion: true,
			want: openLDAPMetaProtocolLocalSearchOutcome(
				success,
				[]openLDAPMetaProtocolRequest{
					openLDAPMetaProtocolBindRequest(3, openLDAPMetaProtocolProxyDN),
					openLDAPMetaProtocolSearchRequest(proxyAuthz, session),
				},
			),
		},
		{
			name:              "proxyAuthz/LDAPv2 refuses identity assertion",
			targetVersion:     2,
			frontendVersion:   3,
			setup:             openLDAPMetaProtocolLocalSetup,
			sessionTracking:   true,
			identityAssertion: true,
			want: openLDAPMetaProtocolLocalSearchOutcome(
				unwilling,
				nil,
			),
		},
		{
			name:              "proxyAuthz/forced LDAPv3 serves LDAPv2 frontend",
			targetVersion:     3,
			frontendVersion:   2,
			setup:             openLDAPMetaProtocolLocalSetup,
			sessionTracking:   true,
			identityAssertion: true,
			want: openLDAPMetaProtocolLocalSearchOutcome(
				success,
				[]openLDAPMetaProtocolRequest{
					openLDAPMetaProtocolBindRequest(3, openLDAPMetaProtocolProxyDN),
					openLDAPMetaProtocolSearchRequest(proxyAuthz, session),
				},
			),
		},
		{
			name:              "proxyAuthz/LDAPv3 baseline",
			targetVersion:     3,
			frontendVersion:   3,
			setup:             openLDAPMetaProtocolLocalSetup,
			sessionTracking:   true,
			identityAssertion: true,
			want: openLDAPMetaProtocolLocalSearchOutcome(
				success,
				[]openLDAPMetaProtocolRequest{
					openLDAPMetaProtocolBindRequest(3, openLDAPMetaProtocolProxyDN),
					openLDAPMetaProtocolSearchRequest(proxyAuthz, session),
				},
			),
		},
	}

	reference := make(map[string]openLDAPMetaProtocolOutcome, len(tests))
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got := runOpenLDAPMetaProtocolScenario(t, tools, false, test)
				if !reflect.DeepEqual(got, test.want) {
					t.Fatalf(
						"OpenLDAP 2.6.13 back-meta protocol fixture drifted:\n got: %#v\nwant: %#v",
						got,
						test.want,
					)
				}
				reference[test.name] = got
			})
		}
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go comparison", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got := runOpenLDAPMetaProtocolScenario(t, tools, true, test)
				if !reflect.DeepEqual(got, reference[test.name]) {
					t.Fatalf(
						"ldap-go back-meta protocol-version differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
						reference[test.name],
						got,
					)
				}
			})
		}
	})
}

func assertPinnedOpenLDAPMetaProtocolSource(t *testing.T) {
	t.Helper()
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	files := map[string]string{
		filepath.Join("servers", "slapd", "back-meta", "config.c"): "2986b25f681595913e40a53db90e50a7dd8d67a314f2b95cb117ff8b9d5834d0",
		filepath.Join("servers", "slapd", "back-meta", "bind.c"):   "b62e5856859ba1e0b9f4b667267cd6605b68f90575da0fe0b58921c2d0c383bb",
	}
	for relativePath, want := range files {
		contents, err := os.ReadFile(filepath.Join(sourceRoot, relativePath))
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", relativePath, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != want {
			t.Fatalf(
				"pinned OpenLDAP source %s SHA-256 = %s, want %s",
				relativePath,
				got,
				want,
			)
		}
	}
}

func openLDAPMetaProtocolBindOutcome(
	code uint16,
	upstreamVersion int,
) openLDAPMetaProtocolOutcome {
	return openLDAPMetaProtocolOutcome{
		operationCode: code,
		upstream: []openLDAPMetaProtocolRequest{
			openLDAPMetaProtocolBindRequest(
				upstreamVersion,
				openLDAPMetaProtocolUserDN,
			),
		},
	}
}

func openLDAPMetaProtocolSearchOutcome(
	code uint16,
	upstreamBindVersion int,
	searchForwarded bool,
	controls []openLDAPMetaProtocolControl,
) openLDAPMetaProtocolOutcome {
	bindRequest := openLDAPMetaProtocolBindRequest(
		upstreamBindVersion,
		openLDAPMetaProtocolUserDN,
	)
	if upstreamBindVersion == 3 {
		bindRequest.controls = []openLDAPMetaProtocolControl{
			openLDAPMetaProtocolExpectedControl(
				sessionTrackingControlOID,
				false,
				true,
				"",
			),
		}
	}
	requests := []openLDAPMetaProtocolRequest{bindRequest}
	if searchForwarded {
		requests = append(requests, openLDAPMetaProtocolSearchRequest(controls...))
	}
	return openLDAPMetaProtocolOutcome{
		setupBind:     true,
		setupBindCode: uint16(ldap.LDAPResultSuccess),
		operationCode: code,
		upstream:      requests,
	}
}

func openLDAPMetaProtocolLocalSearchOutcome(
	code uint16,
	requests []openLDAPMetaProtocolRequest,
) openLDAPMetaProtocolOutcome {
	return openLDAPMetaProtocolOutcome{
		setupBind:     true,
		setupBindCode: uint16(ldap.LDAPResultSuccess),
		operationCode: code,
		upstream:      requests,
	}
}

func openLDAPMetaProtocolBindRequest(
	version int,
	dn string,
) openLDAPMetaProtocolRequest {
	return openLDAPMetaProtocolRequest{
		operation:   "bind",
		bindVersion: version,
		bindDN:      dn,
	}
}

func openLDAPMetaProtocolSearchRequest(
	controls ...openLDAPMetaProtocolControl,
) openLDAPMetaProtocolRequest {
	copyControls := append([]openLDAPMetaProtocolControl(nil), controls...)
	sort.Slice(copyControls, func(i, j int) bool {
		return copyControls[i].oid < copyControls[j].oid
	})
	return openLDAPMetaProtocolRequest{
		operation: "search",
		controls:  copyControls,
	}
}

func openLDAPMetaProtocolExpectedControl(
	oid string,
	critical bool,
	hasValue bool,
	textValue string,
) openLDAPMetaProtocolControl {
	return openLDAPMetaProtocolControl{
		oid:       oid,
		critical:  critical,
		hasValue:  hasValue,
		textValue: textValue,
	}
}

func runOpenLDAPMetaProtocolScenario(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
	test openLDAPMetaProtocolCase,
) openLDAPMetaProtocolOutcome {
	t.Helper()
	provider := startOpenLDAPMetaProtocolProvider(t)
	defer provider.stop()

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaProtocolProxy(
			t,
			provider.uri(),
			test,
		)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaProtocolProxy(
			t,
			tools,
			provider.uri(),
			test,
		)
	}
	defer stopProxy()

	address := strings.TrimPrefix(proxyURI, "ldap://")
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial back-meta protocol fixture %s: %v", proxyURI, err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set back-meta protocol client deadline: %v", err)
	}

	outcome := openLDAPMetaProtocolOutcome{}
	if test.setup == openLDAPMetaProtocolNoSetup {
		response := sendRawLDAPOperation(
			t,
			connection,
			1,
			rawSimpleBindRequestVersion(
				int64(test.frontendVersion),
				openLDAPMetaProtocolUserDN,
				openLDAPMetaProtocolUserPassword,
			),
		)
		outcome.operationCode = openLDAPMetaProtocolResponseCode(t, response)
	} else {
		outcome.setupBind = true
		setupDN := openLDAPMetaProtocolUserDN
		setupPassword := openLDAPMetaProtocolUserPassword
		if test.setup == openLDAPMetaProtocolLocalSetup {
			setupDN = openLDAPMetaProtocolLocalUserDN
			setupPassword = openLDAPMetaProtocolLocalPassword
		}
		response := sendRawLDAPOperation(
			t,
			connection,
			1,
			rawSimpleBindRequestVersion(
				int64(test.frontendVersion),
				setupDN,
				setupPassword,
			),
		)
		outcome.setupBindCode = openLDAPMetaProtocolResponseCode(t, response)

		var controls []*ber.Packet
		if test.requestControl {
			controls = append(controls, openLDAPMetaProtocolRawControl(
				manageDsaITControlOID,
				test.controlCritical,
			))
		}
		response = sendRawLDAPOperation(
			t,
			connection,
			2,
			rawSyncSearchRequestFor(
				t,
				openLDAPMetaBaseDN,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
			controls...,
		)
		outcome.operationCode = openLDAPMetaProtocolResponseCode(t, response)
	}
	outcome.upstream, outcome.providerError = provider.snapshot()
	return outcome
}

func openLDAPMetaProtocolResponseCode(t *testing.T, response *ber.Packet) uint16 {
	t.Helper()
	if response == nil || len(response.Children) < 2 {
		t.Fatalf("malformed back-meta protocol response: %#v", response)
	}
	return uint16(rawLDAPResultCode(t, response.Children[1]))
}

func openLDAPMetaProtocolRawControl(oid string, critical bool) *ber.Packet {
	control := ber.NewSequence("Control")
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		oid,
		"controlType",
	))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	return control
}

func startOpenLDAPMetaProtocolProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	test openLDAPMetaProtocolCase,
) (string, func()) {
	t.Helper()
	targetOptions := []string{
		"protocol-version " + strconv.Itoa(test.targetVersion),
	}
	if test.sessionTracking {
		targetOptions = append(targetOptions, "session-tracking-request yes")
	}
	if test.identityAssertion {
		targetOptions = append(
			targetOptions,
			`idassert-bind bindmethod=simple binddn="`+openLDAPMetaProtocolProxyDN+
				`" credentials=`+openLDAPMetaProtocolProxyPassword+` mode=self`,
			`idassert-authzFrom "*"`,
		)
	}
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
nretries 1
chase-referrals no
onerr stop
pseudoroot-bind-defer yes

uri "%s/%s"
%s`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerURI,
		openLDAPMetaBaseDN,
		strings.Join(targetOptions, "\n"),
	)
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"allow bind_v2",
		configuration,
		fmt.Sprintf(`
dn: %s
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: protocol-client
cn: Protocol Client
sn: Client
userPassword: %s
`, openLDAPMetaProtocolLocalUserDN, openLDAPMetaProtocolLocalPassword),
	)
}

func startLDAPGoMetaProtocolProxy(
	t *testing.T,
	providerURI string,
	test openLDAPMetaProtocolCase,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaProtocolConfiguration(t, store, providerURI, test)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaProtocolConfiguration(
	t *testing.T,
	store storage.Store,
	providerURI string,
	test openLDAPMetaProtocolCase,
) {
	t.Helper()
	databaseDN := "olcDatabase={2}meta,cn=config"
	targetAttributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
		{Description: "olcMetaSub", Values: stringValues("{0}uri")},
		{Description: "olcDbURI", Values: stringValues(providerURI + "/" + openLDAPMetaBaseDN)},
		{Description: "olcDbProtocolVersion", Values: stringValues(strconv.Itoa(test.targetVersion))},
		{Description: "olcDbChaseReferrals", Values: stringValues("FALSE")},
	}
	if test.sessionTracking {
		targetAttributes = append(targetAttributes, directory.Attribute{
			Description: "olcDbSessionTrackingRequest",
			Values:      stringValues("TRUE"),
		})
	}
	if test.identityAssertion {
		targetAttributes = append(
			targetAttributes,
			directory.Attribute{
				Description: "olcDbIDAssertBind",
				Values: stringValues(
					`bindmethod=simple binddn="` + openLDAPMetaProtocolProxyDN +
						`" credentials=` + openLDAPMetaProtocolProxyPassword + ` mode=self`,
				),
			},
			directory.Attribute{
				Description: "olcDbIDAssertAuthzFrom",
				Values:      stringValues("*"),
			},
		)
	}
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
				{Description: "olcAllows", Values: stringValues("bind_v2")},
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
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
			},
		},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{2}meta")},
				{Description: "olcSuffix", Values: stringValues(openLDAPMetaBaseDN)},
				{Description: "olcRootDN", Values: stringValues("cn=admin," + openLDAPMetaBaseDN)},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * write")},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbNretries", Values: stringValues("1")},
				{Description: "olcDbOnErr", Values: stringValues("stop")},
				{Description: "olcDbPseudoRootBindDefer", Values: stringValues("TRUE")},
			},
		},
		{
			DN:         "olcMetaSub={0}uri," + databaseDN,
			Attributes: targetAttributes,
		},
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		},
		{
			DN: openLDAPMetaProtocolLocalUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "person", "organizationalPerson", "inetOrgPerson")},
				{Description: "uid", Values: stringValues("protocol-client")},
				{Description: "cn", Values: stringValues("Protocol Client")},
				{Description: "sn", Values: stringValues("Client")},
				{Description: "userPassword", Values: stringValues(openLDAPMetaProtocolLocalPassword)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{
			"dc=example,dc=com",
			openLDAPMetaBaseDN,
			"cn=config",
		})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta protocol configuration: %v", err)
	}
}

func startOpenLDAPMetaProtocolProvider(
	t *testing.T,
) *openLDAPMetaProtocolProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for back-meta protocol provider: %v", err)
	}
	provider := &openLDAPMetaProtocolProvider{
		listener: listener,
		clients:  make(map[net.Conn]struct{}),
	}
	provider.wg.Add(1)
	go provider.accept()
	return provider
}

func (provider *openLDAPMetaProtocolProvider) uri() string {
	return "ldap://" + provider.listener.Addr().String()
}

func (provider *openLDAPMetaProtocolProvider) accept() {
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

func (provider *openLDAPMetaProtocolProvider) serve(connection net.Conn) {
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
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			provider.record(openLDAPMetaProtocolRequest{
				operation:   "bind",
				bindVersion: request.Version,
				bindDN:      strings.ToLower(request.Name),
				controls:    openLDAPMetaProtocolControls(message.Controls),
			})
			if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)); err != nil {
				return
			}
		case ldapwire.SearchRequest:
			provider.record(openLDAPMetaProtocolRequest{
				operation: "search",
				controls:  openLDAPMetaProtocolControls(message.Controls),
			})
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
			provider.recordError(fmt.Sprintf(
				"unexpected upstream request %T",
				message.Request,
			))
			return
		}
	}
}

func openLDAPMetaProtocolControls(
	controls []ldapwire.Control,
) []openLDAPMetaProtocolControl {
	if len(controls) == 0 {
		return nil
	}
	result := make([]openLDAPMetaProtocolControl, 0, len(controls))
	for _, control := range controls {
		observation := openLDAPMetaProtocolControl{
			oid:      control.OID,
			critical: control.Critical,
			hasValue: control.HasValue,
		}
		if control.OID == proxyAuthorizationControlOID {
			observation.textValue = string(control.Value)
		}
		result = append(result, observation)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].oid < result[j].oid
	})
	return result
}

func (provider *openLDAPMetaProtocolProvider) record(
	request openLDAPMetaProtocolRequest,
) {
	provider.mu.Lock()
	provider.requests = append(provider.requests, request)
	provider.mu.Unlock()
}

func (provider *openLDAPMetaProtocolProvider) recordError(message string) {
	provider.mu.Lock()
	if provider.providerErr == "" {
		provider.providerErr = message
	}
	provider.mu.Unlock()
}

func (provider *openLDAPMetaProtocolProvider) snapshot() (
	[]openLDAPMetaProtocolRequest,
	string,
) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) == 0 {
		return nil, provider.providerErr
	}
	requests := make([]openLDAPMetaProtocolRequest, len(provider.requests))
	for index, request := range provider.requests {
		requests[index] = request
		requests[index].controls = append(
			[]openLDAPMetaProtocolControl(nil),
			request.controls...,
		)
	}
	return requests, provider.providerErr
}

func (provider *openLDAPMetaProtocolProvider) stop() {
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
