package lloadd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

func TestServiceGSSAPIRFC4752SecurityLayers(t *testing.T) {
	tests := []struct {
		name      string
		secprops  string
		selection byte
	}{
		{name: "no layer", secprops: "maxssf=0", selection: saslkrb5.SecurityNone},
		{name: "integrity", secprops: "minssf=1,maxssf=1", selection: saslkrb5.SecurityIntegrity},
		{name: "confidentiality", selection: saslkrb5.SecurityConfidentiality},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := serviceGSSAPITestKey()
			state := saslkrb5.SecurityState{SendSequence: 11, ReceiveSequence: 29}
			initiator := newFixedServiceGSSAPIInitiator(key, state)
			client, peer := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = peer.Close()
			})
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(5 * time.Second))

			observed := make(chan serviceGSSAPINegotiation, 1)
			serverDone := make(chan error, 1)
			go runFixedServiceGSSAPIServer(
				peer,
				key,
				state,
				test.selection,
				observed,
				serverDone,
			)

			backend := serviceGSSAPIProtocolTestBackend(RuntimeBindConfig{
				Method:             "sasl",
				SASLMechanism:      "GSSAPI",
				AuthorizationID:    "u:lloadd-service",
				SecurityProperties: test.secprops,
			})
			nextID := int64(1)
			secured, err := backend.bindServiceSASLGSSAPIWithInitiator(
				client,
				&nextID,
				"ldap/backend.example.test",
				"u:lloadd-service",
				initiator,
			)
			if err != nil {
				t.Fatalf("GSSAPI Bind: %v", err)
			}
			if nextID != 4 {
				t.Fatalf("next message ID = %d, want 4", nextID)
			}
			if got := initiator.Target(); got != "ldap/backend.example.test" {
				t.Fatalf("GSSAPI target = %q", got)
			}
			select {
			case <-initiator.closed:
			case <-time.After(time.Second):
				t.Fatal("GSSAPI initiator was not closed")
			}
			if test.selection == saslkrb5.SecurityNone && secured != client {
				t.Fatal("no-layer negotiation replaced the transport")
			}
			if test.selection != saslkrb5.SecurityNone && secured == client {
				t.Fatal("security-layer negotiation retained the raw transport")
			}
			negotiation := <-observed
			if negotiation.selection != test.selection ||
				negotiation.authorizationID != "u:lloadd-service" {
				t.Fatalf("GSSAPI negotiation = %#v", negotiation)
			}
			wantMaximum := uint32(serviceGSSAPIDefaultBuffer)
			if test.selection == saslkrb5.SecurityNone {
				wantMaximum = 0
			}
			if negotiation.maximum != wantMaximum {
				t.Fatalf("GSSAPI receive maximum = %d, want %d", negotiation.maximum, wantMaximum)
			}

			request := []byte("post-bind LDAP request")
			response := []byte("post-bind LDAP response")
			if _, err := secured.Write(request); err != nil {
				t.Fatalf("write post-Bind frame: %v", err)
			}
			got := make([]byte, len(response))
			if _, err := io.ReadFull(secured, got); err != nil {
				t.Fatalf("read post-Bind frame: %v", err)
			}
			if !bytes.Equal(got, response) {
				t.Fatalf("post-Bind response = %q", got)
			}
			if err := <-serverDone; err != nil {
				t.Fatalf("fixed GSSAPI server: %v", err)
			}
		})
	}
}

type serviceGSSAPINegotiation struct {
	selection       byte
	maximum         uint32
	authorizationID string
}

func runFixedServiceGSSAPIServer(
	connection net.Conn,
	key types.EncryptionKey,
	state saslkrb5.SecurityState,
	wantSelection byte,
	observed chan<- serviceGSSAPINegotiation,
	done chan<- error,
) {
	fail := func(err error) {
		done <- err
	}
	first, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		fail(err)
		return
	}
	request, ok := first.Request.(ldapwire.BindRequest)
	if !ok || request.Authentication.SASLMechanism != "GSSAPI" ||
		!request.Authentication.HasSASLCredentials ||
		!bytes.Equal(request.Authentication.SASLCredentials, []byte("fixed-ap-req")) {
		fail(fmt.Errorf("unexpected GSSAPI AP-REQ: %#v", first.Request))
		return
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		first.ID,
		ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
		[]byte("fixed-ap-rep"),
		true,
		nil,
	)); err != nil {
		fail(err)
		return
	}

	second, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		fail(err)
		return
	}
	request, ok = second.Request.(ldapwire.BindRequest)
	if !ok || request.Authentication.SASLMechanism != "GSSAPI" ||
		request.Authentication.HasSASLCredentials {
		fail(fmt.Errorf("unexpected GSSAPI offer request: %#v", second.Request))
		return
	}
	offer := []byte{
		saslkrb5.SecurityNone | saslkrb5.SecurityIntegrity | saslkrb5.SecurityConfidentiality,
		1, 0, 0,
	}
	wrapper, err := saslkrb5.Wrap(
		offer,
		key,
		true,
		state.AcceptorSubkey,
		state.ReceiveSequence,
	)
	if err != nil {
		fail(err)
		return
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		second.ID,
		ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
		wrapper,
		true,
		nil,
	)); err != nil {
		clear(wrapper)
		fail(err)
		return
	}
	clear(wrapper)

	third, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		fail(err)
		return
	}
	request, ok = third.Request.(ldapwire.BindRequest)
	if !ok || request.Authentication.SASLMechanism != "GSSAPI" ||
		!request.Authentication.HasSASLCredentials {
		fail(fmt.Errorf("unexpected GSSAPI selection request: %#v", third.Request))
		return
	}
	selectionToken, err := saslkrb5.Unwrap(
		request.Authentication.SASLCredentials,
		key,
		false,
		state.AcceptorSubkey,
		state.SendSequence,
	)
	if err != nil {
		fail(err)
		return
	}
	selection, maximum, authorizationID, err := saslkrb5.DecodeNegotiation(selectionToken)
	clear(selectionToken)
	if err != nil {
		fail(err)
		return
	}
	if selection != wantSelection {
		fail(fmt.Errorf("GSSAPI selection = %d, want %d", selection, wantSelection))
		return
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		third.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
		false,
		nil,
	)); err != nil {
		fail(err)
		return
	}
	observed <- serviceGSSAPINegotiation{
		selection:       selection,
		maximum:         maximum,
		authorizationID: authorizationID,
	}

	secured := connection
	serverState := saslkrb5.SecurityState{
		SendSequence:    state.ReceiveSequence + 1,
		ReceiveSequence: state.SendSequence + 1,
		AcceptorSubkey:  state.AcceptorSubkey,
	}
	if selection == saslkrb5.SecurityIntegrity {
		secured, err = saslkrb5.NewIntegrityConnection(
			connection,
			key,
			true,
			serverState,
			maximum,
			serviceGSSAPIDefaultBuffer,
		)
	} else if selection == saslkrb5.SecurityConfidentiality {
		secured, err = saslkrb5.NewConfidentialityConnection(
			connection,
			key,
			true,
			serverState,
			maximum,
			serviceGSSAPIDefaultBuffer,
		)
	}
	if err != nil {
		fail(err)
		return
	}
	requestPayload := make([]byte, len("post-bind LDAP request"))
	if _, err := io.ReadFull(secured, requestPayload); err != nil {
		fail(err)
		return
	}
	if string(requestPayload) != "post-bind LDAP request" {
		fail(fmt.Errorf("post-Bind request = %q", requestPayload))
		return
	}
	_, err = secured.Write([]byte("post-bind LDAP response"))
	done <- err
}

type fixedServiceGSSAPIInitiator struct {
	mu     sync.Mutex
	key    types.EncryptionKey
	state  saslkrb5.SecurityState
	target string
	closed chan struct{}
	once   sync.Once
}

func newFixedServiceGSSAPIInitiator(
	key types.EncryptionKey,
	state saslkrb5.SecurityState,
) *fixedServiceGSSAPIInitiator {
	return &fixedServiceGSSAPIInitiator{
		key:    cloneServiceGSSAPITestKey(key),
		state:  state,
		closed: make(chan struct{}),
	}
}

func (initiator *fixedServiceGSSAPIInitiator) InitialToken(
	target string,
	channelBinding []byte,
) ([]byte, error) {
	if len(channelBinding) != 0 {
		return nil, fmt.Errorf("unexpected channel binding %x", channelBinding)
	}
	initiator.mu.Lock()
	initiator.target = target
	initiator.mu.Unlock()
	return []byte("fixed-ap-req"), nil
}

func (initiator *fixedServiceGSSAPIInitiator) AcceptAPRep(value []byte) error {
	if !bytes.Equal(value, []byte("fixed-ap-rep")) {
		return fmt.Errorf("AP-REP = %x", value)
	}
	return nil
}

func (initiator *fixedServiceGSSAPIInitiator) ContextKey() (types.EncryptionKey, error) {
	initiator.mu.Lock()
	defer initiator.mu.Unlock()
	return cloneServiceGSSAPITestKey(initiator.key), nil
}

func (initiator *fixedServiceGSSAPIInitiator) SecurityState() (saslkrb5.SecurityState, error) {
	return initiator.state, nil
}

func (initiator *fixedServiceGSSAPIInitiator) Close() error {
	initiator.once.Do(func() {
		initiator.mu.Lock()
		clear(initiator.key.KeyValue)
		initiator.key = types.EncryptionKey{}
		initiator.mu.Unlock()
		close(initiator.closed)
	})
	return nil
}

func (initiator *fixedServiceGSSAPIInitiator) Target() string {
	initiator.mu.Lock()
	defer initiator.mu.Unlock()
	return initiator.target
}

func serviceGSSAPITestKey() types.EncryptionKey {
	return types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdef"),
	}
}

func cloneServiceGSSAPITestKey(key types.EncryptionKey) types.EncryptionKey {
	return types.EncryptionKey{KeyType: key.KeyType, KeyValue: bytes.Clone(key.KeyValue)}
}

func TestServiceGSSAPICredentialSourcesAndProviderFailure(t *testing.T) {
	lookup := func(values map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		}
	}
	base := RuntimeBindConfig{
		Method:           "sasl",
		SASLMechanism:    "GSSAPI",
		AuthenticationID: "lloadd@EXAMPLE.TEST",
		Realm:            "EXAMPLE.TEST",
	}

	passwordConfig := base
	passwordConfig.Credentials = []byte("secret-password")
	password, err := resolveServiceGSSAPISettings(passwordConfig, lookup(map[string]string{
		"KRB5_CLIENT_KTNAME": "KCM:ignored-because-password-wins",
		"KRB5_CONFIG":        "/run/krb5.conf",
	}))
	if err != nil {
		t.Fatalf("resolve password: %v", err)
	}
	passwordConfig.Credentials[0] = 'X'
	if password.source != serviceGSSAPIPassword || password.username != "lloadd" ||
		password.realm != "EXAMPLE.TEST" || password.configuration != "/run/krb5.conf" ||
		string(password.password) != "secret-password" {
		t.Fatalf("password settings = %#v", password)
	}
	ownedPassword := password.password
	password.clear()
	for _, value := range ownedPassword {
		if value != 0 {
			t.Fatal("password settings were not cleared")
		}
	}

	keytab, err := resolveServiceGSSAPISettings(base, lookup(map[string]string{
		"KRB5_CLIENT_KTNAME": "FILE:/run/lloadd.keytab",
		"KRB5CCNAME":         "FILE:/run/ignored.ccache",
	}))
	if err != nil {
		t.Fatalf("resolve keytab: %v", err)
	}
	if keytab.source != serviceGSSAPIKeytab || keytab.credentialPath != "/run/lloadd.keytab" {
		t.Fatalf("keytab settings = %#v", keytab)
	}
	keytab.clear()

	cacheConfig := base
	cacheConfig.AuthenticationID = ""
	cacheConfig.Realm = ""
	cache, err := resolveServiceGSSAPISettings(cacheConfig, lookup(map[string]string{
		"KRB5CCNAME": "FILE:/run/krb5cc_lloadd",
	}))
	if err != nil {
		t.Fatalf("resolve ccache: %v", err)
	}
	if cache.source != serviceGSSAPICCache || cache.credentialPath != "/run/krb5cc_lloadd" {
		t.Fatalf("ccache settings = %#v", cache)
	}
	cache.clear()

	for _, test := range []struct {
		name    string
		values  map[string]string
		message string
	}{
		{
			name:    "keytab KCM",
			values:  map[string]string{"KRB5_CLIENT_KTNAME": "KCM:service"},
			message: "provider \"KCM\" is unsupported",
		},
		{
			name:    "ccache KEYRING",
			values:  map[string]string{"KRB5CCNAME": "KEYRING:persistent:1000"},
			message: "provider \"KEYRING\" is unsupported",
		},
		{
			name:    "empty FILE",
			values:  map[string]string{"KRB5CCNAME": "FILE:"},
			message: "path is empty",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := cacheConfig
			if strings.Contains(test.name, "keytab") {
				config = base
			}
			_, err := resolveServiceGSSAPISettings(config, lookup(test.values))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("provider error = %v, want %q", err, test.message)
			}
		})
	}

	if _, _, err := normalizeServiceGSSAPIPrincipal(
		"lloadd@ONE.TEST",
		"TWO.TEST",
	); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("realm conflict error = %v", err)
	}
	if _, err := parseServiceGSSAPISecurityProperties("passcred"); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unsupported secprops error = %v", err)
	}
	if _, err := parseServiceGSSAPISecurityProperties("forwardsec"); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unsupported forwardsec error = %v", err)
	}
}

func TestBindConfMapsServiceGSSAPIPassword(t *testing.T) {
	config, err := Parse(strings.NewReader(`
feature proxyauthz
bindconf bindmethod=sasl saslmech=GSSAPI authcid=lloadd@EXAMPLE.TEST \
 realm=EXAMPLE.TEST authzid=u:lloadd credentials=fixed-password \
 secprops=minssf=1,maxssf=1,maxbufsize=32768 timeout=4
tier roundrobin
backend-server uri=ldap://Backend.Example.Test:389 numconns=1 bindconns=1
`))
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	bind := runtime.Bind
	if bind.SASLMechanism != "GSSAPI" ||
		bind.AuthenticationID != "lloadd@EXAMPLE.TEST" ||
		bind.Realm != "EXAMPLE.TEST" || bind.AuthorizationID != "u:lloadd" ||
		bind.SecurityProperties != "minssf=1,maxssf=1,maxbufsize=32768" ||
		string(bind.Credentials) != "fixed-password" || bind.Timeout != 4*time.Second {
		t.Fatalf("runtime GSSAPI bind = %#v", bind)
	}
	backend := serviceGSSAPIProtocolTestBackend(bind)
	backend.config.URI = runtime.Tiers[0].Backends[0].URI
	target, err := backend.serviceGSSAPITarget()
	if err != nil || target != "ldap/backend.example.test" {
		t.Fatalf("GSSAPI target = %q, %v", target, err)
	}
}

func TestServiceGSSAPIFILECredentialConstructors(t *testing.T) {
	directory := t.TempDir()
	configuration := filepath.Join(directory, "krb5.conf")
	if err := os.WriteFile(configuration, []byte(testdata.KRB5_CONF), 0o600); err != nil {
		t.Fatalf("write krb5.conf: %v", err)
	}

	kt := keytab.New()
	if err := kt.AddEntry(
		"lloadd",
		"EXAMPLE.TEST",
		"fixed-keytab-password",
		time.Unix(1_700_000_000, 0).UTC(),
		1,
		etypeID.AES128_CTS_HMAC_SHA1_96,
	); err != nil {
		t.Fatalf("add fixed keytab entry: %v", err)
	}
	encodedKeytab, err := kt.Marshal()
	if err != nil {
		t.Fatalf("marshal fixed keytab: %v", err)
	}
	keytabPath := filepath.Join(directory, "lloadd.keytab")
	if err := os.WriteFile(keytabPath, encodedKeytab, 0o600); err != nil {
		clear(encodedKeytab)
		t.Fatalf("write fixed keytab: %v", err)
	}
	clear(encodedKeytab)
	keytabInitiator, err := newServiceGSSAPIInitiator(serviceGSSAPISettings{
		source:         serviceGSSAPIKeytab,
		username:       "lloadd",
		realm:          "EXAMPLE.TEST",
		credentialPath: keytabPath,
		configuration:  configuration,
	})
	if err != nil {
		t.Fatalf("create FILE keytab initiator: %v", err)
	}
	if err := keytabInitiator.Close(); err != nil {
		t.Fatalf("close FILE keytab initiator: %v", err)
	}

	encodedCCache, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatalf("decode fixed ccache: %v", err)
	}
	ccachePath := filepath.Join(directory, "krb5cc_lloadd")
	if err := os.WriteFile(ccachePath, encodedCCache, 0o600); err != nil {
		clear(encodedCCache)
		t.Fatalf("write fixed ccache: %v", err)
	}
	clear(encodedCCache)
	ccacheInitiator, err := newServiceGSSAPIInitiator(serviceGSSAPISettings{
		source:         serviceGSSAPICCache,
		username:       "testuser1",
		realm:          "TEST.GOKRB5",
		credentialPath: ccachePath,
		configuration:  configuration,
	})
	if err != nil {
		t.Fatalf("create FILE ccache initiator: %v", err)
	}
	if err := ccacheInitiator.Close(); err != nil {
		t.Fatalf("close FILE ccache initiator: %v", err)
	}

	_, err = newServiceGSSAPIInitiator(serviceGSSAPISettings{
		source:         serviceGSSAPICCache,
		username:       "different-user",
		realm:          "TEST.GOKRB5",
		credentialPath: ccachePath,
		configuration:  configuration,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("ccache principal mismatch error = %v", err)
	}
}

func TestServiceGSSAPITimeoutCancelsTransportAndClearsSecrets(t *testing.T) {
	rawClient, peer := net.Pipe()
	client := &serviceGSSAPICloseCountingConnection{Conn: rawClient}
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	release := make(chan struct{})
	initiator := newBlockingServiceGSSAPIInitiator(release)
	backend := serviceGSSAPIProtocolTestBackend(RuntimeBindConfig{
		Method:           "sasl",
		SASLMechanism:    "GSSAPI",
		AuthenticationID: "lloadd@EXAMPLE.TEST",
		Realm:            "EXAMPLE.TEST",
		Credentials:      []byte("timeout-secret"),
		Timeout:          25 * time.Millisecond,
	})
	backend.config.URI = "ldap://backend.example.test:389"
	nextID := int64(1)
	started := time.Now()
	_, err := backend.bindServiceSASLGSSAPIWithFactory(
		context.Background(),
		client,
		&nextID,
		func(settings serviceGSSAPISettings) (serviceGSSAPIInitiator, error) {
			if string(settings.password) != "timeout-secret" {
				return nil, fmt.Errorf("password copy = %q", settings.password)
			}
			return initiator, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("GSSAPI timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("GSSAPI timeout took %s", elapsed)
	}
	close(release)
	select {
	case <-initiator.closed:
	case <-time.After(time.Second):
		t.Fatal("timed-out GSSAPI initiator was not closed")
	}
	deadline := time.Now().Add(time.Second)
	for client.closes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := client.closes.Load(); got < 2 {
		t.Fatalf("late GSSAPI result did not release its connection: close count = %d", got)
	}
	if nextID != 1 {
		t.Fatalf("timed-out GSSAPI worker changed caller message ID to %d", nextID)
	}
}

func TestServiceGSSAPIPreCanceledContextDoesNotStartWorker(t *testing.T) {
	rawClient, peer := net.Pipe()
	client := &serviceGSSAPICloseCountingConnection{Conn: rawClient}
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	backend := serviceGSSAPIProtocolTestBackend(RuntimeBindConfig{
		Method:           "sasl",
		SASLMechanism:    "GSSAPI",
		AuthenticationID: "lloadd@EXAMPLE.TEST",
		Realm:            "EXAMPLE.TEST",
		Credentials:      []byte("pre-canceled-secret"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var factoryCalls atomic.Int64
	nextID := int64(1)
	_, err := backend.bindServiceSASLGSSAPIWithFactory(
		ctx,
		client,
		&nextID,
		func(serviceGSSAPISettings) (serviceGSSAPIInitiator, error) {
			factoryCalls.Add(1)
			return nil, errorsForServiceGSSAPITest("unexpected factory call")
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled GSSAPI error = %v", err)
	}
	if got := factoryCalls.Load(); got != 0 {
		t.Fatalf("pre-canceled GSSAPI started %d credential workers", got)
	}
	if got := client.closes.Load(); got != 1 {
		t.Fatalf("pre-canceled GSSAPI transport close count = %d, want 1", got)
	}
}

type serviceGSSAPICloseCountingConnection struct {
	net.Conn
	closes atomic.Int64
}

func (connection *serviceGSSAPICloseCountingConnection) Close() error {
	connection.closes.Add(1)
	return connection.Conn.Close()
}

type blockingServiceGSSAPIInitiator struct {
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingServiceGSSAPIInitiator(release chan struct{}) *blockingServiceGSSAPIInitiator {
	return &blockingServiceGSSAPIInitiator{release: release, closed: make(chan struct{})}
}

func (initiator *blockingServiceGSSAPIInitiator) InitialToken(string, []byte) ([]byte, error) {
	<-initiator.release
	return []byte("released-token"), nil
}

func (*blockingServiceGSSAPIInitiator) AcceptAPRep([]byte) error {
	return errorsForServiceGSSAPITest("unexpected AP-REP")
}

func (*blockingServiceGSSAPIInitiator) ContextKey() (types.EncryptionKey, error) {
	return types.EncryptionKey{}, errorsForServiceGSSAPITest("context is unavailable")
}

func (*blockingServiceGSSAPIInitiator) SecurityState() (saslkrb5.SecurityState, error) {
	return saslkrb5.SecurityState{}, errorsForServiceGSSAPITest("state is unavailable")
}

func (initiator *blockingServiceGSSAPIInitiator) Close() error {
	initiator.once.Do(func() { close(initiator.closed) })
	return nil
}

func errorsForServiceGSSAPITest(message string) error { return fmt.Errorf("%s", message) }

func serviceGSSAPIProtocolTestBackend(bind RuntimeBindConfig) *runtimeBackend {
	proxy := &Proxy{
		config: RuntimeConfig{
			Bind:                   bind,
			IOTimeout:              time.Second,
			UpstreamMaxMessageSize: DefaultMaxFrameSize,
		},
		codec: berFrameCodec{},
	}
	return &runtimeBackend{
		proxy: proxy,
		config: RuntimeBackendConfig{
			URI: "ldap://backend.example.test:389",
		},
	}
}

func TestOpenLDAPReferenceLloaddServiceGSSAPISourceContract(t *testing.T) {
	sourceRoot := requirePinnedOpenLDAPLloaddSource(t)
	path := filepath.Join(sourceRoot, "servers", "lloadd", "upstream.c")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP upstream source: %v", err)
	}
	const wantHash = "db9d0725ad5cc3e41be6dd6132e68f28a55138f5544042f658db70a5d138b282"
	if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != wantHash {
		t.Fatalf("SHA-256(%s) = %s, want %s", path, got, wantHash)
	}
	for _, anchor := range []string{
		`sasl_client_new( "ldap", b->b_host`,
		"bindconf.sb_realm.bv_val, bindconf.sb_authcId.bv_val,",
		"bindconf.sb_cred.bv_val, bindconf.sb_authzId.bv_val",
		"sasl_client_start( ctx, bindconf.sb_saslmech.bv_val,",
		"sasl_client_step( ctx,",
		"ldap_pvt_sasl_install( c->c_sb, ctx );",
	} {
		if !strings.Contains(string(contents), anchor) {
			t.Fatalf("pinned OpenLDAP upstream source lacks %q", anchor)
		}
	}
}
