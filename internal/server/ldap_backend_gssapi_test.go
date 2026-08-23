package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

func TestLDAPBackendGSSAPIIntegrityTransport(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	key := ldapBackendGSSAPITestKey()
	state := saslkrb5.SecurityState{
		SendSequence:    11,
		ReceiveSequence: 29,
		AcceptorSubkey:  true,
	}
	serverDone := make(chan error, 1)
	go runLDAPBackendGSSAPITestServer(server, key, state, serverDone)

	initiator := &ldapBackendGSSAPITestInitiator{
		key:   ldapBackendGSSAPITestKey(),
		state: state,
	}
	configuration := syncConsumerConfig{
		bindMethod:       "sasl",
		saslMechanism:    "GSSAPI",
		authenticationID: "proxy",
		authorizationID:  "dn:uid=alice,dc=example,dc=com",
		realm:            "EXAMPLE.TEST",
		credentials:      []byte("secret"),
		credentialsSet:   true,
		securityProperties: syncConsumerSASLSecurityProperties{
			minSSF:        1,
			maxSSF:        1,
			maxBufferSize: 4096,
			noAnonymous:   true,
		},
	}
	transport := &syncConsumerTransport{connection: client, context: context.Background()}
	err := bindLDAPBackendGSSAPIWithFactory(
		context.Background(),
		transport,
		configuration,
		"ldap://ldap.example.test",
		func(settings syncConsumerGSSAPISettings) (ldapBackendGSSAPIInitiator, error) {
			if settings.servicePrincipal != "ldap/ldap.example.test" ||
				settings.authorizationID != configuration.authorizationID {
				return nil, fmt.Errorf("settings = %#v", settings)
			}
			return initiator, nil
		},
	)
	if err != nil {
		t.Fatalf("GSSAPI bind: %v", err)
	}
	if got := string(configuration.credentials); got != "secret" {
		t.Fatalf("runtime GSSAPI credentials were mutated after Bind: %q", got)
	}
	if transport.ssf != 1 {
		t.Fatalf("transport SSF = %d, want 1", transport.ssf)
	}
	if initiator.target != "ldap/ldap.example.test" || len(initiator.binding) != 0 {
		t.Fatalf("initiator target/binding = %q/%x", initiator.target, initiator.binding)
	}
	if err := transport.currentConnection().SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set protected transport deadline: %v", err)
	}
	if _, err := transport.currentConnection().Write([]byte("secured request")); err != nil {
		t.Fatalf("write protected request: %v", err)
	}
	response := make([]byte, len("secured response"))
	if _, err := io.ReadFull(transport.currentConnection(), response); err != nil {
		t.Fatalf("read protected response: %v", err)
	}
	if string(response) != "secured response" {
		t.Fatalf("protected response = %q", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("fake GSSAPI server: %v", err)
	}
}

func TestLDAPBackendGSSAPITLSChannelBinding(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	certificate := &x509.Certificate{
		Raw:                []byte("verified chain endpoint certificate"),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	secured := &ldapBackendGSSAPITLSConn{
		Conn: client,
		state: tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{certificate},
			VerifiedChains:    [][]*x509.Certificate{{certificate}},
		},
	}
	got, err := ldapBackendGSSAPIChannelBinding(secured, "")
	if err != nil || len(got) != 0 {
		t.Fatalf("default channel binding = %x, %v; want NULL", got, err)
	}
	got, err = ldapBackendGSSAPIChannelBinding(
		secured,
		saslkrb5.ChannelBindingTLSServerEndpoint,
	)
	if err != nil {
		t.Fatalf("channel binding: %v", err)
	}
	want, err := saslkrb5.TLSServerEndpoint(certificate)
	if err != nil {
		t.Fatalf("expected channel binding: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("channel binding = %x, want %x", got, want)
	}
	secured.state.VerifiedChains = nil
	if _, err := ldapBackendGSSAPIChannelBinding(
		secured,
		saslkrb5.ChannelBindingTLSServerEndpoint,
	); err == nil {
		t.Fatal("unverified TLS channel binding was accepted")
	}
}

func TestLDAPBackendGSSAPILayerSelectionAccountsForExternalSSF(t *testing.T) {
	key := ldapBackendGSSAPITestKey()
	properties := syncConsumerSASLSecurityProperties{
		minSSF:        128,
		maxSSF:        256,
		maxBufferSize: 4096,
	}
	selection, maximum, ssf, err := selectLDAPBackendGSSAPILayer(
		saslkrb5.SecurityNone|saslkrb5.SecurityIntegrity|saslkrb5.SecurityConfidentiality,
		key,
		properties,
		256,
	)
	if err != nil || selection != saslkrb5.SecurityNone || maximum != 0 || ssf != 0 {
		t.Fatalf("TLS-protected selection = %d/%d/%d, %v", selection, maximum, ssf, err)
	}

	properties.maxSSF = 384
	selection, maximum, ssf, err = selectLDAPBackendGSSAPILayer(
		saslkrb5.SecurityNone|saslkrb5.SecurityIntegrity|saslkrb5.SecurityConfidentiality,
		key,
		properties,
		128,
	)
	wantSSF, strengthErr := saslkrb5.SecurityStrength(key)
	if strengthErr != nil {
		t.Fatalf("key strength: %v", strengthErr)
	}
	if err != nil || selection != saslkrb5.SecurityConfidentiality ||
		maximum != properties.maxBufferSize || ssf != wantSSF {
		t.Fatalf("partially protected selection = %d/%d/%d, %v", selection, maximum, ssf, err)
	}
}

func TestLDAPBackendGSSAPICancellationClosesTransport(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	transport := &syncConsumerTransport{connection: client, context: context.Background()}
	started := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- bindLDAPBackendGSSAPIWithFactory(
			ctx,
			transport,
			syncConsumerConfig{
				bindMethod:       "sasl",
				saslMechanism:    "GSSAPI",
				authenticationID: "proxy",
				realm:            "EXAMPLE.TEST",
				credentials:      []byte("secret"),
				credentialsSet:   true,
			},
			"ldap://ldap.example.test",
			func(syncConsumerGSSAPISettings) (ldapBackendGSSAPIInitiator, error) {
				close(started)
				<-release
				return nil, errors.New("released")
			},
		)
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GSSAPI bind did not observe cancellation")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(ldapBackendGSSAPIInitializationSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if occupied := len(ldapBackendGSSAPIInitializationSlots); occupied != 0 {
		t.Fatalf("GSSAPI initialization slots after release = %d", occupied)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := peer.Read(buffer); err == nil {
		t.Fatal("cancellation did not close the upstream transport")
	}
}

func TestLDAPBackendGSSAPIInitializationAdmissionHonorsCancellation(t *testing.T) {
	if len(ldapBackendGSSAPIInitializationSlots) != 0 {
		t.Fatal("GSSAPI initialization slots are unexpectedly occupied")
	}
	for range cap(ldapBackendGSSAPIInitializationSlots) {
		ldapBackendGSSAPIInitializationSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for len(ldapBackendGSSAPIInitializationSlots) > 0 {
			<-ldapBackendGSSAPIInitializationSlots
		}
	})

	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	transport := &syncConsumerTransport{connection: client, context: context.Background()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var factoryCalls atomic.Int64
	go func() {
		done <- bindLDAPBackendGSSAPIWithFactory(
			ctx,
			transport,
			syncConsumerConfig{
				bindMethod:       "sasl",
				saslMechanism:    "GSSAPI",
				authenticationID: "proxy",
				realm:            "EXAMPLE.TEST",
				credentials:      []byte("secret"),
				credentialsSet:   true,
			},
			"ldap://ldap.example.test",
			func(syncConsumerGSSAPISettings) (ldapBackendGSSAPIInitiator, error) {
				factoryCalls.Add(1)
				return nil, errors.New("unexpected factory call")
			},
		)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("admission cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GSSAPI admission did not observe cancellation")
	}
	if calls := factoryCalls.Load(); calls != 0 {
		t.Fatalf("credential factory calls = %d, want 0", calls)
	}
}

func TestMetaTransportKeySeparatesGSSAPISecurityAndTLS(t *testing.T) {
	t.Setenv("KRB5_CLIENT_KTNAME", "")
	t.Setenv("KRB5_KTNAME", "")
	t.Setenv("KRB5CCNAME", "FILE:"+t.TempDir()+"/ccache")
	t.Setenv("KRB5_CONFIG", t.TempDir()+"/krb5.conf")
	base := defaultChainRemoteConfiguration()
	base.uri = "ldap://ldap.example.test"
	base.endpointKey = base.uri
	base.bind.bindMethod = "sasl"
	base.bind.saslMechanism = "GSSAPI"
	base.bind.authenticationID = "proxy"
	base.bind.realm = "EXAMPLE.TEST"
	base.bind.securityPropertiesText = "minssf=1,maxssf=1"

	security := base.clone()
	security.bind.securityPropertiesText = "minssf=128,maxssf=256"
	tlsPolicy := base.clone()
	tlsPolicy.bind.tls.requireCert = "demand"
	if metaTransportKey("target", base) == metaTransportKey("target", security) {
		t.Fatal("different GSSAPI security policies share a pool key")
	}
	if metaTransportKey("target", base) == metaTransportKey("target", tlsPolicy) {
		t.Fatal("different TLS verification policies share a pool key")
	}

	baseKey := metaTransportKey("target", base)
	t.Setenv("KRB5CCNAME", "FILE:"+t.TempDir()+"/other-ccache")
	if baseKey == metaTransportKey("target", base) {
		t.Fatal("different resolved GSSAPI credential sources share a pool key")
	}
}

func runLDAPBackendGSSAPITestServer(
	connection net.Conn,
	key types.EncryptionKey,
	state saslkrb5.SecurityState,
	done chan<- error,
) {
	fail := func(err error) { done <- err }
	first, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		fail(err)
		return
	}
	request, ok := first.Request.(ldapwire.BindRequest)
	if !ok || request.Authentication.SASLMechanism != "GSSAPI" ||
		!bytes.Equal(request.Authentication.SASLCredentials, []byte("fixed-ap-req")) {
		fail(fmt.Errorf("unexpected AP-REQ: %#v", first.Request))
		return
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		first.ID, ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
		[]byte("fixed-ap-rep"), true, nil,
	)); err != nil {
		fail(err)
		return
	}
	second, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		fail(err)
		return
	}
	offer, err := saslkrb5.Wrap(
		[]byte{saslkrb5.SecurityNone | saslkrb5.SecurityIntegrity, 0, 16, 0},
		key, true, state.AcceptorSubkey, state.ReceiveSequence,
	)
	if err != nil {
		fail(err)
		return
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		second.ID, ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
		offer, true, nil,
	)); err != nil {
		clear(offer)
		fail(err)
		return
	}
	clear(offer)
	third, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		fail(err)
		return
	}
	request, ok = third.Request.(ldapwire.BindRequest)
	if !ok || !request.Authentication.HasSASLCredentials {
		fail(fmt.Errorf("unexpected security selection: %#v", third.Request))
		return
	}
	selectionToken, err := saslkrb5.Unwrap(
		request.Authentication.SASLCredentials,
		key, false, state.AcceptorSubkey, state.SendSequence,
	)
	if err != nil {
		fail(err)
		return
	}
	selection, maximum, authorizationID, err := saslkrb5.DecodeNegotiation(selectionToken)
	clear(selectionToken)
	if err != nil || selection != saslkrb5.SecurityIntegrity ||
		authorizationID != "dn:uid=alice,dc=example,dc=com" {
		fail(fmt.Errorf("selection = %d/%d/%q: %v", selection, maximum, authorizationID, err))
		return
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		third.ID, ldapwire.Result{Code: ldapwire.ResultSuccess}, nil, false, nil,
	)); err != nil {
		fail(err)
		return
	}
	serverState := saslkrb5.SecurityState{
		SendSequence:    state.ReceiveSequence + 1,
		ReceiveSequence: state.SendSequence + 1,
		AcceptorSubkey:  state.AcceptorSubkey,
	}
	secured, err := saslkrb5.NewIntegrityConnection(
		connection, key, true, serverState, maximum, 4096,
	)
	if err != nil {
		fail(err)
		return
	}
	payload := make([]byte, len("secured request"))
	if _, err := io.ReadFull(secured, payload); err != nil {
		fail(err)
		return
	}
	if string(payload) != "secured request" {
		fail(fmt.Errorf("protected payload = %q", payload))
		return
	}
	_, err = secured.Write([]byte("secured response"))
	done <- err
}

type ldapBackendGSSAPITestInitiator struct {
	mu      sync.Mutex
	key     types.EncryptionKey
	state   saslkrb5.SecurityState
	target  string
	binding []byte
}

func (initiator *ldapBackendGSSAPITestInitiator) InitialToken(
	target string,
	binding []byte,
) ([]byte, error) {
	initiator.mu.Lock()
	defer initiator.mu.Unlock()
	initiator.target = target
	initiator.binding = bytes.Clone(binding)
	return []byte("fixed-ap-req"), nil
}

func (*ldapBackendGSSAPITestInitiator) AcceptAPRep(value []byte) error {
	if !bytes.Equal(value, []byte("fixed-ap-rep")) {
		return fmt.Errorf("AP-REP = %x", value)
	}
	return nil
}

func (initiator *ldapBackendGSSAPITestInitiator) ContextKey() (types.EncryptionKey, error) {
	return ldapBackendGSSAPITestKey(), nil
}

func (initiator *ldapBackendGSSAPITestInitiator) SecurityState() (saslkrb5.SecurityState, error) {
	return initiator.state, nil
}

func (initiator *ldapBackendGSSAPITestInitiator) Close() error {
	clear(initiator.key.KeyValue)
	return nil
}

type ldapBackendGSSAPITLSConn struct {
	net.Conn
	state tls.ConnectionState
}

func (connection *ldapBackendGSSAPITLSConn) ConnectionState() tls.ConnectionState {
	return connection.state
}

func ldapBackendGSSAPITestKey() types.EncryptionKey {
	return types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: bytes.Repeat([]byte{0x5a}, 32),
	}
}
