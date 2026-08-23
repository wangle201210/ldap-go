package lloadd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	ldapserver "github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

const (
	serviceSASLTestDN       = "cn=service,dc=example,dc=com"
	serviceSASLTestPassword = "lloadd-service-secret"
	serviceSASLTestBaseDN   = "dc=example,dc=com"
)

func TestRuntimeConfigMapsServiceSASL(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(`
feature proxyauthz
bindconf bindmethod=sasl saslmech=DIGEST-MD5 authcid=service \
 authzid=u:service realm=example.com credentials=lloadd-service-secret secprops=none timeout=3
tier roundrobin
backend-server uri=ldap://127.0.0.1:389 numconns=1 bindconns=1
`))
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	bind := runtime.Bind
	if bind.Method != "sasl" || bind.SASLMechanism != "DIGEST-MD5" ||
		bind.AuthenticationID != "service" || bind.AuthorizationID != "u:service" ||
		bind.Realm != "example.com" || bind.SecurityProperties != "none" ||
		string(bind.Credentials) != serviceSASLTestPassword || bind.Timeout != 3*time.Second {
		t.Fatalf("runtime SASL bind = %#v", bind)
	}
	if runtime.PrivilegedIdentity != "u:service" {
		t.Fatalf("runtime privileged identity = %q", runtime.PrivilegedIdentity)
	}
}

func TestRuntimeServiceSASLRejectsUnsupportedModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		bind    RuntimeBindConfig
		message string
	}{
		{
			name: "GSSAPI",
			bind: RuntimeBindConfig{Method: "sasl", SASLMechanism: "GSSAPI",
				AuthenticationID: "service", Credentials: []byte("hidden")},
			message: "GSSAPI is not supported",
		},
		{
			name: "SCRAM PLUS",
			bind: RuntimeBindConfig{Method: "sasl", SASLMechanism: "SCRAM-SHA-256-PLUS",
				AuthenticationID: "service", Credentials: []byte("hidden")},
			message: "SCRAM-PLUS is not supported",
		},
		{
			name: "security layer",
			bind: RuntimeBindConfig{Method: "sasl", SASLMechanism: "SCRAM-SHA-256",
				AuthenticationID: "service", Credentials: []byte("hidden"),
				SecurityProperties: "minssf=1"},
			message: "auth-only mode",
		},
		{
			name: "CRAM authzid",
			bind: RuntimeBindConfig{Method: "sasl", SASLMechanism: "CRAM-MD5",
				AuthenticationID: "service", AuthorizationID: "u:service",
				Credentials: []byte("hidden")},
			message: "does not support authzid",
		},
		{
			name: "missing authcid",
			bind: RuntimeBindConfig{Method: "sasl", SASLMechanism: "PLAIN",
				Credentials: []byte("hidden")},
			message: "requires authcid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewProxy(RuntimeConfig{ProxyAuthz: true, Bind: test.bind})
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("NewProxy() error = %v, want %q", err, test.message)
			}
			if strings.Contains(err.Error(), "hidden") {
				t.Fatalf("NewProxy() exposed credentials: %v", err)
			}
		})
	}
}

func TestServiceSASLCredentialsAreClonedAndCleared(t *testing.T) {
	t.Parallel()

	credentials := []byte(serviceSASLTestPassword)
	proxy, err := NewProxy(RuntimeConfig{
		ProxyAuthz: true,
		Bind: RuntimeBindConfig{
			Method:           "sasl",
			SASLMechanism:    "SCRAM-SHA-256",
			AuthenticationID: "service",
			Credentials:      credentials,
		},
	})
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	owned := proxy.config.Bind.Credentials
	credentials[0] ^= 0xff
	if string(owned) != serviceSASLTestPassword {
		t.Fatal("NewProxy retained the caller-owned credential buffer")
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if proxy.config.Bind.Credentials != nil {
		t.Fatal("Close retained service SASL credentials")
	}
	for _, value := range owned {
		if value != 0 {
			t.Fatal("Close did not clear the owned service credential buffer")
		}
	}
}

func TestServiceSASLProjectServerTopology(t *testing.T) {
	mechanisms := []struct {
		name              string
		authorizationID   string
		realm             string
		wantNextMessageID int64
	}{
		{name: "PLAIN", authorizationID: "u:service", wantNextMessageID: 2},
		{name: "CRAM-MD5", wantNextMessageID: 3},
		{name: "DIGEST-MD5", authorizationID: "u:service", realm: "example.com", wantNextMessageID: 3},
		{name: "SCRAM-SHA-1", authorizationID: "u:service", wantNextMessageID: 3},
		{name: "SCRAM-SHA-256", authorizationID: "u:service", wantNextMessageID: 3},
		{name: "SCRAM-SHA-512", authorizationID: "u:service", wantNextMessageID: 3},
	}
	for _, mechanism := range mechanisms {
		mechanism := mechanism
		t.Run(mechanism.name, func(t *testing.T) {
			t.Parallel()

			address := startServiceSASLProjectServer(t, serviceSASLTestPassword, nil)
			proxy, _ := startRuntimeProxy(t, serviceSASLRuntimeConfig(
				address,
				mechanism.name,
				mechanism.authorizationID,
				mechanism.realm,
			))
			waitForReadyConnections(t, proxy, PoolRegular, 1)
			waitForReadyConnections(t, proxy, PoolBind, 1)
			if nextID := regularServiceSASLNextID(t, proxy); nextID != mechanism.wantNextMessageID {
				t.Fatalf("%s next upstream message ID = %d, want %d", mechanism.name, nextID, mechanism.wantNextMessageID)
			}
		})
	}
}

func TestServiceSASLStartsAfterBackendStartTLS(t *testing.T) {
	t.Parallel()

	pki := newBackendTLSTestPKI(t)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{pki.serverCertificate},
		MinVersion:   tls.VersionTLS12,
	}
	address := startServiceSASLProjectServer(t, serviceSASLTestPassword, serverTLS)
	backendTLS, err := buildBackendTLSConfig(BindTLSConfig{
		CACertificate: pki.caFile,
		RequireCert:   "demand",
	})
	if err != nil {
		t.Fatalf("buildBackendTLSConfig(): %v", err)
	}
	config := serviceSASLRuntimeConfig(address, "PLAIN", "u:service", "")
	config.BackendTLS = backendTLS
	config.Tiers[0].Backends[0].StartTLS = true
	config.Tiers[0].Backends[0].StartTLSCritical = true
	proxy, _ := startRuntimeProxy(t, config)
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	if nextID := regularServiceSASLNextID(t, proxy); nextID != 3 {
		t.Fatalf("StartTLS PLAIN next upstream message ID = %d, want 3", nextID)
	}
}

func TestServiceSASLFailureIsolatesBackendAndSecrets(t *testing.T) {
	t.Parallel()

	goodAddress := startServiceSASLProjectServer(t, serviceSASLTestPassword, nil)
	badAddress := startServiceSASLProjectServer(t, "different-service-secret", nil)
	var logs bytes.Buffer
	config := serviceSASLRuntimeConfig(goodAddress, "SCRAM-SHA-256", "u:service", "")
	config.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	config.Tiers[0].Backends = append(
		config.Tiers[0].Backends,
		proxyTestBackend(badAddress),
	)
	proxy, _ := startRuntimeProxy(t, config)
	waitForReadyConnections(t, proxy, PoolRegular, 1)
	waitForReadyConnections(t, proxy, PoolBind, 2)
	time.Sleep(100 * time.Millisecond)
	if ready := readyServiceSASLConnections(proxy, PoolRegular); ready != 1 {
		t.Fatalf("ready regular connections = %d, want only healthy backend", ready)
	}
	if strings.Contains(logs.String(), serviceSASLTestPassword) ||
		strings.Contains(logs.String(), "different-service-secret") {
		t.Fatalf("service SASL logs exposed credentials: %q", logs.String())
	}
}

func TestServiceSASLSCRAMRejectsInvalidServerSignature(t *testing.T) {
	t.Parallel()

	credentialClient, err := scram.SHA256.NewClient(
		"service",
		serviceSASLTestPassword,
		"",
	)
	if err != nil {
		t.Fatalf("create SCRAM credential client: %v", err)
	}
	credentials, err := credentialClient.GetStoredCredentialsWithError(scram.KeyFactors{
		Salt:  "fixed-service-salt",
		Iters: serviceSCRAMMinIterations,
	})
	if err != nil {
		t.Fatalf("derive SCRAM credentials: %v", err)
	}
	scramServer, err := scram.SHA256.NewServer(func(username string) (scram.StoredCredentials, error) {
		if username != "service" {
			return scram.StoredCredentials{}, errors.New("unknown service account")
		}
		return credentials, nil
	})
	if err != nil {
		t.Fatalf("create SCRAM server: %v", err)
	}
	conversation := scramServer.NewConversation()
	client, peer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	peerDone := make(chan error, 1)
	go func() {
		for step := 0; step < 2; step++ {
			message, err := ldapwire.ReadMessage(peer, ldapwire.DefaultMaxMessageSize)
			if err != nil {
				peerDone <- err
				return
			}
			request, ok := message.Request.(ldapwire.BindRequest)
			if !ok || request.Authentication.SASLMechanism != "SCRAM-SHA-256" ||
				!request.Authentication.HasSASLCredentials {
				peerDone <- fmt.Errorf("unexpected SCRAM service request: %#v", message.Request)
				return
			}
			response, err := conversation.Step(string(request.Authentication.SASLCredentials))
			if err != nil {
				peerDone <- err
				return
			}
			code := ldapwire.ResultSASLBindInProgress
			if step == 1 {
				code = ldapwire.ResultSuccess
				proof, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(response, "v="))
				if err != nil || len(proof) == 0 {
					peerDone <- errors.New("SCRAM server produced malformed proof")
					return
				}
				proof[0] ^= 0xff
				response = "v=" + base64.StdEncoding.EncodeToString(proof)
				clear(proof)
			}
			if err := ldapwire.Write(peer, ldapwire.EncodeSASLBindResponse(
				message.ID,
				ldapwire.Result{Code: code},
				[]byte(response),
				true,
				nil,
			)); err != nil {
				peerDone <- err
				return
			}
		}
		peerDone <- nil
	}()
	backend := serviceSASLProtocolTestBackend(RuntimeBindConfig{
		Method:           "sasl",
		SASLMechanism:    "SCRAM-SHA-256",
		AuthenticationID: "service",
		Credentials:      []byte(serviceSASLTestPassword),
	})
	nextID := int64(1)
	err = backend.bindServiceSASL(client, &nextID)
	if err == nil || !strings.Contains(err.Error(), "server signature is invalid") {
		t.Fatalf("invalid SCRAM server signature error = %v", err)
	}
	if strings.Contains(err.Error(), serviceSASLTestPassword) {
		t.Fatalf("SCRAM signature error exposed credentials: %v", err)
	}
	if peerErr := <-peerDone; peerErr != nil {
		t.Fatalf("SCRAM proof peer: %v", peerErr)
	}
}

func TestServiceSASLDigestMD5RejectsInvalidServerProof(t *testing.T) {
	t.Parallel()

	client, peer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	peerDone := make(chan error, 1)
	go func() {
		first, err := ldapwire.ReadMessage(peer, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			peerDone <- err
			return
		}
		if err := ldapwire.Write(peer, ldapwire.EncodeSASLBindResponse(
			first.ID,
			ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
			[]byte(`realm="example.com",nonce="fixed-nonce",qop="auth",charset=utf-8,algorithm=md5-sess`),
			true,
			nil,
		)); err != nil {
			peerDone <- err
			return
		}
		second, err := ldapwire.ReadMessage(peer, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			peerDone <- err
			return
		}
		peerDone <- ldapwire.Write(peer, ldapwire.EncodeSASLBindResponse(
			second.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			[]byte("rspauth=00000000000000000000000000000000"),
			true,
			nil,
		))
	}()
	backend := serviceSASLProtocolTestBackend(RuntimeBindConfig{
		Method:           "sasl",
		SASLMechanism:    "DIGEST-MD5",
		AuthenticationID: "service",
		Realm:            "example.com",
		Credentials:      []byte(serviceSASLTestPassword),
	})
	nextID := int64(1)
	err := backend.bindServiceSASL(client, &nextID)
	if err == nil || !strings.Contains(err.Error(), "server proof is invalid") {
		t.Fatalf("invalid DIGEST-MD5 server proof error = %v", err)
	}
	if strings.Contains(err.Error(), serviceSASLTestPassword) {
		t.Fatalf("DIGEST-MD5 proof error exposed credentials: %v", err)
	}
	if peerErr := <-peerDone; peerErr != nil {
		t.Fatalf("DIGEST-MD5 proof peer: %v", peerErr)
	}
}

func TestServiceSASLSCRAMStrictServerParameters(t *testing.T) {
	t.Parallel()

	clientNonce := "fixed-client-nonce"
	tests := []struct {
		name    string
		value   string
		message string
	}{
		{name: "nonce not extended", value: "r=" + clientNonce + ",s=c2FsdA==,i=4096", message: "strictly extend"},
		{name: "low iterations", value: "r=" + clientNonce + "server,s=c2FsdA==,i=4095", message: "between 4096 and 10000000"},
		{name: "high iterations", value: "r=" + clientNonce + "server,s=c2FsdA==,i=10000001", message: "between 4096 and 10000000"},
		{name: "noncanonical iterations", value: "r=" + clientNonce + "server,s=c2FsdA==,i=04096", message: "not canonical"},
		{name: "malformed salt", value: "r=" + clientNonce + "server,s=***,i=4096", message: "salt is malformed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateServiceSCRAMServerFirst([]byte(test.value), clientNonce)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("validate server-first error = %v, want %q", err, test.message)
			}
		})
	}
}

func serviceSASLRuntimeConfig(
	address string,
	mechanism string,
	authorizationID string,
	realm string,
) RuntimeConfig {
	return RuntimeConfig{
		ProxyAuthz: true,
		Bind: RuntimeBindConfig{
			Method:             "sasl",
			SASLMechanism:      mechanism,
			AuthenticationID:   "service",
			AuthorizationID:    authorizationID,
			Realm:              realm,
			Credentials:        []byte(serviceSASLTestPassword),
			SecurityProperties: "none",
			Timeout:            2 * time.Second,
		},
		Tiers: []RuntimeTierConfig{{
			Strategy: "roundrobin",
			Backends: []RuntimeBackendConfig{proxyTestBackend(address)},
		}},
	}
}

func serviceSASLProtocolTestBackend(bind RuntimeBindConfig) *runtimeBackend {
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
			URI: "ldap://127.0.0.1:389",
		},
	}
}

func startServiceSASLProjectServer(
	t *testing.T,
	password string,
	tlsConfig *tls.Config,
) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{
			DN: serviceSASLTestBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: serviceSASLValues("domain")},
				{Description: "dc", Values: serviceSASLValues("example")},
			},
		}, false); err != nil {
			return err
		}
		if err := writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcSaslHost", Values: serviceSASLValues("ldap.example.test")},
				{Description: "olcSaslRealm", Values: serviceSASLValues("example.com")},
				{Description: "olcSaslSecProps", Values: serviceSASLValues("none")},
				{Description: "olcAuthzRegexp", Values: serviceSASLValues(
					`{0}^uid=([^,]+),cn=example\.com,cn=plain,cn=auth$ cn=service,dc=example,dc=com`,
					`{1}^uid=([^,]+),cn=example\.com,cn=cram-md5,cn=auth$ cn=service,dc=example,dc=com`,
					`{2}^uid=([^,]+),cn=example\.com,cn=digest-md5,cn=auth$ cn=service,dc=example,dc=com`,
					`{3}^uid=([^,]+),cn=example\.com,cn=scram-sha-1,cn=auth$ cn=service,dc=example,dc=com`,
					`{4}^uid=([^,]+),cn=example\.com,cn=scram-sha-256,cn=auth$ cn=service,dc=example,dc=com`,
					`{5}^uid=([^,]+),cn=example\.com,cn=scram-sha-512,cn=auth$ cn=service,dc=example,dc=com`,
				)},
			},
		}, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{serviceSASLTestBaseDN})
	}); err != nil {
		t.Fatalf("seed service SASL server: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for service SASL server: %v", err)
	}
	instance, err := ldapserver.New(ldapserver.Config{
		Store:        store,
		RootDN:       serviceSASLTestDN,
		RootPassword: []byte(password),
		TLSConfig:    tlsConfig,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("server.New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("service SASL server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("service SASL server did not stop")
		}
	})
	return listener.Addr().String()
}

func serviceSASLValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}

func regularServiceSASLNextID(t *testing.T, proxy *Proxy) int64 {
	t.Helper()
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	for _, upstream := range proxy.upstreams {
		if upstream.bind {
			continue
		}
		upstream.mu.Lock()
		nextID := upstream.nextID
		upstream.mu.Unlock()
		return nextID
	}
	t.Fatal("no regular service SASL connection")
	return 0
}

func readyServiceSASLConnections(proxy *Proxy, pool Pool) int {
	ready := 0
	for _, connection := range proxy.scheduler.Snapshot().Connections {
		if connection.Pool == pool && connection.State == ConnectionReady {
			ready++
		}
	}
	return ready
}
