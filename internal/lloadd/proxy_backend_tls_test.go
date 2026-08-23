package lloadd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type backendTLSTestPKI struct {
	serverCertificate tls.Certificate
	caFile            string
	revokedCAFile     string
}

type backendTLSPeerResult struct {
	startTLS Frame
	bind     Frame
	err      error
}

func TestConfigRuntimeBackendTLS(t *testing.T) {
	pki := newBackendTLSTestPKI(t)
	config := backendTLSTestConfig(
		"ldaps://127.0.0.1:636",
		StartTLSImplicit,
		pki.caFile,
	)
	config.BindConf.TLS.ProtocolMin = "3.3"
	config.BindConf.TLS.ECName = "prime256v1"
	config.BindConf.TLS.CipherSuite = "HIGH:!aNULL"

	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	if runtime.BackendTLS == nil {
		t.Fatal("RuntimeConfig() did not create backend TLS configuration")
	}
	if runtime.BackendTLS.MinVersion != tls.VersionTLS12 ||
		len(runtime.BackendTLS.CurvePreferences) != 1 ||
		runtime.BackendTLS.CurvePreferences[0] != tls.CurveP256 ||
		runtime.BackendTLS.VerifyConnection == nil {
		t.Fatalf("backend TLS configuration = %#v", runtime.BackendTLS)
	}
	if runtime.Tiers[0].Backends[0].StartTLS {
		t.Fatal("LDAPS backend was also marked for StartTLS")
	}
}

func TestBackendLDAPSThenServiceBind(t *testing.T) {
	pki := newBackendTLSTestPKI(t)
	listener := listenBackendTLSTest(t)
	peer := make(chan backendTLSPeerResult, 1)
	go serveBackendLDAPS(listener, pki.serverCertificate, peer)

	proxy := newBackendTLSTestProxy(
		t,
		backendTLSTestConfig(
			"ldaps://"+listener.Addr().String(),
			StartTLSImplicit,
			pki.caFile,
		),
	)
	upstream := connectBackendTLSTest(t, proxy)
	_ = upstream.conn.Close()

	result := awaitBackendTLSPeer(t, peer)
	if result.err != nil {
		t.Fatalf("LDAPS peer: %v", result.err)
	}
	assertBackendTLSServiceBind(t, result.bind, serviceBindMessageID)
}

func TestBackendStartTLSThenServiceBind(t *testing.T) {
	pki := newBackendTLSTestPKI(t)
	listener := listenBackendTLSTest(t)
	peer := make(chan backendTLSPeerResult, 1)
	go serveBackendStartTLS(
		listener,
		pki.serverCertificate,
		ldapwire.ResultSuccess,
		true,
		peer,
	)

	proxy := newBackendTLSTestProxy(
		t,
		backendTLSTestConfig(
			"ldap://"+listener.Addr().String(),
			StartTLSCritical,
			pki.caFile,
		),
	)
	upstream := connectBackendTLSTest(t, proxy)
	_ = upstream.conn.Close()

	result := awaitBackendTLSPeer(t, peer)
	if result.err != nil {
		t.Fatalf("StartTLS peer: %v", result.err)
	}
	if result.startTLS.MessageID != serviceBindMessageID ||
		result.startTLS.ProtocolTag != TagExtendedRequest ||
		result.startTLS.ExtendedOID != upstreamStartTLSOID {
		t.Fatalf("StartTLS request = %s", result.startTLS)
	}
	assertBackendTLSServiceBind(t, result.bind, serviceBindMessageID+1)
}

func TestBackendStartTLSOptionalAndCriticalFailure(t *testing.T) {
	pki := newBackendTLSTestPKI(t)
	t.Run("optional continues in cleartext", func(t *testing.T) {
		listener := listenBackendTLSTest(t)
		peer := make(chan backendTLSPeerResult, 1)
		go serveBackendStartTLS(
			listener,
			pki.serverCertificate,
			ldapwire.ResultUnavailable,
			true,
			peer,
		)
		proxy := newBackendTLSTestProxy(
			t,
			backendTLSTestConfig(
				"ldap://"+listener.Addr().String(),
				StartTLSOptional,
				pki.caFile,
			),
		)
		upstream := connectBackendTLSTest(t, proxy)
		_ = upstream.conn.Close()

		result := awaitBackendTLSPeer(t, peer)
		if result.err != nil {
			t.Fatalf("optional StartTLS peer: %v", result.err)
		}
		assertBackendTLSServiceBind(t, result.bind, serviceBindMessageID+1)
	})

	t.Run("optional does not downgrade after acceptance", func(t *testing.T) {
		listener := listenBackendTLSTest(t)
		peer := make(chan backendTLSPeerResult, 1)
		go serveBackendStartTLSAndClose(listener, peer)
		proxy := newBackendTLSTestProxy(
			t,
			backendTLSTestConfig(
				"ldap://"+listener.Addr().String(),
				StartTLSOptional,
				pki.caFile,
			),
		)
		backend := proxy.tiers[0].backends[0]
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		upstream, err := backend.connect(ctx, backendConnectionID(backend.id, false, 0), false)
		if upstream != nil {
			_ = upstream.conn.Close()
			t.Fatal("optional StartTLS handshake failure returned an upstream connection")
		}
		if err == nil || !strings.Contains(err.Error(), "StartTLS handshake") {
			t.Fatalf("optional StartTLS handshake error = %v", err)
		}
		if result := awaitBackendTLSPeer(t, peer); result.err != nil {
			t.Fatalf("accepted StartTLS peer: %v", result.err)
		}
	})

	t.Run("critical closes connection", func(t *testing.T) {
		listener := listenBackendTLSTest(t)
		peer := make(chan backendTLSPeerResult, 1)
		go serveBackendStartTLS(
			listener,
			pki.serverCertificate,
			ldapwire.ResultUnavailable,
			false,
			peer,
		)
		proxy := newBackendTLSTestProxy(
			t,
			backendTLSTestConfig(
				"ldap://"+listener.Addr().String(),
				StartTLSCritical,
				pki.caFile,
			),
		)
		backend := proxy.tiers[0].backends[0]
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		upstream, err := backend.connect(ctx, backendConnectionID(backend.id, false, 0), false)
		if upstream != nil {
			_ = upstream.conn.Close()
			t.Fatal("critical StartTLS returned an upstream connection")
		}
		if err == nil || !strings.Contains(err.Error(), "critical StartTLS failed") {
			t.Fatalf("critical StartTLS error = %v", err)
		}
		result := awaitBackendTLSPeer(t, peer)
		if result.err != nil {
			t.Fatalf("critical StartTLS peer: %v", result.err)
		}
		if result.bind.Raw != nil {
			t.Fatalf("service Bind was sent after critical StartTLS failure: %s", result.bind)
		}
	})
}

func TestBackendTLSCertificateValidationFailsClosed(t *testing.T) {
	serverPKI := newBackendTLSTestPKI(t)
	untrustedPKI := newBackendTLSTestPKI(t)
	for _, policy := range []string{"demand", "try"} {
		t.Run(policy, func(t *testing.T) {
			listener := listenBackendTLSTest(t)
			peer := make(chan backendTLSPeerResult, 1)
			go serveBackendLDAPS(listener, serverPKI.serverCertificate, peer)
			config := backendTLSTestConfig(
				"ldaps://"+listener.Addr().String(),
				StartTLSImplicit,
				untrustedPKI.caFile,
			)
			config.BindConf.TLS.RequireCert = policy
			proxy := newBackendTLSTestProxy(t, config)
			backend := proxy.tiers[0].backends[0]
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			upstream, err := backend.connect(ctx, backendConnectionID(backend.id, false, 0), false)
			if upstream != nil {
				_ = upstream.conn.Close()
				t.Fatal("untrusted LDAPS returned an upstream connection")
			}
			if err == nil || !strings.Contains(err.Error(), "verify upstream TLS certificate chain") {
				t.Fatalf("untrusted LDAPS error = %v", err)
			}
			if result := awaitBackendTLSPeer(t, peer); result.err == nil {
				t.Fatal("untrusted LDAPS server unexpectedly completed its handshake")
			}
		})
	}
}

func TestBackendTLSRevocationFailsClosed(t *testing.T) {
	pki := newBackendTLSTestPKI(t)
	listener := listenBackendTLSTest(t)
	peer := make(chan backendTLSPeerResult, 1)
	go serveBackendLDAPS(listener, pki.serverCertificate, peer)
	config := backendTLSTestConfig(
		"ldaps://"+listener.Addr().String(),
		StartTLSImplicit,
		pki.revokedCAFile,
	)
	config.BindConf.TLS.CRLCheck = "peer"
	proxy := newBackendTLSTestProxy(t, config)
	backend := proxy.tiers[0].backends[0]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	upstream, err := backend.connect(ctx, backendConnectionID(backend.id, false, 0), false)
	if upstream != nil {
		_ = upstream.conn.Close()
		t.Fatal("revoked LDAPS certificate returned an upstream connection")
	}
	if err == nil || !strings.Contains(err.Error(), "is revoked") {
		t.Fatalf("revoked LDAPS error = %v", err)
	}
	if result := awaitBackendTLSPeer(t, peer); result.err == nil {
		t.Fatal("revoked LDAPS server unexpectedly completed its handshake")
	}
}

func backendTLSTestConfig(uri string, startTLS StartTLSMode, caFile string) Config {
	config := DefaultConfig()
	config.ProxyAuthz = true
	config.BindConf = BindConfig{
		Method:      BindSimple,
		BindDN:      "cn=Manager,dc=example,dc=com",
		Credentials: "secret",
		Timeout:     time.Second,
		TLS: BindTLSConfig{
			CACertificate: caFile,
			RequireCert:   "demand",
			RequireSAN:    "hard",
		},
	}
	backend := DefaultBackendConfig()
	backend.URI = uri
	backend.StartTLS = startTLS
	config.Tiers = []TierConfig{{
		Name:     "primary",
		Policy:   TierRoundRobin,
		Backends: []BackendConfig{backend},
	}}
	return config
}

func newBackendTLSTestProxy(t *testing.T, config Config) *Proxy {
	t.Helper()
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	proxy, err := NewProxy(runtime)
	if err != nil {
		t.Fatalf("NewProxy(): %v", err)
	}
	return proxy
}

func connectBackendTLSTest(t *testing.T, proxy *Proxy) *upstreamConnection {
	t.Helper()
	backend := proxy.tiers[0].backends[0]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	upstream, err := backend.connect(ctx, backendConnectionID(backend.id, false, 0), false)
	if err != nil {
		t.Fatalf("backend.connect(): %v", err)
	}
	return upstream
}

func listenBackendTLSTest(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func serveBackendLDAPS(
	listener net.Listener,
	certificate tls.Certificate,
	result chan<- backendTLSPeerResult,
) {
	peerResult := backendTLSPeerResult{}
	connection, err := listener.Accept()
	if err != nil {
		peerResult.err = err
		result <- peerResult
		return
	}
	defer connection.Close()
	secured := tls.Server(connection, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err := secured.Handshake(); err != nil {
		peerResult.err = err
		result <- peerResult
		return
	}
	peerResult.bind, peerResult.err = ReadFrame(secured, DefaultMaxFrameSize)
	if peerResult.err == nil {
		peerResult.err = ldapwire.Write(secured, ldapwire.EncodeBindResponse(
			peerResult.bind.MessageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}
	result <- peerResult
}

func serveBackendStartTLS(
	listener net.Listener,
	certificate tls.Certificate,
	startTLSResult ldapwire.ResultCode,
	expectBind bool,
	result chan<- backendTLSPeerResult,
) {
	peerResult := backendTLSPeerResult{}
	connection, err := listener.Accept()
	if err != nil {
		peerResult.err = err
		result <- peerResult
		return
	}
	defer connection.Close()
	peerResult.startTLS, peerResult.err = ReadFrame(connection, DefaultMaxFrameSize)
	if peerResult.err != nil {
		result <- peerResult
		return
	}
	peerResult.err = ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
		peerResult.startTLS.MessageID,
		ldapwire.Result{Code: startTLSResult},
		upstreamStartTLSOID,
		nil,
		nil,
	))
	if peerResult.err != nil {
		result <- peerResult
		return
	}
	if !expectBind {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		var next [1]byte
		_, err := connection.Read(next[:])
		if err == nil {
			peerResult.err = errors.New("received data after critical StartTLS rejection")
		} else {
			var netError net.Error
			if errors.As(err, &netError) && netError.Timeout() {
				peerResult.err = err
			}
		}
		result <- peerResult
		return
	}

	bindConnection := connection
	if startTLSResult == ldapwire.ResultSuccess {
		secured := tls.Server(connection, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
		if err := secured.Handshake(); err != nil {
			peerResult.err = err
			result <- peerResult
			return
		}
		bindConnection = secured
	}
	peerResult.bind, peerResult.err = ReadFrame(bindConnection, DefaultMaxFrameSize)
	if peerResult.err == nil {
		peerResult.err = ldapwire.Write(bindConnection, ldapwire.EncodeBindResponse(
			peerResult.bind.MessageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}
	result <- peerResult
}

func serveBackendStartTLSAndClose(
	listener net.Listener,
	result chan<- backendTLSPeerResult,
) {
	peerResult := backendTLSPeerResult{}
	connection, err := listener.Accept()
	if err != nil {
		peerResult.err = err
		result <- peerResult
		return
	}
	defer connection.Close()
	peerResult.startTLS, peerResult.err = ReadFrame(connection, DefaultMaxFrameSize)
	if peerResult.err == nil {
		peerResult.err = ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			peerResult.startTLS.MessageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			upstreamStartTLSOID,
			nil,
			nil,
		))
	}
	result <- peerResult
}

func assertBackendTLSServiceBind(t *testing.T, frame Frame, messageID int64) {
	t.Helper()
	if frame.MessageID != messageID || frame.ProtocolTag != TagBindRequest || frame.Bind == nil ||
		frame.Bind.DN != "cn=Manager,dc=example,dc=com" {
		t.Fatalf("service Bind = %s", frame)
	}
}

func awaitBackendTLSPeer(
	t *testing.T,
	peer <-chan backendTLSPeerResult,
) backendTLSPeerResult {
	t.Helper()
	select {
	case result := <-peer:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("TLS backend peer did not finish")
		return backendTLSPeerResult{}
	}
}

func newBackendTLSTestPKI(t *testing.T) backendTLSTestPKI {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ldap-go lloadd test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte("ldap-go-lloadd-test-ca"),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(
		rand.Reader,
		serverTemplate,
		caTemplate,
		serverPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	revocationDER, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			SignatureAlgorithm: x509.PureEd25519,
			RevokedCertificateEntries: []x509.RevocationListEntry{{
				SerialNumber:   serverTemplate.SerialNumber,
				RevocationTime: now,
			}},
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(time.Hour),
		},
		caCertificate,
		caPrivate,
	)
	if err != nil {
		t.Fatalf("create certificate revocation list: %v", err)
	}
	serverKey, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	serverCertificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKey}),
	)
	if err != nil {
		t.Fatalf("load server certificate: %v", err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(
		caFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		0o600,
	); err != nil {
		t.Fatalf("write CA certificate: %v", err)
	}
	revokedCAFile := filepath.Join(t.TempDir(), "ca-with-crl.pem")
	caAndCRL := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caAndCRL = append(
		caAndCRL,
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: revocationDER})...,
	)
	if err := os.WriteFile(revokedCAFile, caAndCRL, 0o600); err != nil {
		t.Fatalf("write CA and CRL: %v", err)
	}
	return backendTLSTestPKI{
		serverCertificate: serverCertificate,
		caFile:            caFile,
		revokedCAFile:     revokedCAFile,
	}
}

func (result backendTLSPeerResult) String() string {
	return fmt.Sprintf("StartTLS=%s Bind=%s error=%v", result.startTLS, result.bind, result.err)
}
