package lloadd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestServiceSASLExternalConfiguration(t *testing.T) {
	t.Parallel()
	config, err := Parse(strings.NewReader(`
feature proxyauthz
bindconf bindmethod=sasl saslmech=external authzid=dn:cn=reader,dc=example,dc=com secprops=none
tier roundrobin
backend-server uri=ldapi://%2Ftmp%2Fldap.sock numconns=1 bindconns=1
`))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Bind.SASLMechanism != "EXTERNAL" || runtime.Bind.AuthenticationID != "" ||
		len(runtime.Bind.Credentials) != 0 || runtime.PrivilegedIdentity != "dn:"+externalTestReaderDN {
		t.Fatalf("EXTERNAL runtime = %#v", runtime.Bind)
	}
	for _, test := range []struct {
		name string
		edit func(*RuntimeBindConfig)
	}{
		{"password", func(c *RuntimeBindConfig) { c.Credentials = []byte("hidden-secret") }},
		{"authcid", func(c *RuntimeBindConfig) { c.AuthenticationID = "service" }},
		{"realm", func(c *RuntimeBindConfig) { c.Realm = "example.com" }},
		{"security layer", func(c *RuntimeBindConfig) { c.SecurityProperties = "minssf=1" }},
		{"NUL authzid", func(c *RuntimeBindConfig) { c.AuthorizationID = "dn:cn=reader\x00" }},
		{"invalid UTF8", func(c *RuntimeBindConfig) { c.AuthorizationID = "\xff" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := runtime
			test.edit(&candidate.Bind)
			if _, err := NewProxy(candidate); err == nil || strings.Contains(err.Error(), "hidden-secret") {
				t.Fatalf("invalid EXTERNAL configuration error = %v", err)
			}
		})
	}
}

type externalTestTLSConnection struct {
	net.Conn
	state tls.ConnectionState
}

func (connection externalTestTLSConnection) ConnectionState() tls.ConnectionState {
	return connection.state
}

func TestServiceSASLExternalProtocol(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		authzid     string
		code        ldapwire.ResultCode
		credentials bool
		wrongID     bool
		wantError   bool
	}{
		{name: "transport identity"},
		{name: "requested identity", authzid: "dn:" + externalTestReaderDN},
		{name: "terminal credentials ignored", credentials: true},
		{name: "denied", code: ldapwire.ResultInvalidCredentials, wantError: true},
		{name: "challenge rejected", code: ldapwire.ResultSASLBindInProgress, wantError: true},
		{name: "wrong message ID", wrongID: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
			peerDone := make(chan error, 1)
			go func() {
				message, err := ldapwire.ReadMessage(peer, ldapwire.DefaultMaxMessageSize)
				if err != nil {
					peerDone <- err
					return
				}
				bind, ok := message.Request.(ldapwire.BindRequest)
				if !ok || message.ID != 7 || bind.Version != 3 || bind.Name != "" ||
					!bind.Authentication.IsSASL || bind.Authentication.SASLMechanism != "EXTERNAL" ||
					!bind.Authentication.HasSASLCredentials || string(bind.Authentication.SASLCredentials) != test.authzid {
					peerDone <- fmt.Errorf("EXTERNAL request = %#v", message)
					return
				}
				if test.wrongID {
					message.ID++
				}
				peerDone <- ldapwire.Write(peer, ldapwire.EncodeSASLBindResponse(
					message.ID, ldapwire.Result{Code: test.code}, []byte("ignored"), test.credentials, nil,
				))
			}()
			backend := serviceSASLProtocolTestBackend(RuntimeBindConfig{
				Method: "sasl", SASLMechanism: "EXTERNAL", AuthorizationID: test.authzid,
			})
			nextID := int64(7)
			secured := &externalTestTLSConnection{client, tls.ConnectionState{HandshakeComplete: true}}
			result, err := backend.bindServiceSASL(context.Background(), secured, &nextID)
			if (err != nil) != test.wantError || nextID != 8 || result != secured {
				t.Fatalf("EXTERNAL result: next ID=%d error=%v", nextID, err)
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServiceSASLExternalRejectsUnestablishedTransport(t *testing.T) {
	t.Parallel()
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	for _, connection := range []net.Conn{client, externalTestTLSConnection{Conn: client}} {
		backend := serviceSASLProtocolTestBackend(RuntimeBindConfig{Method: "sasl", SASLMechanism: "EXTERNAL"})
		// The URI alone must never grant an external identity to a custom dialer.
		backend.config.URI = "ldapi://%2Ftmp%2Fldap.sock"
		nextID := int64(1)
		_, err := backend.bindServiceSASL(context.Background(), connection, &nextID)
		if err == nil || !strings.Contains(err.Error(), "established TLS") || nextID != 1 {
			t.Fatalf("unsecured EXTERNAL: next ID=%d error=%v", nextID, err)
		}
	}
}

const externalTestReaderDN = "cn=reader,dc=example,dc=com"

type externalTestPKI struct {
	dir        string
	serverTLS  *tls.Config
	clientTLS  *tls.Config
	caFile     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func newExternalTestPKI(t *testing.T) externalTestPKI {
	t.Helper()
	dir := t.TempDir()
	makeKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	caKey := makeKey()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "EXTERNAL test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	externalTestWrite(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	roots := x509.NewCertPool()
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(ca)
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		key := makeKey()
		certificate := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if usage == x509.ExtKeyUsageServerAuth {
			certificate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
		externalTestWrite(t, certPath, certPEM)
		externalTestWrite(t, keyPath, keyPEM)
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPath, keyPath
	}
	serverCert, serverCertPath, serverKeyPath := issue("ldap-server", 2, x509.ExtKeyUsageServerAuth)
	clientCert, clientCertPath, clientKeyPath := issue("lloadd-service", 3, x509.ExtKeyUsageClientAuth)
	return externalTestPKI{
		dir: dir, caFile: caFile, serverCert: serverCertPath, serverKey: serverKeyPath,
		clientCert: clientCertPath, clientKey: clientKeyPath,
		serverTLS: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert},
			ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots},
		clientTLS: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{clientCert}, RootCAs: roots},
	}
}

func externalTestWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func externalTestSearch(address string) error {
	connection, err := ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: time.Second}))
	if err != nil {
		return err
	}
	defer connection.Close()
	connection.SetTimeout(time.Second)
	if err := connection.Bind(externalTestReaderDN, "reader-secret"); err != nil {
		return err
	}
	result, err := connection.Search(ldap.NewSearchRequest(serviceSASLTestBaseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dc"}, nil))
	if err != nil {
		return err
	}
	if len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("dc") != "example" {
		return fmt.Errorf("EXTERNAL proxy search entries = %#v", result.Entries)
	}
	return nil
}
