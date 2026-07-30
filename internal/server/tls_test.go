package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientStartTLS(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		TLSConfig:    testServerTLSConfig(t),
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedExtension"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		rootDSE.Entries[0].GetAttributeValue("supportedExtension") != startTLSOID {
		t.Fatalf("StartTLS Root DSE = %#v, %v", rootDSE, err)
	}

	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("pre-TLS root Bind(): %v", err)
	}
	whoAmI, err := client.WhoAmI(nil)
	if err != nil || whoAmI.AuthzID != "dn:cn=admin,dc=example,dc=com" {
		t.Fatalf("pre-TLS WhoAmI() = %#v, %v", whoAmI, err)
	}
	if err := client.StartTLS(&tls.Config{
		InsecureSkipVerify: true, // The test certificate is self-signed.
		MinVersion:         tls.VersionTLS12,
	}); err != nil {
		t.Fatalf("StartTLS(): %v", err)
	}
	whoAmI, err = client.WhoAmI(nil)
	if err != nil || whoAmI.AuthzID != "" {
		t.Fatalf("post-TLS WhoAmI() = %#v, %v", whoAmI, err)
	}

	assertLDAPResultCode(
		t,
		client.Add(newPersonAddRequest("anonymous-after-starttls")),
		ldap.LDAPResultStrongAuthRequired,
	)
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("post-TLS root Bind(): %v", err)
	}
	if err := client.Add(newPersonAddRequest("secured")); err != nil {
		t.Fatalf("post-TLS Add(): %v", err)
	}
}

func TestLDAPClientStartTLSUnavailableWithoutTransport(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	assertLDAPResultCode(
		t,
		client.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}),
		ldap.LDAPResultUnavailable,
	)
}

func TestLDAPClientImplicitTLS(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		TLSConfig:   testServerTLSConfig(t),
		ImplicitTLS: true,
	})
	defer stop()

	client, err := ldap.DialURL(
		"ldaps://"+address,
		ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: true, // The test certificate is self-signed.
			MinVersion:         tls.VersionTLS12,
		}),
	)
	if err != nil {
		t.Fatalf("DialURL(ldaps): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("LDAPS Bind(): %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "alice" {
		t.Fatalf("LDAPS Search() = %#v, %v", result, err)
	}
}

func TestImplicitTLSHandshakeFailureCleansUpConnection(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	instance, err := New(Config{
		Store:       store,
		TLSConfig:   testServerTLSConfig(t),
		ImplicitTLS: true,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	client, serverConnection := net.Pipe()
	instance.mu.Lock()
	instance.connections[serverConnection] = struct{}{}
	instance.mu.Unlock()
	instance.wg.Add(1)
	go instance.serveConnection(context.Background(), serverConnection)

	_, _ = client.Write([]byte("not a TLS record"))
	_ = client.Close()
	done := make(chan struct{})
	go func() {
		instance.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("failed implicit TLS connection did not stop")
	}

	instance.mu.Lock()
	connectionCount := len(instance.connections)
	instance.mu.Unlock()
	if connectionCount != 0 {
		t.Fatalf("tracked connection count = %d, want 0", connectionCount)
	}
}

func TestNewRejectsImplicitTLSWithoutTransport(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := New(Config{Store: store, ImplicitTLS: true}); err == nil {
		t.Fatal("implicit TLS without transport was accepted")
	}
}

func TestSecureTransportHandshakeTimeout(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	instance, err := New(Config{
		Store:                  store,
		SecureTransport:        waitingSecureTransport{},
		SecureHandshakeTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, err = instance.secureHandshake(context.Background(), server)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("secureHandshake() error = %v, want context deadline", err)
	}
}

type waitingSecureTransport struct{}

func (waitingSecureTransport) ServerHandshake(
	ctx context.Context,
	_ net.Conn,
) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func testServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ldap-go test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate(): %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  privateKey,
		}},
		MinVersion: tls.VersionTLS12,
	}
}
