package lloadd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	ldapserver "github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestServiceSASLExternalTransportsAndReconnect(t *testing.T) {
	pki := newExternalTestPKI(t)
	for _, transport := range []string{"StartTLS", "LDAPS", "LDAPI"} {
		t.Run(transport, func(t *testing.T) {
			uri := startExternalTestProjectServer(t, pki, transport)
			for _, authzid := range []string{"", "dn:" + externalTestReaderDN, "dn:cn=denied,dc=example,dc=com"} {
				t.Run(authzid, func(t *testing.T) {
					config := externalTestRuntimeConfig(uri, transport, pki)
					config.Bind.AuthorizationID = authzid
					config.PrivilegedIdentity = authzid
					proxy, err := NewProxy(config)
					if err != nil {
						t.Fatal(err)
					}
					defer proxy.Close()
					denied := strings.Contains(authzid, "cn=denied")
					for generation := 0; generation < 2; generation++ {
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						upstream, err := proxy.tiers[0].backends[0].connect(ctx, "external-test", false)
						cancel()
						if denied {
							if err == nil {
								upstream.conn.Close()
								t.Fatal("denied EXTERNAL authorization succeeded")
							}
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						wantNextID := int64(2)
						if transport == "StartTLS" {
							wantNextID++
						}
						if upstream.nextID != wantNextID {
							t.Errorf("next ID = %d, want %d", upstream.nextID, wantNextID)
						}
						connection := ldap.NewConn(upstream.conn, false)
						connection.Start()
						connection.SetTimeout(time.Second)
						identity, err := connection.WhoAmI(nil)
						connection.Close()
						want := "dn:" + serviceSASLTestDN
						if authzid != "" {
							want = authzid
						}
						if err != nil || identity == nil || identity.AuthzID != want {
							t.Fatalf("generation %d identity = %#v, %v; want %q", generation, identity, err, want)
						}
					}
					if denied {
						return
					}
					running, address := startRuntimeProxy(t, config)
					waitForReadyConnections(t, running, PoolRegular, 1)
					waitForReadyConnections(t, running, PoolBind, 1)
					if err := externalTestSearch(address); err != nil {
						t.Fatalf("EXTERNAL proxied Bind/Search: %v", err)
					}
				})
			}
		})
	}
}

func TestServiceSASLExternalMissingCertificateIsolatesBackend(t *testing.T) {
	pki := newExternalTestPKI(t)
	uri := startExternalTestProjectServer(t, pki, "LDAPS")
	config := externalTestRuntimeConfig(uri, "LDAPS", pki)
	config.BackendTLS = config.BackendTLS.Clone()
	config.BackendTLS.Certificates = nil
	proxy, address := startRuntimeProxy(t, config)
	waitForReadyConnections(t, proxy, PoolBind, 1)
	for attempt := 0; attempt < 5; attempt++ {
		if err := externalTestSearch(address); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) {
			t.Fatalf("missing client certificate search = %v", err)
		}
		if readyServiceSASLConnections(proxy, PoolRegular) != 0 {
			t.Fatal("unauthenticated connection entered regular pool")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServiceSASLExternalOptionalStartTLSCannotDowngrade(t *testing.T) {
	listener := listenBackendTLSTest(t)
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			done <- err
			return
		}
		request, ok := message.Request.(ldapwire.ExtendedRequest)
		if !ok || request.Name != upstreamStartTLSOID {
			done <- fmt.Errorf("expected StartTLS, got %#v", message.Request)
			return
		}
		if err := ldapwire.Write(connection, ldapwire.EncodeResultResponse(message.ID,
			ldapwire.ApplicationExtendedResponse, ldapwire.Result{Code: ldapwire.ResultUnavailable}, nil)); err != nil {
			done <- err
			return
		}
		_, err = ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if !errors.Is(err, io.EOF) {
			done <- fmt.Errorf("expected close without EXTERNAL after rejected StartTLS: %v", err)
			return
		}
		done <- nil
	}()
	pki := newExternalTestPKI(t)
	config := externalTestRuntimeConfig("ldap://"+listener.Addr().String(), "StartTLS", pki)
	config.Tiers[0].Backends[0].StartTLSCritical = false
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = proxy.tiers[0].backends[0].connect(ctx, "external-downgrade", false)
	if err == nil || !strings.Contains(err.Error(), "established TLS") {
		t.Fatalf("optional StartTLS failure = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func externalTestRuntimeConfig(uri, transport string, pki externalTestPKI) RuntimeConfig {
	return RuntimeConfig{
		ProxyAuthz: true, BackendTLS: pki.clientTLS, IOTimeout: time.Second,
		Bind: RuntimeBindConfig{Method: "sasl", SASLMechanism: "EXTERNAL", Timeout: time.Second},
		Tiers: []RuntimeTierConfig{{Strategy: "roundrobin", Backends: []RuntimeBackendConfig{{
			URI: uri, RegularConnections: 1, BindConnections: 1, Retry: 20 * time.Millisecond,
			StartTLS: transport == "StartTLS", StartTLSCritical: transport == "StartTLS",
		}}}},
	}
}

func startExternalTestProjectServer(t *testing.T, pki externalTestPKI, transport string) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{DN: "cn=config", Attributes: []directory.Attribute{
				{Description: "olcSaslSecProps", Values: serviceSASLValues("none")},
				{Description: "olcAuthzPolicy", Values: serviceSASLValues("to")},
				{Description: "olcAuthzRegexp", Values: serviceSASLValues(
					`{0}^cn=lloadd-service$ cn=service,dc=example,dc=com`,
					`{1}^gidNumber=[0-9]+\+uidNumber=[0-9]+,cn=peercred,cn=external,cn=auth$ cn=service,dc=example,dc=com`,
				)},
			}},
			{DN: serviceSASLTestBaseDN, Attributes: []directory.Attribute{
				{Description: "objectClass", Values: serviceSASLValues("domain")},
				{Description: "dc", Values: serviceSASLValues("example")},
			}},
		}
		for _, name := range []string{"service", "reader", "denied"} {
			entry := directory.Entry{DN: "cn=" + name + "," + serviceSASLTestBaseDN, Attributes: []directory.Attribute{
				{Description: "objectClass", Values: serviceSASLValues("organizationalRole", "simpleSecurityObject")},
				{Description: "cn", Values: serviceSASLValues(name)},
				{Description: "userPassword", Values: serviceSASLValues(name + "-secret")},
			}}
			if name == "service" {
				entry.Attributes = append(entry.Attributes, directory.Attribute{
					Description: "authzTo", Values: serviceSASLValues("dn.exact:" + externalTestReaderDN),
				})
			}
			entries = append(entries, entry)
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{serviceSASLTestBaseDN})
	}); err != nil {
		t.Fatal(err)
	}
	network, address := "tcp", "127.0.0.1:0"
	if transport == "LDAPI" {
		if runtime.GOOS == "windows" {
			t.Skip("LDAPI requires Unix peer credentials")
		}
		dir, err := os.MkdirTemp("/tmp", "ldap-go-external-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		network, address = "unix", filepath.Join(dir, "ldap.sock")
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := ldapserver.New(ldapserver.Config{
		Store: store, TLSConfig: pki.serverTLS, ImplicitTLS: transport == "LDAPS",
		RootDN: "cn=Manager,dc=example,dc=com", RootPassword: []byte("secret"),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("EXTERNAL test server did not stop")
		}
	})
	switch transport {
	case "LDAPI":
		return "ldapi://" + url.PathEscape(address)
	case "LDAPS":
		return "ldaps://" + listener.Addr().String()
	default:
		return "ldap://" + listener.Addr().String()
	}
}
