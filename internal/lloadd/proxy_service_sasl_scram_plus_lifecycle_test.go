package lloadd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	ldapserver "github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type serviceSCRAMPlusReplayConn struct {
	net.Conn
	reader io.Reader
}

func (conn serviceSCRAMPlusReplayConn) Read(p []byte) (int, error) { return conn.reader.Read(p) }

func TestServiceSASLSCRAMPlusPoolIdentitiesAndReconnect(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	for _, mechanism := range serviceSCRAMPlusTestMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			serviceConnections := make(chan net.Conn, 16)
			uri := startServiceSCRAMPlusTestPeer(t, pki.serverTLS, true, func(conn *tls.Conn) {
				message, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
				if err != nil {
					return
				}
				bind, ok := message.Request.(ldapwire.BindRequest)
				if !ok {
					t.Error("provider did not receive Bind first")
					return
				}
				service := bind.Authentication.IsSASL
				if service {
					encoded, err := ldapwire.EncodeRequestMessage(message)
					if err != nil {
						t.Error(err)
						return
					}
					replay := serviceSCRAMPlusReplayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(encoded), conn)}
					if !serviceSCRAMPlusTestExchange(t, replay, serviceSCRAMPlusTestBinding(pki.serverTLS.Certificates[0]), mechanism, "u:service", false, nil) {
						return
					}
					serviceConnections <- conn
					message, err = ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
				}
				for err == nil {
					switch request := message.Request.(type) {
					case ldapwire.BindRequest:
						if service || request.Authentication.IsSASL || len(message.Controls) != 0 || string(request.Authentication.Simple) == serviceSASLTestPassword {
							t.Error("service credentials/client Bind crossed pool identity boundary")
							return
						}
						code := ldapwire.ResultSuccess
						if string(request.Authentication.Simple) != "secret" {
							code = ldapwire.ResultInvalidCredentials
						}
						err = ldapwire.Write(conn, ldapwire.EncodeResultResponse(message.ID, ldapwire.ApplicationBindResponse, ldapwire.Result{Code: code}, nil))
					case ldapwire.SearchRequest:
						if !service || len(message.Controls) != 1 || message.Controls[0].OID != ProxyAuthzControlOID || !message.Controls[0].Critical {
							t.Error("search lacked service authentication and critical client ProxyAuthz")
							return
						}
						entry := directory.Entry{DN: "cn=observation", Attributes: []directory.Attribute{
							{Description: "uid", Values: [][]byte{message.Controls[0].Value}},
						}}
						err = ldapwire.Write(conn, ldapwire.EncodeSearchResultEntry(message.ID, entry, nil))
						if err == nil {
							err = ldapwire.Write(conn, ldapwire.EncodeSearchResultDone(message.ID, ldapwire.Result{}, nil))
						}
					case ldapwire.UnbindRequest:
						return
					default:
						t.Errorf("unexpected provider request %T", request)
						return
					}
					if err != nil {
						return
					}
					message, err = ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
				}
			})
			config := serviceSCRAMPlusTestConfig(t, pki, uri, mechanism, true)
			config.Tiers[0].Backends[0].Retry = 10 * time.Millisecond
			proxy, address := startRuntimeProxy(t, config)
			waitForReadyConnections(t, proxy, PoolRegular, 1)
			waitForReadyConnections(t, proxy, PoolBind, 1)
			var clients []*ldap.Conn
			for _, name := range []string{"alice", "bob"} {
				client, err := ldap.DialURL("ldap://" + address)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				client.SetTimeout(2 * time.Second)
				if err := client.Bind("cn="+name+",dc=example,dc=com", "secret"); err != nil {
					t.Fatal(err)
				}
				clients = append(clients, client)
			}
			search := func() {
				for i, client := range clients {
					result, err := client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
						0, 0, false, "(objectClass=*)", []string{"uid"}, nil))
					want := []string{"dn:cn=alice,dc=example,dc=com", "dn:cn=bob,dc=example,dc=com"}[i]
					if err != nil || len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("uid") != want {
						t.Fatalf("client identity changed across service pool: %v, %v", result, err)
					}
				}
			}
			search()
			old := <-serviceConnections
			_ = old.Close()
			select {
			case next := <-serviceConnections:
				if old == next {
					t.Fatal("reconnect reused physical TLS connection")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("service connection did not reauthenticate")
			}
			waitForReadyConnections(t, proxy, PoolRegular, 1)
			search()
		})
	}
}

func TestServiceSASLSCRAMPlusCertificateRotationNamespace(t *testing.T) {
	t.Parallel()
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, startTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("TLS=%x/StartTLS=%t", version, startTLS), func(t *testing.T) {
				old, next := newExternalTestPKI(t), newExternalTestPKI(t)
				serverTLS := old.serverTLS.Clone()
				serverTLS.ClientAuth = tls.NoClientCert
				serverTLS.MinVersion, serverTLS.MaxVersion = version, version
				var certificate atomic.Pointer[tls.Certificate]
				certificate.Store(&old.serverTLS.Certificates[0])
				serverTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate.Load(), nil }
				serverTLS.Certificates = nil
				type observation struct {
					resumed  bool
					endpoint []byte
				}
				events := make(chan observation, 4)
				uri := startServiceSCRAMPlusTestPeer(t, serverTLS, startTLS, func(conn *tls.Conn) {
					binding := serviceSCRAMPlusTestBinding(*certificate.Load())
					if serviceSCRAMPlusTestExchange(t, conn, binding, "SCRAM-SHA-256-PLUS", "u:service", false, nil) {
						events <- observation{resumed: conn.ConnectionState().DidResume, endpoint: binding.Data}
					}
				})
				config := serviceSCRAMPlusTestConfig(t, old, uri, "SCRAM-SHA-256-PLUS", startTLS)
				config.BackendTLS = old.clientTLS.Clone()
				config.BackendTLS.MinVersion, config.BackendTLS.MaxVersion = version, version
				config.BackendTLS.ClientSessionCache = tls.NewLRUClientSessionCache(8)
				first, err := NewProxy(config)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				connect := func(proxy *Proxy) observation {
					upstream, err := proxy.tiers[0].backends[0].connect(t.Context(), "rotation", false)
					if err != nil {
						t.Fatal(err)
					}
					_ = upstream.conn.Close()
					select {
					case event := <-events:
						return event
					case <-time.After(3 * time.Second):
						t.Fatal("missing verified exchange")
						return observation{}
					}
				}
				a, b := connect(first), connect(first)
				if a.resumed || !b.resumed || !bytes.Equal(a.endpoint, b.endpoint) {
					t.Fatal("fixture did not exercise TLS resumption")
				}
				certificate.Store(&next.serverTLS.Certificates[0])
				config.BackendTLS = config.BackendTLS.Clone()
				config.BackendTLS.RootCAs = next.clientTLS.RootCAs
				second, err := NewProxy(config)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
				c := connect(second)
				if c.resumed || bytes.Equal(a.endpoint, c.endpoint) || !bytes.Equal(c.endpoint, serviceSCRAMPlusTestBinding(next.serverTLS.Certificates[0]).Data) {
					t.Fatal("new proxy generation retained a retired TLS session or endpoint")
				}
				// A third namespace with stale trust must fail before any SCRAM data.
				config.BackendTLS = config.BackendTLS.Clone()
				config.BackendTLS.RootCAs = x509.NewCertPool()
				third, err := NewProxy(config)
				if err != nil {
					t.Fatal(err)
				}
				defer third.Close()
				if upstream, err := third.tiers[0].backends[0].connect(t.Context(), "stale-trust", false); err == nil || upstream != nil {
					t.Fatal("retired trust admitted the rotated provider")
				}
			})
		}
	}
}

func TestServiceSASLSCRAMPlusProjectProvider(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{DN: "cn=config", Attributes: []directory.Attribute{
			{Description: "olcSaslSecProps", Values: serviceSASLValues("none")},
			{Description: "olcSaslCBinding", Values: serviceSASLValues("tls-endpoint")},
			{Description: "olcAuthzRegexp", Values: serviceSASLValues(`^uid=service,.*cn=auth$ cn=service,dc=example,dc=com`)},
		}}, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{serviceSASLTestBaseDN})
	}); err != nil {
		t.Fatal(err)
	}
	listener := listenBackendTLSTest(t)
	provider, err := ldapserver.New(ldapserver.Config{Store: store, TLSConfig: pki.serverTLS,
		RootDN: serviceSASLTestDN, RootPassword: []byte(serviceSASLTestPassword)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- provider.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	address := listener.Addr().String()
	for _, mechanism := range serviceSCRAMPlusTestMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			config := serviceSCRAMPlusTestConfig(t, pki, "ldap://"+address, mechanism, true)
			proxy, err := NewProxy(config)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			upstream, err := proxy.tiers[0].backends[0].connect(t.Context(), "provider", false)
			if err != nil {
				t.Fatal(err)
			}
			client := ldap.NewConn(upstream.conn, true)
			client.Start()
			defer client.Close()
			client.SetTimeout(time.Second)
			identity, err := client.WhoAmI(nil)
			if err != nil || identity == nil || !strings.EqualFold(identity.AuthzID, "dn:"+serviceSASLTestDN) {
				t.Fatalf("service identity: %+v, %v", identity, err)
			}
		})
	}
}
