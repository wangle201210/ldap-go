package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/xdg-go/scram"
)

var syncConsumerSCRAMPlusMechanisms = []string{
	"SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS",
}

func syncConsumerSCRAMTestConfig(t *testing.T, authority globalTLSTestAuthority) syncConsumerConfig {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.certificateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return syncConsumerConfig{
		bindMethod: "sasl", saslMechanism: "SCRAM-SHA-256-PLUS", authenticationID: "alice", credentials: []byte("secret"),
		securityProperties: defaultSyncConsumerSASLSecurityProperties(),
		networkTimeout:     2 * time.Second, operationTimeout: 2 * time.Second,
		tls: syncConsumerTLSConfig{caCertificate: caPath, requireCert: "demand"},
	}
}

// The listener, accepted socket, handshake, client operations and join are all
// bounded. Using TCP also exercises the transport's real deadline behavior.
func startSyncConsumerSCRAMPeer(t *testing.T, serve func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			err = connection.SetDeadline(time.Now().Add(5 * time.Second))
			if err == nil {
				err = serve(connection)
			}
		}
		done <- err
	}()
	return net.JoinHostPort("localhost", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)), done
}

func waitSyncConsumerSCRAMPeer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("SCRAM test peer did not finish")
	}
}

func readSyncConsumerSCRAMBind(connection net.Conn, mechanism string) (int64, string, error) {
	message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return 0, "", err
	}
	bind, ok := message.Request.(ldapwire.BindRequest)
	if !ok || bind.Authentication.SASLMechanism != mechanism {
		return 0, "", fmt.Errorf("expected %s bind, got %#v", mechanism, message.Request)
	}
	return message.ID, string(bind.Authentication.SASLCredentials), nil
}

func expectSyncConsumerSCRAMClosed(connection net.Conn) error {
	var value [1]byte
	n, err := connection.Read(value[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected close without another bind/search, got %d bytes, %v", n, err)
	}
	return nil
}

func TestSyncConsumerSCRAMPlusWire(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "localhost", true)
	configuration := syncConsumerSCRAMTestConfig(t, authority)
	configuration.authorizationID = "dn:uid=alice,ou=people,dc=example,dc=com"
	for _, mechanism := range syncConsumerSCRAMPlusMechanisms {
		for _, mode := range []string{
			"success", "extra-round", "bad-proof", "missing-proof", "empty-proof", "duplicate-proof",
			"proof-and-error", "wrong-binding", "wrong-password", "unsupported", "early-success", "late-data", "excess-round",
			"unchanged-nonce", "wrong-nonce", "bad-salt", "low-iterations", "huge-iterations", "duplicate-field", "mandatory-extension",
		} {
			t.Run(mechanism+"/"+mode, func(t *testing.T) {
				config := configuration
				config.saslMechanism = mechanism
				generator, _ := saslSCRAMHashGenerator(mechanism)
				credentialClient, err := generator.NewClient("alice", "secret", "")
				if err != nil {
					t.Fatal(err)
				}
				stored := credentialClient.GetStoredCredentials(scram.KeyFactors{Salt: "fixed salt", Iters: 4096})
				server, err := generator.NewServer(func(username string) (scram.StoredCredentials, error) {
					if username != "alice" {
						return scram.StoredCredentials{}, errors.New("wrong username")
					}
					return stored, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				address, done := startSyncConsumerSCRAMPeer(t, func(raw net.Conn) error {
					connection := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate.tlsCertificate}, MinVersion: tls.VersionTLS12})
					if err := connection.Handshake(); err != nil {
						return err
					}
					id, first, err := readSyncConsumerSCRAMBind(connection, mechanism)
					if err != nil {
						return err
					}
					if !strings.HasPrefix(first, "p=ldap,a=dn:uid=3Dalice=2Cou=3Dpeople=2Cdc=3Dexample=2Cdc=3Dcom,n=alice,r=") {
						return fmt.Errorf("unexpected GS2/authzid: %q", first)
					}
					respond := func(code uint16, credentials string, present bool) error {
						return writeSyncConsumerPacket(connection, encodeSyncConsumerTestBindResponse(id, code, []byte(credentials), present))
					}
					if mode == "unsupported" || mode == "early-success" {
						code := uint16(ldap.LDAPResultAuthMethodNotSupported)
						if mode == "early-success" {
							code = ldap.LDAPResultSuccess
						}
						if err := respond(code, "", false); err != nil {
							return err
						}
						return expectSyncConsumerSCRAMClosed(connection)
					}
					data, err := saslkrb5.TLSServerEndpoint(certificate.certificate)
					if err != nil {
						return err
					}
					if mode == "wrong-binding" {
						data[len(data)-1] ^= 1
					}
					conversation := server.NewConversationWithChannelBindingRequired(scram.ChannelBinding{Type: "ldap", Data: data})
					serverFirst, err := conversation.Step(first)
					if err != nil {
						return err
					}
					_, nonce, _ := strings.Cut(first, ",r=")
					malformed := true
					switch mode {
					case "unchanged-nonce":
						serverFirst = "r=" + nonce + ",s=c2FsdA==,i=4096"
					case "wrong-nonce":
						serverFirst = "r=othernonce,s=c2FsdA==,i=4096"
					case "bad-salt":
						serverFirst = "r=" + nonce + "server,s=!,i=4096"
					case "low-iterations":
						serverFirst = "r=" + nonce + "server,s=c2FsdA==,i=1"
					case "huge-iterations":
						serverFirst = "r=" + nonce + "server,s=c2FsdA==,i=10000001"
					case "duplicate-field":
						serverFirst += ",i=4096"
					case "mandatory-extension":
						serverFirst = "m=required," + serverFirst
					default:
						malformed = false
					}
					if err := respond(ldap.LDAPResultSaslBindInProgress, serverFirst, true); err != nil {
						return err
					}
					if malformed {
						return expectSyncConsumerSCRAMClosed(connection)
					}
					id, final, err := readSyncConsumerSCRAMBind(connection, mechanism)
					if err != nil {
						return err
					}
					serverFinal, proofErr := conversation.Step(final)
					if mode == "wrong-binding" || mode == "wrong-password" {
						if proofErr == nil || conversation.Valid() {
							return errors.New("invalid client binding/password was accepted")
						}
						if err := respond(ldap.LDAPResultInvalidCredentials, serverFinal, true); err != nil {
							return err
						}
						return expectSyncConsumerSCRAMClosed(connection)
					}
					if proofErr != nil || !conversation.Valid() || !conversation.Done() {
						return fmt.Errorf("client proof failed: %v", proofErr)
					}
					switch mode {
					case "bad-proof":
						serverFinal = "v=" + base64.StdEncoding.EncodeToString(make([]byte, generator().Size()))
					case "missing-proof", "empty-proof":
						serverFinal = ""
					case "duplicate-proof":
						serverFinal += "," + serverFinal
					case "proof-and-error":
						serverFinal += ",e=invalid-proof"
					}
					if mode == "extra-round" || mode == "late-data" || mode == "excess-round" {
						if err := respond(ldap.LDAPResultSaslBindInProgress, serverFinal, true); err != nil {
							return err
						}
						id, final, err = readSyncConsumerSCRAMBind(connection, mechanism)
						if err != nil || final != "" {
							return fmt.Errorf("expected empty final response: %q, %v", final, err)
						}
						if mode != "late-data" {
							serverFinal = ""
						}
					}
					code := uint16(ldap.LDAPResultSuccess)
					if mode == "excess-round" {
						code = ldap.LDAPResultSaslBindInProgress
					}
					if err := respond(code, serverFinal, mode != "missing-proof"); err != nil {
						return err
					}
					return expectSyncConsumerSCRAMClosed(connection)
				})
				provider := "ldaps://" + address
				if mode == "wrong-password" {
					config.credentials = []byte("wrong")
				}
				wantSuccess := mode == "success" || mode == "extra-round"
				if wantSuccess {
					transport, dialErr := dialSyncConsumer(t.Context(), config, provider)
					if dialErr != nil {
						t.Fatal(dialErr)
					}
					err = bindSyncConsumerSASL(transport, config, provider)
					_ = transport.close()
				} else {
					consumer, store, unitConfig := newSyncConsumerUnitServer(t)
					config.rid, config.partition = unitConfig.rid, unitConfig.partition
					cookie := []byte("rid=001,csn=20260730010101.000001Z#000000#001#000000")
					if err := consumer.storeSyncConsumerCookie(t.Context(), config, cookie); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					err = consumer.runSyncConsumerCycle(ctx, config, provider)
					cancel()
					assertSyncConsumerCookie(t, store, config, cookie)
				}
				if (err == nil) != wantSuccess {
					t.Errorf("bind = %v, want success %v", err, wantSuccess)
				}
				waitSyncConsumerSCRAMPeer(t, done)
			})
		}
	}
}

type syncConsumerFakeTLSState struct {
	net.Conn
	state tls.ConnectionState
}

func (connection syncConsumerFakeTLSState) ConnectionState() tls.ConnectionState {
	return connection.state
}

func TestSyncConsumerSCRAMPlusRequiresVerifiedTLS(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "localhost", true)
	config := syncConsumerSCRAMTestConfig(t, authority)
	for _, mode := range []string{"verified", "never", "allow", "untrusted", "wrong-host", "missing-host", "cleartext", "fake-state", "incomplete", "tlcp"} {
		t.Run(mode, func(t *testing.T) {
			address, done := startSyncConsumerSCRAMPeer(t, func(raw net.Conn) error {
				connection := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate.tlsCertificate}, MinVersion: tls.VersionTLS12})
				if err := connection.Handshake(); err != nil {
					return err
				}
				return expectSyncConsumerSCRAMClosed(connection)
			})
			provider := "ldaps://" + address
			transport, err := dialSyncConsumer(t.Context(), config, provider)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = transport.close() })
			secured := transport.currentConnection().(*tls.Conn)
			if len(secured.ConnectionState().VerifiedChains) != 0 {
				t.Fatal("fixture did not exercise custom syncrepl TLS verification")
			}
			testConfig := config
			switch mode {
			case "never", "allow":
				testConfig.tls.requireCert = mode
			case "untrusted":
				testConfig = syncConsumerSCRAMTestConfig(t, newGlobalTLSTestAuthority(t))
			case "wrong-host":
				provider = "ldaps://wrong.example.test"
			case "missing-host":
				provider = "ldaps:///"
			case "cleartext":
				transport.replaceConnection(secured.NetConn())
			case "fake-state":
				state := secured.ConnectionState()
				state.VerifiedChains = [][]*x509.Certificate{state.PeerCertificates}
				transport.replaceConnection(syncConsumerFakeTLSState{Conn: secured, state: state})
			case "incomplete":
				transport.replaceConnection(tls.Client(secured.NetConn(), &tls.Config{ServerName: "localhost"}))
			case "tlcp":
				transport.replaceConnection(tlcp.Client(secured.NetConn(), &tlcp.Config{}))
			}
			_, _, err = newSyncConsumerSASLConversationForProvider(testConfig, provider, transport)
			if (err == nil) != (mode == "verified") {
				t.Errorf("conversation = %v", err)
			}
			transport.replaceConnection(secured)
			_ = transport.close()
			waitSyncConsumerSCRAMPeer(t, done)
		})
	}
	for _, mechanism := range syncConsumerSCRAMPlusMechanisms {
		config.saslMechanism = mechanism
		if _, _, err := newSyncConsumerSASLConversation(config); err == nil {
			t.Fatalf("%s accepted missing transport", mechanism)
		}
	}
}

func TestSyncConsumerSCRAMPlusTLSMatrix(t *testing.T) {
	for _, mechanism := range syncConsumerSCRAMPlusMechanisms {
		for _, implicit := range []bool{false, true} {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(fmt.Sprintf("%s/implicit=%t/TLS=%x", mechanism, implicit, version), func(t *testing.T) {
					address, tlsConfig := startSASLCBindingConfiguredServer(t, "tls-endpoint", Config{ImplicitTLS: implicit})
					tlsConfig.MaxVersion = version
					tlsConfig.MinVersion = version
					raw, err := net.DialTimeout("tcp", address, 2*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					transport := newSASLSCRAMPlusTransport(raw)
					t.Cleanup(func() { _ = transport.close() })
					if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					secureSASLCBinding(t, transport, tlsConfig, implicit)
					caPath := filepath.Join(t.TempDir(), "ca.pem")
					state := transport.currentConnection().(*tls.Conn).ConnectionState()
					chain := state.VerifiedChains[0]
					if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[len(chain)-1].Raw}), 0600); err != nil {
						t.Fatal(err)
					}
					config := syncConsumerConfig{saslMechanism: strings.ToLower(mechanism), authenticationID: "alice", credentials: []byte("secret"),
						securityProperties: defaultSyncConsumerSASLSecurityProperties(), tls: syncConsumerTLSConfig{caCertificate: caPath}}
					transport.ssf = syncConsumerTLSStateSSF(state)
					config.securityProperties.minSSF = transport.ssf
					_, port, err := net.SplitHostPort(address)
					if err != nil {
						t.Fatal(err)
					}
					if err := bindSyncConsumerSASL(transport, config, "ldap://localhost:"+port); err != nil {
						t.Fatal(err)
					}
					if err := transport.clearDeadline(); err != nil {
						t.Fatal(err)
					}
					client := ldap.NewConn(transport.currentConnection(), true)
					client.Start()
					client.SetTimeout(2 * time.Second)
					defer client.Close()
					identity, err := client.WhoAmI(nil)
					if err != nil || identity.AuthzID != "dn:uid=alice,ou=people,dc=example,dc=com" {
						t.Fatalf("identity = %#v, %v", identity, err)
					}
				})
			}
		}
	}
}

func TestSyncConsumerSCRAMPlusChallengeBounds(t *testing.T) {
	conversation := &syncConsumerSCRAM{clientNonce: "client", hashSize: 32}
	for _, challenge := range []string{
		"", strings.Repeat("x", maxSASLSCRAMSecretSize+1),
		"r=client\x00,s=c2FsdA==,i=4096", "r=client\n,s=c2FsdA==,i=4096",
		"r=clientserver,s=,i=4096", "r=clientserver,s=c2Fs\ndA==,i=4096",
		"r=clientserver,s=" + base64.StdEncoding.EncodeToString(make([]byte, 1025)) + ",i=4096",
		"r=clientserver,s=c2FsdA==,i=+4096", "r=clientserver,s=c2FsdA==,i=04096",
		"r=clientserver,s=c2FsdA==,i=-1", "r=clientserver,s=c2FsdA==,i=4294967296",
	} {
		if err := conversation.validateChallenge([]byte(challenge)); err == nil {
			t.Fatalf("accepted challenge %q", challenge)
		}
	}
	conversation.proofSent = true
	for _, challenge := range []string{"v=", "v=!!!!", "e=invalid-proof", "v=cHJvb2Y=", "v=" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"} {
		if err := conversation.validateChallenge([]byte(challenge)); err == nil {
			t.Fatalf("accepted server-final %q", challenge)
		}
	}
}

func TestSyncConsumerSCRAMPlusBindingFollowsCertificate(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	config := syncConsumerSCRAMTestConfig(t, authority)
	var previous []byte
	for range 2 {
		certificate := authority.issue(t, "localhost", true)
		address, done := startSyncConsumerSCRAMPeer(t, func(raw net.Conn) error {
			connection := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate.tlsCertificate}})
			if err := connection.Handshake(); err != nil {
				return err
			}
			return expectSyncConsumerSCRAMClosed(connection)
		})
		provider := "ldaps://" + address
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		transport, err := dialSyncConsumer(ctx, config, provider)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		binding, err := syncConsumerSCRAMChannelBinding(transport, config, provider)
		_ = transport.close()
		cancel()
		waitSyncConsumerSCRAMPeer(t, done)
		if err != nil {
			t.Fatal(err)
		}
		want, err := saslkrb5.TLSServerEndpoint(certificate.certificate)
		if err != nil || binding.Type != "ldap" || !bytes.Equal(binding.Data, want) || bytes.Equal(binding.Data, previous) {
			t.Fatalf("binding did not follow the actual peer certificate: %v", err)
		}
		previous = binding.Data
	}
}
