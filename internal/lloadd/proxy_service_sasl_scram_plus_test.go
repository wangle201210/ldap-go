package lloadd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/scram"
)

var serviceSCRAMPlusTestMechanisms = []string{
	"SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS",
}

func serviceSCRAMPlusTestConfig(t *testing.T, pki externalTestPKI, uri, mechanism string, startTLS bool) RuntimeConfig {
	t.Helper()
	start := ""
	if startTLS {
		start = " starttls=yes"
	}
	parsed, err := Parse(strings.NewReader(fmt.Sprintf(`
feature proxyauthz
bindconf bindmethod=sasl saslmech=%s authcid=service authzid=u:service credentials=%s secprops=none tls_cacert=%s tls_reqcert=demand timeout=2
tier roundrobin
backend-server uri=%s numconns=1 bindconns=1 retry=1%s
`, mechanism, serviceSASLTestPassword, pki.caFile, uri, start)))
	if err != nil {
		t.Fatal(err)
	}
	config, err := parsed.RuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.IOTimeout = 2 * time.Second
	return config
}

func TestServiceSASLSCRAMPlusConfiguration(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	for _, mechanism := range serviceSCRAMPlusTestMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			config := serviceSCRAMPlusTestConfig(t, pki, "ldaps://127.0.0.1:636", strings.ToLower(mechanism), false)
			if config.Bind.SASLMechanism != mechanism || config.PrivilegedIdentity != "u:service" {
				t.Fatal("PLUS normalization or service authorization identity changed")
			}
			for _, test := range []struct {
				name string
				edit func(*RuntimeConfig)
			}{
				{"missing TLS", func(c *RuntimeConfig) { c.BackendTLS = nil }},
				{"cleartext", func(c *RuntimeConfig) { c.Tiers[0].Backends[0].URI = "ldap://127.0.0.1:389" }},
				{"LDAPI", func(c *RuntimeConfig) { c.Tiers[0].Backends[0].URI = "ldapi://%2Ftmp%2Fplus.sock" }},
				{"no authcid", func(c *RuntimeConfig) { c.Bind.AuthenticationID = "" }},
				{"no credentials", func(c *RuntimeConfig) { c.Bind.Credentials = nil }},
				{"realm", func(c *RuntimeConfig) { c.Bind.Realm = "example.com" }},
				{"security layer", func(c *RuntimeConfig) { c.Bind.SecurityProperties = "minssf=1" }},
				{"ProxyAuthz required", func(c *RuntimeConfig) { c.ProxyAuthz = false }},
				{"unverified replacement", func(c *RuntimeConfig) {
					c.BackendTLS = &tls.Config{InsecureSkipVerify: true, RootCAs: pki.clientTLS.RootCAs}
				}},
				{"no-op verifier", func(c *RuntimeConfig) {
					c.BackendTLS = &tls.Config{InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error { return nil }}
				}},
			} {
				t.Run(test.name, func(t *testing.T) {
					candidate := serviceSCRAMPlusTestConfig(t, pki, "ldaps://127.0.0.1:636", mechanism, false)
					test.edit(&candidate)
					if proxy, err := NewProxy(candidate); err == nil {
						_ = proxy.Close()
						t.Fatal("accepted invalid PLUS configuration")
					} else if strings.Contains(err.Error(), serviceSASLTestPassword) {
						t.Fatal("error exposed service password")
					}
				})
			}
			proxy, err := NewProxy(config)
			if err != nil {
				t.Fatal(err)
			}
			owned := proxy.config.Bind.Credentials
			config.Bind.Credentials[0] ^= 0xff
			if string(owned) != serviceSASLTestPassword {
				t.Fatal("PLUS retained caller-owned credentials")
			}
			_ = proxy.Close()
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("PLUS credentials were not cleared on close")
			}
		})
	}
	for _, policy := range []string{"allow", "never"} {
		parsed := backendTLSTestConfig("ldaps://127.0.0.1:636", StartTLSImplicit, pki.caFile)
		parsed.BindConf.Method = BindSASL
		parsed.BindConf.BindDN = ""
		parsed.BindConf.SASLMechanism = "SCRAM-SHA-256-PLUS"
		parsed.BindConf.AuthCID = "service"
		parsed.BindConf.TLS.RequireCert = policy
		if _, err := parsed.RuntimeConfig(); err == nil || !strings.Contains(err.Error(), "never/allow") {
			t.Fatalf("tls_reqcert=%s: %v", policy, err)
		}
	}
}

// The provider derives the expected Cyrus bytes independently of the production
// TLS helper. The fixture's server certificate uses ECDSAWithSHA256.
func serviceSCRAMPlusTestBinding(certificate tls.Certificate) scram.ChannelBinding {
	digest := sha256.Sum256(certificate.Certificate[0])
	return scram.ChannelBinding{Type: "ldap", Data: append([]byte("tls-server-end-point:"), digest[:]...)}
}

type serviceSCRAMPlusTestReply struct {
	id          int64
	code        ldapwire.ResultCode
	data        string
	present     bool
	expectClose bool
}

func serviceSCRAMPlusTestExchange(t *testing.T, conn net.Conn, binding scram.ChannelBinding, mechanism, authzid string,
	completion bool, alter func(int, *serviceSCRAMPlusTestReply)) bool {
	t.Helper()
	generator, _ := serviceSCRAMGenerator(mechanism)
	client, err := generator.NewClient("service", serviceSASLTestPassword, "")
	if err != nil {
		t.Error(err)
		return false
	}
	credentials, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: "plus-provider-salt", Iters: serviceSCRAMMinIterations})
	if err != nil {
		t.Error(err)
		return false
	}
	server, err := generator.NewServer(func(username string) (scram.StoredCredentials, error) {
		if username != "service" {
			return scram.StoredCredentials{}, errors.New("unexpected service authcid")
		}
		return credentials, nil
	})
	if err != nil {
		t.Error(err)
		return false
	}
	server.WithNonceGenerator(func() string { return "provider-nonce" })
	conversation := server.NewConversationWithChannelBindingRequired(binding)
	header := "p=ldap,,"
	if authzid != "" {
		header = "p=ldap,a=" + strings.NewReplacer("=", "=3D", ",", "=2C").Replace(authzid) + ","
	}
	steps := 2
	if completion {
		steps++
	}
	var previousID int64
	for step := 0; step < steps; step++ {
		message, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			t.Errorf("PLUS provider read step %d: %v", step, err)
			return false
		}
		request, ok := message.Request.(ldapwire.BindRequest)
		if !ok || request.Version != 3 || request.Name != "" || len(message.Controls) != 0 ||
			!request.Authentication.IsSASL || request.Authentication.SASLMechanism != mechanism ||
			!request.Authentication.HasSASLCredentials || (step > 0 && message.ID != previousID+1) {
			t.Errorf("invalid PLUS service Bind metadata at step %d", step)
			return false
		}
		previousID = message.ID
		data := string(request.Authentication.SASLCredentials)
		if strings.Contains(data, serviceSASLTestPassword) {
			t.Error("plaintext service password on SASL wire")
			return false
		}
		if step == 0 && !strings.HasPrefix(data, header+"n=service,r=") {
			t.Errorf("incorrect Cyrus GS2 header: %q", data)
			return false
		}
		if step == 1 {
			want := "c=" + base64.StdEncoding.EncodeToString(append([]byte(header), binding.Data...)) + ",r="
			if !strings.HasPrefix(data, want) {
				t.Error("client proof did not bind the GS2 header and live endpoint bytes")
				return false
			}
		}
		reply := serviceSCRAMPlusTestReply{id: message.ID, code: ldapwire.ResultSuccess, present: step < 2}
		if step < 2 {
			reply.data, err = conversation.Step(data)
			if err != nil {
				t.Errorf("PLUS provider verification: %v", err)
				return false
			}
		} else if data != "" {
			t.Error("completion response is not explicitly empty")
			return false
		}
		if step == 0 || (step == 1 && completion) {
			reply.code = ldapwire.ResultSASLBindInProgress
		}
		if alter != nil {
			alter(step, &reply)
		}
		if err := ldapwire.Write(conn, ldapwire.EncodeSASLBindResponse(reply.id,
			ldapwire.Result{Code: reply.code}, []byte(reply.data), reply.present, nil)); err != nil {
			t.Errorf("PLUS provider response: %v", err)
			return false
		}
		if reply.expectClose {
			var data [1]byte
			n, err := conn.Read(data[:])
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Errorf("rejected PLUS connection sent more data or remained open: n=%d err=%v", n, err)
			}
			return false
		}
	}
	if !conversation.Valid() || !conversation.Done() {
		t.Error("provider did not authenticate service proof")
		return false
	}
	return true
}

func startServiceSCRAMPlusTestPeer(t *testing.T, serverTLS *tls.Config, startTLS bool, handler func(*tls.Conn)) string {
	t.Helper()
	listener := listenBackendTLSTest(t)
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[raw] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				defer func() { mu.Lock(); delete(connections, raw); mu.Unlock() }()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				if startTLS {
					message, err := ldapwire.ReadMessage(raw, ldapwire.DefaultMaxMessageSize)
					if err != nil {
						return
					}
					request, ok := message.Request.(ldapwire.ExtendedRequest)
					if !ok || request.Name != upstreamStartTLSOID || message.ID != 1 {
						t.Error("SASL data preceded StartTLS")
						return
					}
					if err := ldapwire.Write(raw, ldapwire.EncodeResultResponse(message.ID,
						ldapwire.ApplicationExtendedResponse, ldapwire.Result{}, nil)); err != nil {
						return
					}
				}
				secured := tls.Server(raw, serverTLS)
				if err := secured.Handshake(); err == nil {
					handler(secured)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	scheme := "ldaps://"
	if startTLS {
		scheme = "ldap://"
	}
	return scheme + listener.Addr().String()
}

func TestServiceSASLSCRAMPlusTLSProvider(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	for _, mechanism := range serviceSCRAMPlusTestMechanisms {
		for _, startTLS := range []bool{false, true} {
			for _, completion := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/StartTLS=%t/completion=%t", mechanism, startTLS, completion), func(t *testing.T) {
					for _, native := range []bool{false, true} {
						for _, authzid := range []string{"", "u:service", "u:svc,=identity"} {
							done := make(chan bool, 1)
							uri := startServiceSCRAMPlusTestPeer(t, pki.serverTLS, startTLS, func(conn *tls.Conn) {
								done <- serviceSCRAMPlusTestExchange(t, conn, serviceSCRAMPlusTestBinding(pki.serverTLS.Certificates[0]), mechanism, authzid, completion, nil)
							})
							config := serviceSCRAMPlusTestConfig(t, pki, uri, mechanism, startTLS)
							config.Bind.AuthorizationID = authzid
							if native {
								config.BackendTLS = pki.clientTLS
							}
							proxy, err := NewProxy(config)
							if err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { _ = proxy.Close() })
							upstream, err := proxy.tiers[0].backends[0].connect(t.Context(), "plus-test", false)
							if err != nil {
								t.Fatal(err)
							}
							_ = upstream.conn.Close()
							wantID := int64(3)
							if startTLS {
								wantID++
							}
							if completion {
								wantID++
							}
							if upstream.nextID != wantID || !<-done {
								t.Fatalf("PLUS completion/next message ID: got %d, want %d", upstream.nextID, wantID)
							}
						}
					}
				})
			}
		}
	}
}

func TestServiceSASLSCRAMPlusRejectsServerMessages(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	for _, test := range []struct {
		name string
		step int
		edit func(*serviceSCRAMPlusTestReply)
	}{
		{"early success", 0, func(r *serviceSCRAMPlusTestReply) { r.code = ldapwire.ResultSuccess }},
		{"missing first", 0, func(r *serviceSCRAMPlusTestReply) { r.present = false }},
		{"empty first", 0, func(r *serviceSCRAMPlusTestReply) { r.data = "" }},
		{"wrong ID", 0, func(r *serviceSCRAMPlusTestReply) { r.id++ }},
		{"oversized first", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Repeat("r", serviceSASLMaxChallengeSize+1) }},
		{"nonce not extended", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Replace(r.data, "provider-nonce", "", 1) }},
		{"nonce mismatch", 0, func(r *serviceSCRAMPlusTestReply) { r.data = "r=wrong,s=c2FsdA==,i=4096" }},
		{"duplicate", 0, func(r *serviceSCRAMPlusTestReply) { r.data += ",i=4096" }},
		{"extension", 0, func(r *serviceSCRAMPlusTestReply) { r.data += ",m=required" }},
		{"empty salt", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Split(r.data, ",")[0] + ",s=,i=4096" }},
		{"large salt", 0, func(r *serviceSCRAMPlusTestReply) {
			r.data = strings.Split(r.data, ",")[0] + ",s=" + base64.StdEncoding.EncodeToString(make([]byte, serviceSCRAMMaxSaltSize+1)) + ",i=4096"
		}},
		{"salt newline", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Split(r.data, ",")[0] + ",s=c2Fs\r\ndA==,i=4096" }},
		{"low iterations", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Replace(r.data, "i=4096", "i=4095", 1) }},
		{"high iterations", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Replace(r.data, "i=4096", "i=10000001", 1) }},
		{"overflow iterations", 0, func(r *serviceSCRAMPlusTestReply) {
			r.data = strings.Replace(r.data, "i=4096", "i=999999999999999999999", 1)
		}},
		{"leading zero", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Replace(r.data, "i=4096", "i=04096", 1) }},
		{"negative iterations", 0, func(r *serviceSCRAMPlusTestReply) { r.data = strings.Replace(r.data, "i=4096", "i=-1", 1) }},
		{"missing proof", 1, func(r *serviceSCRAMPlusTestReply) { r.present = false }},
		{"wrong proof", 1, func(r *serviceSCRAMPlusTestReply) {
			r.data = "v=" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
		}},
		{"short proof", 1, func(r *serviceSCRAMPlusTestReply) { r.data = "v=YQ==" }},
		{"proof error", 1, func(r *serviceSCRAMPlusTestReply) { r.data = "e=invalid-proof" }},
		{"proof reserved extension", 1, func(r *serviceSCRAMPlusTestReply) { r.data += ",m=required" }},
		{"proof newline", 1, func(r *serviceSCRAMPlusTestReply) { r.data += "\r\n" }},
		{"oversized proof", 1, func(r *serviceSCRAMPlusTestReply) { r.data = "v=" + strings.Repeat("A", serviceSASLMaxChallengeSize) }},
		{"completion failure", 2, func(r *serviceSCRAMPlusTestReply) { r.code = ldapwire.ResultInvalidCredentials }},
		{"completion credentials", 2, func(r *serviceSCRAMPlusTestReply) { r.present = true }},
		{"completion continuation", 2, func(r *serviceSCRAMPlusTestReply) { r.code = ldapwire.ResultSASLBindInProgress }},
	} {
		t.Run(test.name, func(t *testing.T) {
			done := make(chan bool, 1)
			uri := startServiceSCRAMPlusTestPeer(t, pki.serverTLS, false, func(conn *tls.Conn) {
				done <- serviceSCRAMPlusTestExchange(t, conn, serviceSCRAMPlusTestBinding(pki.serverTLS.Certificates[0]),
					"SCRAM-SHA-256-PLUS", "u:service", true, func(step int, reply *serviceSCRAMPlusTestReply) {
						if step == test.step {
							test.edit(reply)
							reply.expectClose = true
						}
					})
			})
			proxy, err := NewProxy(serviceSCRAMPlusTestConfig(t, pki, uri, "SCRAM-SHA-256-PLUS", false))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			upstream, err := proxy.tiers[0].backends[0].connect(t.Context(), "denied", false)
			if err == nil || upstream != nil {
				t.Fatalf("invalid PLUS server admitted: %v", err)
			}
			if strings.Contains(err.Error(), serviceSASLTestPassword) {
				t.Fatal("error exposed password")
			}
			if <-done || readyServiceSASLConnections(proxy, PoolRegular) != 0 {
				t.Fatal("invalid PLUS connection became ready")
			}
		})
	}
}

func TestServiceSASLSCRAMPlusRejectsNonTLSBeforeBind(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	config := serviceSCRAMPlusTestConfig(t, pki, "ldaps://127.0.0.1:636", "SCRAM-SHA-256-PLUS", false)
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	for _, kind := range []string{"cleartext", "forged state", "TLCP", "unfinished TLS", "nil TLS"} {
		t.Run(kind, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			var connection net.Conn = client
			switch kind {
			case "forged state":
				connection = externalTestTLSConnection{Conn: client, state: tls.ConnectionState{
					HandshakeComplete: true, PeerCertificates: []*x509.Certificate{pki.serverTLS.Certificates[0].Leaf},
					VerifiedChains: [][]*x509.Certificate{{pki.serverTLS.Certificates[0].Leaf}},
				}}
			case "TLCP":
				connection = tlcp.Client(client, &tlcp.Config{InsecureSkipVerify: true})
			case "unfinished TLS":
				connection = tls.Client(client, pki.clientTLS)
			case "nil TLS":
				connection = (*tls.Conn)(nil)
			}
			next := int64(1)
			_, err := proxy.tiers[0].backends[0].bindServiceSASL(context.Background(), connection, &next)
			if err == nil || next != 1 {
				t.Fatalf("unverified transport sent SASL: next=%d err=%v", next, err)
			}
		})
	}
}

func TestServiceSASLSCRAMPlusOptionalStartTLSFailure(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	listener := listenBackendTLSTest(t)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
		if err == nil {
			err = ldapwire.Write(conn, ldapwire.EncodeResultResponse(request.ID, ldapwire.ApplicationExtendedResponse,
				ldapwire.Result{Code: ldapwire.ResultUnavailable}, nil))
		}
		if err != nil {
			done <- err
			return
		}
		var data [1]byte
		n, err := conn.Read(data[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			done <- fmt.Errorf("SASL after failed StartTLS: n=%d err=%v", n, err)
			return
		}
		done <- nil
	}()
	proxy, err := NewProxy(serviceSCRAMPlusTestConfig(t, pki, "ldap://"+listener.Addr().String(), "SCRAM-SHA-256-PLUS", true))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if upstream, err := proxy.tiers[0].backends[0].connect(t.Context(), "denied", false); err == nil || upstream != nil {
		t.Fatal("failed optional StartTLS admitted a PLUS connection")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
