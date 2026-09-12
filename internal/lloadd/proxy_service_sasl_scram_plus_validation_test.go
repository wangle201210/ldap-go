package lloadd

import (
	"bytes"
	"crypto/hmac"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/scram"
)

func TestServiceSASLSCRAMPlusOptionalExtensionsTranscript(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	for _, mechanism := range serviceSCRAMPlusTestMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			generator, _ := serviceSCRAMGenerator(mechanism)
			client, err := generator.NewClient("service", serviceSASLTestPassword, "")
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: "salt", Iters: 4096})
			if err != nil {
				t.Fatal(err)
			}
			mac := func(key []byte, value string) []byte {
				h := hmac.New(generator, key)
				_, _ = h.Write([]byte(value))
				return h.Sum(nil)
			}
			done := make(chan error, 1)
			uri := startServiceSCRAMPlusTestPeer(t, pki.serverTLS, false, func(conn *tls.Conn) {
				first, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
				if err != nil {
					done <- err
					return
				}
				bind, ok := first.Request.(ldapwire.BindRequest)
				if !ok {
					done <- fmt.Errorf("initial request is %T", first.Request)
					return
				}
				initial := string(bind.Authentication.SASLCredentials)
				nonce, err := serviceSCRAMClientNonce(initial)
				if err != nil {
					done <- err
					return
				}
				serverFirst := "r=" + nonce + "server,s=c2FsdA==,i=4096,x=optional=metadata,z=\u6d4b\u8bd5"
				if err := ldapwire.Write(conn, ldapwire.EncodeSASLBindResponse(first.ID,
					ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress}, []byte(serverFirst), true, nil)); err != nil {
					done <- err
					return
				}
				final, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
				if err != nil {
					done <- err
					return
				}
				bind, ok = final.Request.(ldapwire.BindRequest)
				if !ok {
					done <- fmt.Errorf("final request is %T", final.Request)
					return
				}
				withoutProof, encodedProof, ok := strings.Cut(string(bind.Authentication.SASLCredentials), ",p=")
				proof, err := base64.StdEncoding.DecodeString(encodedProof)
				if !ok || err != nil || len(proof) != generator().Size() {
					done <- fmt.Errorf("invalid client proof")
					return
				}
				transcript := strings.SplitN(initial, ",", 3)[2] + "," + serverFirst + "," + withoutProof
				signature := mac(credentials.StoredKey, transcript)
				for i := range proof {
					proof[i] ^= signature[i]
				}
				h := generator()
				_, _ = h.Write(proof)
				if !hmac.Equal(h.Sum(nil), credentials.StoredKey) {
					done <- fmt.Errorf("client HMAC dropped or changed optional extension bytes")
					return
				}
				serverFinal := "v=" + base64.StdEncoding.EncodeToString(mac(credentials.ServerKey, transcript)) + ",x=final-extension"
				done <- ldapwire.Write(conn, ldapwire.EncodeSASLBindResponse(final.ID, ldapwire.Result{}, []byte(serverFinal), true, nil))
			})
			proxy, err := NewProxy(serviceSCRAMPlusTestConfig(t, pki, uri, mechanism, false))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			upstream, err := proxy.tiers[0].backends[0].connect(t.Context(), "extensions", false)
			if err != nil {
				t.Fatal(err)
			}
			_ = upstream.conn.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServiceSASLSCRAMPlusBoundsAndExtensions(t *testing.T) {
	t.Parallel()
	const nonce = "client-nonce"
	const first = "r=" + nonce + "server,s=c2FsdA==,i=4096"
	for _, value := range []string{
		first, first + ",x=optional=metadata,z=\u6d4b\u8bd5", first + ",X=a,x=b",
		strings.Replace(first, "4096", "10000000", 1),
		"r=" + nonce + "server,s=" + base64.StdEncoding.EncodeToString(make([]byte, 1024)) + ",i=4096",
		first + ",x=" + strings.Repeat("x", serviceSASLMaxChallengeSize-len(first)-3),
	} {
		if err := validateServiceSCRAMPlusServerFirst([]byte(value), nonce); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{",m=required", ",r=again", ",i=1", ",x=a,x=b", ",x=", ",xyz=value", ",1=a", ",x=a\x00b", ",x=\xff", ","} {
		if err := validateServiceSCRAMPlusServerFirst([]byte(first+suffix), nonce); err == nil {
			t.Fatalf("accepted suffix %q", suffix)
		}
		proof := "v=" + base64.StdEncoding.EncodeToString(make([]byte, 32))
		if err := validateServiceSCRAMPlusServerFinal([]byte(proof+suffix), 32); err == nil {
			t.Fatalf("accepted final suffix %q", suffix)
		}
	}
	for _, mechanism := range serviceSCRAMPlusTestMechanisms {
		generator, _ := serviceSCRAMGenerator(mechanism)
		proof := "v=" + base64.StdEncoding.EncodeToString(make([]byte, generator().Size()))
		if err := validateServiceSCRAMPlusServerFinal([]byte(proof+",x=extension"), generator().Size()); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{proof + "\n", proof + ",v=again", proof + ",e=error", "v=***", "v=YQ=="} {
			if err := validateServiceSCRAMPlusServerFinal([]byte(value), generator().Size()); err == nil {
				t.Fatalf("accepted verifier %q", value)
			}
		}
	}
	for _, value := range []string{
		strings.Replace(first, "c2FsdA==", "c2FsdB==", 1),
		strings.Replace(first, "c2FsdA==", "c2Fs\ndA==", 1),
		first + ",x=" + strings.Repeat("x", serviceSASLMaxChallengeSize),
		strings.Replace(first, "4096", "+4096", 1),
	} {
		if err := validateServiceSCRAMPlusServerFirst([]byte(value), nonce); err == nil {
			t.Fatal("accepted noncanonical/oversized challenge")
		}
	}
	// Existing non-PLUS validation keeps its prior extension behavior.
	if err := validateServiceSCRAMServerFirst([]byte(first+",x=extension"), nonce); err == nil {
		t.Fatal("changed non-PLUS behavior")
	}
}

func TestServiceSASLSCRAMPlusLivePeerVerification(t *testing.T) {
	t.Parallel()
	pki, other := newExternalTestPKI(t), newExternalTestPKI(t)
	uri := startServiceSCRAMPlusTestPeer(t, pki.serverTLS, false, func(conn *tls.Conn) { _, _ = io.Copy(io.Discard, conn) })
	for _, test := range []struct {
		name      string
		edit      func(*RuntimeConfig, *tls.Config)
		wantError bool
	}{
		{"loader verifier with empty VerifiedChains", func(c *RuntimeConfig, dial *tls.Config) {
			dial.InsecureSkipVerify = c.BackendTLS.InsecureSkipVerify
			dial.VerifyConnection = c.BackendTLS.VerifyConnection
			dial.RootCAs = c.BackendTLS.RootCAs
		}, false},
		{"standard verified", func(c *RuntimeConfig, _ *tls.Config) { c.BackendTLS = pki.clientTLS }, false},
		{"unverified actual connection", func(c *RuntimeConfig, dial *tls.Config) {
			c.BackendTLS = pki.clientTLS
			dial.InsecureSkipVerify = true
		}, true},
		{"different backend roots", func(c *RuntimeConfig, _ *tls.Config) { c.BackendTLS = other.clientTLS }, true},
		{"different backend hostname", func(c *RuntimeConfig, _ *tls.Config) { c.BackendTLS.ServerName = "wrong.example" }, true},
		{"custom verifier bypassed during handshake", func(c *RuntimeConfig, _ *tls.Config) {
			strict, err := buildBackendTLSConfig(BindTLSConfig{CACertificate: other.caFile, RequireCert: "demand"})
			if err != nil {
				t.Fatal(err)
			}
			c.backendTLSVerification.verify = strict.VerifyConnection
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := serviceSCRAMPlusTestConfig(t, pki, uri, "SCRAM-SHA-256-PLUS", false)
			dial := pki.clientTLS.Clone()
			test.edit(&config, dial)
			dial.ServerName = "127.0.0.1"
			if verify := dial.VerifyConnection; verify != nil {
				dial.VerifyConnection = func(state tls.ConnectionState) error { state.ServerName = "127.0.0.1"; return verify(state) }
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", strings.TrimPrefix(uri, "ldaps://"), dial)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			proxy, err := NewProxy(config)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			binding, err := proxy.tiers[0].backends[0].serviceSCRAMPlusChannelBinding(conn)
			if (err != nil) != test.wantError {
				t.Fatalf("binding verification: %v", err)
			}
			if !test.wantError && (binding.Type != "ldap" || !bytes.Equal(binding.Data, serviceSCRAMPlusTestBinding(pki.serverTLS.Certificates[0]).Data)) {
				t.Fatal("incorrect live peer endpoint binding")
			}
		})
	}
}

func TestServiceSASLSCRAMPlusLivePeerRevocation(t *testing.T) {
	t.Parallel()
	pki := newBackendTLSTestPKI(t)
	uri := startServiceSCRAMPlusTestPeer(t, &tls.Config{Certificates: []tls.Certificate{pki.serverCertificate}}, false,
		func(conn *tls.Conn) { _, _ = io.Copy(io.Discard, conn) })
	parsed := backendTLSTestConfig(uri, StartTLSImplicit, pki.revokedCAFile)
	parsed.BindConf.Method, parsed.BindConf.BindDN = BindSASL, ""
	parsed.BindConf.SASLMechanism, parsed.BindConf.AuthCID = "SCRAM-SHA-256-PLUS", "service"
	parsed.BindConf.TLS.CRLCheck = "peer"
	config, err := parsed.RuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	dial, err := buildBackendTLSConfig(BindTLSConfig{CACertificate: pki.caFile, RequireCert: "demand"})
	if err != nil {
		t.Fatal(err)
	}
	// Go omits IP SNI, whereas secureConnection normally fills the hostname for
	// this verifier. Use the same expected provider name in this direct probe.
	verify := dial.VerifyConnection
	dial.VerifyConnection = func(state tls.ConnectionState) error { state.ServerName = "127.0.0.1"; return verify(state) }
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", strings.TrimPrefix(uri, "ldaps://"), dial)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := proxy.tiers[0].backends[0].serviceSCRAMPlusChannelBinding(conn); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("live revoked certificate bypassed PLUS verification: %v", err)
	}
}
