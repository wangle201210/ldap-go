package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

func TestTLSOptions(t *testing.T) {
	_, ca := testTLSCertificate(t, "127.0.0.1")
	caPath := testCAFile(t, ca)
	for _, args := range [][]string{
		nil, {"-tls-ca=" + caPath}, {"-start-tls"}, {"-start-tls", "-tls-ca=" + caPath},
	} {
		c := testOptions(t, args...)
		if c.tlsConfig != nil && (c.tlsConfig.InsecureSkipVerify || c.tlsConfig.RootCAs == nil || c.tlsConfig.ServerName != "") {
			t.Fatal("parsed TLS config must retain verification and defer endpoint hostname selection")
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["tls_ca"]; ok != (c.TLSCA != "") {
			t.Fatal("tls_ca must be omitted only when empty")
		}
		if _, ok := fields["start_tls"]; ok != c.StartTLS {
			t.Fatal("start_tls must be omitted when false")
		}
		if c.TLSCA != "" {
			var path string
			if err := json.Unmarshal(fields["tls_ca"], &path); err != nil || path != caPath || c.tlsConfig == nil {
				t.Fatal("custom CA path must be reported and its config parsed")
			}
		} else if c.tlsConfig != nil {
			t.Fatal("default system roots must not be replaced")
		}
		if c.StartTLS && string(fields["start_tls"]) != "true" {
			t.Fatal("StartTLS must be reported as true")
		}
		if bytes.Contains(encoded, []byte("tlsConfig")) || bytes.Contains(encoded, []byte("RootCAs")) || bytes.Contains(encoded, []byte("CERTIFICATE")) {
			t.Fatal("parsed TLS config and certificate material must not be serialized")
		}
	}
	for name, args := range map[string][]string{
		"missing CA":      {"-tls-ca=" + filepath.Join(t.TempDir(), "missing.pem")},
		"empty CA":        {"-tls-ca=" + testCAFile(t, nil)},
		"invalid PEM":     {"-tls-ca=" + testCAFile(t, []byte("not a certificate"))},
		"invalid DER":     {"-tls-ca=" + testCAFile(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad DER")}))},
		"StartTLS LDAPS":  {"-start-tls", "-endpoint=native=ldaps://127.0.0.1:1636"},
		"StartTLS scheme": {"-start-tls", "-endpoint=native=ldapi:///tmp/unused.sock"},
		"insecure flag":   {"-tls-insecure"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := execute(t.Context(), append(testArgs(), args...), testLookup, &out, io.Discard); code != 2 {
				t.Fatalf("invalid TLS arguments must fail before dialing: exit %d", code)
			}
			var r report
			if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Error == "" || r.Config != nil || r.SetupAdds != 0 || len(r.Samples) != 0 {
				t.Fatalf("invalid options must produce an argument-only failure: %s", out.Bytes())
			}
		})
	}
}

func TestVerifiedTLSDial(t *testing.T) {
	certificate, ca := testTLSCertificate(t, "127.0.0.1")
	wrongHostname, otherCA := testTLSCertificate(t, "wrong.example.invalid")
	for _, startTLS := range []bool{false, true} {
		for _, tc := range []struct {
			name        string
			certificate tls.Certificate
			ca          []byte
			wantError   string
		}{
			{"trusted", certificate, ca, ""},
			{"untrusted", certificate, otherCA, "unknown authority"},
			// Platform verifiers can reject this key before checking its issuer.
			{"system roots reject private CA", certificate, nil, "failed to verify certificate"},
			{"hostname mismatch", wrongHostname, otherCA, "IP SANs"},
		} {
			t.Run(fmt.Sprintf("StartTLS=%t/%s", startTLS, tc.name), func(t *testing.T) {
				args := []string{fmt.Sprintf("-start-tls=%t", startTLS)}
				if tc.ca != nil {
					args = append(args, "-tls-ca="+testCAFile(t, tc.ca))
				}
				c := testOptions(t, args...)
				// Removing the input file proves that dialing reuses the parsed CA pool.
				if c.TLSCA != "" {
					if err := os.Remove(c.TLSCA); err != nil {
						t.Fatal(err)
					}
				}
				address := testLDAPListener(t, func(raw net.Conn) error {
					if startTLS {
						if err := testStartTLSReply(raw, ldap.LDAPResultSuccess); err != nil {
							return err
						}
					}
					server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{tc.certificate}})
					err := server.Handshake()
					if tc.wantError != "" {
						if err == nil {
							return errors.New("client accepted an untrusted or mismatched certificate")
						}
						return testPeerClosed(raw)
					}
					if err != nil {
						return err
					}
					if err := testBindReply(server, c.RootBindDN, c.password); err != nil {
						return err
					}
					return testPeerClosed(server)
				})
				scheme := "ldaps"
				if startTLS {
					scheme = "ldap"
				}
				conn, err := dial(c, endpoint{Name: "local", URI: scheme + "://" + address})
				if tc.wantError != "" {
					if err == nil {
						_ = conn.Close()
						t.Fatal("certificate verification unexpectedly succeeded")
					}
					if !strings.Contains(err.Error(), tc.wantError) {
						t.Fatalf("want certificate error containing %q, got %v", tc.wantError, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				state, ok := conn.(*ldap.Conn).TLSConnectionState()
				if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
					t.Fatal("dial must complete verified TLS before returning a bindable connection")
				}
				if err := conn.Bind(c.RootBindDN, c.password); err != nil {
					t.Fatal(err)
				}
				if c.tlsConfig.ServerName != "" {
					t.Fatal("dial must not mutate the shared parsed TLS config")
				}
			})
		}
	}
}

func TestPlaintextDialDefault(t *testing.T) {
	_, ca := testTLSCertificate(t, "127.0.0.1")
	for _, args := range [][]string{nil, {"-tls-ca=" + testCAFile(t, ca)}} {
		c := testOptions(t, args...)
		address := testLDAPListener(t, func(raw net.Conn) error {
			if err := testBindReply(raw, c.RootBindDN, c.password); err != nil {
				return err
			}
			return testPeerClosed(raw)
		})
		conn, err := dial(c, endpoint{URI: "ldap://" + address})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := conn.(*ldap.Conn).TLSConnectionState(); ok {
			_ = conn.Close()
			t.Fatal("ldap:// without -start-tls must remain plaintext, even with -tls-ca")
		}
		err = conn.Bind(c.RootBindDN, c.password)
		_ = conn.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestStartTLSRejectionClosesConnection(t *testing.T) {
	c := testOptions(t, "-start-tls")
	address := testLDAPListener(t, func(raw net.Conn) error {
		if err := testStartTLSReply(raw, ldap.LDAPResultUnavailable); err != nil {
			return err
		}
		return testPeerClosed(raw)
	})
	conn, err := dial(c, endpoint{URI: "ldap://" + address})
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) || conn != nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("StartTLS rejection must close the socket and return no client: %v", err)
	}
}

func TestStartTLSTimeout(t *testing.T) {
	for _, handshake := range []bool{false, true} {
		t.Run(fmt.Sprintf("handshake=%t", handshake), func(t *testing.T) {
			c := testOptions(t, "-start-tls", "-timeout=100ms")
			address := testLDAPListener(t, func(raw net.Conn) error {
				if handshake {
					if err := testStartTLSReply(raw, ldap.LDAPResultSuccess); err != nil {
						return err
					}
					// Consume the ClientHello but never answer; the client must time out and close.
					n, err := io.Copy(io.Discard, raw)
					if err == nil && n == 0 {
						return errors.New("missing TLS ClientHello")
					}
					return err
				}
				if _, err := testLDAPRequest(raw, ldap.ApplicationExtendedRequest); err != nil {
					return err
				}
				return testPeerClosed(raw)
			})
			start := time.Now()
			conn, err := dial(c, endpoint{URI: "ldap://" + address})
			elapsed := time.Since(start)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil || conn != nil || elapsed > 2*time.Second {
				t.Fatalf("StartTLS must fail within the configured timeout: elapsed=%s err=%v", elapsed, err)
			}
		})
	}
}

func TestStartTLSClearsUpgradeDeadline(t *testing.T) {
	certificate, ca := testTLSCertificate(t, "127.0.0.1")
	c := testOptions(t, "-start-tls", "-tls-ca="+testCAFile(t, ca), "-timeout=500ms")
	address := testLDAPListener(t, func(raw net.Conn) error {
		if err := testStartTLSReply(raw, ldap.LDAPResultSuccess); err != nil {
			return err
		}
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err := server.Handshake(); err != nil {
			return err
		}
		if err := testBindReply(server, c.RootBindDN, c.password); err != nil {
			return err
		}
		return testPeerClosed(server)
	})
	conn, err := dial(c, endpoint{URI: "ldap://" + address})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	<-time.After(c.Timeout + 50*time.Millisecond)
	if err := conn.Bind(c.RootBindDN, c.password); err != nil {
		t.Fatalf("expired upgrade deadline must not affect subsequent LDAP requests: %v", err)
	}
}

func testCAFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testTLSCertificate(t *testing.T, host string) (tls.Certificate, []byte) {
	t.Helper()
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Benchmark Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// A single local SDK peer, with deadlines so protocol regressions cannot hang tests.
func testLDAPListener(t *testing.T, serve func(net.Conn) error) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		done <- serve(conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("local LDAP peer: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("local LDAP peer did not stop")
		}
	})
	return listener.Addr().String()
}

func testLDAPRequest(conn net.Conn, tag ber.Tag) (*ber.Packet, error) {
	packet, err := ber.ReadPacket(conn)
	if err != nil {
		return nil, err
	}
	if len(packet.Children) != 2 || packet.Children[1].ClassType != ber.ClassApplication || packet.Children[1].Tag != tag {
		return nil, fmt.Errorf("expected LDAP request tag %d", tag)
	}
	return packet, nil
}

func testLDAPReply(conn net.Conn, request *ber.Packet, tag ber.Tag, code uint16) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP message")
	packet.AppendChild(request.Children[0])
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "LDAP result")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	packet.AppendChild(response)
	_, err := conn.Write(packet.Bytes())
	return err
}

func testStartTLSReply(conn net.Conn, code uint16) error {
	packet, err := testLDAPRequest(conn, ldap.ApplicationExtendedRequest)
	if err != nil {
		return err
	}
	request := packet.Children[1]
	if len(request.Children) != 1 || request.Children[0].Tag != 0 || request.Children[0].Data.String() != "1.3.6.1.4.1.1466.20037" {
		return errors.New("first request must be StartTLS, before any Bind")
	}
	return testLDAPReply(conn, packet, ldap.ApplicationExtendedResponse, code)
}

func testBindReply(conn net.Conn, dn, password string) error {
	packet, err := testLDAPRequest(conn, ldap.ApplicationBindRequest)
	if err != nil {
		return err
	}
	request := packet.Children[1]
	if len(request.Children) != 3 || request.Children[0].Value != int64(3) || request.Children[1].Data.String() != dn || request.Children[2].Data.String() != password {
		return errors.New("unexpected initial Bind credentials or LDAP version")
	}
	return testLDAPReply(conn, packet, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess)
}

func testPeerClosed(conn net.Conn) error {
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected client to close without further requests: bytes=%d err=%v", n, err)
	}
	return nil
}
