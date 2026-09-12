package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestCommandSASLCBindingOutput(t *testing.T) {
	for _, policy := range []string{"none", "tls-unique", "tls-endpoint", "NoNe", "TLS-UNIQUE", "tls-ENDPOINT"} {
		for _, argument := range []string{policy, `"` + policy + `"`} {
			t.Run(argument, func(t *testing.T) {
				input := inputFile(t, "sasl-cbinding "+argument+"\n"+twoDatabases)
				output := filepath.Join(t.TempDir(), "config.ldif")
				for _, extra := range [][]string{nil, {"-out", "-"}, {"-out", output}, {"-check"}} {
					var stdout, stderr bytes.Buffer
					if err := run(t.Context(), append([]string{"-f", input}, extra...), &stdout, &stderr); err != nil {
						t.Fatal(err)
					}
					if len(extra) > 0 && extra[0] == "-check" {
						if stdout.Len() != 0 || stderr.String() != "configuration OK\n" {
							t.Fatalf("check output %q %q", &stdout, &stderr)
						}
						continue
					}
					text := stdout.String()
					if len(extra) == 2 && extra[1] == output {
						if stdout.Len() != 0 {
							t.Fatal("file output also wrote stdout")
						}
						data, err := os.ReadFile(output)
						if err != nil {
							t.Fatal(err)
						}
						text = string(data)
					}
					if stderr.Len() != 0 || strings.Count(text, "olcSaslCBinding: "+policy+"\n") != 1 {
						t.Fatalf("output=%q stderr=%q", text, &stderr)
					}
				}
			})
		}
	}
}

func TestCommandSASLCBindingInvalidAtomicOutput(t *testing.T) {
	for _, directive := range []string{
		"sasl-cbinding", "sasl-cbinding none tls-unique", `sasl-cbinding ""`,
		"sasl-cbinding required", `sasl-cbinding "required"`, `sasl-cbinding " none"`,
		`sasl-cbinding "none "`, `sasl-cbinding "none tls-unique"`, `sasl-cbinding "\"none\""`,
		"sasl-cbinding tls-server-end-point", "sasl-cbinding tls-exporter",
		"sasl-cbinding {0}none", "sasl-cbinding tls-un\u0130que", `sasl-cbinding "none`,
		"sasl-cbinding none\nsasl-cbinding none", "sasl-cbinding none\nsasl-cbinding TLS-ENDPOINT",
	} {
		t.Run(directive, func(t *testing.T) {
			child := inputFile(t, "# included policy\n"+directive+"\n")
			input := inputFile(t, twoDatabases+fmt.Sprintf("include %q\n", child))
			line := 2
			if strings.Contains(directive, "\n") {
				line = 3
			}
			for _, mode := range []string{"stdout", "-out", "-db", "-check"} {
				outputDir := t.TempDir()
				output := filepath.Join(outputDir, "config")
				args := []string{"-f", input}
				switch mode {
				case "-out", "-db":
					args = append(args, mode, output)
				case "-check":
					args = append(args, mode)
				}
				var stdout, stderr bytes.Buffer
				err := run(t.Context(), args, &stdout, &stderr)
				if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%s:%d:", child, line)) {
					t.Fatalf("%s error=%v", mode, err)
				}
				entries, err := os.ReadDir(outputDir)
				if err != nil || len(entries) != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
					t.Fatalf("%s published invalid output: entries=%v stdout=%q stderr=%q error=%v", mode, entries, &stdout, &stderr, err)
				}
				if mode == "-out" || mode == "-db" {
					before := []byte("existing destination\n")
					if err := os.WriteFile(output, before, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := run(t.Context(), args, &stdout, &stderr); err == nil {
						t.Fatal("invalid configuration accepted")
					}
					after, err := os.ReadFile(output)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatalf("existing destination changed: %q, %v", after, err)
					}
				}
			}
		})
	}
}

func TestCommandSASLCBindingOffline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	input := inputFile(t, fmt.Sprintf(`sasl-cbinding tls-unique
serverid 1 ldap://%s
database mdb
suffix dc=example
directory /unused
syncrepl rid=001 provider=ldap://%s searchbase=dc=example type=refreshAndPersist retry="1 +"
`, listener.Addr(), listener.Addr()))
	for _, extra := range [][]string{nil, {"-check"}, {"-db", filepath.Join(t.TempDir(), "config.db")}} {
		if err := run(t.Context(), append([]string{"-f", input}, extra...), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err == nil {
		connection.Close()
		t.Fatal("command contacted the replication provider")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("accept: %v", err)
	}
}

func TestCommandSASLCBindingRuntimeRestart(t *testing.T) {
	tlsDirectives, roots := saslCBindingTLSFiles(t)
	for _, policy := range []string{"", "NoNe", "TLS-UNIQUE", "tls-ENDPOINT"} {
		t.Run(policy, func(t *testing.T) {
			configuration := tlsDirectives + "sasl-secprops none\n" + twoDatabases
			if policy != "" {
				configuration += fmt.Sprintf("sasl-cbinding %q\n", policy)
			}
			input := inputFile(t, configuration)
			output := filepath.Join(t.TempDir(), "config.db")
			if err := run(t.Context(), []string{"-f", input, "-db", output}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			for _, phase := range []string{"initial", "restart"} {
				t.Run(phase, func(t *testing.T) {
					address := startSASLCBindingDatabase(t, output)
					for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
						client, err := ldap.DialURL("ldap://" + address)
						if err != nil {
							t.Fatal(err)
						}
						defer client.Close()
						client.SetTimeout(5 * time.Second)
						if err := client.StartTLS(&tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: version, MaxVersion: version}); err != nil {
							t.Fatal(err)
						}
						result, err := client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"supportedSASLMechanisms"}, nil))
						if err != nil || len(result.Entries) != 1 {
							t.Fatalf("root DSE: %v %v", result, err)
						}
						mechanisms := result.Entries[0].GetAttributeValues("supportedSASLMechanisms")
						wantPlus := strings.EqualFold(policy, "tls-endpoint") || strings.EqualFold(policy, "tls-unique") && version == tls.VersionTLS12
						if got := slices.Contains(mechanisms, "SCRAM-SHA-256-PLUS"); got != wantPlus {
							t.Fatalf("TLS %x: PLUS=%t, want %t; mechanisms=%v", version, got, wantPlus, mechanisms)
						}
						if err := client.Bind("cn=config", "config secret"); err != nil {
							t.Fatal(err)
						}
						for _, attribute := range []string{"olcSaslCBinding", "1.3.6.1.4.1.4203.1.12.2.3.0.100"} {
							result, err := client.Search(ldap.NewSearchRequest("cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{attribute}, nil))
							if err != nil || len(result.Entries) != 1 {
								t.Fatalf("configuration: %v %v", result, err)
							}
							got := result.Entries[0].GetAttributeValues("olcSaslCBinding")
							var want []string
							if policy != "" {
								want = []string{policy}
							}
							if !slices.Equal(got, want) {
								t.Fatalf("%s = %q, want %q", attribute, got, want)
							}
						}
					}
				})
			}
		})
	}
}

func startSASLCBindingDatabase(t *testing.T, path string) string {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	instance, err := server.New(server.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	return listener.Addr().String()
}

func saslCBindingTLSFiles(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	certificatePath, keyPath := filepath.Join(base, "server.pem"), filepath.Join(base, "key.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("could not load test certificate")
	}
	return fmt.Sprintf("TLSCertificateFile %q\nTLSCertificateKeyFile %q\n", certificatePath, keyPath), roots
}
