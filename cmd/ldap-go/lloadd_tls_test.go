package main

import (
	"bufio"
	"bytes"
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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const lloaddCommandTLSProcessEnvironment = "LDAP_GO_LLOADD_TLS_TEST_PROCESS"

type lloaddTLSFiles struct {
	certificate string
	key         string
	ca          []byte
}

type synchronizedLloaddBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedLloaddBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}

func (buffer *synchronizedLloaddBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func TestRunLloaddTestConfigValidatesListenerTLS(t *testing.T) {
	files := newLloaddTLSFiles(t)
	configPath := writeLloaddTLSConfig(t, `
listen ldap://127.0.0.1:0/
tier roundrobin
backend-server uri=ldap://127.0.0.1:1389 numconns=1 bindconns=1
`)
	for _, test := range []struct {
		name      string
		arguments []string
		want      string
	}{
		{
			name: "LDAP StartTLS",
			arguments: []string{
				"-f", configPath, "-test-config",
				"-tls-cert", files.certificate, "-tls-key", files.key,
			},
		},
		{
			name: "LDAPS override",
			arguments: []string{
				"-f", configPath, "-test-config", "-h", "ldaps://127.0.0.1:0/",
				"-tls-cert", files.certificate, "-tls-key", files.key,
			},
		},
		{
			name:      "LDAPS without certificate",
			arguments: []string{"-f", configPath, "-test-config", "-h", "ldaps://127.0.0.1:0/"},
			want:      "requires -tls-cert and -tls-key",
		},
		{
			name: "certificate without key",
			arguments: []string{
				"-f", configPath, "-test-config", "-tls-cert", files.certificate,
			},
			want: "must be configured together",
		},
		{
			name: "key without certificate",
			arguments: []string{
				"-f", configPath, "-test-config", "-tls-key", files.key,
			},
			want: "must be configured together",
		},
		{
			name: "mismatched key pair",
			arguments: []string{
				"-f", configPath, "-test-config",
				"-tls-cert", files.certificate,
				"-tls-key", newLloaddTLSFiles(t).key,
			},
			want: "private key does not match public key",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runLloadd(test.arguments, &stdout, &stderr)
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("runLloadd(-test-config) = %v, want %q", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("runLloadd(-test-config): %v; stderr=%s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "configuration is valid") {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
}

func TestListenLloaddURLLDAPS(t *testing.T) {
	files := newLloaddTLSFiles(t)
	serverTLS, err := loadLloaddClientTLS(files.certificate, files.key)
	if err != nil {
		t.Fatalf("loadLloaddClientTLS(): %v", err)
	}
	listener, description, err := listenLloaddURL("ldaps://127.0.0.1:0/", serverTLS)
	if err != nil {
		t.Fatalf("listenLloaddURL(ldaps): %v", err)
	}
	defer listener.Close()
	if !strings.HasPrefix(description, "ldaps://127.0.0.1:") {
		t.Fatalf("description = %q", description)
	}

	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		secured, ok := connection.(*tls.Conn)
		if !ok {
			serverDone <- fmt.Errorf("accepted connection has type %T", connection)
			return
		}
		serverDone <- secured.Handshake()
	}()
	clientTLS := lloaddTLSClientConfig(t, files.ca)
	connection, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("dial LDAPS listener: %v", err)
	}
	_ = connection.Close()
	if err := <-serverDone; err != nil {
		t.Fatalf("server TLS handshake: %v", err)
	}
}

func TestLloaddCommandServesStartTLSAndLDAPSListeners(t *testing.T) {
	upstreamURI := startLDAPClientToolServer(t, nil)
	ldapAddress := reserveLloaddTLSAddress(t)
	ldapsAddress := reserveLloaddTLSAddress(t)
	configPath := writeLloaddTLSConfig(t, fmt.Sprintf(`
listen ldap://%s/ ldaps://%s/
tier roundrobin
backend-server uri=%s numconns=1 bindconns=1 retry=50
`, ldapAddress, ldapsAddress, upstreamURI))
	files := newLloaddTLSFiles(t)

	command := exec.Command(os.Args[0], "-test.run=^TestLloaddCommandTLSProcess$")
	command.Env = append(os.Environ(),
		lloaddCommandTLSProcessEnvironment+"=1",
		"LDAP_GO_LLOADD_TLS_TEST_CONFIG="+configPath,
		"LDAP_GO_LLOADD_TLS_TEST_CERT="+files.certificate,
		"LDAP_GO_LLOADD_TLS_TEST_KEY="+files.key,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe(): %v", err)
	}
	var stderr synchronizedLloaddBuffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start lloadd command: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
		}
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			<-done
			return fmt.Errorf("lloadd command did not stop")
		}
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("stop lloadd command: %v; stderr=%s", err, stderr.String())
		}
	})

	lines := make(chan string, 16)
	scanDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
		scanDone <- scanner.Err()
	}()
	wantDescriptions := map[string]bool{
		"ldap-go lloadd listening on ldap://" + ldapAddress:   false,
		"ldap-go lloadd listening on ldaps://" + ldapsAddress: false,
	}
	deadline := time.After(5 * time.Second)
	for remaining := len(wantDescriptions); remaining != 0; {
		select {
		case line, ok := <-lines:
			if !ok {
				err := <-scanDone
				t.Fatalf("lloadd command stdout closed: %v; stderr=%s", err, stderr.String())
			}
			if found, exists := wantDescriptions[line]; exists && !found {
				wantDescriptions[line] = true
				remaining--
			}
		case err := <-done:
			stopped = true
			t.Fatalf("lloadd command exited early: %v; stderr=%s", err, stderr.String())
		case <-deadline:
			t.Fatalf("lloadd command did not report all listeners; stderr=%s", stderr.String())
		}
	}

	clientTLS := lloaddTLSClientConfig(t, files.ca)
	assertLloaddTLSCommandSearch(t, "ldap://"+ldapAddress, clientTLS, true)
	assertLloaddTLSCommandSearch(t, "ldaps://"+ldapsAddress, clientTLS, false)
	if err := stop(); err != nil {
		t.Fatalf("stop lloadd command: %v; stderr=%s", err, stderr.String())
	}
}

func TestLloaddCommandTLSProcess(t *testing.T) {
	if os.Getenv(lloaddCommandTLSProcessEnvironment) != "1" {
		return
	}
	err := runLloadd([]string{
		"-f", os.Getenv("LDAP_GO_LLOADD_TLS_TEST_CONFIG"),
		"-tls-cert", os.Getenv("LDAP_GO_LLOADD_TLS_TEST_CERT"),
		"-tls-key", os.Getenv("LDAP_GO_LLOADD_TLS_TEST_KEY"),
	}, os.Stdout, os.Stderr)
	if err != nil {
		t.Fatalf("runLloadd(): %v", err)
	}
}

func assertLloaddTLSCommandSearch(
	t *testing.T,
	uri string,
	tlsConfig *tls.Config,
	startTLS bool,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		options := []ldap.DialOpt{
			ldap.DialWithDialer(&net.Dialer{Timeout: time.Second}),
		}
		if !startTLS {
			options = append(options, ldap.DialWithTLSConfig(tlsConfig.Clone()))
		}
		connection, err := ldap.DialURL(uri, options...)
		if err == nil && startTLS {
			err = connection.StartTLS(tlsConfig.Clone())
		}
		if err == nil {
			connection.SetTimeout(time.Second)
			_, err = connection.Search(ldap.NewSearchRequest(
				clientToolBaseDN,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				1,
				1,
				false,
				"(objectClass=*)",
				[]string{"dc"},
				nil,
			))
		}
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("search through %s: %v", uri, lastErr)
}

func reserveLloaddTLSAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listener address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release listener address: %v", err)
	}
	return address
}

func writeLloaddTLSConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lloadd.conf")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write lloadd config: %v", err)
	}
	return path
}

func newLloaddTLSFiles(t *testing.T) lloaddTLSFiles {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate TLS private key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("issue TLS certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal TLS private key: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	directory := t.TempDir()
	files := lloaddTLSFiles{
		certificate: filepath.Join(directory, "server.pem"),
		key:         filepath.Join(directory, "server-key.pem"),
		ca:          certificatePEM,
	}
	if err := os.WriteFile(files.certificate, certificatePEM, 0o600); err != nil {
		t.Fatalf("write TLS certificate: %v", err)
	}
	if err := os.WriteFile(files.key, keyPEM, 0o600); err != nil {
		t.Fatalf("write TLS private key: %v", err)
	}
	return files
}

func lloaddTLSClientConfig(t *testing.T, certificatePEM []byte) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("append lloadd TLS test certificate")
	}
	return &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}
