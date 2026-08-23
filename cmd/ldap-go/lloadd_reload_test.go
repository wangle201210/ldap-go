package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/lloadd"
)

type lloaddReloadBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (buffer *lloaddReloadBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.Write(value)
}

func (buffer *lloaddReloadBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.String()
}

func TestRunLloaddSIGUSR1HotReloadAndRollback(t *testing.T) {
	first := reserveLloaddTLSAddress(t)
	second := reserveLloaddTLSAddress(t)
	configPath := writeLloaddTLSConfig(t, lloaddReloadConfig([]string{first}))

	ctx, cancel := context.WithCancel(context.Background())
	management := make(chan os.Signal, 4)
	var stdout, stderr lloaddReloadBuffer
	done := make(chan error, 1)
	finished := false
	go func() {
		done <- runLloaddWithSignals(
			ctx,
			management,
			[]string{"-f", configPath, "-hot-reload"},
			&stdout,
			&stderr,
		)
	}()
	t.Cleanup(func() {
		cancel()
		if finished {
			return
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("lloadd SIGHUP test daemon did not stop")
		}
	})
	waitForLloaddReloadListener(t, first)

	transport, err := net.Dial("tcp", first)
	if err != nil {
		t.Fatalf("dial initial lloadd listener: %v", err)
	}
	client := ldap.NewConn(transport, false)
	client.Start()
	defer client.Close()
	assertLloaddReloadMonitor(t, client)

	if err := os.WriteFile(
		configPath,
		[]byte(lloaddReloadConfig([]string{first, second})),
		0o600,
	); err != nil {
		t.Fatalf("write replacement lloadd config: %v", err)
	}
	management <- syscall.SIGUSR1
	waitForLloaddReloadListener(t, second)
	assertLloaddReloadMonitorClosed(t, client)

	reloadedTransport, err := net.Dial("tcp", second)
	if err != nil {
		t.Fatalf("dial reloaded lloadd listener: %v", err)
	}
	reloadedClient := ldap.NewConn(reloadedTransport, false)
	reloadedClient.Start()
	defer reloadedClient.Close()
	assertLloaddReloadMonitor(t, reloadedClient)

	if err := os.WriteFile(configPath, []byte("listen invalid:///\n"), 0o600); err != nil {
		t.Fatalf("write invalid lloadd config: %v", err)
	}
	management <- syscall.SIGUSR1
	waitForLloaddReloadLog(t, &stderr, "SIGUSR1 reload failed; keeping current topology")
	waitForLloaddReloadListener(t, first)
	waitForLloaddReloadListener(t, second)
	assertLloaddReloadMonitor(t, reloadedClient)

	cancel()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatalf("runLloaddWithSignals(): %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runLloaddWithSignals() did not stop")
	}
}

func TestRunLloaddSIGHUPShutsDownByDefault(t *testing.T) {
	address := reserveLloaddTLSAddress(t)
	configPath := writeLloaddTLSConfig(t, lloaddReloadConfig([]string{address}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	management := make(chan os.Signal, 1)
	var stdout, stderr lloaddReloadBuffer
	done := make(chan error, 1)
	go func() {
		done <- runLloaddWithSignals(
			ctx,
			management,
			[]string{"-f", configPath, "-drain-timeout", "250ms"},
			&stdout,
			&stderr,
		)
	}()
	waitForLloaddReloadListener(t, address)
	management <- syscall.SIGHUP
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SIGHUP shutdown: %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lloadd did not stop after SIGHUP")
	}
	connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("lloadd listener still accepted connections after SIGHUP")
	}
}

func TestRunLloaddSIGUSR1ReloadsLDAPSCertificateAndDrainsSession(t *testing.T) {
	address := reserveLloaddTLSAddress(t)
	configPath := writeLloaddTLSConfig(t, lloaddReloadConfigWithScheme("ldaps", []string{address}))
	activeFiles := newLloaddTLSFiles(t)
	replacementFiles := newLloaddTLSFiles(t)
	ctx, cancel := context.WithCancel(context.Background())
	management := make(chan os.Signal, 1)
	var stdout, stderr lloaddReloadBuffer
	done := make(chan error, 1)
	go func() {
		done <- runLloaddWithSignals(
			ctx,
			management,
			[]string{
				"-f", configPath,
				"-hot-reload",
				"-drain-timeout", "2s",
				"-tls-cert", activeFiles.certificate,
				"-tls-key", activeFiles.key,
			},
			&stdout,
			&stderr,
		)
	}()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			cancel()
			<-done
		}
	})
	waitForLloaddReloadListener(t, address)

	oldTLS := dialLloaddReloadTLS(t, address)
	oldCertificate := bytes.Clone(oldTLS.ConnectionState().PeerCertificates[0].Raw)
	oldClient := ldap.NewConn(oldTLS, true)
	oldClient.Start()
	defer oldClient.Close()
	assertLloaddReloadMonitor(t, oldClient)

	copyLloaddReloadFile(t, replacementFiles.certificate, activeFiles.certificate, 0o600)
	copyLloaddReloadFile(t, replacementFiles.key, activeFiles.key, 0o600)
	management <- syscall.SIGUSR1

	deadline := time.Now().Add(5 * time.Second)
	reloaded := false
	var replacementTLS *tls.Conn
	for time.Now().Before(deadline) {
		connection := dialLloaddReloadTLS(t, address)
		current := connection.ConnectionState().PeerCertificates[0].Raw
		if !bytes.Equal(oldCertificate, current) {
			reloaded = true
			replacementTLS = connection
			break
		}
		_ = connection.Close()
		time.Sleep(20 * time.Millisecond)
	}
	if !reloaded {
		t.Fatal("LDAPS listener continued serving the old certificate after SIGUSR1")
	}
	assertLloaddReloadMonitorClosed(t, oldClient)
	replacementClient := ldap.NewConn(replacementTLS, true)
	replacementClient.Start()
	defer replacementClient.Close()
	assertLloaddReloadMonitor(t, replacementClient)

	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("runLloaddWithSignals(): %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lloadd LDAPS reload daemon did not stop")
	}
}

func lloaddReloadConfig(listeners []string) string {
	return lloaddReloadConfigWithScheme("ldap", listeners)
}

func lloaddReloadConfigWithScheme(scheme string, listeners []string) string {
	urls := make([]string, len(listeners))
	for index, address := range listeners {
		urls[index] = scheme + "://" + address + "/"
	}
	return fmt.Sprintf(`
listen %s
tier roundrobin
backend-server uri=ldap://127.0.0.1:1 numconns=1 bindconns=1 retry=50
`, strings.Join(urls, " "))
}

func dialLloaddReloadTLS(t *testing.T, address string) *tls.Conn {
	t.Helper()
	connection, err := tls.Dial("tcp", address, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Test certificates use independent roots.
	})
	if err != nil {
		t.Fatalf("dial lloadd LDAPS listener: %v", err)
	}
	return connection
}

func copyLloaddReloadFile(t *testing.T, source, target string, mode os.FileMode) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read replacement TLS file: %v", err)
	}
	if err := os.WriteFile(target, contents, mode); err != nil {
		t.Fatalf("replace active TLS file: %v", err)
	}
}

func assertLloaddReloadMonitor(t *testing.T, client *ldap.Conn) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		lloadd.MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancer)",
		[]string{"cn", "+"},
		nil,
	))
	entries := 0
	if result != nil {
		entries = len(result.Entries)
	}
	if err != nil || entries != 1 {
		t.Fatalf("monitor Search after reload: entries=%d err=%v", entries, err)
	}
}

func assertLloaddReloadMonitorClosed(t *testing.T, client *ldap.Conn) {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		lloadd.MonitorLoadBalancerDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olmBalancer)",
		[]string{"cn"},
		nil,
	))
	if err == nil {
		t.Fatal("retired lloadd session remained usable after reload")
	}
}

func waitForLloaddReloadListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lloadd listener %s did not become available", address)
}

func waitForLloaddReloadLog(t *testing.T, buffer *lloaddReloadBuffer, marker string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buffer.String(), marker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lloadd stderr lacks %q: %s", marker, buffer.String())
}
