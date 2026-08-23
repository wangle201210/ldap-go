package main

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunLloaddValidatesConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		contents string
	}{
		{name: "LDAP", contents: `
listen ldap://127.0.0.1:0/
tier roundrobin
backend-server uri=ldap://127.0.0.1:1389 numconns=1 bindconns=1
		`},
		{name: "upstream StartTLS", contents: `
listen ldap://127.0.0.1:0/
tier roundrobin
backend-server uri=ldap://127.0.0.1:1389 starttls=critical
		`},
		{name: "upstream LDAPS with system roots", contents: `
listen ldap://127.0.0.1:0/
tier roundrobin
backend-server uri=ldaps://127.0.0.1:1636
		`},
		{name: "upstream keepalive", contents: `
listen ldap://127.0.0.1:0/
bindconf bindmethod=none keepalive=30:3:10
tier roundrobin
backend-server uri=ldap://127.0.0.1:1389 numconns=1 bindconns=1
			`},
		{name: "read pause", contents: `
listen ldap://127.0.0.1:0/
feature read_pause
tier roundrobin
backend-server uri=ldap://127.0.0.1:1389 max-pending-ops=1 conn-max-pending=1
			`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lloadd.conf")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			var stdout, stderr bytes.Buffer
			if err := runLloadd(
				[]string{"-f", path, "-test-config"},
				&stdout,
				&stderr,
			); err != nil {
				t.Fatalf("runLloadd(-test-config): %v; stderr=%s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "configuration is valid") {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
}

func TestRunLloaddRejectsMissingConfiguration(t *testing.T) {
	err := runLloadd(
		[]string{"-f", filepath.Join(t.TempDir(), "missing.conf"), "-test-config"},
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Fatalf("runLloadd(missing) = %v", err)
	}
}

func TestRunLloaddTestConfigValidatesRuntimeRequirements(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		env      map[string]string
		want     string
	}{
		{
			name: "client LDAPS",
			contents: `
listen ldaps://127.0.0.1:636/
`,
			want: "requires -tls-cert and -tls-key",
		},
		{
			name: "client PLDAPS",
			contents: `
listen pldaps://127.0.0.1:636/
`,
			want: "requires -tls-cert and -tls-key",
		},
		{
			name: "GSSAPI password requires realm",
			contents: `
listen ldap://127.0.0.1:0/
feature proxyauthz
bindconf bindmethod=sasl saslmech=GSSAPI authcid=alice credentials=secret
`,
			want: "GSSAPI password credentials require authcid and realm",
		},
		{
			name: "GSSAPI environment provider fails closed",
			contents: `
listen ldap://127.0.0.1:0/
feature proxyauthz
bindconf bindmethod=sasl saslmech=GSSAPI authcid=alice@EXAMPLE.TEST
`,
			env:  map[string]string{"KRB5_CLIENT_KTNAME": "KCM:lloadd"},
			want: `KRB5_CLIENT_KTNAME credential provider "KCM" is unsupported`,
		},
		{
			name: "GSSAPI password credentials",
			contents: `
listen ldap://127.0.0.1:0/
feature proxyauthz
bindconf bindmethod=sasl saslmech=GSSAPI authcid=alice realm=EXAMPLE.TEST credentials=secret
`,
		},
		{
			name: "service Bind without ProxyAuthz",
			contents: `
listen ldap://127.0.0.1:0/
bindconf bindmethod=simple binddn=cn=Manager credentials=secret
`,
			want: "upstream service bind requires ProxyAuthz",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			path := filepath.Join(t.TempDir(), "lloadd.conf")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			err := runLloadd(
				[]string{"-f", path, "-test-config"},
				&bytes.Buffer{},
				&bytes.Buffer{},
			)
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("runLloadd(-test-config) = %v, want %q", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("runLloadd(-test-config): %v", err)
			}
		})
	}
}

func TestListenLloaddURL(t *testing.T) {
	listener, description, err := listenLloaddURL("ldap://127.0.0.1:0/", nil)
	if err != nil {
		t.Fatalf("listenLloaddURL(ldap): %v", err)
	}
	if !strings.HasPrefix(description, "ldap://127.0.0.1:") {
		t.Fatalf("description = %q", description)
	}
	_ = listener.Close()
	socketPath := filepath.Join(t.TempDir(), "lloadd.sock")
	listener, description, err = listenLloaddURL(
		"ldapi://"+url.PathEscape(socketPath)+"/",
		nil,
	)
	if err != nil {
		t.Fatalf("listenLloaddURL(ldapi): %v", err)
	}
	if listener.Addr().String() != socketPath || description != "ldapi://"+socketPath {
		t.Fatalf("LDAPI listener = %q, %q", listener.Addr(), description)
	}
	_ = listener.Close()
	if listener, _, err := listenLloaddURL("ldaps://127.0.0.1:0/", nil); err == nil {
		_ = listener.Close()
		t.Fatal("listenLloaddURL(ldaps without TLS) succeeded")
	}
	proxyTrustedSources, err := parseLloaddProxyTrustedSources([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("parse trusted sources: %v", err)
	}
	listener, description, err = listenLloaddURL(
		"pldap://127.0.0.1:0/",
		nil,
		proxyTrustedSources,
	)
	if err != nil {
		t.Fatalf("listenLloaddURL(pldap): %v", err)
	}
	if !strings.HasPrefix(description, "pldap://127.0.0.1:") {
		t.Fatalf("PROXY listener description = %q", description)
	}
	_ = listener.Close()
	dnsTrustedSources, err := parseLloaddProxyTrustedSources(
		[]string{"127.0.0.0/8", "::1/128"},
	)
	if err != nil {
		t.Fatalf("parse DNS listener trusted sources: %v", err)
	}
	listener, _, err = listenLloaddURL("pldap://localhost:0/", nil, dnsTrustedSources)
	if err != nil {
		t.Fatalf("listenLloaddURL(pldap DNS loopback): %v", err)
	}
	_ = listener.Close()
	for _, raw := range []string{
		"pldap://:389/",
		"pldap://0.0.0.0:389/",
		"pldaps://[::]:636/",
	} {
		if listener, _, err := listenLloaddURL(raw, nil, proxyTrustedSources); err == nil {
			_ = listener.Close()
			t.Fatalf("listenLloaddURL(%q) accepted a wildcard trusted listener", raw)
		}
	}
	if listener, _, err := listenLloaddURL("http://127.0.0.1:0/", nil); err == nil {
		_ = listener.Close()
		t.Fatal("listenLloaddURL(http) succeeded")
	}
}

func TestRunLloaddProxyTrustedSourceValidation(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "lloadd.conf")
	if err := os.WriteFile(configPath, []byte(`
listen pldap://localhost:0/
tier roundrobin
backend-server uri=ldap://127.0.0.1:1389 numconns=1 bindconns=1
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing allowlist",
			args: []string{"-f", configPath, "-test-config"},
			want: "requires at least one -proxy-trusted-source",
		},
		{
			name: "invalid address",
			args: []string{
				"-f", configPath,
				"-test-config",
				"-proxy-trusted-source", "not-an-address",
			},
			want: "parse -proxy-trusted-source",
		},
		{
			name: "all IPv4 addresses",
			args: []string{
				"-f", configPath,
				"-test-config",
				"-proxy-trusted-source", "0.0.0.0/0",
			},
			want: "not a trusted allowlist",
		},
		{
			name: "all IPv6 addresses",
			args: []string{
				"-f", configPath,
				"-test-config",
				"-proxy-trusted-source", "::/0",
			},
			want: "not a trusted allowlist",
		},
		{
			name: "single IP and repeated CIDR",
			args: []string{
				"-f", configPath,
				"-test-config",
				"-proxy-trusted-source", "127.0.0.1",
				"-proxy-trusted-source", "::1/128",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runLloadd(test.args, &stdout, &stderr)
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("runLloadd() = %v, want %q; stderr=%s", err, test.want, stderr.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("runLloadd() = %v; stderr=%s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "configuration is valid") {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
}

func TestRunLloaddReloadRejectsProxyListenerWithoutTrustedSources(t *testing.T) {
	initialAddress := reserveLloaddTLSAddress(t)
	proxyAddress := reserveLloaddTLSAddress(t)
	configPath := writeLloaddTLSConfig(t, lloaddReloadConfig([]string{initialAddress}))
	ctx, cancel := context.WithCancel(context.Background())
	management := make(chan os.Signal, 1)
	var stdout, stderr lloaddReloadBuffer
	done := make(chan error, 1)
	go func() {
		done <- runLloaddWithSignals(
			ctx,
			management,
			[]string{"-f", configPath, "-hot-reload", "-drain-timeout", "500ms"},
			&stdout,
			&stderr,
		)
	}()
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("lloadd reload test did not stop")
		}
	})
	waitForLloaddReloadListener(t, initialAddress)

	if err := os.WriteFile(
		configPath,
		[]byte(lloaddReloadConfigWithScheme("pldap", []string{proxyAddress})),
		0o600,
	); err != nil {
		t.Fatalf("write PROXY reload config: %v", err)
	}
	management <- syscall.SIGUSR1
	waitForLloaddReloadLog(t, &stderr, "requires at least one -proxy-trusted-source")
	waitForLloaddReloadListener(t, initialAddress)
	if connection, err := net.DialTimeout("tcp", proxyAddress, 100*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("reload installed a PROXY listener without trusted sources")
	}

	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("runLloaddWithSignals(): %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lloadd reload test did not stop")
	}
}

func TestRunLloaddReloadPreservesProxyTrustedSources(t *testing.T) {
	initialAddress := reserveLloaddTLSAddress(t)
	reloadedAddress := reserveLloaddTLSAddress(t)
	configPath := writeLloaddTLSConfig(
		t,
		lloaddReloadConfigWithScheme("pldap", []string{initialAddress}),
	)
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
				"-drain-timeout", "500ms",
				"-proxy-trusted-source", "127.0.0.1/32",
			},
			&stdout,
			&stderr,
		)
	}()
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("trusted PROXY reload test did not stop")
		}
	})
	waitForLloaddReloadListener(t, initialAddress)
	assertLloaddTrustedProxyListenerOpen(t, initialAddress)

	if err := os.WriteFile(
		configPath,
		[]byte(lloaddReloadConfigWithScheme("pldap", []string{reloadedAddress})),
		0o600,
	); err != nil {
		t.Fatalf("write trusted PROXY reload config: %v", err)
	}
	management <- syscall.SIGUSR1
	waitForLloaddReloadListener(t, reloadedAddress)
	assertLloaddTrustedProxyListenerOpen(t, reloadedAddress)

	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("runLloaddWithSignals(): %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("trusted PROXY reload test did not stop")
	}
}

func assertLloaddTrustedProxyListenerOpen(t *testing.T, address string) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial trusted PROXY listener %s: %v", address, err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("PROXY UNKNOWN\r\n")); err != nil {
		t.Fatalf("write trusted PROXY header: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set trusted PROXY read deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("trusted PROXY listener returned unexpected LDAP data")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("trusted PROXY listener closed after a valid header: %v", err)
	}
}

func TestCombinedListenerAcceptsEverySource(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen first: %v", err)
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = first.Close()
		t.Fatalf("listen second: %v", err)
	}
	combined, err := newCombinedListener([]net.Listener{first, second})
	if err != nil {
		t.Fatalf("newCombinedListener(): %v", err)
	}
	defer combined.Close()
	clients := make([]net.Conn, 0, 2)
	for _, address := range []string{first.Addr().String(), second.Addr().String()} {
		client, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", address, err)
		}
		clients = append(clients, client)
	}
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()
	for range 2 {
		connection, err := combined.Accept()
		if err != nil {
			t.Fatalf("Accept(): %v", err)
		}
		_ = connection.Close()
	}
}
