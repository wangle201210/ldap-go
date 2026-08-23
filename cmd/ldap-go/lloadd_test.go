package main

import (
	"bytes"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

func TestRunLloaddTestConfigRejectsUnsupportedRuntime(t *testing.T) {
	tests := []struct {
		name     string
		contents string
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
			name: "unsupported service SASL mechanism",
			contents: `
listen ldap://127.0.0.1:0/
feature proxyauthz
bindconf bindmethod=sasl saslmech=GSSAPI authcid=alice credentials=secret
`,
			want: "GSSAPI is not supported",
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
			path := filepath.Join(t.TempDir(), "lloadd.conf")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			err := runLloadd(
				[]string{"-f", path, "-test-config"},
				&bytes.Buffer{},
				&bytes.Buffer{},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runLloadd(-test-config) = %v, want %q", err, test.want)
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
	listener, description, err = listenLloaddURL("pldap://127.0.0.1:0/", nil)
	if err != nil {
		t.Fatalf("listenLloaddURL(pldap): %v", err)
	}
	if !strings.HasPrefix(description, "pldap://127.0.0.1:") {
		t.Fatalf("PROXY listener description = %q", description)
	}
	_ = listener.Close()
	if listener, _, err := listenLloaddURL("http://127.0.0.1:0/", nil); err == nil {
		_ = listener.Close()
		t.Fatal("listenLloaddURL(http) succeeded")
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
