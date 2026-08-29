package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateWebAdminTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		listen  string
		cert    string
		key     string
		wantErr string
	}{
		{name: "IPv4 loopback", listen: "127.0.0.1:8080"},
		{name: "IPv6 loopback", listen: "[::1]:8080"},
		{name: "localhost", listen: "localhost:8080"},
		{name: "public HTTPS", listen: "0.0.0.0:8443", cert: "server.crt", key: "server.key"},
		{name: "empty", wantErr: "non-empty"},
		{name: "missing port", listen: "127.0.0.1", wantErr: "missing port"},
		{name: "wildcard HTTP", listen: ":8080", wantErr: "restricted to loopback"},
		{name: "public HTTP", listen: "192.0.2.1:8080", wantErr: "restricted to loopback"},
		{name: "hostname HTTP", listen: "admin.example:8080", wantErr: "restricted to loopback"},
		{name: "certificate only", listen: "127.0.0.1:8080", cert: "server.crt", wantErr: "both"},
		{name: "key only", listen: "127.0.0.1:8080", key: "server.key", wantErr: "both"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWebAdminTransport(test.listen, test.cert, test.key)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateWebAdminTransport(): %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateWebAdminTransport() = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestRunWebAdminRejectsUnsafeTransportsBeforeListening(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "public HTTP",
			args: []string{"web-admin", "-listen", "0.0.0.0:8080"},
			want: "restricted to loopback",
		},
		{
			name: "remote plaintext LDAP",
			args: []string{"web-admin", "-ldap-url", "ldap://ldap.example:389"},
			want: "plaintext LDAP is restricted",
		},
		{
			name: "incomplete HTTPS pair",
			args: []string{"web-admin", "-tls-cert", "server.crt"},
			want: "requires both",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exit := run(test.args, bytes.NewReader(nil), &stdout, &stderr, os.Getenv)
			if exit != 1 || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("run() exit=%d stdout=%q stderr=%q, want %q", exit, stdout.String(), stderr.String(), test.want)
			}
		})
	}
}

func TestValidateWebAdminLDAPTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, url, wantErr string
		startTLS           bool
	}{
		{name: "loopback LDAP", url: "ldap://127.0.0.1:1389"},
		{name: "localhost LDAP", url: "ldap://localhost:1389"},
		{name: "remote StartTLS", url: "ldap://ldap.example:389", startTLS: true},
		{name: "remote LDAPS", url: "ldaps://ldap.example:636"},
		{name: "remote plaintext", url: "ldap://ldap.example:389", wantErr: "restricted to loopback"},
		{name: "LDAPS plus StartTLS", url: "ldaps://ldap.example:636", startTLS: true, wantErr: "cannot be combined"},
		{name: "unsupported scheme", url: "http://ldap.example", wantErr: "ldap or ldaps"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWebAdminLDAPTransport(test.url, test.startTLS)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateWebAdminLDAPTransport(): %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateWebAdminLDAPTransport() = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestValidateWebAdminPublicURL(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, raw, want  string
		secure, loopback bool
	}{
		{name: "loopback derived", raw: "", loopback: true},
		{name: "HTTP", raw: "http://127.0.0.1:8080", loopback: true},
		{name: "loopback HTTPS proxy", raw: "https://admin.example", loopback: true},
		{name: "HTTPS", raw: "https://admin.example", secure: true},
		{name: "wrong secure scheme", raw: "http://admin.example", secure: true, want: "must use https"},
		{name: "untrusted HTTPS proxy", raw: "https://admin.example", want: "only on a loopback"},
		{name: "path", raw: "https://admin.example/console", secure: true, want: "only scheme and host"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateWebAdminPublicURL(test.raw, test.secure, test.loopback)
			if test.want == "" {
				if err != nil {
					t.Fatalf("validateWebAdminPublicURL(): %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateWebAdminPublicURL() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadWebAdminClientTLSConfigRejectsInvalidCA(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	if _, err := loadWebAdminClientTLSConfig(path, "ldap.example"); err == nil ||
		!strings.Contains(err.Error(), "contains no certificates") {
		t.Fatalf("loadWebAdminClientTLSConfig() = %v", err)
	}
}

func TestWebAdminLDAPServerNameDefaultsToURLHost(t *testing.T) {
	t.Parallel()
	if got := webAdminLDAPServerName("ldap://ldap.example:389", ""); got != "ldap.example" {
		t.Fatalf("default server name = %q", got)
	}
	if got := webAdminLDAPServerName("ldap://ldap.example:389", "directory.internal"); got != "directory.internal" {
		t.Fatalf("override server name = %q", got)
	}
}

func TestRunWebAdminHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if err := runWebAdmin(
		ctx,
		[]string{"-listen", "127.0.0.1:0", "-ldap-url", "ldap://127.0.0.1:1"},
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("runWebAdmin(): %v, stderr=%q", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Web administration listening at http://127.0.0.1:") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
