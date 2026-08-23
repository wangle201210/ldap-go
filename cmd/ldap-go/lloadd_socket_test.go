package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestRunLloaddValidatesUpstreamSocketOptions(t *testing.T) {
	keepaliveDurationRangeError := "exceeds time.Duration"
	if strconv.IntSize == 32 {
		keepaliveDurationRangeError = "out of range"
	}
	for _, test := range []struct {
		name     string
		bindConf string
		want     string
	}{
		{
			name:     "negative keepalive idle",
			bindConf: "keepalive=-1:3:10",
			want:     "unsigned decimal integer",
		},
		{
			name:     "negative keepalive probes",
			bindConf: "keepalive=30:-1:10",
			want:     "unsigned decimal integer",
		},
		{
			name:     "negative keepalive interval",
			bindConf: "keepalive=30:3:-1",
			want:     "unsigned decimal integer",
		},
		{
			name:     "keepalive integer range",
			bindConf: "keepalive=18446744073709551616:3:10",
			want:     "out of range",
		},
		{
			name:     "keepalive duration range",
			bindConf: "keepalive=9223372037:3:10",
			want:     keepaliveDurationRangeError,
		},
		{
			name:     "negative TCP user timeout",
			bindConf: "tcp-user-timeout=-1",
			want:     "non-negative integer",
		},
		{
			name:     "TCP user timeout duration range",
			bindConf: "tcp-user-timeout=9223372036855",
			want:     "overflows time.Duration",
		},
		{
			name:     "TCP user timeout socket range",
			bindConf: "tcp-user-timeout=2147483648",
			want:     "exceeds the platform integer limit",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runLloaddSocketTestConfig(t, test.bindConf, "ldap://127.0.0.1:1389")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runLloadd(-test-config) = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunLloaddTCPUserTimeoutPlatformBehavior(t *testing.T) {
	err := runLloaddSocketTestConfig(
		t,
		"keepalive=30:3:10 tcp-user-timeout=1500",
		"ldap://127.0.0.1:1389",
	)
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("runLloadd(-test-config): %v", err)
		}
	} else if err == nil || !strings.Contains(
		err.Error(),
		"TCP_USER_TIMEOUT is not supported on "+runtime.GOOS,
	) {
		t.Fatalf("runLloadd(-test-config) = %v, want unsupported platform", err)
	}
}

func TestRunLloaddTCPUserTimeoutAllowsLDAPI(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "backend.sock")
	err := runLloaddSocketTestConfig(
		t,
		"keepalive=0:0:0 tcp-user-timeout=1500",
		"ldapi://"+socketPath,
	)
	if err != nil {
		t.Fatalf("runLloadd(-test-config): %v", err)
	}
}

func runLloaddSocketTestConfig(t *testing.T, bindConf, backendURI string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lloadd.conf")
	contents := fmt.Sprintf(`
listen ldap://127.0.0.1:0/
bindconf bindmethod=none %s
tier roundrobin
backend-server uri=%s numconns=1 bindconns=1
`, bindConf, backendURI)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return runLloadd(
		[]string{"-f", path, "-test-config"},
		&bytes.Buffer{},
		&bytes.Buffer{},
	)
}
