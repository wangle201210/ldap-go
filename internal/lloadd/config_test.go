package lloadd

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigMatchesOpenLDAP2613(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	if !reflect.DeepEqual(config.ListenURLs, []string{"ldap:///"}) ||
		config.MaxIncomingClient != 16777215 ||
		config.MaxIncomingUpstream != 16777215 ||
		config.ClientMaxPending != 0 || config.WriteCoherence != 0 ||
		config.IOTimeout != 10*time.Second || config.NetworkTimeout != 0 ||
		config.ProxyAuthz || config.BindConf.Method != BindNone ||
		len(config.Tiers) != 0 || len(config.Restrictions) != 0 {
		t.Fatalf("DefaultConfig() = %#v", config)
	}
	backend := DefaultBackendConfig()
	if backend.NumConns != 1 || backend.BindConns != 1 ||
		backend.Retry != 5*time.Second || backend.MaxPendingOps != 0 ||
		backend.ConnMaxPending != 0 || backend.Weight != 1 ||
		backend.StartTLS != StartTLSDisabled {
		t.Fatalf("DefaultBackendConfig() = %#v", backend)
	}
	if OpenLDAPSourceCommit != "d172686d3d270bc961b78f3ff00d7019c8dfb094" {
		t.Fatalf("source commit = %q", OpenLDAPSourceCommit)
	}
}

func TestParseStandaloneConfig(t *testing.T) {
	t.Parallel()

	input := `# a complete runtime configuration
listen "ldap://127.0.0.1:1389 ldaps://[::1]:1636/"
sockbuf_max_incoming_client 1048576
sockbuf_max_incoming_upstream 2097152
client_max_pending 64
write_coherence -1
iotimeout 1250
feature proxyauthz read_pause
restrict_exop 1.1 reject
restrict_exop 1.3.6.1.1.21.1 connection
restrict_control 1.2.840.113556.1.4.319 backend
bindconf bindmethod=simple \
 binddn="cn=Load Balancer,dc=example,dc=com" \
 credentials="s e\ c r e t" timeout=7 network-timeout=3 \
 keepalive=30:4:10 tcp-user-timeout=1500 tls_reqcert=demand \
 tls_reqsan=allow tls_protocol_min=3.3 tls_crlcheck=peer
tier roundrobin
backend-server uri=ldap://one.example.com numconns=3 bindconns=2 \
 retry=750 max-pending-ops=20 conn-max-pending=4
tier weighted
backend-server uri=ldaps://two.example.com:6636/ numconns=5 bindconns=1 \
 retry=0 max-pending-ops=0 conn-max-pending=0 starttls=critical weight=9
`
	config, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	if !reflect.DeepEqual(config.ListenURLs, []string{"ldap://127.0.0.1:1389", "ldaps://[::1]:1636/"}) {
		t.Fatalf("ListenURLs = %#v", config.ListenURLs)
	}
	if config.MaxIncomingClient != 1048576 || config.MaxIncomingUpstream != 2097152 ||
		config.ClientMaxPending != 64 || config.WriteCoherence != -time.Second ||
		config.IOTimeout != 1250*time.Millisecond || config.NetworkTimeout != 3*time.Second ||
		!config.ProxyAuthz || !config.HasFeature(FeatureReadPause) {
		t.Fatalf("global config = %#v", config)
	}
	bind := config.BindConf
	if bind.Method != BindSimple || bind.BindDN != "cn=Load Balancer,dc=example,dc=com" ||
		bind.Credentials != "s e c r e t" || bind.Timeout != 7*time.Second ||
		bind.TCPUserTimeout != 1500*time.Millisecond ||
		bind.KeepAlive != (KeepAliveConfig{Set: true, Idle: 30, Probes: 4, Interval: 10}) ||
		bind.TLS.RequireCert != "demand" || bind.TLS.RequireSAN != "allow" ||
		bind.TLS.ProtocolMin != "3.3" || bind.TLS.CRLCheck != "peer" {
		t.Fatalf("BindConf = %#v", bind)
	}
	if len(config.Tiers) != 2 || config.Tiers[0].Policy != TierRoundRobin ||
		config.Tiers[1].Policy != TierWeighted || len(config.Tiers[0].Backends) != 1 ||
		len(config.Tiers[1].Backends) != 1 {
		t.Fatalf("Tiers = %#v", config.Tiers)
	}
	first := config.Tiers[0].Backends[0]
	if first.URI != "ldap://one.example.com" || first.NumConns != 3 || first.BindConns != 2 ||
		first.Retry != 750*time.Millisecond || first.MaxPendingOps != 20 ||
		first.ConnMaxPending != 4 || first.Weight != 1 {
		t.Fatalf("first backend = %#v", first)
	}
	second := config.Tiers[1].Backends[0]
	if second.URI != "ldaps://two.example.com:6636/" || second.StartTLS != StartTLSImplicit ||
		second.Weight != 9 || second.Retry != 0 {
		t.Fatalf("second backend = %#v", second)
	}
	if action, ok := config.LookupRestriction(RestrictionExtendedOperation, "1.3.6.1.4.1.99999"); !ok || action != RestrictionActionReject {
		t.Fatalf("default exop restriction = %q, %v", action, ok)
	}
	if action, ok := config.LookupRestriction(RestrictionExtendedOperation, "1.3.6.1.1.21.1"); !ok || action != RestrictionActionConnection {
		t.Fatalf("specific exop restriction = %q, %v", action, ok)
	}
}

func TestParseQuotesEscapesAndIndentedContinuation(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(`bindconf
	bindmethod=simple
	binddn="cn=service,dc=example,dc=com"
	credentials=quoted\ password
tier bestof
backend-server
	uri=ldap://ldap.example.com
	numconns=2
	bindconns=3
	weight=4
`))
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	if config.BindConf.Credentials != "quoted password" || config.BindConf.BindDN != "cn=service,dc=example,dc=com" {
		t.Fatalf("BindConf = %#v", config.BindConf)
	}
	backend := config.Tiers[0].Backends[0]
	if backend.URI != "ldap://ldap.example.com" || backend.NumConns != 2 || backend.BindConns != 3 || backend.Weight != 4 {
		t.Fatalf("backend = %#v", backend)
	}
}

func TestParseIncludePreservesTierOwnershipAndOrder(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	root := filepath.Join(directory, "lloadd.conf")
	child := filepath.Join(directory, "backends.conf")
	grandchild := filepath.Join(directory, "fallback.conf")
	mustWriteFile(t, grandchild, `tier bestof
backend-server uri=ldap://fallback-one.example.com weight=2
`)
	mustWriteFile(t, child, `backend-server uri=ldap://primary-two.example.com
include "fallback.conf"
backend-server uri=ldap://fallback-two.example.com weight=3
`)
	mustWriteFile(t, root, `tier roundrobin
backend-server uri=ldap://primary-one.example.com
include backends.conf
backend-server uri=ldap://fallback-three.example.com weight=4
`)

	config, err := ParseFile(root)
	if err != nil {
		t.Fatalf("ParseFile(): %v", err)
	}
	if len(config.Tiers) != 2 {
		t.Fatalf("tiers = %#v", config.Tiers)
	}
	gotPrimary := backendURIs(config.Tiers[0].Backends)
	gotFallback := backendURIs(config.Tiers[1].Backends)
	if !reflect.DeepEqual(gotPrimary, []string{"ldap://primary-one.example.com", "ldap://primary-two.example.com"}) {
		t.Fatalf("primary backends = %#v", gotPrimary)
	}
	if !reflect.DeepEqual(gotFallback, []string{
		"ldap://fallback-one.example.com",
		"ldap://fallback-two.example.com",
		"ldap://fallback-three.example.com",
	}) {
		t.Fatalf("fallback backends = %#v", gotFallback)
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "unknown directive", input: "database mdb\n", want: "unknown directive"},
		{name: "unterminated quote", input: "listen \"ldap:///\n", want: "unterminated double quote"},
		{name: "unterminated continuation", input: "tier roundrobin \\", want: "unterminated continuation"},
		{name: "duplicate singleton", input: "iotimeout 1\niotimeout 2\n", want: "already set"},
		{name: "duration suffix", input: "iotimeout 1s\n", want: "source units"},
		{name: "duration overflow", input: "iotimeout 9223372036854775807\n", want: "overflows"},
		{name: "negative io timeout", input: "iotimeout -1\n", want: "non-negative"},
		{name: "limit sign", input: "client_max_pending +1\n", want: "unsigned decimal"},
		{name: "limit overflow", input: "client_max_pending 18446744073709551616\n", want: "out of range"},
		{name: "invalid listener", input: "listen http://localhost\n", want: "unsupported"},
		{name: "duplicate listener", input: "listen ldap:/// ldap:///\n", want: "duplicate listener"},
		{name: "backend before tier", input: "backend-server uri=ldap://one.example\n", want: "preceding tier"},
		{name: "unknown tier", input: "tier random\n", want: "unknown tier policy"},
		{name: "missing URI", input: "tier weighted\nbackend-server weight=1\n", want: "missing uri"},
		{name: "backend URL host", input: "tier weighted\nbackend-server uri=ldap:///\n", want: "missing a hostname"},
		{name: "backend URL path", input: "tier weighted\nbackend-server uri=ldap://host/dc=example\n", want: "DN/path"},
		{name: "backend URL userinfo", input: "tier weighted\nbackend-server uri=ldap://user@host\n", want: "userinfo"},
		{name: "backend URL query", input: "tier weighted\nbackend-server uri=ldap://host/?scope=base\n", want: "query"},
		{name: "backend URL port", input: "tier weighted\nbackend-server uri=ldap://host:bad\n", want: "invalid port"},
		{name: "zero numconns", input: "tier weighted\nbackend-server uri=ldap://host numconns=0\n", want: "positive"},
		{name: "negative retry", input: "tier weighted\nbackend-server uri=ldap://host retry=-1\n", want: "non-negative"},
		{name: "unknown backend parameter", input: "tier weighted\nbackend-server uri=ldap://host readonly=yes\n", want: "unknown backend"},
		{name: "duplicate backend parameter", input: "tier weighted\nbackend-server uri=ldap://one uri=ldap://two\n", want: "duplicate backend"},
		{name: "bad starttls", input: "tier weighted\nbackend-server uri=ldap://host starttls=required\n", want: "starttls policy"},
		{name: "bad feature", input: "feature magic\n", want: "unknown lloadd feature"},
		{name: "bad OID", input: "restrict_exop 1.03.6 reject\n", want: "invalid arc"},
		{name: "bad action", input: "restrict_exop 1.2 pin\n", want: "unknown restriction action"},
		{name: "duplicate restriction", input: "restrict_exop 1.2 reject\nrestrict_exop 1.2 write\n", want: "already restricted"},
		{name: "simple requirements", input: "bindconf bindmethod=simple binddn=cn=x\n", want: "requires binddn and credentials"},
		{name: "sasl requirements", input: "bindconf bindmethod=sasl\n", want: "requires saslmech"},
		{name: "bad keepalive", input: "bindconf keepalive=1:2\n", want: "idle:probes:interval"},
		{name: "bad TLS policy", input: "bindconf tls_reqcert=sometimes\n", want: "tls_reqcert"},
		{name: "unknown bind parameter", input: "bindconf password=secret\n", want: "unknown bindconf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseReader("test.conf", strings.NewReader(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseReader() error = %v, want substring %q", err, test.want)
			}
			if !strings.Contains(err.Error(), "test.conf") {
				t.Fatalf("error lacks source name: %v", err)
			}
		})
	}
}

func TestParseIncludeErrors(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	root := filepath.Join(directory, "lloadd.conf")
	mustWriteFile(t, root, "include missing.conf\n")
	if _, err := ParseFile(root); err == nil || !strings.Contains(err.Error(), "missing.conf") || !strings.Contains(err.Error(), ":1:") {
		t.Fatalf("missing include error = %v", err)
	}

	first := filepath.Join(directory, "first.conf")
	second := filepath.Join(directory, "second.conf")
	mustWriteFile(t, first, "include second.conf\n")
	mustWriteFile(t, second, "include first.conf\n")
	if _, err := ParseFile(first); err == nil || !strings.Contains(err.Error(), "include cycle") {
		t.Fatalf("include cycle error = %v", err)
	}
}

func TestRestrictionPriorities(t *testing.T) {
	t.Parallel()

	actions := []RestrictionAction{
		RestrictionActionIgnore,
		RestrictionActionWrite,
		RestrictionActionBackend,
		RestrictionActionConnection,
		RestrictionActionIsolate,
		RestrictionActionReject,
	}
	for index, action := range actions {
		if got := action.Priority(); got != index {
			t.Fatalf("%s.Priority() = %d, want %d", action, got, index)
		}
	}
}

func TestRuntimeConfigMapsServiceBindTimeout(t *testing.T) {
	config := DefaultConfig()
	config.BindConf = BindConfig{
		Method:      BindSimple,
		BindDN:      "cn=Manager,dc=example,dc=com",
		Credentials: "secret",
		Timeout:     2750 * time.Millisecond,
	}
	runtime, err := config.RuntimeConfig()
	if err != nil {
		t.Fatalf("RuntimeConfig(): %v", err)
	}
	if runtime.Bind.Timeout != config.BindConf.Timeout {
		t.Fatalf("Bind timeout = %s, want %s", runtime.Bind.Timeout, config.BindConf.Timeout)
	}
}

func TestParseLDAPIAddress(t *testing.T) {
	tests := map[string]string{
		"ldapi://%2Ftmp%2Fldap-go.sock/": "/tmp/ldap-go.sock",
		"ldapi:///tmp/ldap-go.sock":      "/tmp/ldap-go.sock",
		"ldapi://":                       "",
	}
	for raw, want := range tests {
		got, err := ParseLDAPIAddress(raw)
		if err != nil {
			t.Fatalf("ParseLDAPIAddress(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("ParseLDAPIAddress(%q) = %q, want %q", raw, got, want)
		}
	}
	for _, raw := range []string{
		"ldap:///tmp/ldap-go.sock",
		"ldapi://%2Ftmp%2Fldap.sock/dc=example",
		"ldapi://%zz",
	} {
		if _, err := ParseLDAPIAddress(raw); err == nil {
			t.Fatalf("ParseLDAPIAddress(%q) succeeded", raw)
		}
	}
}

func TestOpenLDAP2613LloadSourceContract(t *testing.T) {
	files := []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: "servers/lloadd/config.c",
			hash: OpenLDAPConfigSourceSHA256,
			anchors: []string{
				`timeout_write_tv = { 10, 0 }`,
				`int lload_write_coherence = 0;`,
				`{ "iotimeout", "ms timeout"`,
				`{ "client_max_pending", NULL`,
				`{ "write_coherence", "seconds"`,
				`{ "restrict_exop", "OID> <action"`,
				`{ "restrict_control", "OID> <action"`,
				`{ BER_BVC("network-timeout=")`,
				`{ BER_BVC("max-pending-ops=")`,
			},
		},
		{
			path: "servers/lloadd/daemon.c",
			hash: OpenLDAPDaemonSourceSHA256,
			anchors: []string{
				`if ( urls == NULL ) urls = "ldap:///";`,
			},
		},
		{
			path: "servers/lloadd/lload.h",
			hash: OpenLDAPHeaderSourceSHA256,
			anchors: []string{
				`#define LLOAD_SB_MAX_INCOMING_CLIENT ( ( 1 << 24 ) - 1 )`,
				`#define LLOAD_SB_MAX_INCOMING_UPSTREAM ( ( 1 << 24 ) - 1 )`,
				`#define LLOAD_CONN_MAX_PDUS_PER_CYCLE_DEFAULT 10`,
			},
		},
		{
			path: "servers/lloadd/backend.c",
			hash: OpenLDAPBackendSourceSHA256,
			anchors: []string{
				`b->b_numconns = 1;`,
				`b->b_numbindconns = 1;`,
				`b->b_weight = 1;`,
				`b->b_retry_timeout = 5000;`,
			},
		},
		{
			path: "servers/lloadd/tier.c",
			hash: OpenLDAPTiersSourceSHA256,
			anchors: []string{
				`{ "roundrobin", &roundrobin_tier }`,
				`{ "weighted", &weighted_tier }`,
				`{ "bestof", &bestof_tier }`,
			},
		},
	}

	for _, file := range files {
		contents, ok := pinnedOpenLDAPSource(t, file.path)
		if !ok {
			return
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != file.hash {
			t.Fatalf("OpenLDAP %s SHA-256 = %s, want %s", file.path, got, file.hash)
		}
		for _, anchor := range file.anchors {
			if !strings.Contains(string(contents), anchor) {
				t.Fatalf("OpenLDAP %s lacks source anchor %q", file.path, anchor)
			}
		}
	}
}

func pinnedOpenLDAPSource(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	if sourceRoot := os.Getenv("OPENLDAP_SOURCE"); sourceRoot != "" {
		if commit := os.Getenv("OPENLDAP_COMMIT"); commit != "" && commit != OpenLDAPSourceCommit {
			t.Fatalf("OPENLDAP_COMMIT = %q, want %q", commit, OpenLDAPSourceCommit)
		}
		contents, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", path, err)
		}
		return contents, true
	}

	reference := filepath.Clean(filepath.Join("..", "..", "..", "openldap-reference"))
	command := exec.Command("git", "-C", reference, "show", OpenLDAPSourceCommit+":"+path)
	contents, err := command.Output()
	if err != nil {
		t.Skipf("pinned OpenLDAP checkout unavailable: %v", err)
		return nil, false
	}
	return contents, true
}

func mustWriteFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func backendURIs(backends []BackendConfig) []string {
	result := make([]string, len(backends))
	for index, backend := range backends {
		result[index] = backend.URI
	}
	return result
}
