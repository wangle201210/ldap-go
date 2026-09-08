package main

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Reference: OpenLDAP 2.6.13 d172686d3d270bc961b78f3ff00d7019c8dfb094,
// clients/tools/common.c, libraries/libldap/{init,url}.c. The historical common
// options are visible in 66af4cfd5d^:clients/tools/common.c, before ITS#8618.
// 2.6.13 rejects -h/-p on network tools; compare equivalent -H invocations and
// ldapurl serialization, not nonexistent 2.6.13 legacy network-tool behavior.
func TestLDAPClientHostPortExternal(t *testing.T) {
	if os.Getenv("LDAP_GO_HOST_PORT_EXTERNAL") != "1" {
		t.Skip("set LDAP_GO_HOST_PORT_EXTERNAL=1 for installed OpenLDAP 2.6.13 differentials")
	}
	search := os.Getenv("OPENLDAP_LDAPSEARCH")
	if search == "" {
		var err error
		search, err = exec.LookPath("ldapsearch")
		if err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Dir(search)
	runExternal := func(t *testing.T, command string, args []string, input string) (string, string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(bin, command), args...)
		cmd.Env = append(os.Environ(), "LDAPNOINIT=1", "LC_ALL=C")
		cmd.Stdin = strings.NewReader(input)
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if ctx.Err() != nil {
			t.Fatalf("external %s timed out", command)
		}
		code := 0
		if err != nil {
			if cmd.ProcessState == nil {
				t.Fatalf("external %s: %v", command, err)
			}
			code = cmd.ProcessState.ExitCode()
		}
		return stdout.String(), stderr.String(), code
	}

	for _, test := range ldapHostPortCommandCases() {
		stdout, stderr, code := runExternal(t, test.command, []string{"-VV"}, "")
		versionName := test.command
		if versionName == "ldapadd" {
			versionName = "ldapmodify"
		}
		if code != 0 || !strings.Contains(stdout+stderr, "OpenLDAP: "+versionName+" 2.6.13") {
			t.Fatalf("requires %s 2.6.13: exit=%d %s%s", test.command, code, stdout, stderr)
		}
		t.Run(test.command+" rejects removed flags", func(t *testing.T) {
			for _, args := range [][]string{{"-h", "localhost"}, {"-p", "389"}, {"-H", "ldap://localhost", "-h", "localhost"}} {
				stdout, stderr, code := runExternal(t, test.command, args, "")
				if code != 1 || stdout != "" || !strings.Contains(stderr, "unrecognized option "+args[len(args)-2]) {
					t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
			}
		})
		t.Run(test.command+" equivalent URI", func(t *testing.T) {
			var results [2]string
			for index := range results {
				// Each tool gets fresh data: writes must execute independently.
				uri := startLDAPClientToolServer(t, nil)
				passwordFile := filepath.Join(t.TempDir(), "password")
				if err := os.WriteFile(passwordFile, []byte(clientToolRootPassword), 0o600); err != nil {
					t.Fatal(err)
				}
				address := ldapHostPortArgs(t, uri)
				if index == 1 {
					address = []string{"-H", uri}
				}
				args := append(address, "-x", "-D", clientToolRootDN, "-y", passwordFile)
				args = append(args, test.args...)
				var stdout, stderr string
				var code int
				if index == 0 {
					stdout, stderr, code = runLDAPClientCommand(append([]string{test.command}, args...), test.input)
				} else {
					stdout, stderr, code = runExternal(t, test.command, args, test.input)
				}
				if code != test.code || stderr != "" || !strings.Contains(stdout, test.output) ||
					strings.Contains(stdout, clientToolRootPassword) || strings.Contains(stdout, "host-port-new-password") {
					t.Fatalf("external=%t exit=%d stdout=%q stderr=%q", index == 1, code, stdout, stderr)
				}
				results[index] = stdout
			}
			if test.command == "ldapsearch" || test.command == "ldapwhoami" || test.command == "ldapcompare" || test.command == "ldapexop" {
				if results[0] != results[1] {
					t.Fatalf("local=%q external=%q", results[0], results[1])
				}
			}
		})
	}

	t.Run("ldapurl host and port forms", func(t *testing.T) {
		for _, host := range []string{"localhost", "directory.example", "127.0.0.1", "::1", "2001:db8::1"} {
			for _, port := range []string{"0", "1", "389", "636", "65535", "+00389", " \t389", "-2", "65536", "389 ", "ldap", "0x185", "4294967685"} {
				local, err := ldapClientHostPortURI(host, repeatedStringFlag{port})
				stdout, stderr, code := runExternal(t, "ldapurl", []string{"-h", host, "-p", port}, "")
				if (err == nil) != (code == 0) {
					t.Fatalf("host=%q port=%q local=%q err=%v external=%d %q %q", host, port, local, err, code, stdout, stderr)
				}
				if err != nil {
					continue
				}
				parsed, err := url.Parse(strings.TrimSpace(stdout))
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Port() == "" {
					parsed.Host += ":389"
				}
				if local != parsed.String() {
					t.Fatalf("local=%q external=%q", local, parsed.String())
				}
			}
		}
		// Deliberate extension differences: bracketed IPv6 is accepted locally;
		// empty hosts, duplicate flags (including -p 0), and host lists fail closed.
		_, _, code := runExternal(t, "ldapurl", []string{"-h", "[::1]"}, "")
		local, err := ldapClientHostPortURI("[::1]", nil)
		if code == 0 || err != nil || local != "ldap://[::1]:389" {
			t.Fatalf("bracketed IPv6 local=%q err=%v external=%d", local, err, code)
		}
		// ldapurl uses -1 as its own unset sentinel; the network extension rejects
		// all negative ports instead of silently falling back to another endpoint.
		_, _, code = runExternal(t, "ldapurl", []string{"-h", "localhost", "-p", "-1"}, "")
		_, err = ldapClientHostPortURI("localhost", repeatedStringFlag{"-1"})
		if code != 0 || err == nil {
			t.Fatalf("negative sentinel: local error=%v external=%d", err, code)
		}
	})

	t.Run("StartTLS equivalent URI", func(t *testing.T) {
		tlsConfig, pem := newLDAPClientToolTLSConfig(t)
		secure := startLDAPClientToolServer(t, tlsConfig)
		cleartext := startLDAPClientToolServer(t, nil)
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, pem, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, uri := range []string{secure, cleartext} {
			for _, mode := range []string{"-Z", "-ZZ"} {
				args := append([]string{"ldapwhoami", "-x", mode}, ldapHostPortArgs(t, uri)...)
				if uri == secure {
					args = append(args, "-tls-ca", ca)
				}
				local, _, localCode := runLDAPClientCommand(args, "")
				external, stderr, externalCode := runExternal(t, "ldapwhoami", []string{
					"-x", mode, "-H", uri, "-o", "TLS_CACERT=" + ca, "-o", "TLS_REQCERT=demand",
				}, "")
				if (localCode == 0) != (externalCode == 0) || local != external {
					t.Fatalf("%s local=%d %q external=%d %q %q", mode, localCode, local, externalCode, external, stderr)
				}
			}
		}
	})
}
