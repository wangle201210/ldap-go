package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPClientSASLQuiet(t *testing.T) {
	uri := startLDAPClientToolSASLServer(t, nil)
	for _, mechanism := range []string{"PLAIN", "CRAM-MD5", "DIGEST-MD5", "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512"} {
		for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
			t.Run(command+"/"+mechanism, func(t *testing.T) {
				args := []string{command, "-H", uri, "-Q", "-Y", mechanism, "-U", "alice", "-w", "sasl-client-secret"}
				if mechanism == "DIGEST-MD5" {
					args = append(args, "-R", "example.com")
				}
				wantCode := 0
				switch command {
				case "ldapsearch":
					args = append(args, "-b", "uid=alice,"+clientToolPeopleDN, "-s", "base", "-LLL", "(objectClass=*)", "uid")
				case "ldapcompare":
					args = append(args, "uid=alice,"+clientToolPeopleDN, "uid:alice")
					wantCode = ldap.LDAPResultCompareTrue
				}
				var stdout, stderr bytes.Buffer
				input := &ldapHostPortUnreadInput{}
				code := run(args, input, &stdout, &stderr, func(string) string { return "" })
				if code != wantCode || stderr.Len() != 0 || stdout.Len() == 0 || input.reads != 0 || strings.Contains(stdout.String(), "sasl-client-secret") {
					t.Fatalf("code=%d stdout=%q stderr=%q stdin reads=%d", code, &stdout, &stderr, input.reads)
				}
			})
		}
	}
}

func TestLDAPClientSASLQuietValidation(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"-Q", "-x"}, "cannot be combined"},
		{[]string{"-x", "-Q"}, "cannot be combined"},
		{[]string{"-Q=false"}, "-Q=false"},
		{[]string{"-Q"}, "requires -Y"},
		{[]string{"-Q", "-Y", "PLAIN"}, "non-empty -U"},
		{[]string{"-Q", "-Y", "PLAIN", "-U", "alice"}, "requires one of"},
		{[]string{"-Q", "-I"}, "interactive mode is not implemented"},
	} {
		var stdout, stderr bytes.Buffer
		input := &ldapHostPortUnreadInput{}
		args := append([]string{"ldapwhoami", "-H", "ldap://127.0.0.1:1"}, test.args...)
		code := run(args, input, &stdout, &stderr, func(string) string { return "" })
		if code == 0 || input.reads != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q reads=%d", test.args, code, &stdout, &stderr, input.reads)
		}
	}
}

func TestLDAPClientSASLQuietExternal(t *testing.T) {
	files, serverTLS := newLDAPClientMutualTLSFiles(t)
	var binds atomic.Int32
	uri := startLDAPClientTLSWireFixture(t, serverTLS, uriListReviewHandler(&binds, ldapwire.ResultSuccess))
	args := []string{"ldapwhoami", "-H", uri, "-Q", "-Y", "EXTERNAL",
		"-tls-ca", files.ca, "-tls-cert", files.certificate, "-tls-key", files.key,
		"-tls-server-name", "localhost"}
	var stdout, stderr bytes.Buffer
	input := &ldapHostPortUnreadInput{}
	code := run(args, input, &stdout, &stderr, func(string) string { return "" })
	if code != 0 || stderr.Len() != 0 || input.reads != 0 || binds.Load() != 1 || stdout.String() != "dn:cn=review\n" {
		t.Fatalf("EXTERNAL code=%d out=%q err=%q reads=%d binds=%d", code, &stdout, &stderr, input.reads, binds.Load())
	}
}

func TestLDAPClientSASLQuietExplicitPromptAndFile(t *testing.T) {
	uri := startLDAPClientToolSASLServer(t, nil)
	args := []string{"ldapwhoami", "-H", uri, "-Q", "-Q", "-Y", "PLAIN", "-U", "alice"}
	out, diagnostics, code := runLDAPClientCommand(append(args, "-W"), "sasl-client-secret\n")
	if code != 0 || out != "dn:uid=alice,"+clientToolPeopleDN+"\n" || diagnostics != "Enter LDAP Password: " {
		t.Fatalf("explicit prompt code=%d out=%q err=%q", code, out, diagnostics)
	}
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("sasl-client-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	out, diagnostics, code = runLDAPClientCommand(append(args, "-y", path), "")
	if code != 0 || out != "dn:uid=alice,"+clientToolPeopleDN+"\n" || diagnostics != "" {
		t.Fatalf("password file code=%d out=%q err=%q", code, out, diagnostics)
	}
	_, diagnostics, code = runLDAPClientCommand([]string{"ldapadd", "-n", "-Q"}, "dn: ou=test,dc=example,dc=com\nobjectClass: organizationalUnit\nou: test\n\n")
	if code != 0 || diagnostics != "" {
		t.Fatalf("dry run code=%d err=%q", code, diagnostics)
	}
}

func TestLDAPClientSASLQuietOpenLDAP(t *testing.T) {
	if os.Getenv("LDAP_GO_SASL_QUIET_EXTERNAL") != "1" {
		t.Skip("set LDAP_GO_SASL_QUIET_EXTERNAL=1 for OpenLDAP 2.6.13 comparison")
	}
	tool := os.Getenv("OPENLDAP_LDAPWHOAMI")
	if tool == "" {
		var err error
		tool, err = exec.LookPath("ldapwhoami")
		if err != nil {
			t.Fatal(err)
		}
	}
	version, err := exec.Command(tool, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "OpenLDAP: ldapwhoami 2.6.13") {
		t.Fatalf("requires OpenLDAP 2.6.13: %s %v", version, err)
	}
	uri := startLDAPClientToolSASLServer(t, nil)
	password := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(password, []byte("sasl-client-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-H", uri, "-Q", "-Y", "PLAIN", "-U", "alice", "-y", password}
	out, diagnostics, code := runLDAPClientCommand(append([]string{"ldapwhoami"}, args...), "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, tool, append(args, "-O", "none")...)
	command.Env = append(os.Environ(), "LDAPNOINIT=1", "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("native -Q: %v %s", err, &stderr)
	}
	if code != 0 || out != stdout.String() || diagnostics != stderr.String() {
		t.Fatalf("local %d %q %q native %q %q", code, out, diagnostics, &stdout, &stderr)
	}
}
