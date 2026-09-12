package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// LDAP_GO_LDAPURL_EXTERNAL=1 OPENLDAP_LDAPURL=/path/to/openldap/bin/ldapurl
// CGO_ENABLED=0 go test ./cmd/ldap-go -run '^TestLDAPURLToolExternal$' -timeout=60s
// No server is started. ldapurl has no version flag; identify the installation
// using its sibling ldapsearch, which must report OpenLDAP 2.6.13.
func TestLDAPURLToolExternal(t *testing.T) {
	if os.Getenv("LDAP_GO_LDAPURL_EXTERNAL") != "1" {
		t.Skip("set LDAP_GO_LDAPURL_EXTERNAL=1 for the OpenLDAP 2.6.13 differential")
	}
	binary := os.Getenv("OPENLDAP_LDAPURL")
	if binary == "" {
		var err error
		binary, err = exec.LookPath("ldapurl")
		if err != nil {
			t.Fatal(err)
		}
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	runExternal := func(t *testing.T, executable string, args ...string) (string, string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LDAPNOINIT=1")
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if ctx.Err() != nil {
			t.Fatalf("external command timed out: %s %q", executable, args)
		}
		code := 0
		if err != nil {
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() < 0 {
				t.Fatalf("external command failed: %v", err)
			}
			code = cmd.ProcessState.ExitCode()
		}
		return stdout.String(), stderr.String(), code
	}
	stdout, stderr, code := runExternal(t, filepath.Join(filepath.Dir(binary), "ldapsearch"), "-VV")
	if code != 0 || !strings.Contains(stdout+stderr, "OpenLDAP: ldapsearch 2.6.13") {
		t.Fatalf("requires OpenLDAP 2.6.13 beside %s: exit=%d stdout=%q stderr=%q", binary, code, stdout, stderr)
	}
	t.Logf("reference=%s; source=d172686d3d270bc961b78f3ff00d7019c8dfb094; cases=%d", binary, len(ldapURLToolCases()))
	for _, test := range ldapURLToolCases() {
		t.Run(test.name, func(t *testing.T) {
			externalOut, externalErr, externalCode := runExternal(t, binary, test.args...)
			// BSD getopt includes argv[0] in its diagnostics. Only normalize
			// that executable path; preserve all remaining bytes and exit status.
			externalErr = strings.Replace(externalErr, binary+": ", "ldapurl: ", 1)
			localOut, localErr, localCode := runLDAPClientCommand(append([]string{"ldapurl"}, test.args...), "")
			if localOut != externalOut || localErr != externalErr || localCode != externalCode {
				t.Fatalf("args=%q\nlocal    exit=%d stdout=%q stderr=%q\nexternal exit=%d stdout=%q stderr=%q", test.args, localCode, localOut, localErr, externalCode, externalOut, externalErr)
			}
		})
	}
}
