package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	clientToolRootDN       = "cn=admin,dc=example,dc=com"
	clientToolRootPassword = "client-tool-secret"
	clientToolBaseDN       = "dc=example,dc=com"
	clientToolPeopleDN     = "ou=people,dc=example,dc=com"
)

func TestLDAPSearchAnonymousBindScopesPagingAndLDIF(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapsearch", "-H", uri, "-x", "-b", "", "-s", "base", "-LLL",
			"(objectClass=*)", "namingContexts",
		},
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("anonymous ldapsearch exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entries := parseLDAPSearchOutput(t, stdout)
	if len(entries) != 1 || entries[0].DN != "" ||
		entries[0].GetAttributeValue("namingContexts") != clientToolBaseDN {
		t.Fatalf("anonymous Root DSE entries = %#v", entries)
	}

	wantScopes := map[string][]string{
		"base": {clientToolPeopleDN},
		"one":  {"uid=alice," + clientToolPeopleDN, "uid=bob," + clientToolPeopleDN},
		"sub":  {clientToolPeopleDN, "uid=alice," + clientToolPeopleDN, "uid=bob," + clientToolPeopleDN},
	}
	for scope, want := range wantScopes {
		t.Run("scope "+scope, func(t *testing.T) {
			stdout, stderr, exitCode := runLDAPClientCommand(
				[]string{
					"ldapsearch", "-H", uri, "-x",
					"-D", clientToolRootDN, "-w", clientToolRootPassword,
					"-b", clientToolPeopleDN, "-s", scope, "-a", "never", "-LLL",
					"(objectClass=*)", "objectClass",
				},
				"",
			)
			if exitCode != 0 || stderr != "" {
				t.Fatalf("ldapsearch scope %s exit=%d stdout=%q stderr=%q", scope, exitCode, stdout, stderr)
			}
			entries := parseLDAPSearchOutput(t, stdout)
			got := make([]string, len(entries))
			for index := range entries {
				got[index] = entries[index].DN
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("scope %s DNs = %q, want %q", scope, got, want)
			}
		})
	}
	if scope, err := parseLDAPSearchScope("children"); err != nil || scope != ldap.ScopeChildren {
		t.Fatalf("parseLDAPSearchScope(children) = %d, %v", scope, err)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapsearch", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-b", clientToolPeopleDN, "-s", "one", "-E", "pr=1/noprompt", "-LLL",
			"(objectClass=inetOrgPerson)", "uid", "description", "jpegPhoto",
		},
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("paged ldapsearch exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entries = parseLDAPSearchOutput(t, stdout)
	if len(entries) != 2 {
		t.Fatalf("paged ldapsearch returned %d entries: %q", len(entries), stdout)
	}
	if !strings.Contains(stdout, "jpegPhoto:: "+base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10})) {
		t.Fatalf("binary jpegPhoto was not emitted as base64 LDIF: %q", stdout)
	}
	if !strings.Contains(stdout, "description:\n") {
		t.Fatalf("empty LDIF value was not preserved: %q", stdout)
	}
	if !strings.Contains(stdout, "\n ") {
		t.Fatalf("long LDIF value was not folded: %q", stdout)
	}
	for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
		if len(line) > ldapSearchLDIFLineWidth {
			t.Fatalf("LDIF line has %d bytes, want <= %d: %q", len(line), ldapSearchLDIFLineWidth, line)
		}
	}
	for _, entry := range entries {
		if entry.GetAttributeValue("uid") != "alice" {
			continue
		}
		if got := []byte(entry.GetAttributeValue("jpegPhoto")); !bytes.Equal(got, []byte{0x00, 0xff, 0x10}) {
			t.Fatalf("round-tripped jpegPhoto = %v", got)
		}
		values := entry.GetAttributeValues("description")
		if len(values) != 2 || values[0] != "" {
			t.Fatalf("round-tripped description values = %#v", values)
		}
	}
}

func TestLDAPWhoAmIAndBindPasswordSources(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapwhoami", "-H", uri, "-x"},
		"",
	)
	if exitCode != 0 || stdout != "anonymous\n" || stderr != "" {
		t.Fatalf("anonymous ldapwhoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, value := range []string{"1", "none", "max"} {
		stdout, stderr, exitCode = runLDAPClientCommand(
			[]string{
				"ldapwhoami", "-H", uri, "-x", "-o", "nettimeout=" + value,
			},
			"",
		)
		if exitCode != 0 || stdout != "anonymous\n" || stderr != "" {
			t.Fatalf(
				"ldapwhoami -o nettimeout=%s exit=%d stdout=%q stderr=%q",
				value, exitCode, stdout, stderr,
			)
		}
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:"+clientToolRootDN+"\n" || stderr != "" {
		t.Fatalf("bound ldapwhoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-x",
			"-D", clientToolRootDN, "-W",
		},
		clientToolRootPassword+"\r\n",
	)
	if exitCode != 0 || stdout != "dn:"+clientToolRootDN+"\n" ||
		stderr != "Enter LDAP Password: " {
		t.Fatalf("prompted ldapwhoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	passwordPath := filepath.Join(t.TempDir(), "bind-password")
	if err := os.WriteFile(passwordPath, []byte(clientToolRootPassword), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-x",
			"-D", clientToolRootDN, "-y", passwordPath,
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:"+clientToolRootDN+"\n" || stderr != "" {
		t.Fatalf("file-password ldapwhoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	if err := os.WriteFile(passwordPath, []byte(clientToolRootPassword+"\n"), 0o600); err != nil {
		t.Fatalf("rewrite password file: %v", err)
	}
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-x",
			"-D", clientToolRootDN, "-y", passwordPath,
		},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "Invalid Credentials") {
		t.Fatalf("newline password file exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	secret := "incorrect-password-must-not-leak"
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", secret,
		},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "Invalid Credentials") ||
		strings.Contains(stderr, secret) {
		t.Fatalf("bad-password ldapwhoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPPromptPasswordInputBoundaries(t *testing.T) {
	for _, input := range []string{"", "\n", "\r\n"} {
		var stderr bytes.Buffer
		password, err := readLDAPPromptPassword(strings.NewReader(input), &stderr)
		clear(password)
		if err == nil {
			t.Fatalf("readLDAPPromptPassword(%q) accepted empty input", input)
		}
		if stderr.Len() != 0 {
			t.Fatalf("non-TTY password input wrote stderr %q", stderr.String())
		}
	}

	reader := strings.NewReader("first-secret\r\nnext input\n")
	password, err := readLDAPPromptPassword(reader, io.Discard)
	if err != nil {
		t.Fatalf("read first password line: %v", err)
	}
	if string(password) != "first-secret" {
		clear(password)
		t.Fatalf("password = %q", password)
	}
	clear(password)
	remainder, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read remaining input: %v", err)
	}
	if string(remainder) != "next input\n" {
		t.Fatalf("password prompt consumed later input: %q", remainder)
	}

	password, err = readLDAPPromptPassword(strings.NewReader("without-newline"), io.Discard)
	if err != nil || string(password) != "without-newline" {
		clear(password)
		t.Fatalf("EOF-terminated password = %q, %v", password, err)
	}
	clear(password)

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", "ldap://127.0.0.1:1", "-x",
			"-D", clientToolRootDN, "-W",
		},
		"",
	)
	if exitCode != 1 || stdout != "" ||
		!strings.Contains(stderr, "password input ended before a password was read") {
		t.Fatalf("empty -W exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPPasswordFilePermissionsWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix password file mode warnings are unavailable on Windows")
	}
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("raw-password\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod password file: %v", err)
	}
	var stderr bytes.Buffer
	password, err := readLDAPPasswordFile(path, &stderr)
	if err != nil {
		t.Fatalf("read wide password file: %v", err)
	}
	if string(password) != "raw-password\n" {
		clear(password)
		t.Fatalf("password file bytes = %q", password)
	}
	clear(password)
	wantWarning := "Warning: Password file " + path + " is publicly readable/writeable\n"
	if stderr.String() != wantWarning {
		t.Fatalf("password file warning = %q, want %q", stderr.String(), wantWarning)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod group-readable password file: %v", err)
	}
	stderr.Reset()
	password, err = readLDAPPasswordFile(path, &stderr)
	clear(password)
	if err != nil || stderr.Len() != 0 {
		t.Fatalf("group-only password mode err=%v stderr=%q", err, stderr.String())
	}
}

func TestLDAPClientPasswordFileLimitAndConflicts(t *testing.T) {
	oversizedPath := filepath.Join(t.TempDir(), "oversized-password")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte{'x'}, maxPasswordInputSize+1), 0o600); err != nil {
		t.Fatalf("write oversized password file: %v", err)
	}
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", "ldap://127.0.0.1:1", "-x",
			"-D", clientToolRootDN, "-y", oversizedPath,
		},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "exceeds 1048576 bytes") {
		t.Fatalf("oversized password exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{name: "SASL default", args: []string{"ldapwhoami"}, message: "requires -Y"},
		{name: "SASL mechanism", args: []string{"ldapwhoami", "-x", "-Y", "PLAIN"}, message: "cannot be combined"},
		{name: "bind without password", args: []string{"ldapwhoami", "-x", "-D", clientToolRootDN}, message: "requires one of -w, -W, or -y"},
		{name: "password without bind", args: []string{"ldapwhoami", "-x", "-w", "hidden"}, message: "requires a non-empty -D"},
		{name: "password sources", args: []string{"ldapwhoami", "-x", "-D", clientToolRootDN, "-w", "hidden", "-W"}, message: "mutually exclusive"},
		{name: "StartTLS modes", args: []string{"ldapwhoami", "-x", "-Z", "-ZZ"}, message: "mutually exclusive"},
		{name: "TLS options on LDAP", args: []string{"ldapwhoami", "-x", "-tls-server-name", "localhost"}, message: "TLS options require"},
		{name: "LDAPS StartTLS", args: []string{"ldapwhoami", "-H", "ldaps://localhost", "-x", "-ZZ"}, message: "cannot be used with an ldaps://"},
		{name: "URI userinfo", args: []string{"ldapwhoami", "-H", "ldap://user:secret@localhost", "-x"}, message: "userinfo is not supported"},
		{name: "whoami arguments", args: []string{"ldapwhoami", "-x", "extra"}, message: "unexpected arguments"},
		{name: "scope", args: []string{"ldapsearch", "-x", "-s", "invalid"}, message: "-s must be"},
		{name: "deref", args: []string{"ldapsearch", "-x", "-a", "invalid"}, message: "-a must be"},
		{name: "negative size", args: []string{"ldapsearch", "-x", "-z", "-1"}, message: "-z must be non-negative"},
		{name: "invalid sort extension", args: []string{"ldapsearch", "-x", "-E", "sss="}, message: "invalid server-side sorting extension"},
		{name: "VLV without sort", args: []string{"ldapsearch", "-x", "-E", "vlv=0/1/1/10"}, message: "requires server-side sorting"},
		{name: "VLV with paging", args: []string{"ldapsearch", "-x", "-E", "sss=cn", "-E", "vlv=0/1/1/10", "-E", "pr=2"}, message: "mutually exclusive"},
		{name: "invalid subentries extension", args: []string{"ldapsearch", "-x", "-E", "subentries=maybe"}, message: "invalid subentries extension value"},
		{name: "invalid deref extension", args: []string{"ldapsearch", "-x", "-E", "deref=seeAlso:"}, message: "invalid deref specification"},
		{name: "noncritical dontUseCopy", args: []string{"ldapsearch", "-x", "-E", "dontUseCopy"}, message: "requires the critical"},
		{name: "unsupported sync response limit", args: []string{"ldapsearch", "-x", "-E", "sync=rp//10"}, message: "response limits are not implemented"},
		{name: "critical paging size", args: []string{"ldapsearch", "-x", "-E", "!pr=0"}, message: "invalid paging size"},
		{name: "interactive paging mode", args: []string{"ldapsearch", "-x", "-E", "pr=2/ask"}, message: "invalid paging prompt mode"},
		{name: "paging conflict", args: []string{"ldapsearch", "-x", "-page-size", "2", "-E", "pr=2"}, message: "mutually exclusive"},
		{name: "unsupported LDAP option", args: []string{"ldapsearch", "-x", "-o", "unknown=1"}, message: "invalid general option name"},
		{name: "missing network timeout", args: []string{"ldapsearch", "-x", "-o", "nettimeout"}, message: "option value expected"},
		{name: "negative network timeout", args: []string{"ldapsearch", "-x", "-o", "nettimeout=-1"}, message: "invalid network timeout"},
		{name: "duplicate network timeout", args: []string{"ldapsearch", "-x", "-o", "nettimeout=1", "-o", "nettimeout=2"}, message: "previously specified"},
		{name: "network timeout conflict", args: []string{"ldapsearch", "-x", "-o", "nettimeout=1", "-timeout", "1s"}, message: "cannot be combined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exitCode := runLDAPClientCommand(test.args, "")
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf("run(%v) exit=%d stdout=%q stderr=%q", test.args, exitCode, stdout, stderr)
			}
			if strings.Contains(stdout, "hidden") || strings.Contains(stderr, "hidden") ||
				strings.Contains(stdout, "secret@") || strings.Contains(stderr, "secret@") {
				t.Fatalf("run(%v) exposed a secret: stdout=%q stderr=%q", test.args, stdout, stderr)
			}
		})
	}
}

func TestLDAPClientStartTLSRequiredAndOptional(t *testing.T) {
	serverTLS, certificatePEM := newLDAPClientToolTLSConfig(t)
	secureURI := startLDAPClientToolServer(t, serverTLS)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", secureURI, "-x", "-ZZ",
			"-o", "nettimeout=none",
			"-tls-ca", caPath, "-tls-server-name", "localhost",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:"+clientToolRootDN+"\n" || stderr != "" {
		t.Fatalf("StartTLS ldapwhoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", secureURI, "-x", "-ZZ",
			"-tls-ca", caPath, "-tls-server-name", "wrong.example.test",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
		},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "certificate") {
		t.Fatalf("wrong-host StartTLS exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	cleartextURI := startLDAPClientToolServer(t, nil)
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapwhoami", "-H", cleartextURI, "-x", "-Z"},
		"",
	)
	if exitCode != 0 || stdout != "anonymous\n" || !strings.Contains(stderr, "continuing over cleartext LDAP") {
		t.Fatalf("optional StartTLS exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPSearchLDIFRendererTypesOnlyAndSafety(t *testing.T) {
	entry := &ldap.Entry{
		DN: "cn=\u6d4b\u8bd5,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			ldap.NewEntryAttribute("cn", []string{"secret value"}),
			ldap.NewEntryAttribute("description", []string{""}),
			{
				Name:       "jpegPhoto",
				Values:     []string{string([]byte{0x00, 0xff, 0x10})},
				ByteValues: [][]byte{{0x00, 0xff, 0x10}},
			},
		},
	}
	var output bytes.Buffer
	if err := writeLDAPSearchLDIF(&output, []*ldap.Entry{entry}, true, false); err != nil {
		t.Fatalf("writeLDAPSearchLDIF(types only): %v", err)
	}
	if strings.Contains(output.String(), "secret value") ||
		!strings.Contains(output.String(), "cn:\n") ||
		!strings.Contains(output.String(), "dn:: ") ||
		!strings.HasPrefix(output.String(), "version: 1\n\n") {
		t.Fatalf("types-only LDIF = %q", output.String())
	}
	parseLDAPSearchOutput(t, output.String())

	bad := &ldap.Entry{
		DN: "dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			ldap.NewEntryAttribute("cn\ninjected", []string{"value"}),
		},
	}
	if err := writeLDAPSearchLDIF(&bytes.Buffer{}, []*ldap.Entry{bad}, false, true); err == nil {
		t.Fatal("writeLDAPSearchLDIF accepted an unsafe attribute description")
	}
}

func TestUsageListsLDAPClientCommands(t *testing.T) {
	stdout, stderr, exitCode := runLDAPClientCommand([]string{"help"}, "")
	if exitCode != 0 || stderr != "" {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, command := range []string{"ldapsearch", "ldapwhoami"} {
		if !strings.Contains(stdout, command) {
			t.Errorf("help does not list %s: %q", command, stdout)
		}
	}
}

func startLDAPClientToolServer(t *testing.T, tlsConfig *tls.Config) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPClientToolDirectory(t, store)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := server.New(server.Config{
		Store:        store,
		RootDN:       clientToolRootDN,
		RootPassword: []byte(clientToolRootPassword),
		AccessPolicy: clientToolAccessPolicy(t),
		TLSConfig:    tlsConfig,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("server.New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("LDAP client tool test server did not stop")
		}
	})
	return "ldap://" + listener.Addr().String()
}

func clientToolAccessPolicy(t *testing.T) *acl.Policy {
	t.Helper()
	rawRules := []string{
		"{0}to attrs=userPassword by self write by anonymous auth by * none",
		"{1}to * by * read",
	}
	rules := make([]acl.Rule, len(rawRules))
	for index, raw := range rawRules {
		rule, err := acl.ParseRule(raw)
		if err != nil {
			t.Fatalf("parse LDAP client test ACL: %v", err)
		}
		rules[index] = rule
	}
	policy, err := acl.NewPolicy(rules, nil)
	if err != nil {
		t.Fatalf("create LDAP client test ACL: %v", err)
	}
	return policy
}

func seedLDAPClientToolDirectory(t *testing.T, store storage.Store) {
	t.Helper()
	longDescription := strings.Repeat("folded LDAP description ", 8)
	entries := []directory.Entry{
		{
			DN: clientToolBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: clientToolValues("domain")},
				{Description: "dc", Values: clientToolValues("example")},
			},
		},
		{
			DN: clientToolPeopleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: clientToolValues("organizationalUnit")},
				{Description: "ou", Values: clientToolValues("people")},
			},
		},
		{
			DN: "uid=alice," + clientToolPeopleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: clientToolValues("inetOrgPerson")},
				{Description: "uid", Values: clientToolValues("alice")},
				{Description: "cn", Values: clientToolValues("Alice Example")},
				{Description: "sn", Values: clientToolValues("Example")},
				{Description: "description", Values: [][]byte{{}, []byte(longDescription)}},
				{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
				{Description: "userPassword", Values: [][]byte{{0x00, 0xff, 0x10}}},
			},
		},
		{
			DN: "uid=bob," + clientToolPeopleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: clientToolValues("inetOrgPerson")},
				{Description: "uid", Values: clientToolValues("bob")},
				{Description: "cn", Values: clientToolValues("Bob Example")},
				{Description: "sn", Values: clientToolValues("Example")},
				{Description: "description", Values: clientToolValues("short")},
				{Description: "jpegPhoto", Values: [][]byte{{0x01, 0x02}}},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{clientToolBaseDN})
	}); err != nil {
		t.Fatalf("seed LDAP client tool directory: %v", err)
	}
}

func clientToolValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}

func newLDAPClientToolTLSConfig(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
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
		t.Fatalf("CreateCertificate(): %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER},
			PrivateKey:  privateKey,
		}},
		MinVersion: tls.VersionTLS12,
	}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}

func parseLDAPSearchOutput(t *testing.T, output string) []*ldap.Entry {
	t.Helper()
	document := &ldif.LDIF{}
	if err := ldif.Unmarshal(strings.NewReader(output), document); err != nil {
		t.Fatalf("parse ldapsearch LDIF: %v\n%s", err, output)
	}
	return document.AllEntries()
}

func runLDAPClientCommand(args []string, stdin string) (string, string, int) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		args,
		strings.NewReader(stdin),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	return stdout.String(), stderr.String(), exitCode
}
