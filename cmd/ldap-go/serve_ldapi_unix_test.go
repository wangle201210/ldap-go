//go:build !windows

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestListenServeLDAPISecureLifecycle(t *testing.T) {
	path := filepath.Join(shortServeSocketDir(t), "ldap-go.sock")
	listener, uri, err := listenServeLDAPI(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	wantURI := "ldapi://" + url.PathEscape(path) + "/"
	if uri != wantURI || listener.Addr().Network() != "unix" ||
		listener.Addr().String() != path {
		listener.Close()
		t.Fatalf("LDAPI listener = %s, %s; want %s", listener.Addr(), uri, wantURI)
	}
	info, err := os.Lstat(path)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		listener.Close()
		t.Fatalf("LDAPI mode = %v", info.Mode())
	}

	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			err = connection.Close()
		}
		accepted <- err
	}()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-accepted; err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("LDAPI socket survived Close(): %v", err)
	}
}

func TestListenServeLDAPIRejectsUnsafePaths(t *testing.T) {
	if listener, _, err := listenServeLDAPI("relative.sock", 0o600); err == nil {
		listener.Close()
		t.Fatal("relative LDAPI path was accepted")
	}
	path := filepath.Join(shortServeSocketDir(t), "existing")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, _, err := listenServeLDAPI(path, 0o600); err == nil {
		listener.Close()
		t.Fatal("existing LDAPI path was replaced")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "do not replace" {
		t.Fatalf("existing path = %q, %v", contents, err)
	}
}

func TestServeMultiListenerAcceptsTCPAndLDAPI(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(shortServeSocketDir(t), "multi.sock")
	unixListener, _, err := listenServeLDAPI(path, 0o600)
	if err != nil {
		tcpListener.Close()
		t.Fatal(err)
	}
	listener := newServeListener([]net.Listener{tcpListener, unixListener})
	defer listener.Close()

	accepted := make(chan string, 2)
	for range 2 {
		go func() {
			connection, err := listener.Accept()
			if err != nil {
				accepted <- "error"
				return
			}
			accepted <- connection.LocalAddr().Network()
			_ = connection.Close()
		}()
	}
	tcpConnection, err := net.DialTimeout("tcp", tcpListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConnection.Close()
	unixConnection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unixConnection.Close()
	got := map[string]bool{<-accepted: true, <-accepted: true}
	if !got["tcp"] || !got["unix"] {
		t.Fatalf("accepted listener networks = %v", got)
	}
}

func TestRunServeAndBuiltInLDAPSearchOverLDAPI(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeLDAPIDatabase(t, databasePath)
	socketPath := filepath.Join(shortServeSocketDir(t), "ldap-go.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr lloaddReloadBuffer
	done := make(chan int, 1)
	go func() {
		done <- runWithContext(
			ctx,
			[]string{
				"serve",
				"-db", databasePath,
				"-listen", "127.0.0.1:0",
				"-ldapi", socketPath,
				"-ldapi-mode", "0600",
				"-root-dn", "cn=admin,dc=example,dc=com",
			},
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(name string) string {
				if name == rootPasswordEnvironment {
					return "secret"
				}
				return ""
			},
		)
	}()
	waitForServeLDAPISocket(t, socketPath, &stderr)

	uri := "ldapi://" + url.PathEscape(socketPath) + "/"
	var searchOut, searchErr bytes.Buffer
	exitCode := run(
		[]string{
			"ldapsearch",
			"-x",
			"-H", uri,
			"-D", "cn=admin,dc=example,dc=com",
			"-w", "secret",
			"-b", "dc=example,dc=com",
			"-s", "base",
			"(objectClass=*)",
			"dc",
		},
		strings.NewReader(""),
		&searchOut,
		&searchErr,
		func(string) string { return "" },
	)
	if exitCode != 0 || !strings.Contains(searchOut.String(), "dn: dc=example,dc=com") {
		t.Fatalf(
			"ldapsearch LDAPI exit=%d stdout=%q stderr=%q",
			exitCode,
			searchOut.String(),
			searchErr.String(),
		)
	}
	var whoOut, whoErr bytes.Buffer
	exitCode = run(
		[]string{
			"ldapwhoami",
			"-H", uri,
			"-Y", "PLAIN",
			"-U", "alice",
			"-w", "secret",
		},
		strings.NewReader(""),
		&whoOut,
		&whoErr,
		func(string) string { return "" },
	)
	if exitCode != 0 || !strings.Contains(
		whoOut.String(),
		"dn:uid=alice,dc=example,dc=com",
	) {
		t.Fatalf(
			"ldapwhoami LDAPI PLAIN exit=%d stdout=%q stderr=%q",
			exitCode,
			whoOut.String(),
			whoErr.String(),
		)
	}
	whoOut.Reset()
	whoErr.Reset()
	exitCode = run(
		[]string{
			"ldapwhoami",
			"-H", uri,
			"-Y", "EXTERNAL",
		},
		strings.NewReader(""),
		&whoOut,
		&whoErr,
		func(string) string { return "" },
	)
	if exitCode != 0 || !strings.Contains(
		whoOut.String(),
		"dn:cn=admin,dc=example,dc=com",
	) {
		t.Fatalf(
			"ldapwhoami LDAPI EXTERNAL exit=%d stdout=%q stderr=%q",
			exitCode,
			whoOut.String(),
			whoErr.String(),
		)
	}

	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("serve LDAPI exit=%d stderr=%s", exitCode, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve LDAPI did not stop")
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("serve LDAPI socket survived shutdown: %v", err)
	}
}

func TestRunServeLDAPIOnly(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeLDAPIDatabase(t, databasePath)
	socketPath := filepath.Join(shortServeSocketDir(t), "only.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr lloaddReloadBuffer
	done := make(chan int, 1)
	go func() {
		done <- runWithContext(
			ctx,
			[]string{
				"serve",
				"-db", databasePath,
				"-listen", "",
				"-ldapi", socketPath,
				"-root-dn", "cn=admin,dc=example,dc=com",
			},
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(name string) string {
				if name == rootPasswordEnvironment {
					return "secret"
				}
				return ""
			},
		)
	}()
	waitForServeLDAPISocket(t, socketPath, &stderr)
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode().Perm() != 0o660 {
		cancel()
		<-done
		t.Fatalf("LDAPI-only default socket mode = %v, %v", info, err)
	}
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(stdout.String(), "ldap-go listening on ldapi://") {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("LDAPI-only listener output was not published: %q", stdout.String())
		}
		time.Sleep(time.Millisecond)
	}
	if strings.Contains(stdout.String(), "ldap://127.") ||
		!strings.Contains(stdout.String(), "ldap-go listening on ldapi://") {
		cancel()
		<-done
		t.Fatalf("LDAPI-only listeners = %q", stdout.String())
	}
	connection, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	_ = connection.Close()
	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("LDAPI-only serve exit=%d stderr=%s", exitCode, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LDAPI-only serve did not stop")
	}
}

func TestOpenLDAPClientSearchesLDAPGoLDAPI(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") != "1" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP LDAPI client test")
	}
	ldapsearch, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatal("OpenLDAP ldapsearch is not available in PATH")
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedServeLDAPIEntries(t, store)
	path := filepath.Join(shortServeSocketDir(t), "native.sock")
	listener, uri, err := listenServeLDAPI(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := server.New(server.Config{
		Store:        store,
		ListenerURLs: []string{uri},
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	defer func() {
		cancel()
		<-done
	}()

	command := exec.Command(
		ldapsearch,
		"-x",
		"-H", uri,
		"-D", "cn=admin,dc=example,dc=com",
		"-w", "secret",
		"-b", "dc=example,dc=com",
		"-s", "base",
		"(objectClass=*)",
		"dc",
	)
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("dn: dc=example,dc=com")) {
		t.Fatalf("OpenLDAP ldapsearch LDAPI: %v\n%s", err, output)
	}
	ldapwhoami, err := exec.LookPath("ldapwhoami")
	if err != nil {
		t.Fatal("OpenLDAP ldapwhoami is not available in PATH")
	}
	command = exec.Command(ldapwhoami, "-Y", "EXTERNAL", "-H", uri)
	output, err = command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("dn:cn=admin,dc=example,dc=com")) {
		t.Fatalf("OpenLDAP ldapwhoami LDAPI EXTERNAL: %v\n%s", err, output)
	}
}

func TestServeLDAPIFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"serve", "-listen", ""},
		{"serve", "-ldapi-mode", "0600"},
		{"serve", "-ldapi", "/tmp/test.sock", "-ldapi-mode", "01000"},
		{"serve", "-ldapi", "/tmp/test.sock", "-ldaps"},
		{"serve", "-ldapi", "/tmp/test.sock", "-tlcp-implicit"},
	} {
		var stdout, stderr bytes.Buffer
		exitCode := run(
			args,
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(string) string { return "" },
		)
		if exitCode != 1 || stdout.Len() != 0 {
			t.Fatalf("serve LDAPI validation %q: exit=%d stdout=%q stderr=%q", args, exitCode, stdout.String(), stderr.String())
		}
	}
}

func TestLDAPClientLDAPIURIValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.sock")
	for _, uri := range []string{
		"ldapi://" + url.PathEscape(path) + "/",
		"ldapi://" + path,
	} {
		flags := flag.NewFlagSet("ldapi-client", flag.ContinueOnError)
		var options ldapClientOptions
		options.register(flags)
		if err := flags.Parse([]string{"-H", uri}); err != nil {
			t.Fatal(err)
		}
		parsed, dialURI, _, err := options.connectionConfiguration(flags)
		if err != nil || parsed.Scheme != "ldapi" || parsed.Path != path || dialURI != uri {
			t.Fatalf("LDAPI config(%q) = %#v, %q, %v", uri, parsed, dialURI, err)
		}
	}
	for _, args := range [][]string{
		{"-H", "ldapi://%ZZ"},
		{"-H", "ldapi://" + url.PathEscape(path) + "/", "-ZZ"},
		{"-H", "ldapi://" + url.PathEscape(path) + "/", "-tls-ca", "ca.pem"},
	} {
		flags := flag.NewFlagSet("invalid-ldapi-client", flag.ContinueOnError)
		var options ldapClientOptions
		options.register(flags)
		if err := flags.Parse(args); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := options.connectionConfiguration(flags); err == nil {
			t.Fatalf("invalid LDAPI client options were accepted: %q", args)
		}
	}
}

func waitForServeLDAPISocket(
	t *testing.T,
	path string,
	stderr interface{ String() string },
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout("unix", path, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve LDAPI socket did not start: %v; stderr=%s", err, stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func seedServeLDAPIDatabase(t *testing.T, path string) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	seedServeLDAPIEntries(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func seedServeLDAPIEntries(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcAuthzRegexp",
					Values: [][]byte{
						[]byte(`{0}^uid=([^,]+),cn=plain,cn=auth$ uid=$1,dc=example,dc=com`),
						[]byte(fmt.Sprintf(
							`{1}^gidNumber=%d\+uidNumber=%d,cn=peercred,cn=external,cn=auth$ cn=admin,dc=example,dc=com`,
							os.Getegid(),
							os.Geteuid(),
						)),
					},
				}},
			},
			{
				DN: "dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("domain")}},
					{Description: "dc", Values: [][]byte{[]byte("example")}},
				},
			},
			{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
					{Description: "uid", Values: [][]byte{[]byte("alice")}},
					{Description: "cn", Values: [][]byte{[]byte("Alice")}},
					{Description: "sn", Values: [][]byte{[]byte("Alice")}},
					{Description: "userPassword", Values: [][]byte{[]byte("secret")}},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: [][]byte{[]byte("{1}mdb")}},
					{Description: "olcSuffix", Values: [][]byte{[]byte("dc=example,dc=com")}},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatal(err)
	}
}

func shortServeSocketDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "ldap-go-ldapi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
