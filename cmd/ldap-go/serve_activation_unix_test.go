//go:build !windows

package main

import (
	"bytes"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const systemdActivationChildEnvironment = "LDAP_GO_TEST_SYSTEMD_ACTIVATION_CHILD"

func TestServeSystemdSocketActivation(t *testing.T) {
	if os.Getenv(systemdActivationChildEnvironment) == "1" {
		if err := os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid())); err != nil {
			t.Fatal(err)
		}
		exitCode := runMain(
			[]string{
				"serve",
				"-systemd-activation",
				"-db", os.Getenv(serveSIGHUPDBEnvironment),
				"-root-dn", "cn=admin,dc=example,dc=com",
			},
			os.Stdin,
			os.Stdout,
			os.Stderr,
			os.Getenv,
		)
		if exitCode != 0 {
			t.Fatalf("systemd activation child exit code = %d", exitCode)
		}
		return
	}

	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeLDAPIDatabase(t, databasePath)
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddress := tcpListener.Addr().String()
	socketPath := filepath.Join(shortServeSocketDir(t), "activated.sock")
	unixListenerRaw, _, err := listenServeLDAPI(socketPath, 0o600)
	if err != nil {
		tcpListener.Close()
		t.Fatal(err)
	}
	unixListener := unixListenerRaw.(*net.UnixListener)
	unixListener.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	tcpFile, err := tcpListener.(*net.TCPListener).File()
	if err != nil {
		tcpListener.Close()
		unixListener.Close()
		t.Fatal(err)
	}
	unixFile, err := unixListener.File()
	if err != nil {
		tcpFile.Close()
		tcpListener.Close()
		unixListener.Close()
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestServeSystemdSocketActivation$")
	command.ExtraFiles = []*os.File{tcpFile, unixFile}
	command.Env = append(
		os.Environ(),
		systemdActivationChildEnvironment+"=1",
		serveSIGHUPDBEnvironment+"="+databasePath,
		rootPasswordEnvironment+"=secret",
		"LISTEN_FDS=2",
		"LISTEN_FDNAMES=ldap:ldapi",
	)
	var stdout, stderr lloaddReloadBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		tcpFile.Close()
		unixFile.Close()
		tcpListener.Close()
		unixListener.Close()
		t.Fatal(err)
	}
	finished := false
	t.Cleanup(func() {
		if !finished && command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	_ = tcpFile.Close()
	_ = unixFile.Close()
	_ = tcpListener.Close()
	_ = unixListener.Close()

	waitForActivatedTCP(t, tcpAddress, &stderr)
	waitForServeLDAPISocket(t, socketPath, &stderr)
	for name, uri := range map[string]string{
		"TCP":   "ldap://" + tcpAddress,
		"LDAPI": "ldapi://" + url.PathEscape(socketPath) + "/",
	} {
		client, err := ldap.DialURL(uri)
		if err != nil {
			t.Fatalf("%s dial: %v", name, err)
		}
		if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
			client.Close()
			t.Fatalf("%s Bind: %v", name, err)
		}
		result, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		))
		client.Close()
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("%s Search = %#v, %v", name, result, err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(stdout.String(), "ldap-go listening on ldapi://") ||
		!strings.Contains(stdout.String(), "ldap-go listening on ldap://") {
		if time.Now().After(deadline) {
			t.Fatalf("activated listener output = %q", stdout.String())
		}
		time.Sleep(time.Millisecond)
	}

	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case err := <-waitDone:
		finished = true
		if err != nil {
			t.Fatalf("activated child exit: %v; stderr=%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("activated child did not stop; stderr=%s", stderr.String())
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("systemd-owned socket was removed: %v, %v", info, err)
	}
}

func TestSystemdActivationEnvironmentValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		values map[string]string
		want   string
	}{
		{name: "missing PID", values: map[string]string{"LISTEN_FDS": "1"}, want: "LISTEN_PID is required"},
		{name: "invalid PID", values: map[string]string{"LISTEN_PID": "pid", "LISTEN_FDS": "1"}, want: "LISTEN_PID must"},
		{name: "wrong PID", values: map[string]string{"LISTEN_PID": "1", "LISTEN_FDS": "1"}, want: "does not match"},
		{name: "missing FDS", values: map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid())}, want: "LISTEN_FDS is required"},
		{name: "zero FDS", values: map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "0"}, want: "between 1 and 1024"},
		{name: "name count", values: map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "2", "LISTEN_FDNAMES": "one"}, want: "contains 1 names"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := listenServeSystemd(func(name string) string {
				return test.values[name]
			}, "ldap")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("activation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSystemdTCPListenerScheme(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, fallback, want string
	}{
		{name: "ldap", fallback: "ldaps", want: "ldap"},
		{name: "ldaps", fallback: "ldap", want: "ldaps"},
		{name: "tlcp", fallback: "ldap", want: "ldap+tlcp"},
		{name: "ldap+tlcp", fallback: "ldap", want: "ldap+tlcp"},
		{name: "public", fallback: "ldaps", want: "ldaps"},
	} {
		if got := systemdTCPListenerScheme(test.name, test.fallback); got != test.want {
			t.Errorf("systemdTCPListenerScheme(%q, %q) = %q, want %q", test.name, test.fallback, got, test.want)
		}
	}
}

func TestServeSystemdActivationFlagConflicts(t *testing.T) {
	for _, conflict := range [][]string{
		{"-listen", "127.0.0.1:0"},
		{"-ldapi", "/tmp/ldap-go.sock"},
		{"-ldapi-mode", "0600"},
	} {
		args := append([]string{"serve", "-systemd-activation"}, conflict...)
		var stdout, stderr bytes.Buffer
		exitCode := run(args, strings.NewReader(""), &stdout, &stderr, func(string) string { return "" })
		if exitCode != 1 || !strings.Contains(stderr.String(), "cannot be combined") {
			t.Fatalf("activation conflict %q: exit=%d stderr=%q", conflict, exitCode, stderr.String())
		}
	}
}

func waitForActivatedTCP(t *testing.T, address string, stderr interface{ String() string }) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("activated TCP listener did not start: %v; stderr=%s", err, stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
