//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	serveSIGHUPChildEnvironment = "LDAP_GO_TEST_SERVE_SIGHUP_CHILD"
	serveSIGHUPDBEnvironment    = "LDAP_GO_TEST_SERVE_SIGHUP_DB"
)

func TestServeSIGHUPGracefulShutdown(t *testing.T) {
	if os.Getenv(serveSIGHUPChildEnvironment) == "1" {
		exitCode := runMain(
			[]string{
				"serve",
				"-db", os.Getenv(serveSIGHUPDBEnvironment),
				"-listen", "127.0.0.1:0",
				"-shutdown-timeout", "2s",
			},
			os.Stdin,
			os.Stdout,
			os.Stderr,
			os.Getenv,
		)
		if exitCode != 0 {
			t.Fatalf("serve child exit code = %d", exitCode)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestServeSIGHUPGracefulShutdown$")
	command.Env = append(
		os.Environ(),
		serveSIGHUPChildEnvironment+"=1",
		serveSIGHUPDBEnvironment+"="+filepath.Join(t.TempDir(), "directory.db"),
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	finished := false
	t.Cleanup(func() {
		if finished || command.Process == nil {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	address := make(chan string, 1)
	scanDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			const prefix = "ldap-go listening on ldap://"
			line := scanner.Text()
			if strings.HasPrefix(line, prefix) {
				address <- strings.TrimPrefix(line, prefix)
			}
		}
		scanDone <- scanner.Err()
	}()

	var bound string
	select {
	case bound = <-address:
	case err := <-scanDone:
		t.Fatalf("serve child exited before listening: %v; stderr=%s", err, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatalf("serve child did not start; stderr=%s", stderr.String())
	}
	connection, err := net.DialTimeout("tcp", bound, time.Second)
	if err != nil {
		t.Fatalf("dial serve child: %v", err)
	}
	_ = connection.Close()

	if err := command.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("signal serve child: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case err := <-waitDone:
		finished = true
		if err != nil {
			t.Fatalf("serve child SIGHUP exit: %v; stderr=%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("serve child did not drain after SIGHUP; stderr=%s", stderr.String())
	}
	if connection, err := net.DialTimeout("tcp", bound, 100*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("serve listener still accepted connections after SIGHUP")
	}
}

func TestOpenLDAPSlapdSIGHUPSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	mainSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "main.c"))
	if err != nil {
		t.Fatal(err)
	}
	daemonSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "daemon.c"))
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"registration": string(mainSource),
		"handler":      string(daemonSource),
	} {
		for _, fragment := range map[string][]string{
			"registration": {"SIGNAL( SIGHUP, slap_sig_shutdown )"},
			"handler": {
				"if (sig == SIGHUP && global_gentlehup",
				"slapd_shutdown = 1",
			},
		}[name] {
			if !strings.Contains(source, fragment) {
				t.Fatalf("OpenLDAP SIGHUP %s source is missing %q", name, fragment)
			}
		}
	}
}
