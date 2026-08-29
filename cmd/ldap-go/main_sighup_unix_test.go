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

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	serveSIGHUPChildEnvironment = "LDAP_GO_TEST_SERVE_SIGHUP_CHILD"
	serveSIGHUPDBEnvironment    = "LDAP_GO_TEST_SERVE_SIGHUP_DB"
	serveGentleHUPEnvironment   = "LDAP_GO_TEST_SERVE_GENTLE_HUP_CHILD"
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

func TestServeGentleHUPPreservesExistingClient(t *testing.T) {
	if os.Getenv(serveGentleHUPEnvironment) == "1" {
		exitCode := runMain(
			[]string{
				"serve",
				"-db", os.Getenv(serveSIGHUPDBEnvironment),
				"-listen", "127.0.0.1:0",
				"-root-dn", "cn=admin,dc=example,dc=com",
				"-shutdown-timeout", "2s",
			},
			os.Stdin,
			os.Stdout,
			os.Stderr,
			os.Getenv,
		)
		if exitCode != 0 {
			t.Fatalf("gentle serve child exit code = %d", exitCode)
		}
		return
	}

	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeGentleHUPDatabase(t, databasePath)
	command := exec.Command(os.Args[0], "-test.run=^TestServeGentleHUPPreservesExistingClient$")
	command.Env = append(
		os.Environ(),
		serveGentleHUPEnvironment+"=1",
		serveSIGHUPDBEnvironment+"="+databasePath,
		rootPasswordEnvironment+"=secret",
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
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			const prefix = "ldap-go listening on ldap://"
			if strings.HasPrefix(scanner.Text(), prefix) {
				address <- strings.TrimPrefix(scanner.Text(), prefix)
				return
			}
		}
	}()
	var bound string
	select {
	case bound = <-address:
	case <-time.After(5 * time.Second):
		t.Fatalf("gentle serve child did not start; stderr=%s", stderr.String())
	}
	client, err := ldap.DialURL("ldap://" + bound)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind before gentle HUP: %v", err)
	}

	if err := command.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", bound, 50*time.Millisecond)
		if dialErr != nil {
			break
		}
		_ = connection.Close()
		if time.Now().After(deadline) {
			t.Fatal("gentle SIGHUP listener remained open")
		}
		time.Sleep(10 * time.Millisecond)
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
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search after gentle SIGHUP = %#v, %v; stderr=%s", result, err, stderr.String())
	}
	add := ldap.NewAddRequest("uid=blocked,ou=people,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"blocked"})
	add.Attribute("cn", []string{"Blocked User"})
	add.Attribute("sn", []string{"User"})
	if err := client.Add(add); !ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		t.Fatalf("Add after gentle SIGHUP = %v", err)
	}

	if err := command.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case err := <-waitDone:
		finished = true
		if err != nil {
			t.Fatalf("second SIGHUP exit = %v; stderr=%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("second SIGHUP did not stop gentle child; stderr=%s", stderr.String())
	}
}

func seedServeGentleHUPDatabase(t *testing.T, path string) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcGentleHUP",
					Values:      [][]byte{[]byte("TRUE")},
				}},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: [][]byte{[]byte("{1}mdb")}},
					{Description: "olcSuffix", Values: [][]byte{[]byte("dc=example,dc=com")}},
				},
			},
			{
				DN: "dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("domain")}},
					{Description: "dc", Values: [][]byte{[]byte("example")}},
				},
			},
			{
				DN: "ou=people,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("organizationalUnit")}},
					{Description: "ou", Values: [][]byte{[]byte("people")}},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	instance, err := server.New(server.Config{
		Store:        store,
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if !instance.GentleHUPEnabled() {
		_ = store.Close()
		t.Fatal("seeded bbolt configuration did not enable olcGentleHUP")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
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
				"close_listeners( 1 )",
				"frontendDB->be_restrictops |= SLAP_RESTRICT_OP_WRITES",
				"slapd_shutdown = 1",
			},
		}[name] {
			if !strings.Contains(source, fragment) {
				t.Fatalf("OpenLDAP SIGHUP %s source is missing %q", name, fragment)
			}
		}
	}
}
