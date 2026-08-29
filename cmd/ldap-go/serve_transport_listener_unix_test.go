//go:build !windows

package main

import (
	"context"
	"crypto/tls"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestServePlainLDAPSAndLDAPITogether(t *testing.T) {
	plainAddress := reserveLloaddTLSAddress(t)
	secureAddress := reserveLloaddTLSAddress(t)
	socketPath := filepath.Join(shortServeSocketDir(t), "mixed.sock")
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeLDAPIDatabase(t, databasePath)
	tlsFiles := newLloaddTLSFiles(t)

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr lloaddReloadBuffer
	done := make(chan int, 1)
	finished := false
	go func() {
		done <- runWithContext(
			ctx,
			[]string{
				"serve",
				"-db", databasePath,
				"-listen", plainAddress,
				"-ldaps-listen", secureAddress,
				"-ldapi", socketPath,
				"-tls-cert", tlsFiles.certificate,
				"-tls-key", tlsFiles.key,
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
	t.Cleanup(func() {
		if finished {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("mixed-listener serve did not stop")
		}
	})

	waitForActivatedTCP(t, plainAddress, &stderr)
	waitForServeLDAPISocket(t, socketPath, &stderr)
	waitForServeLDAPS(t, secureAddress, tlsFiles.ca, &stderr)

	assertServeListenerBind(t, "ldap://"+plainAddress, nil)
	assertServeListenerBind(t, "ldaps://"+secureAddress, lloaddTLSClientConfig(t, tlsFiles.ca))
	assertServeListenerBind(
		t,
		"ldapi://"+url.PathEscape(socketPath)+"/",
		nil,
	)

	output := stdout.String()
	for _, expected := range []string{
		"ldap-go listening on ldap://" + plainAddress,
		"ldap-go listening on ldaps://" + secureAddress,
		"ldap-go listening on ldapi://" + url.PathEscape(socketPath) + "/",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("serve output lacks %q: %q", expected, output)
		}
	}

	cancel()
	select {
	case exitCode := <-done:
		finished = true
		if exitCode != 0 {
			t.Fatalf("serve exit=%d stderr=%q", exitCode, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("mixed-listener serve did not stop; stderr=%q", stderr.String())
	}
}

func waitForServeLDAPS(
	t *testing.T,
	address string,
	certificate []byte,
	stderr interface{ String() string },
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := ldap.DialURL(
			"ldaps://"+address,
			ldap.DialWithTLSConfig(lloaddTLSClientConfig(t, certificate)),
		)
		if err == nil {
			_ = connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("LDAPS listener did not start: %v; stderr=%s", err, stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertServeListenerBind(t *testing.T, uri string, tlsConfig *tls.Config) {
	t.Helper()
	options := []ldap.DialOpt(nil)
	if tlsConfig != nil {
		options = append(options, ldap.DialWithTLSConfig(tlsConfig))
	}
	connection, err := ldap.DialURL(uri, options...)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer connection.Close()
	if err := connection.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}
}
