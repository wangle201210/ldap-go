package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func inputFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "slapd.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const twoDatabases = `database config
rootdn cn=config
rootpw "config secret"
database mdb
suffix dc=first
rootdn cn=admin,dc=first
rootpw "first secret"
directory /unused/first
access to * by * none
database mdb
suffix dc=second
rootdn cn=admin,dc=second
rootpw "second secret"
directory /unused/second
access to * by * none
`

func TestCommandOutputAndNoClobber(t *testing.T) {
	input := inputFile(t, twoDatabases)
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"-f", input}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "olcRootPW: first secret") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", &stdout, &stderr)
	}
	for _, flag := range []string{"-out", "-db"} {
		t.Run(flag, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			if err := run(t.Context(), []string{"-f", input, flag, output}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(output)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("permissions = %v", info.Mode())
			}
			if err := run(t.Context(), []string{"-f", input, flag, output}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("overwrote existing output")
			}
			after, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("existing output changed")
			}
		})
	}
}

func TestCommandFailureHasNoOutput(t *testing.T) {
	input := inputFile(t, twoDatabases+"unknown-security-directive allow\n")
	output := filepath.Join(t.TempDir(), "output")
	for _, extra := range [][]string{nil, {"-out", output}, {"-db", output}} {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), append([]string{"-f", input}, extra...), &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), input+":") {
			t.Fatalf("error = %v", err)
		}
		if stdout.Len() != 0 {
			t.Fatal("partial stdout on failure")
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output exists: %v", err)
		}
	}
}

func TestCommandFlagsCheckAndCancellation(t *testing.T) {
	input := inputFile(t, twoDatabases)
	for _, args := range [][]string{nil, {"-f", input, "unexpected"}, {"-f", input, "-out", "x", "-db", "y"}, {"-f", input, "-check", "-out", "x"}} {
		if err := run(t.Context(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"-f", input, "-check"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || stderr.String() != "configuration OK\n" {
		t.Fatalf("check output %q %q", &stdout, &stderr)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx, []string{"-f", input}, &stdout, &stderr); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
}

func TestGeneratedDatabaseServesScopedCredentials(t *testing.T) {
	input := inputFile(t, twoDatabases)
	output := filepath.Join(t.TempDir(), "ldap-go.db")
	if err := run(t.Context(), []string{"-f", input, "-db", output}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenBolt(output)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	instance, err := server.New(server.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	defer func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}()
	client, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetTimeout(5 * time.Second)
	for _, credential := range []struct{ dn, password string }{
		{"cn=config", "config secret"}, {"cn=admin,dc=first", "first secret"}, {"cn=admin,dc=second", "second secret"},
	} {
		if err := client.Bind(credential.dn, credential.password); err != nil {
			t.Fatalf("bind %s: %v", credential.dn, err)
		}
	}
	if err := client.Bind("cn=admin,dc=second", "first secret"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("cross-database password accepted: %v", err)
	}
}
