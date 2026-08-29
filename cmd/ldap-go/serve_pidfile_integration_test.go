//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunServePIDFileLifecycleAndDuplicateProtection(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeLDAPIDatabase(t, databasePath)
	pidPath := filepath.Join(t.TempDir(), "ldap-go.pid")
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr lloaddReloadBuffer
	done := make(chan int, 1)
	go func() {
		done <- runWithContext(
			ctx,
			[]string{
				"serve",
				"-db", databasePath,
				"-listen", "127.0.0.1:0",
				"-pidfile", pidPath,
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
	deadline := time.Now().Add(5 * time.Second)
	wantPID := fmt.Sprintf("%d\n", os.Getpid())
	for {
		contents, err := os.ReadFile(pidPath)
		if err == nil && string(contents) == wantPID &&
			strings.Contains(stdout.String(), "ldap-go listening on ldap://") {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("serve pidfile did not become ready: %q, %v; stderr=%s", contents, err, stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	var duplicateOut, duplicateErr lloaddReloadBuffer
	exitCode := run(
		[]string{
			"serve",
			"-db", databasePath,
			"-listen", "127.0.0.1:0",
			"-pidfile", pidPath,
		},
		strings.NewReader(""),
		&duplicateOut,
		&duplicateErr,
		func(string) string { return "" },
	)
	if exitCode != 1 || !strings.Contains(duplicateErr.String(), "file exists") {
		cancel()
		<-done
		t.Fatalf("duplicate serve exit=%d stdout=%q stderr=%q", exitCode, duplicateOut.String(), duplicateErr.String())
	}
	contents, err := os.ReadFile(pidPath)
	if err != nil || string(contents) != wantPID {
		cancel()
		<-done
		t.Fatalf("duplicate changed pidfile = %q, %v", contents, err)
	}

	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("pidfile serve exit=%d stderr=%s", exitCode, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pidfile serve did not stop")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("pidfile survived serve shutdown: %v", err)
	}
}
