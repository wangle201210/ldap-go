//go:build !windows

package main

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPrepareServeOnlineBackupDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareServeOnlineBackupDirectory(directory)
	if err != nil || prepared == "" {
		t.Fatalf("prepare backup directory = %q, %v", prepared, err)
	}
	if _, err := prepareServeOnlineBackupDirectory("relative"); err == nil {
		t.Fatal("relative online backup directory was accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareServeOnlineBackupDirectory(file); err == nil {
		t.Fatal("online backup file was accepted as a directory")
	}
	writable := t.TempDir()
	if err := os.Chmod(writable, 0o722); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareServeOnlineBackupDirectory(writable); err == nil {
		t.Fatal("world-writable online backup directory was accepted")
	}
}

func TestRunServeOnlineBackupCommand(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeLDAPIDatabase(t, databasePath)
	backupDirectory := t.TempDir()
	if err := os.Chmod(backupDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(shortServeSocketDir(t), "backup.sock")
	ctx, cancel := context.WithCancel(context.Background())
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
				"-online-backup-dir", backupDirectory,
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
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("online backup test server did not stop")
		}
	})
	waitForServeLDAPISocket(t, socketPath, &stderr)
	uri := "ldapi://" + url.PathEscape(socketPath) + "/"
	var backupOut, backupErr bytes.Buffer
	exitCode := run(
		[]string{
			"online-backup",
			"-x",
			"-H", uri,
			"-D", "cn=admin,dc=example,dc=com",
			"-w", "secret",
		},
		strings.NewReader(""),
		&backupOut,
		&backupErr,
		func(string) string { return "" },
	)
	if exitCode != 0 || !strings.HasPrefix(backupOut.String(), "backup ldap-go-") {
		t.Fatalf("online-backup exit=%d stdout=%q stderr=%q", exitCode, backupOut.String(), backupErr.String())
	}
	fields := strings.Fields(backupOut.String())
	if len(fields) < 2 {
		t.Fatalf("online-backup output = %q", backupOut.String())
	}
	filename := strings.TrimSuffix(fields[1], ":")
	if _, err := storage.CheckBolt(t.Context(), filepath.Join(backupDirectory, filename)); err != nil {
		t.Fatalf("online-backup output file: %v", err)
	}

	var remoteOut, remoteErr bytes.Buffer
	exitCode = run(
		[]string{"online-backup", "-x", "-H", "ldap://127.0.0.1:389"},
		strings.NewReader(""),
		&remoteOut,
		&remoteErr,
		func(string) string { return "" },
	)
	if exitCode != 1 || !strings.Contains(remoteErr.String(), "requires an ldapi:// URI") {
		t.Fatalf("remote online-backup exit=%d stderr=%q", exitCode, remoteErr.String())
	}
}
