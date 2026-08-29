package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestAcquireServePIDFileRequiresAbsolutePath(t *testing.T) {
	for _, path := range []string{"", "ldap-go.pid", filepath.Join("run", "ldap-go.pid")} {
		if pidfile, err := acquireServePIDFile(path); err == nil {
			_ = pidfile.Close()
			t.Fatalf("acquireServePIDFile(%q) succeeded", path)
		}
	}
}

func TestServePIDFileLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap-go.pid")
	pidfile, err := acquireServePIDFile(path)
	if err != nil {
		t.Fatalf("acquire pidfile: %v", err)
	}

	want := fmt.Sprintf("%d\n", os.Getpid())
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	if string(content) != want {
		t.Fatalf("pidfile content = %q, want %q", content, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat pidfile: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("pidfile permissions = %04o, want 0600", got)
		}
	}

	if err := pidfile.Close(); err != nil {
		t.Fatalf("close pidfile: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pidfile after Close stat error = %v, want not exist", err)
	}
	if err := pidfile.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestAcquireServePIDFileRejectsExistingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap-go.pid")
	stale := []byte("999999999\n")
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatalf("write stale pidfile: %v", err)
	}

	pidfile, err := acquireServePIDFile(path)
	if err == nil {
		_ = pidfile.Close()
		t.Fatal("acquire existing pidfile succeeded")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("acquire error = %v, want os.ErrExist", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read stale pidfile: %v", readErr)
	}
	if string(content) != string(stale) {
		t.Fatalf("stale pidfile content = %q, want %q", content, stale)
	}
}

func TestAcquireServePIDFileRejectsExistingSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "ldap-go.pid")
	want := []byte("do not change\n")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	pidfile, err := acquireServePIDFile(path)
	if err == nil {
		_ = pidfile.Close()
		t.Fatal("acquire symlink pidfile succeeded")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("acquire symlink error = %v, want os.ErrExist", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read symlink target: %v", err)
	}
	if string(content) != string(want) {
		t.Fatalf("symlink target content = %q, want %q", content, want)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat symlink: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("existing path mode = %v, want symlink", info.Mode())
	}
}

func TestServePIDFileCloseKeepsChangedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap-go.pid")
	pidfile, err := acquireServePIDFile(path)
	if err != nil {
		t.Fatalf("acquire pidfile: %v", err)
	}
	want := fmt.Sprintf("%d\n", os.Getpid())
	changed := []byte(want)
	if changed[0] == '0' {
		changed[0] = '1'
	} else {
		changed[0] = '0'
	}
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatalf("change pidfile: %v", err)
	}

	if err := pidfile.Close(); err != nil {
		t.Fatalf("close pidfile: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("changed pidfile was removed: %v", err)
	}
	if string(content) != string(changed) {
		t.Fatalf("changed pidfile content = %q, want %q", content, changed)
	}
}

func TestServePIDFileCloseKeepsReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap-go.pid")
	pidfile, err := acquireServePIDFile(path)
	if err != nil {
		t.Fatalf("acquire pidfile: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove original pidfile: %v", err)
	}
	want := fmt.Sprintf("%d\n", os.Getpid())
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("write replacement pidfile: %v", err)
	}

	if err := pidfile.Close(); err != nil {
		t.Fatalf("close pidfile: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement pidfile was removed: %v", err)
	}
	if string(content) != want {
		t.Fatalf("replacement pidfile content = %q, want %q", content, want)
	}
}

func TestAcquireServePIDFileConcurrentSingleOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap-go.pid")
	const contenders = 64
	start := make(chan struct{})
	results := make(chan struct {
		pidfile *servePIDFile
		err     error
	}, contenders)
	var workers sync.WaitGroup
	workers.Add(contenders)
	for range contenders {
		go func() {
			defer workers.Done()
			<-start
			pidfile, err := acquireServePIDFile(path)
			results <- struct {
				pidfile *servePIDFile
				err     error
			}{pidfile: pidfile, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var owner *servePIDFile
	for result := range results {
		if result.err == nil {
			if owner != nil {
				_ = result.pidfile.Close()
				_ = owner.Close()
				t.Fatal("multiple concurrent pidfile owners succeeded")
			}
			owner = result.pidfile
			continue
		}
		if !errors.Is(result.err, os.ErrExist) {
			t.Fatalf("concurrent acquire error = %v, want os.ErrExist", result.err)
		}
	}
	if owner == nil {
		t.Fatal("no concurrent pidfile owner succeeded")
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
}

func TestServePIDFileConcurrentClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap-go.pid")
	pidfile, err := acquireServePIDFile(path)
	if err != nil {
		t.Fatalf("acquire pidfile: %v", err)
	}

	const closers = 32
	errs := make(chan error, closers)
	var workers sync.WaitGroup
	workers.Add(closers)
	for range closers {
		go func() {
			defer workers.Done()
			errs <- pidfile.Close()
		}()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Close: %v", err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pidfile after concurrent Close stat error = %v, want not exist", err)
	}
}
