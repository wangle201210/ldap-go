//go:build unix

package slapdconf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseFIFOOpenDoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slapd.conf")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ParseFileContext(context.Background(), path, ParseOptions{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
}

func TestReadBoundedRejectsPostOpenSwapToFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slapd.conf")
	if err := os.WriteFile(path, []byte("database monitor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options, err := normalizedParseOptions(ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	parser := fileParser{ctx: context.Background(), options: options}
	parser.opener = func(candidate string) (*os.File, os.FileInfo, error) {
		file, info, err := openConfigurationFile(candidate)
		if err != nil {
			return nil, nil, err
		}
		if err := os.Rename(candidate, candidate+".opened"); err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		if err := unix.Mkfifo(candidate, 0o600); err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		return file, info, nil
	}
	if _, _, err := parser.readBounded(path); err == nil || !strings.Contains(err.Error(), "changed while it was opened") {
		t.Fatalf("swap error = %v", err)
	}
}
