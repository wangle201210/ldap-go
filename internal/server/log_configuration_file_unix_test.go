//go:build unix

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenLDAPLogFileRejectsFIFOAndDeviceWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, os.DevNull} {
		done := make(chan error, 1)
		go func() {
			file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{path: path}, nil)
			_ = file.close()
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("accepted special file %s", path)
			}
		case <-time.After(time.Second):
			t.Fatalf("opening %s blocked", path)
		}
	}
}
