//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestLDAPPromptPasswordPTYBoundaries(t *testing.T) {
	t.Run("password is hidden", func(t *testing.T) {
		master, slave, err := pty.Open()
		if err != nil {
			t.Fatalf("open PTY: %v", err)
		}
		defer master.Close()
		defer slave.Close()

		type result struct {
			password []byte
			err      error
		}
		results := make(chan result, 1)
		var stderr bytes.Buffer
		go func() {
			password, err := readLDAPPromptPassword(slave, &stderr)
			results <- result{password: password, err: err}
		}()
		time.Sleep(100 * time.Millisecond)
		if _, err := master.Write([]byte("pty-secret\n")); err != nil {
			t.Fatalf("write PTY password: %v", err)
		}

		select {
		case got := <-results:
			defer clear(got.password)
			if got.err != nil || string(got.password) != "pty-secret" {
				t.Fatalf("PTY password = %q, %v", got.password, got.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("PTY password read timed out")
		}
		if stderr.String() != "\n" {
			t.Fatalf("PTY prompt newline = %q", stderr.String())
		}

		echoed, err := readAvailablePTYBytes(master, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("probe PTY echo: %v", err)
		}
		if len(echoed) != 0 {
			t.Fatalf("terminal echoed password bytes %q", echoed)
		}
	})

	t.Run("blank line", func(t *testing.T) {
		master, slave, err := pty.Open()
		if err != nil {
			t.Fatalf("open PTY: %v", err)
		}
		defer master.Close()
		defer slave.Close()
		results := make(chan error, 1)
		go func() {
			password, err := readLDAPPromptPassword(slave, io.Discard)
			clear(password)
			results <- err
		}()
		time.Sleep(100 * time.Millisecond)
		if _, err := master.Write([]byte("\n")); err != nil {
			t.Fatalf("write PTY input: %v", err)
		}
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("PTY accepted empty password input")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("PTY empty password read timed out")
		}
	})
}

func readAvailablePTYBytes(file *os.File, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil
		}
		milliseconds := int(remaining / time.Millisecond)
		if milliseconds < 1 {
			milliseconds = 1
		}
		poll := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if ready == 0 {
			return nil, nil
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return nil, nil
			}
			continue
		}
		buffer := make([]byte, 64)
		count, err := unix.Read(int(file.Fd()), buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EIO) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return bytes.Clone(buffer[:count]), nil
	}
}
