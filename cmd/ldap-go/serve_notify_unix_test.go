//go:build !windows

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotifySystemdUnixDatagram(t *testing.T) {
	path := filepath.Join(shortServeSocketDir(t), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: path,
		Net:  "unixgram",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	configured, err := notifySystemd(func(name string) string {
		if name == "NOTIFY_SOCKET" {
			return path
		}
		return ""
	}, "READY=1\nSTATUS=ready")
	if err != nil || !configured {
		t.Fatalf("notifySystemd() = %t, %v", configured, err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	length, _, err := listener.ReadFromUnix(buffer)
	if err != nil || string(buffer[:length]) != "READY=1\nSTATUS=ready" {
		t.Fatalf("systemd notification = %q, %v", buffer[:length], err)
	}
	configured, err = notifySystemd(func(string) string { return "" }, "READY=1")
	if err != nil || configured {
		t.Fatalf("unconfigured notifySystemd() = %t, %v", configured, err)
	}
}

func TestRunServeSystemdReadyAndStoppingNotifications(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedServeLDAPIDatabase(t, databasePath)
	notifyPath := filepath.Join(shortServeSocketDir(t), "notify.sock")
	notifyListener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: notifyPath,
		Net:  "unixgram",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer notifyListener.Close()
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
				"-root-dn", "cn=admin,dc=example,dc=com",
			},
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(name string) string {
				switch name {
				case rootPasswordEnvironment:
					return "secret"
				case "NOTIFY_SOCKET":
					return notifyPath
				default:
					return ""
				}
			},
		)
	}()
	ready := readSystemdTestNotification(t, notifyListener)
	if ready != "READY=1\nSTATUS=ldap-go accepting connections" ||
		!strings.Contains(stdout.String(), "ldap-go listening on ldap://") {
		cancel()
		<-done
		t.Fatalf("READY=%q stdout=%q stderr=%q", ready, stdout.String(), stderr.String())
	}
	cancel()
	stopping := readSystemdTestNotification(t, notifyListener)
	if stopping != "STOPPING=1\nSTATUS=ldap-go shutting down" {
		t.Fatalf("STOPPING=%q", stopping)
	}
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("notifying serve exit=%d stderr=%s", exitCode, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notifying serve did not stop")
	}
}

func TestNotifySystemdValidation(t *testing.T) {
	for _, test := range []struct {
		address string
		state   string
	}{
		{address: "relative.sock", state: "READY=1"},
		{address: filepath.Join(os.TempDir(), "missing-notify.sock"), state: "READY=1"},
		{address: "/tmp/notify.sock", state: ""},
		{address: "/tmp/notify.sock", state: "READY=1\rINVALID"},
	} {
		configured, err := notifySystemd(func(string) string { return test.address }, test.state)
		if !configured || err == nil {
			t.Fatalf("notifySystemd(%q, %q) = %t, %v", test.address, test.state, configured, err)
		}
	}
}

func readSystemdTestNotification(
	t *testing.T,
	listener *net.UnixConn,
) string {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 512)
	length, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return string(buffer[:length])
}
