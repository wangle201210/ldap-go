package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSerializedResponseConnectionWriteTimeoutAndDeadlineClear(t *testing.T) {
	t.Parallel()

	const timeout = 75 * time.Millisecond
	t.Run("blocked write", func(t *testing.T) {
		serverSide, clientSide := net.Pipe()
		defer serverSide.Close()
		defer clientSide.Close()
		connection := &serializedResponseConnection{
			Conn:         serverSide,
			mu:           &sync.Mutex{},
			writeTimeout: func() time.Duration { return timeout },
		}
		started := time.Now()
		_, err := connection.Write([]byte("blocked"))
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("blocked Write() error = %v", err)
		}
		if elapsed := time.Since(started); elapsed < timeout/2 || elapsed > time.Second {
			t.Fatalf("blocked Write() elapsed = %s", elapsed)
		}
	})

	t.Run("successful write clears deadline", func(t *testing.T) {
		serverSide, clientSide := net.Pipe()
		defer serverSide.Close()
		defer clientSide.Close()
		connection := &serializedResponseConnection{
			Conn:         serverSide,
			mu:           &sync.Mutex{},
			writeTimeout: func() time.Duration { return timeout },
		}
		read := make(chan error, 1)
		go func() {
			buffer := make([]byte, 1)
			_, err := io.ReadFull(clientSide, buffer)
			read <- err
		}()
		if _, err := connection.Write([]byte("a")); err != nil {
			t.Fatalf("serialized Write(): %v", err)
		}
		if err := <-read; err != nil {
			t.Fatalf("read serialized value: %v", err)
		}

		go func() {
			time.Sleep(2 * timeout)
			buffer := make([]byte, 1)
			_, err := io.ReadFull(clientSide, buffer)
			read <- err
		}()
		if _, err := serverSide.Write([]byte("b")); err != nil {
			t.Fatalf("direct Write() retained old deadline: %v", err)
		}
		if err := <-read; err != nil {
			t.Fatalf("read direct value: %v", err)
		}
	})
}

func TestSerializedResponseConnectionPublishesWriteWaiter(t *testing.T) {
	t.Parallel()

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	monitor := newMonitorState()
	monitored := monitor.registerConnection(1, serverSide, false)
	defer monitor.unregisterConnection(1)
	connection := &serializedResponseConnection{
		Conn:              serverSide,
		mu:                &sync.Mutex{},
		monitor:           monitor,
		monitorConnection: monitored,
	}
	done := make(chan error, 1)
	go func() {
		_, err := connection.Write([]byte("wait"))
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		snapshots := monitor.connectionSnapshots()
		if len(snapshots) == 1 && snapshots[0].writeWaiter {
			if mask := monitorConnectionMask(snapshots[0]); mask != "rw" {
				t.Fatalf("blocked writer mask = %q, want rw", mask)
			}
			entries := monitorWaiterEntries(time.Now(), snapshots)
			if values := entries[1].Values("monitorCounter"); len(values) != 1 || string(values[0]) != "1" {
				t.Fatalf("Write waiter monitor entry = %#v", entries[1])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("blocked writer was not published to Monitor")
		}
		time.Sleep(time.Millisecond)
	}
	buffer := make([]byte, len("wait"))
	if _, err := io.ReadFull(clientSide, buffer); err != nil {
		t.Fatalf("read blocked writer: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("blocked writer completion: %v", err)
	}
	snapshots := monitor.connectionSnapshots()
	if len(snapshots) != 1 || snapshots[0].writeWaiter {
		t.Fatalf("completed writer snapshot = %#v", snapshots)
	}
}

func TestLDAPIdleTimeoutClosesAnonymousAndAuthenticatedConnections(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		name := "anonymous"
		if authenticated {
			name = "authenticated"
		}
		t.Run(name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			putConnectionTimeoutGlobalEntry(t, store, []string{"1"}, nil)
			address, stop := startServer(t, store, Config{
				RootDN:       "cn=admin,dc=example,dc=com",
				RootPassword: []byte("admin-secret"),
			})
			defer stop()

			var connection net.Conn
			var err error
			if authenticated {
				connection = dialAndBindRawLDAP(
					t,
					address,
					"cn=admin,dc=example,dc=com",
					"admin-secret",
				)
			} else {
				connection, err = net.DialTimeout("tcp", address, 2*time.Second)
				if err != nil {
					t.Fatalf("Dial(): %v", err)
				}
			}
			defer connection.Close()
			started := time.Now()
			assertConnectionTimeoutClosesSilently(t, connection, 4*time.Second)
			if elapsed := time.Since(started); elapsed < 700*time.Millisecond {
				t.Fatalf("idle connection closed too early: %s", elapsed)
			}
		})
	}
}

func TestLDAPIdleTimeoutDoesNotCloseExecutingSearch(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionTimeoutGlobalEntry(t, store, []string{"1"}, nil)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)
	time.Sleep(1500 * time.Millisecond)
	writeRawLDAPRequest(t, connection, 3, rawAbandonRequest(2), nil)
	select {
	case <-gate.resumed:
	case <-time.After(2 * time.Second):
		t.Fatal("Abandon did not release executing Search")
	}
	writeRawLDAPRequest(
		t,
		connection,
		4,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		4,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
	assertConnectionTimeoutClosesSilently(t, connection, 4*time.Second)
}

func TestLDAPIdleTimeoutTracksPartialBERReads(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionTimeoutGlobalEntry(t, store, []string{"1"}, nil)
	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()

	partial := []byte{0x30, 0x10, 0x02, 0x01, 0x01}
	for _, value := range partial {
		if _, err := connection.Write([]byte{value}); err != nil {
			t.Fatalf("write partial BER: %v", err)
		}
		time.Sleep(450 * time.Millisecond)
	}
	assertConnectionTimeoutClosesSilently(t, connection, 4*time.Second)
}

func TestLDAPIdleTimeoutOnlineConfigurationAppliesToExistingConnection(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()
	existing, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(existing): %v", err)
	}
	defer existing.Close()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Replace("olcIdleTimeout", []string{"1"})
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("set olcIdleTimeout: %v", err)
	}
	assertConnectionTimeoutClosesSilently(t, existing, 4*time.Second)
}

func TestLDAPIdleTimeoutOnlineDisableKeepsExistingConnection(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	replaceGlobalConfigurationValues(t, store, "olcIdleTimeout", "2")
	address, stop := startServer(t, store, Config{})
	defer stop()
	existing, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(existing): %v", err)
	}
	defer existing.Close()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Delete("olcIdleTimeout", nil)
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("delete olcIdleTimeout: %v", err)
	}
	time.Sleep(2300 * time.Millisecond)
	writeRawLDAPRequest(
		t,
		existing,
		1,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	response := readRawLDAPPacket(t, existing)
	assertRawLDAPEnvelope(
		t,
		response,
		1,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}

func TestLDAPIdleTimeoutContinuesAfterStartTLS(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionTimeoutGlobalEntry(t, store, []string{"1"}, nil)
	address, stop := startServer(t, store, Config{
		TLSConfig: testServerTLSConfig(t),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.StartTLS(&tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}); err != nil {
		t.Fatalf("StartTLS(): %v", err)
	}
	time.Sleep(2 * time.Second)
	if _, err := client.WhoAmI(nil); err == nil {
		t.Fatal("StartTLS connection remained usable past olcIdleTimeout")
	}
}

func TestLDAPWriteTimeoutClosesBlockedResponse(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionTimeoutGlobalEntry(t, store, nil, []string{"1"})
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	instance.wg.Add(1)
	go func() {
		instance.serveConnection(ctx, serverSide)
		close(done)
	}()
	writeRawLDAPRequest(t, clientSide, 1, rawCancellationSearch(t), nil)
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		_ = clientSide.Close()
		t.Fatal("blocked LDAP response did not hit olcWriteTimeout")
	}
	if err := clientSide.SetReadDeadline(time.Now().Add(time.Second)); err != nil &&
		!errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	packet, err := ber.ReadPacket(clientSide)
	if err == nil {
		t.Fatalf("write timeout returned a complete LDAP packet: %#v", packet)
	}
}

func assertConnectionTimeoutClosesSilently(
	t *testing.T,
	connection net.Conn,
	timeout time.Duration,
) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	packet, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatalf("timeout returned an LDAP response: %#v", packet)
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatalf("connection remained open past timeout: %v", err)
	}
}
