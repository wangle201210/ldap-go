package server

import (
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPConnectionPendingLimitUsesAuthenticationState(t *testing.T) {
	for _, test := range []struct {
		name          string
		authenticated bool
		maxPending    string
		maxAuth       string
	}{
		{
			name:       "anonymous",
			maxPending: "1",
			maxAuth:    "8",
		},
		{
			name:          "authenticated",
			authenticated: true,
			maxPending:    "0",
			maxAuth:       "1",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newCancelBlockingStore(storage.NewMemory())
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			putConnectionPendingGlobalEntry(
				t,
				store,
				[]string{test.maxPending},
				[]string{test.maxAuth},
			)

			address, stop := startServer(t, store, Config{
				RootDN:       "cn=admin,dc=example,dc=com",
				RootPassword: []byte("admin-secret"),
			})
			defer stop()

			var connection net.Conn
			var err error
			messageID := int64(1)
			if test.authenticated {
				connection = dialAndBindRawLDAP(
					t,
					address,
					"cn=admin,dc=example,dc=com",
					"admin-secret",
				)
				messageID = 2
			} else {
				connection, err = net.DialTimeout("tcp", address, 2*time.Second)
				if err != nil {
					t.Fatalf("Dial(): %v", err)
				}
			}
			defer connection.Close()

			gate := store.blockNextSearch()
			writeRawLDAPRequest(
				t,
				connection,
				messageID,
				rawCancellationSearch(t),
				nil,
			)
			gate.waitUntilBlocked(t)
			writeRawLDAPRequest(
				t,
				connection,
				messageID+1,
				rawExtendedRequest("1.3.6.1.4.1.4203.666.999", nil, false),
				nil,
			)
			assertLDAPConnectionHasNoResponse(t, connection)

			writeRawLDAPRequest(
				t,
				connection,
				messageID+2,
				rawExtendedRequest("1.3.6.1.4.1.4203.666.999", nil, false),
				nil,
			)
			assertLDAPConnectionClosedWithoutResponse(t, connection)
		})
	}
}

func TestLDAPConnectionPendingByteLimits(t *testing.T) {
	for _, test := range []struct {
		name       string
		connection bool
	}{
		{name: "per connection", connection: true},
		{name: "process"},
	} {
		t.Run(test.name, func(t *testing.T) {
			searchSize := rawLDAPRequestRetainedSizeWithControls(t, 1, rawCancellationSearch(t))
			extendedSize := rawLDAPRequestRetainedSizeWithControls(
				t,
				2,
				rawExtendedRequest("1.3.6.1.4.1.4203.666.999", nil, false),
			)
			limit := searchSize + extendedSize - 1
			store := newCancelBlockingStore(storage.NewMemory())
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			config := Config{
				MaxOperationsPerConnection:   1,
				MaxPendingBytesPerConnection: 1 << 20,
				MaxPendingOperationBytes:     1 << 20,
			}
			if test.connection {
				config.MaxPendingBytesPerConnection = limit
			} else {
				config.MaxPendingOperationBytes = limit
			}
			address, stop := startServer(t, store, config)
			defer stop()
			connection, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				t.Fatalf("Dial(): %v", err)
			}
			defer connection.Close()
			gate := store.blockNextSearch()
			writeRawLDAPRequest(t, connection, 1, rawCancellationSearch(t), nil)
			gate.waitUntilBlocked(t)
			writeRawLDAPRequest(
				t,
				connection,
				2,
				rawExtendedRequest("1.3.6.1.4.1.4203.666.999", nil, false),
				nil,
			)
			assertLDAPConnectionClosedWithoutResponse(t, connection)
		})
	}
}

func TestLDAPAbandonBypassesZeroPendingLimit(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionPendingGlobalEntry(t, store, []string{"0"}, []string{"0"})

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, connection, 1, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)
	writeRawLDAPRequest(t, connection, 2, rawAbandonRequest(1), nil)
	select {
	case <-gate.resumed:
	case <-time.After(2 * time.Second):
		t.Fatal("Abandon did not cancel the active Search")
	}
	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)

	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		3,
		ldapwire.ApplicationExtendedResponse,
		0,
	)
}

func TestLDAPAbandonRemovesPendingOperationAndReleasesLimit(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putConnectionPendingGlobalEntry(t, store, []string{"1"}, []string{"1"})

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, connection, 1, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)
	writeRawLDAPRequest(t, connection, 2, rawCancellationSearch(t), nil)
	writeRawLDAPRequest(t, connection, 3, rawAbandonRequest(2), nil)
	writeRawLDAPRequest(
		t,
		connection,
		4,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	writeRawLDAPRequest(t, connection, 5, rawAbandonRequest(1), nil)

	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		4,
		ldapwire.ApplicationExtendedResponse,
		0,
	)
}

func TestLDAPConnectionPendingOnlineConfigurationAppliesToExistingConnection(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(existing connection): %v", err)
	}
	defer connection.Close()
	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Replace("olcConnMaxPending", []string{"1"})
	modify.Replace("olcConnMaxPendingAuth", []string{"1"})
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("Modify(connection pending limits): %v", err)
	}

	gate := store.blockNextSearch()
	writeRawLDAPRequest(t, connection, 1, rawCancellationSearch(t), nil)
	gate.waitUntilBlocked(t)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawExtendedRequest("1.3.6.1.4.1.4203.666.999", nil, false),
		nil,
	)
	assertLDAPConnectionHasNoResponse(t, connection)
	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest("1.3.6.1.4.1.4203.666.999", nil, false),
		nil,
	)
	assertLDAPConnectionClosedWithoutResponse(t, connection)
}

func assertLDAPConnectionHasNoResponse(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	_, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatal("pending request produced a response while the active Search was blocked")
	}
	if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("connection closed at the configured pending boundary: %v", err)
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
}

func assertLDAPConnectionClosedWithoutResponse(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	packet, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatalf("pending overflow returned an LDAP response: %#v", packet)
	}
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("pending overflow did not close the connection")
	}
}
