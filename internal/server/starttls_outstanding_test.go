package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPStartTLSRejectsOutstandingSearchImmediately(t *testing.T) {
	t.Parallel()

	store := newCancelBlockingStore(storage.NewMemory())
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

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
	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(startTLSOID, nil, false),
		nil,
	)

	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		3,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultOperationsError),
	)
	if diagnostic := rawLDAPDiagnostic(response); diagnostic !=
		"cannot start TLS when operations are outstanding" {
		t.Fatalf("StartTLS diagnostic = %q", diagnostic)
	}
	select {
	case <-gate.resumed:
		t.Fatal("StartTLS rejection canceled the outstanding Search")
	default:
	}

	writeRawLDAPRequest(t, connection, 4, rawAbandonRequest(2), nil)
	writeRawLDAPRequest(
		t,
		connection,
		5,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	response = readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		5,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
}
