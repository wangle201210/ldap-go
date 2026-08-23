package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPTransactionControlCompatibilityRejections(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bbolt",
			open: func(t *testing.T) storage.Store {
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	} {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			const (
				rootDN       = "cn=admin,dc=example,dc=com"
				rootPassword = "admin-secret"
			)
			address, stop := startServer(t, store, Config{
				RootDN:       rootDN,
				RootPassword: []byte(rootPassword),
			})
			defer stop()
			connection := dialAndBindRawLDAP(t, address, rootDN, rootPassword)
			defer connection.Close()

			response := sendRawLDAPOperation(
				t,
				connection,
				2,
				rawExtendedRequest(transactionStartOID, nil, false),
				rawProxyAuthorizationControl(
					true,
					[]byte("dn:"+aliceDN),
					true,
				),
			)
			assertRawLDAPResult(
				t,
				response,
				int64(ldapwire.ResultUnavailableCriticalExtension),
			)
			assertNoRawResponseControls(t, response)

			identifier := startRawLDAPTransaction(t, connection, 3)
			for messageID, oid := range map[int64]string{
				4: preReadControlOID,
				5: postReadControlOID,
			} {
				response = sendRawLDAPOperation(
					t,
					connection,
					messageID,
					rawModifyReplaceRequest(aliceDN, "cn", "Not Applied"),
					rawTransactionSpecificationControl(identifier, true, true),
					rawReadControl(oid, true, "cn"),
				)
				assertRawLDAPResult(
					t,
					response,
					int64(ldapwire.ResultUnwillingToPerform),
				)
				assertNoRawResponseControls(t, response)
			}
			assertRawLDAPResult(
				t,
				endRawLDAPTransaction(t, connection, 6, false, identifier),
				int64(ldapwire.ResultSuccess),
			)
		})
	}
}

func TestOpenLDAPReferenceTransactionControlCombinations(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServer(t, tools, nil)
	defer stop()
	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()

	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawExtendedRequest(transactionStartOID, nil, false),
		rawProxyAuthorizationControl(
			true,
			[]byte("dn:uid=alice,ou=people,dc=example,dc=com"),
			true,
		),
	)
	assertRawLDAPResult(
		t,
		response,
		int64(ldapwire.ResultUnavailableCriticalExtension),
	)
	assertNoRawResponseControls(t, response)

	identifier := startRawLDAPTransaction(t, connection, 3)
	for messageID, oid := range map[int64]string{
		4: preReadControlOID,
		5: postReadControlOID,
	} {
		response = sendRawLDAPOperation(
			t,
			connection,
			messageID,
			rawModifyReplaceRequest(
				"uid=alice,ou=people,dc=example,dc=com",
				"cn",
				"OpenLDAP Compatibility Rejection",
			),
			rawTransactionSpecificationControl(identifier, true, true),
			rawReadControl(oid, true, "cn"),
		)
		assertRawLDAPResult(
			t,
			response,
			int64(ldapwire.ResultUnwillingToPerform),
		)
		assertNoRawResponseControls(t, response)
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 6, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
}
