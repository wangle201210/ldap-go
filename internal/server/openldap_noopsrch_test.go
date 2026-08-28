package server

import (
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPNoOpSearchDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPSingleSourceContribModule(
		t,
		"noopsrch",
		"noopsrch.c",
		"noopsrch.la",
	)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"moduleload "+module,
		"overlay noopsrch",
		"",
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedNoOpSearchOverlay(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopLocal)

	for name, uri := range map[string]string{
		"OpenLDAP": referenceURI,
		"ldap-go":  "ldap://" + localAddress,
	} {
		count := countNoOpSearchCandidates(t, uri)
		unlimited := observeNoOpSearch(
			t,
			strings.TrimPrefix(uri, "ldap://"),
			0,
		)
		if unlimited.outerResult != int64(ldap.LDAPResultSuccess) ||
			unlimited.innerResult != int64(ldap.LDAPResultSuccess) ||
			unlimited.entries != int64(count) ||
			unlimited.references != 0 || unlimited.wireEntries != 0 ||
			!unlimited.hasControl {
			t.Fatalf("%s unlimited noopsrch = %#v, direct count=%d", name, unlimited, count)
		}

		limited := observeNoOpSearch(
			t,
			strings.TrimPrefix(uri, "ldap://"),
			1,
		)
		if limited.outerResult != int64(ldap.LDAPResultSuccess) ||
			limited.innerResult != int64(ldap.LDAPResultSizeLimitExceeded) ||
			limited.entries != int64(count) ||
			limited.references != 0 || limited.wireEntries != 0 ||
			!limited.hasControl {
			t.Fatalf("%s limited noopsrch = %#v, direct count=%d", name, limited, count)
		}
		for _, controls := range [][]ldapwire.Control{
			{{OID: noOpSearchControlOID, Critical: true, HasValue: true, Value: []byte{}}},
			{{OID: noOpSearchControlOID}, {OID: noOpSearchControlOID}},
		} {
			if code := noOpSearchControlResult(
				t,
				strings.TrimPrefix(uri, "ldap://"),
				controls,
			); code != int64(ldap.LDAPResultProtocolError) {
				t.Fatalf("%s noopsrch control validation = %d", name, code)
			}
		}
	}
}

func countNoOpSearchCandidates(t *testing.T, uri string) int {
	t.Helper()
	client := dialAndBindReferencePassword(
		t,
		uri,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("direct candidate Search(%s): %v", uri, err)
	}
	return len(result.Entries)
}
