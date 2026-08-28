package server

import (
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPNopsDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPSingleSourceContribModule(t, "nops", "nops.c", "nops.la")
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"moduleload "+module,
		"overlay nops",
		"userPassword: secret\n",
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedNopsOverlay(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopLocal)

	for name, fixture := range map[string]struct {
		uri string
		dn  string
		sn  string
	}{
		"OpenLDAP": {referenceURI, "uid=bob,ou=people,dc=example,dc=com", "Bob"},
		"ldap-go":  {"ldap://" + localAddress, aliceDN, "Example"},
	} {
		root := dialAndBindReferencePassword(
			t,
			fixture.uri,
			"cn=admin,dc=example,dc=com",
			"secret",
		)
		before := readReferenceAttribute(t, root, fixture.dn, "modifyTimestamp")
		modify := ldap.NewModifyRequest(fixture.dn, nil)
		modify.Replace("sn", []string{fixture.sn})
		if err := root.Modify(modify); err != nil {
			root.Close()
			t.Fatalf("%s idempotent Modify: %v", name, err)
		}
		after := readReferenceAttribute(t, root, fixture.dn, "modifyTimestamp")
		root.Close()
		if !slices.Equal(before, after) {
			t.Fatalf("%s modifyTimestamp changed: %q -> %q", name, before, after)
		}
	}
}
