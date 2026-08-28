package server

import (
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPLastBindDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPSingleSourceContribModule(
		t,
		"lastbind",
		"lastbind.c",
		"lastbind.la",
	)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"moduleload "+module,
		"overlay lastbind\nlastbind-precision 3600",
		"userPassword: secret\n",
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		databaseDN := staticRuntimeDN("olcDatabase={1}mdb,cn=config")
		database, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		database.ReplaceValues("olcLastBindPrecision", stringValues("3600"))
		if err := writer.Put(database, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}lastbind,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcLastBindConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}lastbind")},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopLocal)

	reference := observeLastBindPrecision(
		t,
		referenceURI,
		"uid=bob,ou=people,dc=example,dc=com",
	)
	local := observeLastBindPrecision(t, "ldap://"+localAddress, aliceDN)
	for name, values := range map[string][]string{
		"OpenLDAP": reference,
		"ldap-go":  local,
	} {
		if len(values) != 2 || values[0] == "" || values[0] != values[1] {
			t.Fatalf("%s lastbind precision values = %q", name, values)
		}
		if _, ok := parsePasswordPolicyTime([]byte(values[0])); !ok {
			t.Fatalf("%s authTimestamp = %q", name, values[0])
		}
	}
}

func observeLastBindPrecision(t *testing.T, uri, userDN string) []string {
	t.Helper()
	bind := func() {
		client, err := ldap.DialURL(uri)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err := client.Bind(userDN, "secret"); err != nil {
			t.Fatalf("Bind(%s): %v", uri, err)
		}
	}
	read := func() string {
		root := dialAndBindReferencePassword(
			t,
			uri,
			"cn=admin,dc=example,dc=com",
			"secret",
		)
		defer root.Close()
		values := readReferenceAttribute(t, root, userDN, "authTimestamp")
		if len(values) != 1 {
			t.Fatalf("authTimestamp on %s = %q", uri, values)
		}
		return values[0]
	}
	bind()
	first := read()
	// Keep the second Bind comfortably inside the one-hour precision window.
	time.Sleep(10 * time.Millisecond)
	bind()
	return []string{first, read()}
}
