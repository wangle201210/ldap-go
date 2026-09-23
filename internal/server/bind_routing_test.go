package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestBindRoutingReuseRebindAndReload(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	const rootDN = "cn=admin,dc=example,dc=com"
	const databaseDN = "olcDatabase={1}mdb,cn=config"
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(staticRuntimeDN(databaseDN))
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcRootDN", stringValues(rootDN))
		entry.ReplaceValues("olcRootPW", stringValues("root-secret"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	configuration := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configuration.Close()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assertBind := func(dn, password string, code uint16) {
		t.Helper()
		err := client.Bind(dn, password)
		if code == ldap.LDAPResultSuccess {
			if err != nil {
				t.Fatalf("Bind(%q): %v", dn, err)
			}
		} else {
			assertLDAPResultCode(t, err, code)
		}
		identity, err := client.WhoAmI(nil)
		if err != nil {
			t.Fatalf("WhoAmI after Bind(%q): %v", dn, err)
		}
		want := ""
		if code == ldap.LDAPResultSuccess {
			want = "dn:" + dn
		}
		if identity.AuthzID != want {
			t.Fatalf("WhoAmI after Bind(%q) = %q, want %q", dn, identity.AuthzID, want)
		}
	}
	assertBind(rootDN, "root-secret", ldap.LDAPResultSuccess)
	assertBind(rootDN, "wrong", ldap.LDAPResultInvalidCredentials)
	assertBind(rootDN, "root-secret", ldap.LDAPResultSuccess)
	assertBind("cn=admin,dc=unconfigured", "root-secret", ldap.LDAPResultInvalidCredentials)
	assertBind("undefinedBindName=admin,dc=example,dc=com", "root-secret", ldap.LDAPResultInvalidDNSyntax)
	assertBind("cn=broken,", "root-secret", ldap.LDAPResultInvalidDNSyntax)
	assertBind("cn=config", "config-secret", ldap.LDAPResultSuccess)
	assertBind(rootDN, "root-secret", ldap.LDAPResultSuccess)

	modify := ldap.NewModifyRequest(databaseDN, nil)
	modify.Replace("olcRootPW", []string{"replacement-secret"})
	if err := configuration.Modify(modify); err != nil {
		t.Fatal(err)
	}
	assertBind(rootDN, "root-secret", ldap.LDAPResultInvalidCredentials)
	assertBind(rootDN, "replacement-secret", ldap.LDAPResultSuccess)

	modify = ldap.NewModifyRequest(databaseDN, nil)
	modify.Add("olcRestrict", []string{"bind"})
	if err := configuration.Modify(modify); err != nil {
		t.Fatal(err)
	}
	assertBind(rootDN, "replacement-secret", ldap.LDAPResultUnwillingToPerform)
	modify = ldap.NewModifyRequest(databaseDN, nil)
	modify.Delete("olcRestrict", nil)
	if err := configuration.Modify(modify); err != nil {
		t.Fatal(err)
	}
	assertBind(rootDN, "replacement-secret", ldap.LDAPResultSuccess)
}

func TestBindRoutingReuseValidationOrder(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(staticRuntimeDN("olcDatabase={1}mdb,cn=config"))
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSecurity", stringValues("simple_bind=1"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	const rootDN = "cn=admin,dc=example,dc=com"
	address, stop := startServer(t, store, Config{RootDN: rootDN, RootPassword: []byte("secret")})
	t.Cleanup(stop)
	for _, test := range []struct {
		name     string
		dn       string
		version  int
		controls []ldapwire.Control
		code     int64
	}{
		{name: "root still requires security", dn: rootDN, version: 3, code: ldap.LDAPResultConfidentialityRequired},
		{name: "unknown critical control before security", dn: rootDN, version: 3,
			controls: []ldapwire.Control{{OID: "1.2.3.4", Critical: true}}, code: ldap.LDAPResultUnavailableCriticalExtension},
		{name: "noncritical control retains security", dn: rootDN, version: 3,
			controls: []ldapwire.Control{{OID: "1.2.3.4"}}, code: ldap.LDAPResultConfidentialityRequired},
		{name: "invalid DN before control", dn: "cn=broken,", version: 3,
			controls: []ldapwire.Control{{OID: "1.2.3.4", Critical: true}}, code: ldap.LDAPResultInvalidDNSyntax},
		{name: "schema failure before security", dn: "undefinedBindName=admin,dc=example,dc=com", version: 3,
			code: ldap.LDAPResultInvalidDNSyntax},
		{name: "version before security", dn: rootDN, version: 4, code: ldap.LDAPResultProtocolError},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := authzidTestDial(t, address)
			defer connection.Close()
			response := authzidTestExchange(t, connection, ldapwire.Message{
				ID: 1, Controls: test.controls,
				Request: ldapwire.BindRequest{Version: test.version, Name: test.dn,
					Authentication: ldapwire.Authentication{Simple: []byte("secret")}},
			})
			assertRawLDAPEnvelope(t, response, 1, ldapwire.ApplicationBindResponse, test.code)
		})
	}
}
