package server

import (
	"errors"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPWhoAmIHonorsAuthenticationDatabaseRestrictionReload(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	setWhoAmIRestriction(t, store, true)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stop()

	dataClient := bindWhoAmIRootClient(t, "ldap://"+address, "secret")
	defer dataClient.Close()
	assertWhoAmIRestricted(t, dataClient)

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	modify.Delete("olcRestrict", nil)
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("delete WhoAmI restriction: %v", err)
	}
	response, err := dataClient.WhoAmI(nil)
	if err != nil || response.AuthzID != "dn:cn=admin,dc=example,dc=com" {
		t.Fatalf("WhoAmI after reload = %#v, %v", response, err)
	}
}

func TestOpenLDAPReferenceWhoAmIAuthenticationDatabaseRestriction(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"restrict extended="+whoAmIOID,
		"",
	)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	setWhoAmIRestriction(t, store, true)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLocal()

	reference := observeWhoAmIRestriction(t, referenceURI)
	local := observeWhoAmIRestriction(t, "ldap://"+localAddress)
	if !reflect.DeepEqual(reference, local) {
		t.Fatalf("WhoAmI restriction: OpenLDAP=%#v ldap-go=%#v", reference, local)
	}
	if reference.code != ldap.LDAPResultUnwillingToPerform ||
		reference.diagnostic != "extended operation restricted" {
		t.Fatalf("OpenLDAP WhoAmI restriction = %#v", reference)
	}
}

type whoAmIRestrictionObservation struct {
	code       uint16
	diagnostic string
}

func observeWhoAmIRestriction(t *testing.T, uri string) whoAmIRestrictionObservation {
	t.Helper()
	client := bindWhoAmIRootClient(t, uri, "secret")
	defer client.Close()
	_, err := client.WhoAmI(nil)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("WhoAmI(%s) error = %v", uri, err)
	}
	diagnostic := ""
	if ldapError.Err != nil {
		diagnostic = ldapError.Err.Error()
	}
	return whoAmIRestrictionObservation{
		code:       ldapError.ResultCode,
		diagnostic: diagnostic,
	}
}

func bindWhoAmIRootClient(t *testing.T, uri, password string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	if err := client.Bind("cn=admin,dc=example,dc=com", password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", uri, err)
	}
	return client
}

func assertWhoAmIRestricted(t *testing.T, client *ldap.Conn) {
	t.Helper()
	_, err := client.WhoAmI(nil)
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
}

func setWhoAmIRestriction(t *testing.T, store storage.Store, enabled bool) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		if enabled {
			entry.ReplaceValues("olcRestrict", stringValues("extended="+whoAmIOID))
		} else {
			entry.ReplaceValues("olcRestrict", nil)
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set WhoAmI restriction: %v", err)
	}
}
