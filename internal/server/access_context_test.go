package server

import (
	"context"
	"fmt"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestStorageDecoratorsForwardSnapshotRevision(t *testing.T) {
	t.Parallel()

	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	if err := base.Update(context.Background(), func(storage.Writer) error {
		return nil
	}); err != nil {
		t.Fatalf("Update(): %v", err)
	}
	decorated := &homedirEffectStore{
		Store: &accessContextStore{Store: base},
	}
	want, ok := base.CurrentStorageSnapshotRevision()
	if !ok {
		t.Fatal("base snapshot revision is unavailable")
	}
	got, ok := decorated.CurrentStorageSnapshotRevision()
	if !ok || got != want {
		t.Fatalf("decorated snapshot revision = %d, %t; want %d, true", got, ok, want)
	}
}

func TestConnectionACLSubjectSeparatesSASLStrength(t *testing.T) {
	server := &Server{}
	subject := server.connectionACLSubject(&connectionState{
		secure:      true,
		externalSSF: 256,
		saslSSF:     1,
	})
	if subject.TLSSSF != 256 || subject.TransportSSF != 0 ||
		subject.SASLSSF != 1 || subject.SSF != 256 {
		t.Fatalf("TLS plus SASL subject = %#v", subject)
	}

	subject = server.connectionACLSubject(&connectionState{
		externalSSF: 71,
		saslSSF:     128,
	})
	if subject.TransportSSF != 71 || subject.TLSSSF != 0 ||
		subject.SASLSSF != 128 || subject.SSF != 128 {
		t.Fatalf("transport plus SASL subject = %#v", subject)
	}
}

func TestLDAPClientACLConnectionContext(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()

	search := func() error {
		_, err := anonymous.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		))
		return err
	}
	setACL := func(rule string) {
		t.Helper()
		request := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		request.Replace("olcAccess", []string{"{0}to * by " + rule + " read by * none"})
		if err := configClient.Modify(request); err != nil {
			t.Fatalf("Modify(olcAccess=%q): %v", rule, err)
		}
	}

	allowRules := []string{
		`peername.ip="127.0.0.0%255.0.0.0"`,
		fmt.Sprintf(`sockname="IP=%s"`, address),
		fmt.Sprintf(`sockurl="ldap://%s/"`, address),
		"ssf=0",
		"transport_ssf=0",
	}
	for _, rule := range allowRules {
		setACL(rule)
		if err := search(); err != nil {
			t.Errorf("Search() denied by matching %s ACL: %v", rule, err)
		}
	}

	denyRules := []string{
		`peername.ip="192.0.2.0%255.255.255.0"`,
		"transport_ssf=1",
		"tls_ssf=1",
		"sasl_ssf=1",
	}
	for _, rule := range denyRules {
		setACL(rule)
		assertLDAPResultCode(t, search(), ldap.LDAPResultNoSuchObject)
	}
}

func TestLDAPClientACLSubjectLevels(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	setLevelACL := func(subject string) {
		t.Helper()
		request := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		request.Replace("olcAccess", []string{
			`{0}to attrs=userPassword by anonymous auth by * none`,
			`{1}to dn.base="ou=people,dc=example,dc=com" by ` + subject + ` read by * none`,
			`{2}to * by * none`,
		})
		if err := configClient.Modify(request); err != nil {
			t.Fatalf("Modify(level ACL %q): %v", subject, err)
		}
	}
	setLevelACL("self.level{1}")

	alice, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(alice): %v", err)
	}
	defer alice.Close()
	if err := alice.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(alice): %v", err)
	}
	searchParent := func() error {
		_, err := alice.Search(ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"ou"},
			nil,
		))
		return err
	}
	if err := searchParent(); err != nil {
		t.Fatalf("Search(self.level{1}): %v", err)
	}

	setLevelACL(`dn.level{1}="ou=people,dc=example,dc=com"`)
	if err := searchParent(); err != nil {
		t.Fatalf("Search(dn.level{1}): %v", err)
	}
}

func TestLDAPClientOpenLDAPACI(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	root, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(root): %v", err)
	}
	defer root.Close()
	if err := root.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(root): %v", err)
	}
	config, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer config.Close()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	access.Replace("olcAccess", []string{
		"{0}to * by dynacl/aci read",
		"{1}to * by * none",
	})
	if err := config.Modify(access); err != nil {
		t.Fatalf("Modify(ACI access): %v", err)
	}

	targetDN := "uid=alice,ou=people,dc=example,dc=com"
	aci := ldap.NewModifyRequest(targetDN, nil)
	aci.Add("OpenLDAPaci", []string{
		"0#entry#grant;d,s,r;[all]#public#",
		"1#entry#deny;r;cn#public#",
	})
	if err := root.Modify(aci); err != nil {
		t.Fatalf("Modify(OpenLDAPaci): %v", err)
	}
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		dn, parseErr := directory.ParseDN(targetDN)
		if parseErr != nil {
			return parseErr
		}
		entry, getErr := reader.Get(dn)
		if getErr != nil {
			return getErr
		}
		values := entry.Values("OpenLDAPaci")
		if len(values) != 2 {
			return fmt.Errorf("stored OpenLDAPaci values = %q", values)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify stored OpenLDAPaci: %v", err)
	}

	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()
	searchCN := func() (*ldap.SearchResult, error) {
		return anonymous.Search(ldap.NewSearchRequest(
			targetDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"cn", "uid"},
			nil,
		))
	}
	result, err := searchCN()
	if err != nil {
		t.Fatalf("Search(entry ACI): %v", err)
	}
	if len(result.Entries) != 1 || len(result.Entries[0].GetAttributeValues("cn")) != 0 ||
		result.Entries[0].GetAttributeValue("uid") != "alice" {
		if len(result.Entries) == 1 {
			t.Fatalf(
				"entry ACI values: cn=%q uid=%q attrs=%#v",
				result.Entries[0].GetAttributeValues("cn"),
				result.Entries[0].GetAttributeValues("uid"),
				result.Entries[0].Attributes,
			)
		}
		t.Fatalf("entry ACI result count = %d", len(result.Entries))
	}

	removeEntryACI := ldap.NewModifyRequest(targetDN, nil)
	removeEntryACI.Delete("OpenLDAPaci", nil)
	if err := root.Modify(removeEntryACI); err != nil {
		t.Fatalf("Delete(entry OpenLDAPaci): %v", err)
	}
	parentACI := ldap.NewModifyRequest("ou=people,dc=example,dc=com", nil)
	parentACI.Add("OpenLDAPaci", []string{
		"0#subtree#grant;d,s,r;[all]#public#",
	})
	if err := root.Modify(parentACI); err != nil {
		t.Fatalf("Modify(parent OpenLDAPaci): %v", err)
	}
	result, err = searchCN()
	if err != nil {
		t.Fatalf("Search(parent ACI): %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("cn") != "Alice Example" {
		t.Fatalf("parent ACI result = %#v", result.Entries)
	}
}
