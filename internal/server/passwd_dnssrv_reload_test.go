package server

import (
	"net"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPasswdAndDNSSRVBackendOnlineReloadRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	fixture := writePasswdBackendFixture(
		t,
		"reload:x:2000:2000:Reload User:/home/reload:/bin/sh\n",
	)
	resolver := &fakeDNSSRVResolver{err: &net.DNSError{
		Err: "no such host", Name: "discovery.test", IsNotFound: true,
	}}
	address, stop := startServer(t, store, Config{DNSSRVResolver: resolver})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	const passwdDatabaseDN = "olcDatabase={2}passwd,cn=config"
	passwd := ldap.NewAddRequest(passwdDatabaseDN, nil)
	passwd.Attribute("objectClass", []string{"olcDatabaseConfig", "olcPasswdConfig"})
	passwd.Attribute("olcDatabase", []string{"{2}passwd"})
	passwd.Attribute("olcSuffix", []string{passwdTestSuffix})
	passwd.Attribute("olcPasswdFile", []string{fixture})
	passwd.Attribute("olcAccess", []string{"{0}to * by * read"})
	if err := client.Add(passwd); err != nil {
		t.Fatalf("online Add(passwd): %v", err)
	}
	assertReloadPasswdEntry(t, client)

	invalidPasswd := ldap.NewModifyRequest(passwdDatabaseDN, nil)
	invalidPasswd.Replace("olcPasswdFile", []string{fixture + ".missing"})
	assertLDAPResultCode(t, client.Modify(invalidPasswd), ldap.LDAPResultConstraintViolation)
	assertReloadPasswdEntry(t, client)
	configuredPasswd, err := client.Search(ldap.NewSearchRequest(
		passwdDatabaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcPasswdFile"},
		nil,
	))
	if err != nil || len(configuredPasswd.Entries) != 1 ||
		configuredPasswd.Entries[0].GetAttributeValue("olcPasswdFile") != fixture {
		t.Fatalf("rolled-back olcPasswdFile = %#v, %v", configuredPasswd, err)
	}

	const dnssrvDatabaseDN = "olcDatabase={3}dnssrv,cn=config"
	dnssrv := ldap.NewAddRequest(dnssrvDatabaseDN, nil)
	dnssrv.Attribute("objectClass", []string{"olcDatabaseConfig", "olcDNSSRVConfig"})
	dnssrv.Attribute("olcDatabase", []string{"{3}dnssrv"})
	dnssrv.Attribute("olcSuffix", []string{"dc=discovery,dc=test"})
	dnssrv.Attribute("olcDNSSRVCacheTTL", []string{"1m"})
	dnssrv.Attribute("olcDNSSRVNegativeTTL", []string{"10s"})
	if err := client.Add(dnssrv); err != nil {
		t.Fatalf("online Add(dnssrv): %v", err)
	}
	assertReloadDNSSRVNoSuchObject(t, client)
	if resolver.callCount() != 1 {
		t.Fatalf("initial dnssrv resolver calls = %d", resolver.callCount())
	}
	invalidTTL := ldap.NewModifyRequest(dnssrvDatabaseDN, nil)
	invalidTTL.Replace("olcDNSSRVCacheTTL", []string{"0"})
	assertLDAPResultCode(t, client.Modify(invalidTTL), ldap.LDAPResultConstraintViolation)
	assertReloadDNSSRVNoSuchObject(t, client)
	if resolver.callCount() != 1 {
		t.Fatalf("failed reload replaced active dnssrv cache; resolver calls = %d", resolver.callCount())
	}
	configuredDNSSRV, err := client.Search(ldap.NewSearchRequest(
		dnssrvDatabaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcDNSSRVCacheTTL", "olcDNSSRVNegativeTTL"},
		nil,
	))
	if err != nil || len(configuredDNSSRV.Entries) != 1 ||
		configuredDNSSRV.Entries[0].GetAttributeValue("olcDNSSRVCacheTTL") != "1m" ||
		configuredDNSSRV.Entries[0].GetAttributeValue("olcDNSSRVNegativeTTL") != "10s" {
		t.Fatalf("rolled-back dnssrv TTL = %#v, %v", configuredDNSSRV, err)
	}
}

func assertReloadDNSSRVNoSuchObject(t *testing.T, client *ldap.Conn) {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		"dc=discovery,dc=test",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func assertReloadPasswdEntry(t *testing.T, client *ldap.Conn) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"uid=reload,"+passwdTestSuffix,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=reload)",
		[]string{"cn"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("cn") != "reload" {
		t.Fatalf("passwd runtime after reload = %#v, %v", result, err)
	}
}
