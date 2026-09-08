package server

import (
	"context"
	"fmt"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRWMRewriteDSLRelayRequestAndResponse(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedRelayConfiguration(t, store)
	replaceRWMRewriteConfiguration(
		t,
		store,
		rwmOverlayConfigDN,
		"olcRwmRewrite",
		rwmRewriteOverlayDirectives("dc=virtual,dc=test", "dc=example,dc=com")...,
	)
	address, stop := startServer(t, store, Config{})
	defer stop()
	exerciseRWMRewriteProxy(
		t,
		"ldap://"+address,
		"uid=alice,ou=people,dc=virtual,dc=test",
		"",
		"alice-secret",
	)
}

func TestRWMRewriteDSLDirectLDAPBackendRequestAndResponse(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendRWMProxy(t, proxyStore, "ldap://"+providerAddress, true)
	replaceRWMRewriteConfiguration(
		t,
		proxyStore,
		ldapBackendRWMOverlayDN,
		"olcRwmRewrite",
		rwmRewriteOverlayDirectives(ldapBackendRWMLocalSuffix, ldapBackendTestSuffix)...,
	)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()
	exerciseRWMRewriteProxy(
		t,
		"ldap://"+proxyAddress,
		ldapBackendRWMLocalAliceDN,
		"uid=rewritten,"+ldapBackendRWMLocalPeopleDN,
		ldapBackendTestUserPassword,
	)
}

func TestRWMRewriteDSLMetaBackendRequestAndResponse(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedMetaOperationProxy(t, proxyStore, providerAddress)
	replaceRWMRewriteConfiguration(
		t,
		proxyStore,
		"olcMetaSub={0}uri,"+metaOperationDatabaseDN,
		"olcDbRewrite",
		rwmRewriteMetaDirectives(metaOperationLocalSuffix, ldapBackendTestSuffix)...,
	)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()
	exerciseRWMRewriteProxy(
		t,
		"ldap://"+proxyAddress,
		metaOperationLocalUser,
		"uid=rewritten,"+metaOperationLocalPeople,
		ldapBackendTestUserPassword,
	)
}

func exerciseRWMRewriteProxy(
	t *testing.T,
	uri,
	existingDN,
	addedDN,
	password string,
) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial RWM rewrite proxy: %v", err)
	}
	defer client.Close()
	if err := client.Bind(existingDN, password); err != nil {
		t.Fatalf("bind through RWM rewrite proxy: %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		existingDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 || result.Entries[0].DN != existingDN {
		t.Fatalf("search through RWM rewrite proxy = %#v, %v", result, err)
	}
	if addedDN == "" {
		return
	}

	add := ldap.NewAddRequest(addedDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"rewritten"})
	add.Attribute("cn", []string{"Rewritten User"})
	add.Attribute("sn", []string{"User"})
	if err := client.Add(add); err != nil {
		t.Fatalf("add through RWM rewrite proxy: %v", err)
	}
	result, err = client.Search(ldap.NewSearchRequest(
		addedDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=rewritten)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 || result.Entries[0].DN != addedDN {
		t.Fatalf("search added RWM rewrite entry = %#v, %v", result, err)
	}
}

func rwmRewriteOverlayDirectives(localSuffix, remoteSuffix string) []string {
	return []string{
		"{0}rewriteEngine on",
		"{1}rewriteContext default",
		fmt.Sprintf(`{2}rewriteRule "^(.+,)?%s$" "$1%s" ":"`, localSuffix, remoteSuffix),
		"{3}rewriteContext searchEntryDN",
		fmt.Sprintf(`{4}rewriteRule "^(.+,)?%s$" "$1%s" ":"`, remoteSuffix, localSuffix),
		"{5}rewriteContext searchAttrDN alias searchEntryDN",
		"{6}rewriteContext matchedDN alias searchEntryDN",
	}
}

func rwmRewriteMetaDirectives(localSuffix, remoteSuffix string) []string {
	return []string{
		"{0}rewriteEngine on",
		"{1}rewriteContext default",
		fmt.Sprintf(`{2}rewriteRule "^(.+,)?%s$" "$1%s" ":"`, localSuffix, remoteSuffix),
		"{3}rewriteContext searchResult",
		fmt.Sprintf(`{4}rewriteRule "^(.+,)?%s$" "$1%s" ":"`, remoteSuffix, localSuffix),
		"{5}rewriteContext searchAttrDN alias searchResult",
		"{6}rewriteContext matchedDN alias searchResult",
	}
}

func replaceRWMRewriteConfiguration(
	t *testing.T,
	store storage.Store,
	dn,
	attribute string,
	values ...string,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		parsed, err := directory.ParseDN(dn)
		if err != nil {
			return err
		}
		entry, err := writer.Get(parsed)
		if err != nil {
			return err
		}
		entry.ReplaceValues(attribute, stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("replace %s on %s: %v", attribute, dn, err)
	}
}
