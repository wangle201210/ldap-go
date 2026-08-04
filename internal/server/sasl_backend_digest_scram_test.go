package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPBackendSASLDigestAndSCRAMCredentials(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSASLBackendCredentialProvider(
		t,
		providerStore,
		saslBackendACLReaderDN,
	)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	configureSASLBackendDigestSCRAM(t, proxyStore, ldapBackendTestSuffix)
	configureLDAPBackendSASLCredentialBinds(t, proxyStore, true)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	assertSASLBackendDigestAndSCRAM(
		t,
		proxyAddress,
		ldapBackendTestUserDN,
	)
}

func TestMetaBackendSASLDigestAndSCRAMCredentials(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSASLBackendCredentialProvider(
		t,
		providerStore,
		saslBackendIDAssertDN,
	)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedMetaOperationProxy(t, proxyStore, providerAddress)
	configureSASLBackendDigestSCRAM(t, proxyStore, metaOperationLocalSuffix)
	configureMetaBackendSASLCredentialBind(t, proxyStore)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	assertSASLBackendDigestAndSCRAM(
		t,
		proxyAddress,
		metaOperationLocalUser,
	)
}

func configureSASLBackendDigestSCRAM(
	t *testing.T,
	store storage.Store,
	suffix string,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		configDN, err := directory.ParseDN("cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSaslSecProps", stringValues("none"))
		entry.ReplaceValues("olcSaslHost", stringValues("ldap.example.test"))
		entry.ReplaceValues("olcSaslRealm", stringValues("example.com"))
		entry.ReplaceValues("olcAuthzRegexp", stringValues(
			`{0}^uid=([^,]+),cn=example\.com,cn=digest-md5,cn=auth$ `+
				`uid=$1,ou=people,`+suffix,
			`{1}^uid=([^,]+),cn=example\.com,cn=scram-sha-256,cn=auth$ `+
				`uid=$1,ou=people,`+suffix,
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure backend DIGEST/SCRAM mapping: %v", err)
	}
}

func assertSASLBackendDigestAndSCRAM(
	t *testing.T,
	address string,
	wantDN string,
) {
	t.Helper()

	t.Run("DIGEST-MD5", func(t *testing.T) {
		client, err := dialAndBindSASLDigestMD5(
			address,
			"alice",
			ldapBackendTestUserPassword,
		)
		if err != nil {
			t.Fatalf("DIGEST-MD5 Bind through proxy backend: %v", err)
		}
		identity, err := client.WhoAmI(nil)
		_ = client.Close()
		if err != nil || identity.AuthzID != "dn:"+wantDN {
			t.Fatalf("DIGEST-MD5 proxy WhoAmI = %#v, %v", identity, err)
		}

		client, err = dialAndBindSASLDigestMD5(
			address,
			"alice",
			"wrong-password",
		)
		if client != nil {
			_ = client.Close()
		}
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	})

	t.Run("SCRAM-SHA-256", func(t *testing.T) {
		connection, err := dialAndBindSASLSCRAM(
			address,
			"SCRAM-SHA-256",
			"",
			"alice",
			ldapBackendTestUserPassword,
		)
		if err != nil {
			t.Fatalf("SCRAM-SHA-256 Bind through proxy backend: %v", err)
		}
		client := ldap.NewConn(connection, false)
		client.Start()
		identity, err := client.WhoAmI(nil)
		_ = client.Close()
		if err != nil || identity.AuthzID != "dn:"+wantDN {
			t.Fatalf("SCRAM-SHA-256 proxy WhoAmI = %#v, %v", identity, err)
		}

		connection, err = dialAndBindSASLSCRAM(
			address,
			"SCRAM-SHA-256",
			"",
			"alice",
			"wrong-password",
		)
		if connection != nil {
			_ = connection.Close()
		}
		assertWrappedLDAPResultCode(
			t,
			err,
			ldap.LDAPResultInvalidCredentials,
		)
	})
}
