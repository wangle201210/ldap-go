package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	saslBackendACLReaderDN       = "uid=sasl-reader," + ldapBackendTestPeopleDN
	saslBackendACLReaderPassword = "sasl-reader-secret"
	saslBackendIDAssertDN        = "uid=operation-reader," + ldapBackendTestPeopleDN
	saslBackendIDAssertPassword  = "operation-reader-secret"
)

func TestLDAPBackendSASLCredentialBindSelection(t *testing.T) {
	tests := []struct {
		name             string
		credentialReader string
		configureACLBind bool
		explicitNone     bool
	}{
		{
			name:             "acl-bind has priority",
			credentialReader: saslBackendACLReaderDN,
			configureACLBind: true,
		},
		{
			name:             "idassert is the fallback",
			credentialReader: saslBackendIDAssertDN,
		},
		{
			name:             "explicit acl-bind none uses idassert",
			credentialReader: saslBackendIDAssertDN,
			explicitNone:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerStore := storage.NewMemory()
			t.Cleanup(func() { _ = providerStore.Close() })
			seedSASLBackendCredentialProvider(
				t,
				providerStore,
				test.credentialReader,
			)
			providerAddress, stopProvider := startServer(
				t,
				providerStore,
				Config{},
			)
			defer stopProvider()

			proxyStore := storage.NewMemory()
			t.Cleanup(func() { _ = proxyStore.Close() })
			seedLDAPBackendProxy(t, proxyStore, providerAddress)
			configureSASLBackendGlobal(
				t,
				proxyStore,
				ldapBackendTestSuffix,
			)
			configureLDAPBackendSASLCredentialBinds(
				t,
				proxyStore,
				test.configureACLBind,
			)
			if test.explicitNone {
				configureLDAPBackendExplicitNoneSASLCredentialBind(
					t,
					proxyStore,
				)
			}
			proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
			defer stopProxy()

			assertSASLBackendPlainBindAndSearch(
				t,
				proxyAddress,
				ldapBackendTestUserDN,
			)
			assertSASLBackendInvalidPlainPassword(t, proxyAddress)

			if test.configureACLBind {
				connection, err := dialAndBindSASLCRAMMD5(
					proxyAddress,
					"alice",
					ldapBackendTestUserPassword,
				)
				if err != nil {
					t.Fatalf("CRAM-MD5 Bind through back-ldap acl-bind: %v", err)
				}
				_ = connection.Close()
			}
		})
	}
}

func TestLDAPBackendSASLCredentialSingleURIRetry(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSASLBackendCredentialProvider(
		t,
		providerStore,
		saslBackendACLReaderDN,
	)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	defer stopProvider()
	upstream := startLDAPBackendDropFirstProxy(t, providerAddress)

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, upstream.address)
	configureSASLBackendGlobal(t, proxyStore, ldapBackendTestSuffix)
	configureLDAPBackendSASLCredentialBinds(t, proxyStore, true)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	connection, err := dialAndBindSASLPlain(
		proxyAddress,
		"",
		"alice",
		ldapBackendTestUserPassword,
	)
	if err != nil {
		t.Fatalf("PLAIN Bind after remote reconnect: %v", err)
	}
	_ = connection.Close()
	if got := upstream.accepted.Load(); got != 2 {
		t.Fatalf("remote SASL credential connections = %d, want 2", got)
	}
}

func TestOpenLDAPReferenceSASLCredentialACLBindFallback(t *testing.T) {
	_ = requireOpenLDAPLDAPBackendReferenceTools(t)
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("SASL credential reference requires a verified OpenLDAP build")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != "d172686d3d270bc961b78f3ff00d7019c8dfb094" {
		t.Fatalf("OpenLDAP reference commit = %q", got)
	}
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	path := filepath.Join(sourceRoot, "servers", "slapd", "back-ldap", "bind.c")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP source %s: %v", path, err)
	}
	for _, anchor := range []string{
		"if ( li->li_acl_authmethod == LDAP_AUTH_NONE &&",
		"li->li_idassert_authmethod != LDAP_AUTH_NONE )",
		"ber_dupbv( &lc->lc_bound_ndn, &li->li_idassert_authcDN );",
		"ber_dupbv( &lc->lc_cred, &li->li_idassert_passwd );",
	} {
		if !strings.Contains(string(contents), anchor) {
			t.Fatalf("pinned OpenLDAP back-ldap/bind.c lacks %q", anchor)
		}
	}
}

func TestMetaBackendSASLPlainCredentialsUseTargetIDAssert(t *testing.T) {
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
	configureSASLBackendGlobal(t, proxyStore, metaOperationLocalSuffix)
	configureMetaBackendSASLCredentialBind(t, proxyStore)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	assertSASLBackendPlainBindAndSearch(
		t,
		proxyAddress,
		metaOperationLocalUser,
	)
	assertSASLBackendInvalidPlainPassword(t, proxyAddress)
}

func seedSASLBackendCredentialProvider(
	t *testing.T,
	store storage.Store,
	credentialReader string,
) {
	t.Helper()
	seedLDAPBackendProvider(t, store)
	entries := []directory.Entry{
		{
			DN: saslBackendACLReaderDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("sasl-reader")},
				{Description: "cn", Values: stringValues("SASL Reader")},
				{Description: "sn", Values: stringValues("Reader")},
				{
					Description: "userPassword",
					Values:      stringValues(saslBackendACLReaderPassword),
				},
			},
		},
		{
			DN: saslBackendIDAssertDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("operation-reader")},
				{Description: "cn", Values: stringValues("Operation Reader")},
				{Description: "sn", Values: stringValues("Reader")},
				{
					Description: "userPassword",
					Values:      stringValues(saslBackendIDAssertPassword),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		databaseDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		database, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		database.ReplaceValues("olcAccess", stringValues(
			`{0}to attrs=userPassword by dn.exact="`+credentialReader+
				`" read by anonymous auth by * none`,
			`{1}to attrs=entry,objectClass by dn.exact="`+saslBackendACLReaderDN+
				`" read by dn.exact="`+saslBackendIDAssertDN+`" read by * none`,
			`{2}to * by dn.exact="`+saslBackendIDAssertDN+`" read by * none`,
		))
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("seed SASL backend credential provider: %v", err)
	}
}

func configureSASLBackendGlobal(
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
		entry.ReplaceValues("olcAuthzRegexp", stringValues(
			`{0}^uid=([^,]+),cn=plain,cn=auth$ uid=$1,ou=people,`+suffix,
			`{1}^uid=([^,]+),cn=cram-md5,cn=auth$ uid=$1,ou=people,`+suffix,
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure backend SASL mapping: %v", err)
	}
}

func configureLDAPBackendSASLCredentialBinds(
	t *testing.T,
	store storage.Store,
	configureACLBind bool,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		databaseDN, err := directory.ParseDN(ldapBackendTestDatabaseDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbIDAssertBind", stringValues(
			`bindmethod=simple binddn="`+saslBackendIDAssertDN+
				`" credentials="`+saslBackendIDAssertPassword+`" mode=none`,
		))
		entry.ReplaceValues("olcDbProxyWhoAmI", stringValues("FALSE"))
		if configureACLBind {
			entry.ReplaceValues("olcDbACLBind", stringValues(
				`bindmethod=simple binddn="`+saslBackendACLReaderDN+
					`" credentials="`+saslBackendACLReaderPassword+`"`,
			))
		} else {
			entry.ReplaceValues("olcDbACLBind", nil)
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure back-ldap SASL credential binds: %v", err)
	}
}

func configureLDAPBackendExplicitNoneSASLCredentialBind(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		databaseDN, err := directory.ParseDN(ldapBackendTestDatabaseDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbACLBind", stringValues("bindmethod=none"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure explicit none back-ldap ACL bind: %v", err)
	}
}

func configureMetaBackendSASLCredentialBind(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	targetDN := "olcMetaSub={0}uri," + metaOperationDatabaseDN
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(targetDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbIDAssertBind", stringValues(
			`bindmethod=simple binddn="`+saslBackendIDAssertDN+
				`" credentials="`+saslBackendIDAssertPassword+`" mode=none`,
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure back-meta SASL credential bind: %v", err)
	}
}

func assertSASLBackendPlainBindAndSearch(
	t *testing.T,
	address string,
	wantDN string,
) {
	t.Helper()
	connection, err := dialAndBindSASLPlain(
		address,
		"",
		"alice",
		ldapBackendTestUserPassword,
	)
	if err != nil {
		t.Fatalf("PLAIN Bind through proxy backend: %v", err)
	}
	client := ldap.NewConn(connection, false)
	client.Start()
	defer client.Close()

	whoAmI, err := client.WhoAmI(nil)
	if err != nil || whoAmI.AuthzID != "dn:"+wantDN {
		t.Fatalf("PLAIN proxy WhoAmI = %#v, %v; want dn:%s", whoAmI, err, wantDN)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		wantDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(uid=alice)",
		[]string{"cn"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("cn") != "Alice Proxy" {
		t.Fatalf("Search after PLAIN proxy Bind = %#v, %v", result, err)
	}
}

func assertSASLBackendInvalidPlainPassword(t *testing.T, address string) {
	t.Helper()
	connection, err := dialAndBindSASLPlain(
		address,
		"",
		"alice",
		"wrong-password",
	)
	if connection != nil {
		_ = connection.Close()
	}
	assertWrappedLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
}
