package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const saslAuthorizationBackendGroupRDN = "cn=proxy-authorizers"

func TestOpenLDAPReferenceSASLAuthorizationBackendSource(t *testing.T) {
	_ = requireOpenLDAPLDAPBackendReferenceTools(t)
	const commit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("SASL authorization reference requires a verified OpenLDAP build")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != commit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, commit)
	}
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	checks := []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: filepath.Join("servers", "slapd", "saslauthz.c"),
			hash: "795c4e32127f4fe3b4f4c235637bccb8d530c9f9b38908de7ba0a92d7cfc11be",
			anchors: []string{
				"op.o_ndn = opx->o_conn->c_ndn;",
				"rc = backend_attribute( op, NULL, searchDN, ad, &vals, ACL_AUTH );",
				"op.o_ndn = *authc;",
				"op.o_is_auth_check = 1;",
				"op.ors_slimit = 1;",
				"op.ors_attrs = slap_anlist_no_attrs;",
				"op.ors_attrsonly = 1;",
			},
		},
		{
			path: filepath.Join("servers", "slapd", "back-ldap", "bind.c"),
			hash: "8b01620934ce7436f99b577ced3d1d242651a07d0a107db4d6a09c748701c5d1",
			anchors: []string{
				"if ( op->o_do_not_cache || be_isroot( op ) )",
				"if ( li->li_acl_authmethod == LDAP_AUTH_NONE &&",
				"li->li_idassert_authmethod != LDAP_AUTH_NONE )",
			},
		},
	}
	for _, check := range checks {
		contents, err := os.ReadFile(filepath.Join(sourceRoot, check.path))
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", check.path, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != check.hash {
			t.Fatalf(
				"pinned OpenLDAP source %s SHA-256 = %s, want %s",
				check.path,
				got,
				check.hash,
			)
		}
		for _, anchor := range check.anchors {
			if !strings.Contains(string(contents), anchor) {
				t.Fatalf("pinned OpenLDAP source %s lacks %q", check.path, anchor)
			}
		}
	}
}

func TestLDAPBackendSASLAuthorizationRules(t *testing.T) {
	bobDN := "uid=bob," + ldapBackendTestPeopleDN
	groupDN := saslAuthorizationBackendGroupRDN + "," + ldapBackendTestPeopleDN
	tests := []struct {
		name      string
		policy    string
		authzTo   string
		authzFrom string
	}{
		{
			name:    "authzTo",
			policy:  "to",
			authzTo: "dn:" + bobDN,
		},
		{
			name:      "authzFrom",
			policy:    "from",
			authzFrom: "dn:" + ldapBackendTestUserDN,
		},
		{
			name:    "group",
			policy:  "to",
			authzTo: "group/groupOfNames/member:" + groupDN,
		},
		{
			name:   "authorization LDAP URL",
			policy: "to",
			authzTo: "ldap:///" + ldapBackendTestPeopleDN +
				"??sub?(uid=bob)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerStore := storage.NewMemory()
			t.Cleanup(func() { _ = providerStore.Close() })
			seedSASLBackendCredentialProvider(
				t,
				providerStore,
				saslBackendACLReaderDN,
			)
			configureSASLAuthorizationProvider(
				t,
				providerStore,
				test.authzTo,
				test.authzFrom,
				true,
			)
			providerAddress, stopProvider := startServer(t, providerStore, Config{})
			defer stopProvider()

			proxyStore := storage.NewMemory()
			t.Cleanup(func() { _ = proxyStore.Close() })
			seedLDAPBackendProxy(t, proxyStore, providerAddress)
			configureSASLBackendGlobal(t, proxyStore, ldapBackendTestSuffix)
			configureLDAPBackendSASLCredentialBinds(t, proxyStore, true)
			replaceGlobalConfigurationValues(
				t,
				proxyStore,
				"olcAuthzPolicy",
				test.policy,
			)
			proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
			defer stopProxy()

			client := assertSASLAuthorizationBackendBind(
				t,
				proxyAddress,
				"dn:"+bobDN,
				bobDN,
				true,
			)
			client.Close()
		})
	}
}

func TestLDAPBackendSASLAuthorizationUsesACLBindVisibility(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSASLBackendCredentialProvider(t, providerStore, saslBackendACLReaderDN)
	bobDN := "uid=bob," + ldapBackendTestPeopleDN
	configureSASLAuthorizationProvider(
		t,
		providerStore,
		"dn:"+bobDN,
		"",
		false,
	)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	configureSASLBackendGlobal(t, proxyStore, ldapBackendTestSuffix)
	configureLDAPBackendSASLCredentialBinds(t, proxyStore, true)
	replaceGlobalConfigurationValues(t, proxyStore, "olcAuthzPolicy", "to")
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	assertSASLAuthorizationBackendBind(
		t,
		proxyAddress,
		"dn:"+bobDN,
		bobDN,
		false,
	)
}

func TestLDAPBackendSASLAuthorizationACLBindNoneFallsBackToIDAssert(
	t *testing.T,
) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSASLBackendCredentialProvider(t, providerStore, saslBackendACLReaderDN)
	bobDN := "uid=bob," + ldapBackendTestPeopleDN
	configureSASLAuthorizationProvider(
		t,
		providerStore,
		"dn:"+bobDN,
		"",
		false,
	)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	replaceGlobalConfigurationValues(t, proxyStore, "olcAuthzPolicy", "to")
	if err := proxyStore.Update(context.Background(), func(writer storage.Writer) error {
		database, err := writer.Get(mustProxyAuthorizationDN(ldapBackendTestDatabaseDN))
		if err != nil {
			return err
		}
		database.ReplaceValues("olcDbIDAssertBind", stringValues(
			`bindmethod=simple binddn="`+saslBackendIDAssertDN+
				`" credentials="`+saslBackendIDAssertPassword+`" mode=none`,
		))
		database.ReplaceValues("olcDbACLBind", stringValues("bindmethod=none"))
		database.ReplaceValues("olcDbProxyWhoAmI", stringValues("FALSE"))
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("configure back-ldap auth-check fallback: %v", err)
	}
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := dialAndBindLDAPClient(
		t,
		proxyAddress,
		ldapBackendTestUserDN,
		ldapBackendTestUserPassword,
	)
	defer client.Close()
	identity, err := client.WhoAmI([]ldap.Control{
		proxyAuthorizationControl("dn:"+bobDN, true),
	})
	if err != nil || identity.AuthzID != "dn:"+bobDN {
		t.Fatalf("acl-bind NONE auth-check identity = %#v, %v", identity, err)
	}
}

func TestMetaBackendSASLAuthorizationRulesAndMapping(t *testing.T) {
	localBobDN := "uid=bob," + metaOperationLocalPeople
	localGroupDN := saslAuthorizationBackendGroupRDN + "," + metaOperationLocalPeople
	tests := []struct {
		name      string
		policy    string
		authzTo   string
		authzFrom string
	}{
		{
			name:    "authzTo",
			policy:  "to",
			authzTo: "dn:" + localBobDN,
		},
		{
			name:      "authzFrom",
			policy:    "from",
			authzFrom: "dn:" + metaOperationLocalUser,
		},
		{
			name:    "mapped group",
			policy:  "to",
			authzTo: "group/groupOfNames/member:" + localGroupDN,
		},
		{
			name:   "mapped authorization LDAP URL",
			policy: "to",
			authzTo: "ldap:///" + metaOperationLocalPeople +
				"??sub?(uid=bob)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerStore := storage.NewMemory()
			t.Cleanup(func() { _ = providerStore.Close() })
			seedSASLBackendCredentialProvider(
				t,
				providerStore,
				saslBackendIDAssertDN,
			)
			configureSASLAuthorizationProvider(
				t,
				providerStore,
				test.authzTo,
				test.authzFrom,
				true,
			)
			providerAddress, stopProvider := startServer(t, providerStore, Config{})
			defer stopProvider()

			proxyStore := storage.NewMemory()
			t.Cleanup(func() { _ = proxyStore.Close() })
			seedMetaOperationProxy(t, proxyStore, providerAddress)
			configureSASLBackendGlobal(t, proxyStore, metaOperationLocalSuffix)
			configureMetaBackendSASLCredentialBind(t, proxyStore)
			replaceGlobalConfigurationValues(
				t,
				proxyStore,
				"olcAuthzPolicy",
				test.policy,
			)
			proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
			defer stopProxy()

			client := assertSASLAuthorizationBackendBind(
				t,
				proxyAddress,
				"dn:"+localBobDN,
				localBobDN,
				true,
			)
			client.Close()
		})
	}
}

func TestSASLAuthorizationRegexpURLProxyBackends(t *testing.T) {
	tests := []struct {
		name             string
		localSuffix      string
		localPeople      string
		localBob         string
		seedProxy        func(*testing.T, storage.Store, string)
		configureProxy   func(*testing.T, storage.Store)
		credentialReader string
	}{
		{
			name:             "back-ldap",
			localSuffix:      ldapBackendTestSuffix,
			localPeople:      ldapBackendTestPeopleDN,
			localBob:         "uid=bob," + ldapBackendTestPeopleDN,
			seedProxy:        seedLDAPBackendProxy,
			credentialReader: saslBackendACLReaderDN,
			configureProxy: func(t *testing.T, store storage.Store) {
				configureLDAPBackendSASLCredentialBinds(t, store, true)
			},
		},
		{
			name:             "back-meta",
			localSuffix:      metaOperationLocalSuffix,
			localPeople:      metaOperationLocalPeople,
			localBob:         "uid=bob," + metaOperationLocalPeople,
			seedProxy:        seedMetaOperationProxy,
			credentialReader: saslBackendIDAssertDN,
			configureProxy:   configureMetaBackendSASLCredentialBind,
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
			configureSASLAuthorizationProvider(
				t,
				providerStore,
				"dn:"+test.localBob,
				"",
				true,
			)
			providerAddress, stopProvider := startServer(t, providerStore, Config{})
			defer stopProvider()

			proxyStore := storage.NewMemory()
			t.Cleanup(func() { _ = proxyStore.Close() })
			test.seedProxy(t, proxyStore, providerAddress)
			configureSASLBackendGlobal(t, proxyStore, test.localSuffix)
			test.configureProxy(t, proxyStore)
			replaceGlobalConfigurationValues(t, proxyStore, "olcAuthzPolicy", "to")
			replaceGlobalConfigurationValues(
				t,
				proxyStore,
				"olcAuthzRegexp",
				`{0}^uid=([^,]+),cn=plain,cn=auth$ ldap:///`+
					test.localPeople+`??sub?(uid=$1)`,
			)
			proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
			defer stopProxy()

			connection := assertSASLAuthorizationBackendBind(
				t,
				proxyAddress,
				"u:bob",
				test.localBob,
				true,
			)
			defer connection.Close()

			addDuplicateSASLAuthorizationUser(t, providerAddress)
			assertSASLAuthorizationBackendBind(
				t,
				proxyAddress,
				"u:bob",
				test.localBob,
				false,
			)

			identity, err := connection.WhoAmI(nil)
			if err != nil || identity.AuthzID != "dn:"+test.localBob {
				t.Fatalf(
					"existing identity after failed internal search = %#v, %v",
					identity,
					err,
				)
			}
		})
	}
}

func configureSASLAuthorizationProvider(
	t *testing.T,
	store storage.Store,
	authzTo string,
	authzFrom string,
	allowACLBindAuthorization bool,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		alice, err := writer.Get(mustProxyAuthorizationDN(ldapBackendTestUserDN))
		if err != nil {
			return err
		}
		if authzTo == "" {
			alice.ReplaceValues("authzTo", nil)
		} else {
			alice.ReplaceValues("authzTo", stringValues(authzTo))
		}
		if err := writer.Put(alice, true); err != nil {
			return err
		}

		bobDN := "uid=bob," + ldapBackendTestPeopleDN
		bob, err := writer.Get(mustProxyAuthorizationDN(bobDN))
		if err != nil {
			return err
		}
		if authzFrom == "" {
			bob.ReplaceValues("authzFrom", nil)
		} else {
			bob.ReplaceValues("authzFrom", stringValues(authzFrom))
		}
		if err := writer.Put(bob, true); err != nil {
			return err
		}

		group := directory.Entry{
			DN: saslAuthorizationBackendGroupRDN + "," + ldapBackendTestPeopleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("groupOfNames")},
				{Description: "cn", Values: stringValues("proxy-authorizers")},
				{Description: "member", Values: stringValues(bobDN)},
			},
		}
		if err := writer.Put(group, false); err != nil {
			return err
		}

		database, err := writer.Get(mustProxyAuthorizationDN(
			"olcDatabase={1}mdb,cn=config",
		))
		if err != nil {
			return err
		}
		authorizationAccess := `by dn.exact="` + saslBackendACLReaderDN +
			`" read by dn.exact="` + saslBackendIDAssertDN + `" manage by * none`
		if !allowACLBindAuthorization {
			authorizationAccess = `by dn.exact="` + saslBackendIDAssertDN +
				`" manage by * none`
		}
		database.ReplaceValues("olcAccess", stringValues(
			`{0}to attrs=userPassword by dn.exact="`+saslBackendACLReaderDN+
				`" read by dn.exact="`+saslBackendIDAssertDN+
				`" manage by anonymous auth by * none`,
			`{1}to attrs=authzTo,authzFrom,member,uid `+authorizationAccess,
			`{2}to attrs=entry,objectClass by dn.exact="`+saslBackendACLReaderDN+
				`" read by dn.exact="`+saslBackendIDAssertDN+`" manage by * none`,
			`{3}to * by dn.exact="`+saslBackendIDAssertDN+`" manage by * none`,
		))
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("configure SASL authorization provider: %v", err)
	}
}

func addDuplicateSASLAuthorizationUser(t *testing.T, providerAddress string) {
	t.Helper()
	client := dialLDAPBackendClient(t, providerAddress)
	defer client.Close()
	if err := client.Bind(saslBackendIDAssertDN, saslBackendIDAssertPassword); err != nil {
		t.Fatalf("bind duplicate SASL authorization writer: %v", err)
	}
	request := ldap.NewAddRequest(
		"uid=bob-duplicate,"+ldapBackendTestPeopleDN,
		nil,
	)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{"bob-duplicate", "bob"})
	request.Attribute("cn", []string{"Duplicate Bob"})
	request.Attribute("sn", []string{"Bob"})
	if err := client.Add(request); err != nil {
		t.Fatalf("add duplicate SASL authorization user: %v", err)
	}
}

func assertSASLAuthorizationBackendBind(
	t *testing.T,
	address string,
	authorizationID string,
	wantDN string,
	wantSuccess bool,
) *ldap.Conn {
	t.Helper()
	connection, err := dialAndBindSASLPlain(
		address,
		authorizationID,
		"alice",
		ldapBackendTestUserPassword,
	)
	if !wantSuccess {
		if connection != nil {
			_ = connection.Close()
		}
		assertWrappedLDAPResultCode(
			t,
			err,
			ldap.LDAPResultInappropriateAuthentication,
		)
		return nil
	}
	if err != nil {
		t.Fatalf("SASL PLAIN authorization Bind: %v", err)
	}
	client := ldap.NewConn(connection, false)
	client.Start()
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:"+wantDN {
		client.Close()
		t.Fatalf("authorized identity = %#v, %v; want dn:%s", identity, err, wantDN)
	}
	return client
}
