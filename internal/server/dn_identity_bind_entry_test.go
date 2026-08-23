package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityBindEntryUpperBase = "bindExactName=Tenant,dc=example,dc=com"
	dnIdentityBindEntryLowerBase = "bindExactName=tenant,dc=example,dc=com"
	dnIdentityBindEntryUpperUser = "bindExactName=Alice+bindFoldName=Primary Team,ou=people," + dnIdentityBindEntryUpperBase
	dnIdentityBindEntryLowerUser = "bindExactName=alice+bindFoldName=Primary Team,ou=people," + dnIdentityBindEntryUpperBase
	dnIdentityBindEntryUpperRoot = "bindExactName=Admin+bindFoldName=Root Team," + dnIdentityBindEntryUpperBase
	dnIdentityBindEntryLowerRoot = "bindExactName=admin+bindFoldName=Root Team," + dnIdentityBindEntryLowerBase
)

const dnIdentityBindEntryConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}bindentrydn,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}bindentrydn
olcAttributeTypes: ( 1.3.6.1.4.1.99999.950.1 NAME ( 'bindExactName' 'bindExactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.950.2 NAME ( 'bindFoldName' 'bindFoldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.950.3 NAME 'bindIdentityEntry' SUP top STRUCTURAL MUST cn MAY ( sn $ userPassword $ bindExactName $ bindFoldName ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: bindExactName=Tenant,dc=example,dc=com
olcRootDN: bindExactName=Admin+bindFoldName=Root Team,bindExactName=Tenant,dc=example,dc=com
olcRootPW: upper-root-secret

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: bindExactName=tenant,dc=example,dc=com
olcRootDN: bindExactName=admin+bindFoldName=Root Team,bindExactName=tenant,dc=example,dc=com
olcRootPW: lower-root-secret

`

const dnIdentityBindEntryUpperContentLDIF = `dn: bindExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: bindIdentityEntry
cn: Upper tenant
bindExactName: Tenant

dn: ou=people,bindExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: bindExactName=Alice+bindFoldName=Primary Team,ou=people,bindExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: bindIdentityEntry
cn: Upper Alice
sn: Alice
bindExactName: Alice
bindFoldName: Primary Team
userPassword: upper-user-secret

dn: bindExactName=alice+bindFoldName=Primary Team,ou=people,bindExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: bindIdentityEntry
cn: Lower Alice
sn: alice
bindExactName: alice
bindFoldName: Primary Team
userPassword: lower-user-secret

`

const dnIdentityBindEntryLowerContentLDIF = `dn: bindExactName=tenant,dc=example,dc=com
objectClass: top
objectClass: bindIdentityEntry
cn: Lower tenant
bindExactName: tenant

`

func TestDNIdentityBindEntry(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			testDNIdentityBindEntry(t, backend.open)
		})
	}
}

func testDNIdentityBindEntry(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	dnIdentityBindEntryImport(t, store, "0", dnIdentityBindEntryConfigLDIF, true)
	dnIdentityBindEntryImport(t, store, "1", dnIdentityBindEntryUpperContentLDIF, false)
	dnIdentityBindEntryImport(t, store, "2", dnIdentityBindEntryLowerContentLDIF, false)

	address, instance, stop := startDNIdentityBindEntryServer(t, store)
	t.Cleanup(stop)
	runtime := instance.runtime.Load()

	const equivalentUpperUser = "1.3.6.1.4.1.99999.950.2=PRIMARY TEAM+bindExactAlias=Alice,OU=PEOPLE,bindExactAlias=Tenant,DC=EXAMPLE,DC=COM"
	const canonicalUpperUser = "bindExactName=Alice+bindFoldName=PRIMARY TEAM,ou=PEOPLE,bindExactName=Tenant,dc=EXAMPLE,dc=COM"
	const whoAmIUpperUser = "bindexactname=Alice+bindfoldname=PRIMARY TEAM,ou=PEOPLE,bindexactname=Tenant,dc=EXAMPLE,dc=COM"
	const equivalentUpperRoot = "bindFoldAlias=ROOT TEAM+1.3.6.1.4.1.99999.950.1=Admin,bindExactAlias=Tenant,DC=EXAMPLE,DC=COM"
	const whoAmIUpperRoot = "bindexactname=Admin+bindfoldname=ROOT TEAM,bindexactname=Tenant,dc=EXAMPLE,dc=COM"
	const equivalentLowerRoot = "bindFoldAlias=root team+bindExactAlias=admin,1.3.6.1.4.1.99999.950.1=tenant,DC=EXAMPLE,DC=COM"
	const whoAmILowerRoot = "bindexactname=admin+bindfoldname=root team,bindexactname=tenant,dc=EXAMPLE,dc=COM"

	t.Run("caseExact siblings do not share credentials", func(t *testing.T) {
		assertDNIdentityBindEntryFailure(
			t, address, dnIdentityBindEntryLowerUser, "upper-user-secret",
		)
		assertDNIdentityBindEntryFailure(
			t, address, equivalentUpperUser, "lower-user-secret",
		)
		assertDNIdentityBindEntrySuccess(
			t,
			address,
			dnIdentityBindEntryLowerUser,
			"lower-user-secret",
			"dn:bindexactname=alice+bindfoldname=Primary Team,ou=people,bindexactname=Tenant,dc=example,dc=com",
		)
	})

	t.Run("caseIgnore aliases OIDs and multiAVA bind equivalently", func(t *testing.T) {
		assertDNIdentityBindEntrySuccess(
			t,
			address,
			equivalentUpperUser,
			"upper-user-secret",
			"dn:"+whoAmIUpperUser,
		)
	})

	t.Run("database routing and roots use schema identity", func(t *testing.T) {
		assertDNIdentityBindEntryFailure(
			t, address, equivalentUpperRoot, "lower-root-secret",
		)
		assertDNIdentityBindEntrySuccess(
			t,
			address,
			equivalentUpperRoot,
			"upper-root-secret",
			"dn:"+whoAmIUpperRoot,
		)
		assertDNIdentityBindEntrySuccess(
			t,
			address,
			equivalentLowerRoot,
			"lower-root-secret",
			"dn:"+whoAmILowerRoot,
		)
	})

	t.Run("authenticate and root checks use schema identity", func(t *testing.T) {
		authenticated, err := instance.authenticate(
			context.Background(), runtime, equivalentUpperUser, []byte("upper-user-secret"),
		)
		if err != nil || !authenticated {
			t.Fatalf("authenticate(schema-equivalent user) = %t, %v", authenticated, err)
		}
		authenticated, err = instance.authenticate(
			context.Background(), runtime, dnIdentityBindEntryLowerUser, []byte("upper-user-secret"),
		)
		if err != nil || authenticated {
			t.Fatalf("authenticate(caseExact sibling) = %t, %v", authenticated, err)
		}
		authenticated, err = instance.authenticate(
			context.Background(), runtime, equivalentUpperRoot, []byte("upper-root-secret"),
		)
		if err != nil || !authenticated {
			t.Fatalf("authenticate(schema-equivalent root) = %t, %v", authenticated, err)
		}
		authenticated, err = instance.authenticate(
			context.Background(), runtime, equivalentUpperRoot, []byte("lower-root-secret"),
		)
		if err != nil || authenticated {
			t.Fatalf("authenticate(root from sibling database) = %t, %v", authenticated, err)
		}
		if !instance.isRoot(runtime, equivalentUpperRoot, dnIdentityBindEntryUpperUser, "userPassword") {
			t.Fatal("schema-equivalent root was not recognized")
		}
		if !instance.isRoot(runtime, equivalentUpperRoot, "", "children") {
			t.Fatal("schema-equivalent root was not recognized at the root DSE")
		}
		if instance.isRoot(runtime, equivalentLowerRoot, dnIdentityBindEntryUpperUser, "userPassword") {
			t.Fatal("root from caseExact sibling database was accepted")
		}
	})

	t.Run("successful state uses canonical DN", func(t *testing.T) {
		dn, err := parseRuntimeConnectionDN(runtime, equivalentUpperUser)
		if err != nil {
			t.Fatalf("parseRuntimeConnectionDN(): %v", err)
		}
		state := &connectionState{
			boundDN:                    equivalentUpperUser,
			bindCredentialDN:           equivalentUpperUser,
			passwordPolicyRestrictedDN: equivalentUpperUser,
		}
		canonicalizeBindEntryState(state, dn)
		if state.boundDN != canonicalUpperUser ||
			state.bindCredentialDN != canonicalUpperUser ||
			state.passwordPolicyRestrictedDN != canonicalUpperUser {
			t.Fatalf("canonical Bind state = %#v", state)
		}
	})
}

func dnIdentityBindEntryImport(
	t *testing.T,
	store storage.Store,
	database string,
	ldif string,
	skipSchemaValidation bool,
) {
	t.Helper()
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(ldif),
		migration.ImportOptions{
			Database:             database,
			Replace:              true,
			SkipSchemaValidation: skipSchemaValidation,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(database=%s): %v", database, err)
	}
}

func startDNIdentityBindEntryServer(
	t *testing.T,
	store storage.Store,
) (string, *Server, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
	return fmt.Sprint(listener.Addr()), instance, stop
}

func assertDNIdentityBindEntrySuccess(
	t *testing.T,
	address string,
	dn string,
	password string,
	wantAuthzID string,
) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(dn, password); err != nil {
		t.Fatalf("Bind(%q): %v", dn, err)
	}
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != wantAuthzID {
		t.Fatalf("WhoAmI(%q) = %#v, %v; want %q", dn, identity, err, wantAuthzID)
	}
}

func assertDNIdentityBindEntryFailure(
	t *testing.T,
	address string,
	dn string,
	password string,
) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	err = client.Bind(dn, password)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("Bind(%q) error = %v, want invalid credentials", dn, err)
	}
}
