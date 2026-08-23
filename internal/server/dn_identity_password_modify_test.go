package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityPasswordModifyUpperDN = "passwordModifyExactName=Alice+passwordModifyFoldName=Primary Team,ou=people,passwordModifyExactName=Tenant,dc=example,dc=com"
	dnIdentityPasswordModifyLowerDN = "passwordModifyExactName=alice+passwordModifyFoldName=Primary Team,ou=people,passwordModifyExactName=Tenant,dc=example,dc=com"
	dnIdentityPasswordModifyRootDN  = "passwordModifyExactName=Admin+passwordModifyFoldName=Root Team,ou=people,passwordModifyExactName=Tenant,dc=example,dc=com"
)

const dnIdentityPasswordModifyConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}passwordmodifydn,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}passwordmodifydn
olcAttributeTypes: ( 1.3.6.1.4.1.99999.933.1 NAME ( 'passwordModifyExactName' 'passwordModifyExactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.933.2 NAME ( 'passwordModifyFoldName' 'passwordModifyFoldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.933.3 NAME 'passwordModifyIdentityEntry' SUP top STRUCTURAL MUST cn MAY ( sn $ userPassword $ passwordModifyExactName $ passwordModifyFoldName ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: passwordModifyExactName=Tenant,dc=example,dc=com
olcRootDN: passwordModifyExactName=Admin+passwordModifyFoldName=Root Team,ou=people,passwordModifyExactName=Tenant,dc=example,dc=com
olcRootPW: root-secret
olcAccess: {0}to attrs=userPassword by self =xw by anonymous auth by * none
olcAccess: {1}to * by self write by users read by * none

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: passwordModifyExactName=tenant,dc=example,dc=com
olcAccess: {0}to * by * read

`

const dnIdentityPasswordModifyContentLDIF = `dn: passwordModifyExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: passwordModifyIdentityEntry
cn: Tenant
sn: Tenant
passwordModifyExactName: Tenant

dn: ou=people,passwordModifyExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: passwordModifyExactName=Alice+passwordModifyFoldName=Primary Team,ou=people,passwordModifyExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: passwordModifyIdentityEntry
cn: Upper Alice
sn: Alice
passwordModifyExactName: Alice
passwordModifyFoldName: Primary Team
userPassword: upper-secret

dn: passwordModifyExactName=alice+passwordModifyFoldName=Primary Team,ou=people,passwordModifyExactName=Tenant,dc=example,dc=com
objectClass: top
objectClass: passwordModifyIdentityEntry
cn: Lower Alice
sn: alice
passwordModifyExactName: alice
passwordModifyFoldName: Primary Team
userPassword: lower-secret

`

func TestDNIdentityPasswordModify(t *testing.T) {
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
			testDNIdentityPasswordModify(t, backend.open)
		})
	}
}

func testDNIdentityPasswordModify(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	dnIdentityPasswordModifyImport(t, store, "0", dnIdentityPasswordModifyConfigLDIF, true)
	dnIdentityPasswordModifyImport(t, store, "1", dnIdentityPasswordModifyContentLDIF, false)

	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)

	equivalentUpper := `1.3.6.1.4.1.99999.933.2=\20PRIMARY\20\20TEAM\20+passwordModifyExactAlias=Alice,OU=PEOPLE,passwordModifyExactAlias=Tenant,DC=EXAMPLE,DC=COM`
	equivalentRoot := `passwordModifyFoldAlias=\20ROOT\20\20TEAM\20+passwordModifyExactAlias=Admin,OU=PEOPLE,1.3.6.1.4.1.99999.933.1=Tenant,DC=EXAMPLE,DC=COM`

	t.Run("caseExact sibling is not self", func(t *testing.T) {
		lower := dnIdentityPasswordModifyBind(t, address, dnIdentityPasswordModifyLowerDN, "lower-secret")
		defer lower.Close()
		_, err := lower.PasswordModify(ldap.NewPasswordModifyRequest(
			dnIdentityPasswordModifyUpperDN,
			"",
			"sibling-overwrite",
		))
		dnIdentityPasswordModifyResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)
		dnIdentityPasswordModifyAssertBind(t, address, dnIdentityPasswordModifyUpperDN, "upper-secret", true)
		dnIdentityPasswordModifyAssertBind(t, address, dnIdentityPasswordModifyUpperDN, "sibling-overwrite", false)
	})

	t.Run("self accepts aliases OIDs caseIgnore and multiAVA", func(t *testing.T) {
		upper := dnIdentityPasswordModifyBind(t, address, equivalentUpper, "upper-secret")
		defer upper.Close()
		if _, err := upper.PasswordModify(ldap.NewPasswordModifyRequest(
			equivalentUpper,
			"upper-secret",
			"self-updated",
		)); err != nil {
			t.Fatalf("PasswordModify(schema-equivalent self): %v", err)
		}
		dnIdentityPasswordModifyAssertBind(t, address, dnIdentityPasswordModifyUpperDN, "upper-secret", false)
		dnIdentityPasswordModifyAssertBind(t, address, equivalentUpper, "self-updated", true)
	})

	t.Run("wrong old password preserves entry", func(t *testing.T) {
		upper := dnIdentityPasswordModifyBind(t, address, equivalentUpper, "self-updated")
		defer upper.Close()
		_, err := upper.PasswordModify(ldap.NewPasswordModifyRequest(
			equivalentUpper,
			"wrong-old-password",
			"not-stored",
		))
		dnIdentityPasswordModifyResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
		dnIdentityPasswordModifyAssertBind(t, address, equivalentUpper, "self-updated", true)
		dnIdentityPasswordModifyAssertBind(t, address, equivalentUpper, "not-stored", false)
	})

	generatedPassword := ""
	t.Run("generated password uses normalized target", func(t *testing.T) {
		upper := dnIdentityPasswordModifyBind(t, address, equivalentUpper, "self-updated")
		defer upper.Close()
		result, err := upper.PasswordModify(ldap.NewPasswordModifyRequest(
			"",
			"self-updated",
			"",
		))
		if err != nil || result == nil || len(result.GeneratedPassword) != generatedPasswordLength {
			t.Fatalf("generated PasswordModify() = %#v, %v", result, err)
		}
		generatedPassword = result.GeneratedPassword
		dnIdentityPasswordModifyAssertBind(t, address, equivalentUpper, generatedPassword, true)
	})

	t.Run("schema-equivalent root may update another entry", func(t *testing.T) {
		root := dnIdentityPasswordModifyBind(t, address, equivalentRoot, "root-secret")
		defer root.Close()
		if _, err := root.PasswordModify(ldap.NewPasswordModifyRequest(
			dnIdentityPasswordModifyLowerDN,
			"",
			"root-updated",
		)); err != nil {
			t.Fatalf("root PasswordModify(): %v", err)
		}
		dnIdentityPasswordModifyAssertBind(t, address, dnIdentityPasswordModifyLowerDN, "lower-secret", false)
		dnIdentityPasswordModifyAssertBind(t, address, dnIdentityPasswordModifyLowerDN, "root-updated", true)
	})

	t.Run("proxied identity updates its own password", func(t *testing.T) {
		connection := dialAndBindRawLDAP(t, address, equivalentRoot, "root-secret")
		defer connection.Close()
		response := sendRawLDAPOperation(
			t,
			connection,
			2,
			rawExtendedRequest(
				passwordModifyOID,
				rawPasswordModifyRequestValue(
					[]byte(generatedPassword),
					[]byte("proxy-updated"),
				),
				true,
			),
			rawProxyAuthorizationControl(
				true,
				[]byte("dn:"+equivalentUpper),
				true,
			),
		)
		assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
		dnIdentityPasswordModifyAssertBind(t, address, equivalentUpper, generatedPassword, false)
		dnIdentityPasswordModifyAssertBind(t, address, equivalentUpper, "proxy-updated", true)
	})
}

func dnIdentityPasswordModifyImport(
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

func dnIdentityPasswordModifyBind(
	t *testing.T,
	address string,
	dn string,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%q): %v", dn, err)
	}
	return client
}

func dnIdentityPasswordModifyAssertBind(
	t *testing.T,
	address string,
	dn string,
	password string,
	want bool,
) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	err = client.Bind(dn, password)
	if want && err != nil {
		t.Fatalf("Bind(%q, password=%q): %v", dn, password, err)
	}
	if !want {
		dnIdentityPasswordModifyResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	}
}

func dnIdentityPasswordModifyResultCode(t *testing.T, err error, want uint16) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != want {
		t.Fatalf("LDAP error = %v, want result code %d", err, want)
	}
}
