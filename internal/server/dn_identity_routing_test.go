package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const dnIdentityRoutingConfigPrefix = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}dnidentityrouting,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}dnidentityrouting
olcAttributeTypes: ( 1.3.6.1.4.1.99999.915.1 NAME 'exactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.915.2 NAME 'foldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.915.3 NAME 'dnIdentityRoutingEntry' SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

`

const dnIdentityRoutingExactContent = `dn: exactName=Tenant
objectClass: top
objectClass: dnIdentityRoutingEntry
cn: Exact Tenant
exactName: Tenant

`

const dnIdentityRoutingFoldContent = `dn: foldName=Remote Tenant
objectClass: top
objectClass: dnIdentityRoutingEntry
cn: Folded Tenant
foldName: Remote Tenant

`

type dnIdentityRoutingContent struct {
	database string
	ldif     string
}

func TestDNIdentityRuntimeRoutingAndAuthentication(t *testing.T) {
	t.Run("database suffix uses naming attribute equality", func(t *testing.T) {
		store := newDNIdentityRoutingStore(
			t,
			dnIdentityRoutingConfig(
				dnIdentityRoutingMDB(
					1,
					"exactName=Tenant",
					"exactName=Admin,exactName=Tenant",
					"exact-secret",
				),
				dnIdentityRoutingMDB(
					2,
					"foldName=Remote Tenant",
					"foldName=Directory Admin,foldName=Remote Tenant",
					"fold-secret",
				),
			),
			[]dnIdentityRoutingContent{
				{database: "1", ldif: dnIdentityRoutingExactContent},
				{database: "2", ldif: dnIdentityRoutingFoldContent},
			},
		)
		address, stop := startServer(t, store, Config{})
		t.Cleanup(stop)
		client := dialDNIdentityRouting(t, address)

		t.Run("caseExact configured value routes", func(t *testing.T) {
			assertDNIdentityRoutingBase(
				t,
				client,
				"exactName=Tenant",
				"exactName=Tenant",
				"Exact Tenant",
			)
		})

		t.Run("caseExact different case does not route", func(t *testing.T) {
			_, err := client.Search(newDNIdentityRoutingBaseSearch("exactName=tenant"))
			assertDNIdentityRoutingResultCode(t, err, ldap.LDAPResultNoSuchObject)
		})

		t.Run("caseIgnore case and space equivalent value routes", func(t *testing.T) {
			assertDNIdentityRoutingBase(
				t,
				client,
				`foldName=\20REMOTE\20\20TENANT\20`,
				"foldName=Remote Tenant",
				"Folded Tenant",
			)
		})
	})

	t.Run("rootDN authentication uses naming attribute equality", func(t *testing.T) {
		store := newDNIdentityRoutingStore(
			t,
			dnIdentityRoutingConfig(
				dnIdentityRoutingMDB(
					1,
					"exactName=Tenant",
					"exactName=Admin,exactName=Tenant",
					"exact-secret",
				),
				dnIdentityRoutingMDB(
					2,
					"foldName=Remote Tenant",
					"foldName=Directory Admin,foldName=Remote Tenant",
					"fold-secret",
				),
			),
			nil,
		)
		address, stop := startServer(t, store, Config{})
		t.Cleanup(stop)

		t.Run("caseExact configured root authenticates", func(t *testing.T) {
			client := dialDNIdentityRouting(t, address)
			if err := client.Bind(
				"exactName=Admin,exactName=Tenant",
				"exact-secret",
			); err != nil {
				t.Fatalf("Bind(configured caseExact rootDN): %v", err)
			}
		})

		t.Run("caseExact different case is not root", func(t *testing.T) {
			client := dialDNIdentityRouting(t, address)
			err := client.Bind(
				"exactName=admin,exactName=Tenant",
				"exact-secret",
			)
			assertDNIdentityRoutingResultCode(
				t,
				err,
				ldap.LDAPResultInvalidCredentials,
			)
		})

		t.Run("caseIgnore case and space equivalent root authenticates", func(t *testing.T) {
			client := dialDNIdentityRouting(t, address)
			if err := client.Bind(
				`foldName=\20DIRECTORY\20\20ADMIN\20,foldName=\20REMOTE\20\20TENANT\20`,
				"fold-secret",
			); err != nil {
				t.Fatalf("Bind(caseIgnore-equivalent rootDN): %v", err)
			}
		})
	})

	t.Run("bootstrap root override uses naming attribute equality", func(t *testing.T) {
		t.Run("caseExact different case is outside naming context", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(1, "exactName=Tenant", "", ""),
				),
				nil,
			)
			instance, err := New(Config{
				Store:        store,
				RootDN:       "exactName=Admin,exactName=tenant",
				RootPassword: []byte("override-secret"),
			})
			if err == nil {
				instance.closeSQLBackends()
				t.Fatal("New() accepted a caseExact-non-equivalent root override")
			}
		})

		t.Run("caseIgnore equivalent root authenticates", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(1, "foldName=Remote Tenant", "", ""),
				),
				nil,
			)
			address, stop := startServer(t, store, Config{
				RootDN:       "foldName=Directory Admin,foldName=Remote Tenant",
				RootPassword: []byte("override-secret"),
			})
			t.Cleanup(stop)
			client := dialDNIdentityRouting(t, address)
			if err := client.Bind(
				`foldName=\20DIRECTORY\20\20ADMIN\20,foldName=\20REMOTE\20\20TENANT\20`,
				"override-secret",
			); err != nil {
				t.Fatalf("Bind(caseIgnore-equivalent root override): %v", err)
			}
		})
	})

	t.Run("relay target uses naming attribute equality", func(t *testing.T) {
		t.Run("caseExact different case is rejected", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(1, "exactName=Tenant", "", ""),
					dnIdentityRoutingRelay(
						2,
						"foldName=Virtual Tenant",
						"exactName=tenant",
						"",
					),
				),
				nil,
			)
			instance, err := New(Config{Store: store})
			if err == nil {
				instance.closeSQLBackends()
				t.Fatal("New() accepted a caseExact-non-equivalent olcRelay target")
			}
		})

		t.Run("caseIgnore case and space equivalent target resolves", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(1, "foldName=Remote Tenant", "", ""),
					dnIdentityRoutingRelay(
						2,
						"exactName=Virtual",
						`foldName=\20REMOTE\20\20TENANT\20`,
						"",
					),
				),
				nil,
			)
			instance, err := New(Config{Store: store})
			if err != nil {
				t.Fatalf("New(caseIgnore-equivalent olcRelay target): %v", err)
			}
			instance.closeSQLBackends()
		})
	})

	t.Run("relay route uses naming attribute equality", func(t *testing.T) {
		t.Run("caseExact different case does not enter relay", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(1, "exactName=Tenant", "", ""),
					dnIdentityRoutingRelay(
						2,
						"exactName=Virtual",
						"exactName=Tenant",
						"exactName=Tenant",
					),
				),
				[]dnIdentityRoutingContent{{
					database: "1",
					ldif:     dnIdentityRoutingExactContent,
				}},
			)
			address, stop := startServer(t, store, Config{})
			t.Cleanup(stop)
			client := dialDNIdentityRouting(t, address)

			assertDNIdentityRoutingBase(
				t,
				client,
				"exactName=Virtual",
				"exactName=Virtual",
				"Exact Tenant",
			)
			_, err := client.Search(newDNIdentityRoutingBaseSearch("exactName=virtual"))
			assertDNIdentityRoutingResultCode(t, err, ldap.LDAPResultNoSuchObject)
		})

		t.Run("caseIgnore case and space equivalent value enters relay", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(1, "foldName=Remote Tenant", "", ""),
					dnIdentityRoutingRelay(
						2,
						"foldName=Virtual Tenant",
						"foldName=Remote Tenant",
						"foldName=Remote Tenant",
					),
				),
				[]dnIdentityRoutingContent{{
					database: "1",
					ldif:     dnIdentityRoutingFoldContent,
				}},
			)
			address, stop := startServer(t, store, Config{})
			t.Cleanup(stop)
			client := dialDNIdentityRouting(t, address)

			assertDNIdentityRoutingBase(
				t,
				client,
				`foldName=\20VIRTUAL\20\20TENANT\20`,
				"foldName=Virtual Tenant",
				"Folded Tenant",
			)
		})
	})

	t.Run("relay root authentication uses mapped naming identity", func(t *testing.T) {
		t.Run("caseExact different case is not mapped root", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(
						1,
						"exactName=Tenant",
						"exactName=Admin,exactName=Tenant",
						"exact-secret",
					),
					dnIdentityRoutingRelay(
						2,
						"exactName=Virtual",
						"exactName=Tenant",
						"exactName=Tenant",
					),
				),
				nil,
			)
			address, stop := startServer(t, store, Config{})
			t.Cleanup(stop)

			configured := dialDNIdentityRouting(t, address)
			if err := configured.Bind(
				"exactName=Admin,exactName=Virtual",
				"exact-secret",
			); err != nil {
				t.Fatalf("Bind(configured mapped caseExact rootDN): %v", err)
			}

			differentCase := dialDNIdentityRouting(t, address)
			err := differentCase.Bind(
				"exactName=admin,exactName=Virtual",
				"exact-secret",
			)
			assertDNIdentityRoutingResultCode(
				t,
				err,
				ldap.LDAPResultInvalidCredentials,
			)
		})

		t.Run("caseIgnore equivalent value maps to root", func(t *testing.T) {
			store := newDNIdentityRoutingStore(
				t,
				dnIdentityRoutingConfig(
					dnIdentityRoutingMDB(
						1,
						"foldName=Remote Tenant",
						"foldName=Directory Admin,foldName=Remote Tenant",
						"fold-secret",
					),
					dnIdentityRoutingRelay(
						2,
						"foldName=Virtual Tenant",
						"foldName=Remote Tenant",
						"foldName=Remote Tenant",
					),
				),
				nil,
			)
			address, stop := startServer(t, store, Config{})
			t.Cleanup(stop)
			client := dialDNIdentityRouting(t, address)
			if err := client.Bind(
				`foldName=\20DIRECTORY\20\20ADMIN\20,foldName=\20VIRTUAL\20\20TENANT\20`,
				"fold-secret",
			); err != nil {
				t.Fatalf("Bind(caseIgnore-equivalent mapped rootDN): %v", err)
			}
		})
	})
}

func dnIdentityRoutingConfig(entries ...string) string {
	return dnIdentityRoutingConfigPrefix + strings.Join(entries, "")
}

func dnIdentityRoutingMDB(
	index int,
	suffix string,
	rootDN string,
	rootPassword string,
) string {
	root := ""
	if rootDN != "" {
		root = fmt.Sprintf("olcRootDN: %s\nolcRootPW: %s\n", rootDN, rootPassword)
	}
	return fmt.Sprintf(`dn: olcDatabase={%d}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {%d}mdb
olcSuffix: %s
%solcAccess: {0}to * by * read

`, index, index, suffix, root)
}

func dnIdentityRoutingRelay(
	index int,
	suffix string,
	target string,
	remoteSuffix string,
) string {
	overlay := ""
	if remoteSuffix != "" {
		overlay = fmt.Sprintf(`dn: olcOverlay={0}rwm,olcDatabase={%d}relay,cn=config
objectClass: olcOverlayConfig
objectClass: olcRwmConfig
olcOverlay: {0}rwm
olcRwmRewrite: {0}rwm-suffixmassage "%s" "%s"

`, index, suffix, remoteSuffix)
	}
	return fmt.Sprintf(`dn: olcDatabase={%d}relay,cn=config
objectClass: olcDatabaseConfig
objectClass: olcRelayConfig
olcDatabase: {%d}relay
olcSuffix: %s
olcRelay: %s
olcAccess: {0}to * by * read

`, index, index, suffix, target) + overlay
}

func newDNIdentityRoutingStore(
	t *testing.T,
	configLDIF string,
	content []dnIdentityRoutingContent,
) storage.Store {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(configLDIF),
		migration.ImportOptions{
			Database:             "0",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(cn=config): %v", err)
	}
	for _, imported := range content {
		if _, err := migration.ImportLDIF(
			context.Background(),
			store,
			strings.NewReader(imported.ldif),
			migration.ImportOptions{
				Database: imported.database,
				Replace:  true,
			},
		); err != nil {
			t.Fatalf("ImportLDIF(database=%s): %v", imported.database, err)
		}
	}
	return store
}

func dialDNIdentityRouting(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newDNIdentityRoutingBaseSearch(dn string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "exactName", "foldName"},
		nil,
	)
}

func assertDNIdentityRoutingBase(
	t *testing.T,
	client *ldap.Conn,
	requestDN string,
	wantDN string,
	wantCN string,
) {
	t.Helper()
	result, err := client.Search(newDNIdentityRoutingBaseSearch(requestDN))
	if err != nil {
		t.Fatalf("Search(base=%q): %v", requestDN, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(base=%q) returned %d entries, want 1", requestDN, len(result.Entries))
	}
	entry := result.Entries[0]
	gotParsed, gotErr := ldap.ParseDN(entry.DN)
	wantParsed, wantErr := ldap.ParseDN(wantDN)
	if gotErr != nil || wantErr != nil || !gotParsed.Equal(wantParsed) {
		t.Fatalf("Search(base=%q) DN = %q, want %q", requestDN, entry.DN, wantDN)
	}
	if got := entry.GetAttributeValues("cn"); len(got) != 1 || got[0] != wantCN {
		t.Fatalf("Search(base=%q) cn = %q, want [%q]", requestDN, got, wantCN)
	}
}

func assertDNIdentityRoutingResultCode(t *testing.T, err error, want uint16) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != want {
		t.Fatalf("LDAP error = %v, want result code %d", err, want)
	}
}
