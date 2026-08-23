package server

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityOverlayBaseDN  = "dc=example,dc=com"
	dnIdentityOverlayUpperDN = "overlayexactname=Alice," + dnIdentityOverlayBaseDN
	dnIdentityOverlayLowerDN = "overlayexactname=alice," + dnIdentityOverlayBaseDN
	dnIdentityOverlayFoldDN  = "overlayfoldname=Alice Smith," + dnIdentityOverlayBaseDN
)

const dnIdentityOverlayConfigPrefix = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}dnidentity-overlay,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}dnidentity-overlay
olcAttributeTypes: ( 1.3.6.1.4.1.99999.915.1 NAME 'overlayexactname' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.915.2 NAME 'overlayfoldname' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.915.3 NAME 'dnIdentityOverlayEntry' SUP top STRUCTURAL MUST cn MAY ( overlayexactname $ overlayfoldname $ description ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=admin,dc=example,dc=com
olcRootPW: admin-secret
olcAccess: {0}to * by * read

`

const dnIdentityOverlayContentLDIF = `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: overlayexactname=Alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityOverlayEntry
cn: Exact Upper
overlayexactname: Alice
description: remote-upper

dn: overlayexactname=alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityOverlayEntry
cn: Exact Lower
overlayexactname: alice
description: remote-lower

dn: overlayfoldname=Alice Smith,dc=example,dc=com
objectClass: top
objectClass: dnIdentityOverlayEntry
cn: Folded Name
overlayfoldname: Alice Smith
description: remote-fold

dn: cn=exact-members,dc=example,dc=com
objectClass: top
objectClass: groupOfUniqueNames
cn: exact-members
uniqueMember: overlayexactname=Alice,dc=example,dc=com

`

const dnIdentityOverlayRelayConfigLDIF = `dn: olcDatabase={2}relay,cn=config
objectClass: olcDatabaseConfig
objectClass: olcRelayConfig
olcDatabase: {2}relay
olcSuffix: dc=virtual,dc=test
olcRelay: dc=example,dc=com
olcAccess: {0}to * by * read

dn: olcOverlay={0}rwm,olcDatabase={2}relay,cn=config
objectClass: olcOverlayConfig
objectClass: olcRwmConfig
olcOverlay: {0}rwm
olcRwmRewrite: {0}rwm-suffixmassage "dc=virtual,dc=test" "dc=example,dc=com"
olcRwmMap: {0}attribute member uniqueMember

`

const dnIdentityOverlayRelayPassthroughConfigLDIF = `dn: olcDatabase={2}relay,cn=config
objectClass: olcDatabaseConfig
objectClass: olcRelayConfig
olcDatabase: {2}relay
olcSuffix: ou=relay,dc=example,dc=com
olcRelay: dc=example,dc=com
olcAccess: {0}to * by * read

`

const dnIdentityOverlayRelayPassthroughEntriesLDIF = `dn: ou=relay,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: relay

dn: overlayexactname=Alice,ou=relay,dc=example,dc=com
objectClass: top
objectClass: dnIdentityOverlayEntry
cn: Relay Exact Upper
overlayexactname: Alice

dn: overlayexactname=alice,ou=relay,dc=example,dc=com
objectClass: top
objectClass: dnIdentityOverlayEntry
cn: Relay Exact Lower
overlayexactname: alice

dn: overlayfoldname=Alice Smith,ou=relay,dc=example,dc=com
objectClass: top
objectClass: dnIdentityOverlayEntry
cn: Relay Folded Name
overlayfoldname: Alice Smith

`

const dnIdentityOverlayTranslucentConfigLDIF = `dn: olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcTranslucentConfig
olcOverlay: {0}translucent
olcTranslucentLocal: description

dn: olcDatabase={0}ldap,olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcTranslucentDatabase
olcDatabase: {0}ldap
olcDbURI: %s

`

const dnIdentityOverlayLocalOverridesLDIF = `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: overlayexactname=Alice,dc=example,dc=com
description: local-upper

dn: overlayfoldname=Alice Smith,dc=example,dc=com
description: local-fold

`

type dnIdentityOverlayStoreFactory struct {
	name string
	open func(*testing.T) storage.Store
}

func TestDNIdentityOverlayRuntimeOpenLDAPSemantics(t *testing.T) {
	for _, backend := range dnIdentityOverlayStoreFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Run("alias dereference", func(t *testing.T) {
				t.Run("caseExact aliases that differ only by case are not a loop", func(t *testing.T) {
					client := startDNIdentityAliasRuntime(t, backend.open)
					addDNIdentityOverlayAlias(
						t,
						client,
						"overlayexactname=proxy,"+dnIdentityOverlayBaseDN,
						"overlayexactname",
						"proxy",
						dnIdentityOverlayUpperDN,
					)
					addDNIdentityOverlayAlias(
						t,
						client,
						"overlayexactname=Proxy,"+dnIdentityOverlayBaseDN,
						"overlayexactname",
						"Proxy",
						"overlayexactname=proxy,"+dnIdentityOverlayBaseDN,
					)

					entry := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayexactname=Proxy,"+dnIdentityOverlayBaseDN,
						ldap.DerefFindingBaseObj,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(t, entry, dnIdentityOverlayUpperDN, "Exact Upper")
				})

				t.Run("caseIgnore alias and target accept equivalent DNs", func(t *testing.T) {
					client := startDNIdentityAliasRuntime(t, backend.open)
					addDNIdentityOverlayAlias(
						t,
						client,
						"overlayfoldname=Lookup User,"+dnIdentityOverlayBaseDN,
						"overlayfoldname",
						"Lookup User",
						"overlayfoldname=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
					)

					entry := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayfoldname=\\20LOOKUP\\20\\20USER\\20,DC=EXAMPLE,DC=COM",
						ldap.DerefFindingBaseObj,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(t, entry, dnIdentityOverlayFoldDN, "Folded Name")
				})
			})

			t.Run("relay passthrough", func(t *testing.T) {
				t.Run("caseExact bases remain distinct", func(t *testing.T) {
					client := startDNIdentityRelayPassthroughRuntime(t, backend.open)
					upper := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayexactname=Alice,ou=relay,dc=example,dc=com",
						ldap.NeverDerefAliases,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(
						t,
						upper,
						"overlayexactname=Alice,ou=relay,dc=example,dc=com",
						"Relay Exact Upper",
					)

					lower := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayexactname=alice,ou=relay,dc=example,dc=com",
						ldap.NeverDerefAliases,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(
						t,
						lower,
						"overlayexactname=alice,ou=relay,dc=example,dc=com",
						"Relay Exact Lower",
					)
				})

				t.Run("caseIgnore equivalent base reaches the target partition", func(t *testing.T) {
					client := startDNIdentityRelayPassthroughRuntime(t, backend.open)
					entry := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayfoldname=\\20ALICE\\20\\20SMITH\\20,OU=RELAY,DC=EXAMPLE,DC=COM",
						ldap.NeverDerefAliases,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(
						t,
						entry,
						"overlayfoldname=Alice Smith,ou=relay,dc=example,dc=com",
						"Relay Folded Name",
					)
				})
			})

			t.Run("relay with RWM", func(t *testing.T) {
				t.Run("caseExact bases remain distinct through suffix massage", func(t *testing.T) {
					client := startDNIdentityRelayRuntime(t, backend.open)
					upper := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayexactname=Alice,dc=virtual,dc=test",
						ldap.NeverDerefAliases,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(
						t,
						upper,
						"overlayexactname=Alice,dc=virtual,dc=test",
						"Exact Upper",
					)

					lower := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayexactname=alice,dc=virtual,dc=test",
						ldap.NeverDerefAliases,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(
						t,
						lower,
						"overlayexactname=alice,dc=virtual,dc=test",
						"Exact Lower",
					)
				})

				t.Run("caseIgnore equivalent base reaches the target partition", func(t *testing.T) {
					client := startDNIdentityRelayRuntime(t, backend.open)
					entry := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayfoldname=\\20ALICE\\20\\20SMITH\\20,DC=VIRTUAL,DC=TEST",
						ldap.NeverDerefAliases,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayEntry(
						t,
						entry,
						"overlayfoldname=Alice Smith,dc=virtual,dc=test",
						"Folded Name",
					)
				})

				t.Run("DN-valued attributes are rewritten back to the virtual suffix", func(t *testing.T) {
					client := startDNIdentityRelayRuntime(t, backend.open)
					entry := searchDNIdentityOverlayBase(
						t,
						client,
						"cn=exact-members,dc=virtual,dc=test",
						ldap.NeverDerefAliases,
						"(objectClass=*)",
					)
					assertDNIdentityOverlayMappedReference(
						t,
						entry.GetAttributeValue("member"),
					)
				})
			})

			t.Run("translucent proxy", func(t *testing.T) {
				t.Run("caseExact remote entries do not collapse during merge", func(t *testing.T) {
					client := startDNIdentityTranslucentRuntime(t, backend.open)
					result, err := client.Search(ldap.NewSearchRequest(
						dnIdentityOverlayBaseDN,
						ldap.ScopeWholeSubtree,
						ldap.NeverDerefAliases,
						0,
						0,
						false,
						"(overlayexactname=*)",
						[]string{"cn", "overlayexactname", "description"},
						nil,
					))
					if err != nil {
						t.Fatalf("Search(translucent caseExact subtree): %v", err)
					}
					if len(result.Entries) != 2 {
						t.Fatalf(
							"Search(translucent caseExact subtree) returned %d entries, want 2: %#v",
							len(result.Entries),
							result.Entries,
						)
					}
					entries := make(map[string]*ldap.Entry, len(result.Entries))
					for _, entry := range result.Entries {
						entries[entry.GetAttributeValue("overlayexactname")] = entry
					}
					upper := entries["Alice"]
					lower := entries["alice"]
					if upper == nil || lower == nil {
						t.Fatalf("translucent caseExact entries = %#v, want Alice and alice", entries)
					}
					if got := upper.GetAttributeValue("description"); got != "local-upper" {
						t.Fatalf("upper translucent description = %q, want local-upper", got)
					}
					if got := lower.GetAttributeValue("description"); got != "remote-lower" {
						t.Fatalf("lower translucent description = %q, want remote-lower", got)
					}
				})

				t.Run("caseIgnore equivalent base participates in local filtering", func(t *testing.T) {
					client := startDNIdentityTranslucentRuntime(t, backend.open)
					entry := searchDNIdentityOverlayBase(
						t,
						client,
						"overlayfoldname=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
						ldap.NeverDerefAliases,
						"(description=local-fold)",
					)
					assertDNIdentityOverlayEntry(t, entry, dnIdentityOverlayFoldDN, "Folded Name")
					if got := entry.GetAttributeValue("description"); got != "local-fold" {
						t.Fatalf("caseIgnore translucent description = %q, want local-fold", got)
					}
				})
			})
		})
	}
}

func dnIdentityOverlayStoreFactories() []dnIdentityOverlayStoreFactory {
	return []dnIdentityOverlayStoreFactory{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) storage.Store {
				t.Helper()
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}
}

func startDNIdentityAliasRuntime(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) *ldap.Conn {
	t.Helper()
	store := openStore(t)
	address := startDNIdentityOverlayFixture(
		t,
		store,
		dnIdentityOverlayConfigPrefix,
		dnIdentityOverlayContentLDIF,
	)
	return dialDNIdentityOverlayRoot(t, address, "cn=admin,dc=example,dc=com")
}

func startDNIdentityRelayRuntime(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) *ldap.Conn {
	t.Helper()
	store := openStore(t)
	address := startDNIdentityOverlayFixture(
		t,
		store,
		dnIdentityOverlayConfigPrefix+dnIdentityOverlayRelayConfigLDIF,
		dnIdentityOverlayContentLDIF,
	)
	return dialDNIdentityOverlayRoot(t, address, "cn=admin,dc=virtual,dc=test")
}

func startDNIdentityRelayPassthroughRuntime(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) *ldap.Conn {
	t.Helper()
	store := openStore(t)
	importDNIdentityOverlayFixture(
		t,
		store,
		dnIdentityOverlayConfigPrefix,
		dnIdentityOverlayContentLDIF+dnIdentityOverlayRelayPassthroughEntriesLDIF,
	)
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dnIdentityOverlayRelayPassthroughConfigLDIF),
		migration.ImportOptions{
			Database:             "0",
			SkipSchemaValidation: true,
		},
	); err != nil {
		_ = store.Close()
		t.Fatalf("ImportLDIF(relay passthrough config): %v", err)
	}
	address := startDNIdentityOverlayServer(t, store)
	return dialDNIdentityOverlayRoot(t, address, "cn=admin,dc=example,dc=com")
}

func startDNIdentityTranslucentRuntime(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) *ldap.Conn {
	t.Helper()
	remoteStore := openStore(t)
	remoteAddress := startDNIdentityOverlayFixture(
		t,
		remoteStore,
		dnIdentityOverlayConfigPrefix,
		dnIdentityOverlayContentLDIF,
	)

	localStore := openStore(t)
	localConfig := dnIdentityOverlayConfigPrefix + fmt.Sprintf(
		dnIdentityOverlayTranslucentConfigLDIF,
		"ldap://"+remoteAddress,
	)
	localAddress := startDNIdentityOverlayFixture(
		t,
		localStore,
		localConfig,
		dnIdentityOverlayLocalOverridesLDIF,
	)
	return dialDNIdentityOverlayRoot(t, localAddress, "cn=admin,dc=example,dc=com")
}

func startDNIdentityOverlayFixture(
	t *testing.T,
	store storage.Store,
	configLDIF string,
	contentLDIF string,
) string {
	t.Helper()
	importDNIdentityOverlayFixture(t, store, configLDIF, contentLDIF)
	return startDNIdentityOverlayServer(t, store)
}

func importDNIdentityOverlayFixture(
	t *testing.T,
	store storage.Store,
	configLDIF string,
	contentLDIF string,
) {
	t.Helper()
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
		_ = store.Close()
		t.Fatalf("ImportLDIF(cn=config): %v", err)
	}
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(contentLDIF),
		migration.ImportOptions{
			Database:             "1",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		_ = store.Close()
		t.Fatalf("ImportLDIF(content): %v", err)
	}
}

func startDNIdentityOverlayServer(t *testing.T, store storage.Store) string {
	t.Helper()
	address, stop := startServer(t, store, Config{})
	t.Cleanup(func() {
		stop()
		_ = store.Close()
	})
	return address
}

func dialDNIdentityOverlayRoot(
	t *testing.T,
	address string,
	bindDN string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind(bindDN, "admin-secret"); err != nil {
		t.Fatalf("Bind(%q): %v", bindDN, err)
	}
	return client
}

func addDNIdentityOverlayAlias(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	namingAttribute string,
	namingValue string,
	targetDN string,
) {
	t.Helper()
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"top", "alias", "extensibleObject"})
	request.Attribute(namingAttribute, []string{namingValue})
	request.Attribute("aliasedObjectName", []string{targetDN})
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(alias %q -> %q): %v", dn, targetDN, err)
	}
}

func searchDNIdentityOverlayBase(
	t *testing.T,
	client *ldap.Conn,
	baseDN string,
	derefAliases int,
	filter string,
) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		derefAliases,
		0,
		0,
		false,
		filter,
		[]string{
			"cn",
			"overlayexactname",
			"overlayfoldname",
			"description",
			"member",
		},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(base=%q, deref=%d, filter=%q): %v", baseDN, derefAliases, filter, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf(
			"Search(base=%q, deref=%d, filter=%q) returned %d entries, want 1: %#v",
			baseDN,
			derefAliases,
			filter,
			len(result.Entries),
			result.Entries,
		)
	}
	return result.Entries[0]
}

func assertDNIdentityOverlayEntry(
	t *testing.T,
	entry *ldap.Entry,
	wantDN string,
	wantCN string,
) {
	t.Helper()
	if entry.DN != wantDN {
		t.Fatalf("entry DN = %q, want %q", entry.DN, wantDN)
	}
	if got := entry.GetAttributeValue("cn"); got != wantCN {
		t.Fatalf("entry %q cn = %q, want %q", entry.DN, got, wantCN)
	}
}

func assertDNIdentityOverlayMappedReference(t *testing.T, value string) {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(RWM member %q): %v", value, err)
	}
	rdn := dn.RDNValues()
	if len(rdn) != 1 ||
		!strings.EqualFold(rdn[0].Type, "overlayexactname") ||
		string(rdn[0].Value) != "Alice" {
		t.Fatalf("RWM member RDN = %#v, want caseExact overlayexactname=Alice", rdn)
	}
	parent, ok := dn.Parent()
	if !ok || parent.String() != "dc=virtual,dc=test" {
		t.Fatalf("RWM member parent = %q, want dc=virtual,dc=test", parent.String())
	}
}
