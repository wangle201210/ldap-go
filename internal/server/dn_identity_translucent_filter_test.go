package server

import (
	"fmt"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	translucentDNIdentityBaseDN   = "dc=translucent,dc=test"
	translucentDNIdentityExactOID = "1.3.6.1.4.1.99999.931.1"
	translucentDNIdentityFoldOID  = "1.3.6.1.4.1.99999.931.2"
)

const translucentDNIdentityConfigPrefix = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}translucent-dn-identity,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}translucent-dn-identity
olcAttributeTypes: ( 1.3.6.1.4.1.99999.931.1 NAME ( 'translucentExactName' 'texact' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.931.2 NAME ( 'translucentFoldName' 'tfold' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.931.3 NAME 'translucentDNIdentityEntry' SUP top STRUCTURAL MUST ( cn $ uid ) MAY ( translucentExactName $ translucentFoldName $ description ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=translucent,dc=test
olcRootDN: cn=admin,dc=translucent,dc=test
olcRootPW: admin-secret
olcAccess: {0}to * by * read

`

const translucentDNIdentityOverlayConfig = `dn: olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcTranslucentConfig
olcOverlay: {0}translucent
olcTranslucentLocal: description
olcTranslucentRemote: cn

dn: olcDatabase={0}ldap,olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcTranslucentDatabase
olcDatabase: {0}ldap
olcDbURI: %s

`

const translucentDNIdentityRemoteLDIF = `dn: dc=translucent,dc=test
objectClass: top
objectClass: domain
dc: translucent

dn: translucentExactName=Alice+uid=alpha,dc=translucent,dc=test
objectClass: top
objectClass: translucentDNIdentityEntry
cn: Exact Upper
uid: alpha
translucentExactName: Alice
description: remote-upper

dn: translucentExactName=alice+uid=alpha,dc=translucent,dc=test
objectClass: top
objectClass: translucentDNIdentityEntry
cn: Exact Lower
uid: alpha
translucentExactName: alice
description: remote-lower

dn: translucentFoldName=Alice Smith+uid=fold,dc=translucent,dc=test
objectClass: top
objectClass: translucentDNIdentityEntry
cn: Folded Name
uid: fold
translucentFoldName: Alice Smith
description: remote-fold

dn: translucentFoldName=Filter User+uid=filter,dc=translucent,dc=test
objectClass: top
objectClass: translucentDNIdentityEntry
cn: Filter Candidate
uid: filter
translucentFoldName: Filter User
description: remote-filter

`

const translucentDNIdentityLocalLDIF = `dn: dc=translucent,dc=test
objectClass: top
objectClass: domain
dc: translucent

dn: uid=alpha+1.3.6.1.4.1.99999.931.1=Alice,DC=TRANSLUCENT,DC=TEST
description: local-upper

dn: uid=fold+tfold=\20ALICE\20\20SMITH\20,0.9.2342.19200300.100.1.25=TRANSLUCENT,dc=TEST
description: local-fold

dn: uid=filter+1.3.6.1.4.1.99999.931.2=Filter User,dc=translucent,dc=test
description: local-miss

dn: uid=stale+tfold=Stale User,dc=translucent,dc=test
description: local-stale

`

func TestDNIdentityTranslucentFilterSearchMerge(t *testing.T) {
	for _, backend := range dnIdentityOverlayStoreFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			client := startDNIdentityTranslucentFilterRuntime(t, backend.open)

			entries := searchDNIdentityTranslucentEntries(
				t,
				client,
				"0.9.2342.19200300.100.1.25=TRANSLUCENT,DC=TEST",
				ldap.ScopeSingleLevel,
				"(objectClass=*)",
			)
			assertDNIdentityTranslucentDescriptions(t, entries, map[string]string{
				"Exact Upper":      "local-upper",
				"Exact Lower":      "remote-lower",
				"Folded Name":      "local-fold",
				"Filter Candidate": "local-miss",
			})

			wantOrder := translucentEntryCNs(entries)
			if !slices.Equal(wantOrder, []string{
				"Exact Upper",
				"Exact Lower",
				"Folded Name",
				"Filter Candidate",
			}) {
				t.Fatalf("translucent result order = %q", wantOrder)
			}
			for iteration := 0; iteration < 10; iteration++ {
				repeated := searchDNIdentityTranslucentEntries(
					t,
					client,
					translucentDNIdentityBaseDN,
					ldap.ScopeSingleLevel,
					"(objectClass=*)",
				)
				if got := translucentEntryCNs(repeated); !slices.Equal(got, wantOrder) {
					t.Fatalf(
						"translucent result order on iteration %d = %q, want %q",
						iteration,
						got,
						wantOrder,
					)
				}
			}

			equivalentBase := fmt.Sprintf(
				"uid=fold+%s=\\20alice\\20smith\\20,DC=TRANSLUCENT,DC=TEST",
				translucentDNIdentityFoldOID,
			)
			merged := searchDNIdentityTranslucentEntries(
				t,
				client,
				equivalentBase,
				ldap.ScopeBaseObject,
				"(description=local-fold)",
			)
			assertDNIdentityTranslucentDescriptions(t, merged, map[string]string{
				"Folded Name": "local-fold",
			})

			stale := searchDNIdentityTranslucentEntries(
				t,
				client,
				translucentDNIdentityBaseDN,
				ldap.ScopeSingleLevel,
				"(description=local-stale)",
			)
			if len(stale) != 0 {
				t.Fatalf("stale local-only entry was visible: %#v", stale)
			}

			rechecked := searchDNIdentityTranslucentEntries(
				t,
				client,
				translucentDNIdentityBaseDN,
				ldap.ScopeSingleLevel,
				"(&(cn=Filter Candidate)(description=remote-filter))",
			)
			if len(rechecked) != 0 {
				t.Fatalf("filter recheck returned locally shadowed entry: %#v", rechecked)
			}
		})
	}
}

func startDNIdentityTranslucentFilterRuntime(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) *ldap.Conn {
	t.Helper()
	remoteAddress := startDNIdentityOverlayFixture(
		t,
		openStore(t),
		translucentDNIdentityConfigPrefix,
		translucentDNIdentityRemoteLDIF,
	)
	localAddress := startDNIdentityOverlayFixture(
		t,
		openStore(t),
		translucentDNIdentityConfigPrefix+fmt.Sprintf(
			translucentDNIdentityOverlayConfig,
			"ldap://"+remoteAddress,
		),
		translucentDNIdentityLocalLDIF,
	)
	return dialDNIdentityOverlayRoot(
		t,
		localAddress,
		"cn=admin,"+translucentDNIdentityBaseDN,
	)
}

func searchDNIdentityTranslucentEntries(
	t *testing.T,
	client *ldap.Conn,
	baseDN string,
	scope int,
	filter string,
) []*ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"cn", "description"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(base=%q, scope=%d, filter=%q): %v", baseDN, scope, filter, err)
	}
	return result.Entries
}

func assertDNIdentityTranslucentDescriptions(
	t *testing.T,
	entries []*ldap.Entry,
	want map[string]string,
) {
	t.Helper()
	if len(entries) != len(want) {
		t.Fatalf("translucent entries = %#v, want %d", entries, len(want))
	}
	for _, entry := range entries {
		cn := entry.GetAttributeValue("cn")
		wantDescription, ok := want[cn]
		if !ok {
			t.Fatalf("unexpected translucent entry %q with cn %q", entry.DN, cn)
		}
		if got := entry.GetAttributeValue("description"); got != wantDescription {
			t.Fatalf(
				"translucent entry %q description = %q, want %q",
				entry.DN,
				got,
				wantDescription,
			)
		}
	}
}

func translucentEntryCNs(entries []*ldap.Entry) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.GetAttributeValue("cn")
	}
	return result
}
