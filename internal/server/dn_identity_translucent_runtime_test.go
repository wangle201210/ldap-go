package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	translucentRuntimeBaseDN   = "dc=runtime,dc=test"
	translucentRuntimeExactOID = "1.3.6.1.4.1.99999.932.1"
	translucentRuntimeFoldOID  = "1.3.6.1.4.1.99999.932.2"
)

const translucentRuntimeConfigTemplate = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}translucent-runtime,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}translucent-runtime
olcAttributeTypes: ( 1.3.6.1.4.1.99999.932.1 NAME ( '%s' '%s' 'trExact' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.932.2 NAME ( '%s' '%s' 'trFold' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.932.3 NAME 'translucentRuntimeEntry' SUP top STRUCTURAL MUST ( cn $ uid ) MAY ( 1.3.6.1.4.1.99999.932.1 $ 1.3.6.1.4.1.99999.932.2 $ description $ telephoneNumber $ userPassword ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=runtime,dc=test
olcRootDN: cn=admin,dc=runtime,dc=test
olcRootPW: admin-secret
olcAccess: {0}to * by * read

`

const translucentRuntimeOverlayConfig = `dn: olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config
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

const translucentRuntimeRemoteLDIF = `dn: dc=runtime,dc=test
objectClass: top
objectClass: domain
dc: runtime

dn: translucentRemoteExact=Alice+uid=alpha,dc=runtime,dc=test
objectClass: top
objectClass: translucentRuntimeEntry
cn: Exact Upper
uid: alpha
translucentRemoteExact: Alice
description: remote-upper
telephoneNumber: 100
userPassword: upper-secret

dn: translucentRemoteExact=alice+uid=alpha,dc=runtime,dc=test
objectClass: top
objectClass: translucentRuntimeEntry
cn: Exact Lower
uid: alpha
translucentRemoteExact: alice
description: remote-lower
telephoneNumber: 101
userPassword: lower-secret

dn: translucentRemoteFold=Alice Smith+uid=fold,dc=runtime,dc=test
objectClass: top
objectClass: translucentRuntimeEntry
cn: Folded Name
uid: fold
translucentRemoteFold: Alice Smith
description: remote-fold
telephoneNumber: 102
userPassword: fold-secret

`

const translucentRuntimeLocalLDIF = `dn: dc=runtime,dc=test
objectClass: top
objectClass: domain
dc: runtime

dn: uid=alpha+1.3.6.1.4.1.99999.932.1=Alice,DC=RUNTIME,DC=TEST
description: local-upper

dn: uid=fold+trFold=\20ALICE\20\20SMITH\20,0.9.2342.19200300.100.1.25=RUNTIME,dc=TEST
description: local-fold

`

func TestDNIdentityTranslucentRuntimeOpenLDAPSemantics(t *testing.T) {
	for _, backend := range dnIdentityOverlayStoreFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			client, address := startDNIdentityTranslucentRuntimePair(t, backend.open)

			entries := searchDNIdentityTranslucentRuntime(
				t,
				client,
				"0.9.2342.19200300.100.1.25=RUNTIME,DC=TEST",
				ldap.ScopeSingleLevel,
			)
			if got := translucentRuntimeCNs(entries); !slices.Equal(got, []string{
				"Exact Upper",
				"Exact Lower",
				"Folded Name",
			}) {
				t.Fatalf("translucent runtime result order = %q", got)
			}
			assertTranslucentRuntimeDescription(t, entries, "Exact Upper", "local-upper")
			assertTranslucentRuntimeDescription(t, entries, "Exact Lower", "remote-lower")
			assertTranslucentRuntimeDescription(t, entries, "Folded Name", "local-fold")

			for iteration := 0; iteration < 8; iteration++ {
				repeated := searchDNIdentityTranslucentRuntime(
					t,
					client,
					translucentRuntimeBaseDN,
					ldap.ScopeSingleLevel,
				)
				if got := translucentRuntimeCNs(repeated); !slices.Equal(got, []string{
					"Exact Upper",
					"Exact Lower",
					"Folded Name",
				}) {
					t.Fatalf("translucent runtime iteration %d order = %q", iteration, got)
				}
			}

			foldBase := fmt.Sprintf(
				"uid=fold+%s=\\20alice\\20smith\\20,DC=RUNTIME,DC=TEST",
				translucentRuntimeFoldOID,
			)
			fold := searchDNIdentityTranslucentRuntime(
				t,
				client,
				foldBase,
				ldap.ScopeBaseObject,
			)
			if len(fold) != 1 {
				t.Fatalf("schema-equivalent translucent base returned %d entries", len(fold))
			}
			assertTranslucentRuntimeDescription(t, fold, "Folded Name", "local-fold")
			if !strings.Contains(strings.ToLower(fold[0].DN), "translucentremotefold=") {
				t.Fatalf(
					"remote canonical DN %q does not retain the remote preferred attribute name",
					fold[0].DN,
				)
			}

			upperDN := fmt.Sprintf(
				"uid=alpha+%s=Alice,DC=RUNTIME,DC=TEST",
				translucentRuntimeExactOID,
			)
			matched, err := client.Compare(upperDN, "telephoneNumber", "100")
			if err != nil || !matched {
				t.Fatalf("Compare(remote fallback) = %t, %v", matched, err)
			}
			matched, err = client.Compare(upperDN, "description", "local-upper")
			if err != nil || !matched {
				t.Fatalf("Compare(local override) = %t, %v", matched, err)
			}
			matched, err = client.Compare(upperDN, "description", "remote-upper")
			if err != nil || matched {
				t.Fatalf("Compare(shadowed remote value) = %t, %v", matched, err)
			}

			assertTranslucentRuntimeBind(t, address, upperDN, "upper-secret", true)
			lowerDN := "uid=alpha+trExact=alice,dc=runtime,dc=test"
			assertTranslucentRuntimeBind(t, address, lowerDN, "upper-secret", false)
			assertTranslucentRuntimeBind(t, address, lowerDN, "lower-secret", true)
			assertTranslucentRuntimeBind(t, address, foldBase, "fold-secret", true)
		})
	}
}

func TestTranslucentRuntimeConfigurationKeepsLegacyConfigDNIdentity(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	overlay := translucentTestOverlayEntry(translucentTestOverlayDN, false)
	child := translucentTestBackendEntry(
		"olcDatabase={0}ldap,OLCOVERLAY={0}TRANSLUCENT,OLCDATABASE={1}MDB,CN=CONFIG",
		"{0}ldap",
		"ldap://127.0.0.1:389",
	)
	putTranslucentTestEntries(t, store, overlay, child)

	var configuration translucentRuntimeConfiguration
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		configuration, err = loadTranslucentRuntimeConfiguration(reader, overlay)
		return err
	}); err != nil {
		t.Fatalf("load legacy translucent config DN identity: %v", err)
	}
	overlayDN, err := directory.ParseDN(overlay.DN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", overlay.DN, err)
	}
	if configuration.configDNKey != overlayDN.Key() {
		t.Fatalf(
			"translucent config DN key = %q, want legacy key %q",
			configuration.configDNKey,
			overlayDN.Key(),
		)
	}
}

func startDNIdentityTranslucentRuntimePair(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) (*ldap.Conn, string) {
	t.Helper()
	remoteConfig := fmt.Sprintf(
		translucentRuntimeConfigTemplate,
		"translucentRemoteExact",
		"translucentRuntimeExact",
		"translucentRemoteFold",
		"translucentRuntimeFold",
	)
	remoteAddress := startDNIdentityOverlayFixture(
		t,
		openStore(t),
		remoteConfig,
		translucentRuntimeRemoteLDIF,
	)
	localConfig := fmt.Sprintf(
		translucentRuntimeConfigTemplate,
		"translucentRuntimeExact",
		"translucentRemoteExact",
		"translucentRuntimeFold",
		"translucentRemoteFold",
	) + fmt.Sprintf(translucentRuntimeOverlayConfig, "ldap://"+remoteAddress)
	localAddress := startDNIdentityOverlayFixture(
		t,
		openStore(t),
		localConfig,
		translucentRuntimeLocalLDIF,
	)
	return dialDNIdentityOverlayRoot(
		t,
		localAddress,
		"cn=admin,"+translucentRuntimeBaseDN,
	), localAddress
}

func searchDNIdentityTranslucentRuntime(
	t *testing.T,
	client *ldap.Conn,
	baseDN string,
	scope int,
) []*ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "description", "telephoneNumber"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(base=%q, scope=%d): %v", baseDN, scope, err)
	}
	return result.Entries
}

func translucentRuntimeCNs(entries []*ldap.Entry) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.GetAttributeValue("cn")
	}
	return result
}

func assertTranslucentRuntimeDescription(
	t *testing.T,
	entries []*ldap.Entry,
	cn string,
	want string,
) {
	t.Helper()
	for _, entry := range entries {
		if entry.GetAttributeValue("cn") != cn {
			continue
		}
		if got := entry.GetAttributeValue("description"); got != want {
			t.Fatalf("entry %q description = %q, want %q", entry.DN, got, want)
		}
		return
	}
	t.Fatalf("translucent runtime result omits cn %q: %#v", cn, entries)
}

func assertTranslucentRuntimeBind(
	t *testing.T,
	address string,
	dn string,
	password string,
	wantSuccess bool,
) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	err = client.Bind(dn, password)
	if wantSuccess && err != nil {
		t.Fatalf("Bind(%q): %v", dn, err)
	}
	if !wantSuccess {
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	}
}
