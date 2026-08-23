package server

import (
	"errors"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

const dnIdentityAliasGraphConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}alias-graph,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}alias-graph
olcAttributeTypes: ( 1.3.6.1.4.1.99999.916.1 NAME ( 'graphexactname' 'graphexactalias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.916.2 NAME ( 'graphfoldname' 'graphfoldalias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )

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

const dnIdentityAliasGraphContentLDIF = `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=aliases,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: aliases

dn: ou=targets,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: targets
description: scope-target

dn: cn=child,ou=targets,dc=example,dc=com
objectClass: top
objectClass: organizationalRole
cn: child
description: ancestor-target

dn: graphfoldname=Target Name+graphexactname=Exact,ou=targets,dc=example,dc=com
objectClass: top
objectClass: extensibleObject
cn: graph target
graphfoldname: Target Name
graphexactname: Exact
description: graph-target

dn: graphexactname=Proxy,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
graphexactname: Proxy
aliasedObjectName: graphexactname=proxy,ou=aliases,dc=example,dc=com

dn: graphexactname=proxy,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
graphexactname: proxy
aliasedObjectName: 1.3.6.1.4.1.99999.916.2=\20TARGET\20\20NAME\20+graphexactalias=Exact,OU=TARGETS,DC=EXAMPLE,DC=COM

dn: graphfoldname=Lookup,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
graphfoldname: Lookup
aliasedObjectName: graphexactalias=Exact+graphfoldalias=\20TARGET\20\20NAME\20,ou=targets,dc=example,dc=com

dn: graphfoldname=Scope One,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
graphfoldname: Scope One
aliasedObjectName: ou=targets,dc=example,dc=com

dn: graphfoldname=Scope Two,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
graphfoldname: Scope Two
aliasedObjectName: 2.5.4.11=\20TARGETS\20,DC=EXAMPLE,DC=COM

dn: graphfoldname=Loop A,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
graphfoldname: Loop A
aliasedObjectName: graphfoldalias=\20LOOP\20\20B\20,OU=ALIASES,DC=EXAMPLE,DC=COM

dn: graphfoldname=Loop B,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
graphfoldname: Loop B
aliasedObjectName: 1.3.6.1.4.1.99999.916.2=\20LOOP\20\20A\20,ou=aliases,dc=example,dc=com

dn: ou=virtual,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
ou: virtual
aliasedObjectName: 2.5.4.11=\20TARGETS\20,DC=EXAMPLE,DC=COM

`

func TestDNIdentityAliasGraphOpenLDAPSemantics(t *testing.T) {
	for _, backend := range dnIdentityOverlayStoreFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			client := startDNIdentityOverlayFixture(
				t,
				backend.open(t),
				dnIdentityAliasGraphConfigLDIF,
				dnIdentityAliasGraphContentLDIF,
			)
			connection := dialDNIdentityOverlayRoot(
				t,
				client,
				"cn=admin,dc=example,dc=com",
			)

			t.Run("four dereference modes", func(t *testing.T) {
				aliasDN := "graphexactname=Proxy,ou=aliases,dc=example,dc=com"
				targetDN := "graphfoldname=Target Name+graphexactname=Exact,ou=targets,dc=example,dc=com"
				for _, test := range []struct {
					name string
					mode int
					want string
				}{
					{name: "never", mode: ldap.NeverDerefAliases, want: aliasDN},
					{name: "searching", mode: ldap.DerefInSearching, want: aliasDN},
					{name: "finding", mode: ldap.DerefFindingBaseObj, want: targetDN},
					{name: "always", mode: ldap.DerefAlways, want: targetDN},
				} {
					t.Run(test.name, func(t *testing.T) {
						result := aliasSearch(
							t,
							connection,
							aliasDN,
							ldap.ScopeBaseObject,
							test.mode,
							"(objectClass=*)",
						)
						assertAliasDNs(t, result, []string{test.want})
					})
				}
			})

			t.Run("equivalent target and search scope", func(t *testing.T) {
				for _, test := range []struct {
					name string
					mode int
					want int
				}{
					{name: "never", mode: ldap.NeverDerefAliases},
					{name: "finding", mode: ldap.DerefFindingBaseObj},
					{name: "searching", mode: ldap.DerefInSearching, want: 1},
					{name: "always", mode: ldap.DerefAlways, want: 1},
				} {
					t.Run(test.name, func(t *testing.T) {
						result := aliasSearch(
							t,
							connection,
							"ou=aliases,dc=example,dc=com",
							ldap.ScopeSingleLevel,
							test.mode,
							"(description=scope-target)",
						)
						if len(result.Entries) != test.want {
							t.Fatalf("scope result count = %d, want %d", len(result.Entries), test.want)
						}
						if test.want != 0 {
							assertAliasDNs(t, result, []string{"ou=targets,dc=example,dc=com"})
						}
					})
				}

				graph := aliasSearch(
					t,
					connection,
					"ou=aliases,dc=example,dc=com",
					ldap.ScopeSingleLevel,
					ldap.DerefInSearching,
					"(description=graph-target)",
				)
				assertAliasDNs(t, graph, []string{
					"graphfoldname=Target Name+graphexactname=Exact,ou=targets,dc=example,dc=com",
				})
			})

			t.Run("alias and OID multi-AVA target", func(t *testing.T) {
				result := aliasSearch(
					t,
					connection,
					`GRAPHFOLDALIAS=\20LOOKUP\20,OU=ALIASES,DC=EXAMPLE,DC=COM`,
					ldap.ScopeBaseObject,
					ldap.DerefFindingBaseObj,
					"(description=graph-target)",
				)
				assertAliasDNs(t, result, []string{
					"graphfoldname=Target Name+graphexactname=Exact,ou=targets,dc=example,dc=com",
				})
			})

			t.Run("ancestor alias rewrite", func(t *testing.T) {
				for _, mode := range []int{ldap.DerefFindingBaseObj, ldap.DerefAlways} {
					result := aliasSearch(
						t,
						connection,
						"CN=CHILD,OU=VIRTUAL,DC=EXAMPLE,DC=COM",
						ldap.ScopeBaseObject,
						mode,
						"(description=ancestor-target)",
					)
					assertAliasDNs(t, result, []string{
						"cn=child,ou=targets,dc=example,dc=com",
					})
				}
			})

			t.Run("real normalized loop", func(t *testing.T) {
				_, err := connection.Search(ldap.NewSearchRequest(
					`GRAPHFOLDALIAS=\20LOOP\20\20A\20,OU=ALIASES,DC=EXAMPLE,DC=COM`,
					ldap.ScopeBaseObject,
					ldap.DerefFindingBaseObj,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"1.1"},
					nil,
				))
				var ldapErr *ldap.Error
				if !errors.As(err, &ldapErr) ||
					ldapErr.ResultCode != ldap.LDAPResultAliasProblem {
					t.Fatalf("real alias loop error = %#v, %v", ldapErr, err)
				}
			})
		})
	}
}
