package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestDNIdentityNestGroupConfigurationAndReferences(t *testing.T) {
	registry := dnIdentityOverlayScopeRegistry(t)

	t.Run("caseExact bases and references remain distinct", func(t *testing.T) {
		configuration := nestGroupRuntimeConfiguration{
			id:                "olcOverlay={0}nestgroup,olcDatabase={1}mdb,cn=config",
			memberAttribute:   "member",
			memberOfAttribute: "memberOf",
			bases: []directory.DN{
				mustDNIdentityOverlayScopeLegacyDN(
					t,
					"scopeExactName=Tenant,dc=example,dc=com",
				),
				mustDNIdentityOverlayScopeLegacyDN(
					t,
					"scopeExactName=tenant,dc=example,dc=com",
				),
			},
		}
		configurations := []nestGroupRuntimeConfiguration{configuration}
		if err := validateNestGroupSchema(registry, configurations); err != nil {
			t.Fatalf("validateNestGroupSchema(): %v", err)
		}
		if configurations[0].bases[0].Equal(configurations[0].bases[1]) {
			t.Fatal("caseExact nestgroup bases collapsed")
		}

		upper, err := nestGroupParseReference(
			registry,
			"member",
			[]byte("scopeExactName=Alice,dc=example,dc=com"),
		)
		if err != nil {
			t.Fatalf("parse upper reference: %v", err)
		}
		lower, err := nestGroupParseReference(
			registry,
			"member",
			[]byte("scopeExactName=alice,dc=example,dc=com"),
		)
		if err != nil {
			t.Fatalf("parse lower reference: %v", err)
		}
		if upper.dn.Equal(lower.dn) || upper.dn.Key() == lower.dn.Key() {
			t.Fatal("caseExact nestgroup references share one graph key")
		}
	})

	t.Run("caseIgnore equivalent bases are duplicates", func(t *testing.T) {
		configuration := nestGroupRuntimeConfiguration{
			id:                "olcOverlay={0}nestgroup,olcDatabase={1}mdb,cn=config",
			memberAttribute:   "member",
			memberOfAttribute: "memberOf",
			bases: []directory.DN{
				mustDNIdentityOverlayScopeLegacyDN(
					t,
					"scopeFoldName=Remote Tenant,dc=example,dc=com",
				),
				mustDNIdentityOverlayScopeLegacyDN(
					t,
					`scopeFoldName=\20REMOTE\20\20TENANT\20,DC=EXAMPLE,DC=COM`,
				),
			},
		}
		if err := validateNestGroupSchema(
			registry,
			[]nestGroupRuntimeConfiguration{configuration},
		); err == nil {
			t.Fatal("caseIgnore-equivalent nestgroup bases were accepted")
		}
	})
}
