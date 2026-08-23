package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestDNIdentityCollectAndValueSortScopes(t *testing.T) {
	registry := dnIdentityOverlayScopeRegistry(t)

	t.Run("collect keeps caseExact bases distinct", func(t *testing.T) {
		configuration, err := loadCollectRuntimeConfiguration(directory.Entry{
			DN: collectDatabaseOverlayDN,
			Attributes: []directory.Attribute{{
				Description: "olcCollectInfo",
				Values: stringValues(
					`"scopeExactName=Tenant,dc=example,dc=com" description`,
					`"scopeExactName=tenant,dc=example,dc=com" mail`,
				),
			}},
		})
		if err != nil {
			t.Fatalf("loadCollectRuntimeConfiguration(): %v", err)
		}
		if err := validateCollectSchema(registry, &configuration); err != nil {
			t.Fatalf("validateCollectSchema(): %v", err)
		}
		if configuration.rules[0].base.Equal(configuration.rules[1].base) {
			t.Fatal("caseExact collect bases collapsed to one identity")
		}

		database := runtimeDatabase{name: "{1}mdb", collect: &configuration}
		runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}
		lowerChild := mustDNIdentityOverlayScopeLegacyDN(
			t,
			"uid=alice,scopeExactName=tenant,dc=example,dc=com",
		)
		change := []ldapwire.Modification{{
			Operation: ldapwire.ModificationAdd,
			Attribute: directory.Attribute{
				Description: "description",
				Values:      stringValues("allowed"),
			},
		}}
		if err := validateCollectModify(runtime, database, lowerChild, change); err != nil {
			t.Fatalf("caseExact sibling collect rule applied: %v", err)
		}
	})

	t.Run("collect rejects caseIgnore-equivalent duplicate bases", func(t *testing.T) {
		configuration, err := loadCollectRuntimeConfiguration(directory.Entry{
			DN: collectDatabaseOverlayDN,
			Attributes: []directory.Attribute{{
				Description: "olcCollectInfo",
				Values: stringValues(
					`"scopeFoldName=Remote Tenant,dc=example,dc=com" description`,
					`"scopeFoldName=\20REMOTE\20\20TENANT\20,DC=EXAMPLE,DC=COM" mail`,
				),
			}},
		})
		if err != nil {
			t.Fatalf("loadCollectRuntimeConfiguration(): %v", err)
		}
		if err := validateCollectSchema(registry, &configuration); err == nil {
			t.Fatal("caseIgnore-equivalent collect bases were accepted")
		}
	})

	t.Run("valsort scope follows naming equality", func(t *testing.T) {
		exactBase := mustDNIdentityOverlayScopeLegacyDN(
			t,
			"scopeExactName=Tenant,dc=example,dc=com",
		)
		configuration := &valueSortRuntimeConfiguration{rules: []valueSortRule{{
			attribute: "description",
			base:      exactBase,
			kind:      valueSortAlpha,
			weighted:  true,
		}}}
		if err := validateValueSortSchema(registry, configuration); err != nil {
			t.Fatalf("validateValueSortSchema(): %v", err)
		}
		database := runtimeDatabase{name: "{1}mdb", valueSort: configuration}
		runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}

		lower := directory.Entry{
			DN: "uid=alice,scopeExactName=tenant,dc=example,dc=com",
			Attributes: []directory.Attribute{{
				Description: "description",
				Values:      stringValues("unweighted"),
			}},
		}
		if err := validateValueSortAdd(runtime, database, lower); err != nil {
			t.Fatalf("caseExact sibling valsort rule applied: %v", err)
		}

		upper := lower.Clone()
		upper.DN = "uid=alice,scopeExactName=Tenant,dc=example,dc=com"
		if err := validateValueSortAdd(runtime, database, upper); err == nil {
			t.Fatal("matching caseExact valsort rule was not applied")
		}

		foldBase := mustDNIdentityOverlayScopeLegacyDN(
			t,
			"scopeFoldName=Remote Tenant,dc=example,dc=com",
		)
		configuration.rules[0].base = foldBase
		if err := validateValueSortSchema(registry, configuration); err != nil {
			t.Fatalf("validate caseIgnore valsort rule: %v", err)
		}
		fold := lower.Clone()
		fold.DN = `uid=alice,scopeFoldName=\20REMOTE\20\20TENANT\20,DC=EXAMPLE,DC=COM`
		if err := validateValueSortAdd(runtime, database, fold); err == nil {
			t.Fatal("caseIgnore-equivalent valsort base did not match")
		}
	})
}
