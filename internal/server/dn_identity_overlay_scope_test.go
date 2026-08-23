package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityOverlayScopeSemantics(t *testing.T) {
	registry := dnIdentityOverlayScopeRegistry(t)
	exactSuffix := mustDNIdentityOverlayScopeDN(
		t,
		registry,
		"scopeExactName=Tenant",
	)
	foldSuffix := mustDNIdentityOverlayScopeDN(
		t,
		registry,
		"scopeFoldName=Remote Tenant",
	)
	exactDatabase := runtimeDatabase{
		name:         "{1}mdb",
		suffixes:     []directory.DN{exactSuffix},
		dnNormalizer: registry,
	}
	foldDatabase := runtimeDatabase{
		name:         "{2}mdb",
		suffixes:     []directory.DN{foldSuffix},
		dnNormalizer: registry,
	}

	t.Run("configured bases use naming equality", func(t *testing.T) {
		exactDifferentCase := mustDNIdentityOverlayScopeLegacyDN(
			t,
			"scopeExactName=tenant",
		)
		if uniqueBaseWithinDatabase(exactDatabase, exactDifferentCase) {
			t.Fatal("caseExact-different unique base was accepted inside suffix")
		}
		if derefTargetWithinDatabase(exactDatabase, exactDifferentCase) {
			t.Fatal("caseExact-different deref target was accepted inside suffix")
		}

		foldEquivalent := mustDNIdentityOverlayScopeLegacyDN(
			t,
			`scopeFoldName=\20REMOTE\20\20TENANT\20`,
		)
		if !uniqueBaseWithinDatabase(foldDatabase, foldEquivalent) {
			t.Fatal("caseIgnore-equivalent unique base was rejected")
		}
		if !derefTargetWithinDatabase(foldDatabase, foldEquivalent) {
			t.Fatal("caseIgnore-equivalent deref target was rejected")
		}
	})

	t.Run("constraint restriction uses naming equality", func(t *testing.T) {
		runtime := &runtimeState{schema: registry}
		rule := constraintRule{restrict: &constraintRestriction{
			base:  &exactSuffix,
			scope: directory.ScopeWholeSubtree,
		}}
		applies, err := constraintRuleApplies(runtime, rule, directory.Entry{
			DN: "scopeExactName=tenant",
		})
		if err != nil {
			t.Fatalf("constraintRuleApplies(caseExact): %v", err)
		}
		if applies {
			t.Fatal("caseExact-different entry matched constraint restriction")
		}

		rule.restrict.base = &foldSuffix
		applies, err = constraintRuleApplies(runtime, rule, directory.Entry{
			DN: `scopeFoldName=\20REMOTE\20\20TENANT\20`,
		})
		if err != nil {
			t.Fatalf("constraintRuleApplies(caseIgnore): %v", err)
		}
		if !applies {
			t.Fatal("caseIgnore-equivalent entry missed constraint restriction")
		}
	})

	t.Run("unique ignored DN does not hide caseExact sibling", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		const partition = "dn-identity-overlay-scope"
		entries := []directory.Entry{
			{
				DN: "scopeExactName=Alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "scopeExactName", Values: stringValues("Alice")},
					{Description: "cn", Values: stringValues("duplicate")},
				},
			},
			{
				DN: "scopeExactName=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "scopeExactName", Values: stringValues("alice")},
					{Description: "cn", Values: stringValues("duplicate")},
				},
			},
		}
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			partitionWriter := storage.WriterInPartitionWithNormalizer(
				writer,
				partition,
				registry,
			)
			for _, entry := range entries {
				if err := partitionWriter.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed schema-aware unique entries: %v", err)
		}

		ignored := mustDNIdentityOverlayScopeLegacyDN(
			t,
			"scopeExactName=Alice,dc=example,dc=com",
		)
		base := mustDNIdentityOverlayScopeLegacyDN(t, "dc=example,dc=com")
		var duplicate bool
		if err := store.View(context.Background(), func(reader storage.Reader) error {
			var err error
			duplicate, err = uniqueSearch(
				&runtimeState{schema: registry},
				storage.ReaderInPartitionWithNormalizer(reader, partition, registry),
				ignored,
				base,
				directory.ScopeWholeSubtree,
				directory.Filter{
					Kind:      directory.FilterEquality,
					Attribute: "cn",
					Assertion: []byte("duplicate"),
				},
			)
			return err
		}); err != nil {
			t.Fatalf("uniqueSearch(): %v", err)
		}
		if !duplicate {
			t.Fatal("caseExact sibling was hidden as the ignored DN")
		}
	})
}

func dnIdentityOverlayScopeRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.917.1 NAME 'scopeExactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.917.2 NAME 'scopeFoldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", description, err)
		}
	}
	return registry
}

func mustDNIdentityOverlayScopeDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(value, registry)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", value, err)
	}
	return dn
}

func mustDNIdentityOverlayScopeLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
