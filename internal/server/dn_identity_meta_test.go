package server

import (
	"context"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityMetaBackendRoutingAndCache(t *testing.T) {
	registry := dnIdentityMetaRegistry(t)
	parent := metaBackendTestParent()
	parent.ReplaceValues("olcSuffix", stringValues("metaExactName=Tenant"))
	parent.ReplaceValues("olcDbDnCacheTtl", stringValues("forever"))
	target := metaBackendTestTarget(
		"{0}uri",
		"ldap://127.0.0.1:1389/metaExactName=Tenant",
		"",
	)
	target.ReplaceValues(
		"olcDbSubtreeInclude",
		stringValues("dn.subtree:metaExactName=Alice,metaExactName=Tenant"),
	)

	configuration := loadDNIdentityMetaConfiguration(
		t,
		registry,
		parent,
		target,
	)
	upper := mustDNIdentityMetaLegacyDN(
		t,
		"metaExactName=Alice,metaExactName=Tenant",
	)
	lowerLeaf := mustDNIdentityMetaLegacyDN(
		t,
		"metaExactName=alice,metaExactName=Tenant",
	)
	lowerSuffix := mustDNIdentityMetaLegacyDN(
		t,
		"metaExactName=Alice,metaExactName=tenant",
	)

	if _, ok := configuration.targetForDN(upper); !ok {
		t.Fatal("configured caseExact target did not route")
	}
	if _, ok := configuration.targetForDN(lowerLeaf); ok {
		t.Fatal("caseExact-different subtree routed to the target")
	}
	if _, ok := configuration.targetForDN(lowerSuffix); ok {
		t.Fatal("caseExact-different target suffix routed")
	}

	plans, err := configuration.searchPlans(ldapwire.SearchRequest{
		BaseDN: upper.String(),
		Scope:  directory.ScopeBase,
	})
	if err != nil || len(plans) != 1 {
		t.Fatalf("configured caseExact search plans = %d, %v", len(plans), err)
	}
	plans, err = configuration.searchPlans(ldapwire.SearchRequest{
		BaseDN: lowerLeaf.String(),
		Scope:  directory.ScopeBase,
	})
	if err != nil || len(plans) != 0 {
		t.Fatalf("caseExact-different search plans = %d, %v", len(plans), err)
	}

	cache := newMetaDNRouteCache(nil)
	cache.store(configuration, upper, "upper-target")
	if got := cache.lookup(configuration, upper); got != "upper-target" {
		t.Fatalf("configured caseExact cache target = %q", got)
	}
	if got := cache.lookup(configuration, lowerLeaf); got != "" {
		t.Fatalf("caseExact-different cache target = %q", got)
	}
}

func TestDNIdentityMetaBackendConfigurationAndModifyDN(t *testing.T) {
	registry := dnIdentityMetaRegistry(t)
	parent := metaBackendTestParent()
	parent.ReplaceValues(
		"olcSuffix",
		stringValues("metaExactName=Tenant", "metaExactName=tenant"),
	)
	_, suffixes, err := validateMetaBackendDatabaseWithNormalizer(parent, registry)
	if err != nil {
		t.Fatalf("distinct caseExact suffixes: %v", err)
	}
	if len(suffixes) != 2 || suffixes[0].Equal(suffixes[1]) {
		t.Fatal("caseExact meta suffixes collapsed")
	}

	parent.ReplaceValues(
		"olcSuffix",
		stringValues("metaFoldName=Tenant", "metaFoldName=tenant"),
	)
	if _, _, err := validateMetaBackendDatabaseWithNormalizer(parent, registry); err == nil {
		t.Fatal("caseIgnore-equivalent meta suffixes were not rejected as duplicates")
	}

	source := mustDNIdentityMetaLegacyDN(
		t,
		"metaExactName=Alice,metaExactName=Tenant",
	)
	destination, ok := metaModifyDNDestinationWithNormalizer(
		source,
		ldapwire.ModifyDNRequest{NewRDN: "metaExactName=alice"},
		registry,
	)
	if !ok {
		t.Fatal("schema-aware ModifyDN destination was not created")
	}
	configured, err := registry.NormalizeDN(
		"metaExactName=Alice,metaExactName=Tenant",
	)
	if err != nil {
		t.Fatalf("NormalizeDN(configured): %v", err)
	}
	if destination.Equal(configured) {
		t.Fatal("caseExact-different ModifyDN destination collapsed")
	}
}

func dnIdentityMetaRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.918.1 NAME 'metaExactName' EQUALITY caseExactMatch " +
			"ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.918.2 NAME 'metaFoldName' EQUALITY caseIgnoreMatch " +
			"ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register attribute %q: %v", definition, err)
		}
	}
	return registry
}

func loadDNIdentityMetaConfiguration(
	t *testing.T,
	registry *schema.Registry,
	parent directory.Entry,
	children ...directory.Entry,
) *metaBackendRuntimeConfiguration {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(parent, false); err != nil {
			return err
		}
		for _, child := range children {
			if err := writer.Put(child, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("store meta configuration: %v", err)
	}

	var configuration *metaBackendRuntimeConfiguration
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var loadErr error
		configuration, loadErr = loadMetaBackendRuntimeConfigurationWithNormalizer(
			reader,
			parent,
			registry,
		)
		return loadErr
	}); err != nil {
		t.Fatalf("load schema-aware meta configuration: %v", err)
	}
	configuration.dnCacheTTL = -1 * time.Second
	return configuration
}

func mustDNIdentityMetaLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
