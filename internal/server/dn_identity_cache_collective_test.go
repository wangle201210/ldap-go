package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityPcacheKeys(t *testing.T) {
	registry := dnIdentityCacheRegistry(t)
	configuration, err := loadPcacheRuntimeConfiguration(testPcacheOverlay())
	if err != nil {
		t.Fatalf("loadPcacheRuntimeConfiguration(): %v", err)
	}
	runtime := &runtimeState{schema: registry}
	filter, err := ldapwire.CompileFilter("(sn=Cached)")
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	request := ldapwire.SearchRequest{
		Scope:      directory.ScopeWholeSubtree,
		Filter:     filter,
		Attributes: []string{"uid", "cn"},
	}
	key := func(base string) string {
		t.Helper()
		request.BaseDN = base
		matched, ok := (&Server{}).matchPcacheRequest(runtime, configuration, request)
		if !ok {
			t.Fatalf("matchPcacheRequest(%q) did not match", base)
		}
		return matched.key
	}

	upperExact := key("cacheExactName=Tenant,dc=example,dc=com")
	lowerExact := key("cacheExactName=tenant,dc=example,dc=com")
	if upperExact == lowerExact {
		t.Fatal("caseExact search bases share one pcache key")
	}
	upperFold := key("cacheFoldName=Remote Tenant,dc=example,dc=com")
	lowerFold := key(`cacheFoldName=\20remote\20\20tenant\20,dc=example,dc=com`)
	if upperFold != lowerFold {
		t.Fatal("caseIgnore-equivalent search bases use different pcache keys")
	}
}

func TestDNIdentityCollectiveSources(t *testing.T) {
	registry := dnIdentityCacheRegistry(t)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	const partition = "dn-identity-collective"
	sources := []directory.Entry{
		collectiveAdministrativePointEntry(
			"cacheExactName=Tenant,dc=example,dc=com",
			"collectiveAttributeSpecificArea",
		),
		collectiveAdministrativePointEntry(
			"cacheExactName=tenant,dc=example,dc=com",
			collectiveAttributeSpecificAreaOID,
		),
		collectiveServerSource(
			"cn=source,cacheExactName=Tenant,dc=example,dc=com",
			"{}",
			directory.Attribute{
				Description: "cacheCollectiveDescription",
				Values:      stringValues("upper"),
			},
		),
		collectiveServerSource(
			"cn=source,cacheExactName=tenant,dc=example,dc=com",
			"{}",
			directory.Attribute{
				Description: "cacheCollectiveDescription",
				Values:      stringValues("lower"),
			},
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		scoped := storage.WriterInPartitionWithNormalizer(writer, partition, registry)
		for _, source := range sources {
			if err := scoped.Put(source, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed collective sources: %v", err)
	}

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		scoped := storage.ReaderInPartitionWithNormalizer(reader, partition, registry)
		plan, err := buildCollectiveAttributePlan(registry, scoped)
		if err != nil {
			return err
		}
		if len(plan.sources) != 2 || plan.sources[0].dn.Equal(plan.sources[1].dn) {
			t.Fatalf("schema-aware collective sources = %#v", plan.sources)
		}
		for _, test := range []struct {
			dn   string
			want string
		}{
			{"uid=user,cacheExactName=Tenant,dc=example,dc=com", "upper"},
			{"uid=user,cacheExactName=tenant,dc=example,dc=com", "lower"},
		} {
			entry := directory.Entry{
				DN: test.dn,
				Attributes: []directory.Attribute{{
					Description: "objectClass",
					Values:      stringValues("inetOrgPerson"),
				}},
			}
			derived, err := plan.apply(entry)
			if err != nil {
				return err
			}
			values := derived.Values("cacheCollectiveDescription")
			if len(values) != 1 || string(values[0]) != test.want {
				t.Fatalf("collective values for %q = %q, want [%q]", test.dn, values, test.want)
			}
			if references := derived.Values("collectiveAttributeSubentries"); len(references) != 1 {
				t.Fatalf("collective references for %q = %q", test.dn, references)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("evaluate schema-aware collective sources: %v", err)
	}
}

func dnIdentityCacheRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.920.1 NAME 'cacheExactName' EQUALITY caseExactMatch " +
			"ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.920.2 NAME 'cacheFoldName' EQUALITY caseIgnoreMatch " +
			"ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.920.3 NAME 'cacheCollectiveDescription' " +
			"SUP description COLLECTIVE )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register attribute %q: %v", definition, err)
		}
	}
	return registry
}
