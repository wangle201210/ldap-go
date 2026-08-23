package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityReferralRewrite(t *testing.T) {
	registry := dnIdentityReferralAuditlogRegistry(t)

	t.Run("caseExact base does not capture sibling", func(t *testing.T) {
		base := mustDNIdentityReferralAuditlogDN(
			t,
			registry,
			"referralExactName=Tenant,dc=example,dc=com",
		)
		target := mustDNIdentityReferralAuditlogDN(
			t,
			registry,
			"uid=alice,referralExactName=tenant,dc=example,dc=com",
		)
		got, ok := rewriteReferralURLWithNormalizer(
			"ldap://remote.example/ou=people,dc=remote,dc=example",
			&base,
			&target,
			referralScopeSubtree,
			registry,
		)
		want := "ldap://remote.example/uid=alice,referralExactName=tenant," +
			"dc=example,dc=com??sub"
		if !ok || got != want {
			t.Fatalf("caseExact referral rewrite = %q, %t; want %q, true", got, ok, want)
		}
	})

	t.Run("caseExact referral path remains distinct", func(t *testing.T) {
		target := mustDNIdentityReferralAuditlogDN(
			t,
			registry,
			"uid=alice,referralExactName=Tenant,dc=example,dc=com",
		)
		entry := directory.Entry{
			DN: "referralExactName=Tenant,dc=example,dc=com",
			Attributes: []directory.Attribute{{
				Description: "ref",
				Values: [][]byte{[]byte(
					"ldap://remote.example/referralExactName=tenant,dc=remote,dc=example",
				)},
			}},
		}
		got, err := rewrittenReferralURLsWithNormalizer(
			entry,
			&target,
			referralScopeSubtree,
			registry,
		)
		if err != nil {
			t.Fatalf("rewrittenReferralURLsWithNormalizer(): %v", err)
		}
		want := "ldap://remote.example/uid=alice,referralExactName=tenant," +
			"dc=remote,dc=example??sub"
		if len(got) != 1 || got[0] != want {
			t.Fatalf("caseExact referral path rewrite = %q, want [%q]", got, want)
		}
	})

	t.Run("caseIgnore equivalent base rewrites", func(t *testing.T) {
		base := mustDNIdentityReferralAuditlogDN(
			t,
			registry,
			"referralFoldName=Remote Tenant,dc=example,dc=com",
		)
		target := mustDNIdentityReferralAuditlogDN(
			t,
			registry,
			`uid=alice,referralFoldName=\20REMOTE\20\20TENANT\20,DC=EXAMPLE,DC=COM`,
		)
		got, ok := rewriteReferralURLWithNormalizer(
			"ldap://remote.example/ou=people,dc=remote,dc=example",
			&base,
			&target,
			referralScopeSubtree,
			registry,
		)
		want := "ldap://remote.example/uid=alice,ou=people,dc=remote,dc=example??sub"
		if !ok || got != want {
			t.Fatalf("caseIgnore referral rewrite = %q, %t; want %q, true", got, ok, want)
		}
	})

	t.Run("closest ancestor preserves caseExact identity", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		const partition = "dn-identity-referral"
		parents := []directory.Entry{
			{
				DN: "referralExactName=Tenant,dc=example,dc=com",
				Attributes: []directory.Attribute{{
					Description: "description",
					Values:      [][]byte{[]byte("upper")},
				}},
			},
			{
				DN: "referralExactName=tenant,dc=example,dc=com",
				Attributes: []directory.Attribute{{
					Description: "description",
					Values:      [][]byte{[]byte("lower")},
				}},
			},
		}
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			tx := storage.WriterInPartitionWithNormalizer(writer, partition, registry)
			for _, entry := range parents {
				if err := tx.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed caseExact referral ancestors: %v", err)
		}

		target := mustDNIdentityReferralAuditlogDN(
			t,
			registry,
			"uid=alice,referralExactName=tenant,dc=example,dc=com",
		)
		if err := store.View(context.Background(), func(reader storage.Reader) error {
			tx := storage.ReaderInPartitionWithNormalizer(reader, partition, registry)
			ancestor, found, err := closestExistingAncestor(tx, target)
			if err != nil {
				return err
			}
			if !found || string(ancestor.Values("description")[0]) != "lower" {
				t.Fatalf("closest caseExact ancestor = %#v, %t; want lower parent", ancestor, found)
			}
			return nil
		}); err != nil {
			t.Fatalf("closestExistingAncestor(): %v", err)
		}
	})
}

func TestDNIdentityAuditlogRealDN(t *testing.T) {
	registry := dnIdentityReferralAuditlogRegistry(t)

	t.Run("caseExact identities emit realdn", func(t *testing.T) {
		record := auditlogPendingRecord{
			operation:       accesslogDelete,
			suffix:          "dc=example,dc=com",
			authorizationDN: "referralExactName=Tenant,dc=example,dc=com",
			realDN:          "referralExactName=tenant,dc=example,dc=com",
			requestDN:       "uid=alice,dc=example,dc=com",
			registry:        registry,
		}
		got := string(renderAuditlogRecord(record, 123))
		if !strings.Contains(
			got,
			"# realdn: referralExactName=tenant,dc=example,dc=com\n",
		) {
			t.Fatalf("caseExact auditlog record omitted realdn:\n%s", got)
		}
	})

	t.Run("caseIgnore equivalent identities omit realdn", func(t *testing.T) {
		record := auditlogPendingRecord{
			operation:       accesslogDelete,
			suffix:          "dc=example,dc=com",
			authorizationDN: "referralFoldName=Remote Tenant,dc=example,dc=com",
			realDN: `referralFoldName=\20REMOTE\20\20TENANT\20,` +
				"DC=EXAMPLE,DC=COM",
			requestDN: "uid=alice,dc=example,dc=com",
			registry:  registry,
		}
		got := string(renderAuditlogRecord(record, 123))
		if strings.Contains(got, "# realdn:") {
			t.Fatalf("caseIgnore-equivalent auditlog record emitted realdn:\n%s", got)
		}
	})
}

func dnIdentityReferralAuditlogRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.923.1 NAME 'referralExactName' " +
			"EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.923.2 NAME 'referralFoldName' " +
			"EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", description, err)
		}
	}
	return registry
}

func mustDNIdentityReferralAuditlogDN(
	t *testing.T,
	registry *schema.Registry,
	raw string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(raw)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", raw, err)
	}
	return dn
}
