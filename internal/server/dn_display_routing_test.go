package server

import (
	"errors"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestDatabaseLegacyDisplayRoutingReference(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	var dns []directory.DN
	for _, raw := range []string{"", "cn=config", "dc=com", "dc=example,dc=com", "uid=Alice,dc=example,dc=com",
		"exactName=Alice+foldName=ENGINEERING,dc=example,dc=com", "exactAlias=alice,dc=example,dc=com",
		`cn=Smith\, Alice,dc=example,dc=com`, "2.5.4.3=config", "cn="} {
		dn, err := directory.ParseDN(raw)
		if err != nil {
			t.Fatal(err)
		}
		dns = append(dns, dn)
		if normalized, err := registry.NormalizeDN(raw); err == nil {
			dns = append(dns, normalized)
		}
	}
	for _, left := range dns {
		for _, right := range dns {
			for _, normalizer := range []directory.DNAttributeNormalizer{nil, registry} {
				database := runtimeDatabase{dnNormalizer: normalizer}
				a, ea := normalizeRuntimeDatabaseDN(database, left)
				b, eb := normalizeRuntimeDatabaseDN(database, right)
				wantEqual, wantAncestor := false, false
				if ea == nil && eb == nil {
					wantEqual, wantAncestor = a.Equal(b), a.AncestorOf(b)
				}
				if databaseDNEqual(database, left, right) != wantEqual || databaseDNAtOrBelow(database, right, left) != (wantEqual || wantAncestor) || databaseDNStrictlyBelow(database, right, left) != wantAncestor {
					t.Fatalf("routing differs for %q / %q, normalizer %T", left.String(), right.String(), normalizer)
				}
			}
		}
	}
}

func TestDatabaseDisplayRoutingRetainsCustomErrors(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	custom := &recordingDNParserRegistry{Registry: registry, fail: errors.New("custom DN failure")}
	database := runtimeDatabase{dnNormalizer: custom}
	dn, _ := directory.ParseDN("cn=config")
	for _, match := range []func() bool{
		func() bool { return databaseDNEqual(database, dn, dn) },
		func() bool { return databaseDNAtOrBelow(database, dn, dn) },
		func() bool { return databaseDNStrictlyBelow(database, dn, dn) },
	} {
		custom.calls = 0
		if match() || custom.calls != 1 {
			t.Fatal("custom normalizer was skipped or error order changed")
		}
	}
}
