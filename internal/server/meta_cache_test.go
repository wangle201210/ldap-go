package server

import (
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestMetaDNRouteCacheTTL(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newMetaDNRouteCache(func() time.Time { return now })
	dn := mustMetaBackendDN(t, "uid=user,dc=meta,dc=test")
	configuration := &metaBackendRuntimeConfiguration{
		configDNKey: "meta",
		dnCacheTTL:  2 * time.Second,
	}
	cache.store(configuration, dn, "target")
	if got := cache.lookup(configuration, dn); got != "target" {
		t.Fatalf("cached target = %q", got)
	}
	now = now.Add(2 * time.Second)
	if got := cache.lookup(configuration, dn); got != "" {
		t.Fatalf("expired target = %q", got)
	}
}

func TestMetaDNRouteCacheForeverAndDisabled(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newMetaDNRouteCache(func() time.Time { return now })
	dn := mustMetaBackendDN(t, "uid=user,dc=meta,dc=test")
	forever := &metaBackendRuntimeConfiguration{configDNKey: "meta", dnCacheTTL: -1}
	cache.store(forever, dn, "target")
	now = now.Add(100 * 365 * 24 * time.Hour)
	if got := cache.lookup(forever, dn); got != "target" {
		t.Fatalf("forever target = %q", got)
	}
	cache.remove(forever, dn)
	if got := cache.lookup(forever, dn); got != "" {
		t.Fatalf("removed target = %q", got)
	}

	disabled := &metaBackendRuntimeConfiguration{configDNKey: "disabled"}
	cache.store(disabled, dn, "target")
	if got := cache.lookup(disabled, dn); got != "" {
		t.Fatalf("disabled cache target = %q", got)
	}
}

func TestMetaModifyDNDestination(t *testing.T) {
	source := mustMetaBackendDN(t, "uid=user,ou=people,dc=meta,dc=test")
	destination, ok := metaModifyDNDestination(source, ldapwire.ModifyDNRequest{
		NewRDN: "uid=renamed",
	})
	if !ok || destination.Key() != "uid=renamed,ou=people,dc=meta,dc=test" {
		t.Fatalf("same-parent destination = %q, %t", destination.String(), ok)
	}
	destination, ok = metaModifyDNDestination(source, ldapwire.ModifyDNRequest{
		NewRDN:         "uid=moved",
		NewSuperior:    "ou=team,dc=meta,dc=test",
		HasNewSuperior: true,
	})
	if !ok || destination.Key() != "uid=moved,ou=team,dc=meta,dc=test" {
		t.Fatalf("newSuperior destination = %q, %t", destination.String(), ok)
	}
}
