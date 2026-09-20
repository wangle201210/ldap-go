package server

import (
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestConfigurationAttributeOIDRuntimeAndOnlineValidation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := registry.AttributeType("olcConnMaxPending")
	threads, _ := registry.AttributeType("olcThreads")
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues(pending.OID, stringValues("17"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	instance, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	if instance.runtime.Load().connectionPending.maxPending != 17 {
		t.Fatal("numeric configuration OID did not affect runtime")
	}
	if !readStoredEntry(t, store, "cn=config").HasAttribute(pending.OID) {
		t.Fatal("startup rewrote imported attribute spelling")
	}
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Replace(pending.OID, []string{"23"})
	if err := client.Modify(modify); err != nil {
		t.Fatal(err)
	}
	if instance.runtime.Load().connectionPending.maxPending != 23 {
		t.Fatal("OID modification did not update runtime")
	}
	if got := readStoredEntry(t, store, "cn=config").Values("olcConnMaxPending"); !reflect.DeepEqual(got, stringValues("23")) {
		t.Fatalf("online config not canonical: %q", got)
	}
	modify = ldap.NewModifyRequest("cn=config", nil)
	modify.Replace(pending.OID, []string{"29"})
	modify.Replace(threads.OID, []string{"64"})
	if err := client.Modify(modify); err == nil {
		t.Fatal("numeric OID bypassed unsupported setting validation")
	}
	if instance.runtime.Load().connectionPending.maxPending != 23 {
		t.Fatal("rejected update partially activated")
	}
	if got := readStoredEntry(t, store, "cn=config").Values("olcConnMaxPending"); !reflect.DeepEqual(got, stringValues("23")) {
		t.Fatal("rejected update partially persisted")
	}
}

func TestConfigurationAttributeReaderOnlyChangesReadView(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	attribute, _ := registry.AttributeType("olcSizeLimit")
	for _, dn := range []string{"cn=config", "cn=content,dc=example"} {
		original := directory.Entry{DN: dn, Attributes: []directory.Attribute{{Description: attribute.OID, Values: stringValues("123")}}}
		result := canonicalConfigurationEntry(registry, original)
		want := attribute.OID
		if dn == "cn=config" {
			want = "olcSizeLimit"
		}
		if result.Attributes[0].Description != want || original.Attributes[0].Description != attribute.OID {
			t.Fatal("canonicalization crossed read/data boundaries")
		}
		if !reflect.DeepEqual(original.Attributes[0].Values, result.Attributes[0].Values) {
			t.Fatal("canonicalization changed values")
		}
	}
}

func TestConfigurationAttributeMixedAliasesCannotHideInvalidValue(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	attribute, _ := registry.AttributeType("olcConnMaxPending")
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "olcConnMaxPending", Values: stringValues("10")},
			directory.Attribute{Description: attribute.OID, Values: stringValues("20")})
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateConfiguration(t.Context(), Config{Store: store}); err == nil {
		t.Fatal("duplicate single-valued config hidden behind OID spelling")
	}
	entry := readStoredEntry(t, store, "cn=config")
	if !entry.HasAttribute(attribute.OID) || !entry.HasAttribute("olcConnMaxPending") {
		t.Fatal("read-only validation rewrote source data")
	}
}
