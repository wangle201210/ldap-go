package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityDefaultSearchBaseConfiguration(t *testing.T) {
	registry := dnIdentityOverlayScopeRegistry(t)
	entry := directory.Entry{
		DN: "cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcGlobal")},
			{Description: "cn", Values: stringValues("config")},
			{
				Description: "olcDefaultSearchBase",
				Values: stringValues(
					`1.3.6.1.4.1.99999.917.2=\20REMOTE\20\20TENANT\20,DC=EXAMPLE,DC=COM`,
				),
			},
		},
	}
	parsed, err := parseDefaultSearchBaseEntryWithNormalizer(entry, registry)
	if err != nil {
		t.Fatalf("parseDefaultSearchBaseEntryWithNormalizer(): %v", err)
	}
	if got, want := parsed.dn.String(),
		`scopeFoldName=\ REMOTE  TENANT\ ,dc=EXAMPLE,dc=COM`; got != want {
		t.Fatalf("pretty default search base = %q, want %q", got, want)
	}
	if got, want := parsed.dn.NormalizedString(),
		"scopeFoldName=remote tenant,dc=example,dc=com"; got != want {
		t.Fatalf("normalized default search base = %q, want %q", got, want)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed cn=config: %v", err)
	}
	if err := normalizeDefaultSearchBaseConfigurationWithNormalizer(
		context.Background(),
		store,
		registry,
	); err != nil {
		t.Fatalf("normalizeDefaultSearchBaseConfigurationWithNormalizer(): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		stored, err := reader.Get(configurationSuffix)
		if err != nil {
			return err
		}
		values := stored.Values("olcDefaultSearchBase")
		if len(values) != 1 || string(values[0]) != parsed.dn.String() {
			t.Fatalf("stored default search base = %q", values)
		}
		return nil
	}); err != nil {
		t.Fatalf("read cn=config: %v", err)
	}
}
