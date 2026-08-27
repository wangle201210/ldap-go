package server

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRootDSEFileLastPathMergeAndOnlineAdd(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.ldif")
	second := filepath.Join(root, "second.ldif")
	third := filepath.Join(root, "third.ldif")
	writeRootDSETestFile(t, first, "dn:\ndescription: first-only\n")
	writeRootDSETestFile(t, second, "dn:\ndescription: second-one\nvendorName: custom-vendor\n\ndn:\ndescription: second-two\ncustomRootDSEAttribute: custom-value\n")
	writeRootDSETestFile(t, third, "dn:\ndescription: third-only\n")

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcRootDSE", stringValues(first, second))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	entry := searchRootDSEConfigurationEntry(t, client)
	if got := entry.GetAttributeValues("description"); !slices.Equal(got, []string{"second-one", "second-two"}) {
		t.Fatalf("description = %q", got)
	}
	if got := entry.GetAttributeValues("vendorName"); !slices.Equal(got, []string{"ldap-go", "custom-vendor"}) {
		t.Fatalf("vendorName = %q", got)
	}
	if got := entry.GetAttributeValue("customRootDSEAttribute"); got != "custom-value" {
		t.Fatalf("custom attribute = %q", got)
	}

	configuration, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configuration.Close() })
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	writeRootDSETestFile(t, second, "dn:\ndescription: changed-on-disk\n")
	unrelated := ldap.NewModifyRequest("cn=config", nil)
	unrelated.Add("olcIdleTimeout", []string{"1"})
	if err := configuration.Modify(unrelated); err != nil {
		t.Fatalf("unrelated runtime rebuild: %v", err)
	}
	entry = searchRootDSEConfigurationEntry(t, client)
	if got := entry.GetAttributeValues("description"); !slices.Equal(got, []string{"second-one", "second-two"}) {
		t.Fatalf("unchanged path was reread: %q", got)
	}
	add := ldap.NewModifyRequest("cn=config", nil)
	add.Add("olcRootDSE", []string{third})
	if err := configuration.Modify(add); err != nil {
		t.Fatalf("add olcRootDSE: %v", err)
	}
	entry = searchRootDSEConfigurationEntry(t, client)
	if got := entry.GetAttributeValues("description"); !slices.Equal(got, []string{"third-only"}) {
		t.Fatalf("description after ADD = %q", got)
	}
	if got := entry.GetAttributeValues("vendorName"); !slices.Equal(got, []string{"ldap-go"}) {
		t.Fatalf("vendorName after ADD = %q", got)
	}

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Add("olcRootDSE", []string{filepath.Join(root, "missing.ldif")})
	assertLDAPResultCode(t, configuration.Modify(invalid), ldap.LDAPResultOther)
	entry = searchRootDSEConfigurationEntry(t, client)
	if got := entry.GetAttributeValues("description"); !slices.Equal(got, []string{"third-only"}) {
		t.Fatalf("description after failed ADD = %q", got)
	}
}

func writeRootDSETestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func searchRootDSEConfigurationEntry(t *testing.T, client *ldap.Conn) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description", "vendorName", "customRootDSEAttribute"},
		nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Root DSE entries = %d", len(result.Entries))
	}
	return result.Entries[0]
}
