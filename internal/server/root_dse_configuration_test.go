package server

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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

func TestRootDSEOnlineRemovalRollsBackOIDAndPriorChanges(t *testing.T) {
	file := filepath.Join(t.TempDir(), "root.ldif")
	writeRootDSETestFile(t, file, "dn:\ndescription: preserved\n")
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	const attributeOID = "1.3.6.1.4.1.4203.1.12.2.3.0.51"
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues(attributeOID, stringValues(file))
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
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	request := ldap.NewSearchRequest("cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 2, false, "(objectClass=*)", []string{"*", "+"}, nil)
	before, err := client.Search(request)
	if err != nil {
		t.Fatal(err)
	}
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Replace("olcIdleTimeout", []string{"3"})
	modify.Delete(attributeOID, []string{file})
	assertLDAPResultCode(t, client.Modify(modify), ldap.LDAPResultOther)
	after, err := client.Search(request)
	if err != nil || !reflect.DeepEqual(before.Entries, after.Entries) {
		t.Fatalf("rejected root DSE removal changed configuration: %v", err)
	}
	if got := searchRootDSEConfigurationEntry(t, client).GetAttributeValues("description"); !slices.Equal(got, []string{"preserved"}) {
		t.Fatalf("rejected root DSE removal changed runtime: %q", got)
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
