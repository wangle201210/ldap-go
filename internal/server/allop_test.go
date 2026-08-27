package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestAllopFrontendRootDSESearch(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				}},
			},
			{
				DN: "olcOverlay={0}allop,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcOverlay",
					Values:      stringValues("{0}allop"),
				}},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	search := func(attributes []string) *ldap.Entry {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			attributes,
			nil,
		))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("Root DSE Search = %#v, %v", result, err)
		}
		return result.Entries[0]
	}
	defaultEntry := search(nil)
	if defaultEntry.GetAttributeValue("objectClass") == "" ||
		defaultEntry.GetAttributeValue("supportedControl") == "" {
		names := make([]string, len(defaultEntry.Attributes))
		for index, attribute := range defaultEntry.Attributes {
			names[index] = attribute.Name
		}
		t.Fatalf("allop default attributes = %q", names)
	}
	noAttributes := search([]string{"1.1"})
	if len(noAttributes.Attributes) != 0 {
		t.Fatalf("allop changed 1.1 selection: %#v", noAttributes.Attributes)
	}
	explicitOperational := search([]string{"supportedLDAPVersion"})
	if len(explicitOperational.Attributes) != 1 ||
		explicitOperational.GetAttributeValue("supportedControl") != "" {
		t.Fatalf("allop changed operational-only selection: %#v", explicitOperational.Attributes)
	}
}
