package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestGlobalDatabaseDefaultsAndFrontendReadOnlyOverride(t *testing.T) {
	for _, test := range []struct {
		name             string
		frontendReadOnly *bool
		wantReadOnly     bool
	}{
		{name: "global read-only", wantReadOnly: true},
		{name: "frontend false clears global read-only", frontendReadOnly: boolPointer(false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			entries := []directory.Entry{
				{
					DN: "cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcRestrict", Values: stringValues("search")},
						{Description: "olcReadOnly", Values: stringValues("TRUE")},
					},
				},
				{
					DN: "olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcDatabase", Values: stringValues("{1}mdb")},
						{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
					},
				},
			}
			if test.frontendReadOnly != nil {
				entries = append(entries, directory.Entry{
					DN: "olcDatabase={-1}frontend,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
						{Description: "olcReadOnly", Values: stringValues("FALSE")},
					},
				})
			}
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				for _, entry := range entries {
					if err := writer.Put(entry, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("seed configuration: %v", err)
			}

			databases, err := loadRuntimeDatabases(context.Background(), store)
			if err != nil {
				t.Fatalf("load databases: %v", err)
			}
			database := databaseForDN(&runtimeState{databases: databases}, staticRuntimeDN("dc=example,dc=com"))
			if database == nil {
				t.Fatal("data database was not loaded")
			}
			if database.readOnly != test.wantReadOnly {
				t.Fatalf("read-only = %t, want %t", database.readOnly, test.wantReadOnly)
			}
			if !databaseRestricts(*database, restrictSearch) {
				t.Fatal("global olcRestrict search was not inherited")
			}
		})
	}
}

func TestGlobalRestrictOnlineReloadAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	t.Cleanup(stop)

	configuration, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configuration.Close() })
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	data, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { data.Close() })
	if err := data.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatal(err)
	}

	restrict := ldap.NewModifyRequest("cn=config", nil)
	restrict.Add("olcRestrict", []string{"add"})
	if err := configuration.Modify(restrict); err != nil {
		t.Fatalf("add global restriction: %v", err)
	}
	assertLDAPResultCode(
		t,
		data.Add(newPersonAddRequest("global-restricted")),
		ldap.LDAPResultUnwillingToPerform,
	)

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcRestrict", []string{"not-an-operation"})
	assertLDAPResultCode(
		t,
		configuration.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	assertLDAPResultCode(
		t,
		data.Add(newPersonAddRequest("global-still-restricted")),
		ldap.LDAPResultUnwillingToPerform,
	)

	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete("olcRestrict", nil)
	if err := configuration.Modify(remove); err != nil {
		t.Fatalf("remove global restriction: %v", err)
	}
	if err := data.Add(newPersonAddRequest("global-restored")); err != nil {
		t.Fatalf("Add after removing global restriction: %v", err)
	}
}

func boolPointer(value bool) *bool {
	return &value
}
