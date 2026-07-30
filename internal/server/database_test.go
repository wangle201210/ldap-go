package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadRuntimeDatabasesIgnoresBusinessConfigurationAttributes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "uid=attacker,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcRootDN", Values: stringValues("uid=attacker,dc=example,dc=com")},
			{Description: "olcRootPW", Values: stringValues("secret")},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		if err := tx.Put(entry, false); err != nil {
			return err
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	dn, err := directory.ParseDN("uid=attacker,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	index := databaseIndexForDN(databases, dn)
	if index < 0 {
		t.Fatal("bootstrap naming context was not loaded")
	}
	if databases[index].rootDN != nil || databases[index].rootPasswordSet {
		t.Fatal("business entry created a runtime database root")
	}
}

func TestLoadRuntimeDatabasesRejectsDuplicateSuffixes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
		t.Fatal("duplicate database suffixes were accepted")
	}
}

func TestLoadRuntimeDatabasesAppliesOperationalSettings(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				{Description: "olcReadOnly", Values: stringValues("TRUE")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcReadOnly", Values: stringValues("FALSE")},
				{Description: "olcLastMod", Values: stringValues("FALSE")},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=other,dc=com")},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return tx.SetNamingContexts([]string{
			"dc=example,dc=com",
			"dc=other,dc=com",
			"dc=bootstrap,dc=com",
		})
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	exampleDN, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(example): %v", err)
	}
	example := databases[databaseIndexForDN(databases, exampleDN)]
	if !example.readOnly {
		t.Fatal("frontend olcReadOnly did not restrict an explicitly writable database")
	}
	if example.lastMod {
		t.Fatal("database olcLastMod FALSE was ignored")
	}

	otherDN, err := directory.ParseDN("dc=other,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(other): %v", err)
	}
	other := databases[databaseIndexForDN(databases, otherDN)]
	if !other.readOnly {
		t.Fatal("frontend olcReadOnly was not inherited")
	}
	if !other.lastMod {
		t.Fatal("olcLastMod did not default to TRUE")
	}

	bootstrapDN, err := directory.ParseDN("dc=bootstrap,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(bootstrap): %v", err)
	}
	bootstrap := databases[databaseIndexForDN(databases, bootstrapDN)]
	if !bootstrap.readOnly {
		t.Fatal("frontend olcReadOnly was not inherited by a bootstrap database")
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidOperationalSettings(t *testing.T) {
	t.Parallel()

	for _, attribute := range []string{"olcReadOnly", "olcLastMod"} {
		attribute := attribute
		t.Run(attribute, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			entry := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
					{Description: attribute, Values: stringValues("sometimes")},
				},
			}
			if err := store.Update(context.Background(), func(tx storage.Writer) error {
				return tx.Put(entry, false)
			}); err != nil {
				t.Fatalf("seed store: %v", err)
			}

			if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
				t.Fatalf("invalid %s was accepted", attribute)
			}
		})
	}
}
