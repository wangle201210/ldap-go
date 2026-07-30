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
