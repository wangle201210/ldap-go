package schema

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadOpenLDAPConfigSchema(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	schemaEntry := directory.Entry{
		DN: "cn={1}application,cn=schema,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcAttributeTypes",
				Values: byteValues(
					"{0}( 1.2.3.4 NAME 'appID' EQUALITY caseIgnoreMatch " +
						"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
				),
			},
			{
				Description: "olcObjectClasses",
				Values: byteValues(
					"{0}( 1.2.3.5 NAME 'appUser' SUP top AUXILIARY MUST appID )",
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(schemaEntry, false)
	}); err != nil {
		t.Fatalf("seed schema: %v", err)
	}

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	result, err := LoadOpenLDAPConfig(context.Background(), store, registry)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.AttributeTypes != 1 || result.ObjectClasses != 1 {
		t.Fatalf("LoadResult = %#v", result)
	}

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("inetOrgPerson", "appUser")},
			{Description: "uid", Values: byteValues("alice")},
			{Description: "cn", Values: byteValues("Alice")},
			{Description: "sn", Values: byteValues("Example")},
			{Description: "appID", Values: byteValues("portal")},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(): %v", err)
	}
}

func TestLoadOpenLDAPConfigSchemaIgnoresBusinessEntries(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "olcAttributeTypes", Values: byteValues("not a schema description")},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed entry: %v", err)
	}

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	result, err := LoadOpenLDAPConfig(context.Background(), store, registry)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.AttributeTypes != 0 || result.ObjectClasses != 0 {
		t.Fatalf("LoadResult = %#v", result)
	}
}
