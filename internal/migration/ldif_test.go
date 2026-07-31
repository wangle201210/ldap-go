package migration

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestImportLDIFPreservesSlapcatData(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })

	input := `version: 1

dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
entryUUID: 11111111-1111-1111-1111-111111111111
entryCSN: 20260730000000.000000Z#000000#000#000000

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example
description: a long value that is
 folded across two physical lines
jpegPhoto:: AP8Q

`

	result, err := ImportLDIF(context.Background(), store, bytes.NewBufferString(input), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportLDIF(): %v", err)
	}
	if result.Entries != 2 {
		t.Fatalf("Entries = %d, want 2", result.Entries)
	}
	if len(result.NamingContexts) != 1 || result.NamingContexts[0] != "dc=example,dc=com" {
		t.Fatalf("NamingContexts = %v", result.NamingContexts)
	}

	aliceDN := mustDN(t, "uid=alice,dc=example,dc=com")
	if err := store.View(context.Background(), func(tx storage.Reader) error {
		entry, err := tx.Get(aliceDN)
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("description"), [][]byte{[]byte("a long value that isfolded across two physical lines")})
		assertValues(t, entry.Values("jpegPhoto"), [][]byte{{0x00, 0xff, 0x10}})
		return nil
	}); err != nil {
		t.Fatalf("View(): %v", err)
	}
}

func TestImportLDIFRollsBackOnDuplicate(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })

	existing := directory.Entry{
		DN:         "dc=existing,dc=com",
		Attributes: []directory.Attribute{{Description: "dc", Values: [][]byte{[]byte("existing")}}},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(existing, false)
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	input := `dn: dc=example,dc=com
dc: example

dn: dc=example,dc=com
dc: duplicate

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		bytes.NewBufferString(input),
		ImportOptions{Replace: true},
	); !errors.Is(err, storage.ErrEntryExists) {
		t.Fatalf("ImportLDIF() error = %v, want ErrEntryExists", err)
	}

	if err := store.View(context.Background(), func(tx storage.Reader) error {
		_, err := tx.Get(mustDN(t, existing.DN))
		return err
	}); err != nil {
		t.Fatalf("replace import did not roll back: %v", err)
	}
}

func TestImportLDIFPreservesOpenLDAPDynamicObjectState(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: cn=lease,dc=example,dc=com
objectClass: top
objectClass: organizationalRole
objectClass: dynamicObject
cn: lease
entryTtl: 3600
entryExpireTimestamp: 20260731140000Z
entryUUID: 10000000-0000-4000-8000-000000000001
entryCSN: 20260731130000.000000Z#000001#001#000000

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(dynamicObject): %v", err)
	}
	entryDN := mustDN(t, "cn=lease,dc=example,dc=com")
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.Get(entryDN)
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("objectClass"), [][]byte{
			[]byte("top"),
			[]byte("organizationalRole"),
			[]byte("dynamicObject"),
		})
		assertValues(t, entry.Values("entryTtl"), [][]byte{[]byte("3600")})
		assertValues(
			t,
			entry.Values("entryExpireTimestamp"),
			[][]byte{[]byte("20260731140000Z")},
		)
		return nil
	}); err != nil {
		t.Fatalf("read imported dynamicObject: %v", err)
	}

	var output bytes.Buffer
	if _, err := ExportLDIF(
		context.Background(),
		store,
		&output,
	); err != nil {
		t.Fatalf("ExportLDIF(dynamicObject): %v", err)
	}
	for _, line := range []string{
		"objectClass: dynamicObject",
		"entryTtl: 3600",
		"entryExpireTimestamp: 20260731140000Z",
	} {
		if !strings.Contains(output.String(), line) {
			t.Fatalf("exported dynamicObject has no %q:\n%s", line, output.String())
		}
	}
}

func TestImportLDIFPreservesOpenLDAPDITContentRules(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: cn={8}content-rule,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {8}content-rule
olcAttributeTypes: {0}( 1.3.6.1.4.1.99999.20 NAME 'migrationCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcObjectClasses: {0}( 1.3.6.1.4.1.99999.21 NAME 'migrationAux' SUP top AUXILIARY MUST migrationCode )
olcDitContentRules: {0}( 2.16.840.1.113730.3.2.2 NAME 'migrationPersonRule' AUX migrationAux MUST uid NOT description )

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(DIT content rule): %v", err)
	}

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	result, err := schema.LoadOpenLDAPConfig(
		context.Background(),
		store,
		registry,
	)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.AttributeTypes != 1 ||
		result.ObjectClasses != 1 ||
		result.ContentRules != 1 {
		t.Fatalf("schema LoadResult = %#v", result)
	}
	contentRule, found := registry.DITContentRule("migrationPersonRule")
	if !found ||
		contentRule.OID != "2.16.840.1.113730.3.2.2" ||
		len(contentRule.Auxiliary) != 1 ||
		contentRule.Auxiliary[0] != "migrationAux" {
		t.Fatalf("migrationPersonRule = %#v, found %t", contentRule, found)
	}

	var output bytes.Buffer
	if _, err := ExportLDIF(
		context.Background(),
		store,
		&output,
	); err != nil {
		t.Fatalf("ExportLDIF(DIT content rule): %v", err)
	}
	for _, fragment := range []string{
		"olcAttributeTypes: {0}( 1.3.6.1.4.1.99999.20",
		"olcObjectClasses: {0}( 1.3.6.1.4.1.99999.21",
		"olcDitContentRules: {0}( 2.16.840.1.113730.3.2.2",
	} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("exported schema has no %q:\n%s", fragment, output.String())
		}
	}
}

func assertValues(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("values = %q, want %q", got, want)
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("values[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func mustDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
