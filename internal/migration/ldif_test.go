package migration

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
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
