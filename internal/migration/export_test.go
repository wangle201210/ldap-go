package migration

import (
	"bytes"
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDIFImportExportRoundTrip(t *testing.T) {
	t.Parallel()

	input := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
entryUUID: 11111111-1111-1111-1111-111111111111

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example
jpegPhoto:: AP8Q

`
	source := storage.NewMemory()
	t.Cleanup(func() { _ = source.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		source,
		bytes.NewBufferString(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(source): %v", err)
	}

	var exported bytes.Buffer
	result, err := ExportLDIF(context.Background(), source, &exported)
	if err != nil {
		t.Fatalf("ExportLDIF(): %v", err)
	}
	if result.Entries != 2 {
		t.Fatalf("ExportLDIF() entries = %d, want 2", result.Entries)
	}

	destination := storage.NewMemory()
	t.Cleanup(func() { _ = destination.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		destination,
		bytes.NewReader(exported.Bytes()),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(destination): %v\nexported:\n%s", err, exported.String())
	}

	assertStoresEqual(t, source, destination)
}

func assertStoresEqual(t *testing.T, left, right storage.Store) {
	t.Helper()
	leftEntries := readEntries(t, left)
	rightEntries := readEntries(t, right)
	if len(leftEntries) != len(rightEntries) {
		t.Fatalf("entry counts differ: %d != %d", len(leftEntries), len(rightEntries))
	}
	for i := range leftEntries {
		if !leftEntries[i].Equal(rightEntries[i]) {
			t.Fatalf("entries differ:\nleft: %#v\nright: %#v", leftEntries[i], rightEntries[i])
		}
	}
}

func readEntries(t *testing.T, store storage.Store) []directory.Entry {
	t.Helper()
	var entries []directory.Entry
	if err := store.View(context.Background(), func(tx storage.Reader) error {
		return tx.ForEach(func(entry directory.Entry) error {
			entries = append(entries, entry)
			return nil
		})
	}); err != nil {
		t.Fatalf("read store: %v", err)
	}
	return entries
}
