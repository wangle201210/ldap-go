package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRuntimeDNIdentityMigrationSkipsUnchangedSchema(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	const partition = "fingerprint-db"
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.PutIn(partition, directory.Entry{
			DN: "uid=Legacy,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
				{Description: "uid", Values: [][]byte{[]byte("Legacy")}},
				{Description: "cn", Values: [][]byte{[]byte("Legacy")}},
				{Description: "sn", Values: [][]byte{[]byte("Legacy")}},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed legacy entry: %v", err)
	}
	runtime := &runtimeState{
		schema: registry,
		databases: []runtimeDatabase{{
			name: "{1}mdb", partition: partition, dnNormalizer: registry,
		}},
	}

	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		tracking := &dnIdentityMigrationCountingWriter{Writer: writer}
		if err := migrateRuntimeDNIdentitiesInWriter(tracking, runtime); err != nil {
			return err
		}
		firstScans := tracking.scans
		if firstScans == 0 {
			t.Fatal("initial migration did not scan the legacy partition")
		}
		if err := migrateRuntimeDNIdentitiesInWriter(tracking, runtime); err != nil {
			return err
		}
		if tracking.scans != firstScans {
			t.Fatalf("unchanged schema scans = %d, want %d", tracking.scans, firstScans)
		}

		changed := registry.Clone()
		uid, found := changed.AttributeType("uid")
		if !found {
			t.Fatal("uid attribute is missing")
		}
		uid.Equality = "caseExactMatch"
		if err := changed.UpsertAttributeType(uid); err != nil {
			return err
		}
		runtime.schema = changed
		runtime.databases[0].dnNormalizer = changed
		if err := migrateRuntimeDNIdentitiesInWriter(tracking, runtime); err != nil {
			return err
		}
		if tracking.scans <= firstScans {
			t.Fatalf("changed schema scans = %d, want > %d", tracking.scans, firstScans)
		}
		return nil
	}); err != nil {
		t.Fatalf("migrateRuntimeDNIdentitiesInWriter(): %v", err)
	}
}

type dnIdentityMigrationCountingWriter struct {
	storage.Writer
	scans int
}

func (writer *dnIdentityMigrationCountingWriter) ForEachIn(
	partition string,
	visit func(directory.Entry) error,
) error {
	writer.scans++
	return writer.Writer.ForEachIn(partition, visit)
}
