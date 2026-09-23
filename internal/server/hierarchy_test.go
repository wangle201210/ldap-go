package server

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type hierarchyCountingRegistry struct {
	databaseEqualityIndexRegistry
	calls int
}

func (registry *hierarchyCountingRegistry) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	registry.calls++
	return registry.databaseEqualityIndexRegistry.NormalizeDNAttribute(attribute, value)
}

func TestHierarchyServerWriterEligibility(t *testing.T) {
	server, database, base := newModifySnapshotFixture(t, "bolt", 1024)
	for _, limit := range []uint64{0, 1 << 20} {
		database.entryLimit.bytes = limit
		if err := server.updateStorage(t.Context(), func(writer storage.Writer) error {
			scoped := writerForDatabase(writer, database)
			handled, found, err := storage.HasDescendants(scoped, base)
			if err != nil || !handled || found {
				t.Fatalf("server leaf: %v/%v/%v", handled, found, err)
			}
			parent, _ := base.Parent()
			handled, found, err = storage.HasDescendants(scoped, parent)
			if err != nil || !handled || !found {
				t.Fatalf("server parent: %v/%v/%v", handled, found, err)
			}
			var want, got []directory.Entry
			if err := scoped.ForEach(func(entry directory.Entry) error { want = append(want, entry); return nil }); err != nil {
				return err
			}
			handled, err = storage.ForEachSubtreeEntry(scoped, parent, func(entry directory.Entry) error { got = append(got, entry); return nil })
			if err != nil || !handled || !reflect.DeepEqual(got, want) {
				t.Fatalf("server subtree order/hints: %v/%v", handled, err)
			}
			mapped := &rwmStorageWriter{writer: scoped, rwmStorageReader: &rwmStorageReader{Reader: scoped}}
			if handled, _, err := storage.HasDescendants(mapped, parent); handled || err != nil {
				t.Fatalf("RWM must fall back: %v/%v", handled, err)
			}
			unknown := struct{ storage.Writer }{scoped}
			if handled, _, err := storage.HasDescendants(unknown, parent); handled || err != nil {
				t.Fatalf("unknown outer wrapper must fall back: %v/%v", handled, err)
			}
			registry := &hierarchyCountingRegistry{databaseEqualityIndexRegistry: server.runtime.Load().schema}
			custom := &databaseEqualityIndexNormalizer{registry: registry}
			customScoped := storage.WriterInPartitionWithNormalizer(writer, database.partition, custom)
			if handled, _, err := storage.HasDescendants(customScoped, parent); handled || err != nil || registry.calls != 0 {
				t.Fatalf("custom normalizer consumed work: %v/%v/%d", handled, err, registry.calls)
			}
			if handled, err := storage.ForEachSubtreeEntry(customScoped, parent, func(directory.Entry) error {
				t.Fatal("custom normalizer callback")
				return nil
			}); handled || err != nil || registry.calls != 0 {
				t.Fatalf("custom subtree consumed work: %v/%v/%d", handled, err, registry.calls)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHierarchyNormalizerConcreteRegistryGate(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, normalizer := range []*databaseEqualityIndexNormalizer{
		nil, {}, {registry: (*schema.Registry)(nil)}, {registry: wrappedModifyIndexRegistry{registry}},
	} {
		if _, supported := normalizer.HierarchyIdentityFingerprint(); supported {
			t.Fatalf("custom or nil registry supported: %#v", normalizer)
		}
	}
	normalizer := &databaseEqualityIndexNormalizer{registry: registry}
	if fingerprint, supported := normalizer.HierarchyIdentityFingerprint(); !supported || fingerprint != registry.DNIdentityFingerprint() {
		t.Fatal("concrete registry fingerprint unavailable")
	}
}

func TestHierarchyServerWithoutAttributeIndexes(t *testing.T) {
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "no-attribute-index.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	server, err := New(Config{Store: store, RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
	if err != nil {
		t.Fatal(err)
	}
	runtime := server.runtime.Load()
	base, err := runtime.schema.NormalizeDN("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForNormalizedDN(runtime, base)
	if database == nil || len(database.equalityIndexes.Attributes) != 0 {
		t.Fatal("fixture must have no attribute indexes")
	}
	if err := server.updateStorage(t.Context(), func(writer storage.Writer) error {
		scoped := writerForDatabase(writer, *database)
		handled, found, err := storage.HasDescendants(scoped, base)
		if err != nil || !handled || !found {
			t.Fatalf("no-index runtime normalizer=%T: %v/%v/%v", database.dnNormalizer, handled, found, err)
		}
		count := 0
		handled, err = storage.ForEachSubtreeEntry(scoped, base, func(directory.Entry) error { count++; return nil })
		if err != nil || !handled || count < 2 {
			t.Fatalf("no-index subtree = %v/%v/%d", handled, err, count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
