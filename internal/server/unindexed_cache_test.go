package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestUnindexedValueCacheTracksStorageRevision(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	put := func(description string) {
		t.Helper()
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			return writer.Put(directory.Entry{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("person")},
					{Description: "description", Values: stringValues(description)},
				},
			}, true)
		}); err != nil {
			t.Fatalf("store description %q: %v", description, err)
		}
	}
	put("present")
	cache := newUnindexedValueCache(1 << 20)
	assertAbsent := func(assertion string) (bool, bool) {
		t.Helper()
		var absent, used bool
		if err := store.View(context.Background(), func(reader storage.Reader) error {
			var cacheErr error
			absent, used, cacheErr = cache.definitelyAbsent(
				registry,
				runtimeDatabase{},
				reader,
				directory.Filter{
					Kind:      directory.FilterEquality,
					Attribute: "description",
					Assertion: []byte(assertion),
				},
			)
			return cacheErr
		}); err != nil {
			t.Fatalf("definitelyAbsent(%q): %v", assertion, err)
		}
		return absent, used
	}
	if absent, used := assertAbsent("missing"); !absent || !used {
		t.Fatalf("missing value = absent %t used %t", absent, used)
	}
	if absent, used := assertAbsent("present"); absent || !used {
		t.Fatalf("present value = absent %t used %t", absent, used)
	}
	put("missing")
	if absent, used := assertAbsent("missing"); absent || !used {
		t.Fatalf("value after revision = absent %t used %t", absent, used)
	}
}
