package server

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type recordingDNParserRegistry struct {
	*schema.Registry
	calls int
	fail  error
}

func (registry *recordingDNParserRegistry) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	registry.calls++
	if registry.fail != nil {
		return "", nil, registry.fail
	}
	return registry.Registry.NormalizeDNAttribute(attribute, value)
}

func TestRuntimeDNParserPreservesCustomCallbacks(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	custom := &recordingDNParserRegistry{Registry: registry}
	normalizer := &databaseEqualityIndexNormalizer{registry: custom}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, reader := range []storage.Reader{
			storage.ReaderInPartitionWithNormalizer(writer, "db", normalizer),
			storage.WriterInPartitionWithNormalizer(writer, "db", normalizer),
		} {
			for _, raw := range []string{"CN=Alice,DC=Example,DC=Com", "cn=a+uid=b,dc=com", "undefined=a", "cn=broken,"} {
				for range 2 {
					want, wantErr := directory.ParseDNWithNormalizer(raw, normalizer)
					custom.calls = 0
					got, gotErr := parseRuntimeDN(raw, normalizer)
					if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
						t.Fatalf("parse %q: %v/%v", raw, gotErr, wantErr)
					}
					legacy, err := directory.ParseDN(raw)
					if err != nil {
						continue
					}
					want, wantErr = directory.ParseDNWithNormalizer(legacy.String(), normalizer)
					custom.calls = 0
					got, gotErr = storage.NormalizeReaderDN(reader, legacy)
					if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || custom.calls == 0 {
						t.Fatalf("normalize %q: callbacks=%d errors=%v/%v", raw, custom.calls, gotErr, wantErr)
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	custom.fail = errors.New("changed custom normalizer")
	if _, err := normalizer.ParseDNIdentity("cn=alice"); !errors.Is(err, custom.fail) {
		t.Fatalf("custom parser hid changing error: %v", err)
	}
}

func TestRuntimeDNParserSeesSchemaChanges(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	normalizer := &databaseEqualityIndexNormalizer{registry: registry}
	before, err := normalizer.ParseDNIdentity("uid=Alice,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	attribute, _ := registry.AttributeType("uid")
	attribute.Equality = "caseExactMatch"
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	after, err := normalizer.ParseDNIdentity("uid=Alice,dc=com")
	if err != nil || before.Equal(after) {
		t.Fatalf("schema update retained old identity: %v", err)
	}
	got, err := normalizer.ParseDNIdentity("uid=alice,dc=com")
	if err != nil || after.Equal(got) {
		t.Fatalf("caseExact identities collapsed: %v", err)
	}
}
