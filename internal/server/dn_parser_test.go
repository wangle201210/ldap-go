package server

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
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

func TestRuntimeACLDNParserReference(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ParseAndRegisterAttributeType("( 1.2.3.101 NAME ( 'aclCaseName' 'aclCaseAlias' ) EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"); err != nil {
		t.Fatal(err)
	}
	var parser acl.DNIdentityParser = aclDNNormalizer{Registry: registry}
	for _, raw := range []string{
		"", "cn=config", "CN=Alice,DC=EXAMPLE,DC=COM", "uid=alice+cn=Alice,dc=com",
		`cn=Smith\, Alice,dc=com`, "cn=\u7528\u6237,dc=com", "aclCaseAlias=Alice,dc=com",
		"1.2.3.101=alice,dc=com", "unknown=Alice", "cn=broken,", "cn", "cn=\xff",
	} {
		for range 2 {
			want, wantErr := directory.ParseDNWithNormalizer(raw, registry)
			got, gotErr := parser.ParseDNIdentity(raw)
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
				t.Fatalf("parse %q: got %#v/%v, want %#v/%v", raw, got, gotErr, want, wantErr)
			}
		}
	}
}

type aclDNParserMappedReader struct {
	storage.Reader
	entry directory.Entry
}

func (reader aclDNParserMappedReader) remoteACLView(_ string, _ directory.Entry, attribute string, value []byte) (storage.Reader, string, directory.Entry, string, []byte, error) {
	return reader.Reader, "uid=alice,dc=com", reader.entry, attribute, value, nil
}

func TestRuntimeACLDNParserRefreshesLocalAndRemoteAuthorization(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote=%t", remote), func(t *testing.T) {
			registry, err := schema.NewBuiltinRegistry()
			if err != nil {
				t.Fatal(err)
			}
			rule, err := acl.ParseRule("to * by self read by * none")
			if err != nil {
				t.Fatal(err)
			}
			policy, err := acl.NewPolicy([]acl.Rule{rule}, nil)
			if err != nil {
				t.Fatal(err)
			}
			runtime := &runtimeState{schema: registry, access: policy}
			server := &Server{}
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			entry := directory.Entry{DN: "uid=Alice,dc=com"}
			check := func(want bool) {
				t.Helper()
				if err := store.View(t.Context(), func(reader storage.Reader) error {
					subject := "uid=alice,dc=com"
					if remote {
						reader = aclDNParserMappedReader{Reader: reader, entry: entry}
						subject = "uid=remote,dc=com"
					}
					for range 3 {
						if got := server.allowed(runtime, reader, subject, entry, "mail", []byte("alice@example.com"), acl.Read); got != want {
							t.Fatalf("allowed=%t, want %t", got, want)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			check(true)
			attribute, _ := registry.AttributeType("uid")
			attribute.Equality = "caseExactMatch"
			if err := registry.UpsertAttributeType(attribute); err != nil {
				t.Fatal(err)
			}
			check(false)
			entry.DN = "uid=alice,dc=com"
			check(true)
			deny, err := acl.ParseRule("to * by * none")
			if err != nil {
				t.Fatal(err)
			}
			runtime.access, err = acl.NewPolicy([]acl.Rule{deny}, nil)
			if err != nil {
				t.Fatal(err)
			}
			check(false)
		})
	}
}
