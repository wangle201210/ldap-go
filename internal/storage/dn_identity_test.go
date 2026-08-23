package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type testDNNormalizer struct{}

func (testDNNormalizer) NormalizeDNAttribute(
	attributeType string,
	value []byte,
) (string, []byte, error) {
	switch strings.ToLower(attributeType) {
	case "exactname", "1.3.6.1.4.1.99999.900":
		return "1.3.6.1.4.1.99999.900", []byte(strings.Join(strings.Fields(string(value)), " ")), nil
	case "uid", "userid", "0.9.2342.19200300.100.1.1":
		return "0.9.2342.19200300.100.1.1", []byte(strings.ToLower(strings.Join(strings.Fields(string(value)), " "))), nil
	case "dc", "domaincomponent", "0.9.2342.19200300.100.1.25":
		return "0.9.2342.19200300.100.1.25", []byte(lowerASCII(string(value))), nil
	default:
		return "", nil, errors.New("undefined naming attribute")
	}
}

type testCanonicalDNNormalizer struct{ testDNNormalizer }

func (testCanonicalDNNormalizer) CanonicalDNAttributeName(
	attributeType string,
) (string, error) {
	switch strings.ToLower(attributeType) {
	case "exactname", "1.3.6.1.4.1.99999.900":
		return "exactName", nil
	case "uid", "userid", "0.9.2342.19200300.100.1.1":
		return "uid", nil
	case "dc", "domaincomponent", "0.9.2342.19200300.100.1.25":
		return "dc", nil
	default:
		return "", errors.New("undefined naming attribute")
	}
}

func TestSchemaAwarePartitionCanonicalizesStoredDN(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemory() }},
		{name: "bolt", open: func(t *testing.T) Store {
			store, err := OpenBolt(filepath.Join(t.TempDir(), "canonical-dn.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := test.open(t)
			t.Cleanup(func() { _ = store.Close() })
			ctx := context.Background()
			normalizer := testCanonicalDNNormalizer{}
			entry := directory.Entry{
				DN: "userid=Platform+1.3.6.1.4.1.99999.900=Carol," +
					"domainComponent=example,dc=com",
			}
			if err := store.Update(ctx, func(writer Writer) error {
				return WriterInPartitionWithNormalizer(
					writer,
					"db",
					normalizer,
				).Put(entry, false)
			}); err != nil {
				t.Fatalf("Put(): %v", err)
			}
			if err := store.View(ctx, func(reader Reader) error {
				dn, err := directory.ParseDN(entry.DN)
				if err != nil {
					return err
				}
				got, err := ReaderInPartitionWithNormalizer(
					reader,
					"db",
					normalizer,
				).Get(dn)
				if err != nil {
					return err
				}
				const want = "exactName=Carol+uid=Platform,dc=example,dc=com"
				if got.DN != want {
					t.Fatalf("stored DN = %q, want %q", got.DN, want)
				}
				return nil
			}); err != nil {
				t.Fatalf("Get(): %v", err)
			}
		})
	}
}

func TestSchemaAwarePartitionRuntimeAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemory() }},
		{name: "bolt", open: func(t *testing.T) Store {
			store, err := OpenBolt(filepath.Join(t.TempDir(), "runtime-identity.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := test.open(t)
			t.Cleanup(func() { _ = store.Close() })
			runSchemaAwarePartitionRuntimeAccess(t, store)
		})
	}
}

func TestLegacyPartitionLookupRemainsCaseFolded(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemory() }},
		{name: "bolt", open: func(t *testing.T) Store {
			store, err := OpenBolt(filepath.Join(t.TempDir(), "legacy-casefold.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := test.open(t)
			t.Cleanup(func() { _ = store.Close() })
			ctx := context.Background()
			entry := directory.Entry{DN: "uid=Alice,dc=Example,dc=COM"}
			if err := store.Update(ctx, func(writer Writer) error {
				return writer.PutIn("legacy", entry, false)
			}); err != nil {
				t.Fatalf("PutIn(): %v", err)
			}
			lookup, err := directory.ParseDN("UID=ALICE,DC=EXAMPLE,DC=com")
			if err != nil {
				t.Fatalf("ParseDN(): %v", err)
			}
			if err := store.View(ctx, func(reader Reader) error {
				got, err := reader.GetIn("legacy", lookup)
				if err != nil {
					return err
				}
				if got.DN != entry.DN {
					t.Fatalf("GetIn().DN = %q, want %q", got.DN, entry.DN)
				}
				return nil
			}); err != nil {
				t.Fatalf("legacy case-folded GetIn(): %v", err)
			}
			if err := store.Update(ctx, func(writer Writer) error {
				return writer.DeleteIn("legacy", lookup)
			}); err != nil {
				t.Fatalf("legacy case-folded DeleteIn(): %v", err)
			}
			if err := store.Update(ctx, func(writer Writer) error {
				return writer.Put(entry, false)
			}); err != nil {
				t.Fatalf("Put(): %v", err)
			}
			if err := store.View(ctx, func(reader Reader) error {
				got, err := reader.Get(lookup)
				if err != nil {
					return err
				}
				if got.DN != entry.DN {
					t.Fatalf("Get().DN = %q, want %q", got.DN, entry.DN)
				}
				return nil
			}); err != nil {
				t.Fatalf("legacy case-folded Get(): %v", err)
			}
			if err := store.Update(ctx, func(writer Writer) error {
				return writer.Delete(lookup)
			}); err != nil {
				t.Fatalf("legacy case-folded Delete(): %v", err)
			}
		})
	}
}

func TestInferNamingContextsWithNormalizerRecognizesConfigDNInPendingPartition(
	t *testing.T,
) {
	store := NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer Writer) error {
		for _, entry := range []directory.Entry{
			{DN: "cn=config"},
			{DN: "olcDatabase={0}config,cn=config"},
			{DN: "uid=Alice,dc=example,dc=com"},
		} {
			if err := writer.PutIn("pending", entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed pending partition: %v", err)
	}
	if err := store.View(context.Background(), func(reader Reader) error {
		contexts, err := InferNamingContextsWithNormalizer(reader, testDNNormalizer{})
		if err != nil {
			return err
		}
		for _, want := range []string{"cn=config", "uid=Alice,dc=example,dc=com"} {
			found := false
			for _, got := range contexts {
				if got == want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("namingContexts = %q, missing %q", contexts, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("InferNamingContextsWithNormalizer(): %v", err)
	}
}

func runSchemaAwarePartitionRuntimeAccess(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	entries := []directory.Entry{
		{DN: "exactName=Alice,dc=example,dc=com"},
		{DN: "exactName=alice,dc=example,dc=com"},
		{DN: "uid=Alice,dc=example,dc=com"},
	}
	if err := store.Update(ctx, func(writer Writer) error {
		scoped := WriterInPartitionWithNormalizer(writer, "db", testDNNormalizer{})
		for _, entry := range entries {
			if err := scoped.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("schema-aware Put(): %v", err)
	}

	if err := store.View(ctx, func(reader Reader) error {
		scoped := ReaderInPartitionWithNormalizer(reader, "db", testDNNormalizer{})
		for _, value := range []string{
			"exactName=Alice,dc=example,dc=com",
			"exactName=alice,dc=example,dc=com",
		} {
			dn, err := directory.ParseDN(value)
			if err != nil {
				return err
			}
			entry, err := scoped.Get(dn)
			if err != nil {
				return err
			}
			if entry.DN != value {
				t.Fatalf("Get(%q).DN = %q", value, entry.DN)
			}
		}
		folded, err := directory.ParseDN("uid=ALICE,dc=EXAMPLE,dc=COM")
		if err != nil {
			return err
		}
		entry, err := scoped.Get(folded)
		if err != nil {
			return err
		}
		if entry.DN != "uid=Alice,dc=example,dc=com" {
			t.Fatalf("caseIgnore Get().DN = %q", entry.DN)
		}
		wrongExact, err := directory.ParseDN("exactName=ALICE,dc=example,dc=com")
		if err != nil {
			return err
		}
		if _, err := scoped.Get(wrongExact); !errors.Is(err, ErrEntryNotFound) {
			t.Fatalf("wrong caseExact lookup error = %v, want ErrEntryNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("schema-aware Get(): %v", err)
	}

	if err := store.Update(ctx, func(writer Writer) error {
		scoped := WriterInPartitionWithNormalizer(writer, "db", testDNNormalizer{})
		replacement := entries[2].Clone()
		replacement.Attributes = []directory.Attribute{
			{Description: "description", Values: [][]byte{[]byte("updated")}},
		}
		if err := scoped.Put(replacement, true); err != nil {
			return err
		}
		deleteDN, err := directory.ParseDN("exactName=Alice,dc=example,dc=com")
		if err != nil {
			return err
		}
		return scoped.Delete(deleteDN)
	}); err != nil {
		t.Fatalf("schema-aware replace/delete: %v", err)
	}
	if err := store.View(ctx, func(reader Reader) error {
		scoped := ReaderInPartitionWithNormalizer(reader, "db", testDNNormalizer{})
		deleted, _ := directory.ParseDN("exactName=Alice,dc=example,dc=com")
		if _, err := scoped.Get(deleted); !errors.Is(err, ErrEntryNotFound) {
			t.Fatalf("deleted exact DN lookup error = %v", err)
		}
		remaining, _ := directory.ParseDN("exactName=alice,dc=example,dc=com")
		if _, err := scoped.Get(remaining); err != nil {
			return err
		}
		folded, _ := directory.ParseDN("uid=ALICE,dc=example,dc=com")
		entry, err := scoped.Get(folded)
		if err != nil {
			return err
		}
		if values := entry.Values("description"); len(values) != 1 || string(values[0]) != "updated" {
			t.Fatalf("replacement values = %q", values)
		}
		if _, ok := entry.DNIdentity(); ok {
			t.Fatal("transient DN identity leaked from storage")
		}
		return nil
	}); err != nil {
		t.Fatalf("verify schema-aware writes: %v", err)
	}
}

func TestStoreSchemaAwareDNIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemory() }},
		{name: "bolt", open: func(t *testing.T) Store {
			store, err := OpenBolt(filepath.Join(t.TempDir(), "identity.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := test.open(t)
			t.Cleanup(func() { _ = store.Close() })
			runSchemaAwareDNIdentityContract(t, store)
		})
	}
}

func runSchemaAwareDNIdentityContract(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	upper := directory.Entry{DN: "exactName=Alice,dc=example,dc=com"}
	lower := directory.Entry{DN: "exactName=alice,dc=example,dc=com"}
	upperDN := mustSchemaAwareDN(t, upper.DN)
	lowerDN := mustSchemaAwareDN(t, lower.DN)
	if upperDN.Key() == lowerDN.Key() {
		t.Fatal("schema-aware test DNs have the same key")
	}

	if err := store.Update(ctx, func(writer Writer) error {
		if err := PutInWithDN(writer, "db", upper, upperDN, false); err != nil {
			return err
		}
		return PutInWithDN(writer, "db", lower, lowerDN, false)
	}); err != nil {
		t.Fatalf("store caseExact entries: %v", err)
	}

	if err := store.View(ctx, func(reader Reader) error {
		gotUpper, err := reader.GetIn("db", upperDN)
		if err != nil {
			return err
		}
		gotLower, err := reader.GetIn("db", lowerDN)
		if err != nil {
			return err
		}
		if gotUpper.DN != upper.DN || gotLower.DN != lower.DN {
			t.Fatalf("stored DNs = %q, %q", gotUpper.DN, gotLower.DN)
		}
		legacyFolded, err := directory.ParseDN("exactName=ALICE,dc=example,dc=com")
		if err != nil {
			return err
		}
		if _, err := reader.GetIn("db", legacyFolded); !errors.Is(err, ErrEntryNotFound) {
			t.Fatalf("legacy folded lookup error = %v, want ErrEntryNotFound", err)
		}
		count := 0
		if err := reader.ForEachIn("db", func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 2 {
			t.Fatalf("ForEachIn() count = %d, want 2", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("read schema-aware entries: %v", err)
	}

	if err := store.Update(ctx, func(writer Writer) error {
		return writer.DeleteIn("db", upperDN)
	}); err != nil {
		t.Fatalf("DeleteIn(upper): %v", err)
	}
	if err := store.View(ctx, func(reader Reader) error {
		if _, err := reader.GetIn("db", upperDN); !errors.Is(err, ErrEntryNotFound) {
			t.Fatalf("deleted upper lookup error = %v", err)
		}
		_, err := reader.GetIn("db", lowerDN)
		return err
	}); err != nil {
		t.Fatalf("lower entry disappeared: %v", err)
	}
}

func TestPutInWithDNMigratesLegacyKeyOnReplace(t *testing.T) {
	t.Parallel()

	store := NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{DN: "exactName=Alice,dc=example,dc=com"}
	identityDN := mustSchemaAwareDN(t, entry.DN)
	ctx := context.Background()
	if err := store.Update(ctx, func(writer Writer) error {
		if err := writer.PutIn("db", entry, false); err != nil {
			return err
		}
		return PutInWithDN(writer, "db", entry, identityDN, true)
	}); err != nil {
		t.Fatalf("migrate legacy entry: %v", err)
	}
	if err := store.View(ctx, func(reader Reader) error {
		count := 0
		if err := reader.ForEachIn("db", func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("entry count after migration = %d, want 1", count)
		}
		_, err := reader.GetIn("db", identityDN)
		return err
	}); err != nil {
		t.Fatalf("read migrated entry: %v", err)
	}
}

func mustSchemaAwareDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(value, testDNNormalizer{})
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", value, err)
	}
	return dn
}

func lowerASCII(value string) string {
	buffer := []byte(value)
	for index := range buffer {
		if buffer[index] >= 'A' && buffer[index] <= 'Z' {
			buffer[index] += 'a' - 'A'
		}
	}
	return string(buffer)
}
