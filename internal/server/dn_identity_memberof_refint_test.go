package server

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityReferenceBaseDN        = "dc=example,dc=com"
	dnIdentityReferenceUpperDN       = "exactName=Alice," + dnIdentityReferenceBaseDN
	dnIdentityReferenceLowerDN       = "exactName=alice," + dnIdentityReferenceBaseDN
	dnIdentityReferenceUpperChildDN  = "cn=child," + dnIdentityReferenceUpperDN
	dnIdentityReferenceLowerChildDN  = "cn=child," + dnIdentityReferenceLowerDN
	dnIdentityReferenceRenamedUpper  = "exactName=Renamed Alice," + dnIdentityReferenceBaseDN
	dnIdentityReferenceMovedChildDN  = "cn=child," + dnIdentityReferenceRenamedUpper
	dnIdentityReferenceFoldDN        = "foldName=Alice Smith," + dnIdentityReferenceBaseDN
	dnIdentityReferenceEquivalentDN  = "foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM"
	dnIdentityReferenceRenamedFoldDN = "foldName=Renamed Person," + dnIdentityReferenceBaseDN
	dnIdentityReferenceGroupDN       = "cn=exact-members," + dnIdentityReferenceBaseDN
	dnIdentityReferenceFoldGroupDN   = "cn=fold-members," + dnIdentityReferenceBaseDN
	dnIdentityReferenceHolderDN      = "cn=exact-holder," + dnIdentityReferenceBaseDN
	dnIdentityReferenceFoldHolderDN  = "cn=fold-holder," + dnIdentityReferenceBaseDN
)

func TestDNIdentityMemberOfAndRefintOverlays(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) storage.Store {
				t.Helper()
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}

	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			testDNIdentityMemberOfAndRefintOverlays(t, backend.open(t))
		})
	}
}

func TestDNIdentityMemberOfReferenceDeduplication(t *testing.T) {
	registry := dnIdentityReferenceRegistry(t)
	upper := dnIdentityReferenceDN(t, registry, dnIdentityReferenceUpperDN)
	lower := dnIdentityReferenceDN(t, registry, dnIdentityReferenceLowerDN)
	fold := dnIdentityReferenceDN(t, registry, dnIdentityReferenceFoldDN)
	equivalentFold := dnIdentityReferenceDN(
		t,
		registry,
		dnIdentityReferenceEquivalentDN,
	)
	entry := directory.Entry{
		DN: dnIdentityReferenceHolderDN,
		Attributes: []directory.Attribute{{
			Description: "memberOf",
			Values:      stringValues(upper.String(), fold.String()),
		}},
	}

	if !mutateDNReference(registry, &entry, "memberOf", nil, &lower) {
		t.Fatal("adding a distinct caseExact DN reported no change")
	}
	dnIdentityReferenceRequireDNs(
		t,
		registry,
		entry,
		"memberOf",
		upper.String(),
		lower.String(),
		fold.String(),
	)
	if mutateDNReference(registry, &entry, "memberOf", nil, &equivalentFold) {
		t.Fatal("adding a caseIgnore-equivalent DN reported a duplicate change")
	}
	dnIdentityReferenceRequireDNs(
		t,
		registry,
		entry,
		"memberOf",
		upper.String(),
		lower.String(),
		fold.String(),
	)
}

func testDNIdentityMemberOfAndRefintOverlays(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	t.Cleanup(func() { _ = store.Close() })

	registry := dnIdentityReferenceRegistry(t)
	database := dnIdentityReferenceDatabase(t, registry)
	runtime := &runtimeState{schema: registry}

	err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartitionWithNormalizer(
			writer,
			database.partition,
			registry,
		)
		for _, entry := range dnIdentityReferenceEntries() {
			if err := tx.Put(entry, false); err != nil {
				return fmt.Errorf("seed %q: %w", entry.DN, err)
			}
		}

		before, err := tx.Get(dnIdentityReferenceDN(t, registry, dnIdentityReferenceGroupDN))
		if err != nil {
			return err
		}
		if err := applyMemberOfAdd(runtime, tx, database, before); err != nil {
			return fmt.Errorf("apply memberOf add: %w", err)
		}
		upper, err := tx.Get(dnIdentityReferenceDN(t, registry, dnIdentityReferenceUpperDN))
		if err != nil {
			return err
		}
		lower, err := tx.Get(dnIdentityReferenceDN(t, registry, dnIdentityReferenceLowerDN))
		if err != nil {
			return err
		}
		if !dnIdentityReferenceHasDN(
			registry,
			upper,
			"memberOf",
			dnIdentityReferenceGroupDN,
		) || len(lower.Values("memberOf")) != 0 {
			return fmt.Errorf(
				"memberOf add crossed caseExact identities: upper=%q lower=%q",
				upper.Values("memberOf"),
				lower.Values("memberOf"),
			)
		}

		after := before.Clone()
		after.ReplaceValues("member", stringValues(dnIdentityReferenceLowerDN))
		if err := tx.Put(after, true); err != nil {
			return err
		}
		if err := applyMemberOfModify(runtime, tx, database, before, after); err != nil {
			return fmt.Errorf("apply memberOf modify: %w", err)
		}

		fold := directory.Entry{
			DN: dnIdentityReferenceFoldDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "dnIdentityReferenceEntry")},
				{Description: "cn", Values: stringValues("Folded Target")},
				{Description: "foldName", Values: stringValues("Alice Smith")},
			},
		}
		if err := memberOfAddCheck(
			runtime,
			tx,
			database,
			dnIdentityReferenceDN(t, registry, dnIdentityReferenceFoldDN),
			&fold,
			database.memberOf[0],
		); err != nil {
			return fmt.Errorf("memberOf add-check: %w", err)
		}
		if !dnIdentityReferenceHasDN(
			registry,
			fold,
			"memberOf",
			dnIdentityReferenceFoldGroupDN,
		) {
			return fmt.Errorf(
				"caseIgnore equivalent member was not matched: memberOf=%q",
				fold.Values("memberOf"),
			)
		}
		if err := tx.Put(fold, true); err != nil {
			return err
		}

		if err := applyRefintDelete(
			runtime,
			tx,
			database,
			dnIdentityReferenceDN(t, registry, dnIdentityReferenceUpperDN),
		); err != nil {
			return fmt.Errorf("apply refint delete: %w", err)
		}
		if err := applyRefintModifyDN(
			runtime,
			tx,
			database,
			dnIdentityReferenceDN(t, registry, dnIdentityReferenceUpperDN),
			dnIdentityReferenceDN(t, registry, dnIdentityReferenceRenamedUpper),
			true,
		); err != nil {
			return fmt.Errorf("apply refint subtree ModifyDN: %w", err)
		}
		if err := applyRefintModifyDN(
			runtime,
			tx,
			database,
			dnIdentityReferenceDN(t, registry, dnIdentityReferenceFoldDN),
			dnIdentityReferenceDN(t, registry, dnIdentityReferenceRenamedFoldDN),
			false,
		); err != nil {
			return fmt.Errorf("apply refint ModifyDN: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("overlay transaction: %v", err)
	}

	upper := dnIdentityReferenceRead(t, store, database, registry, dnIdentityReferenceUpperDN)
	lower := dnIdentityReferenceRead(t, store, database, registry, dnIdentityReferenceLowerDN)
	if len(upper.Values("memberOf")) != 0 {
		t.Fatalf("upper caseExact memberOf = %q, want empty", upper.Values("memberOf"))
	}
	dnIdentityReferenceRequireDNs(
		t,
		registry,
		lower,
		"memberOf",
		dnIdentityReferenceGroupDN,
	)

	holder := dnIdentityReferenceRead(t, store, database, registry, dnIdentityReferenceHolderDN)
	dnIdentityReferenceRequireDNs(
		t,
		registry,
		holder,
		"managerRef",
		dnIdentityReferenceLowerDN,
		dnIdentityReferenceMovedChildDN,
		dnIdentityReferenceLowerChildDN,
	)
	foldHolder := dnIdentityReferenceRead(
		t,
		store,
		database,
		registry,
		dnIdentityReferenceFoldHolderDN,
	)
	dnIdentityReferenceRequireDNs(
		t,
		registry,
		foldHolder,
		"managerRef",
		dnIdentityReferenceRenamedFoldDN,
	)
}

func dnIdentityReferenceRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.916.1 NAME 'exactName' EQUALITY caseExactMatch " +
			"ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.916.2 NAME 'foldName' EQUALITY caseIgnoreMatch " +
			"ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.916.3 NAME 'managerRef' EQUALITY distinguishedNameMatch SYNTAX " +
			schema.SyntaxDistinguishedName + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register attribute %q: %v", definition, err)
		}
	}
	definition := "( 1.3.6.1.4.1.99999.916.4 NAME 'dnIdentityReferenceEntry' " +
		"SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName $ managerRef ) )"
	if err := registry.ParseAndRegisterObjectClass(definition); err != nil {
		t.Fatalf("register object class: %v", err)
	}
	return registry
}

func dnIdentityReferenceDatabase(
	t *testing.T,
	registry *schema.Registry,
) runtimeDatabase {
	t.Helper()
	suffix := dnIdentityReferenceDN(t, registry, dnIdentityReferenceBaseDN)
	return runtimeDatabase{
		name:      "{1}mdb",
		partition: configuredDatabasePartition("{1}mdb"),
		suffixes:  []directory.DN{suffix},
		memberOf: []memberOfRuntimeConfiguration{{
			refint:            true,
			addCheck:          true,
			groupObjectClass:  "groupOfNames",
			memberAttribute:   "member",
			memberOfAttribute: "memberOf",
		}},
		refint: []refintRuntimeConfiguration{{attributes: []string{"managerRef"}}},
	}
}

func dnIdentityReferenceEntries() []directory.Entry {
	return []directory.Entry{
		{
			DN: dnIdentityReferenceBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		},
		dnIdentityReferenceTarget(dnIdentityReferenceUpperDN, "Upper Target", "exactName", "Alice"),
		dnIdentityReferenceTarget(dnIdentityReferenceLowerDN, "Lower Target", "exactName", "alice"),
		dnIdentityReferenceTarget(dnIdentityReferenceFoldDN, "Folded Target", "foldName", "Alice Smith"),
		{
			DN: dnIdentityReferenceGroupDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "groupOfNames")},
				{Description: "cn", Values: stringValues("exact-members")},
				{Description: "member", Values: stringValues(dnIdentityReferenceUpperDN)},
			},
		},
		{
			DN: dnIdentityReferenceFoldGroupDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "groupOfNames")},
				{Description: "cn", Values: stringValues("fold-members")},
				{Description: "member", Values: stringValues(dnIdentityReferenceEquivalentDN)},
			},
		},
		{
			DN: dnIdentityReferenceHolderDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "dnIdentityReferenceEntry")},
				{Description: "cn", Values: stringValues("exact-holder")},
				{Description: "managerRef", Values: stringValues(
					dnIdentityReferenceUpperDN,
					dnIdentityReferenceLowerDN,
					dnIdentityReferenceUpperChildDN,
					dnIdentityReferenceLowerChildDN,
				)},
			},
		},
		{
			DN: dnIdentityReferenceFoldHolderDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "dnIdentityReferenceEntry")},
				{Description: "cn", Values: stringValues("fold-holder")},
				{Description: "managerRef", Values: stringValues(
					dnIdentityReferenceEquivalentDN,
					dnIdentityReferenceRenamedFoldDN,
				)},
			},
		},
	}
}

func dnIdentityReferenceTarget(
	dn,
	commonName,
	namingAttribute,
	namingValue string,
) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "dnIdentityReferenceEntry")},
			{Description: "cn", Values: stringValues(commonName)},
			{Description: namingAttribute, Values: stringValues(namingValue)},
		},
	}
}

func dnIdentityReferenceDN(
	t *testing.T,
	registry *schema.Registry,
	raw string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(raw)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", raw, err)
	}
	return dn
}

func dnIdentityReferenceRead(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	registry *schema.Registry,
	rawDN string,
) directory.Entry {
	t.Helper()
	var result directory.Entry
	err := store.View(context.Background(), func(reader storage.Reader) error {
		tx := storage.ReaderInPartitionWithNormalizer(
			reader,
			database.partition,
			registry,
		)
		var err error
		result, err = tx.Get(dnIdentityReferenceDN(t, registry, rawDN))
		return err
	})
	if err != nil {
		t.Fatalf("read %q: %v", rawDN, err)
	}
	return result
}

func dnIdentityReferenceHasDN(
	registry *schema.Registry,
	entry directory.Entry,
	attribute,
	want string,
) bool {
	target, err := registry.NormalizeDN(want)
	if err != nil {
		return false
	}
	for _, value := range entry.Values(attribute) {
		candidate, err := registry.NormalizeDN(string(value))
		if err == nil && candidate.Equal(target) {
			return true
		}
	}
	return false
}

func dnIdentityReferenceRequireDNs(
	t *testing.T,
	registry *schema.Registry,
	entry directory.Entry,
	attribute string,
	want ...string,
) {
	t.Helper()
	values := entry.Values(attribute)
	if len(values) != len(want) {
		t.Fatalf("%s on %q = %q, want %q", attribute, entry.DN, values, want)
	}
	remaining := make(map[string]struct{}, len(want))
	for _, raw := range want {
		remaining[dnIdentityReferenceDN(t, registry, raw).Key()] = struct{}{}
	}
	for _, value := range values {
		dn := dnIdentityReferenceDN(t, registry, string(value))
		if _, found := remaining[dn.Key()]; !found {
			t.Fatalf("%s on %q contains unexpected DN %q", attribute, entry.DN, value)
		}
		delete(remaining, dn.Key())
	}
	if len(remaining) != 0 {
		t.Fatalf("%s on %q is missing identities %v", attribute, entry.DN, remaining)
	}
}
