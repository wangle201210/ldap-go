package server

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSortableLDAPIntegerPreservesOrdering(t *testing.T) {
	values := []string{"-100", "-10", "-2", "-1", "0", "1", "2", "10", "100"}
	encoded := make([][]byte, len(values))
	for index, value := range values {
		var err error
		encoded[index], err = sortableLDAPInteger([]byte(value))
		if err != nil {
			t.Fatalf("sortableLDAPInteger(%q): %v", value, err)
		}
	}
	for left := range encoded {
		for right := left + 1; right < len(encoded); right++ {
			if bytes.Compare(encoded[left], encoded[right]) >= 0 {
				t.Fatalf("encoded %s does not sort before %s", values[left], values[right])
			}
		}
	}
}

func TestGeneralizedTimeOrderingIndexPreservesFractionalSecondOrdering(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	configEntry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcDbIndex",
			Values:      [][]byte{[]byte("createTimestamp ordering")},
		}},
	}
	normalizer, _, err := loadDatabaseEqualityIndexes(configEntry, registry)
	if err != nil {
		t.Fatal(err)
	}
	indexed := normalizer.(*databaseEqualityIndexNormalizer)

	wholeSecond := []byte("20260823010205Z")
	fractionalSecond := []byte("20260823010205.1Z")
	comparison, err := registry.CompareOrdering(
		"createTimestamp",
		"",
		wholeSecond,
		fractionalSecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if comparison >= 0 {
		t.Fatalf("whole-second comparison = %d, want less than fractional second", comparison)
	}
	wholeKey, err := indexed.NormalizeOrderingIndexAssertion("createTimestamp", wholeSecond)
	if err != nil {
		t.Fatal(err)
	}
	fractionalKey, err := indexed.NormalizeOrderingIndexAssertion("createTimestamp", fractionalSecond)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(wholeKey, fractionalKey) >= 0 {
		t.Fatalf("ordering index keys %q and %q do not preserve generalizedTime ordering", wholeKey, fractionalKey)
	}

	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			t.Helper()
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
			if err != nil {
				t.Fatal(err)
			}
			return store
		}},
	}
	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				for _, entry := range []directory.Entry{
					{
						DN: "cn=whole,dc=example",
						Attributes: []directory.Attribute{{
							Description: "createTimestamp",
							Values:      [][]byte{wholeSecond},
						}},
					},
					{
						DN: "cn=fractional,dc=example",
						Attributes: []directory.Attribute{{
							Description: "createTimestamp",
							Values:      [][]byte{fractionalSecond},
						}},
					},
				} {
					if err := writer.PutIn("db", entry, false); err != nil {
						return err
					}
				}
				return storage.EnsureEqualityIndexes(writer, "db", indexed)
			}); err != nil {
				t.Fatal(err)
			}

			for _, filter := range []directory.Filter{
				{
					Kind:      directory.FilterGreaterOrEqual,
					Attribute: "createTimestamp",
					Assertion: wholeSecond,
				},
				{
					Kind:      directory.FilterLessOrEqual,
					Attribute: "createTimestamp",
					Assertion: fractionalSecond,
				},
			} {
				err := store.View(context.Background(), func(reader storage.Reader) error {
					planned, candidates, err := storage.ForEachFilterCandidate(
						storage.ReaderInPartitionWithNormalizer(reader, "db", indexed),
						filter,
						func(entry directory.Entry) error {
							matches := false
							for _, value := range registry.AttributeValues(entry, filter.Attribute) {
								comparison, err := registry.CompareOrdering(
									filter.Attribute,
									"",
									value,
									filter.Assertion,
								)
								if err != nil {
									return err
								}
								matches = matches ||
									filter.Kind == directory.FilterGreaterOrEqual && comparison >= 0 ||
									filter.Kind == directory.FilterLessOrEqual && comparison <= 0
							}
							if !matches {
								t.Fatalf("index returned non-matching entry %q", entry.DN)
							}
							return nil
						},
					)
					if err == nil && (!planned || candidates != 2) {
						t.Fatalf("filter kind %d planned=%v candidates=%d, want true and 2", filter.Kind, planned, candidates)
					}
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestLoadDatabaseEqualityIndexesAliasOIDAndModes(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDbIndex", Values: [][]byte{
				[]byte("{0}cn eq,pres,sub"),
				[]byte("{1}0.9.2342.19200300.100.1.1 eq,pres,sub"),
				[]byte("{2}2.5.4.3 eq"),
				[]byte("{3}uidNumber ordering"),
			}},
		},
	}
	normalizer, config, err := loadDatabaseEqualityIndexes(entry, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Attributes) != 3 {
		t.Fatalf("config = %#v", config)
	}
	indexed, ok := normalizer.(*databaseEqualityIndexNormalizer)
	if !ok {
		t.Fatalf("normalizer type = %T", normalizer)
	}
	canonical, equality, presence, err := indexed.ResolveEqualityIndexAttribute("cn")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "2.5.4.3" || !equality || !presence {
		t.Fatalf("cn mode = %q %v %v", canonical, equality, presence)
	}
	canonical, equality, presence, err = indexed.ResolveEqualityIndexAttribute("userid")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "0.9.2342.19200300.100.1.1" || !equality || !presence {
		t.Fatalf("uid mode = %q %v %v", canonical, equality, presence)
	}
	normalized, err := indexed.NormalizeEqualityIndexAssertion("cn", []byte("  ALICE  "))
	if err != nil {
		t.Fatal(err)
	}
	if string(normalized) != "alice" {
		t.Fatalf("normalized assertion = %q", normalized)
	}
	canonical, initial, any, final, err := indexed.ResolveSubstringIndexAttribute("cn")
	if err != nil || canonical != "2.5.4.3" || !initial || !any || !final {
		t.Fatalf("cn substring mode = %q %v %v %v err=%v", canonical, initial, any, final, err)
	}
	canonical, ordering, err := indexed.ResolveOrderingIndexAttribute("uidNumber")
	if err != nil || canonical != "1.3.6.1.1.1.1.0" || !ordering {
		t.Fatalf("uidNumber ordering mode = %q %v err=%v", canonical, ordering, err)
	}
}

func TestLoadDatabaseEqualityIndexesRejectsUnimplementedModes(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"cn approx",
		"objectClass sub",
		"objectClass ordering",
		"cn nolang",
		"default eq",
	} {
		t.Run(strings.ReplaceAll(value, " ", "_"), func(t *testing.T) {
			entry := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcDbIndex",
					Values:      [][]byte{[]byte(value)},
				}},
			}
			if _, _, err := loadDatabaseEqualityIndexes(entry, registry); err == nil {
				t.Fatalf("olcDbIndex %q was accepted", value)
			}
		})
	}
}

func TestDatabaseEqualityIndexObjectClassIncludesAncestors(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcDbIndex",
			Values:      [][]byte{[]byte("objectClass eq")},
		}},
	}
	normalizer, _, err := loadDatabaseEqualityIndexes(entry, registry)
	if err != nil {
		t.Fatal(err)
	}
	indexed := normalizer.(*databaseEqualityIndexNormalizer)
	values, err := indexed.EqualityIndexValues(directory.Entry{
		DN: "cn=Alice,dc=example",
		Attributes: []directory.Attribute{{
			Description: "objectClass",
			Values:      [][]byte{[]byte("inetOrgPerson")},
		}},
	}, "2.5.4.0")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"inetorgperson":        true,
		"organizationalperson": true,
		"person":               true,
		"top":                  true,
	}
	for _, value := range values {
		delete(want, strings.ToLower(string(value)))
	}
	if len(want) != 0 {
		t.Fatalf("missing normalized objectClass ancestors: %v; values=%q", want, values)
	}
}

func TestEnsureSearchEqualityIndexesFirstBuildAndReload(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	configEntry := func(index string) directory.Entry {
		return directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcDbIndex",
				Values:      [][]byte{[]byte(index)},
			}},
		}
	}
	cnNormalizer, cnConfig, err := loadDatabaseEqualityIndexes(
		configEntry("cn eq,pres,sub"),
		registry,
	)
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewMemory()
	defer store.Close()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn("db", directory.Entry{
			DN: "cn=Alice,dc=example",
			Attributes: []directory.Attribute{
				{Description: "cn", Values: [][]byte{[]byte("Alice")}},
				{Description: "uid", Values: [][]byte{[]byte("a1")}},
				{Description: "uidNumber", Values: [][]byte{[]byte("100")}},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	instance := &Server{config: Config{Store: store}}
	runtime := &runtimeState{databases: []runtimeDatabase{{
		name:              "{1}mdb",
		partition:         "db",
		dnNormalizer:      cnNormalizer,
		equalityIndexes:   cnConfig,
		equalityIndexInit: &databaseEqualityIndexInitialization{},
	}}}
	routes := []databaseSearchRoute{{databaseIndex: 0}}
	instance.ensureSearchEqualityIndexes(context.Background(), runtime, routes)
	assertServerIndexPlanned(t, store, runtime.databases[0], directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("ALICE"),
	})
	assertServerIndexPlanned(t, store, runtime.databases[0], directory.Filter{
		Kind:      directory.FilterSubstrings,
		Attribute: "cn",
		Substring: directory.Substring{Any: [][]byte{[]byte("lic")}},
	})

	uidNormalizer, uidConfig, err := loadDatabaseEqualityIndexes(
		configEntry("userid eq,pres"),
		registry,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime.databases[0].dnNormalizer = uidNormalizer
	runtime.databases[0].equalityIndexes = uidConfig
	runtime.databases[0].equalityIndexInit = &databaseEqualityIndexInitialization{}
	instance.ensureSearchEqualityIndexes(context.Background(), runtime, routes)
	assertServerIndexPlanned(t, store, runtime.databases[0], directory.Filter{
		Kind: directory.FilterEquality, Attribute: "0.9.2342.19200300.100.1.1", Assertion: []byte("A1"),
	})
}

func assertServerIndexPlanned(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	filter directory.Filter,
) {
	t.Helper()
	err := store.View(context.Background(), func(reader storage.Reader) error {
		planned, candidates, err := storage.ForEachFilterCandidate(
			readerForDatabase(reader, database),
			filter,
			func(directory.Entry) error { return nil },
		)
		if err != nil {
			return err
		}
		if !planned || candidates != 1 {
			t.Fatalf("planned=%v candidates=%d", planned, candidates)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
