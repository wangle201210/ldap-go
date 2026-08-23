package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadDatabaseEqualityIndexesAliasOIDAndModes(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDbIndex", Values: [][]byte{
				[]byte("{0}cn,0.9.2342.19200300.100.1.1 eq,pres"),
				[]byte("{1}2.5.4.3 eq"),
			}},
		},
	}
	normalizer, config, err := loadDatabaseEqualityIndexes(entry, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Attributes) != 2 {
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
}

func TestLoadDatabaseEqualityIndexesRejectsUnimplementedModes(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"cn sub",
		"cn approx",
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
		configEntry("cn eq,pres"),
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
