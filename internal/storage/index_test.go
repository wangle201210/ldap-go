package storage

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type indexTestSchema struct {
	config EqualityIndexConfig
	failOn string
}

func (schema indexTestSchema) NormalizeDNAttribute(
	attribute string,
	value []byte,
) (string, []byte, error) {
	canonical, ok := indexTestAttribute(attribute)
	if !ok {
		return "", nil, errors.New("undefined attribute")
	}
	return canonical, indexTestNormalize(value), nil
}

func (schema indexTestSchema) CanonicalDNAttributeName(attribute string) (string, error) {
	canonical, ok := indexTestAttribute(attribute)
	if !ok {
		return "", errors.New("undefined attribute")
	}
	switch canonical {
	case "2.5.4.3":
		return "cn", nil
	case "0.9.2342.19200300.100.1.1":
		return "uid", nil
	default:
		return "dc", nil
	}
}

func (schema indexTestSchema) EqualityIndexConfiguration() EqualityIndexConfig {
	return schema.config
}

func (schema indexTestSchema) ResolveEqualityIndexAttribute(
	description string,
) (string, bool, bool, error) {
	canonical, ok := indexTestAttribute(description)
	if !ok {
		return "", false, false, nil
	}
	for _, configured := range schema.config.Attributes {
		if configured.Attribute == canonical {
			return canonical, configured.Equality, configured.Presence, nil
		}
	}
	return canonical, false, false, nil
}

func (schema indexTestSchema) ResolveApproximateIndexAttribute(
	description string,
) (string, bool, bool, error) {
	canonical, ok := indexTestAttribute(description)
	if !ok {
		return "", false, false, nil
	}
	for _, configured := range schema.config.Attributes {
		if configured.Attribute == canonical {
			return canonical, configured.Approximate, configured.Equality && !configured.Approximate, nil
		}
	}
	return canonical, false, false, nil
}

func (schema indexTestSchema) ApproximateIndexAssertionTerms(
	_ string,
	value []byte,
) ([][]byte, bool, error) {
	return indexTestApproximateTerms(value), true, nil
}

func (schema indexTestSchema) ApproximateIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	values, err := schema.EqualityIndexValues(entry, canonicalAttribute)
	if err != nil {
		return nil, err
	}
	var result [][]byte
	for _, value := range values {
		result = append(result, indexTestApproximateTerms(value)...)
	}
	return result, nil
}

func (schema indexTestSchema) NormalizeEqualityIndexAssertion(
	_ string,
	value []byte,
) ([]byte, error) {
	if string(value) == schema.failOn {
		return nil, errors.New("injected index normalization failure")
	}
	return indexTestNormalize(value), nil
}

func (schema indexTestSchema) EqualityIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	var result [][]byte
	for _, attribute := range entry.Attributes {
		canonical, ok := indexTestAttribute(attribute.Description)
		if !ok || canonical != canonicalAttribute {
			continue
		}
		for _, value := range attribute.Values {
			if string(value) == schema.failOn {
				return nil, errors.New("injected index normalization failure")
			}
			result = append(result, indexTestNormalize(value))
		}
	}
	return result, nil
}

func (schema indexTestSchema) ResolveSubstringIndexAttribute(
	description string,
) (string, bool, bool, bool, error) {
	canonical, ok := indexTestAttribute(description)
	if !ok {
		return "", false, false, false, nil
	}
	for _, configured := range schema.config.Attributes {
		if configured.Attribute == canonical {
			return canonical, configured.SubstringInitial, configured.SubstringAny, configured.SubstringFinal, nil
		}
	}
	return canonical, false, false, false, nil
}

func (schema indexTestSchema) NormalizeSubstringIndexAssertion(
	_ string,
	value directory.Substring,
) (directory.Substring, error) {
	result := directory.Substring{}
	if value.Initial != nil {
		result.Initial = indexTestNormalize(value.Initial)
	}
	for _, part := range value.Any {
		result.Any = append(result.Any, indexTestNormalize(part))
	}
	if value.Final != nil {
		result.Final = indexTestNormalize(value.Final)
	}
	return result, nil
}

func (schema indexTestSchema) SubstringIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	return schema.EqualityIndexValues(entry, canonicalAttribute)
}

func (schema indexTestSchema) ResolveOrderingIndexAttribute(
	description string,
) (string, bool, error) {
	canonical, ok := indexTestAttribute(description)
	if !ok {
		return "", false, nil
	}
	for _, configured := range schema.config.Attributes {
		if configured.Attribute == canonical {
			return canonical, configured.Ordering, nil
		}
	}
	return canonical, false, nil
}

func (schema indexTestSchema) NormalizeOrderingIndexAssertion(
	_ string,
	value []byte,
) ([]byte, error) {
	if string(value) == schema.failOn {
		return nil, errors.New("injected index normalization failure")
	}
	return indexTestNormalize(value), nil
}

func (schema indexTestSchema) OrderingIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	return schema.EqualityIndexValues(entry, canonicalAttribute)
}

func indexTestAttribute(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	switch value {
	case "cn", "commonname", "2.5.4.3":
		return "2.5.4.3", true
	case "uid", "userid", "0.9.2342.19200300.100.1.1":
		return "0.9.2342.19200300.100.1.1", true
	case "dc", "domaincomponent", "0.9.2342.19200300.100.1.25":
		return "0.9.2342.19200300.100.1.25", true
	default:
		return "", false
	}
}

func indexTestNormalize(value []byte) []byte {
	return []byte(strings.ToLower(strings.Join(strings.Fields(string(value)), " ")))
}

func indexTestApproximateTerms(value []byte) [][]byte {
	fields := strings.Fields(string(indexTestNormalize(value)))
	result := make([][]byte, len(fields))
	for index, field := range fields {
		result[index] = []byte(field)
	}
	return result
}

func indexTestConfig(attributes ...EqualityIndexAttribute) EqualityIndexConfig {
	return EqualityIndexConfig{Version: EqualityIndexFormatVersion, Attributes: attributes}
}

func indexTestCNConfig() EqualityIndexConfig {
	return indexTestConfig(EqualityIndexAttribute{
		Attribute:    "2.5.4.3",
		EqualityRule: "caseignorematch",
		Equality:     true,
		Presence:     true,
	})
}

func indexTestCNPhase2Config() EqualityIndexConfig {
	return indexTestConfig(EqualityIndexAttribute{
		Attribute:        "2.5.4.3",
		EqualityRule:     "caseignorematch",
		ApproximateRule:  "testapproxmatch",
		SubstringRule:    "caseignoresubstringsmatch",
		OrderingRule:     "caseignoreorderingmatch",
		Equality:         true,
		Presence:         true,
		Approximate:      true,
		SubstringInitial: true,
		SubstringAny:     true,
		SubstringFinal:   true,
		Ordering:         true,
	})
}

func indexTestEntry(dn, cn, uid string) directory.Entry {
	attributes := []directory.Attribute{{
		Description: "commonName",
		Values:      [][]byte{[]byte(cn)},
	}}
	if uid != "" {
		attributes = append(attributes, directory.Attribute{
			Description: "0.9.2342.19200300.100.1.1",
			Values:      [][]byte{[]byte(uid)},
		})
	}
	return directory.Entry{DN: dn, Attributes: attributes}
}

func TestEqualityIndexMemoryAndBoltLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			store := openIndexTestStore(t, backend)
			defer store.Close()
			testEqualityIndexLifecycle(t, store)
		})
	}
}

func TestEqualityIndexesCurrentThroughMaintenanceReader(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			store := openIndexTestStore(t, backend)
			defer store.Close()
			ctx := context.Background()
			schema := indexTestSchema{config: indexTestCNConfig()}
			assertCurrent := func(want bool) {
				t.Helper()
				if err := store.View(ctx, func(reader Reader) error {
					current, err := EqualityIndexesCurrent(
						indexMaintenanceReader{Reader: reader},
						"db",
						schema,
					)
					if err != nil {
						return err
					}
					if current != want {
						t.Fatalf("EqualityIndexesCurrent() = %v, want %v", current, want)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}

			assertCurrent(false)
			if err := store.Update(ctx, func(writer Writer) error {
				return WriterInPartitionWithNormalizer(writer, "db", schema).Put(
					indexTestEntry("cn=Alice,dc=example", "Alice", "a1"),
					false,
				)
			}); err != nil {
				t.Fatal(err)
			}
			assertCurrent(true)
			if err := store.Update(ctx, func(writer Writer) error {
				return writer.PutIn(
					"db",
					indexTestEntry("cn=Raw,dc=example", "Raw", "r1"),
					false,
				)
			}); err != nil {
				t.Fatal(err)
			}
			assertCurrent(false)
		})
	}
}

type indexMaintenanceReader struct {
	Reader
}

func (reader indexMaintenanceReader) MaintenanceStorageReader() Reader {
	return reader.Reader
}

func testEqualityIndexLifecycle(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	schema := indexTestSchema{config: indexTestCNConfig()}
	initial := []directory.Entry{
		indexTestEntry("cn=Alice,dc=example", " Alice ", "a1"),
		indexTestEntry("cn=Bob,dc=example", "Bob", "b1"),
		indexTestEntry("cn=Carol,dc=example", "Carol", ""),
	}
	if err := store.Update(ctx, func(writer Writer) error {
		indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
		for _, entry := range initial {
			if err := indexed.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed indexed entries: %v", err)
	}

	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "commonName", Assertion: []byte("ALICE"),
	}, true)
	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "2.5.4.3", Assertion: []byte("bob"),
	}, true)
	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind: directory.FilterPresent, Attribute: "cn",
	}, true)
	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind: directory.FilterAnd,
		Children: []directory.Filter{
			{Kind: directory.FilterPresent, Attribute: "2.5.4.3"},
			{Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Bob")},
			{Kind: directory.FilterSubstrings, Attribute: "cn", Substring: directory.Substring{Initial: []byte("B")}},
		},
	}, true)
	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind: directory.FilterOr,
		Children: []directory.Filter{
			{Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Alice")},
			{Kind: directory.FilterEquality, Attribute: "2.5.4.3", Assertion: []byte("Carol")},
		},
	}, true)
	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind: directory.FilterOr,
		Children: []directory.Filter{
			{Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Alice")},
			{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("b1")},
		},
	}, false)

	if err := store.Update(ctx, func(writer Writer) error {
		indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
		return indexed.Put(indexTestEntry("cn=Bob,dc=example", "Bobby", "b1"), true)
	}); err != nil {
		t.Fatalf("replace indexed entry: %v", err)
	}
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Bob"),
	}, true, nil)
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Bobby"),
	}, true, []string{"cn=Bob,dc=example"})

	if err := store.Update(ctx, func(writer Writer) error {
		indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
		oldDN, _ := directory.ParseDN("cn=Carol,dc=example")
		if err := indexed.Delete(oldDN); err != nil {
			return err
		}
		return indexed.Put(indexTestEntry("cn=Caroline,dc=example", "Caroline", ""), false)
	}); err != nil {
		t.Fatalf("indexed ModifyDN transaction: %v", err)
	}
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Caroline"),
	}, true, []string{"cn=Caroline,dc=example"})

	injected := indexTestSchema{config: indexTestCNConfig(), failOn: "explode"}
	err := store.Update(ctx, func(writer Writer) error {
		indexed := WriterInPartitionWithNormalizer(writer, "db", injected)
		return indexed.Put(indexTestEntry("cn=Alice,dc=example", "explode", "a1"), true)
	})
	if err == nil {
		t.Fatal("index normalization failure committed")
	}
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Alice"),
	}, true, []string{"cn=Alice,dc=example"})

	if err := store.Update(ctx, func(writer Writer) error {
		return writer.PutIn("db", indexTestEntry("cn=Raw,dc=example", "Raw", "r1"), false)
	}); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Raw"),
	}, false, nil)
	if err := store.Update(ctx, func(writer Writer) error {
		return WriterInPartitionWithNormalizer(writer, "db", schema).Put(
			indexTestEntry("cn=Dave,dc=example", "Dave", "d1"),
			false,
		)
	}); err != nil {
		t.Fatalf("rebuild after raw write: %v", err)
	}
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Raw"),
	}, true, []string{"cn=Raw,dc=example"})

	uidSchema := indexTestSchema{config: indexTestConfig(EqualityIndexAttribute{
		Attribute:    "0.9.2342.19200300.100.1.1",
		EqualityRule: "caseignorematch",
		Equality:     true,
		Presence:     true,
	})}
	assertIndexDNs(t, store, uidSchema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("a1"),
	}, false, nil)
	if err := store.Update(ctx, func(writer Writer) error {
		return RebuildEqualityIndexes(writer, "db", uidSchema)
	}); err != nil {
		t.Fatalf("reload equality indexes: %v", err)
	}
	assertIndexDNs(t, store, uidSchema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "userid", Assertion: []byte("A1"),
	}, true, []string{"cn=Alice,dc=example"})
}

func TestEqualityIndexLegacyFirstBuildAndBoltReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	schema := indexTestSchema{config: indexTestCNPhase2Config()}
	if err := store.Update(context.Background(), func(writer Writer) error {
		if err := writer.PutIn(
			"db",
			indexTestEntry("CN=Legacy,DC=example", "Legacy", "legacy"),
			false,
		); err != nil {
			return err
		}
		return WriterInPartitionWithNormalizer(writer, "db", schema).Put(
			indexTestEntry("cn=New,dc=example", "New", "new"),
			false,
		)
	}); err != nil {
		t.Fatal(err)
	}
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("legacy"),
	}, true, []string{"CN=Legacy,DC=example"})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "commonName", Assertion: []byte("new"),
	}, true, []string{"cn=New,dc=example"})
	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind:      directory.FilterSubstrings,
		Attribute: "cn",
		Substring: directory.Substring{Any: [][]byte{[]byte("ega")}},
	}, true)
}

func TestSubstringAndOrderingIndexMemoryAndBoltNeverMissCandidates(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			store := openIndexTestStore(t, backend)
			defer store.Close()
			schema := indexTestSchema{config: indexTestCNPhase2Config()}
			var longBuilder strings.Builder
			for index := 0; index < substringIndexMaxNGrams+100; index++ {
				longBuilder.WriteString(strconv.FormatInt(int64(index), 36))
				longBuilder.WriteByte('|')
			}
			longBuilder.WriteString("late-target")
			longValue := longBuilder.String()
			entries := []directory.Entry{
				indexTestEntry("cn=Alpha Bravo,dc=example", " Alpha   Bravo ", "a1"),
				indexTestEntry("cn=Alphabet Soup,dc=example", "Alphabet Soup", "a2"),
				indexTestEntry("cn=Middle Target,dc=example", "Middle Target", "m1"),
				indexTestEntry("cn=Zulu,dc=example", "Zulu", "z1"),
				indexTestEntry("cn=Long,dc=example", longValue, "long"),
			}
			if err := store.Update(context.Background(), func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
				for _, entry := range entries {
					if err := indexed.Put(entry, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			filters := []directory.Filter{
				{Kind: directory.FilterSubstrings, Attribute: "commonName", Substring: directory.Substring{Initial: []byte("ALP")}},
				{Kind: directory.FilterSubstrings, Attribute: "2.5.4.3", Substring: directory.Substring{Any: [][]byte{[]byte("ha"), []byte("bet")}}},
				{Kind: directory.FilterSubstrings, Attribute: "cn", Substring: directory.Substring{Final: []byte("BRAVO")}},
				{Kind: directory.FilterSubstrings, Attribute: "cn", Substring: directory.Substring{Initial: []byte("alpha"), Any: [][]byte{[]byte("ha b")}, Final: []byte("avo")}},
				{Kind: directory.FilterSubstrings, Attribute: "cn", Substring: directory.Substring{Any: [][]byte{[]byte("late-target")}}},
				{Kind: directory.FilterGreaterOrEqual, Attribute: "cn", Assertion: []byte("middle")},
				{Kind: directory.FilterLessOrEqual, Attribute: "cn", Assertion: []byte("middle target")},
			}
			for _, filter := range filters {
				assertIndexPlanMatchesScan(t, store, schema, filter, true)
			}
			assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
				Kind:      directory.FilterSubstrings,
				Attribute: "cn",
				Substring: directory.Substring{Any: [][]byte{[]byte("x")}},
			}, false)

			if err := store.Update(context.Background(), func(writer Writer) error {
				indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
				if err := indexed.Put(indexTestEntry("cn=Zulu,dc=example", "Beta Updated", "z1"), true); err != nil {
					return err
				}
				oldDN, _ := directory.ParseDN("cn=Middle Target,dc=example")
				if err := indexed.Delete(oldDN); err != nil {
					return err
				}
				return indexed.Put(indexTestEntry("cn=Renamed,dc=example", "Renamed Target", "m1"), false)
			}); err != nil {
				t.Fatal(err)
			}
			assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
				Kind:      directory.FilterSubstrings,
				Attribute: "cn",
				Substring: directory.Substring{Any: [][]byte{[]byte("updated")}},
			}, true)
			assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
				Kind:      directory.FilterGreaterOrEqual,
				Attribute: "cn",
				Assertion: []byte("renamed"),
			}, true)

			injected := indexTestSchema{config: indexTestCNPhase2Config(), failOn: "explode"}
			if err := store.Update(context.Background(), func(writer Writer) error {
				return WriterInPartitionWithNormalizer(writer, "db", injected).Put(
					indexTestEntry("cn=Alpha Bravo,dc=example", "explode", "a1"),
					true,
				)
			}); err == nil {
				t.Fatal("phase-2 index normalization failure committed")
			}
			assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
				Kind:      directory.FilterSubstrings,
				Attribute: "cn",
				Substring: directory.Substring{Initial: []byte("alpha")},
			}, true)

			if err := store.Update(context.Background(), func(writer Writer) error {
				if err := writer.PutIn("db", indexTestEntry("cn=Raw Phase2,dc=example", "Raw Phase2", "raw"), false); err != nil {
					return err
				}
				_, err := MigrateSchemaAwareDNIdentities(writer, "db", schema)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
				Kind:      directory.FilterSubstrings,
				Attribute: "cn",
				Substring: directory.Substring{Any: [][]byte{[]byte("phase")}},
			}, false)
			if err := store.Update(context.Background(), func(writer Writer) error {
				return RebuildEqualityIndexes(writer, "db", schema)
			}); err != nil {
				t.Fatal(err)
			}
			assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
				Kind:      directory.FilterSubstrings,
				Attribute: "cn",
				Substring: directory.Substring{Any: [][]byte{[]byte("phase")}},
			}, true)
		})
	}
}

func TestEqualityIndexBoltMaintenance(t *testing.T) {
	ctx := context.Background()
	directoryPath := t.TempDir()
	databasePath := filepath.Join(directoryPath, "directory.db")
	backupPath := filepath.Join(directoryPath, "backup.db")
	restoredPath := filepath.Join(directoryPath, "restored.db")
	schema := indexTestSchema{config: indexTestCNPhase2Config()}
	store, err := OpenBolt(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(ctx, func(writer Writer) error {
		indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
		return indexed.Put(indexTestEntry("cn=Alice,dc=example", "Alice", "a1"), false)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := CheckBoltWithNormalizer(ctx, databasePath, schema)
	if err != nil {
		t.Fatalf("check indexed Bolt: %v", err)
	}
	if report.EqualityIndexConfigs != 1 || report.EqualityIndexPostings <= 2 {
		t.Fatalf("index report = %#v", report)
	}
	if _, err := BackupBolt(ctx, databasePath, backupPath, false); err != nil {
		t.Fatalf("backup indexed Bolt: %v", err)
	}
	if _, err := RestoreBolt(ctx, backupPath, restoredPath, false); err != nil {
		t.Fatalf("restore indexed Bolt: %v", err)
	}
	if _, err := CheckBoltWithNormalizer(ctx, restoredPath, schema); err != nil {
		t.Fatalf("check restored index: %v", err)
	}
	if _, err := RebuildBolt(ctx, databasePath); err != nil {
		t.Fatalf("compact indexed Bolt: %v", err)
	}
	if _, err := CheckBoltWithNormalizer(ctx, databasePath, schema); err != nil {
		t.Fatalf("check compacted index: %v", err)
	}
	store, err = OpenBolt(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assertIndexDNs(t, store, schema, directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("alice"),
	}, true, []string{"cn=Alice,dc=example"})
	assertIndexPlanMatchesScan(t, store, schema, directory.Filter{
		Kind:      directory.FilterSubstrings,
		Attribute: "cn",
		Substring: directory.Substring{Final: []byte("ice")},
	}, true)
}

func assertIndexPlanMatchesScan(
	t *testing.T,
	store Store,
	schema indexTestSchema,
	filter directory.Filter,
	wantPlanned bool,
) {
	t.Helper()
	var plannedDNs, scannedDNs []string
	err := store.View(context.Background(), func(reader Reader) error {
		indexed := ReaderInPartitionWithNormalizer(reader, "db", schema)
		planned, _, err := ForEachFilterCandidate(indexed, filter, func(entry directory.Entry) error {
			matches, err := filter.Match(entry)
			if err == nil && matches {
				plannedDNs = append(plannedDNs, entry.DN)
			}
			return err
		})
		if err != nil {
			return err
		}
		if planned != wantPlanned {
			t.Fatalf("planned = %v, want %v", planned, wantPlanned)
		}
		return indexed.ForEach(func(entry directory.Entry) error {
			matches, err := filter.Match(entry)
			if err == nil && matches {
				scannedDNs = append(scannedDNs, entry.DN)
			}
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if wantPlanned {
		sort.Strings(plannedDNs)
		sort.Strings(scannedDNs)
		if strings.Join(plannedDNs, "\n") != strings.Join(scannedDNs, "\n") {
			t.Fatalf("planner DNs = %v, scan DNs = %v", plannedDNs, scannedDNs)
		}
	}
}

func assertIndexDNs(
	t *testing.T,
	store Store,
	schema indexTestSchema,
	filter directory.Filter,
	wantPlanned bool,
	want []string,
) {
	t.Helper()
	var got []string
	err := store.View(context.Background(), func(reader Reader) error {
		indexed := ReaderInPartitionWithNormalizer(reader, "db", schema)
		planned, _, err := ForEachFilterCandidate(indexed, filter, func(entry directory.Entry) error {
			got = append(got, entry.DN)
			return nil
		})
		if planned != wantPlanned {
			t.Fatalf("planned = %v, want %v", planned, wantPlanned)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if want != nil {
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("candidate DNs = %v, want %v", got, want)
		}
	}
}

func openIndexTestStore(t *testing.T, backend string) Store {
	t.Helper()
	if backend == "memory" {
		return NewMemory()
	}
	store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func BenchmarkEqualityIndexCandidateCount(b *testing.B) {
	store := NewMemory()
	defer store.Close()
	schema := indexTestSchema{config: indexTestCNConfig()}
	if err := store.Update(context.Background(), func(writer Writer) error {
		indexed := WriterInPartitionWithNormalizer(writer, "db", schema)
		for index := 0; index < 1000; index++ {
			name := "other"
			if index == 500 {
				name = "target"
			}
			entry := indexTestEntry(
				"cn=entry"+strconv.Itoa(index)+",dc=example",
				name,
				"",
			)
			if err := indexed.Put(entry, false); err != nil && !errors.Is(err, ErrEntryExists) {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	filter := directory.Filter{
		Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("target"),
	}
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if err := store.View(context.Background(), func(reader Reader) error {
			indexed := ReaderInPartitionWithNormalizer(reader, "db", schema)
			planned, candidates, err := ForEachFilterCandidate(
				indexed,
				filter,
				func(directory.Entry) error { return nil },
			)
			if !planned || candidates != 1 {
				b.Fatalf("planned=%v candidates=%d", planned, candidates)
			}
			return err
		}); err != nil {
			b.Fatal(err)
		}
	}
}
