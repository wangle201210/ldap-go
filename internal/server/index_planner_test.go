package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
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
				[]byte("{2}uidNumber ordering"),
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
	canonical, equality, presence, err = indexed.ResolveEqualityIndexAttribute("2.5.4.3")
	if err != nil || canonical != "2.5.4.3" || !equality || !presence {
		t.Fatalf("cn OID mode = %q %v %v err=%v", canonical, equality, presence, err)
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

func TestLoadDatabaseEqualityIndexesDefaultNoLangAndApproximate(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcDbIndex",
			Values: [][]byte{
				[]byte("{3}cn approx"),
				[]byte("{2}description eq,nolang"),
				[]byte("{1}uid"),
				[]byte("{0}default eq,pres"),
			},
		}},
	}
	normalizer, config, err := loadDatabaseEqualityIndexes(entry, registry)
	if err != nil {
		t.Fatal(err)
	}
	indexed := normalizer.(*databaseEqualityIndexNormalizer)
	if len(config.Attributes) != 3 {
		t.Fatalf("config = %#v", config)
	}
	byOID := make(map[string]storage.EqualityIndexAttribute, len(config.Attributes))
	for _, attribute := range config.Attributes {
		byOID[attribute.Attribute] = attribute
	}
	uid := byOID["0.9.2342.19200300.100.1.1"]
	if !uid.Equality || !uid.Presence {
		t.Fatalf("default index was not inherited by uid: %#v", uid)
	}
	description := byOID["2.5.4.13"]
	if !description.Equality || description.Presence || !description.NoTags {
		t.Fatalf("explicit description modes = %#v", description)
	}
	commonName := byOID["2.5.4.3"]
	if !commonName.Approximate || commonName.ApproximateRule != "directorystringapproxmatch" || commonName.Equality {
		t.Fatalf("cn approximate mode = %#v", commonName)
	}

	canonical, equality, _, err := indexed.ResolveEqualityIndexAttribute("description;lang-en")
	if err != nil || canonical != "2.5.4.13" || equality {
		t.Fatalf("nolang tagged equality = %q %v err=%v", canonical, equality, err)
	}
	canonical, equality, _, err = indexed.ResolveEqualityIndexAttribute("description")
	if err != nil || canonical != "2.5.4.13" || !equality {
		t.Fatalf("nolang base equality = %q %v err=%v", canonical, equality, err)
	}
}

func TestLoadDatabaseEqualityIndexesRejectsUnimplementedSubitems(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"objectClass sub",
		"objectClass ordering",
		"objectClass approx",
		"description;lang-en eq",
		"cn nosubtypes",
		"cn",
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

func TestLoadDatabaseEqualityIndexesRejectsDuplicateAttributeDescription(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "same name", values: []string{"cn eq", "cn pres"}},
		{name: "name and OID", values: []string{"cn eq", "2.5.4.3 pres"}},
		{name: "same directive", values: []string{"cn,2.5.4.3 eq"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := make([][]byte, len(test.values))
			for index, value := range test.values {
				values[index] = []byte(value)
			}
			entry := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcDbIndex",
					Values:      values,
				}},
			}
			_, _, err := loadDatabaseEqualityIndexes(entry, registry)
			if err == nil || !strings.Contains(err.Error(), "duplicate index definition") {
				t.Fatalf("loadDatabaseEqualityIndexes() error = %v", err)
			}
		})
	}
}

func TestDatabaseIndexDefaultNoLangApproximateMemoryAndBolt(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	configEntry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcDbIndex",
			Values: [][]byte{
				[]byte("{0}default eq,pres"),
				[]byte("{1}uid"),
				[]byte("{2}description eq,nolang"),
				[]byte("{3}cn approx"),
				[]byte("{4}uidNumber eq"),
			},
		}},
	}
	normalizer, _, err := loadDatabaseEqualityIndexes(configEntry, registry)
	if err != nil {
		t.Fatal(err)
	}
	indexed := normalizer.(*databaseEqualityIndexNormalizer)
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
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
			entries := []directory.Entry{
				{
					DN: "uid=alice,dc=example",
					Attributes: []directory.Attribute{
						{Description: "uid", Values: [][]byte{[]byte("alice")}},
						{Description: "cn", Values: [][]byte{[]byte("Alice Smith")}},
						{Description: "description;lang-en", Values: [][]byte{[]byte("English")}},
						{Description: "uidNumber", Values: [][]byte{[]byte("100")}},
					},
				},
				{
					DN: "uid=bob,dc=example",
					Attributes: []directory.Attribute{
						{Description: "uid", Values: [][]byte{[]byte("bob")}},
						{Description: "cn", Values: [][]byte{[]byte("Bob Jones")}},
						{Description: "description", Values: [][]byte{[]byte("English")}},
						{Description: "uidNumber", Values: [][]byte{[]byte("200")}},
					},
				},
			}
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				for _, entry := range entries {
					if err := writer.PutIn("db", entry, false); err != nil {
						return err
					}
				}
				return storage.EnsureEqualityIndexes(writer, "db", indexed)
			}); err != nil {
				t.Fatal(err)
			}

			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("ALICE"),
			}, true, []string{"uid=alice,dc=example"})
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterPresent, Attribute: "uid",
			}, true, []string{"uid=alice,dc=example", "uid=bob,dc=example"})
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "description", Assertion: []byte("English"),
			}, true, []string{"uid=alice,dc=example", "uid=bob,dc=example"})
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "description;lang-en", Assertion: []byte("English"),
			}, false, []string{"uid=alice,dc=example"})
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterApprox, Attribute: "cn", Assertion: []byte("Alice Smyth"),
			}, false, []string{"uid=alice,dc=example"})
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterApprox, Attribute: "uidNumber", Assertion: []byte("100"),
			}, true, []string{"uid=alice,dc=example"})

			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				wrapped := storage.WriterInPartitionWithNormalizer(writer, "db", indexed)
				updated := entries[0]
				updated.Attributes[0].Values = [][]byte{[]byte("alice-updated")}
				return wrapped.Put(updated, true)
			}); err != nil {
				t.Fatal(err)
			}
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("alice-updated"),
			}, true, []string{"uid=alice,dc=example"})

			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				return writer.PutIn("db", directory.Entry{
					DN: "uid=carol,dc=example",
					Attributes: []directory.Attribute{{
						Description: "uid", Values: [][]byte{[]byte("carol")},
					}},
				}, false)
			}); err != nil {
				t.Fatal(err)
			}
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("carol"),
			}, false, []string{"uid=carol,dc=example"})
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				return storage.RebuildEqualityIndexes(writer, "db", indexed)
			}); err != nil {
				t.Fatal(err)
			}
			assertDatabaseIndexMatchesScan(t, store, indexed, registry, directory.Filter{
				Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("carol"),
			}, true, []string{"uid=carol,dc=example"})
		})
	}
}

func assertDatabaseIndexMatchesScan(
	t *testing.T,
	store storage.Store,
	normalizer *databaseEqualityIndexNormalizer,
	registry *schema.Registry,
	filter directory.Filter,
	wantPlanned bool,
	wantDNs []string,
) {
	t.Helper()
	var candidateDNs, scanDNs []string
	err := store.View(context.Background(), func(reader storage.Reader) error {
		indexed := storage.ReaderInPartitionWithNormalizer(reader, "db", normalizer)
		planned, _, err := storage.ForEachFilterCandidate(indexed, filter, func(entry directory.Entry) error {
			candidateDNs = append(candidateDNs, entry.DN)
			return nil
		})
		if err != nil {
			return err
		}
		if planned != wantPlanned {
			t.Fatalf("filter %#v planned=%v, want %v", filter, planned, wantPlanned)
		}
		return indexed.ForEach(func(entry directory.Entry) error {
			matches, err := filter.MatchWith(entry, registry)
			if err == nil && matches {
				scanDNs = append(scanDNs, entry.DN)
			}
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(candidateDNs)
	sort.Strings(scanDNs)
	sort.Strings(wantDNs)
	if strings.Join(scanDNs, "\n") != strings.Join(wantDNs, "\n") {
		t.Fatalf("filter %#v scan DNs=%v, want %v", filter, scanDNs, wantDNs)
	}
	if !wantPlanned {
		if len(candidateDNs) != 0 {
			t.Fatalf("unplanned filter %#v returned candidates %v", filter, candidateDNs)
		}
		return
	}
	for _, matchedDN := range scanDNs {
		index := sort.SearchStrings(candidateDNs, matchedDN)
		if index >= len(candidateDNs) || candidateDNs[index] != matchedDN {
			t.Fatalf("filter %#v candidate set %v missed %q", filter, candidateDNs, matchedDN)
		}
	}
}

func TestOpenLDAPMDBIndexSemanticSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	indexSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "index.c"))
	if err != nil {
		t.Fatal(err)
	}
	attributeSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "back-mdb", "attr.c"))
	if err != nil {
		t.Fatal(err)
	}
	backendIndexSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "back-mdb", "index.c"))
	if err != nil {
		t.Fatal(err)
	}
	schemaSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "schema_init.c"))
	if err != nil {
		t.Fatal(err)
	}
	phoneticSource, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "phonetic.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`{ BER_BVC("nolang"), 0 },`,
		`while ( !idxstr[i].mask ) i--;`,
	} {
		if !bytes.Contains(indexSource, []byte(fragment)) {
			t.Fatalf("pinned OpenLDAP index.c no longer contains %q", fragment)
		}
	}
	for _, fragment := range []string{
		"mask = mdb->mi_defaultmask;",
		"mdb->mi_defaultmask |= mask;",
		"approx index of attribute",
		"duplicate index definition for attr",
	} {
		if !bytes.Contains(attributeSource, []byte(fragment)) {
			t.Fatalf("pinned OpenLDAP back-mdb/attr.c no longer contains %q", fragment)
		}
	}
	if !bytes.Contains(backendIndexSource, []byte("Use EQUALITY rule and index for approximate match")) {
		t.Fatal("pinned OpenLDAP equality fallback contract changed")
	}
	for _, fragment := range []string{
		"UTF8bvnormalize( value, NULL, LDAP_UTF8_APPROX, NULL )",
		"values[i] = phonetic(c);",
		"nextavail=i+1;",
	} {
		if !bytes.Contains(schemaSource, []byte(fragment)) {
			t.Fatalf("pinned OpenLDAP schema_init.c no longer contains %q", fragment)
		}
	}
	for _, fragment := range []string{
		"#define MAXPHONEMELEN\t4",
		"Metaphone was originally developed",
		"Drop duplicates except for CC",
	} {
		if !bytes.Contains(phoneticSource, []byte(fragment)) {
			t.Fatalf("pinned OpenLDAP phonetic.c no longer contains %q", fragment)
		}
	}
}

func TestOpenLDAPReferenceApproximateMatching(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"index cn approx",
		`

dn: uid=phonetic,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: phonetic
cn: Alice Smith
sn: Smith
`,
	)
	defer stop()

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: "uid=phonetic,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "cn",
			Values:      [][]byte{[]byte("Alice Smith")},
		}},
	}
	for _, test := range []struct {
		assertion string
		want      bool
	}{
		{assertion: "Alice Smyth", want: true},
		{assertion: "Smyth Alice", want: false},
		{assertion: "Alice Jones", want: false},
	} {
		filter := directory.Filter{
			Kind:      directory.FilterApprox,
			Attribute: "cn",
			Assertion: []byte(test.assertion),
		}
		localMatch, err := filter.MatchWith(entry, registry)
		if err != nil {
			t.Fatal(err)
		}
		result, err := client.Search(ldap.NewSearchRequest(
			"uid=phonetic,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(cn~="+ldap.EscapeFilter(test.assertion)+")",
			[]string{"dn"},
			nil,
		))
		if err != nil {
			t.Fatal(err)
		}
		referenceMatch := len(result.Entries) == 1
		if referenceMatch != test.want || localMatch != referenceMatch {
			t.Fatalf(
				"cn~=%q: ldap-go=%v OpenLDAP=%v want=%v",
				test.assertion,
				localMatch,
				referenceMatch,
				test.want,
			)
		}
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
