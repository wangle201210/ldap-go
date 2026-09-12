package server

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestMatchingRuleOIDIndexedSearchWire(t *testing.T) {
	for _, rule := range []struct {
		name, oid, equality, syntax string
		ignoreCase, binary          bool
	}{
		{"caseIgnoreSubstringsMatch", "2.5.13.4", "caseIgnoreMatch", schema.SyntaxDirectoryString, true, false},
		{"caseExactSubstringsMatch", "2.5.13.7", "caseExactMatch", schema.SyntaxDirectoryString, false, false},
		{"caseIgnoreIA5SubstringsMatch", "1.3.6.1.4.1.1466.109.114.3", "caseIgnoreIA5Match", schema.SyntaxIA5String, true, false},
		{"caseExactIA5SubstringsMatch", "1.3.6.1.4.1.4203.1.2.1", "caseExactIA5Match", schema.SyntaxIA5String, false, false},
		{"octetStringSubstringsMatch", "2.5.13.19", "octetStringMatch", schema.SyntaxOctetString, false, true},
	} {
		t.Run(rule.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "directory.db")
			store, err := storage.OpenBolt(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				entry := directory.Entry{
					DN: "cn={9}substringrules,cn=schema,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcAttributeTypes", Values: stringValues(
							fmt.Sprintf("( 1.3.6.1.4.1.99999.997.1 NAME 'oidSubstringValue' EQUALITY %s SUBSTR %s SYNTAX %s )", rule.equality, rule.oid, rule.syntax),
							fmt.Sprintf("( 1.3.6.1.4.1.99999.997.2 NAME 'namedSubstringValue' EQUALITY %s SUBSTR %s SYNTAX %s )", rule.equality, rule.name, rule.syntax),
						)},
						{Description: "olcObjectClasses", Values: stringValues(
							"( 1.3.6.1.4.1.99999.997.3 NAME 'substringRuleProbe' SUP top AUXILIARY MAY ( oidSubstringValue $ namedSubstringValue ) )",
						)},
					},
				}
				if err := writer.Put(entry, false); err != nil {
					return err
				}
				dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
				if err != nil {
					return err
				}
				config, err := writer.Get(dn)
				if err != nil {
					return err
				}
				config.ReplaceValues("olcDbIndex", stringValues("oidSubstringValue,namedSubstringValue sub"))
				return writer.Put(config, true)
			}); err != nil {
				t.Fatal(err)
			}

			t.Run("initial", func(t *testing.T) {
				checkMatchingRuleOIDWireSearches(t, store, rule.ignoreCase, rule.binary, true)
			})
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = storage.OpenBolt(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("reopened", func(t *testing.T) {
				// Verify persisted index metadata before a server can rebuild it.
				matchingRuleOIDWireDatabase(t, store, true)
				checkMatchingRuleOIDWireSearches(t, store, rule.ignoreCase, rule.binary, false)
			})
			t.Run("reindexed", func(t *testing.T) {
				count, err := ReindexOfflineSelected(t.Context(), store, OfflineReindexOptions{
					Database: "1", Attributes: []string{"oidSubstringValue", "namedSubstringValue"},
				})
				if err != nil || count != 1 {
					t.Fatalf("ReindexOfflineSelected() = %d, %v; want 1, nil", count, err)
				}
				matchingRuleOIDWireDatabase(t, store, true)
				checkMatchingRuleOIDWireSearches(t, store, rule.ignoreCase, rule.binary, false)
			})
		})
	}
}

func checkMatchingRuleOIDWireSearches(t *testing.T, store storage.Store, ignoreCase, binary, addEntries bool) {
	t.Helper()
	address, stop := startServer(t, store, Config{
		RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetTimeout(5 * time.Second)
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatal(err)
	}
	if addEntries {
		entries := [][]string{
			{"Alpha Needle Omega"},
			{"alpha needle omega"},
			{"ALPHA NEEDLE OMEGA"},
			{"Alpha Needletail Omega"},
			{"PreAlpha Needle OmegaSuffix"},
			{"unrelated"},
			{"Other", "Alpha Needle Omega"},
			{"Needle", "Alpha Omega"},
			{"Alpha  Needle   Omega"},
			{"AlphaXNeedleYOmega"},
		}
		if binary {
			entries = [][]string{
				{"\x00Alpha\xff Needle Omega"},
				{"\x00alpha\xff Needle Omega"},
				{" Alpha  Needle Omega "},
				{"Alpha\x00Needle\xffOmega"},
				{"Alpha", "Needle", "\xffOmega", "\x00"},
				{"unrelated"},
				{"Alpha Needle Omega"},
				{"Alpha  Needle Omega"},
				{"ALPHA NEEDLE OMEGA"},
			}
		}
		for index, values := range entries {
			request := newPersonAddRequest(fmt.Sprintf("substring-%02d", index))
			request.Attributes[0].Vals = []string{"inetOrgPerson", "substringRuleProbe"}
			request.Attribute("oidSubstringValue", values)
			request.Attribute("namedSubstringValue", values)
			if err := client.Add(request); err != nil {
				t.Fatalf("Add(%s): %v", request.DN, err)
			}
		}
	}
	runtime, database := matchingRuleOIDWireDatabase(t, store, false)
	type searchCase struct {
		pattern       string
		exact, folded []int
	}
	cases := []searchCase{
		{"Alpha*", []int{0, 3, 6, 7, 8, 9}, []int{0, 1, 2, 3, 6, 7, 8, 9}},
		{"*Needle*", []int{0, 3, 4, 6, 7, 8, 9}, []int{0, 1, 2, 3, 4, 6, 7, 8, 9}},
		{"*Omega", []int{0, 3, 6, 7, 8, 9}, []int{0, 1, 2, 3, 6, 7, 8, 9}},
		{"Alpha*Needle*Omega", []int{0, 3, 6, 8, 9}, []int{0, 1, 2, 3, 6, 8, 9}},
		{"alpha*needle*omega", []int{1}, []int{0, 1, 2, 3, 6, 8, 9}},
		{"Alpha Needle*", []int{0, 3, 6, 8}, []int{0, 1, 2, 3, 6, 8}},
		{"Omega*Needle*Alpha", nil, nil},
		{"*absent*", nil, nil},
	}
	if binary {
		cases = []searchCase{
			{`\00Alpha\ff*`, []int{0}, nil},
			{`\00alpha\ff*`, []int{1}, nil},
			{`\00ALPHA\ff*`, nil, nil},
			{`*\00Needle\ff*`, []int{3}, nil},
			{`*\ffOmega`, []int{3, 4}, nil},
			{`Alpha*Needle*\ffOmega`, []int{3}, nil},
			{"Alpha Needle*", []int{6}, nil},
			{"Alpha  Needle*", []int{7}, nil},
			{" Alpha  Needle Omega *", []int{2}, nil},
			{"*Needle Omega", []int{0, 1, 6, 7}, nil},
			{"alpha*needle*omega", nil, nil},
			{"ALPHA*NEEDLE*OMEGA", []int{8}, nil},
		}
	}
	for _, test := range cases {
		t.Run(test.pattern, func(t *testing.T) {
			indices := test.exact
			if ignoreCase {
				indices = test.folded
			}
			var want []string
			for _, index := range indices {
				want = append(want, fmt.Sprintf("uid=substring-%02d,ou=people,dc=example,dc=com", index))
			}
			var previousCandidates []string
			for index, attribute := range []string{"oidSubstringValue", "namedSubstringValue"} {
				filterText := "(" + attribute + "=" + test.pattern + ")"
				result, err := client.Search(ldap.NewSearchRequest(
					"ou=people,dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
					0, 0, false, filterText, []string{"uid"}, nil,
				))
				if err != nil {
					t.Fatalf("Search(%s): %v", filterText, err)
				}
				var got []string
				for _, entry := range result.Entries {
					got = append(got, entry.DN)
				}
				slices.Sort(got)
				if !slices.Equal(got, want) {
					t.Fatalf("Search(%s) = %v; want %v", filterText, got, want)
				}
				filter, err := ldapwire.CompileFilter(filterText)
				if err != nil {
					t.Fatal(err)
				}
				candidates := matchingRuleOIDWireCandidates(t, store, runtime, database, filter, want)
				if index > 0 && !slices.Equal(candidates, previousCandidates) {
					t.Fatalf("numeric/name rule index candidates differ: %v / %v", previousCandidates, candidates)
				}
				previousCandidates = candidates
			}
		})
	}
}

func matchingRuleOIDWireDatabase(t *testing.T, store storage.Store, requireCurrent bool) (*runtimeState, runtimeDatabase) {
	t.Helper()
	var runtime *runtimeState
	var database runtimeDatabase
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		var err error
		_, runtime, err = buildOfflineRuntime(reader, store)
		if err != nil {
			return err
		}
		indices, err := selectOfflineDatabases(runtime, "1", false)
		if err != nil {
			return err
		}
		if len(indices) != 1 {
			return fmt.Errorf("database selection = %v, want one database", indices)
		}
		database = runtime.databases[indices[0]]
		if requireCurrent {
			current, err := storage.EqualityIndexesCurrent(reader, database.partition, database.dnNormalizer.(storage.EqualityIndexSchema))
			if err != nil {
				return err
			}
			if !current {
				return fmt.Errorf("persisted substring indexes are not current")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return runtime, database
}

func matchingRuleOIDWireCandidates(t *testing.T, store storage.Store, runtime *runtimeState, database runtimeDatabase, filter directory.Filter, want []string) []string {
	t.Helper()
	var candidates, scanned []string
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		indexed := readerForDatabase(reader, database)
		planned, _, err := storage.ForEachFilterCandidate(indexed, filter, func(entry directory.Entry) error {
			candidates = append(candidates, entry.DN)
			return nil
		})
		if err != nil {
			return err
		}
		if !planned {
			return fmt.Errorf("substring filter on %s did not use an index", filter.Attribute)
		}
		return indexed.ForEach(func(entry directory.Entry) error {
			matches, err := filter.MatchWith(entry, runtime.schema)
			if matches && err == nil {
				scanned = append(scanned, entry.DN)
			}
			return err
		})
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(candidates)
	slices.Sort(scanned)
	if !slices.Equal(scanned, want) {
		t.Fatalf("unindexed scan on %s = %v; want %v", filter.Attribute, scanned, want)
	}
	for _, dn := range want {
		if !slices.Contains(candidates, dn) {
			t.Fatalf("index on %s omitted %s from %v", filter.Attribute, dn, candidates)
		}
	}
	return candidates
}
