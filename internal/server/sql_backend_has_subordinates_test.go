package server

import (
	"context"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSQLBackendLoadEntryDefersHasSubordinatesQuery(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "deferred-has-subordinates.db")
	seedSQLBackendDatabase(t, databaseName)
	configuration := openDeferredHasSubordinatesSQLBackend(t, databaseName)
	validQuery := configuration.hasChildrenQuery
	configuration.hasChildrenQuery = "SELECT child_count FROM missing_children WHERE dn=?"

	reader := &sqlBackendReader{
		configuration: configuration,
		ctx:           context.Background(),
	}
	alice := mustDeferredHasSubordinatesDN(t, "uid=alice,dc=example,dc=com")

	entry, err := reader.Get(alice)
	if err != nil {
		t.Fatalf("ordinary Get issued has-children query: %v", err)
	}
	if entry.HasAttribute("hasSubordinates") {
		t.Fatalf("ordinary Get returned deferred operational attribute: %#v", entry)
	}

	reader.ctx = withSQLBackendSearchRequirements(
		context.Background(),
		[]string{"uid", "cn"},
		directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
	)
	visited := 0
	if err := reader.ForEach(func(candidate directory.Entry) error {
		visited++
		if candidate.HasAttribute("hasSubordinates") {
			t.Fatalf("ordinary Search candidate returned hasSubordinates: %#v", candidate)
		}
		return nil
	}); err != nil {
		t.Fatalf("ordinary Search scan issued has-children query: %v", err)
	}
	if visited != 2 {
		t.Fatalf("ordinary Search visited %d entries, want 2", visited)
	}

	reader.ctx = withSQLBackendSearchRequirements(
		context.Background(),
		[]string{"hasSubordinates"},
	)
	_, err = reader.Get(alice)
	assertDeferredHasSubordinatesQueryFailure(t, err)

	reader.ctx = withSQLBackendSearchRequirements(
		context.Background(),
		[]string{"uid"},
		directory.Filter{
			Kind: directory.FilterAnd,
			Children: []directory.Filter{
				{Kind: directory.FilterPresent, Attribute: "objectClass"},
				{
					Kind:      directory.FilterEquality,
					Attribute: "2.5.18.9",
					Assertion: []byte("FALSE"),
				},
			},
		},
	)
	_, err = reader.Get(alice)
	assertDeferredHasSubordinatesQueryFailure(t, err)

	configuration.hasChildrenQuery = validQuery
	parent := mustDeferredHasSubordinatesDN(t, "dc=example,dc=com")
	reader.ctx = withSQLBackendSearchRequirements(context.Background(), []string{"+"})
	parentEntry, err := reader.Get(parent)
	if err != nil {
		t.Fatalf("Get(parent with operational attributes): %v", err)
	}
	if got := string(parentEntry.Values("hasSubordinates")[0]); got != "TRUE" {
		t.Fatalf("parent hasSubordinates = %q, want TRUE", got)
	}
	leafEntry, err := reader.Get(alice)
	if err != nil {
		t.Fatalf("Get(leaf with operational attributes): %v", err)
	}
	if got := string(leafEntry.Values("hasSubordinates")[0]); got != "FALSE" {
		t.Fatalf("leaf hasSubordinates = %q, want FALSE", got)
	}
}

func TestSQLBackendSearchHasSubordinatesRequirements(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		attributes []string
		filters    []directory.Filter
		want       bool
	}{
		{name: "default user attributes"},
		{name: "explicit name", attributes: []string{"HASsubordinates"}, want: true},
		{name: "attribute OID", attributes: []string{"2.5.18.9"}, want: true},
		{name: "all operational attributes", attributes: []string{"+"}, want: true},
		{
			name:       "ordinary filter",
			attributes: []string{"uid"},
			filters: []directory.Filter{{
				Kind:      directory.FilterEquality,
				Attribute: "uid",
				Assertion: []byte("alice"),
			}},
		},
		{
			name:       "nested filter",
			attributes: []string{"uid"},
			filters: []directory.Filter{{
				Kind: directory.FilterNot,
				Children: []directory.Filter{{
					Kind:      directory.FilterEquality,
					Attribute: "hasSubordinates",
					Assertion: []byte("TRUE"),
				}},
			}},
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sqlBackendSearchRequestsHasSubordinates(
				test.attributes,
				test.filters,
			); got != test.want {
				t.Fatalf("requirements = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSQLBackendSearchQueriesHasSubordinatesOnlyWhenNeeded(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "search-has-subordinates.db")
	seedSQLBackendDatabase(t, databaseName)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSQLBackendConfiguration(t, store, databaseName)
	configureDeferredHasSubordinatesQueryFailure(t, store)

	address, stop := startServer(t, store, Config{SQLDriver: "sqlite"})
	defer stop()

	ordinary := searchDeferredHasSubordinates(t, address, "(objectClass=*)", []string{"dc"}, nil)
	if len(ordinary.Entries) != 2 {
		t.Fatalf("ordinary Search entries = %d, want 2", len(ordinary.Entries))
	}
	for _, entry := range ordinary.Entries {
		if entry.GetAttributeValue("hasSubordinates") != "" {
			t.Fatalf("ordinary Search returned hasSubordinates for %s", entry.DN)
		}
	}

	tests := []struct {
		name       string
		filter     string
		attributes []string
		controls   []ldap.Control
	}{
		{
			name:       "requested attribute",
			filter:     "(objectClass=*)",
			attributes: []string{"dc", "hasSubordinates"},
		},
		{
			name:       "main filter",
			filter:     "(hasSubordinates=TRUE)",
			attributes: []string{"dc"},
		},
		{
			name:       "assertion filter",
			filter:     "(objectClass=*)",
			attributes: []string{"dc"},
			controls: []ldap.Control{
				newAssertionControl(t, "(hasSubordinates=TRUE)"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := searchDeferredHasSubordinatesResult(
				t,
				address,
				test.filter,
				test.attributes,
				test.controls,
			)
			assertLDAPResultCode(t, err, ldap.LDAPResultOther)
		})
	}
}

func openDeferredHasSubordinatesSQLBackend(
	t *testing.T,
	databaseName string,
) *sqlBackendRuntimeConfiguration {
	t.Helper()
	configuration := &sqlBackendRuntimeConfiguration{
		databaseName:      databaseName,
		databaseUser:      "unused",
		driverName:        "sqlite",
		ocQuery:           defaultSQLOCQuery,
		attributeQuery:    defaultSQLATQuery,
		idQuery:           defaultSQLIDQuery,
		aliasingKeyword:   "AS ",
		insertEntry:       defaultSQLInsertEntryStatement,
		deleteEntry:       defaultSQLDeleteEntryStatement,
		renameEntry:       defaultSQLRenameEntryStatement,
		deleteObjectClass: defaultSQLDeleteObjectClassesStatement,
		registry:          testSQLBuiltinRegistry(t),
	}
	if _, err := configuration.database(context.Background()); err != nil {
		t.Fatalf("initialize SQL backend: %v", err)
	}
	t.Cleanup(func() { _ = configuration.close() })
	return configuration
}

func mustDeferredHasSubordinatesDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func assertDeferredHasSubordinatesQueryFailure(t *testing.T, err error) {
	t.Helper()
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultOther {
		t.Fatalf("children query error = %#v, want LDAP result %d", err, ldapwire.ResultOther)
	}
}

func configureDeferredHasSubordinatesQueryFailure(t *testing.T, store storage.Store) {
	t.Helper()
	dn := mustDeferredHasSubordinatesDN(t, "olcDatabase={1}sql,cn=config")
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSqlDnMatchCond", stringValues(
			"ldap_entries.dn=? AND missing_children.id=1",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure failing has-children query: %v", err)
	}
}

func searchDeferredHasSubordinates(
	t *testing.T,
	address,
	filter string,
	attributes []string,
	controls []ldap.Control,
) *ldap.SearchResult {
	t.Helper()
	result, err := searchDeferredHasSubordinatesResult(
		t,
		address,
		filter,
		attributes,
		controls,
	)
	if err != nil {
		t.Fatalf("Search(%s): %v", filter, err)
	}
	return result
}

func searchDeferredHasSubordinatesResult(
	t *testing.T,
	address,
	filter string,
	attributes []string,
	controls []ldap.Control,
) (*ldap.SearchResult, error) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	return client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		controls,
	))
}
