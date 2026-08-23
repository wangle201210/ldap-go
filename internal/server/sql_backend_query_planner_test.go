package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestSQLBackendQueryPlannerUsesParametersAndBooleanCandidates(t *testing.T) {
	configuration, database := openSQLBackendQueryPlanner(t)
	recorder := &sqlBackendQueryRecorder{database: database}

	tests := []struct {
		name        string
		filter      directory.Filter
		wantPlanned bool
		wantIDs     []int64
	}{
		{
			name: "octet equality fallback",
			filter: directory.Filter{
				Kind: directory.FilterEquality, Attribute: "userPassword", Assertion: []byte("alice-secret"),
			},
		},
		{
			name: "presence",
			filter: directory.Filter{
				Kind: directory.FilterPresent, Attribute: "jpegPhoto",
			},
			wantPlanned: true,
			wantIDs:     []int64{2},
		},
		{
			name: "objectClass equality",
			filter: directory.Filter{
				Kind: directory.FilterEquality, Attribute: "objectClass", Assertion: []byte("inetOrgPerson"),
			},
			wantPlanned: true,
			wantIDs:     []int64{2},
		},
		{
			name: "and partial",
			filter: directory.Filter{Kind: directory.FilterAnd, Children: []directory.Filter{
				{Kind: directory.FilterPresent, Attribute: "jpegPhoto"},
				{Kind: directory.FilterSubstrings, Attribute: "cn"},
			}},
			wantPlanned: true,
			wantIDs:     []int64{2},
		},
		{
			name: "or equality fallback",
			filter: directory.Filter{Kind: directory.FilterOr, Children: []directory.Filter{
				{Kind: directory.FilterEquality, Attribute: "userPassword", Assertion: []byte("alice-secret")},
				{Kind: directory.FilterPresent, Attribute: "jpegPhoto"},
			}},
		},
		{
			name: "or fallback",
			filter: directory.Filter{Kind: directory.FilterOr, Children: []directory.Filter{
				{Kind: directory.FilterEquality, Attribute: "userPassword", Assertion: []byte("alice-secret")},
				{Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("Alice Example")},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &sqlBackendReader{
				configuration: configuration,
				queryer:       recorder,
				ctx: withSQLBackendSearchRequirements(
					context.Background(), []string{"uid"}, test.filter,
				),
			}
			ids, planned, err := reader.sqlBackendFilterCandidates(recorder)
			if err != nil {
				t.Fatalf("sqlBackendFilterCandidates(): %v", err)
			}
			if planned != test.wantPlanned {
				t.Fatalf("planned = %t, want %t", planned, test.wantPlanned)
			}
			if got := sqlBackendTestIDValues(ids); !equalInt64s(got, test.wantIDs) {
				t.Fatalf("candidate IDs = %v, want %v", got, test.wantIDs)
			}
		})
	}

	injection := "secret') OR 1=1 --"
	reader := &sqlBackendReader{
		configuration: configuration,
		queryer:       recorder,
		ctx: withSQLBackendSearchRequirements(context.Background(), nil, directory.Filter{
			Kind: directory.FilterEquality, Attribute: "userPassword", Assertion: []byte(injection),
		}),
	}
	ids, planned, err := reader.sqlBackendFilterCandidates(recorder)
	if err != nil || planned || ids != nil {
		t.Fatalf("injection candidates = %#v, %t, %v", ids, planned, err)
	}
	for _, call := range recorder.snapshot() {
		if strings.Contains(call.query, injection) {
			t.Fatalf("assertion was interpolated into SQL: %s", call.query)
		}
	}
}

func TestSQLBackendQueryPlannerOctetStringTextFallbackDoesNotOmitMatch(t *testing.T) {
	configuration, database := openSQLBackendQueryPlanner(t)

	var storageClass string
	var blobParameterEqual bool
	if err := database.QueryRow(
		`SELECT typeof(user_password), user_password = ? FROM persons WHERE id = 20`,
		[]byte("alice-secret"),
	).Scan(&storageClass, &blobParameterEqual); err != nil {
		t.Fatalf("inspect SQLite TEXT/BLOB comparison: %v", err)
	}
	if storageClass != "text" || blobParameterEqual {
		t.Fatalf(
			"SQLite fixture storage class = %q, TEXT equals BLOB = %t; want text, false",
			storageClass,
			blobParameterEqual,
		)
	}

	filter := directory.Filter{
		Kind:      directory.FilterEquality,
		Attribute: "userPassword",
		Assertion: []byte("alice-secret"),
	}
	recorder := &sqlBackendQueryRecorder{database: database}
	reader := &sqlBackendReader{
		configuration: configuration,
		queryer:       recorder,
		ctx: withSQLBackendSearchRequirements(
			context.Background(), []string{"userPassword"}, filter,
		),
	}
	ids, planned, err := reader.sqlBackendFilterCandidates(recorder)
	if err != nil {
		t.Fatalf("sqlBackendFilterCandidates(): %v", err)
	}
	if planned || ids != nil {
		t.Fatalf("octetString candidates = %#v, planned %t; want full-scan fallback", ids, planned)
	}
	if calls := recorder.snapshot(); len(calls) != 0 {
		t.Fatalf("octetString fallback executed candidate SQL: %#v", calls)
	}

	var matches []string
	if err := reader.ForEach(func(entry directory.Entry) error {
		matched, matchErr := filter.MatchWith(entry, configuration.registry)
		if matchErr != nil {
			return matchErr
		}
		if matched {
			matches = append(matches, entry.DN)
		}
		return nil
	}); err != nil {
		t.Fatalf("ForEach(full scan): %v", err)
	}
	if len(matches) != 1 || !strings.EqualFold(matches[0], "uid=alice,dc=example,dc=com") {
		t.Fatalf("final LDAP filter matches = %q, want Alice entry", matches)
	}
}

func TestSQLBackendQueryPlannerCaseIgnoreFallbackDoesNotOmitCandidates(t *testing.T) {
	configuration, database := openSQLBackendQueryPlanner(t)
	tests := []struct {
		name      string
		attribute string
		assertion string
	}{
		{
			name:      "caseIgnore leading trailing and repeated spaces",
			attribute: "cn",
			assertion: "Alice Example",
		},
		{
			name:      "caseIgnoreList whitespace folding",
			attribute: "postalAddress",
			assertion: "123 Main Street$Example City",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := directory.Filter{
				Kind:      directory.FilterEquality,
				Attribute: test.attribute,
				Assertion: []byte(test.assertion),
			}
			recorder := &sqlBackendQueryRecorder{database: database}
			reader := &sqlBackendReader{
				configuration: configuration,
				queryer:       recorder,
				ctx: withSQLBackendSearchRequirements(
					context.Background(), []string{test.attribute}, filter,
				),
			}

			ids, planned, err := reader.sqlBackendFilterCandidates(recorder)
			if err != nil {
				t.Fatalf("sqlBackendFilterCandidates(): %v", err)
			}
			if planned || ids != nil {
				t.Fatalf("caseIgnore candidates = %#v, planned %t; want full-scan fallback", ids, planned)
			}

			var matches []string
			if err := reader.ForEach(func(entry directory.Entry) error {
				matched, matchErr := filter.MatchWith(entry, configuration.registry)
				if matchErr != nil {
					return matchErr
				}
				if matched {
					matches = append(matches, entry.DN)
				}
				return nil
			}); err != nil {
				t.Fatalf("ForEach(full scan): %v", err)
			}
			if len(matches) != 1 || !strings.EqualFold(matches[0], "uid=alice,dc=example,dc=com") {
				t.Fatalf("final LDAP filter matches = %q, want Alice entry", matches)
			}
			for _, call := range recorder.snapshot() {
				if strings.Contains(strings.ToUpper(call.query), "UPPER(") {
					t.Fatalf("caseIgnore assertion was pushed through UPPER(): %s", call.query)
				}
			}
		})
	}
}

func TestSQLBackendRequestedAttributePruningAndBinary(t *testing.T) {
	configuration, database := openSQLBackendQueryPlanner(t)
	bad := configuration.objectClasses[1].attributes["cn"]
	bad[0].query = "SELECT value FROM missing_requested_attribute WHERE id=?"
	configuration.objectClasses[1].attributes["cn"] = bad
	filter := directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"}
	reader := &sqlBackendReader{
		configuration: configuration,
		queryer:       database,
		ctx: withSQLBackendSearchRequirements(
			context.Background(), []string{"uid", "jpegPhoto"}, filter,
		),
	}
	var alice directory.Entry
	if err := reader.ForEach(func(entry directory.Entry) error {
		if strings.HasPrefix(strings.ToLower(entry.DN), "uid=alice,") {
			alice = entry
		}
		return nil
	}); err != nil {
		t.Fatalf("ForEach(pruned): %v", err)
	}
	if got := string(alice.Values("uid")[0]); got != "alice" {
		t.Fatalf("uid = %q, want alice", got)
	}
	if got := alice.Values("jpegPhoto"); len(got) != 1 || string(got[0]) != string([]byte{0, 0xff, 0x10}) {
		t.Fatalf("jpegPhoto = %#v", got)
	}
	if alice.HasAttribute("cn") {
		t.Fatalf("unrequested cn was loaded: %#v", alice)
	}

	configuration.fetchAttrs = []string{"cn"}
	if err := reader.ForEach(func(directory.Entry) error { return nil }); err == nil {
		t.Fatal("olcSqlFetchAttrs did not force the configured mapping query")
	}
}

func TestSQLBackendBaseObjectTrueAndUnsupportedDirectives(t *testing.T) {
	databaseName := filepath.Join(t.TempDir(), "base-object.db")
	seedSQLBackendDatabase(t, databaseName)
	entry := directory.Entry{
		DN: "olcDatabase={1}sql,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDbName", Values: stringValues(databaseName)},
			{Description: "olcDbUser", Values: stringValues("unused")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcSqlBaseObject", Values: stringValues("TRUE")},
		},
	}
	configuration, err := loadSQLBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadSQLBackendRuntimeConfiguration(): %v", err)
	}
	configuration.setRuntime(testSQLBuiltinRegistry(t), "sqlite", nil)
	reader := &sqlBackendReader{configuration: configuration, ctx: context.Background()}
	base, err := reader.Get(mustDeferredHasSubordinatesDN(t, "dc=example,dc=com"))
	if err != nil {
		t.Fatalf("Get(baseObject): %v", err)
	}
	if !base.HasAttribute("description") || string(base.Values("dc")[0]) != "example" {
		t.Fatalf("baseObject = %#v", base)
	}
	count := 0
	if err := reader.ForEach(func(directory.Entry) error { count++; return nil }); err != nil {
		t.Fatalf("ForEach(baseObject): %v", err)
	}
	if count != 2 {
		t.Fatalf("entries including de-duplicated baseObject = %d, want 2", count)
	}
	_ = configuration.close()

	for _, attribute := range []string{
		"olcSqlConcatPattern", "olcSqlSubtreeCond", "olcSqlChildrenCond", "olcSqlStrcastFunc",
	} {
		rejected := entry.Clone()
		rejected.ReplaceValues(attribute, stringValues("unsupported"))
		if _, err := loadSQLBackendRuntimeConfiguration(rejected); err == nil {
			t.Fatalf("%s was accepted", attribute)
		}
	}
}

func openSQLBackendQueryPlanner(
	t *testing.T,
) (*sqlBackendRuntimeConfiguration, *sql.DB) {
	t.Helper()
	databaseName := filepath.Join(t.TempDir(), "query-planner.db")
	seedSQLBackendDatabase(t, databaseName)
	database, err := sql.Open("sqlite", databaseName)
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	if _, err := database.Exec(`ALTER TABLE persons ADD COLUMN postal_address TEXT`); err != nil {
		t.Fatalf("add postalAddress fixture column: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO ldap_attr_mappings VALUES
		(7,1,'postalAddress','persons.postal_address','persons',NULL,NULL,NULL,0,0,
		 'UPPER(persons.postal_address)')`); err != nil {
		t.Fatalf("add postalAddress fixture mapping: %v", err)
	}
	if _, err := database.Exec(`UPDATE persons SET
		cn='  Alice   Example  ',
		postal_address='  123   Main Street  $  Example   City  ',
		user_password=CAST(user_password AS TEXT)`); err != nil {
		t.Fatalf("configure equality fixture values: %v", err)
	}
	if _, err := database.Exec(`UPDATE ldap_attr_mappings SET sel_expr_u =
		CASE name
		WHEN 'uid' THEN 'UPPER(persons.uid)'
		WHEN 'cn' THEN 'UPPER(persons.cn)'
		WHEN 'dc' THEN 'UPPER(organizations.dc)'
		ELSE sel_expr_u END`); err != nil {
		t.Fatalf("configure uppercase mappings: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close mapping database: %v", err)
	}
	configuration := openDeferredHasSubordinatesSQLBackend(t, databaseName)
	database, err = configuration.database(context.Background())
	if err != nil {
		t.Fatalf("configuration.database(): %v", err)
	}
	return configuration, database
}

type sqlBackendQueryCall struct {
	query     string
	arguments []any
}

type sqlBackendQueryRecorder struct {
	mu       sync.Mutex
	database *sql.DB
	calls    []sqlBackendQueryCall
}

func (recorder *sqlBackendQueryRecorder) QueryContext(
	ctx context.Context,
	query string,
	arguments ...any,
) (*sql.Rows, error) {
	recorder.mu.Lock()
	recorder.calls = append(recorder.calls, sqlBackendQueryCall{
		query: query, arguments: append([]any(nil), arguments...),
	})
	recorder.mu.Unlock()
	return recorder.database.QueryContext(ctx, query, arguments...)
}

func (recorder *sqlBackendQueryRecorder) QueryRowContext(
	ctx context.Context,
	query string,
	arguments ...any,
) *sql.Row {
	return recorder.database.QueryRowContext(ctx, query, arguments...)
}

func (recorder *sqlBackendQueryRecorder) snapshot() []sqlBackendQueryCall {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]sqlBackendQueryCall(nil), recorder.calls...)
}

func sqlBackendTestIDValues(ids []sqlEntryID) []int64 {
	result := make([]int64, len(ids))
	for index := range ids {
		result[index] = ids[index].id
	}
	return result
}

func equalInt64s(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
