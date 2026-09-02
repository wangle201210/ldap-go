package migration

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDIFImportExportRoundTrip(t *testing.T) {
	t.Parallel()

	input := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
entryUUID: 11111111-1111-1111-1111-111111111111

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example
jpegPhoto:: AP8Q

`
	source := storage.NewMemory()
	t.Cleanup(func() { _ = source.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		source,
		bytes.NewBufferString(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(source): %v", err)
	}

	var exported bytes.Buffer
	result, err := ExportLDIF(context.Background(), source, &exported)
	if err != nil {
		t.Fatalf("ExportLDIF(): %v", err)
	}
	if result.Entries != 2 {
		t.Fatalf("ExportLDIF() entries = %d, want 2", result.Entries)
	}

	destination := storage.NewMemory()
	t.Cleanup(func() { _ = destination.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		destination,
		bytes.NewReader(exported.Bytes()),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(destination): %v\nexported:\n%s", err, exported.String())
	}

	assertStoresEqual(t, source, destination)
}

func TestExportLDIFFilterUsesImportedSchema(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

dn: uid=bob,dc=example,dc=com
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Example

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(): %v", err)
	}

	var output bytes.Buffer
	result, err := ExportLDIFWithOptions(
		context.Background(),
		store,
		&output,
		ExportOptions{Filter: "(&(objectClass=inetOrgPerson)(uid=ALICE))"},
	)
	if err != nil {
		t.Fatalf("ExportLDIFWithOptions(filter): %v", err)
	}
	if result.Entries != 1 ||
		!strings.Contains(output.String(), "dn: uid=alice,dc=example,dc=com") ||
		strings.Contains(output.String(), "uid=bob") {
		t.Fatalf("filtered export result=%#v output=\n%s", result, output.String())
	}

	output.Reset()
	if _, err := ExportLDIFWithOptions(
		context.Background(),
		store,
		&output,
		ExportOptions{Filter: "(uid="},
	); err == nil || !strings.Contains(err.Error(), "invalid export filter") {
		t.Fatalf("invalid export filter error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("invalid filter wrote %d output bytes", output.Len())
	}
}

func TestExportLDIFDefaultSelectionRequiresContentDatabase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	var output bytes.Buffer
	_, err := ExportLDIFWithOptions(
		context.Background(),
		store,
		&output,
		ExportOptions{SelectDefaultDatabase: true},
	)
	if err == nil || !strings.Contains(err.Error(), "no available OpenLDAP content database") {
		t.Fatalf("ExportLDIFWithOptions(default without database) error = %v", err)
	}
}

func TestDatabaseSelectedImportExportSupportsDuplicateDN(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
entryUUID: 11111111-1111-4111-8111-111111111111

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: dc=example,dc=com
olcHidden: TRUE
entryUUID: 22222222-2222-4222-8222-222222222222

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(configLDIF),
		ImportOptions{Database: "0", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(config): %v", err)
	}

	dataLDIF := func(description string) string {
		return "dn: dc=example,dc=com\n" +
			"objectClass: domain\n" +
			"dc: example\n" +
			"description: " + description + "\n\n"
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(
			dataLDIF("old visible")+
				"dn: ou=stale,dc=example,dc=com\n"+
				"objectClass: organizationalUnit\n"+
				"ou: stale\n\n",
		),
		ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(database 1): %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dataLDIF("hidden")),
		ImportOptions{Database: "{2}mdb", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(database 2): %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dataLDIF("visible")),
		ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("replace database 1: %v", err)
	}

	dn := mustDN(t, "dc=example,dc=com")
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		visible, err := reader.GetIn(
			storage.OpenLDAPDatabasePartition(
				"{1}mdb",
				[]byte("11111111-1111-4111-8111-111111111111"),
			),
			dn,
		)
		if err != nil {
			return err
		}
		if got := string(visible.Values("description")[0]); got != "visible" {
			t.Fatalf("visible description = %q", got)
		}
		hidden, err := reader.GetIn(
			storage.OpenLDAPDatabasePartition(
				"{2}mdb",
				[]byte("22222222-2222-4222-8222-222222222222"),
			),
			dn,
		)
		if err != nil {
			return err
		}
		if got := string(hidden.Values("description")[0]); got != "hidden" {
			t.Fatalf("hidden description = %q", got)
		}
		staleDN := mustDN(t, "ou=stale,dc=example,dc=com")
		if _, err := reader.GetIn(
			storage.OpenLDAPDatabasePartition(
				"{1}mdb",
				[]byte("11111111-1111-4111-8111-111111111111"),
			),
			staleDN,
		); !errors.Is(err, storage.ErrEntryNotFound) {
			t.Fatalf("stale entry error = %v, want ErrEntryNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify partitioned imports: %v", err)
	}

	var combined bytes.Buffer
	if _, err := ExportLDIF(context.Background(), store, &combined); err == nil ||
		!strings.Contains(err.Error(), "exists in multiple databases") {
		t.Fatalf("combined ExportLDIF() error = %v", err)
	}

	var visible bytes.Buffer
	if _, err := ExportLDIFWithOptions(
		context.Background(),
		store,
		&visible,
		ExportOptions{Database: "1"},
	); err != nil {
		t.Fatalf("ExportLDIFWithOptions(database 1): %v", err)
	}
	if !strings.Contains(visible.String(), "description: visible") ||
		strings.Contains(visible.String(), "description: hidden") {
		t.Fatalf("visible export:\n%s", visible.String())
	}

	var hidden bytes.Buffer
	if _, err := ExportLDIFWithOptions(
		context.Background(),
		store,
		&hidden,
		ExportOptions{Database: "olcDatabase={2}mdb,cn=config"},
	); err != nil {
		t.Fatalf("ExportLDIFWithOptions(database DN): %v", err)
	}
	if !strings.Contains(hidden.String(), "description: hidden") ||
		strings.Contains(hidden.String(), "description: visible") {
		t.Fatalf("hidden export:\n%s", hidden.String())
	}
}

func TestExportLDIFRejectsBackendWithoutOfflineExport(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={1}ldap,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}ldap
olcSuffix: dc=example,dc=com

`),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("ImportLDIF(config): %v", err)
	}
	var output bytes.Buffer
	if _, err := ExportLDIFWithOptions(
		context.Background(),
		store,
		&output,
		ExportOptions{Database: "1"},
	); err == nil || !strings.Contains(err.Error(), "does not support offline entry export") {
		t.Fatalf("ExportLDIFWithOptions(LDAP backend) error = %v", err)
	}
}

func TestExportLDIFSelectedGlueSuperiorIncludesSubordinates(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: ou=people,dc=example,dc=com
olcSubordinate: TRUE

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: dc=example,dc=com

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(configLDIF),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("ImportLDIF(config): %v", err)
	}
	contentLDIF := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(contentLDIF),
		ImportOptions{
			SelectDefaultDatabase: true,
			SkipSchemaValidation:  true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(content): %v", err)
	}

	for _, test := range []struct {
		name                string
		includeSubordinates bool
		wantEntries         int
		wantAlice           bool
	}{
		{name: "glue enabled", includeSubordinates: true, wantEntries: 3, wantAlice: true},
		{name: "glue disabled", wantEntries: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			result, err := ExportLDIFWithOptions(
				context.Background(),
				store,
				&output,
				ExportOptions{
					Database:            "2",
					IncludeSubordinates: test.includeSubordinates,
				},
			)
			if err != nil {
				t.Fatalf("ExportLDIFWithOptions(): %v", err)
			}
			if result.Entries != test.wantEntries {
				t.Fatalf("Entries = %d, want %d\n%s", result.Entries, test.wantEntries, output.String())
			}
			containsAlice := strings.Contains(output.String(), "dn: uid=alice,ou=people,dc=example,dc=com")
			if containsAlice != test.wantAlice {
				t.Fatalf("contains Alice = %t, want %t\n%s", containsAlice, test.wantAlice, output.String())
			}
		})
	}

	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

`),
		ImportOptions{
			Database:               "2",
			DisableSubordinateGlue: true,
			SkipSchemaValidation:   true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(duplicate glue suffix): %v", err)
	}
	var invalid bytes.Buffer
	if _, err := ExportLDIFWithOptions(
		context.Background(),
		store,
		&invalid,
		ExportOptions{Database: "2", IncludeSubordinates: true},
	); err == nil || !strings.Contains(err.Error(), "also present in superior database") {
		t.Fatalf("ExportLDIFWithOptions(duplicate glue suffix) error = %v", err)
	}
}

func assertStoresEqual(t *testing.T, left, right storage.Store) {
	t.Helper()
	leftEntries := readEntries(t, left)
	rightEntries := readEntries(t, right)
	if len(leftEntries) != len(rightEntries) {
		t.Fatalf("entry counts differ: %d != %d", len(leftEntries), len(rightEntries))
	}
	for i := range leftEntries {
		if !leftEntries[i].Equal(rightEntries[i]) {
			t.Fatalf("entries differ:\nleft: %#v\nright: %#v", leftEntries[i], rightEntries[i])
		}
	}
}

func readEntries(t *testing.T, store storage.Store) []directory.Entry {
	t.Helper()
	var entries []directory.Entry
	if err := store.View(context.Background(), func(tx storage.Reader) error {
		return tx.ForEach(func(entry directory.Entry) error {
			entries = append(entries, entry)
			return nil
		})
	}); err != nil {
		t.Fatalf("read store: %v", err)
	}
	return entries
}
