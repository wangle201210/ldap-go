package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOfflineToolsMemoryAndBolt(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			store := fixture.open(t)
			t.Cleanup(func() { _ = store.Close() })
			seedOfflineToolStore(t, store)

			t.Run("slapauth mapping and authorization", func(t *testing.T) {
				result, err := CheckOfflineAuthorization(
					context.Background(), store, "PLAIN", "", "alice", "u:bob",
				)
				if err != nil {
					t.Fatalf("CheckOfflineAuthorization(): %v", err)
				}
				if result.AuthenticationDN != offlineAliceDN ||
					result.AuthorizationDN != offlineBobDN || !result.Authorized {
					t.Fatalf("authorization result = %#v", result)
				}
				mapped, err := CheckOfflineAuthorization(
					context.Background(), store, "", "", "alice", "",
				)
				if err != nil || mapped.AuthenticationDN != offlineAliceDN {
					t.Fatalf("default mechanism mapping = %#v, %v", mapped, err)
				}
			})

			t.Run("slapschema is read only", func(t *testing.T) {
				invalid := offlineToolEntry(
					"uid=invalid,ou=people,dc=example,dc=com",
					"inetOrgPerson",
					map[string][]string{"uid": {"invalid"}, "cn": {"Invalid"}},
				)
				putOfflineToolEntry(t, store, invalid)
				before := readOfflineToolEntry(t, store, invalid.DN)
				report, err := CheckOfflineSchema(
					context.Background(), store, OfflineSchemaOptions{
						Database: "1", Continue: true,
					},
				)
				if err != nil {
					t.Fatalf("CheckOfflineSchema(): %v", err)
				}
				if len(report.Issues) != 1 || report.Issues[0].DN != invalid.DN {
					t.Fatalf("schema report = %#v", report)
				}
				after := readOfflineToolEntry(t, store, invalid.DN)
				if !before.Equal(after) {
					t.Fatalf("schema check modified entry: before=%#v after=%#v", before, after)
				}
			})

			t.Run("slapmodify applies records", func(t *testing.T) {
				input := `dn: uid=alice,ou=people,dc=example,dc=com
changetype: modify
replace: cn
cn: Alice Updated
-
increment: uidNumber
uidNumber: 2

dn: uid=carol,ou=people,dc=example,dc=com
changetype: add
objectClass: inetOrgPerson
objectClass: posixAccount
uid: carol
cn: Carol Example
sn: Example
uidNumber: 3000
gidNumber: 3000
homeDirectory: /home/carol
`
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", IncludeSubordinates: true},
				)
				if err != nil {
					t.Fatalf("ApplyOfflineChanges(): %v", err)
				}
				if report.Applied != 2 || len(report.Failures) != 0 {
					t.Fatalf("modify report = %#v", report)
				}
				alice := readOfflineToolEntry(t, store, offlineAliceDN)
				if got := string(alice.Values("cn")[0]); got != "Alice Updated" {
					t.Fatalf("alice cn = %q", got)
				}
				if got := string(alice.Values("uidNumber")[0]); got != "1002" {
					t.Fatalf("alice uidNumber = %q", got)
				}
				_ = readOfflineToolEntry(t, store, "uid=carol,ou=people,dc=example,dc=com")
			})

			t.Run("slapmodify dry run and continue", func(t *testing.T) {
				before := readOfflineToolEntry(t, store, offlineAliceDN)
				dryRun := `dn: uid=alice,ou=people,dc=example,dc=com
changetype: modify
replace: sn
sn: Dry Run
`
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(dryRun),
					OfflineModifyOptions{Database: "1", DryRun: true},
				)
				if err != nil || report.Applied != 1 {
					t.Fatalf("dry run report=%#v error=%v", report, err)
				}
				if after := readOfflineToolEntry(t, store, offlineAliceDN); !before.Equal(after) {
					t.Fatal("dry run modified the entry")
				}

				failed := `dn: uid=alice,ou=people,dc=example,dc=com
changetype: modify
replace: sn
sn: Must Roll Back

dn: uid=missing,ou=people,dc=example,dc=com
changetype: delete

this is not ldif

dn: uid=bob,ou=people,dc=example,dc=com
changetype: modify
replace: description
description: continued after failures
`
				report, err = ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(failed),
					OfflineModifyOptions{Database: "1", Continue: true},
				)
				if err == nil || report.Applied != 2 || len(report.Failures) != 2 {
					t.Fatalf("failed report=%#v error=%v", report, err)
				}
				if after := readOfflineToolEntry(t, store, offlineAliceDN); string(after.Values("sn")[0]) != "Must Roll Back" {
					t.Fatalf("successful record was not retained: %#v", after)
				}
				if after := readOfflineToolEntry(t, store, offlineBobDN); string(after.Values("description")[0]) != "continued after failures" {
					t.Fatalf("record after failures was not retained: %#v", after)
				}
			})

			t.Run("slapmodify file URL and moddn subtree", func(t *testing.T) {
				valuePath := filepath.Join(t.TempDir(), "description value.txt")
				if err := os.WriteFile(valuePath, []byte("value loaded from file"), 0o600); err != nil {
					t.Fatalf("WriteFile(): %v", err)
				}
				fileURL := (&url.URL{Scheme: "file", Path: valuePath}).String()
				input := "dn: " + offlineAliceDN + "\n" +
					"changetype: modify\nreplace: description\n" +
					"description:< " + fileURL + "\n\n" +
					"dn: " + offlineAliceDN + "\n" +
					"changetype: moddn\nnewrdn: uid=alice-renamed\n" +
					"deleteoldrdn: 1\nnewsuperior: ou=archive,dc=example,dc=com\n"
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1"},
				)
				if err != nil || report.Applied != 2 {
					t.Fatalf("file URL/moddn report=%#v error=%v", report, err)
				}
				renamedDN := "uid=alice-renamed,ou=archive,dc=example,dc=com"
				renamed := readOfflineToolEntry(t, store, renamedDN)
				if got := string(renamed.Values("description")[0]); got != "value loaded from file" {
					t.Fatalf("description = %q", got)
				}
				if got := string(renamed.Values("uid")[0]); got != "alice-renamed" {
					t.Fatalf("renamed uid = %q", got)
				}
				childDN := "cn=child," + renamedDN
				if child := readOfflineToolEntry(t, store, childDN); child.DN != childDN {
					t.Fatalf("renamed child = %#v", child)
				}
				assertOfflineToolEntryMissing(t, store, offlineAliceDN)
			})

			t.Run("slapindex selected database", func(t *testing.T) {
				count, err := ReindexOfflineSelected(
					context.Background(), store, OfflineReindexOptions{
						Database: "1", IncludeSubordinates: true,
						Attributes: []string{"uid"}, Quick: true,
					},
				)
				if err != nil || count != 1 {
					t.Fatalf("ReindexOfflineSelected() = %d, %v", count, err)
				}
				count, err = ReindexOfflineSelected(
					context.Background(), store, OfflineReindexOptions{
						Database: "1", Attributes: []string{"cn"},
					},
				)
				if err != nil || count != 1 {
					t.Fatalf("selective ReindexOfflineSelected() = %d, %v", count, err)
				}
				if err := store.View(context.Background(), func(reader storage.Reader) error {
					_, runtime, err := buildOfflineRuntime(reader, store)
					if err != nil {
						return err
					}
					indexes, err := selectOfflineDatabases(runtime, "1", false)
					if err != nil {
						return err
					}
					if len(indexes) != 1 {
						return fmt.Errorf("selected database count = %d, want 1", len(indexes))
					}
					database := &runtime.databases[indexes[0]]
					stored, err := reader.Metadata(
						runtimeDNIdentityFingerprintMetadataKey(database.partition),
					)
					if err != nil {
						return err
					}
					want := runtime.schema.DNIdentityFingerprint()
					if !bytes.Equal(stored, want[:]) {
						return fmt.Errorf("DN identity fingerprint = %x, want %x", stored, want)
					}
					return nil
				}); err != nil {
					t.Fatalf("verify DN identity fingerprint: %v", err)
				}
				if _, err := ReindexOfflineSelected(
					context.Background(), store, OfflineReindexOptions{
						Database: "1", Attributes: []string{"description"},
					},
				); err == nil || !strings.Contains(err.Error(), "no index configured") {
					t.Fatalf("unconfigured attribute error = %v", err)
				}
			})
		})
	}
}

func TestOfflineSchemaStableEntryIDsAcrossStores(t *testing.T) {
	stores := []storage.Store{storage.NewMemory()}
	bolt, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	stores = append(stores, bolt)
	for _, store := range stores {
		defer store.Close()
		seedOfflineToolStore(t, store)
	}
	var want map[string]uint64
	for index, store := range stores {
		report, err := CheckOfflineSchema(
			context.Background(), store, OfflineSchemaOptions{Database: "1", Continue: true},
		)
		if err != nil {
			t.Fatalf("CheckOfflineSchema(store %d): %v", index, err)
		}
		got := make(map[string]uint64, len(report.Records))
		for _, record := range report.Records {
			if record.EntryID == 0 {
				t.Fatalf("zero entry ID for %q", record.DN)
			}
			got[record.DN] = record.EntryID
		}
		if want == nil {
			want = got
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("stable ID count = %d, want %d", len(got), len(want))
		}
		for dn, id := range want {
			if got[dn] != id {
				t.Fatalf("stable ID for %q = %x, want %x", dn, got[dn], id)
			}
		}
	}
}

func TestOfflineFileURLSafety(t *testing.T) {
	if _, err := readOfflineFileURL("file://remote.example/tmp/value"); err == nil {
		t.Fatal("remote file authority was accepted")
	}
	if _, err := readOfflineFileURL((&url.URL{Scheme: "file", Path: t.TempDir()}).String()); err == nil {
		t.Fatal("directory URL was accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	inside := t.TempDir()
	link := filepath.Join(inside, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}
	if _, err := readOfflineFileURL((&url.URL{Scheme: "file", Path: link}).String()); err == nil {
		t.Fatal("escaping symlink URL was accepted")
	}
}

const (
	offlineAliceDN = "uid=alice,ou=people,dc=example,dc=com"
	offlineBobDN   = "uid=bob,ou=people,dc=example,dc=com"
)

func seedOfflineToolStore(t *testing.T, store storage.Store) {
	t.Helper()
	config := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
				{Description: "olcAuthzPolicy", Values: stringValues("to")},
				{Description: "olcAuthzRegexp", Values: stringValues(
					`{0}^uid=([^,]+),cn=plain,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
					`{1}^uid=([^,]+),cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
				)},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=example,dc=com")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * manage")},
				{Description: "olcDbIndex", Values: stringValues("uid eq", "cn eq")},
			},
		},
	}
	content := []directory.Entry{
		offlineToolEntry("dc=example,dc=com", "domain", map[string][]string{"dc": {"example"}}),
		offlineToolEntry("ou=people,dc=example,dc=com", "organizationalUnit", map[string][]string{"ou": {"people"}}),
		offlineToolEntry("ou=archive,dc=example,dc=com", "organizationalUnit", map[string][]string{"ou": {"archive"}}),
		offlineToolEntry(offlineAliceDN, "inetOrgPerson", map[string][]string{
			"uid": {"alice"}, "cn": {"Alice Example"}, "sn": {"Example"},
			"uidNumber": {"1000"}, "gidNumber": {"1000"},
			"homeDirectory": {"/home/alice"}, "authzTo": {"dn:" + offlineBobDN},
		}),
		offlineToolEntry(offlineBobDN, "inetOrgPerson", map[string][]string{
			"uid": {"bob"}, "cn": {"Bob Example"}, "sn": {"Example"},
		}),
		offlineToolEntry("cn=child,"+offlineAliceDN, "person", map[string][]string{
			"cn": {"child"}, "sn": {"Child"},
		}),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range config {
			if err := writer.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
				return err
			}
		}
		partition := storage.OpenLDAPDatabasePartition("{1}mdb", nil)
		for _, entry := range content {
			if err := writer.PutIn(partition, entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	}); err != nil {
		t.Fatalf("seed offline tool store: %v", err)
	}
}

func offlineToolEntry(dn, objectClass string, values map[string][]string) directory.Entry {
	objectClasses := []string{objectClass}
	if _, ok := values["uidNumber"]; ok {
		objectClasses = append(objectClasses, "posixAccount")
	}
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues(objectClasses...)},
			{Description: "structuralObjectClass", Values: stringValues(objectClass)},
		},
	}
	for description, rawValues := range values {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: description, Values: stringValues(rawValues...),
		})
	}
	return entry
}

func putOfflineToolEntry(t *testing.T, store storage.Store, entry directory.Entry) {
	t.Helper()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(storage.OpenLDAPDatabasePartition("{1}mdb", nil), entry, false)
	})
	if err != nil {
		t.Fatalf("put offline entry %q: %v", entry.DN, err)
	}
}

func readOfflineToolEntry(t *testing.T, store storage.Store, rawDN string) directory.Entry {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	var entry directory.Entry
	err = store.View(context.Background(), func(reader storage.Reader) error {
		var readErr error
		entry, readErr = reader.GetIn(
			storage.OpenLDAPDatabasePartition("{1}mdb", nil), dn,
		)
		return readErr
	})
	if err != nil {
		if errors.Is(err, storage.ErrEntryNotFound) {
			t.Fatalf("offline entry %q was not found", rawDN)
		}
		t.Fatalf("read offline entry %q: %v", rawDN, err)
	}
	return entry
}

func assertOfflineToolEntryMissing(t *testing.T, store storage.Store, rawDN string) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.GetIn(storage.OpenLDAPDatabasePartition("{1}mdb", nil), dn)
		return err
	})
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("entry %q still exists: %v", rawDN, err)
	}
}
