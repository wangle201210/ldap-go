package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOfflineModifyDirectorySafetyMemoryAndBolt(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			t.Run("non-leaf delete is rejected", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				input := "dn: " + offlineAliceDN + "\nchangetype: delete\n"
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1"},
				)
				failure := offlineModifyFailureResult(report)
				if err == nil || report.Applied != 0 || failure == nil ||
					failure.Code != ldapwire.ResultNotAllowedOnNonLeaf {
					t.Fatalf("non-leaf delete report=%#v error=%v", report, err)
				}
				_ = readOfflineToolEntry(t, store, offlineAliceDN)
				_ = readOfflineToolEntry(t, store, "cn=child,"+offlineAliceDN)
			})

			t.Run("RDN value cannot be removed", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				input := "dn: " + offlineAliceDN + "\nchangetype: modify\n" +
					"replace: uid\nuid: renamed-without-moddn\n"
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1"},
				)
				failure := offlineModifyFailureResult(report)
				if err == nil || report.Applied != 0 || failure == nil ||
					failure.Code != ldapwire.ResultNamingViolation {
					t.Fatalf("RDN mismatch report=%#v error=%v", report, err)
				}
				entry := readOfflineToolEntry(t, store, offlineAliceDN)
				if got := string(entry.Values("uid")[0]); got != "alice" {
					t.Fatalf("rolled-back uid = %q", got)
				}
			})

			t.Run("dry-run shares one transaction", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				input := `dn: ou=dry-run,dc=example,dc=com
changetype: add
objectClass: organizationalUnit
ou: dry-run

dn: cn=child,ou=dry-run,dc=example,dc=com
changetype: add
objectClass: person
cn: child
sn: Child
`
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", DryRun: true},
				)
				if err != nil || report.Applied != 2 || len(report.Failures) != 0 {
					t.Fatalf("dependent dry-run report=%#v error=%v", report, err)
				}
				assertOfflineToolEntryMissing(t, store, "ou=dry-run,dc=example,dc=com")
				assertOfflineToolEntryMissing(t, store, "cn=child,ou=dry-run,dc=example,dc=com")
			})

			t.Run("CSNs are unique across record transactions", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				input := "dn: " + offlineAliceDN + "\nchangetype: modify\n" +
					"replace: description\ndescription: one\n\n" +
					"dn: " + offlineBobDN + "\nchangetype: modify\n" +
					"replace: description\ndescription: two\n"
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", ServerID: 7},
				)
				if err != nil || report.Applied != 2 {
					t.Fatalf("CSN modify report=%#v error=%v", report, err)
				}
				alice := readOfflineToolEntry(t, store, offlineAliceDN).Values("entryCSN")
				bob := readOfflineToolEntry(t, store, offlineBobDN).Values("entryCSN")
				if len(alice) != 1 || len(bob) != 1 || string(alice[0]) == string(bob[0]) {
					t.Fatalf("entryCSNs = %q and %q", alice, bob)
				}
			})

			t.Run("contextCSN uses the configured sync subentry", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				configDN, _ := directory.ParseDN("olcDatabase={1}mdb,cn=config")
				if err := store.Update(context.Background(), func(writer storage.Writer) error {
					entry, err := writer.GetIn(storage.OpenLDAPConfigPartition, configDN)
					if err != nil {
						return err
					}
					entry.ReplaceValues("olcSyncUseSubentry", stringValues("TRUE"))
					return writer.PutIn(storage.OpenLDAPConfigPartition, entry, true)
				}); err != nil {
					t.Fatalf("enable olcSyncUseSubentry: %v", err)
				}
				input := "dn: " + offlineBobDN + "\nchangetype: modify\n" +
					"replace: description\ndescription: context update\n"
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{
						Database: "1", ServerID: 7, UpdateContextCSN: true,
					},
				)
				if err != nil || report.Applied != 1 {
					t.Fatalf("subentry contextCSN report=%#v error=%v", report, err)
				}
				root := readOfflineToolEntry(t, store, "dc=example,dc=com")
				if values := root.Values("contextCSN"); len(values) != 0 {
					t.Fatalf("suffix root contextCSN = %q", values)
				}
				subentry := readOfflineToolEntry(t, store, "cn=ldapsync,dc=example,dc=com")
				if values := subentry.Values("contextCSN"); len(values) != 1 ||
					!strings.Contains(string(values[0]), "#007#") {
					t.Fatalf("sync subentry contextCSN = %q", values)
				}
				if got := string(subentry.Values("structuralObjectClass")[0]); got != "subentry" {
					t.Fatalf("structuralObjectClass = %q", got)
				}
				if got := string(subentry.Values("subtreeSpecification")[0]); got != "{}" {
					t.Fatalf("subtreeSpecification = %q", got)
				}
			})

			t.Run("slapschema detects missing structuralObjectClass", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				entry := readOfflineToolEntry(t, store, offlineBobDN)
				entry.ReplaceValues("structuralObjectClass", nil)
				if err := store.Update(context.Background(), func(writer storage.Writer) error {
					return writer.PutIn(
						storage.OpenLDAPDatabasePartition("{1}mdb", nil), entry, true,
					)
				}); err != nil {
					t.Fatalf("remove structuralObjectClass: %v", err)
				}
				report, err := CheckOfflineSchema(
					context.Background(), store,
					OfflineSchemaOptions{Database: "1", Subtree: offlineBobDN, Continue: true},
				)
				if err != nil || len(report.Issues) != 1 ||
					report.Issues[0].Code != uint16(ldapwire.ResultObjectClassViolation) {
					t.Fatalf("structuralObjectClass report=%#v error=%v", report, err)
				}
			})
		})
	}
}

func TestOfflineModifyDeleteAdvancesContextCSNMemoryAndBolt(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			t.Run("pure delete", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store,
					strings.NewReader("dn: "+offlineBobDN+"\nchangetype: delete\n"),
					OfflineModifyOptions{
						Database: "1", ServerID: 7, UpdateContextCSN: true,
					},
				)
				if err != nil || report.Applied != 1 || len(report.Failures) != 0 {
					t.Fatalf("pure delete report=%#v error=%v", report, err)
				}
				assertOfflineToolEntryMissing(t, store, offlineBobDN)
				assertOfflineContextCSNSIDs(t, store, "007")
			})

			t.Run("preserves multiple SIDs", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				modify := "dn: " + offlineBobDN + "\nchangetype: modify\n" +
					"replace: description\ndescription: sid three\n"
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(modify),
					OfflineModifyOptions{
						Database: "1", ServerID: 3, UpdateContextCSN: true,
					},
				)
				if err != nil || report.Applied != 1 {
					t.Fatalf("SID 3 modify report=%#v error=%v", report, err)
				}
				report, err = ApplyOfflineChanges(
					context.Background(), store,
					strings.NewReader("dn: "+offlineBobDN+"\nchangetype: delete\n"),
					OfflineModifyOptions{
						Database: "1", ServerID: 7, UpdateContextCSN: true,
					},
				)
				if err != nil || report.Applied != 1 {
					t.Fatalf("SID 7 delete report=%#v error=%v", report, err)
				}
				assertOfflineToolEntryMissing(t, store, offlineBobDN)
				assertOfflineContextCSNSIDs(t, store, "003", "007")
			})

			t.Run("post-delete failure rolls back entry and waterline", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				modify := "dn: " + offlineBobDN + "\nchangetype: modify\n" +
					"replace: description\ndescription: baseline\n"
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(modify),
					OfflineModifyOptions{
						Database: "1", ServerID: 3, UpdateContextCSN: true,
					},
				)
				if err != nil || report.Applied != 1 {
					t.Fatalf("baseline modify report=%#v error=%v", report, err)
				}
				before := readOfflineToolEntry(t, store, "dc=example,dc=com").Values("contextCSN")

				failingStore := &offlineNamingContextFailureStore{
					Store: storage.Store(store), failNext: true,
				}
				report, err = ApplyOfflineChanges(
					context.Background(), failingStore,
					strings.NewReader("dn: "+offlineBobDN+"\nchangetype: delete\n"),
					OfflineModifyOptions{
						Database: "1", ServerID: 7, UpdateContextCSN: true,
					},
				)
				if err == nil || !strings.Contains(err.Error(), "injected naming context failure") ||
					report.Applied != 0 || len(report.Failures) != 1 {
					t.Fatalf("failed delete report=%#v error=%v", report, err)
				}
				_ = readOfflineToolEntry(t, store, offlineBobDN)
				after := readOfflineToolEntry(t, store, "dc=example,dc=com").Values("contextCSN")
				if len(before) != 1 || len(after) != 1 || string(before[0]) != string(after[0]) {
					t.Fatalf("contextCSN changed after rollback: before=%q after=%q", before, after)
				}
				assertOfflineContextCSNSIDs(t, store, "003")
			})
		})
	}
}

type offlineNamingContextFailureStore struct {
	storage.Store
	failNext bool
}

func (store *offlineNamingContextFailureStore) Update(
	ctx context.Context,
	fn func(storage.Writer) error,
) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		return fn(&offlineNamingContextFailureWriter{Writer: writer, store: store})
	})
}

type offlineNamingContextFailureWriter struct {
	storage.Writer
	store *offlineNamingContextFailureStore
}

func (writer *offlineNamingContextFailureWriter) SetNamingContexts(contexts []string) error {
	if writer.store.failNext {
		writer.store.failNext = false
		return errors.New("injected naming context failure")
	}
	return writer.Writer.SetNamingContexts(contexts)
}

func assertOfflineContextCSNSIDs(
	t *testing.T,
	store storage.Store,
	want ...string,
) {
	t.Helper()
	values := readOfflineToolEntry(t, store, "dc=example,dc=com").Values("contextCSN")
	got := make(map[string]struct{}, len(values))
	for _, value := range values {
		parts := strings.Split(string(value), "#")
		if len(parts) != 4 {
			t.Fatalf("invalid contextCSN %q", value)
		}
		got[parts[2]] = struct{}{}
	}
	if len(got) != len(want) {
		t.Fatalf("contextCSN SIDs = %v, want %v (values %q)", got, want, values)
	}
	for _, sid := range want {
		if _, ok := got[sid]; !ok {
			t.Fatalf("contextCSN SIDs = %v, want %v (values %q)", got, want, values)
		}
	}
}

func TestOfflineModifyNormalizesConfigDNBeforeRuntimeValidation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOfflineToolStore(t, store)
	passwdFile := writePasswdBackendFixture(t, "valid:x:1000:1000:Valid:/home/valid:/bin/sh\n")
	entry := directory.Entry{
		DN: "olcDatabase={2}passwd,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcPasswdConfig")},
			{Description: "olcDatabase", Values: stringValues("{2}passwd")},
			{Description: "olcSuffix", Values: stringValues("ou=system-accounts")},
			{Description: "olcPasswdFile", Values: stringValues(passwdFile)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, false)
	}); err != nil {
		t.Fatalf("seed passwd config: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing-passwd")
	input := `dn: olcDatabase={2}passwd,cn=\63onfig
changetype: modify
replace: olcPasswdFile
olcPasswdFile: ` + missing + "\n"
	report, err := ApplyOfflineChanges(
		context.Background(), store, strings.NewReader(input),
		OfflineModifyOptions{Database: "0"},
	)
	if err == nil || report.Applied != 0 ||
		!strings.Contains(err.Error(), "validate modified cn=config") {
		t.Fatalf("escaped config DN report=%#v error=%v", report, err)
	}
	var stored directory.Entry
	if readErr := store.View(context.Background(), func(reader storage.Reader) error {
		var getErr error
		dn, _ := directory.ParseDN(entry.DN)
		stored, getErr = reader.GetIn(storage.OpenLDAPConfigPartition, dn)
		return getErr
	}); readErr != nil {
		t.Fatalf("read rolled-back config: %v", readErr)
	}
	if got := string(stored.Values("olcPasswdFile")[0]); got != passwdFile {
		t.Fatalf("rolled-back olcPasswdFile = %q, want %q", got, passwdFile)
	}
}

func offlineModifyFailureResult(report OfflineModifyReport) *ldapwire.Result {
	if len(report.Failures) == 0 {
		return nil
	}
	var failure *operationFailure
	if !errors.As(report.Failures[0].Err, &failure) {
		return nil
	}
	return &failure.result
}

func openOfflineSecurityStore(t *testing.T, backend string) storage.Store {
	t.Helper()
	var store storage.Store
	if backend == "bolt" {
		bolt, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
		if err != nil {
			t.Fatalf("OpenBolt(): %v", err)
		}
		store = bolt
	} else {
		store = storage.NewMemory()
	}
	t.Cleanup(func() { _ = store.Close() })
	seedOfflineToolStore(t, store)
	return store
}
