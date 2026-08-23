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
