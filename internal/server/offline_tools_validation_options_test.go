package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestOfflineModifyValidationOptionsMemoryAndBolt(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			t.Run("schema check controls add and naming validation", func(t *testing.T) {
				input := `dn: cn=schema-disabled,dc=example,dc=com
changetype: add
objectClass: organizationalUnit
ou: schema-disabled
`
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1"},
				)
				failure := offlineModifyFailureResult(report)
				if err == nil || report.Applied != 0 || failure == nil ||
					failure.Code != ldapwire.ResultNamingViolation {
					t.Fatalf("schema-enabled report=%#v error=%v", report, err)
				}

				store = openOfflineSecurityStore(t, backend)
				report, err = ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", SkipSchema: true},
				)
				if err != nil || report.Applied != 1 || len(report.Failures) != 0 {
					t.Fatalf("schema-disabled report=%#v error=%v", report, err)
				}
				_ = readOfflineToolEntry(t, store, "cn=schema-disabled,dc=example,dc=com")
			})

			t.Run("value check remains active without schema check", func(t *testing.T) {
				input := `dn: uid=invalid-value,dc=example,dc=com
changetype: add
objectClass: inetOrgPerson
objectClass: posixAccount
uid: invalid-value
cn: Invalid Value
sn: Value
uidNumber: not-an-integer
gidNumber: 1000
homeDirectory: /home/invalid-value
`
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", SkipSchema: true},
				)
				failure := offlineModifyFailureResult(report)
				if err == nil || report.Applied != 0 || failure == nil ||
					failure.Code != ldapwire.ResultInvalidAttributeSyntax {
					t.Fatalf("value-enabled report=%#v error=%v", report, err)
				}

				store = openOfflineSecurityStore(t, backend)
				report, err = ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{
						Database: "1", SkipSchema: true, SkipValueValidation: true,
					},
				)
				if err != nil || report.Applied != 1 || len(report.Failures) != 0 {
					t.Fatalf("value-disabled report=%#v error=%v", report, err)
				}
				entry := readOfflineToolEntry(t, store, "uid=invalid-value,dc=example,dc=com")
				if got := string(entry.Values("uidNumber")[0]); got != "not-an-integer" {
					t.Fatalf("stored uidNumber = %q", got)
				}
			})

			t.Run("schema check controls modify RDN validation", func(t *testing.T) {
				input := "dn: " + offlineAliceDN + "\nchangetype: modify\n" +
					"replace: uid\nuid: detached-from-rdn\n"
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1"},
				)
				failure := offlineModifyFailureResult(report)
				if err == nil || report.Applied != 0 || failure == nil ||
					failure.Code != ldapwire.ResultNamingViolation {
					t.Fatalf("schema-enabled report=%#v error=%v", report, err)
				}

				store = openOfflineSecurityStore(t, backend)
				report, err = ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", SkipSchema: true},
				)
				if err != nil || report.Applied != 1 || len(report.Failures) != 0 {
					t.Fatalf("schema-disabled report=%#v error=%v", report, err)
				}
				entry := readOfflineToolEntry(t, store, offlineAliceDN)
				if got := string(entry.Values("uid")[0]); got != "detached-from-rdn" {
					t.Fatalf("stored uid = %q", got)
				}
			})

			t.Run("value syntax precedes final RDN validation", func(t *testing.T) {
				input := "dn: " + offlineAliceDN + "\nchangetype: modify\n" +
					"replace: uid\nuid: detached-from-rdn\n-\n" +
					"replace: uidNumber\nuidNumber: not-an-integer\n"
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1"},
				)
				failure := offlineModifyFailureResult(report)
				if err == nil || failure == nil ||
					failure.Code != ldapwire.ResultInvalidAttributeSyntax ||
					!strings.Contains(failure.DiagnosticMessage, "integer") {
					t.Fatalf("value-first report=%#v error=%v", report, err)
				}

				store = openOfflineSecurityStore(t, backend)
				report, err = ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", SkipValueValidation: true},
				)
				failure = offlineModifyFailureResult(report)
				if err == nil || failure == nil || failure.Code != ldapwire.ResultNamingViolation {
					t.Fatalf("schema-after-value-skip report=%#v error=%v", report, err)
				}
			})

			t.Run("add value syntax precedes backend parent validation", func(t *testing.T) {
				input := `dn: uid=invalid,ou=missing,dc=example,dc=com
changetype: add
objectClass: inetOrgPerson
objectClass: posixAccount
uid: invalid
cn: Invalid
sn: Value
uidNumber: not-an-integer
gidNumber: 1000
homeDirectory: /home/invalid
`
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1"},
				)
				failure := offlineModifyFailureResult(report)
				if err == nil || failure == nil ||
					failure.Code != ldapwire.ResultInvalidAttributeSyntax ||
					!strings.Contains(failure.DiagnosticMessage, "integer") {
					t.Fatalf("value-first add report=%#v error=%v", report, err)
				}

				store = openOfflineSecurityStore(t, backend)
				report, err = ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", SkipValueValidation: true},
				)
				if err == nil || report.Applied != 0 || len(report.Failures) != 1 ||
					!strings.Contains(report.Failures[0].Err.Error(), "parent") {
					t.Fatalf("parent-after-value-skip report=%#v error=%v", report, err)
				}
			})

			t.Run("dry run executes selected validation and rolls back", func(t *testing.T) {
				input := "dn: " + offlineAliceDN + "\nchangetype: modify\n" +
					"replace: uidNumber\nuidNumber: not-an-integer\n"
				store := openOfflineSecurityStore(t, backend)
				before := readOfflineToolEntry(t, store, offlineAliceDN)
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{
						Database: "1", DryRun: true, SkipValueValidation: true,
					},
				)
				if err != nil || report.Applied != 1 || len(report.Failures) != 0 {
					t.Fatalf("dry-run report=%#v error=%v", report, err)
				}
				after := readOfflineToolEntry(t, store, offlineAliceDN)
				if !before.Equal(after) {
					t.Fatalf("dry-run changed entry: before=%#v after=%#v", before, after)
				}
			})

			t.Run("continue retains valid records and ordered failures", func(t *testing.T) {
				input := "dn: " + offlineAliceDN + "\nchangetype: modify\n" +
					"replace: uidNumber\nuidNumber: not-an-integer\n\n" +
					"dn: " + offlineBobDN + "\nchangetype: modify\n" +
					"replace: description\ndescription: retained\n"
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store, strings.NewReader(input),
					OfflineModifyOptions{Database: "1", Continue: true},
				)
				if err == nil || report.Applied != 1 || len(report.Failures) != 1 ||
					report.Failures[0].Line != 1 {
					t.Fatalf("continue report=%#v error=%v", report, err)
				}
				entry := readOfflineToolEntry(t, store, offlineBobDN)
				if got := string(entry.Values("description")[0]); got != "retained" {
					t.Fatalf("stored description = %q", got)
				}
			})

			t.Run("continue rejects configuration database", func(t *testing.T) {
				store := openOfflineSecurityStore(t, backend)
				report, err := ApplyOfflineChanges(
					context.Background(), store,
					strings.NewReader(`dn: cn=config
changetype: modify
replace: cn
cn: config
`),
					OfflineModifyOptions{Database: "0", Continue: true},
				)
				if err == nil || report.Applied != 0 ||
					!strings.Contains(err.Error(), "does not support cn=config") {
					t.Fatalf("config continue report=%#v error=%v", report, err)
				}
			})
		})
	}
}
