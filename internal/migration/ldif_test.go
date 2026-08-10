package migration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestImportLDIFPreservesSlapcatData(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })

	input := `version: 1

dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
entryUUID: 11111111-1111-1111-1111-111111111111
entryCSN: 20260730000000.000000Z#000000#000#000000

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example
description: a long value that is
 folded across two physical lines
jpegPhoto:: AP8Q

`

	result, err := ImportLDIF(context.Background(), store, bytes.NewBufferString(input), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportLDIF(): %v", err)
	}
	if result.Entries != 2 {
		t.Fatalf("Entries = %d, want 2", result.Entries)
	}
	if len(result.NamingContexts) != 1 || result.NamingContexts[0] != "dc=example,dc=com" {
		t.Fatalf("NamingContexts = %v", result.NamingContexts)
	}

	aliceDN := mustDN(t, "uid=alice,dc=example,dc=com")
	if err := store.View(context.Background(), func(tx storage.Reader) error {
		entry, err := tx.Get(aliceDN)
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("description"), [][]byte{[]byte("a long value that isfolded across two physical lines")})
		assertValues(t, entry.Values("jpegPhoto"), [][]byte{{0x00, 0xff, 0x10}})
		return nil
	}); err != nil {
		t.Fatalf("View(): %v", err)
	}
}

func TestImportLDIFRollsBackOnDuplicate(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })

	existing := directory.Entry{
		DN:         "dc=existing,dc=com",
		Attributes: []directory.Attribute{{Description: "dc", Values: [][]byte{[]byte("existing")}}},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(existing, false)
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	input := `dn: dc=example,dc=com
dc: example

dn: dc=example,dc=com
dc: duplicate

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		bytes.NewBufferString(input),
		ImportOptions{Replace: true},
	); !errors.Is(err, storage.ErrEntryExists) {
		t.Fatalf("ImportLDIF() error = %v, want ErrEntryExists", err)
	}

	if err := store.View(context.Background(), func(tx storage.Reader) error {
		_, err := tx.Get(mustDN(t, existing.DN))
		return err
	}); err != nil {
		t.Fatalf("replace import did not roll back: %v", err)
	}
}

func TestImportLDIFPreservesOpenLDAPDynamicObjectState(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: cn=lease,dc=example,dc=com
objectClass: top
objectClass: organizationalRole
objectClass: dynamicObject
cn: lease
entryTtl: 3600
entryExpireTimestamp: 20260731140000Z
entryUUID: 10000000-0000-4000-8000-000000000001
entryCSN: 20260731130000.000000Z#000001#001#000000

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(dynamicObject): %v", err)
	}
	entryDN := mustDN(t, "cn=lease,dc=example,dc=com")
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.Get(entryDN)
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("objectClass"), [][]byte{
			[]byte("top"),
			[]byte("organizationalRole"),
			[]byte("dynamicObject"),
		})
		assertValues(t, entry.Values("entryTtl"), [][]byte{[]byte("3600")})
		assertValues(
			t,
			entry.Values("entryExpireTimestamp"),
			[][]byte{[]byte("20260731140000Z")},
		)
		return nil
	}); err != nil {
		t.Fatalf("read imported dynamicObject: %v", err)
	}

	var output bytes.Buffer
	if _, err := ExportLDIF(
		context.Background(),
		store,
		&output,
	); err != nil {
		t.Fatalf("ExportLDIF(dynamicObject): %v", err)
	}
	for _, line := range []string{
		"objectClass: dynamicObject",
		"entryTtl: 3600",
		"entryExpireTimestamp: 20260731140000Z",
	} {
		if !strings.Contains(output.String(), line) {
			t.Fatalf("exported dynamicObject has no %q:\n%s", line, output.String())
		}
	}
}

func TestImportLDIFPreservesOpenLDAPPasswordPolicyState(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com

dn: olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: {0}ppolicy
olcPPolicyDefault: cn=default,ou=policies,dc=example,dc=com
olcPPolicyHashCleartext: TRUE
olcPPolicyForwardUpdates: TRUE
olcPPolicyUseLockout: TRUE
olcPPolicyDisableWrite: FALSE
olcPPolicySendNetscapeControls: TRUE
olcPPolicyCheckModule: check_password.so

dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=policies,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: 2.5.4.35
pwdMinAge: 30
pwdMaxAge: 3600
pwdInHistory: 5
pwdCheckQuality: 2
pwdMinLength: 12
pwdMaxLength: 128
pwdExpireWarning: 300
pwdGraceAuthNLimit: 3
pwdGraceExpiry: 600
pwdLockout: TRUE
pwdLockoutDuration: 900
pwdMaxFailure: 5
pwdFailureCountInterval: 120
pwdMustChange: TRUE
pwdAllowUserChange: TRUE
pwdSafeModify: TRUE
pwdMinDelay: 1
pwdMaxDelay: 8
pwdMaxIdle: 7200
pwdMaxRecordedFailure: 10

dn: uid=alice,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example
userPassword: {SSHA}stored-password
pwdChangedTime: 20260731120000Z
pwdAccountLockedTime: 20260731123000Z
pwdFailureTime: 20260731122958.000001Z
pwdFailureTime: 20260731122959.000002Z
pwdHistory: 20260730120000Z#1.3.6.1.4.1.1466.115.121.1.40#20#{SSHA}old-password
pwdGraceUseTime: 20260731121000.000003Z
pwdReset: TRUE
pwdPolicySubentry: cn=default,ou=policies,dc=example,dc=com
pwdStartTime: 20260701000000Z
pwdEndTime: 20261231000000Z
pwdLastSuccess: 20260731110000Z
pwdAccountTmpLockoutEnd: 20260731123100Z

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(ppolicy): %v", err)
	}

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		overlay, err := reader.Get(mustDN(
			t,
			"olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config",
		))
		if err != nil {
			return err
		}
		assertValues(t, overlay.Values("olcPPolicyDefault"), [][]byte{
			[]byte("cn=default,ou=policies,dc=example,dc=com"),
		})
		assertValues(t, overlay.Values("olcPPolicyCheckModule"), [][]byte{
			[]byte("check_password.so"),
		})
		entry, err := reader.Get(mustDN(t, "uid=alice,dc=example,dc=com"))
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("pwdFailureTime"), [][]byte{
			[]byte("20260731122958.000001Z"),
			[]byte("20260731122959.000002Z"),
		})
		assertValues(t, entry.Values("pwdHistory"), [][]byte{
			[]byte("20260730120000Z#1.3.6.1.4.1.1466.115.121.1.40#20#{SSHA}old-password"),
		})
		for _, attribute := range []string{
			"pwdChangedTime",
			"pwdAccountLockedTime",
			"pwdGraceUseTime",
			"pwdReset",
			"pwdPolicySubentry",
			"pwdStartTime",
			"pwdEndTime",
			"pwdLastSuccess",
			"pwdAccountTmpLockoutEnd",
		} {
			if !entry.HasAttribute(attribute) {
				t.Fatalf("imported ppolicy entry has no %s", attribute)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read imported ppolicy state: %v", err)
	}

	var output bytes.Buffer
	if _, err := ExportLDIF(
		context.Background(),
		store,
		&output,
	); err != nil {
		t.Fatalf("ExportLDIF(ppolicy): %v", err)
	}
	for _, fragment := range []string{
		"olcOverlay: {0}ppolicy",
		"olcPPolicyDefault: cn=default,ou=policies,dc=example,dc=com",
		"olcPPolicyHashCleartext: TRUE",
		"olcPPolicyForwardUpdates: TRUE",
		"olcPPolicyUseLockout: TRUE",
		"olcPPolicyDisableWrite: FALSE",
		"olcPPolicySendNetscapeControls: TRUE",
		"olcPPolicyCheckModule: check_password.so",
		"objectClass: pwdPolicy",
		"pwdMaxRecordedFailure: 10",
		"pwdAccountLockedTime: 20260731123000Z",
		"pwdFailureTime: 20260731122958.000001Z",
		"pwdHistory: 20260730120000Z#1.3.6.1.4.1.1466.115.121.1.40#20#{SSHA}",
		"pwdGraceUseTime: 20260731121000.000003Z",
		"pwdAccountTmpLockoutEnd: 20260731123100Z",
	} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("exported ppolicy LDIF has no %q:\n%s", fragment, output.String())
		}
	}

	destination := storage.NewMemory()
	t.Cleanup(func() { _ = destination.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		destination,
		bytes.NewReader(output.Bytes()),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("re-import ppolicy LDIF: %v", err)
	}
	assertStoresEqual(t, store, destination)
}

func TestImportLDIFPreservesOpenLDAPDITContentRules(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: cn={8}content-rule,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {8}content-rule
olcAttributeTypes: {0}( 1.3.6.1.4.1.99999.20 NAME 'migrationCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcObjectClasses: {0}( 1.3.6.1.4.1.99999.21 NAME 'migrationAux' SUP top AUXILIARY MUST migrationCode )
olcDitContentRules: {0}( 2.16.840.1.113730.3.2.2 NAME 'migrationPersonRule' AUX migrationAux MUST uid NOT description )

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(DIT content rule): %v", err)
	}

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	result, err := schema.LoadOpenLDAPConfig(
		context.Background(),
		store,
		registry,
	)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.AttributeTypes != 1 ||
		result.ObjectClasses != 1 ||
		result.ContentRules != 1 {
		t.Fatalf("schema LoadResult = %#v", result)
	}
	contentRule, found := registry.DITContentRule("migrationPersonRule")
	if !found ||
		contentRule.OID != "2.16.840.1.113730.3.2.2" ||
		len(contentRule.Auxiliary) != 1 ||
		contentRule.Auxiliary[0] != "migrationAux" {
		t.Fatalf("migrationPersonRule = %#v, found %t", contentRule, found)
	}

	var output bytes.Buffer
	if _, err := ExportLDIF(
		context.Background(),
		store,
		&output,
	); err != nil {
		t.Fatalf("ExportLDIF(DIT content rule): %v", err)
	}
	for _, fragment := range []string{
		"olcAttributeTypes: {0}( 1.3.6.1.4.1.99999.20",
		"olcObjectClasses: {0}( 1.3.6.1.4.1.99999.21",
		"olcDitContentRules: {0}( 2.16.840.1.113730.3.2.2",
	} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("exported schema has no %q:\n%s", fragment, output.String())
		}
	}
}

func TestImportLDIFPreservesOpenLDAPAuthorizationRules(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: uid=alice,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Alice
authzTo: {0}dn.subtree:ou=services,dc=example,dc=com
authzTo: {1}ldap:///ou=people,dc=example,dc=com??sub?(uid=*)
authzFrom: group:cn=proxy users,ou=groups,dc=example,dc=com

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(authorization rules): %v", err)
	}

	entryDN := mustDN(t, "uid=alice,ou=people,dc=example,dc=com")
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.Get(entryDN)
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("authzTo"), [][]byte{
			[]byte("{0}dn.subtree:ou=services,dc=example,dc=com"),
			[]byte("{1}ldap:///ou=people,dc=example,dc=com??sub?(uid=*)"),
		})
		assertValues(t, entry.Values("authzFrom"), [][]byte{
			[]byte("group:cn=proxy users,ou=groups,dc=example,dc=com"),
		})
		return nil
	}); err != nil {
		t.Fatalf("read imported authorization rules: %v", err)
	}

	var output bytes.Buffer
	if _, err := ExportLDIF(context.Background(), store, &output); err != nil {
		t.Fatalf("ExportLDIF(authorization rules): %v", err)
	}
	for _, line := range []string{
		"authzTo: {0}dn.subtree:ou=services,dc=example,dc=com",
		"authzTo: {1}ldap:///ou=people,dc=example,dc=com??sub?(uid=*)",
		"authzFrom: group:cn=proxy users,ou=groups,dc=example,dc=com",
	} {
		if !strings.Contains(output.String(), line) {
			t.Fatalf(
				"exported authorization rules have no %q:\n%s",
				line,
				output.String(),
			)
		}
	}
}

func TestImportLDIFValidatesSchemaAtomically(t *testing.T) {
	t.Parallel()

	base := `dn: dc=example,dc=com
objectClass: domain
dc: example

`
	for _, test := range []struct {
		name     string
		entry    string
		fragment string
	}{
		{
			name: "undefined attribute",
			entry: `dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example
notRegistered: value

`,
			fragment: "undefined attribute type",
		},
		{
			name: "invalid integer syntax",
			entry: `dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: alice
cn: Alice
sn: Example
uidNumber: not-an-integer
gidNumber: 1000
homeDirectory: /home/alice

`,
			fragment: "value is not an integer",
		},
		{
			name: "missing required attribute",
			entry: `dn: cn=alice,dc=example,dc=com
objectClass: person
cn: alice

`,
			fragment: "requires attribute 'sn'",
		},
		{
			name: "multiple single values",
			entry: `dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: alice
cn: Alice
sn: Example
uidNumber: 1000
uidNumber: 1001
gidNumber: 1000
homeDirectory: /home/alice

`,
			fragment: "single-valued attribute has multiple values",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			_, err := ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(base+test.entry),
				ImportOptions{Replace: true},
			)
			if err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("ImportLDIF() error = %v, want fragment %q", err, test.fragment)
			}
			if err := store.View(context.Background(), func(reader storage.Reader) error {
				count := 0
				if err := reader.ForEach(func(directory.Entry) error {
					count++
					return nil
				}); err != nil {
					return err
				}
				if count != 0 {
					t.Fatalf("failed atomic import retained %d entries", count)
				}
				return nil
			}); err != nil {
				t.Fatalf("inspect rolled-back import: %v", err)
			}
		})
	}
}

func TestImportLDIFUsesImportedOpenLDAPSchema(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: cn={9}custom,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}custom
olcAttributeTypes: ( 1.3.6.1.4.1.99999.20 NAME 'customCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.21 NAME 'customPerson' SUP top STRUCTURAL MUST ( cn $ customCode ) )

dn: cn=custom,dc=example,dc=com
objectClass: customPerson
cn: custom
customCode: C-100

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(custom schema and content): %v", err)
	}

	dn := mustDN(t, "cn=custom,dc=example,dc=com")
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.Get(dn)
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("customCode"), [][]byte{[]byte("C-100")})
		assertValues(t, entry.Values("structuralObjectClass"), [][]byte{[]byte("customPerson")})
		return nil
	}); err != nil {
		t.Fatalf("read custom-schema entry: %v", err)
	}
}

func TestImportLDIFImportedModuleSyntaxHonorsValueCheckMode(t *testing.T) {
	t.Parallel()

	input := `dn: cn={9}module,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}module
olcAttributeTypes: ( 1.3.6.1.4.1.99999.500 NAME 'moduleValue' SYNTAX 1.3.6.1.4.1.99999.501 )
olcObjectClasses: ( 1.3.6.1.4.1.99999.502 NAME 'moduleEntry' SUP top STRUCTURAL MUST ( cn $ moduleValue ) )

dn: cn=module,dc=example,dc=com
objectClass: moduleEntry
cn: module
moduleValue: opaque

`
	for _, test := range []struct {
		name                string
		skipValueValidation bool
		wantError           string
	}{
		{
			name:                "default slapadd value check disabled",
			skipValueValidation: true,
		},
		{
			name:      "explicit value check enabled",
			wantError: `unsupported syntax "1.3.6.1.4.1.99999.501"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			_, err := ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(input),
				ImportOptions{
					Replace:             true,
					SkipValueValidation: test.skipValueValidation,
				},
			)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ImportLDIF(): %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ImportLDIF() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestImportLDIFAppliesSlapaddNamingAndStructuralClass(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain

`),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(missing naming value): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.Get(mustDN(t, "dc=example,dc=com"))
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("dc"), [][]byte{[]byte("example")})
		assertValues(t, entry.Values("structuralObjectClass"), [][]byte{[]byte("domain")})
		return nil
	}); err != nil {
		t.Fatalf("read prepared entry: %v", err)
	}
}

func TestImportLDIFRejectsInconsistentStructuralObjectClass(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example
structuralObjectClass: organizationalUnit

`),
		ImportOptions{Replace: true},
	)
	if err == nil || !strings.Contains(err.Error(), "objectClass values resolve to") {
		t.Fatalf("ImportLDIF() error = %v, want structuralObjectClass mismatch", err)
	}
}

func TestImportLDIFCanDisableSchemaValidation(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: uid=raw,dc=example,dc=com
notRegistered: value

`),
		ImportOptions{Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("ImportLDIF(schema disabled): %v", err)
	}
}

func TestImportLDIFSelectedDatabaseAllowsChildBeforeParent(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	input := `dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: dc=example,dc=com
objectClass: domain
dc: example

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(child before parent): %v", err)
	}
}

func TestImportLDIFSelectedDatabaseRejectsOrphansAtomically(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	initial := `dn: dc=example,dc=com
objectClass: domain
dc: example
description: retained

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(initial),
		ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("seed selected database: %v", err)
	}
	orphan := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=orphan,ou=missing,dc=example,dc=com
objectClass: inetOrgPerson
uid: orphan
cn: Orphan
sn: User

`
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(orphan),
		ImportOptions{Database: "1", Replace: true},
	)
	if err == nil || !strings.Contains(err.Error(), "parent entry") {
		t.Fatalf("ImportLDIF(orphan) error = %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		entry, err := reader.GetIn(target.partition, mustDN(t, "dc=example,dc=com"))
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("description"), [][]byte{[]byte("retained")})
		return nil
	}); err != nil {
		t.Fatalf("inspect rolled-back selected import: %v", err)
	}
}

func TestImportLDIFSelectedDatabaseRejectsDNOutsideSuffix(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=other,dc=com
objectClass: domain
dc: other

`),
		ImportOptions{Database: "1", Replace: true},
	)
	if err == nil || !strings.Contains(err.Error(), "outside the selected database suffixes") {
		t.Fatalf("ImportLDIF(outside suffix) error = %v", err)
	}
}

func TestImportLDIFRoutesUnselectedContentToConfiguredDatabase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	input := `dn: cn=config
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

dn: dc=example,dc=com
objectClass: domain
dc: example

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("ImportLDIF(mixed configuration and content): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		dn := mustDN(t, "dc=example,dc=com")
		if _, err := reader.GetIn(target.partition, dn); err != nil {
			return fmt.Errorf("configured partition: %w", err)
		}
		if _, err := reader.GetIn("", dn); !errors.Is(err, storage.ErrEntryNotFound) {
			t.Fatalf("default partition lookup error = %v, want ErrEntryNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect routed import: %v", err)
	}
}

func TestImportLDIFSelectedDatabaseRejectsMoreSpecificDatabase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(
			storage.OpenLDAPConfigPartition,
			directory.Entry{
				DN: "olcDatabase={2}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("olcDatabaseConfig")}},
					{Description: "olcDatabase", Values: [][]byte{[]byte("{2}mdb")}},
					{Description: "olcSuffix", Values: [][]byte{[]byte("ou=people,dc=example,dc=com")}},
				},
			},
			false,
		)
	}); err != nil {
		t.Fatalf("seed subordinate database: %v", err)
	}
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

`),
		ImportOptions{Database: "1", SkipSchemaValidation: true},
	)
	if err == nil || !strings.Contains(err.Error(), "belongs to OpenLDAP database \"{2}mdb\"") {
		t.Fatalf("ImportLDIF(parent database) error = %v", err)
	}
}

func TestImportLDIFSelectedGlueDoesNotCrossIntermediateDatabase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: ou=people,ou=region,dc=example,dc=com
olcSubordinate: TRUE

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: ou=region,dc=example,dc=com

dn: olcDatabase={3}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {3}mdb
olcSuffix: dc=example,dc=com

`),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("seed nested database configuration: %v", err)
	}
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: uid=alice,ou=people,ou=region,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

`),
		ImportOptions{Database: "3", SkipSchemaValidation: true},
	)
	if err == nil || !strings.Contains(err.Error(), `belongs to OpenLDAP database "{2}mdb"`) {
		t.Fatalf("ImportLDIF(root database across intermediate database) error = %v", err)
	}
}

func TestImportLDIFRejectsBackendWithoutOfflineImport(t *testing.T) {
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
		t.Fatalf("seed LDAP backend configuration: %v", err)
	}
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

`),
		ImportOptions{Database: "1", SkipSchemaValidation: true},
	)
	if err == nil || !strings.Contains(err.Error(), "does not support offline entry import") {
		t.Fatalf("ImportLDIF(LDAP backend) error = %v", err)
	}
}

func TestImportExportLDIFBackendsWithOfflineToolCallbacks(t *testing.T) {
	t.Parallel()

	for _, backend := range []string{"ldif", "wt"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			suffix := "dc=" + backend + ",dc=com"
			config := fmt.Sprintf(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}%s,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}%s
olcSuffix: %s

`, backend, backend, suffix)
			if _, err := ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(config),
				ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
			); err != nil {
				t.Fatalf("ImportLDIF(config): %v", err)
			}
			content := fmt.Sprintf(`dn: %s
objectClass: domain
dc: %s
entryCSN: 20260810120000.000000Z#000000#001#000000

`, suffix, backend)
			if _, err := ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(content),
				ImportOptions{
					Database:             "1",
					SkipSchemaValidation: true,
					UpdateContextCSN:     true,
				},
			); err != nil {
				t.Fatalf("ImportLDIF(content): %v", err)
			}
			var output bytes.Buffer
			result, err := ExportLDIFWithOptions(
				context.Background(),
				store,
				&output,
				ExportOptions{Database: "1"},
			)
			if err != nil {
				t.Fatalf("ExportLDIFWithOptions(): %v", err)
			}
			if result.Entries != 1 || !strings.Contains(
				output.String(),
				"contextCSN: 20260810120000.000000Z#000000#001#000000",
			) {
				t.Fatalf("export result = %#v\n%s", result, output.String())
			}
		})
	}
}

func TestImportLDIFNullBackendValidatesAndDiscardsEntries(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={1}null,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}null
olcSuffix: dc=discarded,dc=com

`),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("seed null backend configuration: %v", err)
	}
	result, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: uid=discarded,dc=discarded,dc=com
objectClass: inetOrgPerson
uid: discarded
cn: Discarded
sn: Entry

`),
		ImportOptions{Database: "1", SkipSchemaValidation: true},
	)
	if err != nil {
		t.Fatalf("ImportLDIF(null backend): %v", err)
	}
	if result.Entries != 1 {
		t.Fatalf("null backend Entries = %d, want 1", result.Entries)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		count := 0
		if err := reader.ForEachIn(target.partition, func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("null backend retained %d entries", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect null backend: %v", err)
	}
	_, err = ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=discarded,dc=com
objectClass: domain
dc: discarded

`),
		ImportOptions{
			Database:         "1",
			UpdateContextCSN: true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "does not support offline contextCSN updates") {
		t.Fatalf("ImportLDIF(null backend -w) error = %v", err)
	}
}

func TestImportLDIFSelectedGlueSuperiorRoutesSubordinateEntries(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
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

`),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("seed glue database configuration: %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
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

`),
		ImportOptions{
			SelectDefaultDatabase: true,
			SkipSchemaValidation:  true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(glue superior): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		child, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		parent, err := resolveDatabaseTarget(reader, "2")
		if err != nil {
			return err
		}
		if _, err := reader.GetIn(parent.partition, mustDN(t, "dc=example,dc=com")); err != nil {
			return fmt.Errorf("parent suffix partition: %w", err)
		}
		for _, rawDN := range []string{
			"ou=people,dc=example,dc=com",
			"uid=alice,ou=people,dc=example,dc=com",
		} {
			if _, err := reader.GetIn(child.partition, mustDN(t, rawDN)); err != nil {
				return fmt.Errorf("subordinate partition %s: %w", rawDN, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect glue import: %v", err)
	}
}

func TestImportLDIFSelectedGlueUsesSuperiorToolMetadataAndReplaceClearsTree(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: ou=people,dc=example,dc=com
olcRootDN: cn=child,ou=people,dc=example,dc=com
olcSubordinate: TRUE

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=parent,dc=example,dc=com

`),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("seed glue database configuration: %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
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

`),
		ImportOptions{
			SelectDefaultDatabase:         true,
			SkipSchemaValidation:          true,
			GenerateOperationalAttributes: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(glue superior metadata): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		child, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		entry, err := reader.GetIn(
			child.partition,
			mustDN(t, "uid=alice,ou=people,dc=example,dc=com"),
		)
		if err != nil {
			return err
		}
		assertValues(
			t,
			entry.Values("creatorsName"),
			[][]byte{[]byte("cn=parent,dc=example,dc=com")},
		)
		assertValues(
			t,
			entry.Values("modifiersName"),
			[][]byte{[]byte("cn=parent,dc=example,dc=com")},
		)
		return nil
	}); err != nil {
		t.Fatalf("inspect glue operational metadata: %v", err)
	}

	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

`),
		ImportOptions{
			SelectDefaultDatabase: true,
			Replace:               true,
			SkipSchemaValidation:  true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(replace glued tree): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		child, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		for _, rawDN := range []string{
			"ou=people,dc=example,dc=com",
			"uid=alice,ou=people,dc=example,dc=com",
		} {
			_, err := reader.GetIn(child.partition, mustDN(t, rawDN))
			if !errors.Is(err, storage.ErrEntryNotFound) {
				t.Fatalf("stale subordinate entry %q lookup error = %v", rawDN, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect replaced glue tree: %v", err)
	}
}

func TestImportLDIFSelectedGlueSuperiorCanDisableSubordinateRouting(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
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

`),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("seed glue database configuration: %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

`),
		ImportOptions{
			SelectDefaultDatabase:  true,
			DisableSubordinateGlue: true,
			SkipSchemaValidation:   true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(glue disabled): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		child, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		parent, err := resolveDatabaseTarget(reader, "2")
		if err != nil {
			return err
		}
		dn := mustDN(t, "ou=people,dc=example,dc=com")
		if _, err := reader.GetIn(parent.partition, dn); err != nil {
			return fmt.Errorf("parent partition: %w", err)
		}
		if _, err := reader.GetIn(child.partition, dn); !errors.Is(err, storage.ErrEntryNotFound) {
			t.Fatalf("subordinate partition lookup error = %v, want ErrEntryNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect glue-disabled import: %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(""),
		ImportOptions{SelectDefaultDatabase: true},
	); err == nil || !strings.Contains(err.Error(), "also present in superior database") {
		t.Fatalf("ImportLDIF(inconsistent glue state) error = %v", err)
	}
}

func TestResolveDatabaseTargetIgnoresConfigurationDNOutsideConfigPartition(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: [][]byte{[]byte("{1}mdb")}},
				{Description: "olcSuffix", Values: [][]byte{[]byte("dc=forged,dc=com")}},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed forged configuration DN: %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		if len(target.suffixes) != 1 || target.suffixes[0].String() != "dc=example,dc=com" {
			t.Fatalf("resolved suffixes = %v", target.suffixes)
		}
		return nil
	}); err != nil {
		t.Fatalf("resolve database target: %v", err)
	}
}

func TestImportLDIFConfigurationValidationChecksHierarchyAndObjectClass(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		input    string
		fragment string
	}{
		{
			name: "missing objectClass",
			input: `dn: cn=config
cn: config

`,
			fragment: "no objectClass attribute",
		},
		{
			name: "missing config parent",
			input: `dn: cn={1}custom,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {1}custom

`,
			fragment: "parent entry \"cn=schema,cn=config\" is missing",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			_, err := ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(test.input),
				ImportOptions{
					Database:                     "0",
					SkipSchemaValidation:         true,
					RequireObjectClass:           true,
					ValidateConfigurationEntries: true,
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("ImportLDIF(configuration validation) error = %v", err)
			}
		})
	}
}

func TestImportLDIFSchemaDisabledCanRequireObjectClass(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: uid=raw,dc=example,dc=com
notRegistered: value

`),
		ImportOptions{
			Replace:              true,
			SkipSchemaValidation: true,
			RequireObjectClass:   true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "no objectClass attribute") {
		t.Fatalf("ImportLDIF(required objectClass) error = %v", err)
	}
}

func TestImportLDIFGeneratesMissingSlapaddOperationalAttributes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	const (
		entryUUID       = "11111111-2222-4333-8444-555555555555"
		createTimestamp = "20260801010203Z"
	)
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example
entryUUID: `+entryUUID+`
createTimestamp: `+createTimestamp+`

`),
		ImportOptions{
			Database:                      "1",
			Replace:                       true,
			GenerateOperationalAttributes: true,
			CSNServerID:                   0xabc,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(generate operational attributes): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		entry, err := reader.GetIn(target.partition, mustDN(t, "dc=example,dc=com"))
		if err != nil {
			return err
		}
		assertValues(t, entry.Values("entryUUID"), [][]byte{[]byte(entryUUID)})
		assertValues(t, entry.Values("createTimestamp"), [][]byte{[]byte(createTimestamp)})
		for _, attribute := range []string{"entryCSN", "modifyTimestamp"} {
			if len(entry.Values(attribute)) != 1 {
				t.Fatalf("%s = %q", attribute, entry.Values(attribute))
			}
		}
		if csn := string(entry.Values("entryCSN")[0]); !strings.Contains(csn, "#abc#") {
			t.Fatalf("entryCSN = %q, want server ID abc", csn)
		}
		for _, attribute := range []string{"creatorsName", "modifiersName"} {
			assertValues(
				t,
				entry.Values(attribute),
				[][]byte{[]byte("cn=admin,dc=example,dc=com")},
			)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect generated operational attributes: %v", err)
	}
}

func TestImportLDIFHonorsDisabledOpenLDAPLastMod(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn := mustDN(t, "olcDatabase={1}mdb,cn=config")
		entry, err := writer.GetIn(storage.OpenLDAPConfigPartition, dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcLastMod", [][]byte{[]byte("FALSE")})
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, true)
	}); err != nil {
		t.Fatalf("disable olcLastMod: %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

`),
		ImportOptions{
			Database:                      "1",
			Replace:                       true,
			GenerateOperationalAttributes: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(olcLastMod FALSE): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		entry, err := reader.GetIn(target.partition, mustDN(t, "dc=example,dc=com"))
		if err != nil {
			return err
		}
		for _, attribute := range []string{
			"entryUUID",
			"entryCSN",
			"creatorsName",
			"createTimestamp",
			"modifiersName",
			"modifyTimestamp",
		} {
			if len(entry.Values(attribute)) != 0 {
				t.Fatalf("olcLastMod FALSE generated %s", attribute)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect olcLastMod FALSE entry: %v", err)
	}
}

func TestImportLDIFUpdatesContextCSNPerServerID(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	const (
		rootCSN   = "20260801000000.000001Z#000000#001#000000"
		firstCSN  = "20260801000010.000001Z#000000#001#000000"
		secondCSN = "20260801000008.000001Z#000000#002#000000"
	)
	input := `dn: dc=example,dc=com
objectClass: domain
dc: example
entryCSN: ` + rootCSN + `
contextCSN: 20260801000005.000001Z#000000#001#000000

dn: uid=first,dc=example,dc=com
objectClass: inetOrgPerson
uid: first
cn: First
sn: User
entryCSN: ` + firstCSN + `

dn: uid=second,dc=example,dc=com
objectClass: inetOrgPerson
uid: second
cn: Second
sn: User
entryCSN: ` + secondCSN + `

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{
			Database:         "1",
			Replace:          true,
			UpdateContextCSN: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(update contextCSN): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		entry, err := reader.GetIn(target.partition, mustDN(t, "dc=example,dc=com"))
		if err != nil {
			return err
		}
		assertValues(
			t,
			entry.Values("contextCSN"),
			[][]byte{[]byte(firstCSN), []byte(secondCSN)},
		)
		return nil
	}); err != nil {
		t.Fatalf("inspect contextCSN: %v", err)
	}
}

func TestImportLDIFUpdatesContextCSNWithDisjointExistingServerID(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	const (
		importedCSN = "20260801000010.000001Z#000000#001#000000"
		existingCSN = "20260801000008.000001Z#000000#002#000000"
	)
	input := `dn: dc=example,dc=com
objectClass: domain
dc: example
contextCSN: ` + existingCSN + `

dn: uid=first,dc=example,dc=com
objectClass: inetOrgPerson
uid: first
cn: First
sn: User
entryCSN: ` + importedCSN + `

`
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(input),
		ImportOptions{
			Database:         "1",
			Replace:          true,
			UpdateContextCSN: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(update disjoint contextCSN): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		entry, err := reader.GetIn(target.partition, mustDN(t, "dc=example,dc=com"))
		if err != nil {
			return err
		}
		assertValues(
			t,
			entry.Values("contextCSN"),
			[][]byte{[]byte(importedCSN), []byte(existingCSN)},
		)
		return nil
	}); err != nil {
		t.Fatalf("inspect disjoint contextCSN: %v", err)
	}
}

func TestImportLDIFUpdatesContextCSNInSyncProviderSubentry(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn := mustDN(t, "olcDatabase={1}mdb,cn=config")
		entry, err := writer.GetIn(storage.OpenLDAPConfigPartition, dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSyncUseSubentry", [][]byte{[]byte("TRUE")})
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, true)
	}); err != nil {
		t.Fatalf("enable sync context subentry: %v", err)
	}
	const csn = "20260801000010.000001Z#000000#001#000000"
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example
entryCSN: `+csn+`

`),
		ImportOptions{
			Database:         "1",
			Replace:          true,
			UpdateContextCSN: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(sync context subentry): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		root, err := reader.GetIn(target.partition, mustDN(t, "dc=example,dc=com"))
		if err != nil {
			return err
		}
		if values := root.Values("contextCSN"); len(values) != 0 {
			t.Fatalf("suffix root contextCSN = %q", values)
		}
		subentry, err := reader.GetIn(
			target.partition,
			mustDN(t, "cn=ldapsync,dc=example,dc=com"),
		)
		if err != nil {
			return err
		}
		assertValues(t, subentry.Values("objectClass"), [][]byte{
			[]byte("top"),
			[]byte("subentry"),
			[]byte("syncProviderSubentry"),
		})
		assertValues(t, subentry.Values("structuralObjectClass"), [][]byte{[]byte("subentry")})
		assertValues(t, subentry.Values("cn"), [][]byte{[]byte("ldapsync")})
		assertValues(t, subentry.Values("subtreeSpecification"), [][]byte{[]byte("{}")})
		assertValues(t, subentry.Values("contextCSN"), [][]byte{[]byte(csn)})
		for _, attribute := range []string{
			"entryUUID",
			"entryCSN",
			"creatorsName",
			"createTimestamp",
			"modifiersName",
			"modifyTimestamp",
		} {
			if values := subentry.Values(attribute); len(values) != 0 {
				t.Fatalf("generated sync subentry %s = %q", attribute, values)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect sync context subentry: %v", err)
	}
}

func TestImportLDIFConfigDatabaseGeneratesMetadataAndUpdatesContextCSN(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	const (
		rootCSN  = "20260801000000.000001Z#000000#001#000000"
		childCSN = "20260801000010.000001Z#000000#001#000000"
	)
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config
entryCSN: `+rootCSN+`

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
entryCSN: `+childCSN+`

`),
		ImportOptions{
			Database:                      "0",
			Replace:                       true,
			SkipSchemaValidation:          true,
			GenerateOperationalAttributes: true,
			UpdateContextCSN:              true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(config -w): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		root, err := reader.GetIn(
			storage.OpenLDAPConfigPartition,
			mustDN(t, "cn=config"),
		)
		if err != nil {
			return err
		}
		assertValues(t, root.Values("contextCSN"), [][]byte{[]byte(childCSN)})
		assertValues(t, root.Values("creatorsName"), [][]byte{[]byte("cn=config")})
		assertValues(t, root.Values("modifiersName"), [][]byte{[]byte("cn=config")})
		return nil
	}); err != nil {
		t.Fatalf("inspect config contextCSN: %v", err)
	}
}

func TestImportLDIFDryRunRollsBackAPITransaction(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=old,dc=com
objectClass: domain
dc: old

`),
		ImportOptions{Replace: true},
	); err != nil {
		t.Fatalf("seed old directory: %v", err)
	}
	validated := false
	result, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=new,dc=com
objectClass: domain
dc: new

`),
		ImportOptions{
			Replace: true,
			DryRun:  true,
			ValidateTransaction: func(reader storage.Reader) error {
				validated = true
				_, err := reader.Get(mustDN(t, "dc=new,dc=com"))
				return err
			},
		},
	)
	if err != nil {
		t.Fatalf("ImportLDIF(dry-run): %v", err)
	}
	if !validated || result.Entries != 1 ||
		len(result.NamingContexts) != 1 || result.NamingContexts[0] != "dc=new,dc=com" {
		t.Fatalf("dry-run result = %+v, validated = %t", result, validated)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		if _, err := reader.Get(mustDN(t, "dc=old,dc=com")); err != nil {
			return fmt.Errorf("old entry after dry-run: %w", err)
		}
		if _, err := reader.Get(mustDN(t, "dc=new,dc=com")); !errors.Is(err, storage.ErrEntryNotFound) {
			return fmt.Errorf("new entry after dry-run lookup error = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestImportLDIFDefaultSelectionRequiresContentDatabase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(""),
		ImportOptions{SelectDefaultDatabase: true},
	)
	if err == nil || !strings.Contains(err.Error(), "no available OpenLDAP content database") {
		t.Fatalf("ImportLDIF(default without database) error = %v", err)
	}
}

func TestImportLDIFSelectsFirstOpenLDAPDatabaseByDefault(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=first,dc=com

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: dc=second,dc=com

`),
		ImportOptions{Database: "0", Replace: true, SkipSchemaValidation: true},
	); err != nil {
		t.Fatalf("seed two databases: %v", err)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=first,dc=com
objectClass: domain
dc: first

`),
		ImportOptions{
			SelectDefaultDatabase: true,
			SkipSchemaValidation:  true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(default database): %v", err)
	}
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=second,dc=com
objectClass: domain
dc: second

`),
		ImportOptions{
			SelectDefaultDatabase: true,
			SkipSchemaValidation:  true,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "not selected database \"{1}mdb\"") {
		t.Fatalf("ImportLDIF(second database through default) error = %v", err)
	}
}

func seedImportDatabaseConfig(t *testing.T, store storage.Store) {
	t.Helper()
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=admin,dc=example,dc=com
entryUUID: 11111111-1111-4111-8111-111111111111

`),
		ImportOptions{
			Database:             "0",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		t.Fatalf("seed OpenLDAP database config: %v", err)
	}
}

func assertValues(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("values = %q, want %q", got, want)
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("values[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func mustDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
