package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPSlapaddSchemaReferenceVersion = "2.6.13"
	openLDAPSlapaddSchemaReferenceCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
)

func TestOpenLDAPReferenceSlapaddContentSchemaValidation(t *testing.T) {
	tools := requireOpenLDAPSlapaddSchemaReferenceTools(t)
	configLDIF := exportOpenLDAPSlapaddSchemaConfiguration(t, tools)

	tests := []struct {
		name       string
		args       []string
		ldif       string
		wantExit   int
		wantOutput []string
	}{
		{
			name: "valid entry",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=valid,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
uid: valid
cn: Valid User
sn: User
employeeNumber: 1000
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/valid
`,
			wantExit: 0,
		},
		{
			name: "child before parent",
			ldif: `dn: uid=unordered,ou=people,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: unordered
cn: Unordered User
sn: User

dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
`,
			wantExit: 0,
		},
		{
			name: "orphan entry",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=orphan,ou=missing,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: orphan
cn: Orphan User
sn: User
`,
			wantExit: 1,
		},
		{
			name: "entry outside suffix",
			ldif: `dn: dc=other,dc=com
objectClass: top
objectClass: domain
dc: other
`,
			wantExit: 1,
		},
		{
			name: "schema disabled still requires objectClass",
			args: []string{"-s"},
			ldif: `dn: dc=example,dc=com
dc: example
`,
			wantExit: 1,
		},
		{
			name: "unknown attribute",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=unknown,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: unknown
cn: Unknown Attribute
sn: Attribute
notRegistered: value
`,
			wantExit:   1,
			wantOutput: []string{"notRegistered", "attribute type undefined"},
		},
		{
			name: "invalid integer syntax",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=invalid-integer,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
uid: invalid-integer
cn: Invalid Integer
sn: Integer
uidNumber: not-an-integer
gidNumber: 1000
homeDirectory: /home/invalid-integer
`,
			wantExit: 0,
		},
		{
			name: "invalid integer with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=invalid-integer,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
uid: invalid-integer
cn: Invalid Integer
sn: Integer
uidNumber: not-an-integer
gidNumber: 1000
homeDirectory: /home/invalid-integer
`,
			wantExit:   1,
			wantOutput: []string{"uidNumber", "invalid per syntax"},
		},
		{
			name: "arbitrary precision integer with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=large-integer,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
uid: large-integer
cn: Large Integer
sn: Integer
uidNumber: 999999999999999999999999999999999999999999999999999999999999
gidNumber: 1000
homeDirectory: /home/large-integer
`,
			wantExit: 0,
		},
		{
			name: "integer plus sign rejected with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=plus-integer,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
uid: plus-integer
cn: Plus Integer
sn: Integer
uidNumber: +1
gidNumber: 1000
homeDirectory: /home/plus-integer
`,
			wantExit: 1,
		},
		{
			name: "integer leading zero rejected with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=zero-integer,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
uid: zero-integer
cn: Zero Integer
sn: Integer
uidNumber: 01
gidNumber: 1000
homeDirectory: /home/zero-integer
`,
			wantExit: 1,
		},
		{
			name: "negative zero rejected with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=negative-zero,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
uid: negative-zero
cn: Negative Zero
sn: Integer
uidNumber: -0
gidNumber: 1000
homeDirectory: /home/negative-zero
`,
			wantExit: 1,
		},
		{
			name: "generalized time hour form with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
createTimestamp: 2026081012Z
`,
			wantExit: 0,
		},
		{
			name: "generalized time offset form with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
createTimestamp: 20260810120000+0800
`,
			wantExit: 0,
		},
		{
			name: "valid authzMatch default normalization",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
authzTo: dn.subtree:ou=people,dc=example,dc=com
`,
			wantExit: 0,
		},
		{
			name: "invalid authzMatch default normalization",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
authzTo: not an authz rule
`,
			wantExit: 1,
		},
		{
			name: "invalid IA5 accepted without value check",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=invalid-ia5,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: invalid-ia5
cn: Invalid IA5
sn: IA5
mail:: /0BleGFtcGxlLmNvbQ==
`,
			wantExit: 0,
		},
		{
			name: "invalid IA5 rejected with value check",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=invalid-ia5,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: invalid-ia5
cn: Invalid IA5
sn: IA5
mail:: /0BleGFtcGxlLmNvbQ==
`,
			wantExit:   1,
			wantOutput: []string{"mail", "invalid per syntax"},
		},
		{
			name: "invalid directory string rejected by equality normalizer",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
description:: /w==
`,
			wantExit: 1,
		},
		{
			name: "invalid UUID rejected by equality normalizer",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
entryUUID: not-a-uuid
`,
			wantExit: 1,
		},
		{
			name: "invalid DN rejected by equality normalizer",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
modifiersName: cn=unterminated\
`,
			wantExit: 1,
		},
		{
			name: "unknown attribute option",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
description;unknown: value
`,
			wantExit: 1,
		},
		{
			name: "language attribute option",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
description;lang-en: value
`,
			wantExit: 0,
		},
		{
			name: "binary option on text syntax",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
description;binary: value
`,
			wantExit: 1,
		},
		{
			name: "certificate syntax requires binary option",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: pkiUser
dc: example
userCertificate:: AQ==
`,
			wantExit: 1,
		},
		{
			name: "certificate pair sequence with binary option",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
testCertificatePair;binary:: MAA=
`,
			wantExit: 0,
		},
		{
			name: "certificate pair rejects wrong sequence tag",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
testCertificatePair;binary:: MQA=
`,
			wantExit: 1,
		},
		{
			name: "certificate pair requires binary option",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
testCertificatePair:: MAA=
`,
			wantExit: 1,
		},
		{
			name: "supported algorithm accepts opaque binary value",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
testSupportedAlgorithm;binary:: /w==
`,
			wantExit: 0,
		},
		{
			name: "ACI Item default value check accepts opaque value",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
testACIItem;binary:: /w==
`,
			wantExit: 0,
		},
		{
			name: "ACI Item explicit value check has no validator",
			args: []string{"-o", "value-check=yes"},
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: example
testACIItem;binary:: /w==
`,
			wantExit: 1,
		},
		{
			name: "missing MUST attribute",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: cn=missing-sn,dc=example,dc=com
objectClass: top
objectClass: person
cn: missing-sn
`,
			wantExit:   1,
			wantOutput: []string{"object class 'person' requires attribute 'sn'"},
		},
		{
			name: "duplicate SINGLE-VALUE attribute",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=duplicate,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: duplicate
cn: Duplicate Employee Number
sn: Employee Number
employeeNumber: 1000
employeeNumber: 2000
`,
			wantExit:   1,
			wantOutput: []string{"attribute 'employeeNumber' cannot have multiple values"},
		},
		{
			name: "obsolete object class",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: cn=obsolete,dc=example,dc=com
objectClass: top
objectClass: obsoletePerson
cn: obsolete
sn: Person
`,
			wantExit: 1,
		},
		{
			name: "ordinary obsolete attribute type",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=obsolete,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: extensibleObject
uid: obsolete
cn: Obsolete Attribute
sn: Attribute
obsoleteCode: legacy
`,
			wantExit: 0,
		},
		{
			name: "obsolete naming attribute type",
			ldif: `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: obsoleteCode=legacy,dc=example,dc=com
objectClass: top
objectClass: domain
objectClass: extensibleObject
dc: child
obsoleteCode: legacy
`,
			wantExit:   1,
			wantOutput: []string{"naming attribute 'obsoleteCode' is obsolete"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, exitCode, _ := runOpenLDAPSlapaddSchemaValidation(
				t,
				tools,
				test.args,
				test.ldif,
			)
			if exitCode != test.wantExit {
				t.Fatalf(
					"OpenLDAP 2.6.13 slapadd exit code = %d, want %d\noutput:\n%s",
					exitCode,
					test.wantExit,
					output,
				)
			}
			for _, fragment := range test.wantOutput {
				if !strings.Contains(output, fragment) {
					t.Errorf(
						"OpenLDAP 2.6.13 slapadd output does not contain %q:\n%s",
						fragment,
						output,
					)
				}
			}
			t.Logf("slapadd exit code %d; output: %s", exitCode, strings.TrimSpace(output))

			_, implementationErr := runLDAPGoSlapaddSchemaValidation(
				t,
				configLDIF,
				test.args,
				test.ldif,
			)
			if (implementationErr == nil) != (test.wantExit == 0) {
				t.Errorf(
					"ldap-go acceptance differs from OpenLDAP: error=%v, OpenLDAP exit=%d",
					implementationErr,
					test.wantExit,
				)
			}
		})
	}
}

func TestOpenLDAPReferenceSlapaddConfigSchemaValidation(t *testing.T) {
	tools := requireOpenLDAPSlapaddSchemaReferenceTools(t)
	configuration := exportOpenLDAPSlapaddSchemaConfiguration(t, tools)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(configuration),
		migration.ImportOptions{
			Database:                     "0",
			Replace:                      true,
			SkipValueValidation:          true,
			RequireObjectClass:           true,
			ValidateConfigurationEntries: true,
			ValidateTransaction: func(reader storage.Reader) error {
				_, err := ValidateConfigurationReader(
					context.Background(),
					Config{},
					reader,
				)
				return err
			},
		},
	); err != nil {
		t.Fatalf("schema-valid slapcat -n 0 configuration import: %v", err)
	}
}

func TestOpenLDAPReferenceSlapaddOperationalAttributes(t *testing.T) {
	tools := requireOpenLDAPSlapaddSchemaReferenceTools(t)
	configLDIF := exportOpenLDAPSlapaddSchemaConfiguration(t, tools)
	input := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
entryUUID: 11111111-2222-4333-8444-555555555555
createTimestamp: 20260801010203Z
`
	args := []string{"-S", "2748"}
	output, exitCode, referenceLDIF := runOpenLDAPSlapaddSchemaValidation(
		t,
		tools,
		args,
		input,
	)
	if exitCode != 0 {
		t.Fatalf("OpenLDAP slapadd exit code = %d\n%s", exitCode, output)
	}
	implementationLDIF, err := runLDAPGoSlapaddSchemaValidation(
		t,
		configLDIF,
		args,
		input,
	)
	if err != nil {
		t.Fatalf("ldap-go slapadd: %v", err)
	}
	reference := singleLDIFEntryAttributes(t, referenceLDIF)
	implementation := singleLDIFEntryAttributes(t, implementationLDIF)
	for _, attribute := range []string{
		"entryUUID",
		"createTimestamp",
		"creatorsName",
		"modifiersName",
		"structuralObjectClass",
	} {
		if got, want := implementation[attribute], reference[attribute]; !equalStringSlices(got, want) {
			t.Errorf("%s = %q, want OpenLDAP %q", attribute, got, want)
		}
	}
	for _, attributes := range []map[string][]string{reference, implementation} {
		if values := attributes["entryCSN"]; len(values) != 1 ||
			!strings.Contains(values[0], "#abc#") {
			t.Errorf("entryCSN = %q, want generated SID abc", values)
		}
		if values := attributes["modifyTimestamp"]; len(values) != 1 {
			t.Errorf("modifyTimestamp = %q, want one generated value", values)
		}
	}
}

func TestOpenLDAPReferenceSlapaddUpdatesContextCSN(t *testing.T) {
	tools := requireOpenLDAPSlapaddSchemaReferenceTools(t)
	configLDIF := exportOpenLDAPSlapaddSchemaConfiguration(t, tools)
	input := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
entryCSN: 20260801000000.000001Z#000000#001#000000

dn: uid=first,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: first
cn: First User
sn: User
entryCSN: 20260801000010.000001Z#000000#001#000000

dn: uid=second,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: second
cn: Second User
sn: User
entryCSN: 20260801000008.000001Z#000000#002#000000
`
	args := []string{"-w"}
	output, exitCode, referenceLDIF := runOpenLDAPSlapaddSchemaValidation(
		t,
		tools,
		args,
		input,
	)
	if exitCode != 0 {
		t.Fatalf("OpenLDAP slapadd exit code = %d\n%s", exitCode, output)
	}
	implementationLDIF, err := runLDAPGoSlapaddSchemaValidation(
		t,
		configLDIF,
		args,
		input,
	)
	if err != nil {
		t.Fatalf("ldap-go slapadd: %v", err)
	}
	reference := ldifEntryAttributesByDN(t, referenceLDIF)["dc=example,dc=com"]
	implementation := ldifEntryAttributesByDN(t, implementationLDIF)["dc=example,dc=com"]
	if got, want := implementation["contextCSN"], reference["contextCSN"]; !equalStringSlices(got, want) {
		t.Fatalf("contextCSN = %q, want OpenLDAP %q", got, want)
	}
}

func TestOpenLDAPReferenceSlapaddConfigDatabaseUpdatesContextCSN(t *testing.T) {
	tools := requireOpenLDAPSlapaddSchemaReferenceTools(t)
	configLDIF := prepareOpenLDAPConfigRestoreLDIF(
		t,
		exportOpenLDAPSlapaddSchemaConfiguration(t, tools),
	)

	root := t.TempDir()
	configDir := filepath.Join(root, "slapd.d")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("create restored OpenLDAP config directory: %v", err)
	}
	inputPath := filepath.Join(root, "config.ldif")
	if err := os.WriteFile(inputPath, []byte(configLDIF), 0o600); err != nil {
		t.Fatalf("write restored OpenLDAP config LDIF: %v", err)
	}
	output, err := exec.Command(
		tools.slapadd,
		"-F", configDir,
		"-n", "0",
		"-w",
		"-l", inputPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP slapadd -n 0 -w: %v\n%s", err, output)
	}
	slapcat := openLDAPSiblingTool(t, tools.slapadd, "slapcat")
	referenceLDIF, err := exec.Command(
		slapcat,
		"-F", configDir,
		"-n", "0",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP slapcat -n 0: %v\n%s", err, referenceLDIF)
	}

	store := storage.NewMemory()
	defer store.Close()
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(configLDIF),
		migration.ImportOptions{
			Database:                      "0",
			Replace:                       true,
			SkipSchemaValidation:          true,
			GenerateOperationalAttributes: true,
			UpdateContextCSN:              true,
		},
	); err != nil {
		t.Fatalf("ldap-go slapadd -n 0 -w: %v", err)
	}
	var implementationLDIF bytes.Buffer
	if _, err := migration.ExportLDIFWithOptions(
		context.Background(),
		store,
		&implementationLDIF,
		migration.ExportOptions{Database: "0"},
	); err != nil {
		t.Fatalf("ldap-go slapcat -n 0: %v", err)
	}

	reference := ldifEntryAttributesByDN(t, string(referenceLDIF))["cn=config"]
	implementation := ldifEntryAttributesByDN(t, implementationLDIF.String())["cn=config"]
	if got, want := implementation["contextCSN"], reference["contextCSN"]; !equalStringSlices(got, want) || len(want) == 0 {
		t.Fatalf("config contextCSN = %q, want OpenLDAP %q", got, want)
	}
	for _, attribute := range []string{"creatorsName", "modifiersName"} {
		if got, want := implementation[attribute], reference[attribute]; !equalStringSlices(got, want) || len(want) != 1 {
			t.Errorf("config %s = %q, want OpenLDAP %q", attribute, got, want)
		}
	}
}

func prepareOpenLDAPConfigRestoreLDIF(t *testing.T, input string) string {
	t.Helper()
	document := &ldif.LDIF{}
	var output bytes.Buffer
	for record, err := range ldif.UnmarshalEntries(strings.NewReader(input), document) {
		if err != nil {
			t.Fatalf("parse OpenLDAP config LDIF: %v", err)
		}
		if record == nil || record.Entry == nil {
			continue
		}
		attributes := record.Entry.Attributes[:0]
		for _, attribute := range record.Entry.Attributes {
			switch strings.ToLower(attribute.Name) {
			case "contextcsn", "entryuuid", "creatorsname", "createtimestamp",
				"modifiersname", "modifytimestamp":
				continue
			}
			attributes = append(attributes, attribute)
		}
		record.Entry.Attributes = attributes
		if err := ldif.Dump(&output, 76, record.Entry); err != nil {
			t.Fatalf("render OpenLDAP config LDIF: %v", err)
		}
	}
	return output.String()
}

func TestOpenLDAPReferenceSlapaddUpdatesSyncContextSubentry(t *testing.T) {
	tools := requireOpenLDAPSlapaddSchemaReferenceTools(t)
	const directives = "sync_use_subentry yes\n"
	configLDIF := exportOpenLDAPSlapaddSchemaConfigurationWithDirectives(
		t,
		tools,
		directives,
	)
	input := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: uid=first,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
uid: first
cn: First User
sn: User
entryCSN: 20260801000010.000001Z#000000#001#000000
`
	args := []string{"-w"}
	output, exitCode, referenceLDIF := runOpenLDAPSlapaddSchemaValidationWithDirectives(
		t,
		tools,
		args,
		input,
		directives,
	)
	if exitCode != 0 {
		t.Fatalf("OpenLDAP slapadd exit code = %d\n%s", exitCode, output)
	}
	implementationLDIF, err := runLDAPGoSlapaddSchemaValidation(
		t,
		configLDIF,
		args,
		input,
	)
	if err != nil {
		t.Fatalf("ldap-go slapadd: %v", err)
	}
	const contextDN = "cn=ldapsync,dc=example,dc=com"
	referenceEntries := ldifEntryAttributesByDN(t, referenceLDIF)
	implementationEntries := ldifEntryAttributesByDN(t, implementationLDIF)
	reference, found := referenceEntries[contextDN]
	if !found {
		t.Fatalf("OpenLDAP export has no %s:\n%s", contextDN, referenceLDIF)
	}
	implementation, found := implementationEntries[contextDN]
	if !found {
		t.Fatalf("ldap-go export has no %s:\n%s", contextDN, implementationLDIF)
	}
	for _, attribute := range []string{
		"objectClass",
		"structuralObjectClass",
		"cn",
		"subtreeSpecification",
	} {
		if got, want := implementation[attribute], reference[attribute]; !equalStringSlices(got, want) {
			t.Errorf("%s = %q, want OpenLDAP %q", attribute, got, want)
		}
	}
	gotContext := implementation["contextCSN"]
	wantContext := reference["contextCSN"]
	if len(gotContext) != len(wantContext) || len(gotContext) != 2 {
		t.Fatalf("contextCSN = %q, want OpenLDAP shape %q", gotContext, wantContext)
	}
	for index := range gotContext {
		gotParts := strings.Split(gotContext[index], "#")
		wantParts := strings.Split(wantContext[index], "#")
		if len(gotParts) != 4 || len(wantParts) != 4 || gotParts[2] != wantParts[2] {
			t.Fatalf("contextCSN[%d] = %q, want OpenLDAP SID shape %q", index, gotContext[index], wantContext[index])
		}
		if gotParts[2] != "000" && gotContext[index] != wantContext[index] {
			t.Errorf("contextCSN[%d] = %q, want %q", index, gotContext[index], wantContext[index])
		}
	}
	for _, attribute := range []string{
		"entryUUID",
		"entryCSN",
		"creatorsName",
		"createTimestamp",
		"modifiersName",
		"modifyTimestamp",
	} {
		if got, want := implementation[attribute], reference[attribute]; !equalStringSlices(got, want) {
			t.Errorf("%s = %q, want OpenLDAP %q", attribute, got, want)
		}
	}
	for name, entries := range map[string]map[string]map[string][]string{
		"OpenLDAP": referenceEntries,
		"ldap-go":  implementationEntries,
	} {
		if values := entries["dc=example,dc=com"]["contextCSN"]; len(values) != 0 {
			t.Errorf("%s suffix root contextCSN = %q", name, values)
		}
	}
}

func singleLDIFEntryAttributes(t *testing.T, input string) map[string][]string {
	t.Helper()
	entries := ldifEntryAttributesByDN(t, input)
	if len(entries) != 1 {
		t.Fatalf("LDIF contains %d entries, want 1\n%s", len(entries), input)
	}
	for _, attributes := range entries {
		return attributes
	}
	return nil
}

func ldifEntryAttributesByDN(
	t *testing.T,
	input string,
) map[string]map[string][]string {
	t.Helper()
	document := &ldif.LDIF{}
	entries := make(map[string]map[string][]string)
	for record, err := range ldif.UnmarshalEntries(strings.NewReader(input), document) {
		if err != nil {
			t.Fatalf("parse LDIF: %v\n%s", err, input)
		}
		if record == nil || record.Entry == nil {
			continue
		}
		attributes := make(map[string][]string)
		for _, attribute := range record.Entry.Attributes {
			attributes[attribute.Name] = append([]string(nil), attribute.Values...)
		}
		entries[record.Entry.DN] = attributes
	}
	return entries
}

func equalStringSlices(left, right []string) bool {
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

func exportOpenLDAPSlapaddSchemaConfiguration(
	t *testing.T,
	tools openLDAPReferenceTools,
) string {
	return exportOpenLDAPSlapaddSchemaConfigurationWithDirectives(t, tools, "")
}

func exportOpenLDAPSlapaddSchemaConfigurationWithDirectives(
	t *testing.T,
	tools openLDAPReferenceTools,
	directives string,
) string {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP database directory: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	configDir := filepath.Join(root, "slapd.d")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP configuration directory: %v", err)
	}
	if err := os.WriteFile(
		configPath,
		[]byte(openLDAPSlapaddSchemaConfigWithDirectives(
			tools,
			databaseDir,
			directives,
		)),
		0o600,
	); err != nil {
		t.Fatalf("write OpenLDAP slapd.conf: %v", err)
	}
	seedPath := filepath.Join(root, "seed.ldif")
	if err := os.WriteFile(seedPath, []byte(`dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
`), 0o600); err != nil {
		t.Fatalf("write OpenLDAP seed LDIF: %v", err)
	}
	if output, err := exec.Command(
		tools.slapadd,
		"-f", configPath,
		"-l", seedPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("initialize OpenLDAP database: %v\n%s", err, output)
	}
	slaptest := openLDAPSiblingTool(t, tools.slapadd, "slaptest")
	if output, err := exec.Command(
		slaptest,
		"-f", configPath,
		"-F", configDir,
	).CombinedOutput(); err != nil {
		t.Fatalf("convert OpenLDAP configuration: %v\n%s", err, output)
	}
	slapcat := openLDAPSiblingTool(t, tools.slapadd, "slapcat")
	output, err := exec.Command(slapcat, "-F", configDir, "-n", "0").CombinedOutput()
	if err != nil {
		t.Fatalf("export OpenLDAP configuration: %v\n%s", err, output)
	}
	return string(output)
}

func openLDAPSiblingTool(t *testing.T, primary, name string) string {
	t.Helper()
	candidate := filepath.Join(filepath.Dir(primary), name)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	t.Skipf("OpenLDAP %s is not installed", name)
	return ""
}

func runLDAPGoSlapaddSchemaValidation(
	t *testing.T,
	configLDIF string,
	args []string,
	contentLDIF string,
) (string, error) {
	t.Helper()
	store := storage.NewMemory()
	defer store.Close()
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(configLDIF),
		migration.ImportOptions{
			Database:             "0",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		t.Fatalf("import OpenLDAP configuration into ldap-go: %v", err)
	}
	valueCheck := false
	schemaCheck := true
	updateContextCSN := false
	var serverID uint16
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-S" {
			parsed, err := strconv.ParseUint(args[index+1], 10, 12)
			if err != nil {
				t.Fatalf("parse test server ID: %v", err)
			}
			serverID = uint16(parsed)
			continue
		}
		if args[index] != "-o" {
			continue
		}
		switch {
		case strings.EqualFold(args[index+1], "value-check=yes"):
			valueCheck = true
		case strings.EqualFold(args[index+1], "schema-check=no"):
			schemaCheck = false
		}
	}
	for _, argument := range args {
		if argument == "-s" {
			schemaCheck = false
		}
		if argument == "-w" {
			updateContextCSN = true
		}
	}
	_, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(contentLDIF),
		migration.ImportOptions{
			Database:                      "1",
			Replace:                       true,
			SkipSchemaValidation:          !schemaCheck,
			SkipValueValidation:           !valueCheck,
			RequireObjectClass:            true,
			GenerateOperationalAttributes: true,
			CSNServerID:                   serverID,
			UpdateContextCSN:              updateContextCSN,
		},
	)
	if err != nil {
		return "", err
	}
	var output bytes.Buffer
	if _, err := migration.ExportLDIFWithOptions(
		context.Background(),
		store,
		&output,
		migration.ExportOptions{Database: "1"},
	); err != nil {
		return "", err
	}
	return output.String(), nil
}

func requireOpenLDAPSlapaddSchemaReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPSlapaddSchemaReferenceVersion {
		t.Fatalf(
			"OPENLDAP_ACTUAL_VERSION = %q, want %q",
			got,
			openLDAPSlapaddSchemaReferenceVersion,
		)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPSlapaddSchemaReferenceCommit {
		t.Fatalf(
			"OPENLDAP_COMMIT = %q, want %q",
			got,
			openLDAPSlapaddSchemaReferenceCommit,
		)
	}
	return tools
}

func openLDAPSlapaddSchemaConfigWithDirectives(
	tools openLDAPReferenceTools,
	databaseDir string,
	directives string,
) string {
	return fmt.Sprintf(
		`include %s
include %s
include %s
include %s

attributetype ( 1.3.6.1.4.1.99999.90 NAME 'obsoleteCode' OBSOLETE EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectclass ( 1.3.6.1.4.1.99999.91 NAME 'obsoletePerson' OBSOLETE SUP top STRUCTURAL MAY obsoleteCode )
attributetype ( 1.3.6.1.4.1.99999.92 NAME 'testCertificatePair' SYNTAX 1.3.6.1.4.1.1466.115.121.1.10 )
attributetype ( 1.3.6.1.4.1.99999.93 NAME 'testSupportedAlgorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.49 )
attributetype ( 1.3.6.1.4.1.99999.94 NAME 'testACIItem' SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
%s
directory %s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(tools.schemaDir, "nis.schema"),
		directives,
		databaseDir,
	)
}

func runOpenLDAPSlapaddSchemaValidation(
	t *testing.T,
	tools openLDAPReferenceTools,
	args []string,
	ldif string,
) (string, int, string) {
	return runOpenLDAPSlapaddSchemaValidationWithDirectives(
		t,
		tools,
		args,
		ldif,
		"",
	)
}

func runOpenLDAPSlapaddSchemaValidationWithDirectives(
	t *testing.T,
	tools openLDAPReferenceTools,
	args []string,
	ldif string,
	directives string,
) (string, int, string) {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP database directory: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	dataPath := filepath.Join(root, "content.ldif")
	config := openLDAPSlapaddSchemaConfigWithDirectives(tools, databaseDir, directives)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP slapd.conf: %v", err)
	}
	if err := os.WriteFile(dataPath, []byte(ldif), 0o600); err != nil {
		t.Fatalf("write OpenLDAP content LDIF: %v", err)
	}

	commandArgs := append([]string(nil), args...)
	commandArgs = append(commandArgs, "-f", configPath, "-l", dataPath)
	output, err := exec.Command(tools.slapadd, commandArgs...).CombinedOutput()
	if err == nil {
		slapcat := openLDAPSiblingTool(t, tools.slapadd, "slapcat")
		exported, exportErr := exec.Command(
			slapcat,
			"-f", configPath,
			"-n", "1",
		).CombinedOutput()
		if exportErr != nil {
			t.Fatalf("export OpenLDAP slapadd database: %v\n%s", exportErr, exported)
		}
		return string(output), 0, string(exported)
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run OpenLDAP slapadd: %v\n%s", err, output)
	}
	return string(output), exitError.ExitCode(), ""
}
