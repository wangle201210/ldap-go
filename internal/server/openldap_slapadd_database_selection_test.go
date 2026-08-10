package server

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	openLDAPDatabaseSelectionReferenceVersion = "2.6.13"
	openLDAPDatabaseSelectionReferenceCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
)

func TestOpenLDAPReferenceSlapaddSlapcatDatabaseSelection(t *testing.T) {
	tools := requireOpenLDAPDatabaseSelectionReferenceTools(t)
	ldapGo := buildLDAPGoDatabaseSelectionTool(t)

	t.Run("default skips monitor and subordinate in configuration order", func(t *testing.T) {
		fixture := newOpenLDAPDatabaseSelectionFixture(t, tools, false)
		ldapGoDatabase := fixture.seedLDAPGo(t, ldapGo)

		otherLDIF := `dn: dc=other,dc=com
objectClass: top
objectClass: domain
dc: other
`
		fixture.runOpenLDAPSlapadd(t, []string{"-n", "4"}, otherLDIF)
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase, "-n", "4"},
			otherLDIF,
		)

		defaultLDIF := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
`
		fixture.runOpenLDAPSlapadd(t, nil, defaultLDIF)
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase},
			defaultLDIF,
		)

		reference := fixture.runOpenLDAPSlapcat(t, nil)
		implementation := runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapcat", "-db", ldapGoDatabase},
			"",
		)
		assertOpenLDAPDatabaseSelectionDNs(
			t,
			"default slapcat",
			implementation,
			reference,
			[]string{"dc=example,dc=com"},
		)
	})

	t.Run("base selects the most specific legal suffix", func(t *testing.T) {
		fixture := newOpenLDAPDatabaseSelectionFixture(t, tools, false)
		ldapGoDatabase := fixture.seedLDAPGo(t, ldapGo)
		childLDIF := `dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: cn=alice,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
cn: Alice
sn: Example
`
		base := "cn=alice,ou=people,dc=example,dc=com"
		fixture.runOpenLDAPSlapadd(t, []string{"-b", base}, childLDIF)
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase, "-b", base},
			childLDIF,
		)

		reference := fixture.runOpenLDAPSlapcat(t, []string{"-b", base})
		implementation := runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapcat", "-db", ldapGoDatabase, "-b", base},
			"",
		)
		assertOpenLDAPDatabaseSelectionDNs(
			t,
			"slapcat -b",
			implementation,
			reference,
			[]string{
				"ou=people,dc=example,dc=com",
				"cn=alice,ou=people,dc=example,dc=com",
			},
		)
	})

	t.Run("glue routes subordinate entries to the physical child database", func(t *testing.T) {
		fixture := newOpenLDAPDatabaseSelectionFixture(t, tools, false)
		ldapGoDatabase := fixture.seedLDAPGo(t, ldapGo)
		contentLDIF := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: cn=alice,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
cn: Alice
sn: Example
`
		fixture.runOpenLDAPSlapadd(t, nil, contentLDIF)
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase},
			contentLDIF,
		)

		for _, database := range []struct {
			name string
			num  string
			want []string
		}{
			{
				name: "subordinate",
				num:  "2",
				want: []string{
					"ou=people,dc=example,dc=com",
					"cn=alice,ou=people,dc=example,dc=com",
				},
			},
			{
				name: "superior",
				num:  "3",
				want: []string{"dc=example,dc=com"},
			},
		} {
			t.Run(database.name, func(t *testing.T) {
				// -g exposes OpenLDAP's physical MDB instead of the glue view.
				reference := fixture.runOpenLDAPSlapcat(
					t,
					[]string{"-g", "-n", database.num},
				)
				implementation := runLDAPGoDatabaseSelectionCommand(
					t,
					ldapGo,
					[]string{
						"slapcat", "-db", ldapGoDatabase,
						"-g", "-n", database.num,
					},
					"",
				)
				assertOpenLDAPDatabaseSelectionDNs(
					t,
					database.name+" physical database",
					implementation,
					reference,
					database.want,
				)
			})
		}

		allDNs := []string{
			"dc=example,dc=com",
			"ou=people,dc=example,dc=com",
			"cn=alice,ou=people,dc=example,dc=com",
		}
		assertOpenLDAPDatabaseSelectionDNs(
			t,
			"default glue slapcat",
			runLDAPGoDatabaseSelectionCommand(
				t,
				ldapGo,
				[]string{"slapcat", "-db", ldapGoDatabase},
				"",
			),
			fixture.runOpenLDAPSlapcat(t, nil),
			allDNs,
		)
		assertOpenLDAPDatabaseSelectionDNs(
			t,
			"slapcat -g superior",
			runLDAPGoDatabaseSelectionCommand(
				t,
				ldapGo,
				[]string{"slapcat", "-db", ldapGoDatabase, "-g"},
				"",
			),
			fixture.runOpenLDAPSlapcat(t, []string{"-g"}),
			[]string{"dc=example,dc=com"},
		)

		referenceEntries := ldifEntryAttributesByDN(
			t,
			fixture.runOpenLDAPSlapcat(t, []string{"-g", "-n", "2"}),
		)
		implementationEntries := ldifEntryAttributesByDN(
			t,
			runLDAPGoDatabaseSelectionCommand(
				t,
				ldapGo,
				[]string{"slapcat", "-db", ldapGoDatabase, "-g", "-n", "2"},
				"",
			),
		)
		aliceDN := "cn=alice,ou=people,dc=example,dc=com"
		for _, attribute := range []string{"creatorsName", "modifiersName"} {
			got := implementationEntries[aliceDN][attribute]
			want := referenceEntries[aliceDN][attribute]
			if !equalStringSlices(got, want) {
				t.Errorf("glued Alice %s = %q, want OpenLDAP %q", attribute, got, want)
			}
		}
	})

	t.Run("disable glue keeps subordinate DNs in the superior database", func(t *testing.T) {
		fixture := newOpenLDAPDatabaseSelectionFixture(t, tools, false)
		ldapGoDatabase := fixture.seedLDAPGo(t, ldapGo)
		contentLDIF := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: cn=alice,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
cn: Alice
sn: Example
`
		// Ensure an empty physical child MDB exists so slapcat -g can inspect it.
		fixture.runOpenLDAPSlapadd(t, []string{"-g", "-n", "2"}, "")
		fixture.runOpenLDAPSlapadd(t, []string{"-g"}, contentLDIF)
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase, "-g"},
			contentLDIF,
		)

		allDNs := []string{
			"dc=example,dc=com",
			"ou=people,dc=example,dc=com",
			"cn=alice,ou=people,dc=example,dc=com",
		}
		for _, database := range []struct {
			name string
			num  string
			want []string
		}{
			{name: "subordinate", num: "2", want: nil},
			{name: "superior", num: "3", want: allDNs},
		} {
			t.Run(database.name, func(t *testing.T) {
				assertOpenLDAPDatabaseSelectionDNs(
					t,
					"slapadd -g "+database.name+" physical database",
					runLDAPGoDatabaseSelectionCommand(
						t,
						ldapGo,
						[]string{
							"slapcat", "-db", ldapGoDatabase,
							"-g", "-n", database.num,
						},
						"",
					),
					fixture.runOpenLDAPSlapcat(
						t,
						[]string{"-g", "-n", database.num},
					),
					database.want,
				)
			})
		}

		t.Run("default slapcat rejects duplicate glue suffix entry", func(t *testing.T) {
			_, referenceError, referenceExit := fixture.runOpenLDAPSlapcatOutcome(t, nil)
			_, implementationError, implementationExit :=
				runOpenLDAPDatabaseSelectionCommand(
					t,
					ldapGo,
					[]string{"slapcat", "-db", ldapGoDatabase},
					"",
				)
			if referenceExit == 0 || implementationExit == 0 {
				t.Fatalf(
					"default slapcat exit codes: OpenLDAP=%d ldap-go=%d",
					referenceExit,
					implementationExit,
				)
			}
			for name, output := range map[string]string{
				"OpenLDAP": referenceError,
				"ldap-go":  implementationError,
			} {
				for _, fragment := range []string{
					"subordinate database suffix entry DN",
					"also present in superior database",
				} {
					if !strings.Contains(output, fragment) {
						t.Errorf("%s default slapcat error lacks %q:\n%s", name, fragment, output)
					}
				}
			}
		})

		t.Run("slapcat -g exports the superior physical database", func(t *testing.T) {
			assertOpenLDAPDatabaseSelectionDNs(
				t,
				"slapadd -g slapcat -g",
				runLDAPGoDatabaseSelectionCommand(
					t,
					ldapGo,
					[]string{"slapcat", "-db", ldapGoDatabase, "-g"},
					"",
				),
				fixture.runOpenLDAPSlapcat(t, []string{"-g"}),
				allDNs,
			)
		})
	})

	t.Run("base ignores hidden and disabled suffixes", func(t *testing.T) {
		fixture := newOpenLDAPDatabaseSelectionFixture(t, tools, true)
		ldapGoDatabase := fixture.seedLDAPGo(t, ldapGo)

		parentLDIF := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
`
		fixture.runOpenLDAPSlapadd(t, []string{"-n", "3"}, parentLDIF)
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase, "-n", "3"},
			parentLDIF,
		)

		for _, entry := range []struct {
			base string
			ldif string
		}{
			{
				base: "ou=hidden,dc=example,dc=com",
				ldif: `dn: ou=hidden,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: hidden
`,
			},
			{
				base: "ou=disabled,dc=example,dc=com",
				ldif: `dn: ou=disabled,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: disabled
`,
			},
		} {
			fixture.runOpenLDAPSlapadd(t, []string{"-b", entry.base}, entry.ldif)
			runLDAPGoDatabaseSelectionCommand(
				t,
				ldapGo,
				[]string{"slapadd", "-db", ldapGoDatabase, "-b", entry.base},
				entry.ldif,
			)
		}

		reference := fixture.runOpenLDAPSlapcat(
			t,
			[]string{"-b", "ou=hidden,dc=example,dc=com"},
		)
		implementation := runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{
				"slapcat", "-db", ldapGoDatabase,
				"-b", "ou=hidden,dc=example,dc=com",
			},
			"",
		)
		assertOpenLDAPDatabaseSelectionDNs(
			t,
			"hidden and disabled -b fallback",
			implementation,
			reference,
			[]string{
				"dc=example,dc=com",
				"ou=disabled,dc=example,dc=com",
				"ou=hidden,dc=example,dc=com",
			},
		)
	})
}

func TestOpenLDAPReferenceOfflineBackendToolCallbacks(t *testing.T) {
	tools := requireOpenLDAPDatabaseSelectionReferenceTools(t)
	ldapGo := buildLDAPGoDatabaseSelectionTool(t)

	t.Run("ldif backend imports and exports", func(t *testing.T) {
		root := t.TempDir()
		backendDir := filepath.Join(root, "ldif")
		if err := os.Mkdir(backendDir, 0o700); err != nil {
			t.Fatalf("create LDIF backend directory: %v", err)
		}
		configPath := filepath.Join(root, "slapd.conf")
		config := fmt.Sprintf(`include %s
include %s

database ldif
suffix "dc=example,dc=com"
directory %s
`,
			filepath.Join(tools.schemaDir, "core.schema"),
			filepath.Join(tools.schemaDir, "cosine.schema"),
			backendDir,
		)
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			t.Fatalf("write back-ldif configuration: %v", err)
		}
		content := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: cn=alice,dc=example,dc=com
objectClass: top
objectClass: person
cn: Alice
sn: Example
`
		stdout, stderr, exitCode := runOpenLDAPDatabaseSelectionCommand(
			t,
			tools.slapadd,
			[]string{"-f", configPath},
			content,
		)
		if exitCode != 0 {
			t.Fatalf("OpenLDAP back-ldif slapadd exit=%d\nstdout:\n%s\nstderr:\n%s", exitCode, stdout, stderr)
		}
		slapcat := openLDAPDatabaseSelectionSiblingTool(t, tools.slapadd, "slapcat")
		reference, stderr, exitCode := runOpenLDAPDatabaseSelectionCommand(
			t,
			slapcat,
			[]string{"-f", configPath},
			"",
		)
		if exitCode != 0 {
			t.Fatalf("OpenLDAP back-ldif slapcat exit=%d\nstderr:\n%s", exitCode, stderr)
		}

		ldapGoDatabase := filepath.Join(t.TempDir(), "ldap-go.db")
		configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}ldif,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}ldif
olcSuffix: dc=example,dc=com
`
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase, "-n", "0", "-s"},
			configLDIF,
		)
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase},
			content,
		)
		implementation := runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapcat", "-db", ldapGoDatabase},
			"",
		)
		assertOpenLDAPDatabaseSelectionDNs(
			t,
			"back-ldif slapadd/slapcat",
			implementation,
			reference,
			[]string{"dc=example,dc=com", "cn=alice,dc=example,dc=com"},
		)
	})

	t.Run("ldap backend rejects offline export", func(t *testing.T) {
		root := t.TempDir()
		configPath := filepath.Join(root, "slapd.conf")
		config := fmt.Sprintf(`include %s

database ldap
suffix "dc=example,dc=com"
uri "ldap://127.0.0.1:1"
`, filepath.Join(tools.schemaDir, "core.schema"))
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			t.Fatalf("write back-ldap configuration: %v", err)
		}
		slapcat := openLDAPDatabaseSelectionSiblingTool(t, tools.slapadd, "slapcat")
		_, referenceError, referenceExit := runOpenLDAPDatabaseSelectionCommand(
			t,
			slapcat,
			[]string{"-f", configPath},
			"",
		)

		ldapGoDatabase := filepath.Join(t.TempDir(), "ldap-go.db")
		configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}ldap,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}ldap
olcSuffix: dc=example,dc=com
olcDbURI: ldap://127.0.0.1:1
`
		runLDAPGoDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapadd", "-db", ldapGoDatabase, "-n", "0", "-s"},
			configLDIF,
		)
		_, implementationError, implementationExit := runOpenLDAPDatabaseSelectionCommand(
			t,
			ldapGo,
			[]string{"slapcat", "-db", ldapGoDatabase, "-n", "1"},
			"",
		)
		if referenceExit == 0 || implementationExit == 0 {
			t.Fatalf(
				"back-ldap slapcat exit codes: OpenLDAP=%d ldap-go=%d\nOpenLDAP: %s\nldap-go: %s",
				referenceExit,
				implementationExit,
				referenceError,
				implementationError,
			)
		}
		if !strings.Contains(implementationError, "does not support offline entry export") {
			t.Fatalf("ldap-go back-ldap slapcat error:\n%s", implementationError)
		}
	})
}

type openLDAPDatabaseSelectionFixture struct {
	tools      openLDAPReferenceTools
	configPath string
	configLDIF string
}

func newOpenLDAPDatabaseSelectionFixture(
	t *testing.T,
	tools openLDAPReferenceTools,
	hiddenAndDisabled bool,
) openLDAPDatabaseSelectionFixture {
	t.Helper()
	root := t.TempDir()
	databaseRoot := filepath.Join(root, "databases")
	if err := os.Mkdir(databaseRoot, 0o700); err != nil {
		t.Fatalf("create OpenLDAP database root: %v", err)
	}
	databaseDir := func(name string) string {
		path := filepath.Join(databaseRoot, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create OpenLDAP %s database: %v", name, err)
		}
		return path
	}

	var config string
	var configLDIF string
	if hiddenAndDisabled {
		config = fmt.Sprintf(`include %s
include %s

database mdb
suffix "ou=hidden,dc=example,dc=com"
hidden on
maxsize 1073741824
directory %s

database mdb
suffix "ou=disabled,dc=example,dc=com"
disabled on
maxsize 1073741824
directory %s

database mdb
suffix "dc=example,dc=com"
maxsize 1073741824
directory %s
`,
			filepath.Join(tools.schemaDir, "core.schema"),
			filepath.Join(tools.schemaDir, "cosine.schema"),
			databaseDir("hidden"),
			databaseDir("disabled"),
			databaseDir("visible"),
		)
		configLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: ou=hidden,dc=example,dc=com
olcHidden: TRUE

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: ou=disabled,dc=example,dc=com
olcDisabled: TRUE

dn: olcDatabase={3}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {3}mdb
olcSuffix: dc=example,dc=com
`
	} else {
		config = fmt.Sprintf(`include %s
include %s

database monitor

database mdb
suffix "ou=people,dc=example,dc=com"
rootdn "cn=child,ou=people,dc=example,dc=com"
subordinate
maxsize 1073741824
directory %s

database mdb
suffix "dc=example,dc=com"
rootdn "cn=parent,dc=example,dc=com"
maxsize 1073741824
directory %s

database mdb
suffix "dc=other,dc=com"
maxsize 1073741824
directory %s
`,
			filepath.Join(tools.schemaDir, "core.schema"),
			filepath.Join(tools.schemaDir, "cosine.schema"),
			databaseDir("people"),
			databaseDir("example"),
			databaseDir("other"),
		)
		configLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}monitor,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}monitor

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: ou=people,dc=example,dc=com
olcRootDN: cn=child,ou=people,dc=example,dc=com
olcSubordinate: TRUE

dn: olcDatabase={3}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {3}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=parent,dc=example,dc=com

dn: olcDatabase={4}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {4}mdb
olcSuffix: dc=other,dc=com
`
	}

	configPath := filepath.Join(root, "slapd.conf")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP database-selection configuration: %v", err)
	}
	return openLDAPDatabaseSelectionFixture{
		tools:      tools,
		configPath: configPath,
		configLDIF: configLDIF,
	}
}

func (fixture openLDAPDatabaseSelectionFixture) seedLDAPGo(
	t *testing.T,
	ldapGo string,
) string {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "ldap-go.db")
	runLDAPGoDatabaseSelectionCommand(
		t,
		ldapGo,
		[]string{"slapadd", "-db", databasePath, "-n", "0", "-s"},
		fixture.configLDIF,
	)
	return databasePath
}

func (fixture openLDAPDatabaseSelectionFixture) runOpenLDAPSlapadd(
	t *testing.T,
	args []string,
	input string,
) {
	t.Helper()
	commandArgs := append([]string{"-f", fixture.configPath}, args...)
	stdout, stderr, exitCode := runOpenLDAPDatabaseSelectionCommand(
		t,
		fixture.tools.slapadd,
		commandArgs,
		input,
	)
	if exitCode != 0 {
		t.Fatalf(
			"OpenLDAP slapadd %v exit=%d\nstdout:\n%s\nstderr:\n%s",
			args,
			exitCode,
			stdout,
			stderr,
		)
	}
}

func (fixture openLDAPDatabaseSelectionFixture) runOpenLDAPSlapcat(
	t *testing.T,
	args []string,
) string {
	t.Helper()
	stdout, stderr, exitCode := fixture.runOpenLDAPSlapcatOutcome(t, args)
	if exitCode != 0 {
		t.Fatalf(
			"OpenLDAP slapcat %v exit=%d\nstdout:\n%s\nstderr:\n%s",
			args,
			exitCode,
			stdout,
			stderr,
		)
	}
	return stdout
}

func (fixture openLDAPDatabaseSelectionFixture) runOpenLDAPSlapcatOutcome(
	t *testing.T,
	args []string,
) (string, string, int) {
	t.Helper()
	slapcat := openLDAPDatabaseSelectionSiblingTool(t, fixture.tools.slapadd, "slapcat")
	commandArgs := append([]string{"-f", fixture.configPath}, args...)
	stdout, stderr, exitCode := runOpenLDAPDatabaseSelectionCommand(
		t,
		slapcat,
		commandArgs,
		"",
	)
	return stdout, stderr, exitCode
}

func buildLDAPGoDatabaseSelectionTool(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get test working directory: %v", err)
	}
	repositoryRoot := filepath.Clean(filepath.Join(workingDirectory, "..", ".."))
	binary := filepath.Join(t.TempDir(), "ldap-go")
	command := exec.Command("go", "build", "-o", binary, "./cmd/ldap-go")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build ldap-go database-selection test tool: %v\n%s", err, output)
	}
	return binary
}

func runLDAPGoDatabaseSelectionCommand(
	t *testing.T,
	binary string,
	args []string,
	input string,
) string {
	t.Helper()
	stdout, stderr, exitCode := runOpenLDAPDatabaseSelectionCommand(
		t,
		binary,
		args,
		input,
	)
	if exitCode != 0 {
		t.Fatalf(
			"ldap-go %v exit=%d\nstdout:\n%s\nstderr:\n%s",
			args,
			exitCode,
			stdout,
			stderr,
		)
	}
	return stdout
}

func runOpenLDAPDatabaseSelectionCommand(
	t *testing.T,
	binary string,
	args []string,
	input string,
) (string, string, int) {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run %s: %v", binary, err)
	}
	return stdout.String(), stderr.String(), exitError.ExitCode()
}

func assertOpenLDAPDatabaseSelectionDNs(
	t *testing.T,
	operation string,
	implementationLDIF string,
	referenceLDIF string,
	want []string,
) {
	t.Helper()
	implementation := openLDAPDatabaseSelectionDNs(t, implementationLDIF)
	reference := openLDAPDatabaseSelectionDNs(t, referenceLDIF)
	expected := openLDAPDatabaseSelectionDNKeys(t, want)
	if !equalOpenLDAPDatabaseSelectionStrings(reference, expected) {
		t.Fatalf("OpenLDAP %s DNs = %q, want %q", operation, reference, expected)
	}
	if !equalOpenLDAPDatabaseSelectionStrings(implementation, reference) {
		t.Fatalf(
			"ldap-go %s DNs = %q, want OpenLDAP 2.6.13 %q",
			operation,
			implementation,
			reference,
		)
	}
}

func openLDAPDatabaseSelectionDNs(t *testing.T, input string) []string {
	t.Helper()
	document := &ldif.LDIF{}
	var result []string
	for record, err := range ldif.UnmarshalEntries(strings.NewReader(input), document) {
		if err != nil {
			t.Fatalf("parse database-selection LDIF: %v\n%s", err, input)
		}
		if record == nil || record.Entry == nil {
			continue
		}
		dn, err := directory.ParseDN(record.Entry.DN)
		if err != nil {
			t.Fatalf("parse database-selection DN %q: %v", record.Entry.DN, err)
		}
		result = append(result, dn.Key())
	}
	sort.Strings(result)
	return result
}

func openLDAPDatabaseSelectionDNKeys(t *testing.T, rawDNs []string) []string {
	t.Helper()
	result := make([]string, 0, len(rawDNs))
	for _, rawDN := range rawDNs {
		dn, err := directory.ParseDN(rawDN)
		if err != nil {
			t.Fatalf("parse expected database-selection DN %q: %v", rawDN, err)
		}
		result = append(result, dn.Key())
	}
	sort.Strings(result)
	return result
}

func equalOpenLDAPDatabaseSelectionStrings(left, right []string) bool {
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

func requireOpenLDAPDatabaseSelectionReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPDatabaseSelectionReferenceVersion {
		t.Fatalf(
			"OPENLDAP_ACTUAL_VERSION = %q, want %q",
			got,
			openLDAPDatabaseSelectionReferenceVersion,
		)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPDatabaseSelectionReferenceCommit {
		t.Fatalf(
			"OPENLDAP_COMMIT = %q, want %q",
			got,
			openLDAPDatabaseSelectionReferenceCommit,
		)
	}
	return tools
}

func openLDAPDatabaseSelectionSiblingTool(
	t *testing.T,
	primary string,
	name string,
) string {
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
