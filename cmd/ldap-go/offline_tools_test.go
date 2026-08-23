package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOfflineToolCommands(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedSlapOfflineCommandDatabase(t, databasePath)

	stdout, stderr, exitCode := runOfflineToolCommand(
		[]string{
			"slapauth", "-db", databasePath, "-M", "PLAIN",
			"-U", "alice", "-X", "u:bob",
		},
		"",
	)
	if exitCode != 0 || stdout != "" ||
		!strings.Contains(stderr, "authcDN: <"+offlineCommandAliceDN+">") ||
		!strings.Contains(stderr, "authorization OK") {
		t.Fatalf("slapauth exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	modify := `dn: uid=alice,ou=people,dc=example,dc=com
changetype: modify
replace: cn
cn: Alice Updated
`
	stdout, stderr, exitCode = runOfflineToolCommand(
		[]string{"slapmodify", "-db", databasePath, "-n", "1", "-u", "-v"},
		modify,
	)
	if exitCode != 0 || !strings.Contains(stdout, "validated 1 change record") {
		t.Fatalf("slapmodify -u exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if got := offlineCommandAttribute(t, databasePath, offlineCommandAliceDN, "cn"); got != "Alice Example" {
		t.Fatalf("slapmodify -u stored cn %q", got)
	}

	stdout, stderr, exitCode = runOfflineToolCommand(
		[]string{"slapmodify", "-db", databasePath, "-b", "dc=example,dc=com", "-v"},
		modify,
	)
	if exitCode != 0 || !strings.Contains(stdout, "applied 1 change record") {
		t.Fatalf("slapmodify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if got := offlineCommandAttribute(t, databasePath, offlineCommandAliceDN, "cn"); got != "Alice Updated" {
		t.Fatalf("slapmodify stored cn %q", got)
	}

	continuing := `dn: uid=alice,ou=people,dc=example,dc=com
changetype: modify
replace: sn
sn: Retained Before Failure

dn: uid=missing,ou=people,dc=example,dc=com
changetype: delete
`
	_, stderr, exitCode = runOfflineToolCommand(
		[]string{"slapmodify", "-db", databasePath, "-n", "1", "-c"},
		continuing,
	)
	if exitCode != 1 || !strings.Contains(stderr, "uid=missing") {
		t.Fatalf("slapmodify continue exit=%d stderr=%q", exitCode, stderr)
	}
	if got := offlineCommandAttribute(t, databasePath, offlineCommandAliceDN, "sn"); got != "Retained Before Failure" {
		t.Fatalf("successful slapmodify record stored sn %q", got)
	}

	resume := "invalid skipped record\n\n" +
		"dn: " + offlineCommandBobDN + "\nchangetype: modify\n" +
		"replace: description\ndescription: resumed\n"
	stdout, stderr, exitCode = runOfflineToolCommand(
		[]string{"slapmodify", "-db", databasePath, "-n", "1", "-j", "3", "-w", "-v"},
		resume,
	)
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "applied 1 change record") {
		t.Fatalf("slapmodify -j -w exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if got := offlineCommandAttribute(t, databasePath, offlineCommandBobDN, "description"); got != "resumed" {
		t.Fatalf("resumed description = %q", got)
	}
	if got := offlineCommandAttribute(t, databasePath, "dc=example,dc=com", "contextCSN"); got == "" {
		t.Fatal("slapmodify -w did not update contextCSN")
	}

	stdout, stderr, exitCode = runOfflineToolCommand(
		[]string{"slapindex", "-db", databasePath, "-n", "1", "-q", "uid"},
		"",
	)
	if exitCode != 0 || stderr != "" || stdout != "reindexed 1 database(s)\n" {
		t.Fatalf("slapindex -q uid exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	seedOfflineCommandInvalidEntry(t, databasePath)
	stdout, stderr, exitCode = runOfflineToolCommand(
		[]string{"slapschema", "-db", databasePath, "-n", "1", "-c", "-v"},
		"",
	)
	if exitCode != 65 || stderr != "" ||
		!strings.Contains(stdout, "# id=") ||
		!strings.Contains(stdout, "dn: uid=invalid,ou=people,dc=example,dc=com") {
		t.Fatalf("slapschema exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOfflineToolRejectsOpenLDAPConfigBeforeOpeningDatabase(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "missing", "directory.db")
	_, stderr, exitCode := runOfflineToolCommand(
		[]string{"slapmodify", "-db", databasePath, "-f", "slapd.conf"},
		"",
	)
	if exitCode != 1 || !strings.Contains(stderr, "option -f is not supported") {
		t.Fatalf("exit=%d stderr=%q", exitCode, stderr)
	}
	if _, err := storage.OpenBoltReadOnly(databasePath); err == nil {
		t.Fatal("rejected -f unexpectedly created a database")
	}
}

func TestOpenLDAPReferenceOfflineToolCLI(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") != "1" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run OpenLDAP offline-tool differential tests")
	}
	if commit := os.Getenv("OPENLDAP_VERIFIED_COMMIT"); commit != "d172686d3d270bc961b78f3ff00d7019c8dfb094" {
		t.Skipf("requires verified OpenLDAP 2.6.13 commit, got %q", commit)
	}
	slapadd := os.Getenv("OPENLDAP_SLAPADD")
	schemaDirectory := os.Getenv("OPENLDAP_SCHEMA_DIR")
	if slapadd == "" || schemaDirectory == "" {
		t.Skip("OPENLDAP_SLAPADD and OPENLDAP_SCHEMA_DIR are required")
	}
	toolDirectory := filepath.Dir(slapadd)
	slapauth := filepath.Join(toolDirectory, "slapauth")
	slapmodify := filepath.Join(toolDirectory, "slapmodify")
	if _, err := os.Stat(slapauth); err != nil {
		t.Skipf("OpenLDAP slapauth is unavailable: %v", err)
	}
	if _, err := os.Stat(slapmodify); err != nil {
		t.Skipf("OpenLDAP slapmodify is unavailable: %v", err)
	}

	directory := t.TempDir()
	databaseDirectory := filepath.Join(directory, "mdb")
	if err := os.Mkdir(databaseDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir(mdb): %v", err)
	}
	configPath := filepath.Join(directory, "slapd.conf")
	config := strings.Join([]string{
		"include " + filepath.Join(schemaDirectory, "core.schema"),
		"include " + filepath.Join(schemaDirectory, "cosine.schema"),
		"include " + filepath.Join(schemaDirectory, "nis.schema"),
		"include " + filepath.Join(schemaDirectory, "inetorgperson.schema"),
		`authz-policy to`,
		`authz-regexp "^uid=([^,]+),cn=plain,cn=auth$" "uid=$1,ou=people,dc=example,dc=com"`,
		"database mdb",
		"maxsize 1073741824",
		"suffix dc=example,dc=com",
		"rootdn cn=admin,dc=example,dc=com",
		"rootpw secret",
		"directory " + databaseDirectory,
		"access to * by * manage",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write slapd.conf: %v", err)
	}
	dataPath := filepath.Join(directory, "data.ldif")
	data := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example
authzTo: dn:uid=bob,ou=people,dc=example,dc=com

dn: uid=bob,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: bob
cn: Bob Example
sn: Example
`
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write data LDIF: %v", err)
	}
	if output, err := exec.Command(slapadd, "-f", configPath, "-l", dataPath).CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP slapadd: %v\n%s", err, output)
	}
	authOutput, err := exec.Command(
		slapauth, "-f", configPath, "-M", "PLAIN", "-U", "alice", "-X", "u:bob",
	).CombinedOutput()
	if err != nil || !bytes.Contains(authOutput, []byte("authorization OK")) {
		t.Fatalf("OpenLDAP slapauth: %v\n%s", err, authOutput)
	}

	modifyPath := filepath.Join(directory, "modify.ldif")
	modify := `dn: uid=alice,ou=people,dc=example,dc=com
changetype: modify
replace: cn
cn: Alice Updated
`
	if err := os.WriteFile(modifyPath, []byte(modify), 0o600); err != nil {
		t.Fatalf("write modify LDIF: %v", err)
	}
	if output, err := exec.Command(
		slapmodify, "-f", configPath, "-l", modifyPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP slapmodify: %v\n%s", err, output)
	}

	resumePath := filepath.Join(directory, "resume.ldif")
	resume := "invalid skipped record\n\n" + `dn: uid=bob,ou=people,dc=example,dc=com
changetype: modify
replace: description
description: resumed
`
	if err := os.WriteFile(resumePath, []byte(resume), 0o600); err != nil {
		t.Fatalf("write resume LDIF: %v", err)
	}
	if output, err := exec.Command(
		slapmodify, "-f", configPath, "-j", "3", "-w", "-l", resumePath,
	).CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP slapmodify -j -w: %v\n%s", err, output)
	}
	slapcat := filepath.Join(toolDirectory, "slapcat")
	resumeOutput, err := exec.Command(slapcat, "-f", configPath).CombinedOutput()
	if err != nil || !bytes.Contains(resumeOutput, []byte("description: resumed")) ||
		!bytes.Contains(resumeOutput, []byte("contextCSN:")) {
		t.Fatalf("OpenLDAP slapmodify -j -w result: %v\n%s", err, resumeOutput)
	}

	// ldap-go intentionally extends slapmodify with offline moddn support.
	// OpenLDAP 2.6.13 parses the record but rejects request tag 0x6c.
	moddnPath := filepath.Join(directory, "moddn.ldif")
	moddn := `dn: uid=bob,ou=people,dc=example,dc=com
changetype: moddn
newrdn: uid=robert
deleteoldrdn: 1
`
	if err := os.WriteFile(moddnPath, []byte(moddn), 0o600); err != nil {
		t.Fatalf("write moddn LDIF: %v", err)
	}
	moddnOutput, moddnErr := exec.Command(
		slapmodify, "-f", configPath, "-l", moddnPath,
	).CombinedOutput()
	if moddnErr == nil || !bytes.Contains(moddnOutput, []byte("not supported")) {
		t.Fatalf("OpenLDAP moddn rejection: err=%v output=%q", moddnErr, moddnOutput)
	}

	invalidPath := filepath.Join(directory, "invalid.ldif")
	invalid := `dn: uid=alice,ou=people,dc=example,dc=com
changetype: modify
delete: sn
`
	if err := os.WriteFile(invalidPath, []byte(invalid), 0o600); err != nil {
		t.Fatalf("write invalid LDIF: %v", err)
	}
	if output, err := exec.Command(
		slapmodify, "-f", configPath, "-s", "-l", invalidPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP slapmodify -s: %v\n%s", err, output)
	}

	resolvedSlapadd, err := filepath.EvalSymlinks(slapadd)
	if err != nil {
		t.Fatalf("resolve slapadd: %v", err)
	}
	slapschema := filepath.Join(directory, "slapschema")
	if err := os.Symlink(resolvedSlapadd, slapschema); err != nil {
		t.Fatalf("link slapschema: %v", err)
	}
	schemaOutput, schemaErr := exec.Command(slapschema, "-f", configPath, "-c").CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(schemaErr, &exitErr) || exitErr.ExitCode() != 65 ||
		!bytes.Contains(schemaOutput, []byte("uid=alice,ou=people,dc=example,dc=com")) {
		t.Fatalf("OpenLDAP slapschema exit=%v output=%q", schemaErr, schemaOutput)
	}
}

func runOfflineToolCommand(args []string, input string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	exitCode := run(
		args,
		strings.NewReader(input),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	return stdout.String(), stderr.String(), exitCode
}

const (
	offlineCommandAliceDN = "uid=alice,ou=people,dc=example,dc=com"
	offlineCommandBobDN   = "uid=bob,ou=people,dc=example,dc=com"
)

func seedSlapOfflineCommandDatabase(t *testing.T, path string) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer store.Close()
	config := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: slapOfflineCommandValues("olcGlobal")},
				{Description: "cn", Values: slapOfflineCommandValues("config")},
				{Description: "olcAuthzPolicy", Values: slapOfflineCommandValues("to")},
				{Description: "olcAuthzRegexp", Values: slapOfflineCommandValues(
					`{0}^uid=([^,]+),cn=plain,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
				)},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: slapOfflineCommandValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: slapOfflineCommandValues("{0}config")},
				{Description: "olcRootDN", Values: slapOfflineCommandValues("cn=config")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: slapOfflineCommandValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: slapOfflineCommandValues("{1}mdb")},
				{Description: "olcSuffix", Values: slapOfflineCommandValues("dc=example,dc=com")},
				{Description: "olcRootDN", Values: slapOfflineCommandValues("cn=admin,dc=example,dc=com")},
				{Description: "olcAccess", Values: slapOfflineCommandValues("{0}to * by * manage")},
				{Description: "olcDbIndex", Values: slapOfflineCommandValues("uid eq", "cn eq")},
			},
		},
	}
	content := []directory.Entry{
		offlineCommandEntry("dc=example,dc=com", "domain", map[string][]string{"dc": {"example"}}),
		offlineCommandEntry("ou=people,dc=example,dc=com", "organizationalUnit", map[string][]string{"ou": {"people"}}),
		offlineCommandEntry(offlineCommandAliceDN, "inetOrgPerson", map[string][]string{
			"uid": {"alice"}, "cn": {"Alice Example"}, "sn": {"Example"},
			"authzTo": {"dn:" + offlineCommandBobDN},
		}),
		offlineCommandEntry(offlineCommandBobDN, "inetOrgPerson", map[string][]string{
			"uid": {"bob"}, "cn": {"Bob Example"}, "sn": {"Example"},
		}),
	}
	err = store.Update(context.Background(), func(writer storage.Writer) error {
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
	})
	if err != nil {
		t.Fatalf("seed database: %v", err)
	}
}

func seedOfflineCommandInvalidEntry(t *testing.T, path string) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer store.Close()
	entry := offlineCommandEntry(
		"uid=invalid,ou=people,dc=example,dc=com",
		"inetOrgPerson",
		map[string][]string{"uid": {"invalid"}, "cn": {"Invalid"}},
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(storage.OpenLDAPDatabasePartition("{1}mdb", nil), entry, false)
	}); err != nil {
		t.Fatalf("seed invalid entry: %v", err)
	}
}

func offlineCommandEntry(dn, objectClass string, values map[string][]string) directory.Entry {
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: slapOfflineCommandValues(objectClass)},
		},
	}
	for description, raw := range values {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: description, Values: slapOfflineCommandValues(raw...),
		})
	}
	return entry
}

func slapOfflineCommandValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}

func offlineCommandAttribute(t *testing.T, path, rawDN, attribute string) string {
	t.Helper()
	store, err := storage.OpenBoltReadOnly(path)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(): %v", err)
	}
	defer store.Close()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	var value string
	err = store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(storage.OpenLDAPDatabasePartition("{1}mdb", nil), dn)
		if err != nil {
			return err
		}
		values := entry.Values(attribute)
		if len(values) != 0 {
			value = string(values[0])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read attribute: %v", err)
	}
	return value
}
