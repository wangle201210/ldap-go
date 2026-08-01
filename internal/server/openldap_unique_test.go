package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceUniqueOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{uniqueReferenceOverlayConfiguration()},
		"",
		"",
		uniqueReferenceArchiveLDIF(),
	)
	defer stopOpenLDAP()
	openLDAP, err := ldap.DialURL(openLDAPURI)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP): %v", err)
	}
	defer openLDAP.Close()
	if err := openLDAP.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(OpenLDAP): %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGo := bindUniqueClient(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer ldapGo.Close()
	for _, uid := range []string{"bob", "carol"} {
		if err := ldapGo.Add(uniquePersonAdd(
			"uid="+uid+",ou=people,dc=example,dc=com",
			uid,
			uid,
		)); err != nil {
			t.Fatalf("Add(ldap-go seed %s): %v", uid, err)
		}
	}
	archiveSeed := uniquePersonAdd(
		"uid=archive-seed,ou=archive,dc=example,dc=com",
		"archive-seed",
		"Archive",
	)
	archiveSeed.Attribute("description", []string{"archive-duplicate"})
	if err := ldapGo.Add(archiveSeed); err != nil {
		t.Fatalf("Add(ldap-go archive seed): %v", err)
	}
	configClient := bindUniqueClient(
		t,
		ldapGoAddress,
		"cn=config",
		"config-secret",
	)
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testUniqueOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcUniqueConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}unique"})
	overlay.Attribute("olcUniqueURI", uniqueReferenceURIValues())
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go unique overlay): %v", err)
	}

	openLDAPResults := runUniqueReferenceScenario(t, openLDAP)
	ldapGoResults := runUniqueReferenceScenario(t, ldapGo)
	want := []uint16{
		ldap.LDAPResultSuccess,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultSuccess,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultSuccess,
	}
	labels := []string{
		"valid add",
		"duplicate uid add",
		"normalized mail add",
		"duplicate uid modify",
		"duplicate RDN",
		"second strict value",
		"strict null modify",
		"ignore domain add",
		"Relax add",
	}
	if len(openLDAPResults) != len(want) || len(ldapGoResults) != len(want) {
		t.Fatalf(
			"result lengths: OpenLDAP=%d ldap-go=%d want=%d",
			len(openLDAPResults),
			len(ldapGoResults),
			len(want),
		)
	}
	for index := range want {
		if openLDAPResults[index] != want[index] ||
			ldapGoResults[index] != openLDAPResults[index] {
			t.Fatalf(
				"%s result: OpenLDAP=%d ldap-go=%d want=%d",
				labels[index],
				openLDAPResults[index],
				ldapGoResults[index],
				want[index],
			)
		}
	}
}

func TestOpenLDAPSlapcatUniqueConfigImport(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	slaptest := findOpenLDAPSchemaTool(
		t,
		"slaptest",
		"/opt/homebrew/opt/openldap/sbin/slaptest",
		"/usr/sbin/slaptest",
	)
	slapcat := findOpenLDAPSchemaTool(
		t,
		"slapcat",
		"/opt/homebrew/opt/openldap/sbin/slapcat",
		"/usr/sbin/slapcat",
	)

	root := t.TempDir()
	configDir := filepath.Join(root, "slapd.d")
	databaseDir := filepath.Join(root, "db")
	for _, path := range []string{configDir, databaseDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%s): %v", path, err)
		}
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
include %s
include %s
pidfile %s
argsfile %s

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
overlay unique
unique_uri "ldap:///ou=people,dc=example,dc=com?uid,mail?one?(objectClass=inetOrgPerson)"
unique_uri "strict ldap:///ou=people,dc=example,dc=com?description?one?(objectClass=inetOrgPerson)"
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		databaseDir,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write slapd.conf: %v", err)
	}
	dataPath := filepath.Join(root, "data.ldif")
	data := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

`
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write OpenLDAP seed data: %v", err)
	}
	command := exec.Command(
		tools.slapadd,
		"-q",
		"-f",
		configPath,
		"-l",
		dataPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slapadd failed: %v\n%s", err, output)
	}
	command = exec.Command(slaptest, "-f", configPath, "-F", configDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slaptest failed: %v\n%s", err, output)
	}

	var stderr bytes.Buffer
	command = exec.Command(
		slapcat,
		"-F",
		configDir,
		"-n",
		"0",
		"-a",
		"(olcOverlay=*)",
	)
	command.Stderr = &stderr
	exported, err := command.Output()
	if err != nil {
		t.Fatalf("slapcat -n 0 failed: %v\n%s", err, stderr.Bytes())
	}
	if !bytes.Contains(exported, []byte("olcUniqueURI:")) ||
		!bytes.Contains(exported, []byte("olcUniqueConfig")) {
		t.Fatalf("slapcat output has no unique configuration:\n%s", exported)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		bytes.NewReader(exported),
		migration.ImportOptions{},
	); err != nil {
		t.Fatalf("ImportLDIF(real slapcat unique config): %v\n%s", err, exported)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindUniqueClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer client.Close()

	source := uniquePersonAdd(
		"uid=slapcat-source,ou=people,dc=example,dc=com",
		"slapcat-source",
		"Slapcat",
	)
	source.Attribute("mail", []string{"slapcat@example.com"})
	if err := client.Add(source); err != nil {
		t.Fatalf("Add(slapcat unique source): %v", err)
	}
	duplicate := uniquePersonAdd(
		"uid=slapcat-duplicate,ou=people,dc=example,dc=com",
		"slapcat-duplicate",
		"Slapcat",
	)
	duplicate.Attribute("mail", []string{"SLAPCAT@example.com"})
	assertLDAPResultCode(
		t,
		client.Add(duplicate),
		ldap.LDAPResultConstraintViolation,
	)
}

func runUniqueReferenceScenario(t *testing.T, client *ldap.Conn) []uint16 {
	t.Helper()

	sourceDN := "uid=unique-valid,ou=people,dc=example,dc=com"
	source := uniquePersonAdd(sourceDN, "unique-valid", "Valid")
	source.Attribute("mail", []string{"unique@example.com"})
	source.Attribute("description", []string{"first-description"})
	results := []uint16{uniqueLDAPResultCode(t, client.Add(source))}

	duplicateUID := ldap.NewAddRequest(
		"uid=unique-duplicate,ou=people,dc=example,dc=com",
		nil,
	)
	duplicateUID.Attribute("objectClass", []string{"inetOrgPerson"})
	duplicateUID.Attribute("uid", []string{"unique-duplicate", "alice"})
	duplicateUID.Attribute("cn", []string{"unique-duplicate"})
	duplicateUID.Attribute("sn", []string{"Duplicate"})
	results = append(results, uniqueLDAPResultCode(t, client.Add(duplicateUID)))

	duplicateMail := uniquePersonAdd(
		"uid=unique-mail,ou=people,dc=example,dc=com",
		"unique-mail",
		"Duplicate",
	)
	duplicateMail.Attribute("mail", []string{"UNIQUE@example.com"})
	results = append(results, uniqueLDAPResultCode(t, client.Add(duplicateMail)))

	duplicateModify := ldap.NewModifyRequest(sourceDN, nil)
	duplicateModify.Add("uid", []string{"bob"})
	results = append(results, uniqueLDAPResultCode(t, client.Modify(duplicateModify)))

	rename := ldap.NewModifyDNRequest(sourceDN, "uid=alice", true, "")
	results = append(results, uniqueLDAPResultCode(t, client.ModifyDN(rename)))

	strictDN := "uid=unique-strict,ou=people,dc=example,dc=com"
	strictEntry := uniquePersonAdd(strictDN, "unique-strict", "Strict")
	strictEntry.Attribute("description", []string{"second-description"})
	results = append(results, uniqueLDAPResultCode(t, client.Add(strictEntry)))

	strictNull := ldap.NewModifyRequest(strictDN, nil)
	strictNull.Replace("description", []string{})
	results = append(results, uniqueLDAPResultCode(t, client.Modify(strictNull)))

	archiveDuplicate := uniquePersonAdd(
		"uid=archive-duplicate,ou=archive,dc=example,dc=com",
		"archive-duplicate",
		"Archive",
	)
	archiveDuplicate.Attribute("description", []string{"ARCHIVE-DUPLICATE"})
	results = append(
		results,
		uniqueLDAPResultCode(t, client.Add(archiveDuplicate)),
	)

	relaxed := uniquePersonAdd(
		"uid=unique-relaxed,ou=people,dc=example,dc=com",
		"unique-relaxed",
		"Relaxed",
	)
	relaxed.Controls = []ldap.Control{relaxLDAPControl()}
	relaxed.Attribute("mail", []string{"unique@example.com"})
	relaxed.Attribute("description", []string{"first-description"})
	results = append(results, uniqueLDAPResultCode(t, client.Add(relaxed)))
	return results
}

func uniqueLDAPResultCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("LDAP operation returned non-LDAP error: %v", err)
	}
	return ldapErr.ResultCode
}

func uniqueReferenceOverlayConfiguration() string {
	values := uniqueReferenceURIValues()
	return "unique\n" +
		"unique_uri \"" + values[0] + "\"\n" +
		"unique_uri \"" + values[1] + "\"\n" +
		"unique_uri \"" + values[2] + "\""
}

func uniqueReferenceURIValues() []string {
	return []string{
		"ldap:///ou=people,dc=example,dc=com?uid,mail?one?" +
			"(objectClass=inetOrgPerson)",
		"strict ldap:///ou=people,dc=example,dc=com?description?one?" +
			"(objectClass=inetOrgPerson)",
		"ignore serialize ldap:///ou=archive,dc=example,dc=com?" +
			"objectClass,uid,cn,sn?one?(objectClass=inetOrgPerson)",
	}
}

func uniqueReferenceArchiveLDIF() string {
	return `

dn: ou=archive,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: archive

dn: uid=archive-seed,ou=archive,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: archive-seed
cn: archive-seed
sn: Archive
description: archive-duplicate
`
}
