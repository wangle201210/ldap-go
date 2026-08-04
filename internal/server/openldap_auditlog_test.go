package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type auditlogReferenceRecord struct {
	operation              string
	targetDN               string
	authorizationDN        string
	headerHasSuffix        bool
	headerHasAuthorization bool
	headerHasPeer          bool
	headerHasConnection    bool
	hasEnd                 bool
	realDN                 string
	addValues              []string
	modifications          []auditlogReferenceModification
	newRDN                 string
	deleteOldRDN           string
	newSuperior            string
}

type auditlogReferenceModification struct {
	operation string
	attribute string
	values    []string
}

func TestOpenLDAPReferenceAuditlogOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPLog := filepath.Join(t.TempDir(), "openldap-audit.ldif")
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{"auditlog\nauditlog \"" + openLDAPLog + "\""},
		"include "+filepath.Join(tools.schemaDir, "nis.schema"),
		"access to * by self write by * read",
		`
dn: ou=archive,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: archive
`,
	)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	ldapGoLog := filepath.Join(t.TempDir(), "ldap-go-audit.ldif")
	seedAuditlogOverlay(t, store, ldapGoLog)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLDAPGo()

	reference := observeAuditlogReferenceScenario(t, openLDAPURI, openLDAPLog)
	implementation := observeAuditlogReferenceScenario(
		t,
		"ldap://"+ldapGoAddress,
		ldapGoLog,
	)
	if !reflect.DeepEqual(reference, implementation) {
		t.Fatalf(
			"auditlog mismatch\nOpenLDAP: %#v\nldap-go:  %#v\n\nOpenLDAP file:\n%s\nldap-go file:\n%s",
			reference,
			implementation,
			readAuditlogFile(t, openLDAPLog),
			readAuditlogFile(t, ldapGoLog),
		)
	}
	proxied := auditlogReferenceRecord{}
	for _, record := range implementation {
		if record.targetDN == aliceDN && record.operation == "modify" {
			proxied = record
			break
		}
	}
	if proxied.authorizationDN != aliceDN ||
		proxied.realDN != "cn=admin,dc=example,dc=com" {
		t.Fatalf("proxied auditlog identity = %#v", proxied)
	}
}

func TestOpenLDAPReferenceAuditlogTransactions(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	filename := filepath.Join(t.TempDir(), "openldap-audit-transactions.ldif")
	uri, stop := startOpenLDAPReferenceServer(
		t,
		tools,
		[]string{"auditlog\nauditlog \"" + filename + "\""},
	)
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	committed := transactionTestPerson("audit-reference-committed")
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(committed),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		4,
		rawModifyReplaceRequest(committed.DN, "cn", "Audit Reference Committed"),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	if _, err := os.Stat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted OpenLDAP auditlog file error = %v, want not-exist", err)
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 5, true, identifier),
		int64(ldapwire.ResultSuccess),
	)
	if got := auditlogRecordCount(t, filename); got != 2 {
		t.Fatalf("committed OpenLDAP auditlog records = %d, want 2", got)
	}

	identifier = startRawLDAPTransaction(t, connection, 6)
	aborted := transactionTestPerson("audit-reference-aborted")
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		7,
		rawAddRequest(aborted),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 8, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
	if got := auditlogRecordCount(t, filename); got != 2 {
		t.Fatalf("OpenLDAP auditlog records after abort = %d, want 2", got)
	}

	identifier = startRawLDAPTransaction(t, connection, 9)
	rolledBack := transactionTestPerson("audit-reference-rollback")
	for _, messageID := range []int64{10, 11} {
		assertRawLDAPResult(t, sendRawLDAPOperation(
			t,
			connection,
			messageID,
			rawAddRequest(rolledBack),
			rawTransactionSpecificationControl(identifier, true, true),
		), int64(ldapwire.ResultSuccess))
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 12, true, identifier),
		int64(ldapwire.ResultEntryAlreadyExists),
	)
	if got := auditlogRecordCount(t, filename); got != 3 {
		t.Fatalf(
			"OpenLDAP auditlog records after database rollback = %d, want 3:\n%s",
			got,
			readAuditlogFile(t, filename),
		)
	}
}

func TestOpenLDAPReferenceAuditlogFrontendOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	filename := filepath.Join(t.TempDir(), "openldap-frontend-audit.ldif")
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"database frontend\noverlay auditlog\nauditlog \""+filename+"\"",
		"",
		"",
	)
	defer stop()

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial OpenLDAP frontend auditlog: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind OpenLDAP frontend auditlog: %v", err)
	}
	if err := client.Add(newPersonAddRequest("audit-frontend-reference")); err != nil {
		t.Fatalf("Add with OpenLDAP frontend auditlog: %v", err)
	}
	reference, err := parseAuditlogReferenceRecords(readAuditlogFile(t, filename))
	if err != nil {
		t.Fatalf("parse OpenLDAP frontend auditlog: %v", err)
	}
	if len(reference) != 1 {
		t.Fatalf("OpenLDAP frontend auditlog records = %d, want 1", len(reference))
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	implementationFilename := filepath.Join(t.TempDir(), "ldap-go-frontend-audit.ldif")
	seedFrontendAuditlogOverlay(t, store, implementationFilename)
	address, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLDAPGo()
	implementationClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial ldap-go frontend auditlog: %v", err)
	}
	defer implementationClient.Close()
	if err := implementationClient.Bind(
		"cn=admin,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("bind ldap-go frontend auditlog: %v", err)
	}
	if err := implementationClient.Add(
		newPersonAddRequest("audit-frontend-reference"),
	); err != nil {
		t.Fatalf("Add with ldap-go frontend auditlog: %v", err)
	}
	implementation, err := parseAuditlogReferenceRecords(
		readAuditlogFile(t, implementationFilename),
	)
	if err != nil {
		t.Fatalf("parse ldap-go frontend auditlog: %v", err)
	}
	if !reflect.DeepEqual(reference, implementation) {
		t.Fatalf(
			"frontend auditlog mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}
}

func TestOpenLDAPSlapcatAuditlogConfigImport(t *testing.T) {
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
	filename := filepath.Join(root, "imported-audit.ldif")
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
overlay auditlog
auditlog "%s"
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		databaseDir,
		filename,
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
	unfoldedExport := []byte(strings.ReplaceAll(string(exported), "\n ", ""))
	for _, expected := range [][]byte{
		[]byte("olcAuditlogConfig"),
		[]byte("olcAuditlogFile: " + filename),
	} {
		if !bytes.Contains(unfoldedExport, expected) {
			t.Fatalf("slapcat output is missing %q:\n%s", expected, exported)
		}
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
		t.Fatalf("ImportLDIF(real slapcat auditlog config): %v\n%s", err, exported)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Add(newPersonAddRequest("audit-slapcat-import")); err != nil {
		t.Fatalf("Add after auditlog slapcat import: %v", err)
	}
	if got := auditlogRecordCount(t, filename); got != 1 {
		t.Fatalf("imported auditlog records = %d, want 1", got)
	}
}

func observeAuditlogReferenceScenario(
	t *testing.T,
	uri,
	filename string,
) []auditlogReferenceRecord {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial auditlog provider %s: %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind auditlog provider %s: %v", uri, err)
	}
	proxied := ldap.NewModifyRequest(
		aliceDN,
		[]ldap.Control{proxyAuthorizationControl("dn:"+aliceDN, true)},
	)
	proxied.Replace("description", []string{"proxied auditlog update"})
	if err := client.Modify(proxied); err != nil {
		t.Fatalf("proxied Modify(%s): %v", uri, err)
	}

	dn := "uid=audit-reference,ou=people,dc=example,dc=com"
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"audit-reference"})
	add.Attribute("cn", []string{"Audit Reference"})
	add.Attribute("sn", []string{"Reference"})
	noOp := ldap.NewAddRequest(dn, []ldap.Control{
		ldap.NewControlString(noOpControlOID, true, ""),
	})
	noOp.Attributes = add.Attributes
	assertLDAPResultCode(t, client.Add(noOp), uint16(ldapwire.ResultNoOperation))
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(%s): %v", uri, err)
	}

	modify := ldap.NewModifyRequest(dn, nil)
	modify.Replace("cn", []string{"Audit Updated"})
	modify.Add("description", []string{"first", "second"})
	modify.Delete("description", []string{"first"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(%s): %v", uri, err)
	}
	if _, err := client.PasswordModify(
		ldap.NewPasswordModifyRequest(dn, "", "audit-secret"),
	); err != nil {
		t.Fatalf("PasswordModify(%s): %v", uri, err)
	}

	keptDN := "uid=audit-kept,ou=people,dc=example,dc=com"
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		dn,
		"uid=audit-kept",
		false,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN retaining old RDN (%s): %v", uri, err)
	}
	renamedDN := "uid=audit-renamed,ou=archive,dc=example,dc=com"
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		keptDN,
		"uid=audit-renamed",
		true,
		"ou=archive,dc=example,dc=com",
	)); err != nil {
		t.Fatalf("ModifyDN(%s): %v", uri, err)
	}
	if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("Delete(%s): %v", uri, err)
	}

	rotated := filename + ".rotated"
	if err := os.Rename(filename, rotated); err != nil {
		t.Fatalf("rotate auditlog provider %s file: %v", uri, err)
	}
	afterRotationAdd := newPersonAddRequest("audit-after-rotation")
	afterRotationAdd.Attribute("mail", []string{"audit-after-rotation@example.com"})
	if err := client.Add(afterRotationAdd); err != nil {
		t.Fatalf("Add after auditlog rotation (%s): %v", uri, err)
	}
	deleteAll := ldap.NewModifyRequest(afterRotationAdd.DN, nil)
	deleteAll.Delete("mail", nil)
	if err := client.Modify(deleteAll); err != nil {
		t.Fatalf("Delete all attribute values (%s): %v", uri, err)
	}
	assertLDAPResultCode(
		t,
		client.Add(newPersonAddRequest("audit-after-rotation")),
		ldap.LDAPResultEntryAlreadyExists,
	)
	incrementAdd := newAccesslogPersonAddRequest("audit-increment")
	if err := client.Add(incrementAdd); err != nil {
		t.Fatalf("Add increment auditlog entry (%s): %v", uri, err)
	}
	increment := ldap.NewModifyRequest(incrementAdd.DN, nil)
	increment.Increment("uidNumber", "2")
	if err := client.Modify(increment); err != nil {
		t.Fatalf("Increment auditlog value (%s): %v", uri, err)
	}
	encodingAdd := newPersonAddRequest("audit-encoding")
	encodingAdd.Attribute("description", []string{
		" Leading",
		"trailing ",
		":colon",
		"<less-than",
		"\u56fd\u5bc6\u5ba1\u8ba1",
		strings.Repeat("long-value-", 20),
	})
	encodingAdd.Attribute("jpegPhoto", []string{string([]byte{0x00, 0xff, 0x10})})
	encodingAdd.Attribute("userPassword", []string{"encoding-secret"})
	if err := client.Add(encodingAdd); err != nil {
		t.Fatalf("Add auditlog encoding values (%s): %v", uri, err)
	}
	beforeRotation, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatalf("read rotated auditlog provider %s file: %v", uri, err)
	}
	afterRotation, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read auditlog provider %s file: %v", uri, err)
	}
	data := append(beforeRotation, afterRotation...)
	if !bytes.Contains(data, []byte("userPassword:: ")) ||
		!bytes.Contains(data, []byte("\n ")) {
		t.Fatalf("auditlog provider %s did not Base64 encode and fold LDIF:\n%s", uri, data)
	}
	records, err := parseAuditlogReferenceRecords(string(data))
	if err != nil {
		t.Fatalf("parse auditlog provider %s file: %v\n%s", uri, err, data)
	}
	return records
}

func parseAuditlogReferenceRecords(value string) ([]auditlogReferenceRecord, error) {
	lines := unfoldAuditlogLines(value)
	var records []auditlogReferenceRecord
	for len(lines) > 0 {
		for len(lines) > 0 && lines[0] == "" {
			lines = lines[1:]
		}
		if len(lines) == 0 {
			break
		}
		end := 0
		for end < len(lines) && lines[end] != "" {
			end++
		}
		record, err := parseAuditlogReferenceRecord(lines[:end])
		if err != nil {
			return nil, err
		}
		records = append(records, record)
		lines = lines[end:]
	}
	return records, nil
}

func unfoldAuditlogLines(value string) []string {
	physical := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(physical))
	for _, line := range physical {
		if strings.HasPrefix(line, " ") && len(lines) > 0 {
			lines[len(lines)-1] += line[1:]
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func parseAuditlogReferenceRecord(lines []string) (auditlogReferenceRecord, error) {
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "# ") {
		return auditlogReferenceRecord{}, fmt.Errorf("invalid auditlog record %q", lines)
	}
	headerFields := strings.Fields(lines[0])
	if len(headerFields) < 7 {
		return auditlogReferenceRecord{}, fmt.Errorf("invalid auditlog header %q", lines[0])
	}
	record := auditlogReferenceRecord{
		operation:              headerFields[1],
		authorizationDN:        headerFields[4],
		headerHasSuffix:        strings.Contains(lines[0], " dc=example,dc=com "),
		headerHasAuthorization: strings.Contains(lines[0], " cn=admin,dc=example,dc=com "),
		headerHasPeer:          strings.Contains(lines[0], " IP="),
		headerHasConnection:    strings.Contains(lines[0], " conn="),
	}
	index := 1
	if index < len(lines) && strings.HasPrefix(lines[index], "# realdn: ") {
		record.realDN = strings.TrimPrefix(lines[index], "# realdn: ")
		index++
	}
	if index >= len(lines) || !strings.HasPrefix(lines[index], "dn: ") {
		return auditlogReferenceRecord{}, fmt.Errorf("missing auditlog DN in %q", lines)
	}
	record.targetDN = strings.TrimPrefix(lines[index], "dn: ")
	index++
	if index >= len(lines) || lines[index] != "changetype: "+record.operation {
		return auditlogReferenceRecord{}, fmt.Errorf("invalid auditlog changetype in %q", lines)
	}
	index++

	switch record.operation {
	case "add":
		for index < len(lines) && !strings.HasPrefix(lines[index], "# end ") {
			name, raw, err := parseAuditlogValueLine(lines[index])
			if err != nil {
				return auditlogReferenceRecord{}, err
			}
			record.addValues = append(
				record.addValues,
				auditlogReferenceValue(name, raw),
			)
			index++
		}
		sort.Strings(record.addValues)
	case "modify":
		for index < len(lines) && !strings.HasPrefix(lines[index], "# end ") {
			separator := strings.Index(lines[index], ": ")
			if separator < 0 {
				return auditlogReferenceRecord{}, fmt.Errorf("invalid modification header %q", lines[index])
			}
			modification := auditlogReferenceModification{
				operation: lines[index][:separator],
				attribute: strings.ToLower(lines[index][separator+2:]),
			}
			index++
			for index < len(lines) && lines[index] != "-" {
				name, raw, err := parseAuditlogValueLine(lines[index])
				if err != nil {
					return auditlogReferenceRecord{}, err
				}
				modification.values = append(
					modification.values,
					auditlogReferenceValue(name, raw),
				)
				index++
			}
			if index >= len(lines) || lines[index] != "-" {
				return auditlogReferenceRecord{}, fmt.Errorf("unterminated modification in %q", lines)
			}
			sort.Strings(modification.values)
			record.modifications = append(record.modifications, modification)
			index++
		}
	case "modrdn":
		for index < len(lines) && !strings.HasPrefix(lines[index], "# end ") {
			switch {
			case strings.HasPrefix(lines[index], "newrdn: "):
				record.newRDN = strings.TrimPrefix(lines[index], "newrdn: ")
			case strings.HasPrefix(lines[index], "deleteoldrdn: "):
				record.deleteOldRDN = strings.TrimPrefix(lines[index], "deleteoldrdn: ")
			case strings.HasPrefix(lines[index], "newsuperior: "):
				record.newSuperior = strings.TrimPrefix(lines[index], "newsuperior: ")
			default:
				return auditlogReferenceRecord{}, fmt.Errorf("invalid modrdn line %q", lines[index])
			}
			index++
		}
	case "delete":
	default:
		return auditlogReferenceRecord{}, fmt.Errorf("unsupported auditlog operation %q", record.operation)
	}
	if index < len(lines) && lines[index] == "# end "+record.operation+" "+headerFields[2] {
		record.hasEnd = true
		index++
	}
	if index != len(lines) {
		return auditlogReferenceRecord{}, fmt.Errorf("trailing auditlog lines %q", lines[index:])
	}
	return record, nil
}

func parseAuditlogValueLine(line string) (string, []byte, error) {
	separator := strings.IndexByte(line, ':')
	if separator < 1 {
		return "", nil, fmt.Errorf("invalid LDIF value line %q", line)
	}
	name := strings.ToLower(line[:separator])
	remainder := line[separator+1:]
	if strings.HasPrefix(remainder, ": ") {
		decoded, err := base64.StdEncoding.DecodeString(remainder[2:])
		if err != nil {
			return "", nil, fmt.Errorf("decode %s: %w", name, err)
		}
		return name, decoded, nil
	}
	if remainder == "" {
		return name, nil, nil
	}
	if !strings.HasPrefix(remainder, " ") {
		return "", nil, fmt.Errorf("invalid LDIF value line %q", line)
	}
	return name, []byte(remainder[1:]), nil
}

func auditlogReferenceValue(name string, value []byte) string {
	switch strings.ToLower(name) {
	case "entryuuid", "entrycsn", "createtimestamp", "modifytimestamp":
		value = []byte("<generated>")
	case "userpassword":
		value = []byte("<password>")
	}
	return strings.ToLower(name) + "=" + base64.StdEncoding.EncodeToString(value)
}
