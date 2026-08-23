package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPAddAndModifyExecuteLDIFInOrder(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	carolDN := "uid=carol," + clientToolPeopleDN
	binaryPhoto := []byte{0x00, 0xff, 0x10, 0x80}
	longDescription := strings.Repeat("folded write value ", 10)
	addInput := strings.Join([]string{
		"version: 1",
		"",
		"dn: " + carolDN,
		"objectClass: inetOrgPerson",
		"uid: carol",
		"cn: Carol Example",
		"sn: Example",
		"description: " + longDescription[:80],
		" " + longDescription[80:],
		"jpegPhoto:: " + base64.StdEncoding.EncodeToString(binaryPhoto),
		"",
	}, "\n")

	stdout, stderr, exitCode := runLDAPClientCommand(
		ldapWriteAuthArgs("ldapadd", uri),
		addInput,
	)
	if exitCode != 0 || stderr != "" || stdout != "ldapadd: applied 1 record(s), 0 failed\n" {
		t.Fatalf("ldapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entry := requireLDAPWriteEntry(t, uri, carolDN)
	if got := []byte(entry.GetAttributeValue("jpegPhoto")); !bytes.Equal(got, binaryPhoto) {
		t.Fatalf("ldapadd jpegPhoto = %v, want %v", got, binaryPhoto)
	}
	if got := entry.GetAttributeValues("description"); len(got) != 1 || got[0] != longDescription {
		t.Fatalf("ldapadd descriptions = %#v", got)
	}

	carolineDN := "uid=caroline," + clientToolPeopleDN
	temporaryDN := "uid=temporary," + clientToolPeopleDN
	replacementPhoto := []byte{0x01, 0x00, 0xfe, 0x7f}
	modifyInput := strings.Join([]string{
		"dn: " + carolDN,
		"changetype: modify",
		"replace: jpegPhoto",
		"jpegPhoto:: " + base64.StdEncoding.EncodeToString(replacementPhoto),
		"-",
		"replace: description",
		"description: replaced after binary value",
		"-",
		"",
		"dn: " + carolDN,
		"changetype: moddn",
		"newrdn: uid=caroline",
		"deleteoldrdn: 1",
		"",
		"dn: " + carolineDN,
		"changetype: modify",
		"replace: cn",
		"cn: Caroline Example",
		"-",
		"",
		"dn: " + temporaryDN,
		"changetype: add",
		"objectClass: inetOrgPerson",
		"uid: temporary",
		"cn: Temporary Example",
		"sn: Example",
		"",
		"dn: " + temporaryDN,
		"changetype: delete",
		"",
	}, "\n")
	modifyPath := filepath.Join(t.TempDir(), "changes.ldif")
	if err := os.WriteFile(modifyPath, []byte(modifyInput), 0o600); err != nil {
		t.Fatalf("write modify LDIF: %v", err)
	}
	args := append(ldapWriteAuthArgs("ldapmodify", uri), "-f", modifyPath)
	stdout, stderr, exitCode = runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapmodify: applied 5 record(s), 0 failed\n" {
		t.Fatalf("ldapmodify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, carolDN)
	assertLDAPWriteEntryAbsent(t, uri, temporaryDN)
	entry = requireLDAPWriteEntry(t, uri, carolineDN)
	if entry.GetAttributeValue("uid") != "caroline" || entry.GetAttributeValue("cn") != "Caroline Example" {
		t.Fatalf("renamed entry attributes = %#v", entry.Attributes)
	}
	if got := []byte(entry.GetAttributeValue("jpegPhoto")); !bytes.Equal(got, replacementPhoto) {
		t.Fatalf("ldapmodify jpegPhoto = %v, want %v", got, replacementPhoto)
	}
	if got := entry.GetAttributeValues("description"); len(got) != 1 || got[0] != "replaced after binary value" {
		t.Fatalf("ldapmodify description = %#v", got)
	}
}

func TestLDAPModifyAddMode(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	dn := "uid=modify-add," + clientToolPeopleDN
	input := strings.Join([]string{
		"dn: " + dn,
		"objectClass: inetOrgPerson",
		"uid: modify-add",
		"cn: Modify Add",
		"sn: Add",
		"",
		"dn: " + dn,
		"changetype: modify",
		"replace: cn",
		"cn: Modified After Add",
		"-",
		"",
	}, "\n")
	args := append(ldapWriteAuthArgs("ldapmodify", uri), "-a")
	stdout, stderr, exitCode := runLDAPClientCommand(args, input)
	if exitCode != 0 || stderr != "" ||
		stdout != "ldapmodify: applied 2 record(s), 0 failed\n" {
		t.Fatalf("ldapmodify -a exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entry := requireLDAPWriteEntry(t, uri, dn)
	if got := entry.GetAttributeValue("cn"); got != "Modified After Add" {
		t.Fatalf("ldapmodify -a cn = %q", got)
	}
}

func TestLDAPModifyDefaultsToModifyChangeRecord(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	dn := "uid=default-modify," + clientToolPeopleDN
	addEntriesWithLDAPAdd(t, uri, posixPersonContentLDIF(dn, "default-modify", 10))
	input := strings.Join([]string{
		"dn: " + dn,
		"replace: cn",
		"cn: Default Modify",
		"-",
		"add: description",
		"description: remove me",
		"description: keep me",
		"-",
		"delete: description",
		"description: remove me",
		"-",
		"increment: uidNumber",
		"uidNumber: 2",
		"",
	}, "\n")
	stdout, stderr, exitCode := runLDAPClientCommand(
		ldapWriteAuthArgs("ldapmodify", uri),
		input,
	)
	if exitCode != 0 || stderr != "" ||
		stdout != "ldapmodify: applied 1 record(s), 0 failed\n" {
		t.Fatalf("default modify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entry := requireLDAPWriteEntry(t, uri, dn)
	if got := entry.GetAttributeValue("cn"); got != "Default Modify" {
		t.Fatalf("default modify cn = %q", got)
	}
	if got := entry.GetAttributeValues("description"); len(got) != 1 || got[0] != "keep me" {
		t.Fatalf("default modify description = %#v", got)
	}
	if got := entry.GetAttributeValue("uidNumber"); got != "12" {
		t.Fatalf("default modify uidNumber = %q", got)
	}
}

func TestLDAPModifyDefaultModifyWireAndOpenLDAPParser(t *testing.T) {
	const dn = "uid=wire,dc=example,dc=com"
	input := "dn: " + dn + "\nreplace: cn\ncn: Wire Default\n-\n" +
		"increment: uidNumber\nuidNumber: 1\n"
	requests := make(chan ldapwire.ModifyRequest, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.ModifyRequest)
		if !ok {
			return nil, nil
		}
		requests <- request
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapmodify", "-H", fixture.uri, "-x"},
		input,
	)
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "applied 1 record") {
		t.Fatalf("wire default modify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	request := <-requests
	if request.DN != dn || len(request.Changes) != 2 ||
		request.Changes[0].Operation != ldapwire.ModificationReplace ||
		request.Changes[1].Operation != ldapwire.ModificationIncrement {
		t.Fatalf("default Modify request = %#v", request)
	}

	binary := openLDAPModifyBinary(t)
	command := exec.Command(binary, "-n")
	command.Stdin = strings.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP default modify parser error=%v output=%q", err, output)
	}
}

func openLDAPModifyBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join(os.Getenv("OPENLDAP_BUILD"), "clients", "tools", "ldapmodify"),
		filepath.Join(os.Getenv("OPENLDAP_SOURCE"), "clients", "tools", "ldapmodify"),
		"/opt/homebrew/opt/openldap/bin/ldapmodify",
	}
	if path, err := exec.LookPath("ldapmodify"); err == nil {
		candidates = append(candidates, path)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); candidate != "" && err == nil &&
			!info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	t.Skip("OpenLDAP 2.6.13 ldapmodify is unavailable")
	return ""
}

func TestLDAPModifyContinueFailureFileAndInvalidRecordSafety(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	failurePath := filepath.Join(t.TempDir(), "failed.ldif")
	continuedDN := "uid=continued," + clientToolPeopleDN
	failedPhoto := []byte{0x00, 0xff, 0x81}
	input := strings.Join([]string{
		"dn: uid=alice," + clientToolPeopleDN,
		"changetype: add",
		"objectClass: inetOrgPerson",
		"uid: alice",
		"cn: Duplicate Alice",
		"sn: Example",
		"jpegPhoto:: " + base64.StdEncoding.EncodeToString(failedPhoto),
		"",
		"dn: " + continuedDN,
		"changetype: add",
		"objectClass: inetOrgPerson",
		"uid: continued",
		"cn: Continued Example",
		"sn: Example",
		"",
	}, "\n")
	args := append(ldapWriteAuthArgs("ldapmodify", uri), "-c", "-S", failurePath)
	stdout, stderr, exitCode := runLDAPClientCommand(args, input)
	if exitCode != 1 || stdout != "ldapmodify: applied 1 record(s), 1 failed\n" ||
		!strings.Contains(stderr, "Already Exists") {
		t.Fatalf("ldapmodify -c exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stderr, clientToolRootPassword) {
		t.Fatalf("ldapmodify exposed bind password: %q", stderr)
	}
	requireLDAPWriteEntry(t, uri, continuedDN)

	info, err := os.Stat(failurePath)
	if err != nil {
		t.Fatalf("stat failure LDIF: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("failure LDIF mode = %#o, want 0600", got)
	}
	failureData, err := os.ReadFile(failurePath)
	if err != nil {
		t.Fatalf("read failure LDIF: %v", err)
	}
	if !strings.Contains(string(failureData), "jpegPhoto:: "+base64.StdEncoding.EncodeToString(failedPhoto)) {
		t.Fatalf("failure LDIF did not preserve binary value: %q", failureData)
	}
	document := &ldif.LDIF{}
	if err := ldif.Unmarshal(bytes.NewReader(failureData), document); err != nil {
		t.Fatalf("failure output is not valid LDIF: %v\n%s", err, failureData)
	}
	if len(document.Entries) != 1 || document.Entries[0].Add == nil ||
		document.Entries[0].Add.DN != "uid=alice,"+clientToolPeopleDN {
		t.Fatalf("failure LDIF entries = %#v", document.Entries)
	}

	secret := "invalid-record-secret-must-not-leak"
	invalidFailureDir := t.TempDir()
	invalidFailurePath := filepath.Join(invalidFailureDir, "invalid.ldif")
	validAfterInvalidDN := "uid=after-invalid," + clientToolPeopleDN
	invalidInput := strings.Join([]string{
		"dn: uid=invalid," + clientToolPeopleDN,
		"changetype: unsupported",
		"userPassword: " + secret,
		"",
		"dn: " + validAfterInvalidDN,
		"changetype: add",
		"objectClass: inetOrgPerson",
		"uid: after-invalid",
		"cn: After Invalid",
		"sn: Example",
		"",
	}, "\n")
	args = append(ldapWriteAuthArgs("ldapmodify", uri), "-c", "-S", invalidFailurePath)
	stdout, stderr, exitCode = runLDAPClientCommand(args, invalidInput)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "record 1: invalid LDIF syntax") {
		t.Fatalf("invalid continue exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, validAfterInvalidDN)
	if _, err := os.Stat(invalidFailurePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("syntax error created replay output: %v", err)
	}
	if strings.Contains(stderr, secret) {
		t.Fatalf("invalid record secret leaked to stderr: %q", stderr)
	}
	files, err := os.ReadDir(invalidFailureDir)
	if err != nil || len(files) != 0 {
		t.Fatalf("syntax error left failure artifacts: files=%v err=%v", files, err)
	}
}

func TestLDAPModifyIncrementAndReplayFailureLDIF(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	counterDN := "uid=counter," + clientToolPeopleDN
	addEntriesWithLDAPAdd(t, uri, posixPersonContentLDIF(counterDN, "counter", 10))
	increment := strings.Join([]string{
		"dn: " + counterDN,
		"changetype: modify",
		"increment: uidNumber",
		"uidNumber: 2",
		"-",
		"",
	}, "\n")
	stdout, stderr, exitCode := runLDAPClientCommand(
		ldapWriteAuthArgs("ldapmodify", uri),
		increment,
	)
	if exitCode != 0 || stderr != "" || stdout != "ldapmodify: applied 1 record(s), 0 failed\n" {
		t.Fatalf("increment exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if got := requireLDAPWriteEntry(t, uri, counterDN).GetAttributeValue("uidNumber"); got != "12" {
		t.Fatalf("incremented uidNumber = %q, want 12", got)
	}

	replayDN := "uid=replay-increment," + clientToolPeopleDN
	failureDir := t.TempDir()
	failurePath := filepath.Join(failureDir, "increment-failed.ldif")
	failedIncrement := strings.Join([]string{
		"dn: " + replayDN,
		"changetype: modify",
		"increment: uidNumber",
		"uidNumber: 3",
		"-",
		"",
	}, "\n")
	args := append(ldapWriteAuthArgs("ldapmodify", uri), "-S", failurePath)
	stdout, stderr, exitCode = runLDAPClientCommand(args, failedIncrement)
	if exitCode != 1 || stdout != "ldapmodify: applied 0 record(s), 1 failed\n" ||
		!strings.Contains(stderr, "No Such Object") {
		t.Fatalf("failed increment exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	failureData, err := os.ReadFile(failurePath)
	if err != nil {
		t.Fatalf("read increment replay LDIF: %v", err)
	}
	if !strings.Contains(string(failureData), "increment: uidNumber\nuidNumber: 3\n-\n") {
		t.Fatalf("increment replay LDIF is incomplete: %q", failureData)
	}
	files, err := os.ReadDir(failureDir)
	if err != nil || len(files) != 1 || files[0].Name() != filepath.Base(failurePath) {
		t.Fatalf("failure publish left temporary artifacts: files=%v err=%v", files, err)
	}

	addEntriesWithLDAPAdd(t, uri, posixPersonContentLDIF(replayDN, "replay-increment", 20))
	args = append(ldapWriteAuthArgs("ldapmodify", uri), "-f", failurePath)
	stdout, stderr, exitCode = runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapmodify: applied 1 record(s), 0 failed\n" {
		t.Fatalf("replay increment exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if got := requireLDAPWriteEntry(t, uri, replayDN).GetAttributeValue("uidNumber"); got != "23" {
		t.Fatalf("replayed uidNumber = %q, want 23", got)
	}

	for name, values := range map[string][]string{
		"no value":   nil,
		"two values": {"uidNumber: 1", "uidNumber: 2"},
	} {
		t.Run(name, func(t *testing.T) {
			lines := []string{
				"dn: " + counterDN,
				"changetype: modify",
				"increment: uidNumber",
			}
			lines = append(lines, values...)
			lines = append(lines, "-", "")
			stdout, stderr, exitCode := runLDAPClientCommand(
				[]string{"ldapmodify", "-n"},
				strings.Join(lines, "\n"),
			)
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "requires exactly one value") {
				t.Fatalf("increment validation exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
		})
	}
}

func TestLDAPWriteDryRunBoundsAndSafePaths(t *testing.T) {
	validLDIF := strings.Join([]string{
		"dn: uid=dry-run," + clientToolPeopleDN,
		"changetype: add",
		"objectClass: inetOrgPerson",
		"uid: dry-run",
		"cn: Dry Run",
		"sn: Example",
		"",
	}, "\n")
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapmodify", "-n", "-H", "ldap://127.0.0.1:1"},
		validLDIF,
	)
	if exitCode != 0 || stderr != "" || stdout != "ldapmodify: validated 1 record(s), 0 failed\n" {
		t.Fatalf("ldapmodify -n exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapmodify", "-n", "-c"},
		"dn: not a DN\nchangetype: delete\n\n"+validLDIF,
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "record 1: invalid DN") {
		t.Fatalf("ldapmodify malformed -n exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	if _, err := splitLDAPWriteRecords(bytes.Repeat([]byte{'x'}, maxLDAPWriteLineSize+1)); err == nil || !strings.Contains(err.Error(), "physical line exceeds") {
		t.Fatalf("oversized physical line error = %v", err)
	}
	var oversizedRecord bytes.Buffer
	physicalLine := bytes.Repeat([]byte{'x'}, maxLDAPWriteLineSize)
	for oversizedRecord.Len() <= maxLDAPWriteRecordSize {
		overSizedBefore := oversizedRecord.Len()
		overSizedAfter, err := oversizedRecord.Write(physicalLine)
		if err != nil || overSizedAfter != len(physicalLine) || oversizedRecord.Len() == overSizedBefore {
			t.Fatalf("build oversized record: wrote=%d err=%v", overSizedAfter, err)
		}
		overSizedBefore = oversizedRecord.Len()
		if err := oversizedRecord.WriteByte('\n'); err != nil || oversizedRecord.Len() == overSizedBefore {
			t.Fatalf("append oversized record newline: %v", err)
		}
	}
	if _, err := splitLDAPWriteRecords(oversizedRecord.Bytes()); err == nil || !strings.Contains(err.Error(), "record exceeds") {
		t.Fatalf("oversized logical record error = %v", err)
	}

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.ldif")
	if err := os.WriteFile(inputPath, []byte(validLDIF), 0o600); err != nil {
		t.Fatalf("write input LDIF: %v", err)
	}
	_, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapadd", "-n", "-f", inputPath, "-S", inputPath},
		"",
	)
	if exitCode != 1 || !strings.Contains(stderr, "must be different files") {
		t.Fatalf("same -f/-S exit=%d stderr=%q", exitCode, stderr)
	}

	wideFailurePath := filepath.Join(tempDir, "wide-failure.ldif")
	if err := os.WriteFile(wideFailurePath, nil, 0o644); err != nil {
		t.Fatalf("write wide failure file: %v", err)
	}
	if err := os.Chmod(wideFailurePath, 0o644); err != nil {
		t.Fatalf("chmod wide failure file: %v", err)
	}
	_, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapadd", "-n", "-S", wideFailurePath},
		validLDIF,
	)
	if exitCode != 1 || !strings.Contains(stderr, "permissions") {
		t.Fatalf("wide -S exit=%d stderr=%q", exitCode, stderr)
	}

	unchangedFailurePath := filepath.Join(tempDir, "unchanged-failure.ldif")
	const unchangedFailure = "existing replay data\n"
	if err := os.WriteFile(unchangedFailurePath, []byte(unchangedFailure), 0o600); err != nil {
		t.Fatalf("write existing failure file: %v", err)
	}
	_, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapmodify", "-n", "-S", unchangedFailurePath},
		"dn: invalid DN\nchangetype: delete\n\n",
	)
	if exitCode != 1 || !strings.Contains(stderr, "invalid DN") {
		t.Fatalf("syntax error with existing -S exit=%d stderr=%q", exitCode, stderr)
	}
	unchangedData, err := os.ReadFile(unchangedFailurePath)
	if err != nil || string(unchangedData) != unchangedFailure {
		t.Fatalf("syntax error changed existing -S file: data=%q err=%v", unchangedData, err)
	}

	inputLink := filepath.Join(tempDir, "input-link.ldif")
	if err := os.Symlink(inputPath, inputLink); err != nil {
		t.Fatalf("symlink input: %v", err)
	}
	_, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapadd", "-n", "-f", inputLink},
		"",
	)
	if exitCode != 1 || !strings.Contains(stderr, "non-symlink regular file") {
		t.Fatalf("symlink input exit=%d stderr=%q", exitCode, stderr)
	}

	failureTarget := filepath.Join(tempDir, "failure-target.ldif")
	if err := os.WriteFile(failureTarget, nil, 0o600); err != nil {
		t.Fatalf("write failure target: %v", err)
	}
	failureLink := filepath.Join(tempDir, "failure-link.ldif")
	if err := os.Symlink(failureTarget, failureLink); err != nil {
		t.Fatalf("symlink failure output: %v", err)
	}
	_, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapadd", "-n", "-S", failureLink},
		validLDIF,
	)
	if exitCode != 1 || !strings.Contains(stderr, "non-symlink regular file") {
		t.Fatalf("symlink -S exit=%d stderr=%q", exitCode, stderr)
	}

	realParent := filepath.Join(tempDir, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("mkdir failure parent: %v", err)
	}
	parentLink := filepath.Join(tempDir, "parent-link")
	if err := os.Symlink(realParent, parentLink); err != nil {
		t.Fatalf("symlink failure parent: %v", err)
	}
	_, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapadd", "-n", "-S", filepath.Join(parentLink, "failed.ldif")},
		validLDIF,
	)
	if exitCode != 1 || !strings.Contains(stderr, "parent directory") {
		t.Fatalf("symlink parent -S exit=%d stderr=%q", exitCode, stderr)
	}
}

func TestLDAPDeleteArgumentsInputAndRecursive(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	standaloneDN := "uid=delete-argument," + clientToolPeopleDN
	firstInputDN := "uid=delete-input-one," + clientToolPeopleDN
	secondInputDN := "uid=delete-input-two," + clientToolPeopleDN
	projectDN := "ou=project," + clientToolBaseDN
	childDN := "ou=child," + projectDN
	leafDN := "uid=leaf," + childDN
	addEntriesWithLDAPAdd(t, uri,
		personContentLDIF(standaloneDN, "delete-argument", "Delete Argument"),
		personContentLDIF(firstInputDN, "delete-input-one", "Delete Input One"),
		personContentLDIF(secondInputDN, "delete-input-two", "Delete Input Two"),
		organizationalUnitContentLDIF(projectDN, "project"),
		organizationalUnitContentLDIF(childDN, "child"),
		personContentLDIF(leafDN, "leaf", "Leaf Entry"),
	)

	args := append(ldapWriteAuthArgs("ldapdelete", uri), standaloneDN)
	stdout, stderr, exitCode := runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapdelete: deleted 1 entry(s)\n" {
		t.Fatalf("ldapdelete argument exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, standaloneDN)

	deletePath := filepath.Join(t.TempDir(), "delete-dns.txt")
	if err := os.WriteFile(deletePath, []byte("# delete from file\n"+firstInputDN+"\r\n"), 0o600); err != nil {
		t.Fatalf("write ldapdelete input: %v", err)
	}
	args = append(ldapWriteAuthArgs("ldapdelete", uri), "-f", deletePath)
	stdout, stderr, exitCode = runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapdelete: deleted 1 entry(s)\n" {
		t.Fatalf("ldapdelete -f exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, firstInputDN)

	lineInput := "# delete from stdin\n\n" + secondInputDN + "\n"
	stdout, stderr, exitCode = runLDAPClientCommand(ldapWriteAuthArgs("ldapdelete", uri), lineInput)
	if exitCode != 0 || stderr != "" || stdout != "ldapdelete: deleted 1 entry(s)\n" {
		t.Fatalf("ldapdelete stdin exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, secondInputDN)

	args = append(ldapWriteAuthArgs("ldapdelete", uri), "-r", projectDN)
	stdout, stderr, exitCode = runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapdelete: deleted 3 entry(s)\n" {
		t.Fatalf("ldapdelete -r exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, dn := range []string{leafDN, childDN, projectDN} {
		assertLDAPWriteEntryAbsent(t, uri, dn)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapdelete", "-n", "uid=dry-delete," + clientToolPeopleDN},
		"",
	)
	if exitCode != 0 || stderr != "" || stdout != "ldapdelete: validated 1 entry(s)\n" {
		t.Fatalf("ldapdelete -n exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPModRDNArgumentsPairsAndNewSuperior(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	firstDN := "uid=rename-one," + clientToolPeopleDN
	renamedFirstDN := "uid=renamed-one," + clientToolPeopleDN
	secondDN := "uid=rename-two," + clientToolPeopleDN
	renamedSecondDN := "uid=renamed-two," + clientToolPeopleDN
	archiveDN := "ou=archive," + clientToolBaseDN
	archivedDN := "uid=archived," + archiveDN
	addEntriesWithLDAPAdd(t, uri,
		organizationalUnitContentLDIF(archiveDN, "archive"),
		personContentLDIF(firstDN, "rename-one", "Rename One"),
		personContentLDIF(secondDN, "rename-two", "Rename Two"),
	)

	args := append(ldapWriteAuthArgs("ldapmodrdn", uri), "-r", firstDN, "uid=renamed-one")
	stdout, stderr, exitCode := runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapmodrdn: modified 1 entry(s)\n" {
		t.Fatalf("ldapmodrdn arguments exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, firstDN)
	requireLDAPWriteEntry(t, uri, renamedFirstDN)

	stdout, stderr, exitCode = runLDAPClientCommand(
		ldapWriteAuthArgs("ldapmodrdn", uri),
		"# rename second entry\n"+secondDN+"\nuid=renamed-two\n",
	)
	if exitCode != 0 || stderr != "" || stdout != "ldapmodrdn: modified 1 entry(s)\n" {
		t.Fatalf("ldapmodrdn pairs exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, secondDN)
	requireLDAPWriteEntry(t, uri, renamedSecondDN)

	args = append(ldapWriteAuthArgs("ldapmodrdn", uri), "-r", "-s", archiveDN, renamedFirstDN, "uid=archived")
	stdout, stderr, exitCode = runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapmodrdn: modified 1 entry(s)\n" {
		t.Fatalf("ldapmodrdn -s exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPWriteEntryAbsent(t, uri, renamedFirstDN)
	requireLDAPWriteEntry(t, uri, archivedDN)

	modrdnLDIF := strings.Join([]string{
		"dn: " + archivedDN,
		"changetype: modrdn",
		"newrdn: uid=validated",
		"deleteoldrdn: 1",
		"newsuperior: " + clientToolPeopleDN,
		"",
	}, "\n")
	stdout, stderr, exitCode = runLDAPClientCommand([]string{"ldapmodify", "-n"}, modrdnLDIF)
	if exitCode != 0 || stderr != "" || stdout != "ldapmodify: validated 1 record(s), 0 failed\n" {
		t.Fatalf("modrdn LDIF dry-run exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPWriteStartTLSAndPromptPasswordLeavesInput(t *testing.T) {
	tlsConfig, caPEM := newLDAPClientToolTLSConfig(t)
	uri := startLDAPClientToolServer(t, tlsConfig)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	tlsDN := "uid=starttls-write," + clientToolPeopleDN
	tlsInput := personContentLDIF(tlsDN, "starttls-write", "StartTLS Write")
	args := append(ldapWriteAuthArgs("ldapadd", uri),
		"-ZZ", "-tls-ca", caPath, "-tls-server-name", "localhost")
	stdout, stderr, exitCode := runLDAPClientCommand(args, tlsInput)
	if exitCode != 0 || stderr != "" || stdout != "ldapadd: applied 1 record(s), 0 failed\n" {
		t.Fatalf("StartTLS ldapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	requireLDAPWriteEntry(t, uri, tlsDN)

	promptDN := "uid=prompt-write," + clientToolPeopleDN
	promptInput := clientToolRootPassword + "\r\n" +
		personContentLDIF(promptDN, "prompt-write", "Prompt Write")
	promptArgs := []string{
		"ldapadd", "-H", uri, "-x", "-D", clientToolRootDN, "-W",
		"-ZZ", "-tls-ca", caPath, "-tls-server-name", "localhost",
	}
	stdout, stderr, exitCode = runLDAPClientCommand(promptArgs, promptInput)
	if exitCode != 0 || stderr != "Enter LDAP Password: " ||
		stdout != "ldapadd: applied 1 record(s), 0 failed\n" {
		t.Fatalf("prompt ldapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	requireLDAPWriteEntry(t, uri, promptDN)

	reader := strings.NewReader("first-secret\r\nnext LDIF line\n")
	password, err := readLDAPPasswordLine(reader)
	if err != nil {
		t.Fatalf("readLDAPPasswordLine: %v", err)
	}
	defer clear(password)
	if string(password) != "first-secret" {
		t.Fatalf("password = %q", password)
	}
	remainder, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read password remainder: %v", err)
	}
	if string(remainder) != "next LDIF line\n" {
		t.Fatalf("password reader consumed remainder: %q", remainder)
	}

	oversized := strings.NewReader(strings.Repeat("x", maxPasswordInputSize+1) + "\nremaining")
	password, err = readLDAPPasswordLine(oversized)
	if password != nil || err == nil || !strings.Contains(err.Error(), "exceeds 1048576 bytes") {
		t.Fatalf("oversized prompt password = %d bytes, %v", len(password), err)
	}
}

func TestLDAPWriteRejectsConflictingAndUnsupportedOptions(t *testing.T) {
	validLDIF := personContentLDIF(
		"uid=options,"+clientToolPeopleDN,
		"options",
		"Options Entry",
	)
	tests := []struct {
		name    string
		args    []string
		stdin   string
		message string
	}{
		{name: "modify named control", args: []string{"ldapmodify", "-n", "-E", "noop"}, stdin: validLDIF, message: "invalid LDAP control OID"},
		{name: "modify content", args: []string{"ldapmodify", "-n"}, stdin: validLDIF, message: "unsupported modify change"},
		{name: "modify false add mode", args: []string{"ldapmodify", "-n", "-a=false"}, stdin: validLDIF, message: "-a=false is not supported"},
		{name: "add arguments", args: []string{"ldapadd", "-n", "extra"}, stdin: validLDIF, message: "unexpected arguments"},
		{name: "delete input conflict", args: []string{"ldapdelete", "-n", "-f", "input", "dc=example,dc=com"}, message: "mutually exclusive"},
		{name: "delete named control", args: []string{"ldapdelete", "-n", "-E", "noop", "dc=example,dc=com"}, message: "invalid LDAP control OID"},
		{name: "modrdn odd input", args: []string{"ldapmodrdn", "-n"}, stdin: "uid=old,dc=example,dc=com\n", message: "must contain old DN/new RDN pairs"},
		{name: "modrdn bad superior", args: []string{"ldapmodrdn", "-n", "-s", "not-a-dn", "uid=old,dc=example,dc=com", "uid=new"}, message: "invalid new superior DN"},
		{name: "SASL", args: []string{"ldapadd", "-Y", "PLAIN", "-n"}, stdin: validLDIF, message: "option -Y is not supported"},
		{name: "false dry-run", args: []string{"ldapadd", "-n=false"}, stdin: validLDIF, message: "-n=false is not supported"},
		{name: "dry-run URI", args: []string{"ldapadd", "-n", "-H", "https://localhost"}, stdin: validLDIF, message: "must use an ldap:// or ldaps:// URI"},
		{name: "dry-run TLS options", args: []string{"ldapadd", "-n", "-tls-server-name", "localhost"}, stdin: validLDIF, message: "TLS options require"},
		{name: "remote URL value", args: []string{"ldapadd", "-n"}, stdin: "dn: uid=url," + clientToolPeopleDN + "\ncn:< https://example.test/value\n\n", message: "local file:// absolute URL"},
		{name: "misplaced request control", args: []string{"ldapmodify", "-n"}, stdin: "dn: uid=x," + clientToolPeopleDN + "\nchangetype: delete\ncontrol: 1.2.3\n\n", message: "must follow dn before changetype"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exitCode := runLDAPClientCommand(test.args, test.stdin)
			if exitCode != 1 || !strings.Contains(stderr, test.message) {
				t.Fatalf("run(%v) exit=%d stdout=%q stderr=%q", test.args, exitCode, stdout, stderr)
			}
		})
	}

	stdout, stderr, exitCode := runLDAPClientCommand([]string{"help"}, "")
	if exitCode != 0 || stderr != "" {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, command := range []string{"ldapadd", "ldapmodify", "ldapdelete", "ldapmodrdn"} {
		if !strings.Contains(stdout, command) {
			t.Errorf("help does not list %s: %q", command, stdout)
		}
	}
}

func ldapWriteAuthArgs(command, uri string) []string {
	return []string{
		command,
		"-H", uri,
		"-x",
		"-D", clientToolRootDN,
		"-w", clientToolRootPassword,
	}
}

func personContentLDIF(dn, uid, commonName string) string {
	return strings.Join([]string{
		"dn: " + dn,
		"objectClass: inetOrgPerson",
		"uid: " + uid,
		"cn: " + commonName,
		"sn: Example",
		"",
	}, "\n")
}

func posixPersonContentLDIF(dn, uid string, uidNumber int) string {
	return strings.Join([]string{
		"dn: " + dn,
		"objectClass: inetOrgPerson",
		"objectClass: posixAccount",
		"uid: " + uid,
		"cn: " + uid,
		"sn: Example",
		fmt.Sprintf("uidNumber: %d", uidNumber),
		"gidNumber: 10",
		"homeDirectory: /home/" + uid,
		"",
	}, "\n")
}

func organizationalUnitContentLDIF(dn, name string) string {
	return strings.Join([]string{
		"dn: " + dn,
		"objectClass: organizationalUnit",
		"ou: " + name,
		"",
	}, "\n")
}

func addEntriesWithLDAPAdd(t *testing.T, uri string, records ...string) {
	t.Helper()
	stdout, stderr, exitCode := runLDAPClientCommand(
		ldapWriteAuthArgs("ldapadd", uri),
		strings.Join(records, "\n"),
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("seed with ldapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func requireLDAPWriteEntry(t *testing.T, uri, dn string) *ldap.Entry {
	t.Helper()
	entry, found := lookupLDAPWriteEntry(t, uri, dn)
	if !found {
		t.Fatalf("LDAP entry %q does not exist", dn)
	}
	return entry
}

func assertLDAPWriteEntryAbsent(t *testing.T, uri, dn string) {
	t.Helper()
	if _, found := lookupLDAPWriteEntry(t, uri, dn); found {
		t.Fatalf("LDAP entry %q still exists", dn)
	}
}

func lookupLDAPWriteEntry(t *testing.T, uri, dn string) (*ldap.Entry, bool) {
	t.Helper()
	connection, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial LDAP test server: %v", err)
	}
	defer connection.Close()
	if err := connection.Bind(clientToolRootDN, clientToolRootPassword); err != nil {
		t.Fatalf("bind LDAP test server: %v", err)
	}
	result, err := connection.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("search LDAP entry %q: %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("search LDAP entry %q returned %d entries", dn, len(result.Entries))
	}
	return result.Entries[0], true
}
