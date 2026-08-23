package main

import (
	"bytes"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPModifyJumpFileURLAndRecordControls(t *testing.T) {
	value := []byte{0xde, 0xad, 0x00, 0xbe, 0xef}
	valuePath := filepath.Join(t.TempDir(), "value.bin")
	if err := os.WriteFile(valuePath, value, 0o600); err != nil {
		t.Fatalf("write external value: %v", err)
	}
	fileURI := (&url.URL{Scheme: "file", Path: valuePath}).String()

	requests := make(chan ldapwire.Message, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.AddRequest); !ok {
			return nil, nil
		}
		requests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	input := "this skipped record is invalid\n\n" +
		"dn: uid=file-control," + clientToolPeopleDN + "\n" +
		"control: 1.2.3 true:: AAE=\n" +
		"control: 1.2.4 false:< " + fileURI + "\n" +
		"changetype: add\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: file-control\n" +
		"cn: File Control\n" +
		"sn: Control\n" +
		"jpegPhoto:< " + fileURI + "\n\n"
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapmodify", "-H", fixture.uri, "-x", "-j", "3",
	}, input)
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "applied 1 record") {
		t.Fatalf("ldapmodify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	message := awaitLDAPClientWireMessage(t, requests)
	request := message.Request.(ldapwire.AddRequest)
	if got := request.Entry.Values("jpegPhoto"); len(got) != 1 || !bytes.Equal(got[0], value) {
		t.Fatalf("jpegPhoto = %x, want %x", got, value)
	}
	assertLDAPWireControl(t, message.Controls, "1.2.3", true, true, []byte{0, 1})
	assertLDAPWireControl(t, message.Controls, "1.2.4", false, true, value)
}

func TestLDAPModifyFileURLRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	fileURI := (&url.URL{Scheme: "file", Path: link}).String()
	input := "dn: uid=symlink," + clientToolPeopleDN + "\n" +
		"changetype: add\nobjectClass: inetOrgPerson\nuid: symlink\n" +
		"cn:< " + fileURI + "\nsn: Symlink\n\n"
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapmodify", "-n"}, input,
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "non-symlink regular file") {
		t.Fatalf("ldapmodify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPModifyFailureFilePreservesRecordControls(t *testing.T) {
	failurePath := filepath.Join(t.TempDir(), "failed.ldif")
	failedRequests := make(chan ldapwire.Message, 1)
	failingFixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.AddRequest); !ok {
			return nil, nil
		}
		failedRequests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.Result{Code: ldapwire.ResultEntryAlreadyExists},
			nil,
		)}, nil
	})
	input := "dn: uid=controlled-failure," + clientToolPeopleDN + "\n" +
		"control: 1.2.3 true:: AAE=\n" +
		"control: 1.2.4 false\n" +
		"changetype: add\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: controlled-failure\n" +
		"cn: Controlled Failure\n" +
		"sn: Failure\n\n"
	stdout, _, exitCode := runLDAPClientCommand([]string{
		"ldapmodify", "-H", failingFixture.uri, "-x", "-S", failurePath,
	}, input)
	if exitCode != 1 || stdout != "ldapmodify: applied 0 record(s), 1 failed\n" {
		t.Fatalf("failing ldapmodify exit=%d stdout=%q", exitCode, stdout)
	}
	failedMessage := awaitLDAPClientWireMessage(t, failedRequests)
	assertLDAPWireControl(t, failedMessage.Controls, "1.2.3", true, true, []byte{0, 1})
	assertLDAPWireControl(t, failedMessage.Controls, "1.2.4", false, false, nil)

	failureData, err := os.ReadFile(failurePath)
	if err != nil {
		t.Fatalf("read failure LDIF: %v", err)
	}
	for _, expected := range []string{
		"control: 1.2.3 true:: AAE=",
		"control: 1.2.4 false",
	} {
		if !bytes.Contains(failureData, []byte(expected)) {
			t.Fatalf("failure LDIF omitted %q:\n%s", expected, failureData)
		}
	}

	replayedRequests := make(chan ldapwire.Message, 1)
	replayFixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.AddRequest); !ok {
			return nil, nil
		}
		replayedRequests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapmodify", "-H", replayFixture.uri, "-x", "-f", failurePath,
	}, "")
	if exitCode != 0 || stderr != "" || stdout != "ldapmodify: applied 1 record(s), 0 failed\n" {
		t.Fatalf("replay exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	replayedMessage := awaitLDAPClientWireMessage(t, replayedRequests)
	assertLDAPWireControl(t, replayedMessage.Controls, "1.2.3", true, true, []byte{0, 1})
	assertLDAPWireControl(t, replayedMessage.Controls, "1.2.4", false, false, nil)
}

func TestLDAPModifyExternalValuesEnforceCumulativeRecordLimit(t *testing.T) {
	valuePath := filepath.Join(t.TempDir(), "large-value.bin")
	value := bytes.Repeat([]byte{'x'}, maxLDAPWriteRecordSize/2+1)
	if err := os.WriteFile(valuePath, value, 0o600); err != nil {
		t.Fatalf("write external value: %v", err)
	}
	clear(value)
	fileURI := (&url.URL{Scheme: "file", Path: valuePath}).String()
	input := "dn: uid=cumulative-limit," + clientToolPeopleDN + "\n" +
		"changetype: add\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: cumulative-limit\n" +
		"cn: Cumulative Limit\n" +
		"sn: Limit\n" +
		"jpegPhoto:< " + fileURI + "\n" +
		"audio:< " + fileURI + "\n\n"
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapmodify", "-n"},
		input,
	)
	if exitCode != 1 || stdout != "" ||
		!strings.Contains(stderr, "expanded LDIF record exceeds") {
		t.Fatalf("ldapmodify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPModifyJumpPastAllRecordsIsSuccessfulNoOp(t *testing.T) {
	input := "dn: uid=skipped," + clientToolPeopleDN + "\n" +
		"changetype: delete\n\n"
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapmodify", "-n", "-j", "999"},
		input,
	)
	if exitCode != 0 || stderr != "" ||
		stdout != "ldapmodify: validated 0 record(s), 0 failed\n" {
		t.Fatalf("ldapmodify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOpenLDAPReferenceLDAPModifyJumpAndFileURL(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") != "1" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP ldapmodify differential")
	}
	if commit := os.Getenv("OPENLDAP_VERIFIED_COMMIT"); commit != "d172686d3d270bc961b78f3ff00d7019c8dfb094" {
		t.Skipf("requires verified OpenLDAP 2.6.13 commit, got %q", commit)
	}
	ldapmodify := os.Getenv("OPENLDAP_LDAPMODIFY")
	if ldapmodify == "" {
		var err error
		ldapmodify, err = exec.LookPath("ldapmodify")
		if err != nil {
			t.Skipf("OpenLDAP ldapmodify is unavailable: %v", err)
		}
	}
	if _, err := os.Stat(ldapmodify); err != nil {
		t.Skipf("OpenLDAP ldapmodify is unavailable: %v", err)
	}
	directory := t.TempDir()
	valuePath := filepath.Join(directory, "value")
	if err := os.WriteFile(valuePath, []byte("External Value"), 0o600); err != nil {
		t.Fatalf("write value: %v", err)
	}
	inputPath := filepath.Join(directory, "changes.ldif")
	input := "invalid skipped record\n\n" +
		"dn: uid=file,dc=example,dc=com\n" +
		"control: 1.2.3 true:: AAE=\nchangetype: add\n" +
		"objectClass: inetOrgPerson\nuid: file\ncn:< " +
		(&url.URL{Scheme: "file", Path: valuePath}).String() + "\nsn: Value\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatalf("write LDIF: %v", err)
	}
	output, err := exec.Command(ldapmodify, "-n", "-j", "3", "-f", inputPath).CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("adding new entry")) {
		t.Fatalf("OpenLDAP ldapmodify -j/file URL: %v\n%s", err, output)
	}

	referenceRequests := make(chan ldapwire.Message, 1)
	referenceFixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.AddRequest); !ok {
			return nil, nil
		}
		referenceRequests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID, ldapwire.ApplicationAddResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess}, nil,
		)}, nil
	})
	referenceOutput, err := exec.Command(
		ldapmodify, "-H", referenceFixture.uri, "-x", "-j", "3", "-f", inputPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP wire ldapmodify: %v\n%s", err, referenceOutput)
	}
	referenceMessage := awaitLDAPClientWireMessage(t, referenceRequests)

	implementationRequests := make(chan ldapwire.Message, 1)
	implementationFixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.AddRequest); !ok {
			return nil, nil
		}
		implementationRequests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID, ldapwire.ApplicationAddResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess}, nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapmodify", "-H", implementationFixture.uri, "-x",
		"-j", "3", "-f", inputPath,
	}, "")
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "applied 1 record") {
		t.Fatalf("ldap-go ldapmodify exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	implementationMessage := awaitLDAPClientWireMessage(t, implementationRequests)
	for name, message := range map[string]ldapwire.Message{
		"OpenLDAP": referenceMessage, "ldap-go": implementationMessage,
	} {
		request := message.Request.(ldapwire.AddRequest)
		if got := request.Entry.Values("cn"); len(got) != 1 || string(got[0]) != "External Value" {
			t.Fatalf("%s external cn = %q", name, got)
		}
		assertLDAPWireControl(t, message.Controls, "1.2.3", true, true, []byte{0, 1})
	}
}
