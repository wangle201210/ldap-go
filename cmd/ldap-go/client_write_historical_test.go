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

func TestLDAPModifyVerboseDryRunMatchesOpenLDAP213(t *testing.T) {
	ldapmodify := openLDAPModify213Binary(t)
	input := "dn: uid=verbose,dc=example,dc=com\n" +
		"changetype: add\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: verbose\n" +
		"cn: Verbose User\n" +
		"sn: User\n" +
		"description:: w78=\n\n" +
		"dn: uid=verbose,dc=example,dc=com\n" +
		"changetype: modify\n" +
		"replace: cn\n" +
		"cn: Renamed User\n" +
		"-\n" +
		"delete: description\n" +
		"-\n\n" +
		"dn: uid=gone,dc=example,dc=com\n" +
		"changetype: delete\n\n" +
		"dn: uid=rename,dc=example,dc=com\n" +
		"changetype: modrdn\n" +
		"newrdn: uid=renamed\n" +
		"deleteoldrdn: 1\n" +
		"newsuperior: ou=people,dc=example,dc=com\n\n"

	command := exec.Command(ldapmodify, "-n", "-v")
	command.Stdin = strings.NewReader(input)
	var referenceStdout, referenceStderr bytes.Buffer
	command.Stdout = &referenceStdout
	command.Stderr = &referenceStderr
	if err := command.Run(); err != nil {
		t.Fatalf(
			"OpenLDAP 2.6.13 ldapmodify -n -v: %v stdout=%q stderr=%q",
			err,
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapmodify", "-n", "-v"},
		input,
	)
	if exitCode != 0 || stderr != referenceStderr.String() ||
		stdout != referenceStdout.String() {
		t.Fatalf(
			"verbose dry-run differs: exit=%d stdout=%q stderr=%q; OpenLDAP stdout=%q stderr=%q",
			exitCode,
			stdout,
			stderr,
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}
}

func TestLDAPAddVerboseCompletionAndFailure(t *testing.T) {
	input := "dn: uid=verbose-add,dc=example,dc=com\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: verbose-add\n" +
		"cn: Verbose Add\n" +
		"sn: Add\n\n"
	for _, test := range []struct {
		name       string
		resultCode ldapwire.ResultCode
		wantExit   int
		completion string
	}{
		{name: "success", resultCode: ldapwire.ResultSuccess, wantExit: 0, completion: "modify complete\n"},
		{name: "failure", resultCode: ldapwire.ResultEntryAlreadyExists, wantExit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
				if _, ok := message.Request.(ldapwire.AddRequest); !ok {
					return nil, nil
				}
				return [][]byte{ldapwire.EncodeResultResponse(
					message.ID,
					ldapwire.ApplicationAddResponse,
					ldapwire.Result{Code: test.resultCode},
					nil,
				)}, nil
			})
			stdout, stderr, exitCode := runLDAPClientCommand([]string{
				"ldapadd", "-H", fixture.uri, "-x", "-v",
			}, input)
			if exitCode != test.wantExit ||
				!strings.Contains(stdout, "adding new entry \"uid=verbose-add,dc=example,dc=com\"\n") ||
				strings.Contains(stdout, "ldapadd: applied") ||
				strings.Contains(stdout, "modify complete\n") != (test.completion != "") {
				t.Fatalf(
					"verbose ldapadd exit=%d stdout=%q stderr=%q",
					exitCode,
					stdout,
					stderr,
				)
			}
		})
	}
}

func TestLDAPModifyVerboseNetworkMatchesOpenLDAP213(t *testing.T) {
	ldapmodify := openLDAPModify213Binary(t)
	input := "dn: uid=verbose-network,dc=example,dc=com\n" +
		"changetype: add\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: verbose-network\n" +
		"cn: Verbose Network\n" +
		"sn: Network\n\n"

	referenceRequests := make(chan ldapwire.Message, 1)
	referenceFixture := startLDAPClientWireFixture(t, ldapModifyAddCaptureHandler(referenceRequests))
	command := exec.Command(
		ldapmodify,
		"-H", referenceFixture.uri,
		"-x",
		"-v",
		"-MM",
	)
	command.Stdin = strings.NewReader(input)
	var referenceStdout, referenceStderr bytes.Buffer
	command.Stdout = &referenceStdout
	command.Stderr = &referenceStderr
	if err := command.Run(); err != nil {
		t.Fatalf(
			"OpenLDAP 2.6.13 verbose network modify: %v stdout=%q stderr=%q",
			err,
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}
	referenceMessage := awaitLDAPClientWireMessage(t, referenceRequests)

	implementationRequests := make(chan ldapwire.Message, 1)
	implementationFixture := startLDAPClientWireFixture(t, ldapModifyAddCaptureHandler(implementationRequests))
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapmodify",
		"-H", implementationFixture.uri,
		"-x",
		"-v",
		"-MM",
	}, input)
	wantReferenceStderr := "ldap_initialize( " + referenceFixture.uri + "/??base )\n"
	wantImplementationStderr := "ldap_initialize( " + implementationFixture.uri + "/??base )\n"
	if exitCode != 0 || stdout != referenceStdout.String() ||
		referenceStderr.String() != wantReferenceStderr ||
		stderr != wantImplementationStderr {
		t.Fatalf(
			"verbose network differs: exit=%d stdout=%q stderr=%q want-stderr=%q; OpenLDAP stdout=%q stderr=%q want-stderr=%q",
			exitCode,
			stdout,
			stderr,
			wantImplementationStderr,
			referenceStdout.String(),
			referenceStderr.String(),
			wantReferenceStderr,
		)
	}
	implementationMessage := awaitLDAPClientWireMessage(t, implementationRequests)
	for name, message := range map[string]ldapwire.Message{
		"OpenLDAP": referenceMessage,
		"ldap-go":  implementationMessage,
	} {
		assertLDAPWireControl(
			t,
			message.Controls,
			ldapManageDsaITOID,
			true,
			false,
			nil,
		)
		if len(message.Controls) != 1 {
			t.Fatalf("%s controls = %#v", name, message.Controls)
		}
	}
}

func TestLDAPModifyManageDsaITMatchesOpenLDAP213(t *testing.T) {
	ldapmodify := openLDAPModify213Binary(t)
	input := "dn: uid=managed,dc=example,dc=com\nchangetype: delete\n\n"
	for _, test := range []struct {
		name     string
		options  []string
		critical bool
	}{
		{name: "noncritical", options: []string{"-M"}},
		{name: "critical", options: []string{"-MM"}, critical: true},
		{name: "repeated is critical", options: []string{"-M", "-M"}, critical: true},
		{name: "combined is critical", options: []string{"-M", "-MM"}, critical: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			referenceRequests := make(chan ldapwire.Message, 1)
			referenceFixture := startLDAPClientWireFixture(t, ldapModifyDeleteCaptureHandler(referenceRequests))
			referenceArgs := []string{"-H", referenceFixture.uri, "-x"}
			referenceArgs = append(referenceArgs, test.options...)
			command := exec.Command(ldapmodify, referenceArgs...)
			command.Stdin = strings.NewReader(input)
			var referenceStdout, referenceStderr bytes.Buffer
			command.Stdout = &referenceStdout
			command.Stderr = &referenceStderr
			if err := command.Run(); err != nil {
				t.Fatalf(
					"OpenLDAP 2.6.13 ldapmodify %v: %v stdout=%q stderr=%q",
					test.options,
					err,
					referenceStdout.String(),
					referenceStderr.String(),
				)
			}
			referenceMessage := awaitLDAPClientWireMessage(t, referenceRequests)

			implementationRequests := make(chan ldapwire.Message, 1)
			implementationFixture := startLDAPClientWireFixture(t, ldapModifyDeleteCaptureHandler(implementationRequests))
			implementationArgs := []string{"ldapmodify", "-H", implementationFixture.uri, "-x"}
			implementationArgs = append(implementationArgs, test.options...)
			stdout, stderr, exitCode := runLDAPClientCommand(implementationArgs, input)
			if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "applied 1 record") {
				t.Fatalf(
					"ldap-go ldapmodify %v exit=%d stdout=%q stderr=%q",
					test.options,
					exitCode,
					stdout,
					stderr,
				)
			}
			implementationMessage := awaitLDAPClientWireMessage(t, implementationRequests)

			for name, message := range map[string]ldapwire.Message{
				"OpenLDAP": referenceMessage,
				"ldap-go":  implementationMessage,
			} {
				if len(message.Controls) != 1 {
					t.Fatalf("%s controls = %#v", name, message.Controls)
				}
				assertLDAPWireControl(
					t,
					message.Controls,
					ldapManageDsaITOID,
					test.critical,
					false,
					nil,
				)
			}
		})
	}
}

func TestLDAPModifyHistoricalOptionValidationPrecedesIO(t *testing.T) {
	validInput := "dn: uid=managed,dc=example,dc=com\nchangetype: delete\n\n"
	for _, test := range []struct {
		name    string
		args    []string
		message string
	}{
		{
			name:    "verbose false before connection and input",
			args:    []string{"ldapmodify", "-v=false", "-H", "https://invalid", "-f", "/missing"},
			message: "-v=false is not supported",
		},
		{
			name:    "manage false before connection and input",
			args:    []string{"ldapmodify", "-M=false", "-H", "https://invalid", "-f", "/missing"},
			message: "-M=false is not supported",
		},
		{
			name:    "critical manage false before connection and input",
			args:    []string{"ldapmodify", "-MM=false", "-H", "https://invalid", "-f", "/missing"},
			message: "-MM=false is not supported",
		},
		{
			name: "duplicate manage control before connection",
			args: []string{
				"ldapmodify", "-M", "-e", ldapManageDsaITOID,
				"-H", "ldap://127.0.0.1:1", "-x",
			},
			message: "was provided more than once",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exitCode := runLDAPClientCommand(test.args, validInput)
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf(
					"validation exit=%d stdout=%q stderr=%q",
					exitCode,
					stdout,
					stderr,
				)
			}
			for _, unexpected := range []string{"connect to", "read LDIF", "must use an ldap://"} {
				if strings.Contains(stderr, unexpected) {
					t.Fatalf("validation reached I/O/configuration: %q", stderr)
				}
			}
		})
	}
}

func ldapModifyDeleteCaptureHandler(
	requests chan<- ldapwire.Message,
) ldapClientWireHandler {
	return func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.DeleteRequest); !ok {
			return nil, nil
		}
		requests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	}
}

func ldapModifyAddCaptureHandler(
	requests chan<- ldapwire.Message,
) ldapClientWireHandler {
	return func(message ldapwire.Message) ([][]byte, error) {
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
	}
}

func openLDAPModify213Binary(t *testing.T) string {
	t.Helper()
	ldapmodify := openLDAPModifyBinary(t)
	output, err := exec.Command(ldapmodify, "-VV").CombinedOutput()
	if err != nil {
		t.Skipf("cannot identify OpenLDAP ldapmodify: %v: %s", err, output)
	}
	if !bytes.Contains(output, []byte("OpenLDAP: ldapmodify 2.6.13")) ||
		!bytes.Contains(output, []byte("OpenLDAP 20613")) {
		t.Skipf("requires OpenLDAP ldapmodify 2.6.13, got: %s", output)
	}
	return ldapmodify
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
