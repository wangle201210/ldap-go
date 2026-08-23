package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPCompareHistoricalExtensionIsUnrecognized(t *testing.T) {
	const dn = "uid=alice,dc=example,dc=com"
	for _, test := range []struct {
		name    string
		options []string
	}{
		{name: "documented critical control", options: []string{"-E", "!dontUseCopy"}},
		{name: "bare", options: []string{"-E"}},
		{name: "compact", options: []string{"-E!dontUseCopy"}},
		{name: "compact value", options: []string{"-E=!dontUseCopy"}},
		{name: "missing criticality", options: []string{"-E", "dontUseCopy"}},
		{name: "unexpected value", options: []string{"-E", "!dontUseCopy=value"}},
		{name: "unknown", options: []string{"-E", "!unknown"}},
		{name: "repeated", options: []string{"-E", "!dontUseCopy", "-E", "!dontUseCopy"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []string{"ldapcompare", "-H", "ldap://127.0.0.1:1", "-x"}
			args = append(args, test.options...)
			args = append(args, dn, "uid:alice")
			stdout, stderr, exitCode := runLDAPClientCommand(args, "")
			if exitCode != 1 || stdout != "" ||
				!strings.Contains(stderr, "ldapcompare: unrecognized option -E") ||
				!strings.Contains(stderr, "usage: ldapcompare [options]") ||
				!strings.Contains(stderr, "!dontUseCopy") {
				t.Fatalf(
					"ldapcompare -E exit=%d stdout=%q stderr=%q",
					exitCode,
					stdout,
					stderr,
				)
			}
			if strings.Contains(stderr, "connect to") {
				t.Fatalf("ldapcompare -E used a non-reference path: %q", stderr)
			}
		})
	}
}

func TestOpenLDAPLDAPCompareHistoricalExtensionBehavior(t *testing.T) {
	ldapcompare := openLDAPCompareBinary(t)
	for _, options := range [][]string{
		{"-E"},
		{"-E!dontUseCopy"},
		{"-E=!dontUseCopy"},
		{"-E", "!dontUseCopy"},
		{"-E", "dontUseCopy"},
		{"-E", "!dontUseCopy=value"},
		{"-E", "!unknown"},
		{"-E", "!dontUseCopy", "-E", "!dontUseCopy"},
	} {
		command := exec.Command(ldapcompare, options...)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 1 || stdout.Len() != 0 ||
			!strings.Contains(stderr.String(), "unrecognized option -E") ||
			!strings.Contains(stderr.String(), "usage: ldapcompare [options]") {
			t.Fatalf(
				"OpenLDAP ldapcompare %q error=%v stdout=%q stderr=%q",
				options,
				err,
				stdout.String(),
				stderr.String(),
			)
		}
	}
}

func TestLDAPCompareVerboseLDAPResultDetailsAndControls(t *testing.T) {
	const (
		dn        = "uid=missing,dc=example,dc=com"
		matchedDN = "dc=example,dc=com"
		referral  = "ldap://provider.example/dc=example,dc=com"
	)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.UnbindRequest); ok {
			return [][]byte{{}}, nil
		}
		if _, ok := message.Request.(ldapwire.CompareRequest); !ok {
			return nil, nil
		}
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.Result{
				Code:              ldapwire.ResultNoSuchObject,
				MatchedDN:         matchedDN,
				DiagnosticMessage: "missing compare target",
				Referrals:         []string{referral},
			},
			[]ldapwire.Control{{
				OID:      "1.2.3",
				Critical: true,
				Value:    []byte{0, 1, 2},
				HasValue: true,
			}},
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapcompare", "-H", fixture.uri, "-x", "-v", dn, "uid:missing",
	}, "")
	wantStdout := "Compare Result: No such object (32)\n" +
		"Additional info: missing compare target\n" +
		"Matched DN: " + matchedDN + "\n" +
		"Referral: " + referral + "\n" +
		"UNDEFINED\n" +
		"control: 1.2.3 false AAEC\n"
	if exitCode != ldap.LDAPResultNoSuchObject || stdout != wantStdout ||
		stderr != "DN:"+dn+", attr:uid, value:missing\n" {
		t.Fatalf("verbose result exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	command := exec.Command(
		openLDAPCompareBinary(t),
		"-H", fixture.uri, "-x", "-v", dn, "uid:missing",
	)
	var referenceStdout, referenceStderr bytes.Buffer
	command.Stdout = &referenceStdout
	command.Stderr = &referenceStderr
	err := command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != exitCode ||
		referenceStdout.String() != stdout ||
		!strings.Contains(referenceStderr.String(), stderr) {
		t.Fatalf(
			"OpenLDAP verbose result error=%v stdout=%q stderr=%q; Go stdout=%q stderr=%q",
			err,
			referenceStdout.String(),
			referenceStderr.String(),
			stdout,
			stderr,
		)
	}
}

func TestOpenLDAPLDAPCompareExtensionSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OpenLDAP source commit = %q, want %q", got, openLDAPClientToolsCommit)
	}
	path := filepath.Join(source, "clients/tools/ldapcompare.c")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OpenLDAP ldapcompare source: %v", err)
	}
	text := string(data)
	optionsStart := strings.Index(text, "const char options[]")
	if optionsStart < 0 {
		t.Fatal("OpenLDAP ldapcompare options[] declaration is missing")
	}
	optionsEnd := strings.Index(text[optionsStart:], ";")
	if optionsEnd < 0 {
		t.Fatal("OpenLDAP ldapcompare options[] terminator is missing")
	}
	options := text[optionsStart : optionsStart+optionsEnd]
	if strings.Contains(options, "E:") || strings.Contains(options, `"E"`) {
		t.Fatalf("OpenLDAP ldapcompare unexpectedly registers -E: %s", options)
	}
	for _, anchor := range []string{
		`case 'E': /* compare extensions */`,
		`strcasecmp( control, "dontUseCopy" )`,
		`dontUseCopy control previously specified`,
		`dontUseCopy: no control value expected`,
		`dontUseCopy: critical flag required`,
		`Invalid compare extension name: %s`,
		`DN:%s, attr:%s, value:%s`,
		`Compare Result: %s (%d)`,
	} {
		if !strings.Contains(text, anchor) {
			t.Errorf("OpenLDAP ldapcompare source lacks %q", anchor)
		}
	}
}

func TestLDAPCompareVerboseResult(t *testing.T) {
	const dn = "uid=alice,dc=example,dc=com"
	requests := make(chan ldapwire.Message, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.CompareRequest); !ok {
			return nil, nil
		}
		requests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.Result{Code: ldapwire.ResultCompareTrue},
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapcompare", "-H", fixture.uri, "-x", "-v", dn, "uid:alice",
	}, "")
	if exitCode != ldap.LDAPResultCompareTrue ||
		stdout != "Compare Result: Compare True (6)\nTRUE\n" ||
		stderr != "DN:"+dn+", attr:uid, value:alice\n" {
		t.Fatalf("verbose ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	message := awaitLDAPClientWireMessage(t, requests)
	request := message.Request.(ldapwire.CompareRequest)
	if request.DN != dn || request.Attribute != "uid" ||
		!bytes.Equal(request.Assertion, []byte("alice")) {
		t.Fatalf("verbose Compare request = %#v", request)
	}
}

func TestLDAPCompareVerboseDryRunPreservesBase64Display(t *testing.T) {
	const dn = "uid=alice,dc=example,dc=com"
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapcompare", "-n", "-v", dn, "userPassword::YWJj",
	}, "")
	if exitCode != 0 || stdout != "" ||
		stderr != "DN:"+dn+", attr:userPassword, value::YWJj\n" {
		t.Fatalf("verbose dry-run exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOpenLDAPLDAPCompareVerboseBehavior(t *testing.T) {
	ldapcompare := openLDAPCompareBinary(t)
	uri := startLDAPClientToolServer(t, nil)
	passwordPath := filepath.Join(t.TempDir(), "bind-password")
	if err := os.WriteFile(passwordPath, []byte(clientToolRootPassword), 0o600); err != nil {
		t.Fatalf("write bind password: %v", err)
	}
	dn := "uid=alice," + clientToolPeopleDN
	referenceArguments := []string{
		"-H", uri, "-x", "-D", clientToolRootDN, "-y", passwordPath,
		"-v", dn, "uid:alice",
	}
	command := exec.Command(ldapcompare, referenceArguments...)
	var referenceStdout, referenceStderr bytes.Buffer
	command.Stdout = &referenceStdout
	command.Stderr = &referenceStderr
	err := command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != ldap.LDAPResultCompareTrue {
		t.Fatalf(
			"OpenLDAP verbose ldapcompare error=%v stdout=%q stderr=%q",
			err,
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}

	arguments := append([]string{"ldapcompare"}, referenceArguments...)
	stdout, stderr, exitCode := runLDAPClientCommand(arguments, "")
	diagnostic := "DN:" + dn + ", attr:uid, value:alice\n"
	if exitCode != exitError.ExitCode() || stdout != referenceStdout.String() ||
		stderr != diagnostic || !strings.Contains(referenceStderr.String(), diagnostic) {
		t.Fatalf(
			"verbose ldapcompare differs: exit=%d stdout=%q stderr=%q; reference stdout=%q stderr=%q",
			exitCode,
			stdout,
			stderr,
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}
}

func openLDAPCompareBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join(os.Getenv("OPENLDAP_BUILD"), "clients", "tools", "ldapcompare"),
		"/opt/homebrew/opt/openldap/bin/ldapcompare",
	}
	if path, err := exec.LookPath("ldapcompare"); err == nil {
		candidates = append(candidates, path)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	t.Skip("OpenLDAP 2.6.13 ldapcompare is unavailable")
	return ""
}
