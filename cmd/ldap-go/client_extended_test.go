package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPCompareResultsBinaryErrorsAndDryRun(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	aliceDN := "uid=alice," + clientToolPeopleDN
	common := []string{
		"ldapcompare", "-H", uri, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
		aliceDN,
	}

	stdout, stderr, exitCode := runLDAPClientCommand(
		append(append([]string(nil), common...), "uid:alice"),
		"",
	)
	if exitCode != ldap.LDAPResultCompareTrue || stdout != "TRUE\n" || stderr != "" {
		t.Fatalf("true ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...), "uid:bob"),
		"",
	)
	if exitCode != ldap.LDAPResultCompareFalse || stdout != "FALSE\n" || stderr != "" {
		t.Fatalf("false ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	quiet := append(append([]string(nil), common[:len(common)-1]...), "-z", aliceDN, "uid:bob")
	stdout, stderr, exitCode = runLDAPClientCommand(quiet, "")
	if exitCode != ldap.LDAPResultCompareFalse || stdout != "" || stderr != "" {
		t.Fatalf("quiet false ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	binaryAssertion := "userPassword::" + base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10})
	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...), binaryAssertion),
		"",
	)
	if exitCode != ldap.LDAPResultCompareTrue || stdout != "TRUE\n" || stderr != "" {
		t.Fatalf("binary ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	missingDN := "uid=missing," + clientToolPeopleDN
	missing := append(append([]string(nil), common[:len(common)-1]...), missingDN, "uid:missing")
	stdout, stderr, exitCode = runLDAPClientCommand(missing, "")
	if exitCode != ldap.LDAPResultNoSuchObject || stdout != "" ||
		!strings.Contains(stderr, "No Such Object") {
		t.Fatalf("missing ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	quietMissing := append(
		append([]string(nil), common[:len(common)-1]...),
		"-z", missingDN, "uid:missing",
	)
	stdout, stderr, exitCode = runLDAPClientCommand(quietMissing, "")
	if exitCode != ldap.LDAPResultNoSuchObject || stdout != "" || stderr != "" {
		t.Fatalf("quiet missing ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapcompare", "-n", aliceDN, "uid::not-base64"},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "base64") {
		t.Fatalf("invalid ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapcompare", "-n", "-H", "ldap://127.0.0.1:1", aliceDN, "uid:alice"},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("dry-run ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	for _, option := range [][]string{{"-E", "dontUseCopy"}} {
		args := append([]string{"ldapcompare", "-n"}, option...)
		args = append(args, aliceDN, "uid:alice")
		stdout, stderr, exitCode = runLDAPClientCommand(args, "")
		if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "not implemented") {
			t.Fatalf("unsupported ldapcompare %q exit=%d stdout=%q stderr=%q", option, exitCode, stdout, stderr)
		}
	}
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapcompare", "-n", "-e", "1.2.3", aliceDN, "uid:alice"},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("ldapcompare controls exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, option := range []string{"-M", "-MM"} {
		stdout, stderr, exitCode = runLDAPClientCommand(
			[]string{"ldapcompare", "-n", option, aliceDN, "uid:alice"},
			"",
		)
		if exitCode != 0 || stdout != "" || stderr != "" {
			t.Fatalf("ldapcompare %s exit=%d stdout=%q stderr=%q", option, exitCode, stdout, stderr)
		}
	}
}

func TestLDAPCompareStartTLS(t *testing.T) {
	tlsConfig, caPEM := newLDAPClientToolTLSConfig(t)
	uri := startLDAPClientToolServer(t, tlsConfig)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapcompare", "-H", uri, "-x", "-ZZ",
			"-tls-ca", caPath, "-tls-server-name", "localhost",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-M",
			"uid=alice," + clientToolPeopleDN, "uid:alice",
		},
		"",
	)
	if exitCode != ldap.LDAPResultCompareTrue || stdout != "TRUE\n" || stderr != "" {
		t.Fatalf("StartTLS ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapexop", "-H", uri, "-x", "-ZZ",
			"-tls-ca", caPath, "-tls-server-name", "localhost",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"whoami",
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:"+clientToolRootDN+"\n" || stderr != "" {
		t.Fatalf("StartTLS ldapexop exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	bobDN := "uid=bob," + clientToolPeopleDN
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x", "-ZZ",
			"-tls-ca", caPath, "-tls-server-name", "localhost",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-s", "starttls-password", bobDN,
		},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("StartTLS ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, bobDN, "starttls-password")
}

func TestOpenLDAPLDAPCompareReferenceExitCodes(t *testing.T) {
	const ldapcompare = "/opt/homebrew/opt/openldap/bin/ldapcompare"
	if _, err := os.Stat(ldapcompare); err != nil {
		t.Skipf("OpenLDAP ldapcompare is unavailable: %v", err)
	}
	uri := startLDAPClientToolServer(t, nil)
	passwordPath := filepath.Join(t.TempDir(), "bind-password")
	if err := os.WriteFile(passwordPath, []byte(clientToolRootPassword), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	aliceDN := "uid=alice," + clientToolPeopleDN
	baseArguments := []string{
		"-H", uri, "-x", "-D", clientToolRootDN, "-y", passwordPath, aliceDN,
	}
	for _, test := range []struct {
		name      string
		assertion string
		wantCode  int
		wantOut   string
	}{
		{name: "true", assertion: "uid:alice", wantCode: ldap.LDAPResultCompareTrue, wantOut: "TRUE\n"},
		{name: "false", assertion: "uid:bob", wantCode: ldap.LDAPResultCompareFalse, wantOut: "FALSE\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(ldapcompare, append(baseArguments, test.assertion)...)
			output, err := command.CombinedOutput()
			code := 0
			if err != nil {
				var exitError *exec.ExitError
				if !errors.As(err, &exitError) {
					t.Fatalf("ldapcompare: %v", err)
				}
				code = exitError.ExitCode()
			}
			if code != test.wantCode || string(output) != test.wantOut {
				t.Fatalf("OpenLDAP ldapcompare exit=%d output=%q", code, output)
			}
		})
	}

	missingDN := "uid=missing," + clientToolPeopleDN
	quietArguments := []string{
		"-H", uri, "-x", "-D", clientToolRootDN, "-y", passwordPath,
		"-z", missingDN, "uid:missing",
	}
	var referenceStdout, referenceStderr bytes.Buffer
	command := exec.Command(ldapcompare, quietArguments...)
	command.Stdout = &referenceStdout
	command.Stderr = &referenceStderr
	err := command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != ldap.LDAPResultNoSuchObject {
		t.Fatalf("quiet OpenLDAP ldapcompare error = %v", err)
	}
	if referenceStdout.Len() != 0 || referenceStderr.Len() != 0 {
		t.Fatalf(
			"quiet OpenLDAP ldapcompare stdout=%q stderr=%q",
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}
	ourArguments := append([]string{"ldapcompare"}, quietArguments...)
	stdout, stderr, exitCode := runLDAPClientCommand(ourArguments, "")
	if exitCode != exitError.ExitCode() || stdout != referenceStdout.String() ||
		stderr != referenceStderr.String() {
		t.Fatalf(
			"quiet ldapcompare differs: exit=%d stdout=%q stderr=%q",
			exitCode,
			stdout,
			stderr,
		)
	}
}

func TestLDAPPasswdOmitsEmptyRequestValue(t *testing.T) {
	const generatedPassword = "strict-generated-password"
	uri, done := startLDAPExtendedWireServer(
		t,
		func(messageID int64, request ldapwire.ExtendedRequest) ([]byte, error) {
			if request.Name != ldapPasswordModifyOID {
				return nil, fmt.Errorf("extended request OID = %q", request.Name)
			}
			if request.HasValue {
				return nil, fmt.Errorf(
					"password modify request unexpectedly contained requestValue %x",
					request.Value,
				)
			}
			return ldapwire.EncodeExtendedResponse(
				messageID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				ldapPasswordModifyOID,
				ldapwire.EncodePasswordModifyResponseValue([]byte(generatedPassword)),
				nil,
			), nil
		},
	)
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldappasswd", "-H", uri, "-x"},
		"",
	)
	awaitLDAPExtendedWireServer(t, done)
	if exitCode != 0 || stderr != "" || stdout != "New password: "+generatedPassword+"\n" {
		t.Fatalf("strict ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPPasswordModifyRequestBERPreservesBytes(t *testing.T) {
	if value, err := newLDAPPasswordModifyRequestValue("", nil, false, nil, false); err != nil || value != nil {
		t.Fatalf("empty password modify value = %#v, %v", value, err)
	}
	oldPassword := []byte{0x00, 0xff, 'o'}
	newPassword := []byte{'n', 0x00, 0xfe}
	value, err := newLDAPPasswordModifyRequestValue(
		"u:alice",
		oldPassword,
		true,
		newPassword,
		true,
	)
	if err != nil {
		t.Fatalf("encode password modify request: %v", err)
	}
	defer clearBERPacket(value)
	decoded, err := ldapwire.DecodePasswordModifyRequestValue(value.Data.Bytes(), true)
	if err != nil {
		t.Fatalf("decode password modify request: %v", err)
	}
	defer clear(decoded.UserIdentity)
	defer clear(decoded.OldPassword)
	defer clear(decoded.NewPassword)
	if !bytes.Equal(decoded.UserIdentity, []byte("u:alice")) || !decoded.HasUserIdentity ||
		!decoded.HasOldPassword || !bytes.Equal(decoded.OldPassword, oldPassword) ||
		!decoded.HasNewPassword || !bytes.Equal(decoded.NewPassword, newPassword) {
		t.Fatalf("decoded password modify request = %#v", decoded)
	}
}

func TestLDAPWhoAmIRequiresPresentResponseValue(t *testing.T) {
	commands := []struct {
		name string
		args []string
	}{
		{name: "ldapwhoami", args: []string{"ldapwhoami"}},
		{name: "ldapexop", args: []string{"ldapexop", "whoami"}},
	}
	for _, command := range commands {
		for _, response := range []struct {
			name  string
			value []byte
			want  string
		}{
			{name: "missing", value: nil},
			{name: "empty", value: []byte{}, want: "anonymous\n"},
		} {
			t.Run(command.name+"/"+response.name, func(t *testing.T) {
				uri, done := startLDAPExtendedWireServer(
					t,
					func(messageID int64, request ldapwire.ExtendedRequest) ([]byte, error) {
						if request.Name != ldapWhoAmIOID || request.HasValue {
							return nil, fmt.Errorf("Who Am I request = %#v", request)
						}
						return ldapwire.EncodeExtendedResponse(
							messageID,
							ldapwire.Result{Code: ldapwire.ResultSuccess},
							ldapWhoAmIOID,
							response.value,
							nil,
						), nil
					},
				)
				args := append(append([]string(nil), command.args...), "-H", uri, "-x")
				if command.name == "ldapexop" {
					args = []string{"ldapexop", "-H", uri, "-x", "whoami"}
				}
				stdout, stderr, exitCode := runLDAPClientCommand(args, "")
				awaitLDAPExtendedWireServer(t, done)
				if response.value == nil {
					if exitCode != 1 || stdout != "" ||
						!strings.Contains(stderr, "omitted the extended response value") {
						t.Fatalf("missing response exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
					}
					return
				}
				if exitCode != 0 || stdout != response.want || stderr != "" {
					t.Fatalf("empty response exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
				}
			})
		}
	}
}

func TestLDAPPasswdCurrentSpecifiedGeneratedAndPrompts(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	currentDN := addLDAPClientToolUser(t, uri, "password-current", "alice-old-password")
	generatedDN := addLDAPClientToolUser(t, uri, "password-generated", "")

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x",
			"-D", currentDN, "-w", "alice-old-password",
			"-a", "alice-old-password", "-s", "alice-new-password",
		},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("current-user ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, currentDN, "alice-new-password")

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			generatedDN,
		},
		"",
	)
	if exitCode != 0 || stderr != "" || !strings.HasPrefix(stdout, "New password: ") ||
		!strings.HasSuffix(stdout, "\n") {
		t.Fatalf("generated ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	generated := strings.TrimSuffix(strings.TrimPrefix(stdout, "New password: "), "\n")
	if generated == "" {
		t.Fatal("generated password is empty")
	}
	assertLDAPClientToolBind(t, uri, generatedDN, generated)

	const promptedPassword = "prompted-password-must-not-leak"
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-S", generatedDN,
		},
		promptedPassword+"\n"+promptedPassword+"\n",
	)
	if exitCode != 0 || stdout != "" ||
		stderr != "New password: Re-enter new password: " ||
		strings.Contains(stderr, promptedPassword) {
		t.Fatalf("prompted ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, generatedDN, promptedPassword)

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x",
			"-D", generatedDN, "-w", promptedPassword,
			"-A", "-s", "after-old-prompt",
		},
		promptedPassword+"\n"+promptedPassword+"\n",
	)
	if exitCode != 0 || stdout != "" || stderr != "Old password: Re-enter old password: " {
		t.Fatalf("old-prompt ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, generatedDN, "after-old-prompt")

	const wrongOld = "wrong-old-password-must-not-leak"
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-a", wrongOld, "-s", "unused-new-password", generatedDN,
		},
		"",
	)
	if exitCode != 1 || stdout != "" ||
		(!strings.Contains(stderr, "Invalid Credentials") &&
			!strings.Contains(stderr, "unwilling to verify old password")) ||
		strings.Contains(stderr, wrongOld) || strings.Contains(stderr, "unused-new-password") {
		t.Fatalf("bad-old ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPPasswdBindEarlyPromptOrderAndFiles(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	targetDN := addLDAPClientToolUser(t, uri, "password-files", "")
	const newPassword = "bind-early-new-password"
	stdin := clientToolRootPassword + "\n" + newPassword + "\n" + newPassword + "\ntrailing-input\n"
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x", "-E",
			"-D", clientToolRootDN, "-W", "-S", targetDN,
		},
		stdin,
	)
	if exitCode != 0 || stdout != "" ||
		stderr != "Enter LDAP Password: New password: Re-enter new password: " {
		t.Fatalf("bind-early ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, targetDN, newPassword)

	filePassword := []byte("password-from-raw-file")
	passwordPath := filepath.Join(t.TempDir(), "new-password")
	if err := os.WriteFile(passwordPath, filePassword, 0o600); err != nil {
		t.Fatalf("write new password file: %v", err)
	}
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-T", passwordPath, targetDN,
		},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("file ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, targetDN, string(filePassword))

	oldPasswordPath := filepath.Join(t.TempDir(), "old-password")
	if err := os.WriteFile(oldPasswordPath, filePassword, 0o600); err != nil {
		t.Fatalf("write old password file: %v", err)
	}
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", uri, "-x",
			"-D", targetDN, "-w", string(filePassword),
			"-t", oldPasswordPath, "-s", "after-old-file",
		},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("old-file ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, targetDN, "after-old-file")
}

func TestLDAPPasswdRejectsConflictsControlsAndUnsafeSecrets(t *testing.T) {
	oversizedPath := filepath.Join(t.TempDir(), "oversized-password")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte{'x'}, maxPasswordInputSize+1), 0o600); err != nil {
		t.Fatalf("write oversized password: %v", err)
	}
	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{name: "old conflict", args: []string{"-n", "-a", "secret", "-A"}, message: "mutually exclusive"},
		{name: "new conflict", args: []string{"-n", "-s", "secret", "-S"}, message: "mutually exclusive"},
		{name: "repeated old", args: []string{"-n", "-a", "first-secret-must-not-leak", "-a", "second-secret-must-not-leak"}, message: "provided more than once"},
		{name: "empty old", args: []string{"-n", "-a", ""}, message: "must not be empty"},
		{name: "empty file path", args: []string{"-n", "-t", ""}, message: "non-empty"},
		{name: "oversized file", args: []string{"-n", "-T", oversizedPath}, message: "exceeds 1048576 bytes"},
		{name: "SASL", args: []string{"-n", "-Y", "PLAIN"}, message: "SASL mechanisms are not implemented"},
		{name: "two users", args: []string{"-n", "uid=a", "uid=b"}, message: "at most one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"ldappasswd"}, test.args...)
			stdout, stderr, exitCode := runLDAPClientCommand(args, "")
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf("ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			for _, secret := range []string{
				"first-secret-must-not-leak",
				"second-secret-must-not-leak",
				strings.Repeat("x", 64),
			} {
				if strings.Contains(stderr, secret) {
					t.Fatalf("stderr leaked password material %q: %q", secret, stderr)
				}
			}
		})
	}

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldappasswd", "-n", "-H", "ldap://127.0.0.1:1", "-s", "validated"},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("dry-run ldappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	const firstPrompt = "first-prompt-secret-must-not-leak"
	const secondPrompt = "second-prompt-secret-must-not-leak"
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldappasswd", "-H", "ldap://127.0.0.1:1", "-x", "-S",
			"uid=unreachable," + clientToolPeopleDN,
		},
		firstPrompt+"\n"+secondPrompt+"\n",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "passwords do not match") ||
		strings.Contains(stderr, firstPrompt) || strings.Contains(stderr, secondPrompt) {
		t.Fatalf("mismatched prompt exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPExopPasswdUsesPasswordModifyOptionsAndResponse(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	targetDN := addLDAPClientToolUser(t, uri, "exop-password", "old-exop-password")
	generatedDN := addLDAPClientToolUser(t, uri, "exop-generated", "")

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapexop", "-H", uri, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
		"-a", "old-exop-password", "-s", "new-exop-password",
		"passwd", targetDN,
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("ldapexop passwd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPClientToolBind(t, uri, targetDN, "new-exop-password")

	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapexop", "-H", uri, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
		"passwd", generatedDN,
	}, "")
	if exitCode != 0 || stderr != "" || !strings.HasPrefix(stdout, "New password: ") ||
		!strings.HasSuffix(stdout, "\n") {
		t.Fatalf("generated ldapexop passwd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	generated := strings.TrimSuffix(strings.TrimPrefix(stdout, "New password: "), "\n")
	if generated == "" {
		t.Fatal("ldapexop generated password is empty")
	}
	assertLDAPClientToolBind(t, uri, generatedDN, generated)

	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapexop", "-n", "-s", "validated", "passwd", targetDN,
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("dry-run ldapexop passwd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapexop", "-n", "-s", "not-applicable", "whoami",
	}, "")
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "require the passwd operation") ||
		strings.Contains(stderr, "not-applicable") {
		t.Fatalf("misplaced passwd options exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPExopPasswdRequestControlsAndGeneratedResponse(t *testing.T) {
	const generatedPassword = "exop-generated-password"
	requests := make(chan ldapwire.Message, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.ExtendedRequest)
		if !ok {
			return nil, nil
		}
		requests <- message
		if request.Name != ldapPasswordModifyOID || !request.HasValue {
			return nil, fmt.Errorf("password modify request = %#v", request)
		}
		decoded, err := ldapwire.DecodePasswordModifyRequestValue(request.Value, true)
		if err != nil {
			return nil, err
		}
		defer clear(decoded.UserIdentity)
		defer clear(decoded.OldPassword)
		defer clear(decoded.NewPassword)
		if !decoded.HasUserIdentity || string(decoded.UserIdentity) != "u:alice" ||
			!decoded.HasOldPassword || string(decoded.OldPassword) != "old-password" ||
			decoded.HasNewPassword {
			return nil, fmt.Errorf("decoded password modify request = %#v", decoded)
		}
		return [][]byte{ldapwire.EncodeExtendedResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			ldapPasswordModifyOID,
			ldapwire.EncodePasswordModifyResponseValue([]byte(generatedPassword)),
			nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapexop", "-H", fixture.uri, "-x",
		"-e", "!1.2.3=:password-control", "-a", "old-password",
		"passwd", "u:alice",
	}, "")
	if exitCode != 0 || stdout != "New password: "+generatedPassword+"\n" || stderr != "" {
		t.Fatalf("wire ldapexop passwd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	message := awaitLDAPClientWireMessage(t, requests)
	assertLDAPWireControl(
		t,
		message.Controls,
		"1.2.3",
		true,
		true,
		[]byte("password-control"),
	)
}

func TestLDAPExopWhoAmIGenericCancelAndErrors(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	common := []string{
		"ldapexop", "-H", uri, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
	}
	stdout, stderr, exitCode := runLDAPClientCommand(
		append(append([]string(nil), common...), "whoami"),
		"",
	)
	if exitCode != 0 || stdout != "dn:"+clientToolRootDN+"\n" || stderr != "" {
		t.Fatalf("ldapexop whoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...), ldapWhoAmIOID),
		"",
	)
	if exitCode != 0 || stderr != "" ||
		stdout != "# extended operation response\ndata:: "+
			base64.StdEncoding.EncodeToString([]byte("dn:"+clientToolRootDN))+"\n" {
		t.Fatalf("generic whoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...), "cancel", "999"),
		"",
	)
	if exitCode != 1 || stdout != "" ||
		(!strings.Contains(stderr, "No Such Operation") && !strings.Contains(stderr, "Result Code 119")) {
		t.Fatalf("ldapexop cancel exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	binaryValue := base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10})
	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...), "1.2.3::"+binaryValue),
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "extended operation 1.2.3") {
		t.Fatalf("unknown generic exop exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	for _, test := range []struct {
		name    string
		args    []string
		message string
	}{
		{name: "cancel zero", args: []string{"cancel", "0"}, message: "invalid cancel"},
		{name: "cancel text", args: []string{"cancel", "abc"}, message: "invalid cancel"},
		{name: "refresh TTL", args: []string{"refresh", clientToolBaseDN, "0"}, message: "invalid refresh TTL"},
		{name: "unknown alias", args: []string{"unknown"}, message: "invalid LDAP extended operation OID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"ldapexop", "-n"}, test.args...)
			stdout, stderr, exitCode := runLDAPClientCommand(args, "")
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf("ldapexop exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
		})
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{"ldapexop", "-n", "-H", "ldap://127.0.0.1:1", "whoami"},
		"",
	)
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("dry-run ldapexop exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPExopRefresh(t *testing.T) {
	uri := startLDAPClientToolDDSServer(t)
	dynamicDN := "cn=temporary," + clientToolPeopleDN
	connection := bindLDAPClientToolRoot(t, uri)
	request := ldap.NewAddRequest(dynamicDN, nil)
	request.Attribute("objectClass", []string{"top", "organizationalRole", "dynamicObject"})
	request.Attribute("cn", []string{"temporary"})
	if err := connection.Add(request); err != nil {
		connection.Close()
		t.Fatalf("add dynamic object: %v", err)
	}
	connection.Close()

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapexop", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"refresh", dynamicDN, "45",
		},
		"",
	)
	if exitCode != 0 || stdout != "newttl=45\n" || stderr != "" {
		t.Fatalf("ldapexop refresh exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPGenericExopBinaryParsingAndOutput(t *testing.T) {
	binary := []byte{0x00, 0xff, 0x10}
	oid, value, present, err := parseLDAPGenericExop(
		"1.2.840.113556::" + base64.StdEncoding.EncodeToString(binary),
	)
	if err != nil || oid != "1.2.840.113556" || !present || !bytes.Equal(value, binary) {
		t.Fatalf("parse binary exop = %q %v %t, %v", oid, value, present, err)
	}
	clear(value)

	oid, value, present, err = parseLDAPGenericExop("1.2.3:")
	if err != nil || oid != "1.2.3" || !present || len(value) != 0 {
		t.Fatalf("parse empty exop = %q %v %t, %v", oid, value, present, err)
	}
	oid, value, present, err = parseLDAPGenericExop("1.2.3")
	if err != nil || oid != "1.2.3" || present || value != nil {
		t.Fatalf("parse absent exop = %q %v %t, %v", oid, value, present, err)
	}
	oid, value, present, err = parseLDAPGenericExop("1.2.3:raw:value")
	if err != nil || oid != "1.2.3" || !present || string(value) != "raw:value" {
		t.Fatalf("parse raw exop = %q %q %t, %v", oid, value, present, err)
	}
	clear(value)
	oid, value, present, err = parseLDAPGenericExop("  1.2.3  :   spaced value")
	if err != nil || oid != "1.2.3" || !present || string(value) != "spaced value" {
		t.Fatalf("parse spaced exop = %q %q %t, %v", oid, value, present, err)
	}
	clear(value)
	oid, value, present, err = parseLDAPGenericExop(
		"1.2.3:: \t" + base64.StdEncoding.EncodeToString(binary),
	)
	if err != nil || oid != "1.2.3" || !present || !bytes.Equal(value, binary) {
		t.Fatalf("parse spaced base64 exop = %q %v %t, %v", oid, value, present, err)
	}
	clear(value)

	valuePath := filepath.Join(t.TempDir(), "extended value.bin")
	if err := os.WriteFile(valuePath, binary, 0o600); err != nil {
		t.Fatalf("write extended value: %v", err)
	}
	location := (&url.URL{Scheme: "file", Path: valuePath}).String()
	oid, value, present, err = parseLDAPGenericExop("1.2.3:< \t" + location)
	if err != nil || oid != "1.2.3" || !present || !bytes.Equal(value, binary) {
		t.Fatalf("parse URL exop = %q %v %t, %v", oid, value, present, err)
	}
	clear(value)

	packet := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, nil, "responseValue")
	_, _ = packet.Data.Write(binary)
	response := &ldap.ExtendedResponse{Name: "1.2.3", Value: packet}
	var output bytes.Buffer
	if err := writeLDAPExtendedResponse(&output, response); err != nil {
		t.Fatalf("writeLDAPExtendedResponse(): %v", err)
	}
	want := "# extended operation response\noid: 1.2.3\ndata:: " +
		base64.StdEncoding.EncodeToString(binary) + "\n"
	if output.String() != want {
		t.Fatalf("binary extended response = %q, want %q", output.String(), want)
	}

	output.Reset()
	plainPacket := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, nil, "responseValue")
	_, _ = plainPacket.Data.Write([]byte("plain response"))
	if err := writeLDAPExtendedResponse(
		&output,
		&ldap.ExtendedResponse{Name: "1.2.3", Value: plainPacket},
	); err != nil {
		t.Fatalf("write plain extended response: %v", err)
	}
	want = "# extended operation response\noid: 1.2.3\ndata:: " +
		base64.StdEncoding.EncodeToString([]byte("plain response")) + "\n"
	if output.String() != want {
		t.Fatalf("plain extended response = %q, want %q", output.String(), want)
	}

	output.Reset()
	emptyPacket := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, nil, "responseValue")
	if err := writeLDAPExtendedResponse(
		&output,
		&ldap.ExtendedResponse{Value: emptyPacket},
	); err != nil {
		t.Fatalf("write empty extended response: %v", err)
	}
	if output.String() != "# extended operation response\ndata:\n" {
		t.Fatalf("empty extended response = %q", output.String())
	}

	output.Reset()
	secret := []byte{0x00, '\n', 0xff}
	if err := writeLDAPGeneratedPassword(&output, secret); err != nil {
		t.Fatalf("write generated password: %v", err)
	}
	if output.String() != "New password:: "+base64.StdEncoding.EncodeToString(secret)+"\n" {
		t.Fatalf("unsafe generated password output = %q", output.String())
	}

	requestValue := newLDAPExtendedRequestValue(binary)
	if !bytes.Equal(requestValue.Data.Bytes(), binary) {
		t.Fatalf("extended request value = %v", requestValue.Data.Bytes())
	}
	if _, _, _, err := parseLDAPGenericExop("1.2.3::not-base64"); err == nil {
		t.Fatal("parseLDAPGenericExop accepted invalid base64")
	}
	if _, _, _, err := parseLDAPGenericExop("1.2.3::"); err == nil {
		t.Fatal("parseLDAPGenericExop accepted missing base64 data")
	}
	if _, _, _, err := parseLDAPGenericExop("1.2.3:< https://example.com/value"); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Fatalf("parseLDAPGenericExop network URL error = %v", err)
	}
	if _, _, _, err := parseLDAPGenericExop("1.02.3:value"); err == nil {
		t.Fatal("parseLDAPGenericExop accepted a non-canonical OID")
	}
	if _, _, _, err := parseLDAPGenericExop(
		"1.2.3:" + strings.Repeat("x", maxLDAPExtendedValueSize+1),
	); err == nil {
		t.Fatal("parseLDAPGenericExop accepted an oversized value")
	}
	refresh, err := parseLDAPExopInvocation([]string{"refresh", clientToolBaseDN})
	if err != nil || refresh.refreshTTL != defaultLDAPRefreshSeconds {
		t.Fatalf("default refresh invocation = %#v, %v", refresh, err)
	}
}

func TestLDAPExopFileValueAndForcedBinaryOutput(t *testing.T) {
	requestValue := []byte{0x00, 0xff, 'x', '\n'}
	valuePath := filepath.Join(t.TempDir(), "request value.bin")
	if err := os.WriteFile(valuePath, requestValue, 0o600); err != nil {
		t.Fatalf("write request value: %v", err)
	}
	location := (&url.URL{Scheme: "file", Path: valuePath}).String()
	uri, done := startLDAPExtendedWireServer(
		t,
		func(messageID int64, request ldapwire.ExtendedRequest) ([]byte, error) {
			if request.Name != "1.2.3" || !request.HasValue ||
				!bytes.Equal(request.Value, requestValue) {
				return nil, fmt.Errorf("generic extended request = %#v", request)
			}
			return ldapwire.EncodeExtendedResponse(
				messageID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				"1.2.3",
				[]byte("plain response"),
				nil,
			), nil
		},
	)
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapexop", "-H", uri, "-x", " 1.2.3 :< \t" + location},
		"",
	)
	awaitLDAPExtendedWireServer(t, done)
	want := "# extended operation response\noid: 1.2.3\ndata:: " +
		base64.StdEncoding.EncodeToString([]byte("plain response")) + "\n"
	if exitCode != 0 || stdout != want || stderr != "" {
		t.Fatalf("file ldapexop exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOpenLDAPLDAPExopFileAndResponseReference(t *testing.T) {
	const ldapexop = "/opt/homebrew/opt/openldap/bin/ldapexop"
	if _, err := os.Stat(ldapexop); err != nil {
		t.Skipf("OpenLDAP ldapexop is unavailable: %v", err)
	}
	requestValue := []byte{0x00, 0xff, 'r'}
	valuePath := filepath.Join(t.TempDir(), "reference value.bin")
	if err := os.WriteFile(valuePath, requestValue, 0o600); err != nil {
		t.Fatalf("write reference value: %v", err)
	}
	location := (&url.URL{Scheme: "file", Path: valuePath}).String()
	responseValue := []byte("plain response")
	handler := func(messageID int64, request ldapwire.ExtendedRequest) ([]byte, error) {
		if request.Name != "1.2.3" || !request.HasValue ||
			!bytes.Equal(request.Value, requestValue) {
			return nil, fmt.Errorf("reference generic request = %#v", request)
		}
		return ldapwire.EncodeExtendedResponse(
			messageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			"1.2.3",
			responseValue,
			nil,
		), nil
	}

	referenceURI, referenceDone := startLDAPExtendedWireServer(t, handler)
	command := exec.Command(
		ldapexop,
		"-H", referenceURI,
		"-x",
		"1.2.3:< "+location,
	)
	var referenceStdout, referenceStderr bytes.Buffer
	command.Stdout = &referenceStdout
	command.Stderr = &referenceStderr
	referenceErr := command.Run()
	awaitLDAPExtendedWireServer(t, referenceDone)
	if referenceErr != nil {
		t.Fatalf(
			"OpenLDAP ldapexop: %v, stdout=%q stderr=%q",
			referenceErr,
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}

	ourURI, ourDone := startLDAPExtendedWireServer(t, handler)
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapexop", "-H", ourURI, "-x", "1.2.3:< " + location},
		"",
	)
	awaitLDAPExtendedWireServer(t, ourDone)
	if exitCode != 0 || stdout != referenceStdout.String() ||
		stderr != referenceStderr.String() {
		t.Fatalf(
			"ldapexop differs from OpenLDAP: exit=%d stdout=%q stderr=%q; reference stdout=%q stderr=%q",
			exitCode,
			stdout,
			stderr,
			referenceStdout.String(),
			referenceStderr.String(),
		)
	}
}

func TestLDAPPlaintextPasswordFlagDiagnostics(t *testing.T) {
	for _, test := range []struct {
		command string
		flags   []string
	}{
		{command: "ldapwhoami", flags: []string{"w"}},
		{command: "ldappasswd", flags: []string{"w", "a", "s"}},
	} {
		stdout, stderr, exitCode := runLDAPClientCommand(
			[]string{test.command, "-help"},
			"",
		)
		if exitCode != 1 || stdout != "" {
			t.Fatalf("%s help exit=%d stdout=%q stderr=%q", test.command, exitCode, stdout, stderr)
		}
		for _, name := range test.flags {
			if !strings.Contains(stderr, "-"+name) ||
				!strings.Contains(stderr, "visible in process arguments") {
				t.Fatalf("%s help does not diagnose -%s plaintext risk: %q", test.command, name, stderr)
			}
		}
	}

	const secret = "command-line-secret-must-not-render"
	var value secretFlagValue
	if err := value.Set(secret); err != nil {
		t.Fatalf("set secret flag: %v", err)
	}
	defer value.clear()
	if rendered := value.String(); rendered != "" || strings.Contains(rendered, secret) {
		t.Fatalf("secret flag rendered as %q", rendered)
	}
}

func TestLDAPExtendedClientUsage(t *testing.T) {
	stdout, stderr, exitCode := runLDAPClientCommand([]string{"help"}, "")
	if exitCode != 0 || stderr != "" {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, command := range []string{"ldapcompare", "ldappasswd", "ldapexop"} {
		if !strings.Contains(stdout, command) {
			t.Errorf("help does not list %s: %q", command, stdout)
		}
	}
}

type ldapExtendedWireHandler func(
	messageID int64,
	request ldapwire.ExtendedRequest,
) ([]byte, error)

func startLDAPExtendedWireServer(
	t *testing.T,
	handler ldapExtendedWireHandler,
) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for LDAP wire server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		_ = listener.Close()
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}

		bindMessage, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			done <- fmt.Errorf("read bind request: %w", err)
			return
		}
		if _, ok := bindMessage.Request.(ldapwire.BindRequest); !ok {
			done <- fmt.Errorf("first LDAP request is %T, want BindRequest", bindMessage.Request)
			return
		}
		if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			bindMessage.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)); err != nil {
			done <- fmt.Errorf("write bind response: %w", err)
			return
		}

		message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			done <- fmt.Errorf("read extended request: %w", err)
			return
		}
		request, ok := message.Request.(ldapwire.ExtendedRequest)
		if !ok {
			done <- fmt.Errorf("second LDAP request is %T, want ExtendedRequest", message.Request)
			return
		}
		response, handlerErr := handler(message.ID, request)
		if response == nil {
			response = ldapwire.EncodeExtendedResponse(
				message.ID,
				ldapwire.Result{
					Code:              ldapwire.ResultProtocolError,
					DiagnosticMessage: "test handler rejected extended request",
				},
				"",
				nil,
				nil,
			)
		}
		if err := ldapwire.Write(connection, response); err != nil {
			done <- fmt.Errorf("write extended response: %w", err)
			return
		}
		done <- handlerErr
	}()
	return "ldap://" + listener.Addr().String(), done
}

func awaitLDAPExtendedWireServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("LDAP wire server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LDAP wire server timed out")
	}
}

func addLDAPClientToolUser(t *testing.T, uri, uid, password string) string {
	t.Helper()
	connection := bindLDAPClientToolRoot(t, uri)
	defer connection.Close()
	dn := "uid=" + uid + "," + clientToolPeopleDN
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{uid})
	if password != "" {
		request.Attribute("userPassword", []string{password})
	}
	if err := connection.Add(request); err != nil {
		t.Fatalf("add password test user %s: %v", dn, err)
	}
	return dn
}

func assertLDAPClientToolBind(t *testing.T, uri, dn, password string) {
	t.Helper()
	connection, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial %s: %v", uri, err)
	}
	defer connection.Close()
	if err := connection.Bind(dn, password); err != nil {
		t.Fatalf("bind as %s: %v", dn, err)
	}
}

func bindLDAPClientToolRoot(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	connection, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial %s: %v", uri, err)
	}
	if err := connection.Bind(clientToolRootDN, clientToolRootPassword); err != nil {
		connection.Close()
		t.Fatalf("bind root: %v", err)
	}
	return connection
}

func startLDAPClientToolDDSServer(t *testing.T) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPClientToolDirectory(t, store)

	const databaseName = "{1}mdb"
	databasePartition := storage.OpenLDAPDatabasePartition(databaseName, nil)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		var entries []directory.Entry
		if err := writer.ForEachIn("", func(entry directory.Entry) error {
			entries = append(entries, entry)
			return nil
		}); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := writer.PutIn(databasePartition, entry, false); err != nil {
				return err
			}
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if err := writer.DeleteIn("", dn); err != nil {
				return err
			}
		}
		database := directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: clientToolValues(databaseName)},
				{Description: "olcSuffix", Values: clientToolValues(clientToolBaseDN)},
			},
		}
		overlay := directory.Entry{
			DN: "olcOverlay={0}dds,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: clientToolValues("{0}dds")},
				{Description: "olcDDSdefaultTtl", Values: clientToolValues("1h")},
			},
		}
		if err := writer.PutIn(storage.OpenLDAPConfigPartition, database, false); err != nil {
			return err
		}
		return writer.PutIn(storage.OpenLDAPConfigPartition, overlay, false)
	}); err != nil {
		t.Fatalf("configure DDS test directory: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := server.New(server.Config{
		Store:        store,
		RootDN:       clientToolRootDN,
		RootPassword: []byte(clientToolRootPassword),
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("server.New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("DDS LDAP client tool test server did not stop")
		}
	})
	return "ldap://" + listener.Addr().String()
}
