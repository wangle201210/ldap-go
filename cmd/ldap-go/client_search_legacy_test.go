package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLDAPSearchLegacyLDIFLevels(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	dn := "uid=alice," + clientToolPeopleDN
	common := []string{
		"ldapsearch", "-H", uri, "-x", "-b", dn, "-s", "base",
		"(objectClass=*)", "uid",
	}
	wantEntry := "dn: " + dn + "\nuid: alice\n\n"
	tests := []struct {
		name string
		flag string
		want string
	}{
		{
			name: "default",
			want: "# extended LDIF\n" +
				"#\n" +
				"# LDAPv3\n" +
				"# base <" + dn + "> with scope baseObject\n" +
				"# filter: (objectClass=*)\n" +
				"# requesting: uid \n" +
				"#\n\n" +
				"# alice, people, example.com\n" +
				wantEntry +
				"# search result\n" +
				"search: 2\n" +
				"result: 0 Success\n\n" +
				"# numResponses: 2\n" +
				"# numEntries: 1\n",
		},
		{
			name: "L",
			flag: "-L",
			want: "version: 1\n\n" +
				"#\n" +
				"# LDAPv3\n" +
				"# base <" + dn + "> with scope baseObject\n" +
				"# filter: (objectClass=*)\n" +
				"# requesting: uid \n" +
				"#\n\n" +
				"# alice, people, example.com\n" +
				wantEntry +
				"# search result\n\n" +
				"# numResponses: 2\n" +
				"# numEntries: 1\n",
		},
		{name: "LL", flag: "-LL", want: "version: 1\n\n" + wantEntry},
		{name: "LLL", flag: "-LLL", want: wantEntry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string(nil), common[:8]...)
			if test.flag != "" {
				args = append(args, test.flag)
			}
			args = append(args, common[8:]...)
			stdout, stderr, exitCode := runLDAPClientCommand(args, "")
			if exitCode != 0 || stderr != "" || stdout != test.want {
				t.Fatalf(
					"ldapsearch %s exit=%d\nstdout:\n%q\nwant:\n%q\nstderr=%q",
					test.flag,
					exitCode,
					stdout,
					test.want,
					stderr,
				)
			}
		})
	}

	repeatedArgs := append(append([]string(nil), common[:8]...), "-L", "-L")
	repeatedArgs = append(repeatedArgs, common[8:]...)
	stdout, stderr, exitCode := runLDAPClientCommand(repeatedArgs, "")
	wantRepeated := "version: 1\n\n" + wantEntry
	if exitCode != 0 || stderr != "" || stdout != wantRepeated {
		t.Fatalf("ldapsearch -L -L exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPSearchContinuousModeContinuesPastInvalidFilter(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	batchPath := filepath.Join(t.TempDir(), "filters.txt")
	if err := os.WriteFile(
		batchPath,
		[]byte("alice\nalice)(\nbob\n"),
		0o600,
	); err != nil {
		t.Fatalf("write ldapsearch invalid-filter batch: %v", err)
	}
	common := []string{
		"ldapsearch", "-H", uri, "-x", "-b", clientToolPeopleDN, "-s", "one",
		"-f", batchPath, "-LLL", "(uid=%s)", "uid",
	}

	withoutContinuous, stderr, exitCode := runLDAPClientCommand(common, "")
	if exitCode != 249 || stderr != "ldap_search_ext: Bad search filter (-7)\n" {
		t.Fatalf(
			"ldapsearch invalid filter exit=%d stdout=%q stderr=%q",
			exitCode,
			withoutContinuous,
			stderr,
		)
	}
	if !strings.Contains(withoutContinuous, "dn: uid=alice,") ||
		strings.Contains(withoutContinuous, "dn: uid=bob,") {
		t.Fatalf("ldapsearch invalid-filter stop output = %q", withoutContinuous)
	}

	continuousArgs := append(append([]string(nil), common[:8]...), "-c")
	continuousArgs = append(continuousArgs, common[8:]...)
	withContinuous, stderr, exitCode := runLDAPClientCommand(continuousArgs, "")
	if exitCode != 249 || stderr != "ldap_search_ext: Bad search filter (-7)\n" {
		t.Fatalf(
			"ldapsearch -c invalid filter exit=%d stdout=%q stderr=%q",
			exitCode,
			withContinuous,
			stderr,
		)
	}
	if !strings.Contains(withContinuous, "dn: uid=alice,") ||
		!strings.Contains(withContinuous, "dn: uid=bob,") {
		t.Fatalf("ldapsearch -c invalid-filter output = %q", withContinuous)
	}
}

func TestNormalizeLDAPSearchLDIFArgs(t *testing.T) {
	arguments, level := normalizeLDAPSearchLDIFArgs([]string{
		"-x", "-LLLL", "-L", "--", "(objectClass=*)", "-LLL",
	})
	want := []string{
		"-x", "-L", "-L", "-L", "-L", "-L", "--", "(objectClass=*)", "-LLL",
	}
	if level != 3 || strings.Join(arguments, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("normalize LDAP search args = (%q, %d), want (%q, 3)", arguments, level, want)
	}
}

func TestLDAPSearchContinuousModeContinuesAndReturnsLDAPStatus(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	batchPath := writeLDAPSearchLegacyBatch(t)
	common := []string{
		"ldapsearch", "-H", uri, "-x",
		"-b", clientToolPeopleDN, "-s", "one", "-z", "1",
		"-f", batchPath, "-LLL", "(uid=%s)", "uid",
	}

	withoutContinuous, stderr, exitCode := runLDAPClientCommand(common, "")
	if exitCode != 4 || stderr != "Size limit exceeded (4)\n" {
		t.Fatalf(
			"ldapsearch without -c exit=%d stdout=%q stderr=%q",
			exitCode,
			withoutContinuous,
			stderr,
		)
	}
	if strings.Contains(withoutContinuous, "dn: uid=bob,") {
		t.Fatalf("ldapsearch without -c executed the query after the error: %q", withoutContinuous)
	}

	continuousArgs := append(append([]string(nil), common[:12]...), "-c")
	continuousArgs = append(continuousArgs, common[12:]...)
	withContinuous, stderr, exitCode := runLDAPClientCommand(continuousArgs, "")
	if exitCode != 4 || stderr != "Size limit exceeded (4)\n" {
		t.Fatalf(
			"ldapsearch -c exit=%d stdout=%q stderr=%q",
			exitCode,
			withContinuous,
			stderr,
		)
	}
	if !strings.Contains(withContinuous, "dn: uid=bob,") {
		t.Fatalf("ldapsearch -c did not execute the query after the error: %q", withContinuous)
	}
}

func TestOpenLDAPReferenceLDAPSearchLegacyOutputAndContinuousMode(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP ldapsearch reference test")
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OPENLDAP_COMMIT = %q, want %q", got, openLDAPClientToolsCommit)
	}
	referenceTool, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatalf("find OpenLDAP ldapsearch: %v", err)
	}
	uri := startLDAPClientToolServer(t, nil)
	dn := "uid=alice," + clientToolPeopleDN
	for _, level := range [][]string{{}, {"-L"}, {"-LL"}, {"-LLL"}, {"-LLLL"}, {"-L", "-L"}} {
		t.Run(strings.Join(level, "_"), func(t *testing.T) {
			arguments := []string{"-H", uri, "-x", "-b", dn, "-s", "base"}
			arguments = append(arguments, level...)
			arguments = append(arguments, "(objectClass=*)", "uid")
			assertLDAPSearchMatchesOpenLDAP(t, referenceTool, arguments)
		})
	}
	t.Run("double_dash_position", func(t *testing.T) {
		assertLDAPSearchMatchesOpenLDAP(t, referenceTool, []string{
			"-H", uri, "-x", "-b", dn, "-s", "base", "--",
			"(objectClass=*)", "-L",
		})
	})

	batchPath := writeLDAPSearchLegacyBatch(t)
	baseArguments := []string{
		"-H", uri, "-x", "-b", clientToolPeopleDN, "-s", "one", "-z", "1",
		"-f", batchPath, "-LLL", "(uid=%s)", "uid",
	}
	for _, continuous := range []bool{false, true} {
		name := "stop"
		arguments := append([]string(nil), baseArguments...)
		if continuous {
			name = "continuous"
			arguments = append(arguments[:11], append([]string{"-c"}, arguments[11:]...)...)
		}
		t.Run(name, func(t *testing.T) {
			assertLDAPSearchMatchesOpenLDAP(t, referenceTool, arguments)
		})
	}

	invalidBatchPath := filepath.Join(t.TempDir(), "invalid-filters.txt")
	if err := os.WriteFile(
		invalidBatchPath,
		[]byte("alice\nalice)(\nbob\n"),
		0o600,
	); err != nil {
		t.Fatalf("write invalid-filter reference batch: %v", err)
	}
	for _, continuous := range []bool{false, true} {
		name := "invalid_filter_stop"
		arguments := []string{
			"-H", uri, "-x", "-b", clientToolPeopleDN, "-s", "one",
			"-f", invalidBatchPath, "-LLL", "(uid=%s)", "uid",
		}
		if continuous {
			name = "invalid_filter_continue"
			arguments = append(arguments[:7], append([]string{"-c"}, arguments[7:]...)...)
		}
		t.Run(name, func(t *testing.T) {
			assertLDAPSearchMatchesOpenLDAP(t, referenceTool, arguments)
		})
	}

	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Fatal("OPENLDAP_SOURCE is not set")
	}
	assertOpenLDAPClientSourceAnchors(t, source, "clients/tools/ldapsearch.c", []string{
		"case 'L':\t/* print entries in LDIF format */",
		"++ldif;",
		"if ( !contoper )",
		"if ( ldif == 0 ) {",
		"} else if ( ldif < 3 ) {",
		"if (ldif < 2 ) {",
	})
}

func writeLDAPSearchLegacyBatch(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "filters.txt")
	if err := os.WriteFile(path, []byte("alice\n*\nbob\n"), 0o600); err != nil {
		t.Fatalf("write ldapsearch batch: %v", err)
	}
	return path
}

func assertLDAPSearchMatchesOpenLDAP(t *testing.T, referenceTool string, arguments []string) {
	t.Helper()
	var referenceStderr bytes.Buffer
	command := exec.Command(referenceTool, arguments...)
	command.Stderr = &referenceStderr
	referenceStdout, referenceErr := command.Output()
	referenceExit := commandExitCode(referenceErr)

	localStdout, localStderr, localExit := runLDAPClientCommand(
		append([]string{"ldapsearch"}, arguments...),
		"",
	)
	if localExit != referenceExit || localStdout != string(referenceStdout) ||
		localStderr != referenceStderr.String() {
		t.Fatalf(
			"ldapsearch differs from OpenLDAP\nargs=%q\n"+
				"ldap-go: exit=%d stdout=%q stderr=%q\n"+
				"OpenLDAP: exit=%d stdout=%q stderr=%q err=%v",
			arguments,
			localExit,
			localStdout,
			localStderr,
			referenceExit,
			string(referenceStdout),
			referenceStderr.String(),
			referenceErr,
		)
	}
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
