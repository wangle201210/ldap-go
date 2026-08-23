package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestLDAPSearchBatchFileAndStdinSubstitution(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	batchPath := filepath.Join(t.TempDir(), "filters.txt")
	if err := os.WriteFile(batchPath, []byte("alice\nbob\r\n"), 0o600); err != nil {
		t.Fatalf("write batch file: %v", err)
	}

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapsearch", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-b", clientToolPeopleDN, "-s", "one", "-LLL",
			"-f", batchPath, "(uid=%s)", "uid",
		},
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("batch file search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entries := parseLDAPSearchOutput(t, stdout)
	got := make([]string, len(entries))
	for index := range entries {
		got[index] = entries[index].GetAttributeValue("uid")
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"alice", "bob"}) {
		t.Fatalf("batch file UIDs = %q", got)
	}

	stdin := clientToolRootPassword + "\nalice\nbob\n"
	stdout, stderr, exitCode = runLDAPClientCommand(
		[]string{
			"ldapsearch", "-H", uri, "-x", "-D", clientToolRootDN, "-W",
			"-b", clientToolPeopleDN, "-s", "one", "-LLL",
			"-f", "-", "(uid=%s)", "uid",
		},
		stdin,
	)
	if exitCode != 0 || !strings.Contains(stderr, "Enter LDAP Password:") {
		t.Fatalf("stdin batch search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stdout, clientToolRootPassword) || strings.Contains(stderr, clientToolRootPassword) {
		t.Fatalf("stdin batch search exposed the bind password: stdout=%q stderr=%q", stdout, stderr)
	}
	entries = parseLDAPSearchOutput(t, stdout)
	if len(entries) != 2 {
		t.Fatalf("stdin batch entries = %d, want 2: %q", len(entries), stdout)
	}
}

func TestLDAPSearchBatchPatternValidationAndInputSafety(t *testing.T) {
	for _, pattern := range []string{"(uid=%d)", "(&(uid=%s)(cn=%s))", "(uid=100%)"} {
		if _, err := validateLDAPSearchBatchPattern(pattern); err == nil {
			t.Errorf("validateLDAPSearchBatchPattern(%q) succeeded", pattern)
		}
	}
	placeholder, err := validateLDAPSearchBatchPattern("(uid=%s)")
	if err != nil || placeholder < 0 {
		t.Fatalf("validateLDAPSearchBatchPattern(valid) = %d, %v", placeholder, err)
	}
	queries, err := readLDAPSearchBatch(
		strings.NewReader("alice\nbob"),
		"(uid=%s)",
		placeholder,
		"test batch",
	)
	if err != nil || !slices.Equal(queries, []string{"(uid=alice)", "(uid=bob)"}) {
		t.Fatalf("readLDAPSearchBatch(valid) = %q, %v", queries, err)
	}

	const confidential = "confidential-filter-value"
	_, err = readLDAPSearchBatch(
		strings.NewReader(confidential+")("),
		"(uid=%s)",
		placeholder,
		"test batch",
	)
	if err == nil || strings.Contains(err.Error(), confidential) {
		t.Fatalf("malformed batch error = %q", err)
	}
	_, err = readLDAPSearchBatch(
		strings.NewReader("alice\x00admin\n"),
		"(uid=%s)",
		placeholder,
		"test batch",
	)
	if err == nil || !strings.Contains(err.Error(), "prohibited control") {
		t.Fatalf("NUL batch error = %v", err)
	}

	oversized := bytes.Repeat([]byte{'a'}, maxLDAPSearchBatchSize+1)
	_, err = readLDAPSearchBatch(bytes.NewReader(oversized), "(uid=%s)", placeholder, "test batch")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized batch error = %v", err)
	}
}

func TestLDAPSearchBatchFilePathAndPermissionChecks(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "batch.txt")
	if err := os.WriteFile(path, []byte("alice\n"), 0o600); err != nil {
		t.Fatalf("write batch input: %v", err)
	}
	placeholder, err := validateLDAPSearchBatchPattern("(uid=%s)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readLDAPSearchBatchFile(path, "(uid=%s)", placeholder); err != nil {
		t.Fatalf("read secure batch file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o622); err != nil {
			t.Fatalf("chmod batch input: %v", err)
		}
		if _, err := readLDAPSearchBatchFile(path, "(uid=%s)", placeholder); err == nil ||
			!strings.Contains(err.Error(), "writable by group") {
			t.Fatalf("insecure batch permissions error = %v", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("restore batch permissions: %v", err)
		}
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(directory, "batch-link.txt")
		if err := os.Symlink(path, link); err != nil {
			t.Fatalf("symlink batch input: %v", err)
		}
		if _, err := readLDAPSearchBatchFile(link, "(uid=%s)", placeholder); err == nil ||
			!strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("batch symlink error = %v", err)
		}
	}
	if err := os.Truncate(path, maxLDAPSearchBatchSize+1); err != nil {
		t.Fatalf("truncate batch input: %v", err)
	}
	if _, err := readLDAPSearchBatchFile(path, "(uid=%s)", placeholder); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized batch file error = %v", err)
	}
}

func TestLDAPSearchBinaryValuesToSecureFiles(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	directory := t.TempDir()
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapsearch", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-b", "uid=alice," + clientToolPeopleDN, "-s", "base", "-LLL",
			"-t", "-T", directory, "-F", "https://files.example.test/ldap-values/",
			"(objectClass=*)", "cn", "jpegPhoto",
		},
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("temporary value search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stdout, base64Value([]byte{0x00, 0xff, 0x10})) ||
		!strings.Contains(stdout, "cn: Alice Example") {
		t.Fatalf("temporary value LDIF did not preserve printable values: %q", stdout)
	}
	var reference string
	unfolded := strings.ReplaceAll(stdout, "\n ", "")
	for _, line := range strings.Split(unfolded, "\n") {
		if strings.HasPrefix(line, "jpegPhoto:< ") {
			reference = strings.TrimPrefix(line, "jpegPhoto:< ")
			break
		}
	}
	if reference == "" {
		t.Fatalf("temporary value LDIF has no URL: %q", stdout)
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "files.example.test" {
		t.Fatalf("temporary value URL = %q, %v", reference, err)
	}
	valuePath := filepath.Join(directory, filepath.Base(parsed.Path))
	value, err := os.ReadFile(valuePath)
	if err != nil {
		t.Fatalf("read temporary value: %v", err)
	}
	if !bytes.Equal(value, []byte{0x00, 0xff, 0x10}) {
		t.Fatalf("temporary value = %v", value)
	}
	if info, err := os.Stat(valuePath); err != nil {
		t.Fatalf("stat temporary value: %v", err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("temporary value permissions = %o", info.Mode().Perm())
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary directory entries = %v, %v", files, err)
	}
}

func TestLDAPSearchValueFileConfigurationRejectsUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	for _, prefix := range []string{
		"ftp://files.example.test/",
		"https://user:secret@files.example.test/",
		"https://files.example.test/path?token=secret",
		"file://remote.example.test/tmp/",
	} {
		if _, err := openLDAPSearchValueFiles(true, directory, prefix); err == nil ||
			strings.Contains(err.Error(), "secret") {
			t.Errorf("openLDAPSearchValueFiles(prefix=%q) error = %v", prefix, err)
		}
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(filepath.Dir(directory), "value-dir-link")
		if err := os.Symlink(directory, link); err != nil {
			t.Fatalf("symlink temporary directory: %v", err)
		}
		defer os.Remove(link)
		if _, err := openLDAPSearchValueFiles(true, link, ""); err == nil ||
			!strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("temporary directory symlink error = %v", err)
		}
	}
}

func TestLDAPSearchCriticalAndPromptPaging(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	common := []string{
		"ldapsearch", "-H", uri, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
		"-b", clientToolPeopleDN, "-s", "one", "-LLL",
	}
	stdout, stderr, exitCode := runLDAPClientCommand(
		append(append([]string(nil), common...),
			"-E", "!pr=1/noprompt", "(objectClass=inetOrgPerson)", "uid"),
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("critical paging exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if entries := parseLDAPSearchOutput(t, stdout); len(entries) != 2 {
		t.Fatalf("critical paging entries = %d: %q", len(entries), stdout)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...),
			"-E", "pr=1/prompt", "(objectClass=inetOrgPerson)", "uid"),
		"2\n",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("prompt paging exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Count(stdout, "dn: uid=") != 2 ||
		!strings.Contains(stdout, "Press [size] Enter for the next {1|size} entries.") {
		t.Fatalf("prompt paging output = %q", stdout)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...),
			"-E", "pr=1/prompt", "(objectClass=inetOrgPerson)", "uid"),
		"",
	)
	if exitCode != 0 || strings.Count(stdout, "dn: uid=") != 2 {
		t.Fatalf("EOF prompt paging exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPSearchPagingOptionAndPromptParsing(t *testing.T) {
	paging, err := parseLDAPSearchPagingExtension("!pr=25/prompt")
	if err != nil || paging.size != 25 || !paging.critical || !paging.prompt {
		t.Fatalf("parse critical prompt paging = %#v, %v", paging, err)
	}
	control := newLDAPSearchPagingControl(25, []byte("cookie"), true)
	if !control.critical || control.oid != ldap.ControlTypePaging || !control.hasValue || len(control.value) == 0 {
		t.Fatalf("critical paging control = %#v", control)
	}
	reader := bufio.NewReader(strings.NewReader("100\n\n"))
	if size, provided, err := readLDAPSearchPagingPrompt(reader); err != nil || !provided || size != 100 {
		t.Fatalf("read paging size = %d, %t, %v", size, provided, err)
	}
	if size, provided, err := readLDAPSearchPagingPrompt(reader); err != nil || provided || size != 0 {
		t.Fatalf("read empty paging prompt = %d, %t, %v", size, provided, err)
	}
	const confidential = "confidential-paging-input"
	_, _, err = readLDAPSearchPagingPrompt(bufio.NewReader(strings.NewReader(confidential + "\n")))
	if err == nil || strings.Contains(err.Error(), confidential) {
		t.Fatalf("invalid paging input error = %v", err)
	}
}

func TestLDAPSearchCriticalAndPromptPagingRejectReferralChasing(t *testing.T) {
	for _, extension := range []string{"!pr=1/noprompt", "pr=1/prompt", "!pr=1/prompt"} {
		stdout, stderr, exitCode := runLDAPClientCommand(
			[]string{"ldapsearch", "-x", "-C", "-E", extension, "(objectClass=*)"},
			"",
		)
		if exitCode != 1 || stdout != "" ||
			!strings.Contains(stderr, "cannot be combined with referral chasing") {
			t.Errorf(
				"ldapsearch -C -E %s exit=%d stdout=%q stderr=%q",
				extension,
				exitCode,
				stdout,
				stderr,
			)
		}
	}
}

func base64Value(value []byte) string {
	return "jpegPhoto:: " + base64.StdEncoding.EncodeToString(value)
}
