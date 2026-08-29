package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestProductionCheckReportsConfirmedRisksWithoutSecrets(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedProductionCheckDatabase(t, databasePath, false, "cleartext-secret")

	var stdout, stderr bytes.Buffer
	err := runProductionCheck(
		[]string{"-db", databasePath, "-format", "json"},
		&stdout,
		&stderr,
	)
	if code := productionCheckErrorCode(err); code != productionCheckExitNotReady {
		t.Fatalf("runProductionCheck() exit = %d, error = %v, stderr = %q", code, err, stderr.String())
	}
	if strings.Contains(stdout.String(), "cleartext-secret") {
		t.Fatalf("JSON report leaked password material: %s", stdout.String())
	}

	var report productionCheckReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	if report.SchemaVersion != 1 || report.Ready || report.ExitCode != productionCheckExitNotReady {
		t.Fatalf("report header = %#v", report)
	}
	for _, id := range []string{
		"access.anonymous_updates",
		"audit.integrity",
		"backup.recovery",
		"password.default_hash",
		"password.stored_values",
		"timeout.connections",
		"transport.encryption",
	} {
		finding, ok := productionFindingByID(report, id)
		if !ok || finding.Status != productionCheckFail {
			t.Errorf("finding %s = %#v, present=%t", id, finding, ok)
		}
	}
}

func TestProductionCheckReadyJSON(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedProductionCheckDatabase(t, databasePath, true, "")

	var stdout, stderr bytes.Buffer
	err := runProductionCheck([]string{
		"-db", databasePath,
		"-tls-terminated-upstream",
		"-require-starttls",
		"-external-backup",
		"-audit-log", filepath.Join(t.TempDir(), "audit.jsonl"),
		"-audit-key-env",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runProductionCheck() error = %v, stderr = %q\n%s", err, stderr.String(), stdout.String())
	}

	var report productionCheckReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !report.Ready || report.ExitCode != 0 || report.Summary.Fail != 0 ||
		report.Summary.Unknown != 0 || report.Summary.Warn != 0 {
		t.Fatalf("ready report = %#v", report)
	}
	if len(report.Checks) < 10 {
		t.Fatalf("check count = %d, want at least 10", len(report.Checks))
	}
}

func TestProductionCheckExitCodePolicy(t *testing.T) {
	tests := []struct {
		name   string
		report productionCheckReport
		want   int
	}{
		{name: "ready", report: productionCheckReport{Summary: productionCheckSummary{Pass: 1}}, want: 0},
		{name: "warning", report: productionCheckReport{Summary: productionCheckSummary{Warn: 1}}, want: 0},
		{name: "strict warning", report: productionCheckReport{Strict: true, Summary: productionCheckSummary{Warn: 1}}, want: productionCheckExitInconclusive},
		{name: "unknown", report: productionCheckReport{Summary: productionCheckSummary{Unknown: 1}}, want: productionCheckExitInconclusive},
		{name: "failure wins", report: productionCheckReport{Strict: true, Summary: productionCheckSummary{Fail: 1, Unknown: 1}}, want: productionCheckExitNotReady},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := productionCheckReportExitCode(test.report); got != test.want {
				t.Fatalf("productionCheckReportExitCode() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestProductionCheckInvalidAuditKeyIsStructuredFailure(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedProductionCheckDatabase(t, databasePath, true, "")
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatalf("write audit key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err := runProductionCheck([]string{
		"-db", databasePath,
		"-tls-terminated-upstream",
		"-external-backup",
		"-audit-log", filepath.Join(t.TempDir(), "audit.jsonl"),
		"-audit-key-file", keyPath,
	}, &stdout, &stderr)
	if code := productionCheckErrorCode(err); code != productionCheckExitNotReady {
		t.Fatalf("exit = %d, error = %v, stderr = %q", code, err, stderr.String())
	}
	var report productionCheckReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	finding, ok := productionFindingByID(report, "audit.integrity")
	if !ok || finding.Status != productionCheckFail ||
		!strings.Contains(finding.Summary, "shorter than 32 bytes") {
		t.Fatalf("audit finding = %#v, present=%t", finding, ok)
	}
}

func TestProductionCheckInvalidConfigurationIsJSONFailure(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "directory.db")
	seedProductionCheckDatabase(t, databasePath, true, "")
	store, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.GetIn(storage.OpenLDAPConfigPartition, dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcPasswordHash", productionCheckValues("{NOT-A-HASH}"))
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, true)
	})
	if closeErr := store.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("make invalid configuration: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err = runProductionCheck([]string{"-db", databasePath}, &stdout, &stderr)
	if code := productionCheckErrorCode(err); code != productionCheckExitNotReady {
		t.Fatalf("exit = %d, error = %v", code, err)
	}
	var report productionCheckReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	if len(report.Checks) != 1 || report.Checks[0].ID != "configuration.valid" ||
		report.Checks[0].Status != productionCheckFail {
		t.Fatalf("configuration report = %#v", report)
	}
}

func TestProductionCheckUsageAndTextOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runProductionCheck([]string{"-format", "yaml"}, &stdout, &stderr)
	if code := productionCheckErrorCode(err); code != 2 {
		t.Fatalf("invalid format exit = %d, error = %v", code, err)
	}

	stdout.Reset()
	stderr.Reset()
	err = runProductionCheck([]string{"-h"}, &stdout, &stderr)
	if code := productionCheckErrorCode(err); code != 0 {
		t.Fatalf("help exit = %d, error = %v", code, err)
	}
	if !strings.Contains(stderr.String(), "production-check") {
		t.Fatalf("help output = %q", stderr.String())
	}

	var text bytes.Buffer
	report := productionCheckReport{
		Ready:   true,
		Summary: productionCheckSummary{Pass: 1},
		Checks: []productionCheckFinding{{
			ID: "configuration.valid", Status: productionCheckPass,
			Summary: "configuration valid",
		}},
	}
	if err := writeProductionCheckReport(&text, report, "text"); err != nil {
		t.Fatalf("write text report: %v", err)
	}
	if !strings.Contains(text.String(), "PASS") || !strings.Contains(text.String(), "ready=true exit=0") {
		t.Fatalf("text report = %q", text.String())
	}
}

func TestProductionStoredPasswordStrength(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	hash32 := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	hash64 := base64.RawStdEncoding.EncodeToString(make([]byte, 64))
	tests := []struct {
		value string
		want  productionPasswordStrength
	}{
		{value: "plain", want: productionPasswordWeak},
		{value: "{SSHA}opaque", want: productionPasswordWeak},
		{value: "{PBKDF2-SM3}100000$" + salt + "$" + hash32, want: productionPasswordStrong},
		{value: "{PBKDF2-SM3}1$" + salt + "$" + hash32, want: productionPasswordWeak},
		{value: "{PBKDF2-SHA256}100000$" + salt + "$" + hash32, want: productionPasswordStrong},
		{value: "{PBKDF2-SHA512}100000$" + salt + "$" + hash64, want: productionPasswordStrong},
		{value: "{PBKDF2-SM3}opaque", want: productionPasswordUnknown},
		{value: "{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$" + salt + "$" + hash32, want: productionPasswordStrong},
		{value: "{ARGON2}$argon2id$v=19$m=32,t=1,p=1$" + salt + "$" + hash32, want: productionPasswordWeak},
		{value: "{ARGON2}opaque", want: productionPasswordUnknown},
		{value: "{CRYPT}$y$j9T$opaque", want: productionPasswordUnknown},
		{value: "{CRYPT}$6$opaque", want: productionPasswordWeak},
		{value: "{RADIUS}opaque", want: productionPasswordUnknown},
		{value: "!{SSHA}disabled", want: productionPasswordDisabled},
	}
	for _, test := range tests {
		if got := productionStoredPasswordStrength([]byte(test.value)); got != test.want {
			t.Errorf("productionStoredPasswordStrength(%q) = %d, want %d", test.value, got, test.want)
		}
	}
}

func TestProductionDiagnosticRedaction(t *testing.T) {
	t.Parallel()

	raw := `syncrepl credential=top-secret password = "hidden" provider=ldap://user:pass@example.test token:abc123`
	redacted := redactProductionDiagnostic(raw)
	for _, secret := range []string{"top-secret", "hidden", "user:pass", "abc123"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redacted diagnostic leaked %q: %q", secret, redacted)
		}
	}
	if strings.Count(redacted, "<redacted>") < 4 {
		t.Fatalf("redacted diagnostic = %q", redacted)
	}
}

func TestProductionDatabasePermissionFinding(t *testing.T) {
	t.Run("private regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "directory.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write database: %v", err)
		}
		finding := productionDatabasePermissionFinding(path)
		want := productionCheckPass
		if runtime.GOOS == "windows" {
			want = productionCheckUnknown
		}
		if finding.Status != want {
			t.Fatalf("finding = %#v, want status %s", finding, want)
		}
	})

	t.Run("missing file is unknown", func(t *testing.T) {
		finding := productionDatabasePermissionFinding(filepath.Join(t.TempDir(), "missing.db"))
		if finding.Status != productionCheckUnknown {
			t.Fatalf("finding = %#v, want unknown", finding)
		}
	})

	t.Run("directory is rejected", func(t *testing.T) {
		finding := productionDatabasePermissionFinding(t.TempDir())
		if finding.Status != productionCheckFail || !strings.Contains(finding.Summary, "regular file") {
			t.Fatalf("finding = %#v, want regular-file failure", finding)
		}
	})

	if runtime.GOOS == "windows" {
		return
	}

	t.Run("symbolic link is rejected", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.db")
		link := filepath.Join(directory, "directory.db")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		finding := productionDatabasePermissionFinding(link)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "symbolic-link") {
			t.Fatalf("finding = %#v, want symbolic-link failure", finding)
		}
	})

	t.Run("group access is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "directory.db")
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatalf("write database: %v", err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatalf("chmod database: %v", err)
		}
		finding := productionDatabasePermissionFinding(path)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "0640") {
			t.Fatalf("finding = %#v, want mode failure", finding)
		}
	})

	t.Run("owner must be able to read and write", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "directory.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write database: %v", err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatalf("chmod database: %v", err)
		}
		finding := productionDatabasePermissionFinding(path)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "0400") {
			t.Fatalf("finding = %#v, want owner-mode failure", finding)
		}
	})

	t.Run("writable parent is rejected without exposing its path", func(t *testing.T) {
		secret := "credential=do-not-report"
		parent := filepath.Join(t.TempDir(), secret)
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatalf("mkdir parent: %v", err)
		}
		path := filepath.Join(parent, "directory.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write database: %v", err)
		}
		if err := os.Chmod(parent, 0o770); err != nil {
			t.Fatalf("chmod parent: %v", err)
		}
		finding := productionDatabasePermissionFinding(path)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "0770") {
			t.Fatalf("finding = %#v, want parent-mode failure", finding)
		}
		if strings.Contains(fmt.Sprint(finding), secret) {
			t.Fatalf("finding leaked inspected path: %#v", finding)
		}
	})

	t.Run("writable grandparent is rejected", func(t *testing.T) {
		grandparent := filepath.Join(t.TempDir(), "shared")
		parent := filepath.Join(grandparent, "private")
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatalf("mkdir ancestry: %v", err)
		}
		path := filepath.Join(parent, "directory.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write database: %v", err)
		}
		if err := os.Chmod(grandparent, 0o777); err != nil {
			t.Fatalf("chmod grandparent: %v", err)
		}
		finding := productionDatabasePermissionFinding(path)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "0777") {
			t.Fatalf("finding = %#v, want ancestor-mode failure", finding)
		}
	})

	t.Run("intermediate symbolic link is rejected", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		link := filepath.Join(root, "linked")
		if err := os.Symlink(realParent, link); err != nil {
			t.Fatalf("symlink parent: %v", err)
		}
		path := filepath.Join(link, "directory.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write database: %v", err)
		}
		finding := productionDatabasePermissionFinding(path)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "symbolic-link") {
			t.Fatalf("finding = %#v, want intermediate symlink failure", finding)
		}
	})
}

func TestProductionBackupDirectoryPermissionFinding(t *testing.T) {
	t.Run("private directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "backups")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir backup: %v", err)
		}
		finding := productionBackupDirectoryPermissionFinding(path)
		want := productionCheckPass
		if runtime.GOOS == "windows" {
			want = productionCheckUnknown
		}
		if finding.Status != want {
			t.Fatalf("finding = %#v, want status %s", finding, want)
		}
	})

	t.Run("missing directory is rejected", func(t *testing.T) {
		finding := productionBackupDirectoryPermissionFinding(filepath.Join(t.TempDir(), "missing"))
		if finding.Status != productionCheckFail {
			t.Fatalf("finding = %#v, want failure", finding)
		}
	})

	t.Run("regular file is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "backups")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write backup path: %v", err)
		}
		finding := productionBackupDirectoryPermissionFinding(path)
		if finding.Status != productionCheckFail || !strings.Contains(finding.Summary, "directory") {
			t.Fatalf("finding = %#v, want directory failure", finding)
		}
	})

	if runtime.GOOS == "windows" {
		return
	}

	t.Run("group access is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "backups")
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatalf("mkdir backup: %v", err)
		}
		if err := os.Chmod(path, 0o750); err != nil {
			t.Fatalf("chmod backup: %v", err)
		}
		finding := productionBackupDirectoryPermissionFinding(path)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "0750") {
			t.Fatalf("finding = %#v, want mode failure", finding)
		}
	})

	t.Run("writable parent is rejected", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatalf("mkdir parent: %v", err)
		}
		path := filepath.Join(parent, "backups")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir backup: %v", err)
		}
		if err := os.Chmod(parent, 0o707); err != nil {
			t.Fatalf("chmod parent: %v", err)
		}
		finding := productionBackupDirectoryPermissionFinding(path)
		if finding.Status != productionCheckFail || !productionFindingHasEvidence(finding, "0707") {
			t.Fatalf("finding = %#v, want parent-mode failure", finding)
		}
	})
}

func productionFindingHasEvidence(finding productionCheckFinding, substring string) bool {
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence, substring) {
			return true
		}
	}
	return false
}

func productionCheckErrorCode(err error) int {
	if err == nil {
		return 0
	}
	code, _, ok := ldapClientExitStatus(err)
	if !ok {
		return 1
	}
	return code
}

func productionFindingByID(
	report productionCheckReport,
	id string,
) (productionCheckFinding, bool) {
	for _, finding := range report.Checks {
		if finding.ID == id {
			return finding, true
		}
	}
	return productionCheckFinding{}, false
}

func seedProductionCheckDatabase(
	t *testing.T,
	path string,
	secure bool,
	password string,
) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer store.Close()

	global := directory.Entry{
		DN: "cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: productionCheckValues("olcGlobal")},
			{Description: "cn", Values: productionCheckValues("config")},
		},
	}
	database := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: productionCheckValues("olcDatabaseConfig")},
			{Description: "olcDatabase", Values: productionCheckValues("{1}mdb")},
			{Description: "olcSuffix", Values: productionCheckValues("dc=example,dc=com")},
		},
	}
	if secure {
		global.Attributes = append(global.Attributes,
			directory.Attribute{Description: "olcPasswordHash", Values: productionCheckValues("{PBKDF2-SM3}")},
			directory.Attribute{Description: "olcIdleTimeout", Values: productionCheckValues("300")},
			directory.Attribute{Description: "olcWriteTimeout", Values: productionCheckValues("30")},
		)
		database.Attributes = append(database.Attributes, directory.Attribute{
			Description: "olcAccess", Values: productionCheckValues("{0}to * by users read by * none"),
		})
	} else {
		global.Attributes = append(global.Attributes,
			directory.Attribute{Description: "olcAllows", Values: productionCheckValues("update_anon")},
		)
		database.Attributes = append(database.Attributes, directory.Attribute{
			Description: "olcAccess", Values: productionCheckValues("{0}to * by * manage"),
		})
	}

	err = store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{global, database} {
			if err := writer.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
				return err
			}
		}
		if password != "" {
			entry := directory.Entry{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: productionCheckValues("inetOrgPerson")},
					{Description: "uid", Values: productionCheckValues("alice")},
					{Description: "cn", Values: productionCheckValues("Alice")},
					{Description: "sn", Values: productionCheckValues("Example")},
					{Description: "userPassword", Values: productionCheckValues(password)},
				},
			}
			if err := writer.PutIn(
				storage.OpenLDAPDatabasePartition("{1}mdb", nil), entry, false,
			); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	})
	if err != nil {
		t.Fatalf("seed database: %v", err)
	}
}

func productionCheckValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}
