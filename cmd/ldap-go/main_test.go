package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPasswordCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		password string
	}{
		{name: "environment", password: "environment secret"},
		{name: "stdin LF", input: "stdin secret\n", password: "stdin secret"},
		{name: "stdin CRLF", input: "stdin secret\r\n", password: "stdin secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(
				[]string{"passwd", "-iterations", "10"},
				strings.NewReader(test.input),
				&stdout,
				&stderr,
				func(name string) string {
					if name == passwordEnvironment && test.input == "" {
						return test.password
					}
					return ""
				},
			)
			if exitCode != 0 {
				t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
			}
			stored := []byte(strings.TrimSuffix(stdout.String(), "\n"))
			if !strings.HasPrefix(string(stored), "{PBKDF2-SM3}10$") {
				t.Fatalf("stdout = %q", stdout.String())
			}
			if !auth.VerifyPassword(stored, []byte(test.password)) {
				t.Fatal("generated password does not verify")
			}
			if auth.VerifyPassword(stored, []byte("wrong")) {
				t.Fatal("generated password accepted an incorrect value")
			}
		})
	}
}

func TestAuditVerifyCommand(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	logPath := filepath.Join(directoryPath, "audit.jsonl")
	keyPath := filepath.Join(directoryPath, "audit.key")
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	sink, err := audit.OpenFile(logPath, key)
	if err != nil {
		t.Fatalf("OpenFile(): %v", err)
	}
	if err := sink.Record(audit.Event{Operation: "search", Outcome: "success"}); err != nil {
		t.Fatalf("Record(): %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"audit-verify", "-audit-log", logPath, "-audit-key-file", keyPath},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 || stdout.String() != "verified 1 audit records\n" {
		t.Fatalf("audit-verify exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}

	encoded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	encoded = bytes.Replace(encoded, []byte(`"search"`), []byte(`"delete"`), 1)
	if err := os.WriteFile(logPath, encoded, 0o600); err != nil {
		t.Fatalf("tamper log: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	exitCode = run(
		[]string{"audit-verify", "-audit-log", logPath, "-audit-key-file", keyPath},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 1 || !strings.Contains(stderr.String(), "integrity") {
		t.Fatalf("tampered audit-verify exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestMaintenanceCommands(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	databasePath := filepath.Join(directoryPath, "directory.db")
	backupPath := filepath.Join(directoryPath, "backup.db")
	restoredPath := filepath.Join(directoryPath, "restored.db")
	store, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	entry := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      [][]byte{[]byte("top"), []byte("domain")},
			},
			{
				Description: "structuralObjectClass",
				Values:      [][]byte{[]byte("domain")},
			},
			{Description: "dc", Values: [][]byte{[]byte("example")}},
		},
	}
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	entryPartition := storage.OpenLDAPBootstrapPartition(entryDN)
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.PutIn(
			entryPartition,
			entry,
			false,
		); err != nil {
			return err
		}
		if err := writer.SetNamingContexts([]string{"dc=example,dc=com"}); err != nil {
			return err
		}
		return writer.SetMetadata("test", []byte("metadata"))
	})
	if err != nil {
		_ = store.Close()
		t.Fatalf("seed database: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	tests := []struct {
		name     string
		args     []string
		action   string
		metadata int
	}{
		{
			name:   "check",
			args:   []string{"check", "-db", databasePath},
			action: "checked",
		},
		{
			name: "backup",
			args: []string{
				"backup", "-db", databasePath, "-out", backupPath,
			},
			action: "backed up",
		},
		{
			name: "restore",
			args: []string{
				"restore", "-backup", backupPath, "-db", restoredPath,
			},
			action:   "restored",
			metadata: 5,
		},
		{
			name:     "rebuild",
			args:     []string{"rebuild", "-db", restoredPath},
			action:   "rebuilt",
			metadata: 5,
		},
		{
			name:     "reindex alias",
			args:     []string{"reindex", "-db", restoredPath},
			action:   "rebuilt",
			metadata: 5,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(
				test.args,
				strings.NewReader(""),
				&stdout,
				&stderr,
				func(string) string { return "" },
			)
			if exitCode != 0 {
				t.Fatalf(
					"run() exit code = %d, stdout = %q, stderr = %q",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
			metadata := test.metadata
			if metadata == 0 {
				metadata = 2
			}
			if !strings.Contains(stdout.String(), test.action+" 1 entries in 1 partitions") ||
				!strings.Contains(stdout.String(), fmt.Sprintf("with %d metadata records", metadata)) {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
	var slapindexStdout bytes.Buffer
	var slapindexStderr bytes.Buffer
	if exitCode := run(
		[]string{"slapindex", "-db", restoredPath},
		strings.NewReader(""),
		&slapindexStdout,
		&slapindexStderr,
		func(string) string { return "" },
	); exitCode != 0 || slapindexStdout.String() != "reindexed 1 database(s)\n" {
		t.Fatalf(
			"slapindex exit=%d stdout=%q stderr=%q",
			exitCode,
			slapindexStdout.String(),
			slapindexStderr.String(),
		)
	}

	restored, err := storage.OpenBolt(restoredPath)
	if err != nil {
		t.Fatalf("OpenBolt(restored): %v", err)
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	err = restored.View(context.Background(), func(reader storage.Reader) error {
		got, err := reader.GetIn(entryPartition, dn)
		if err != nil {
			return err
		}
		if !entry.Equal(got) {
			t.Fatalf("restored entry = %#v, want %#v", got, entry)
		}
		metadata, err := reader.Metadata("test")
		if err != nil {
			return err
		}
		if !bytes.Equal(metadata, []byte("metadata")) {
			t.Fatalf("restored metadata = %q", metadata)
		}
		return nil
	})
	if err != nil {
		_ = restored.Close()
		t.Fatalf("verify restored database: %v", err)
	}
	if err := restored.Close(); err != nil {
		t.Fatalf("Close(restored): %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"backup", "-db", databasePath, "-out", backupPath},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 1 || !strings.Contains(stderr.String(), "--replace") {
		t.Fatalf(
			"second backup exit code = %d, stdout = %q, stderr = %q",
			exitCode,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestMaintenanceCommandsValidateArguments(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"backup"},
		{"restore"},
		{"check", "unexpected"},
		{"rebuild", "unexpected"},
	}
	for _, args := range tests {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if exitCode := run(
			args,
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(string) string { return "" },
		); exitCode != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "error:") {
			t.Errorf(
				"run(%v) exit code = %d, stdout = %q, stderr = %q",
				args,
				exitCode,
				stdout.String(),
				stderr.String(),
			)
		}
	}
}

func TestDNCommandUsesBuiltinAndConfiguredSchema(t *testing.T) {
	t.Parallel()

	databasePath := seedOfflineCommandDatabase(t, "")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "normalized multiple DNs",
			args: []string{
				"dn", "-db", databasePath, "-N",
				"CN= Alice  Smith ,DC=Example,DC=COM",
				"employeeCode= AB  12 ,DC=Example,DC=COM",
			},
			want: "cn=alice smith,dc=example,dc=com\n" +
				"employeeCode=ab 12,dc=example,dc=com\n",
		},
		{
			name: "pretty alias",
			args: []string{
				"slapdn", "-db", databasePath, "-P",
				"CN= Alice  Smith ,DC=Example,DC=COM",
			},
			want: "cn=Alice  Smith,dc=Example,dc=COM\n",
		},
		{
			name: "OpenLDAP default report",
			args: []string{
				"dn", "-db", databasePath,
				"CN= Alice  Smith ,DC=Example,DC=COM",
			},
			want: "DN: <CN= Alice  Smith ,DC=Example,DC=COM> check succeeded\n" +
				"normalized: <cn=alice smith,dc=example,dc=com>\n" +
				"pretty:     <cn=Alice  Smith,dc=Example,dc=COM>\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(
				test.args,
				strings.NewReader(""),
				&stdout,
				&stderr,
				func(string) string { return "" },
			)
			if exitCode != 0 || stdout.String() != test.want || stderr.Len() != 0 {
				t.Fatalf(
					"run() exit = %d, stdout = %q, stderr = %q",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}

func TestDNCommandRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	databasePath := seedOfflineCommandDatabase(t, "")
	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{
			name:    "invalid DN syntax",
			args:    []string{"dn", "-db", databasePath, "cn"},
			message: "check failed",
		},
		{
			name:    "invalid attribute syntax",
			args:    []string{"dn", "-db", databasePath, "dc=张,dc=com"},
			message: "value is not IA5",
		},
		{
			name:    "empty directory string",
			args:    []string{"dn", "-db", databasePath, "uid=,dc=example,dc=com"},
			message: "empty DN assertion value",
		},
		{
			name:    "empty octet string",
			args:    []string{"dn", "-db", databasePath, "jpegPhoto=,dc=example,dc=com"},
			message: "empty DN assertion value",
		},
		{
			name: "unknown attribute type",
			args: []string{
				"dn", "-db", databasePath,
				"unknownAttribute=value,dc=example,dc=com",
			},
			message: "undefined attribute type",
		},
		{
			name: "mode conflict",
			args: []string{
				"dn", "-db", databasePath, "-N", "-P",
				"dc=example,dc=com",
			},
			message: "mutually exclusive",
		},
		{
			name: "unsupported OpenLDAP config flag",
			args: []string{
				"slapdn", "-db", databasePath, "-f", "slapd.conf",
				"dc=example,dc=com",
			},
			message: "flag provided but not defined",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(
				test.args,
				strings.NewReader(""),
				&stdout,
				&stderr,
				func(string) string { return "" },
			)
			if exitCode != 1 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), test.message) {
				t.Fatalf(
					"run() exit = %d, stdout = %q, stderr = %q",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}

func TestConfigurationTestCommandAndAlias(t *testing.T) {
	t.Parallel()

	databasePath := seedOfflineCommandDatabase(t, "")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"config-test", "-db", databasePath},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), "configuration OK: 1 databases, 1 overlays") ||
		!strings.Contains(stdout.String(), "ACL: 1 rules") {
		t.Fatalf(
			"config-test exit = %d, stdout = %q, stderr = %q",
			exitCode,
			stdout.String(),
			stderr.String(),
		)
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = run(
		[]string{"slaptest", "-db", databasePath, "-Q"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf(
			"quiet slaptest exit = %d, stdout = %q, stderr = %q",
			exitCode,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestConfigurationTestRejectsInvalidRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	databasePath := seedOfflineCommandDatabase(t, "minssf=invalid")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"config-test", "-db", databasePath},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "olcSaslSecProps") {
		t.Fatalf(
			"config-test exit = %d, stdout = %q, stderr = %q",
			exitCode,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestOfflineConfigurationCommandsDoNotModifyDatabase(t *testing.T) {
	t.Parallel()

	databasePath := seedOfflineCommandDatabase(t, "")
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read database before commands: %v", err)
	}
	for _, args := range [][]string{
		{"config-test", "-db", databasePath, "-Q"},
		{"dn", "-db", databasePath, "-N", "dc=example,dc=com"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if exitCode := run(
			args,
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(string) string { return "" },
		); exitCode != 0 {
			t.Fatalf(
				"run(%v) exit = %d, stdout = %q, stderr = %q",
				args,
				exitCode,
				stdout.String(),
				stderr.String(),
			)
		}
	}
	after, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read database after commands: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("offline commands modified the bbolt database file")
	}
}

func TestOfflineConfigurationCommandsDoNotCreateMissingDatabase(t *testing.T) {
	t.Parallel()

	parent := filepath.Join(t.TempDir(), "missing")
	databasePath := filepath.Join(parent, "directory.db")
	for _, args := range [][]string{
		{"config-test", "-db", databasePath},
		{"dn", "-db", databasePath, "dc=example,dc=com"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if exitCode := run(
			args,
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(string) string { return "" },
		); exitCode != 1 || stdout.Len() != 0 {
			t.Fatalf(
				"run(%v) exit = %d, stdout = %q, stderr = %q",
				args,
				exitCode,
				stdout.String(),
				stderr.String(),
			)
		}
		if _, err := os.Stat(parent); !os.IsNotExist(err) {
			t.Fatalf("run(%v) created parent directory: %v", args, err)
		}
	}
}

func seedOfflineCommandDatabase(t *testing.T, saslSecurityProperties string) string {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "offline.db")
	store, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	globalAttributes := []directory.Attribute{
		{Description: "objectClass", Values: offlineCommandValues("olcGlobal")},
		{Description: "cn", Values: offlineCommandValues("config")},
		{
			Description: "olcAccess",
			Values:      offlineCommandValues("{0}to * by * read"),
		},
	}
	if saslSecurityProperties != "" {
		globalAttributes = append(globalAttributes, directory.Attribute{
			Description: "olcSaslSecProps",
			Values:      offlineCommandValues(saslSecurityProperties),
		})
	}
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{DN: "cn=config", Attributes: globalAttributes},
			{
				DN: "cn={1}offline,cn=schema,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcAttributeTypes",
						Values: offlineCommandValues(
							"( 1.3.6.1.4.1.55555.1.1 NAME 'employeeCode' " +
								"EQUALITY caseIgnoreMatch SYNTAX " +
								"1.3.6.1.4.1.1466.115.121.1.15 )",
						),
					},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcDatabase",
						Values:      offlineCommandValues("{1}mdb"),
					},
					{
						Description: "olcSuffix",
						Values:      offlineCommandValues("dc=example,dc=com"),
					},
				},
			},
			{
				DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcOverlay",
						Values:      offlineCommandValues("{0}sssvlv"),
					},
				},
			},
			{
				DN: "dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "dc", Values: offlineCommandValues("example")},
				},
			},
		}
		for index, entry := range entries {
			partition := storage.OpenLDAPConfigPartition
			if index == len(entries)-1 {
				partition = ""
			}
			if err := writer.PutIn(partition, entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	})
	if err != nil {
		_ = store.Close()
		t.Fatalf("seed offline database: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close offline database: %v", err)
	}
	return databasePath
}

func offlineCommandValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}

func TestOpenAuditSinkValidatesConfiguration(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	logPath := filepath.Join(directoryPath, "audit.jsonl")
	keyPath := filepath.Join(directoryPath, "audit.key")
	getenv := func(string) string { return "" }
	if _, err := openAuditSink("", keyPath, getenv); err == nil {
		t.Fatal("openAuditSink() accepted a key without a log")
	}
	if _, err := openAuditSink(logPath, "", getenv); err == nil {
		t.Fatal("openAuditSink() accepted a log without a key")
	}
	if _, err := openAuditSink(logPath, logPath, getenv); err == nil {
		t.Fatal("openAuditSink() accepted the same log and key path")
	}
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("k", 32)), 0o644); err != nil {
		t.Fatalf("write permissive key: %v", err)
	}
	if _, err := openAuditSink(logPath, keyPath, getenv); err == nil ||
		!strings.Contains(err.Error(), "permissions") {
		t.Fatalf("openAuditSink(permissive key) error = %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("Chmod(): %v", err)
	}
	sink, err := openAuditSink(logPath, keyPath, getenv)
	if err != nil {
		t.Fatalf("openAuditSink(valid): %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, err := openAuditSink(logPath, keyPath, func(name string) string {
		if name == auditKeyEnvironment {
			return strings.Repeat("e", 32)
		}
		return ""
	}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("openAuditSink(duplicate keys) error = %v", err)
	}
}

func TestServeRejectsNonPositiveShutdownTimeout(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"0", "-1s"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run(
			[]string{"serve", "-shutdown-timeout", value},
			strings.NewReader(""),
			&stdout,
			&stderr,
			func(string) string { return "" },
		)
		if exitCode != 1 || stdout.Len() != 0 ||
			!strings.Contains(stderr.String(), "shutdown-timeout must be positive") {
			t.Fatalf(
				"serve shutdown timeout %q: exit=%d stdout=%q stderr=%q",
				value,
				exitCode,
				stdout.String(),
				stderr.String(),
			)
		}
	}
}

func TestServeRejectsNonPositiveTransactionLimits(t *testing.T) {
	t.Parallel()

	for _, flagName := range []string{
		"transaction-max-operations",
		"transaction-max-queued-bytes",
	} {
		for _, value := range []string{"0", "-1"} {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(
				[]string{"serve", "-" + flagName, value},
				strings.NewReader(""),
				&stdout,
				&stderr,
				func(string) string { return "" },
			)
			if exitCode != 1 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), "-"+flagName+" must be positive") {
				t.Fatalf(
					"serve %s %q: exit=%d stdout=%q stderr=%q",
					flagName,
					value,
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
		}
	}
}

func TestServeRejectsNonPositiveGlobalResourceLimits(t *testing.T) {
	t.Parallel()
	for _, flagName := range []string{
		"max-connections",
		"max-concurrent-operations",
		"max-concurrent-handshakes",
	} {
		for _, value := range []string{"0", "-1"} {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(
				[]string{"serve", "-" + flagName, value},
				strings.NewReader(""),
				&stdout,
				&stderr,
				func(string) string { return "" },
			)
			if exitCode != 1 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), "-"+flagName+" must be positive") {
				t.Fatalf(
					"serve %s %q: exit=%d stdout=%q stderr=%q",
					flagName,
					value,
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
		}
	}
}

func TestPasswordCommandRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		args  []string
		input string
	}{
		{name: "empty", args: []string{"passwd"}},
		{
			name:  "iterations",
			args:  []string{"passwd", "-iterations", "0"},
			input: "secret\n",
		},
		{
			name:  "unexpected argument",
			args:  []string{"passwd", "secret"},
			input: "ignored\n",
		},
		{
			name:  "input limit",
			args:  []string{"passwd"},
			input: strings.Repeat("x", maxPasswordInputSize+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if exitCode := run(
				test.args,
				strings.NewReader(test.input),
				&stdout,
				&stderr,
				func(string) string { return "" },
			); exitCode != 1 {
				t.Fatalf(
					"run() exit code = %d, stdout = %q, stderr = %q",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "error:") {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestImportCommand(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "directory.db")
	input := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"import", "-db", databasePath, "-ldif", "-", "-replace"},
		strings.NewReader(input),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "imported 2 entries") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	store, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	dn, err := directory.ParseDN("uid=alice,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.View(context.Background(), func(tx storage.Reader) error {
		_, err := tx.Get(dn)
		return err
	}); err != nil {
		t.Fatalf("imported entry: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = run(
		[]string{"export", "-db", databasePath, "-ldif", "-"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("export run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dn: uid=alice,dc=example,dc=com") ||
		!strings.Contains(stderr.String(), "exported 2 entries") {
		t.Fatalf("export stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestDatabaseSelectedImportExportCommands(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "partitioned.db")
	configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
entryUUID: 11111111-1111-4111-8111-111111111111

`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		[]string{"import", "-db", databasePath, "-ldif", "-", "-replace"},
		strings.NewReader(configLDIF),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("config import exit code = %d, stderr = %q", exitCode, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	dataLDIF := `dn: dc=example,dc=com
objectClass: domain
dc: example
description: selected database

`
	exitCode = run(
		[]string{
			"import",
			"-db", databasePath,
			"-ldif", "-",
			"-database", "1",
			"-replace",
		},
		strings.NewReader(dataLDIF),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("data import exit code = %d, stderr = %q", exitCode, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = run(
		[]string{
			"export",
			"-db", databasePath,
			"-ldif", "-",
			"-database", "{1}mdb",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 0 {
		t.Fatalf("selected export exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "description: selected database") ||
		!strings.Contains(stderr.String(), "exported 1 entries") {
		t.Fatalf("selected export stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestDatabaseSelectorForDNSkipsInactiveAndNestedDefinitions(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "partitioned.db")
	store, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: [][]byte{[]byte("{1}mdb")}},
				{Description: "olcSuffix", Values: [][]byte{[]byte("dc=example,dc=com")}},
			},
		},
		{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: [][]byte{[]byte("{2}mdb")}},
				{Description: "olcSuffix", Values: [][]byte{[]byte("ou=hidden,dc=example,dc=com")}},
				{Description: "olcHidden", Values: [][]byte{[]byte("TRUE")}},
			},
		},
		{
			DN: "olcDatabase={3}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: [][]byte{[]byte("{3}mdb")}},
				{Description: "olcSuffix", Values: [][]byte{[]byte("ou=disabled,dc=example,dc=com")}},
				{Description: "olcDisabled", Values: [][]byte{[]byte("yes")}},
			},
		},
		{
			DN: "olcDatabase={4}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: [][]byte{[]byte("{4}mdb")}},
				{Description: "olcSuffix", Values: [][]byte{[]byte("ou=people,dc=example,dc=com")}},
			},
		},
		{
			DN: "olcDatabase={9}mdb,cn=module,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: [][]byte{[]byte("{9}mdb")}},
				{Description: "olcSuffix", Values: [][]byte{[]byte("ou=nested,dc=example,dc=com")}},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed database definitions: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	for _, test := range []struct {
		dn   string
		want string
	}{
		{dn: "uid=alice,ou=people,dc=example,dc=com", want: "{4}mdb"},
		{dn: "uid=alice,ou=hidden,dc=example,dc=com", want: "{1}mdb"},
		{dn: "uid=alice,ou=disabled,dc=example,dc=com", want: "{1}mdb"},
		{dn: "uid=alice,ou=nested,dc=example,dc=com", want: "{1}mdb"},
	} {
		selector, err := databaseSelectorForDN(databasePath, test.dn)
		if err != nil {
			t.Fatalf("databaseSelectorForDN(%q): %v", test.dn, err)
		}
		if selector != test.want {
			t.Errorf("databaseSelectorForDN(%q) = %q, want %q", test.dn, selector, test.want)
		}
	}
}

func TestSlapaddConfigRuntimeValidationRollsBackAtomically(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "invalid-config.db")
	input := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcReadOnly: not-a-boolean

`
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{
			"slapadd",
			"-db", databasePath,
			"-n", "0",
			"-s",
			"-ldif", "-",
		},
		input,
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "olcReadOnly") {
		t.Fatalf("slapadd invalid config exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	store, err := storage.OpenBoltReadOnly(databasePath)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(): %v", err)
	}
	defer store.Close()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		count := 0
		if err := reader.ForEachPartition(func(string, directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("failed config import retained %d entries", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect rolled-back config import: %v", err)
	}
}

func TestOpenLDAPImportExportAliasesRoundTrip(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	sourceDatabase := filepath.Join(directoryPath, "source.db")
	targetDatabase := filepath.Join(directoryPath, "target.db")
	seedOpenLDAPAliasDatabase(t, sourceDatabase)
	seedOpenLDAPAliasDatabase(t, targetDatabase)

	dataPath := filepath.Join(directoryPath, "data.ldif")
	dataLDIF := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People

dn: uid=alice,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example

dn: ou=Systems,dc=example,dc=com
objectClass: organizationalUnit
ou: Systems

dn: uid=service,ou=Systems,dc=example,dc=com
objectClass: inetOrgPerson
uid: service
cn: Service Account
sn: Account

`
	if err := os.WriteFile(dataPath, []byte(dataLDIF), 0o600); err != nil {
		t.Fatalf("write data LDIF: %v", err)
	}
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slapadd", "-db", sourceDatabase, "-l", dataPath, "-n", "1"},
		"",
	)
	if exitCode != 0 || !strings.Contains(stdout, "imported 5 entries") || stderr != "" {
		t.Fatalf("slapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapcat", "-db", sourceDatabase, "-n", "1"},
		"",
	)
	if exitCode != 0 || !strings.Contains(stderr, "exported 5 entries") ||
		!strings.Contains(stdout, "dn: uid=service,ou=Systems,dc=example,dc=com") {
		t.Fatalf("slapcat -n exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	beforeDryRun, err := os.ReadFile(sourceDatabase)
	if err != nil {
		t.Fatalf("read source before dry run: %v", err)
	}
	dryRunPath := filepath.Join(directoryPath, "dry-run.ldif")
	if err := os.WriteFile(dryRunPath, []byte(`dn: uid=dry-run,dc=example,dc=com
objectClass: inetOrgPerson
uid: dry-run
cn: Dry Run
sn: Run

`), 0o600); err != nil {
		t.Fatalf("write dry-run LDIF: %v", err)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slapadd", "-db", sourceDatabase, "-l", dryRunPath,
			"-b", "dc=example,dc=com", "-u",
		},
		"",
	)
	if exitCode != 0 || !strings.Contains(stdout, "validated 1 entries") || stderr != "" {
		t.Fatalf("slapadd dry run exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	afterDryRun, err := os.ReadFile(sourceDatabase)
	if err != nil {
		t.Fatalf("read source after dry run: %v", err)
	}
	if !bytes.Equal(beforeDryRun, afterDryRun) {
		t.Fatal("slapadd -u modified the destination database")
	}

	subtreePath := filepath.Join(directoryPath, "people.ldif")
	beforeSlapcat := bytes.Clone(afterDryRun)
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slapcat", "-db", sourceDatabase,
			"-s", "ou=People,dc=example,dc=com", "-l", subtreePath,
		},
		"",
	)
	if exitCode != 0 || stdout != "" || !strings.Contains(stderr, "exported 2 entries") {
		t.Fatalf("slapcat exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	subtreeLDIF, err := os.ReadFile(subtreePath)
	if err != nil {
		t.Fatalf("read subtree LDIF: %v", err)
	}
	if !bytes.Contains(subtreeLDIF, []byte("dn: ou=People,dc=example,dc=com")) ||
		!bytes.Contains(subtreeLDIF, []byte("dn: uid=alice,ou=People,dc=example,dc=com")) ||
		bytes.Contains(subtreeLDIF, []byte("ou=Systems")) {
		t.Fatalf("slapcat subtree output = %q", subtreeLDIF)
	}
	if info, err := os.Stat(subtreePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("slapcat output mode = %v, error = %v", info, err)
	}
	afterSlapcat, err := os.ReadFile(sourceDatabase)
	if err != nil {
		t.Fatalf("read source after slapcat: %v", err)
	}
	if !bytes.Equal(beforeSlapcat, afterSlapcat) {
		t.Fatal("slapcat modified the source database")
	}

	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slapcat", "-db", sourceDatabase, "-n", "1",
			"-a", "(&(objectClass=inetOrgPerson)(uid=ALICE))",
		},
		"",
	)
	if exitCode != 0 || !strings.Contains(stderr, "exported 1 entries") ||
		!strings.Contains(stdout, "dn: uid=alice,ou=People,dc=example,dc=com") ||
		strings.Contains(stdout, "uid=service") {
		t.Fatalf("slapcat -a exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapadd", "-db", targetDatabase, "-n", "1"},
		`dn: dc=example,dc=com
objectClass: domain
dc: example

`,
	)
	if exitCode != 0 || !strings.Contains(stdout, "imported 1 entries") || stderr != "" {
		t.Fatalf("target suffix slapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slapadd", "-db", targetDatabase, "-l", subtreePath,
			"-b", "uid=alice,ou=People,dc=example,dc=com",
		},
		"",
	)
	if exitCode != 0 || !strings.Contains(stdout, "imported 2 entries") || stderr != "" {
		t.Fatalf("round-trip slapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slapcat", "-db", targetDatabase,
			"-b", "dc=example,dc=com",
			"-s", "ou=People,dc=example,dc=com",
		},
		"",
	)
	if exitCode != 0 || !strings.Contains(stderr, "exported 2 entries") {
		t.Fatalf("round-trip slapcat exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != strings.TrimSpace(string(subtreeLDIF)) {
		t.Fatalf("round-trip output:\n%s\nwant:\n%s", stdout, subtreeLDIF)
	}
	resumeInput := `this malformed record must be skipped

dn: uid=resumed,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
uid: resumed
cn: Resumed User
sn: User

`
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapadd", "-db", sourceDatabase, "-n", "1", "-j", "3"},
		resumeInput,
	)
	if exitCode != 0 || !strings.Contains(stdout, "imported 1 entries") || stderr != "" {
		t.Fatalf("slapadd -j exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestSlapaddSchemaValidationModes(t *testing.T) {
	t.Parallel()

	validStructureInvalidValue := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=invalid,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: invalid
cn: Invalid Integer
sn: Integer
uidNumber: not-an-integer
gidNumber: 1000
homeDirectory: /home/invalid

`
	invalidStructure := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=unknown,dc=example,dc=com
objectClass: inetOrgPerson
uid: unknown
cn: Unknown Attribute
sn: Attribute
notRegistered: value

`

	for _, test := range []struct {
		name       string
		command    string
		extraArgs  []string
		input      string
		wantExit   int
		wantStderr string
	}{
		{
			name:       "slapadd rejects structural schema violation",
			command:    "slapadd",
			input:      invalidStructure,
			wantExit:   1,
			wantStderr: "undefined attribute type",
		},
		{
			name:     "slapadd default skips value syntax validation",
			command:  "slapadd",
			input:    validStructureInvalidValue,
			wantExit: 0,
		},
		{
			name:       "slapadd value-check validates syntax",
			command:    "slapadd",
			extraArgs:  []string{"-o", "value-check=yes"},
			input:      validStructureInvalidValue,
			wantExit:   1,
			wantStderr: "value is not an integer",
		},
		{
			name:       "native import validates value syntax",
			command:    "import",
			input:      validStructureInvalidValue,
			wantExit:   1,
			wantStderr: "value is not an integer",
		},
		{
			name:      "slapadd schema disable accepts undefined attribute",
			command:   "slapadd",
			extraArgs: []string{"-s"},
			input:     invalidStructure,
			wantExit:  0,
		},
		{
			name:      "slapadd schema-check option accepts undefined attribute",
			command:   "slapadd",
			extraArgs: []string{"-o", "schema-check=no"},
			input:     invalidStructure,
			wantExit:  0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "directory.db")
			if test.command == "slapadd" {
				configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com

`
				stdout, stderr, exitCode := runCLIForTest(
					t,
					[]string{"import", "-db", databasePath, "-replace"},
					configLDIF,
				)
				if exitCode != 0 {
					t.Fatalf(
						"seed config exit=%d stdout=%q stderr=%q",
						exitCode,
						stdout,
						stderr,
					)
				}
			}
			args := append(
				[]string{test.command, "-db", databasePath, "-ldif", "-", "-replace"},
				test.extraArgs...,
			)
			stdout, stderr, exitCode := runCLIForTest(t, args, test.input)
			if exitCode != test.wantExit {
				t.Fatalf(
					"exit = %d, want %d; stdout=%q stderr=%q",
					exitCode,
					test.wantExit,
					stdout,
					stderr,
				)
			}
			if test.wantStderr != "" && !strings.Contains(stderr, test.wantStderr) {
				t.Fatalf("stderr = %q, want fragment %q", stderr, test.wantStderr)
			}
		})
	}
}

func TestSlapaddDryRunDoesNotCreateMissingDatabase(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	parent := filepath.Join(root, "missing")
	databasePath := filepath.Join(parent, "directory.db")
	ldifPath := filepath.Join(root, "entry.ldif")
	if err := os.WriteFile(ldifPath, []byte(`dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

`), 0o600); err != nil {
		t.Fatalf("write LDIF: %v", err)
	}
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-l", ldifPath, "-u", "-n", "0", "-s"},
		"",
	)
	if exitCode != 0 || !strings.Contains(stdout, "validated 2 entries") || stderr != "" {
		t.Fatalf("slapadd -u exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatalf("slapadd -u created the destination directory: %v", err)
	}
}

func TestSlapaddAndSlapcatSubordinateGlueFlag(t *testing.T) {
	t.Parallel()

	configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: ou=people,dc=example,dc=com
olcSubordinate: TRUE

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: dc=example,dc=com

`
	contentLDIF := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

`
	seed := func(t *testing.T, databasePath string) {
		t.Helper()
		stdout, stderr, exitCode := runCLIForTest(
			t,
			[]string{"import", "-db", databasePath, "-replace"},
			configLDIF,
		)
		if exitCode != 0 {
			t.Fatalf("seed config exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	}

	t.Run("default glue and slapcat disable", func(t *testing.T) {
		databasePath := filepath.Join(t.TempDir(), "directory.db")
		seed(t, databasePath)
		stdout, stderr, exitCode := runCLIForTest(
			t,
			[]string{"slapadd", "-db", databasePath},
			contentLDIF,
		)
		if exitCode != 0 {
			t.Fatalf("slapadd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
		stdout, stderr, exitCode = runCLIForTest(
			t,
			[]string{"slapcat", "-db", databasePath, "-n", "2"},
			"",
		)
		if exitCode != 0 || !strings.Contains(stdout, "dn: ou=people,dc=example,dc=com") {
			t.Fatalf("glued slapcat exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
		stdout, stderr, exitCode = runCLIForTest(
			t,
			[]string{"slapcat", "-db", databasePath, "-n", "2", "-g"},
			"",
		)
		if exitCode != 0 || strings.Contains(stdout, "dn: ou=people,dc=example,dc=com") {
			t.Fatalf("unglued slapcat exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})

	t.Run("slapadd disable stores in superior", func(t *testing.T) {
		databasePath := filepath.Join(t.TempDir(), "directory.db")
		seed(t, databasePath)
		stdout, stderr, exitCode := runCLIForTest(
			t,
			[]string{"slapadd", "-db", databasePath, "-n", "2", "-g"},
			contentLDIF,
		)
		if exitCode != 0 {
			t.Fatalf("slapadd -g exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
		stdout, stderr, exitCode = runCLIForTest(
			t,
			[]string{"slapcat", "-db", databasePath, "-n", "2", "-g"},
			"",
		)
		if exitCode != 0 || !strings.Contains(stdout, "dn: ou=people,dc=example,dc=com") {
			t.Fatalf("superior slapcat exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
		stdout, stderr, exitCode = runCLIForTest(
			t,
			[]string{"slapcat", "-db", databasePath, "-n", "2"},
			"",
		)
		if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "also present in superior database") {
			t.Fatalf("inconsistent glued slapcat exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})
}

func TestSlapcatAliasDoesNotCreateMissingDatabase(t *testing.T) {
	t.Parallel()

	parent := filepath.Join(t.TempDir(), "missing")
	databasePath := filepath.Join(parent, "directory.db")
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slapcat", "-db", databasePath},
		"",
	)
	if exitCode != 1 || stdout != "" || stderr == "" {
		t.Fatalf("slapcat exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatalf("slapcat created the missing database directory: %v", err)
	}
}

func TestSlappasswdCompatibilityOptions(t *testing.T) {
	t.Parallel()

	const secret = "compatibility-secret"
	tests := []struct {
		name      string
		args      []string
		password  []byte
		prefix    string
		noNewline bool
	}{
		{
			name:     "OpenLDAP default SSHA",
			args:     []string{"slappasswd", "-s", secret},
			password: []byte(secret),
			prefix:   "{SSHA}",
		},
		{
			name:      "national salted SM3 RFC2307 without newline",
			args:      []string{"slappasswd", "-u", "-n", "-h", "{SSM3}", "-s", secret},
			password:  []byte(secret),
			prefix:    "{SSM3}",
			noNewline: true,
		},
		{
			name:     "national PBKDF2",
			args:     []string{"slappasswd", "-h", "{PBKDF2-SM3}", "-iterations", "10", "-s", secret},
			password: []byte(secret),
			prefix:   "{PBKDF2-SM3}10$",
		},
		{
			name:     "OpenLDAP contrib salted SHA-256",
			args:     []string{"slappasswd", "-h", "{SSHA256}", "-s", secret},
			password: []byte(secret),
			prefix:   "{SSHA256}",
		},
		{
			name:     "OpenLDAP contrib SHA-384",
			args:     []string{"slappasswd", "-h", "{SHA384}", "-s", secret},
			password: []byte(secret),
			prefix:   "{SHA384}",
		},
		{
			name:     "OpenLDAP contrib salted SHA-512",
			args:     []string{"slappasswd", "-h", "{SSHA512}", "-s", secret},
			password: []byte(secret),
			prefix:   "{SSHA512}",
		},
		{
			name:     "OpenLDAP contrib PBKDF2 alias",
			args:     []string{"slappasswd", "-h", auth.OpenLDAPPBKDF2HashScheme, "-s", secret},
			password: []byte(secret),
			prefix:   auth.OpenLDAPPBKDF2HashScheme + "10000$",
		},
		{
			name:     "OpenLDAP contrib PBKDF2 SHA-1",
			args:     []string{"slappasswd", "-h", auth.OpenLDAPPBKDF2SHA1HashScheme, "-s", secret},
			password: []byte(secret),
			prefix:   auth.OpenLDAPPBKDF2SHA1HashScheme + "10000$",
		},
		{
			name:     "OpenLDAP contrib PBKDF2 SHA-256",
			args:     []string{"slappasswd", "-h", auth.OpenLDAPPBKDF2SHA256HashScheme, "-s", secret},
			password: []byte(secret),
			prefix:   auth.OpenLDAPPBKDF2SHA256HashScheme + "10000$",
		},
		{
			name:     "OpenLDAP contrib PBKDF2 SHA-512",
			args:     []string{"slappasswd", "-h", auth.OpenLDAPPBKDF2SHA512HashScheme, "-s", secret},
			password: []byte(secret),
			prefix:   auth.OpenLDAPPBKDF2SHA512HashScheme + "10000$",
		},
		{
			name:     "OpenLDAP contrib APR1",
			args:     []string{"slappasswd", "-h", auth.OpenLDAPAPR1HashScheme, "-s", secret},
			password: []byte(secret),
			prefix:   auth.OpenLDAPAPR1HashScheme,
		},
		{
			name:     "OpenLDAP contrib BSD MD5",
			args:     []string{"slappasswd", "-h", auth.OpenLDAPBSDMD5HashScheme, "-s", secret},
			password: []byte(secret),
			prefix:   auth.OpenLDAPBSDMD5HashScheme,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exitCode := runCLIForTest(t, test.args, "unused stdin")
			if exitCode != 0 || stderr != "" || strings.Contains(stderr, secret) {
				t.Fatalf("slappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			if test.noNewline == strings.HasSuffix(stdout, "\n") {
				t.Fatalf("slappasswd newline mismatch: %q", stdout)
			}
			stored := []byte(strings.TrimSuffix(stdout, "\n"))
			if !bytes.HasPrefix(stored, []byte(test.prefix)) ||
				!auth.VerifyPassword(stored, test.password) {
				t.Fatalf("slappasswd output = %q", stdout)
			}
		})
	}

	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slappasswd", "-h", auth.TOTP1HashScheme, "-s", secret},
		"unused stdin",
	)
	wantTOTP := auth.TOTP1HashScheme + base32.StdEncoding.EncodeToString([]byte(secret)) + "\n"
	if exitCode != 0 || stderr != "" || stdout != wantTOTP {
		t.Fatalf("slappasswd TOTP exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slappasswd",
			"-h",
			auth.TOTP256AndPWHashScheme,
			"-s",
			"seed|static-secret",
		},
		"unused stdin",
	)
	if exitCode != 0 || stderr != "" ||
		!strings.HasPrefix(stdout, auth.TOTP256AndPWHashScheme+"ONSWKZA=|{SSHA}") {
		t.Fatalf("slappasswd TOTP ANDPW exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	passwordFile := filepath.Join(t.TempDir(), "password.txt")
	filePassword := []byte("password-from-file\n")
	if err := os.WriteFile(passwordFile, filePassword, 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slappasswd", "-T", passwordFile, "-h", "{SM3}"},
		"unused stdin",
	)
	if exitCode != 0 || stderr != "" ||
		!auth.VerifyPassword([]byte(strings.TrimSuffix(stdout, "\n")), filePassword) {
		t.Fatalf("slappasswd -T exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runCLIForTest(t, []string{"slappasswd", "-g", "-n"}, "")
	if exitCode != 0 || stderr != "" || strings.HasSuffix(stdout, "\n") {
		t.Fatalf("slappasswd -g exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(stdout)
	if err != nil || len(decoded) != 6 {
		t.Fatalf("generated password = %q, decode error = %v", stdout, err)
	}
}

func TestSlappasswdCryptFormats(t *testing.T) {
	t.Parallel()

	const secret = "crypt-compatibility-secret"
	for _, test := range []struct {
		name   string
		args   []string
		prefix string
	}{
		{
			name:   "default CRYPT scheme",
			args:   []string{"slappasswd", "-h", auth.OpenLDAPCryptHashScheme, "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme,
		},
		{
			name:   "traditional DES",
			args:   []string{"slappasswd", "-c", "%.2s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme,
		},
		{
			name:   "MD5 crypt",
			args:   []string{"slappasswd", "-c", "$1$%.8s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$1$",
		},
		{
			name:   "bcrypt 2a",
			args:   []string{"slappasswd", "-c", "$2a$05$%.22s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$2a$05$",
		},
		{
			name:   "bcrypt 2b",
			args:   []string{"slappasswd", "-c", "$2b$05$%.22s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$2b$05$",
		},
		{
			name:   "bcrypt 2y",
			args:   []string{"slappasswd", "-c", "$2y$05$%.22s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$2y$05$",
		},
		{
			name:   "SHA256 crypt",
			args:   []string{"slappasswd", "-c", "$5$%.16s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$5$",
		},
		{
			name:   "SHA512 crypt with rounds",
			args:   []string{"slappasswd", "-c", "$6$rounds=1000$%.8s", "-n", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$6$rounds=1000$",
		},
		{
			name:   "SM3 crypt",
			args:   []string{"slappasswd", "-c", "$sm3$rounds=1000$%.16s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$sm3$rounds=1000$",
		},
		{
			name:   "SM3 yescrypt",
			args:   []string{"slappasswd", "-c", "$sm3y$j75$%.16s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$sm3y$j75$",
		},
		{
			name:   "GOST yescrypt",
			args:   []string{"slappasswd", "-c", "$gy$j75$%.16s", "-s", secret},
			prefix: auth.OpenLDAPCryptHashScheme + "$gy$j75$",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exitCode := runCLIForTest(t, test.args, "unused stdin")
			if exitCode != 0 || stderr != "" {
				t.Fatalf("slappasswd exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			stored := []byte(strings.TrimSuffix(stdout, "\n"))
			if !bytes.HasPrefix(stored, []byte(test.prefix)) ||
				!auth.VerifyPassword(stored, []byte(secret)) ||
				auth.VerifyPassword(stored, []byte("wrong")) {
				t.Fatalf("slappasswd output = %q", stdout)
			}
			if strings.Contains(stdout, secret) {
				t.Fatalf("slappasswd exposed the password: %q", stdout)
			}
		})
	}
}

func TestOpenLDAPAliasesRejectUnsupportedAndConflictingOptions(t *testing.T) {
	t.Parallel()

	const secret = "must-not-appear"
	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{name: "slapadd false continue", args: []string{"slapadd", "-c=false"}, message: "-c=false is not supported"},
		{name: "slapadd false quick", args: []string{"slapadd", "-q=false"}, message: "-q=false is not supported"},
		{name: "slapcat continue", args: []string{"slapcat", "-c"}, message: "option -c is not supported"},
		{name: "slapindex continue", args: []string{"slapindex", "-c"}, message: "option -c is not supported"},
		{name: "slapindex truncate", args: []string{"slapindex", "-t"}, message: "option -t is not supported"},
		{name: "slappasswd crypt unknown", args: []string{"slappasswd", "-c", "$9$%.16s", "-s", secret}, message: "unsupported crypt hash"},
		{name: "slappasswd crypt bcrypt cost", args: []string{"slappasswd", "-c", "$2b$17$%.22s", "-s", secret}, message: "exceeds 16"},
		{name: "slappasswd crypt SHA rounds", args: []string{"slappasswd", "-c", "$6$rounds=1000001$%.8s", "-s", secret}, message: "exceeds 1000000"},
		{name: "slappasswd crypt format", args: []string{"slappasswd", "-c", "%x", "-s", secret}, message: "only supports"},
		{name: "slappasswd crypt scheme conflict", args: []string{"slappasswd", "-c", "%.2s", "-h", "{SSHA}", "-s", secret}, message: "mutually exclusive"},
		{name: "slappasswd generated hash", args: []string{"slappasswd", "-g", "-h", "{SSHA}"}, message: "mutually exclusive"},
		{name: "slappasswd secret sources", args: []string{"slappasswd", "-s", secret, "-T", "password.txt"}, message: "mutually exclusive"},
		{name: "slappasswd verify-only Netscape scheme", args: []string{"slappasswd", "-h", auth.OpenLDAPNetscapeMTAHashScheme, "-s", secret}, message: "scheme provided no hash function"},
		{name: "slappasswd empty verify-only Netscape scheme", args: []string{"slappasswd", "-h", auth.OpenLDAPNetscapeMTAHashScheme, "-s", ""}, message: "scheme provided no hash function"},
		{name: "slappasswd verify-only RADIUS scheme", args: []string{"slappasswd", "-h", auth.OpenLDAPRADIUSHashScheme, "-s", secret}, message: "scheme provided no hash function"},
		{name: "slappasswd empty verify-only RADIUS scheme", args: []string{"slappasswd", "-h", auth.OpenLDAPRADIUSHashScheme, "-s", ""}, message: "scheme provided no hash function"},
		{name: "database selectors", args: []string{"slapadd", "-b", "dc=example,dc=com", "-n", "1"}, message: "mutually exclusive"},
		{name: "negative database", args: []string{"slapadd", "-n", "-1"}, message: "must be non-negative"},
		{name: "empty suffix", args: []string{"slapadd", "-b", ""}, message: "requires a non-empty suffix"},
		{name: "false dry run", args: []string{"slapadd", "-u=false"}, message: "-u=false is not supported"},
		{name: "negative resume line", args: []string{"slapadd", "-j", "-1"}, message: "-j must be non-negative"},
		{name: "empty subtree", args: []string{"slapcat", "-s", ""}, message: "requires a non-empty subtree"},
		{name: "empty filter", args: []string{"slapcat", "-a", ""}, message: "requires a non-empty LDAP filter"},
		{name: "invalid filter", args: []string{"slapcat", "-a", "(uid="}, message: "invalid export filter"},
		{name: "empty password file", args: []string{"slappasswd", "-T", ""}, message: "open password file"},
		{name: "false generation", args: []string{"slappasswd", "-g=false"}, message: "-g=false is not supported"},
		{name: "duplicate secret", args: []string{"slappasswd", "-s", secret, "-s", "replacement"}, message: "provided more than once"},
		{name: "LDIF outputs", args: []string{"slapcat", "-l", "one.ldif", "-ldif", "two.ldif"}, message: "mutually exclusive"},
		{name: "unknown config option", args: []string{"slapadd", "-f", "slapd.conf"}, message: "flag provided but not defined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exitCode := runCLIForTest(t, test.args, "")
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf("run(%v) exit=%d stdout=%q stderr=%q", test.args, exitCode, stdout, stderr)
			}
			if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) ||
				strings.Contains(stdout, "replacement") || strings.Contains(stderr, "replacement") {
				t.Fatalf("run(%v) exposed the password: stdout=%q stderr=%q", test.args, stdout, stderr)
			}
		})
	}
}

func TestSlapaddContinueRetainsSuccessfulRecords(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "continue.db")
	seedOpenLDAPAliasDatabase(t, databasePath)
	input := `dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=invalid,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: invalid
cn: Invalid
sn: Entry
undefinedAttribute: rejected

`
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "1", "-replace", "-c"},
		input,
	)
	if exitCode != 1 || !strings.Contains(stdout, "imported 3 entries") {
		t.Fatalf("slapadd -c exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, fragment := range []string{
		"slapadd: line 15:",
		`dn="uid=invalid,ou=people,dc=example,dc=com"`,
		"undefined attribute type",
		"completed with 1 record errors; 3 entries retained",
	} {
		if !strings.Contains(stderr, fragment) {
			t.Errorf("stderr %q does not contain %q", stderr, fragment)
		}
	}

	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapcat", "-db", databasePath, "-n", "1"},
		"",
	)
	if exitCode != 0 || !strings.Contains(stderr, "exported 3 entries") {
		t.Fatalf("slapcat after -c exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, dn := range []string{
		"dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
	} {
		if !strings.Contains(stdout, "dn: "+dn+"\n") {
			t.Errorf("slapcat output omitted %q:\n%s", dn, stdout)
		}
	}
	if strings.Contains(stdout, "dn: uid=invalid,") {
		t.Fatalf("slapadd -c retained invalid entry:\n%s", stdout)
	}
}

func TestSlapaddContinueDryRunUsesDisposableDatabase(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "continue-dry-run.db")
	seedOpenLDAPAliasDatabase(t, databasePath)
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read database before dry run: %v", err)
	}
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "1", "-c", "-u"},
		`dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=invalid,dc=example,dc=com
objectClass: inetOrgPerson
uid: invalid
cn: Invalid
sn: Entry
undefinedAttribute: rejected

`,
	)
	if exitCode != 1 || !strings.Contains(stdout, "validated 1 entries") ||
		!strings.Contains(stderr, "1 record errors") {
		t.Fatalf("slapadd -c -u exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	after, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read database after dry run: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("slapadd -c -u modified the destination database")
	}
}

func TestSlapaddQuickModeOnlySkipsValueChecks(t *testing.T) {
	t.Parallel()

	t.Run("schema remains enabled", func(t *testing.T) {
		databasePath := filepath.Join(t.TempDir(), "quick-schema.db")
		seedOpenLDAPAliasDatabase(t, databasePath)
		stdout, stderr, exitCode := runCLIForTest(
			t,
			[]string{"slapadd", "-db", databasePath, "-n", "1", "-replace", "-q"},
			`dn: dc=example,dc=com
objectClass: domain
dc: example
cn: rejected

`,
		)
		if exitCode != 1 || !strings.Contains(stderr, "not allowed") {
			t.Fatalf("slapadd -q exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})

	t.Run("value checks are disabled", func(t *testing.T) {
		databasePath := filepath.Join(t.TempDir(), "quick-value.db")
		seedOpenLDAPAliasDatabase(t, databasePath)
		stdout, stderr, exitCode := runCLIForTest(
			t,
			[]string{
				"slapadd", "-db", databasePath, "-n", "1", "-replace", "-q",
				"-o", "value-check=yes",
			},
			`dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=quick,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: quick
cn: Quick Value
sn: Value
uidNumber: not-an-integer
gidNumber: 1000
homeDirectory: /home/quick

`,
		)
		if exitCode != 0 || !strings.Contains(stdout, "imported 2 entries") ||
			!strings.Contains(stderr, "value-check incompatible with quick mode; disabled.") {
			t.Fatalf("slapadd -q exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})

	t.Run("schema disable is independent", func(t *testing.T) {
		databasePath := filepath.Join(t.TempDir(), "quick-no-schema.db")
		seedOpenLDAPAliasDatabase(t, databasePath)
		stdout, stderr, exitCode := runCLIForTest(
			t,
			[]string{
				"slapadd", "-db", databasePath, "-n", "1", "-replace", "-q", "-s",
			},
			`dn: dc=example,dc=com
objectClass: domain
dc: example
cn: retained

`,
		)
		if exitCode != 0 || !strings.Contains(stdout, "imported 1 entries") {
			t.Fatalf("slapadd -q -s exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})

	t.Run("objectClass remains required", func(t *testing.T) {
		databasePath := filepath.Join(t.TempDir(), "quick-object-class.db")
		seedOpenLDAPAliasDatabase(t, databasePath)
		stdout, stderr, exitCode := runCLIForTest(
			t,
			[]string{
				"slapadd", "-db", databasePath, "-n", "1", "-replace", "-q", "-s",
			},
			`dn: dc=example,dc=com
dc: example
quickAttribute: rejected

`,
		)
		if exitCode != 1 || !strings.Contains(stderr, "objectClass") {
			t.Fatalf("slapadd -q -s exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})
}

func TestSlapaddContinueRejectsConfigurationDatabase(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "config-continue.db")
	seedOpenLDAPAliasDatabase(t, databasePath)
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "0", "-replace", "-c"},
		`dn: cn=config
objectClass: olcGlobal
cn: config

`,
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(
		stderr,
		"does not support cn=config imports",
	) {
		t.Fatalf("config slapadd -c exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapcat", "-db", databasePath, "-n", "0"},
		"",
	)
	if exitCode != 0 || !strings.Contains(stdout, "olcDatabase: {1}mdb") {
		t.Fatalf("config changed after rejected -c exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOpenLDAPReferenceSlapaddContinueAndQuickExitBehavior(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP slapadd reference test")
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	slapadd := os.Getenv("OPENLDAP_SLAPADD")
	if slapadd == "" {
		t.Skip("OPENLDAP_SLAPADD is not configured")
	}
	schemaDir := os.Getenv("OPENLDAP_SCHEMA_DIR")
	if schemaDir == "" {
		t.Skip("OPENLDAP_SCHEMA_DIR is not configured")
	}

	root := t.TempDir()
	referenceDB := filepath.Join(root, "reference-db")
	if err := os.Mkdir(referenceDB, 0o700); err != nil {
		t.Fatalf("create reference database: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := "include " + filepath.Join(schemaDir, "core.schema") + "\n" +
		"include " + filepath.Join(schemaDir, "cosine.schema") + "\n\n" +
		"database mdb\nmaxsize 1073741824\n" +
		"suffix \"dc=example,dc=com\"\n" +
		"rootdn \"cn=admin,dc=example,dc=com\"\n" +
		"directory " + referenceDB + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write reference config: %v", err)
	}
	input := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=one,dc=example,dc=com
objectClass: organizationalUnit
ou: one

dn: ou=one,dc=example,dc=com
objectClass: organizationalUnit
ou: one

dn: ou=two,dc=example,dc=com
objectClass: organizationalUnit
ou: two

`
	inputPath := filepath.Join(root, "continue.ldif")
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatalf("write reference LDIF: %v", err)
	}
	reference := exec.Command(slapadd, "-f", configPath, "-c", "-l", inputPath)
	referenceOutput, referenceErr := reference.CombinedOutput()
	if referenceErr == nil || reference.ProcessState.ExitCode() != 1 {
		t.Fatalf("OpenLDAP slapadd -c error=%v output=%q", referenceErr, referenceOutput)
	}
	slapcat := filepath.Join(filepath.Dir(slapadd), "slapcat")
	referenceData, err := exec.Command(slapcat, "-f", configPath).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP slapcat: %v\n%s", err, referenceData)
	}
	for _, dn := range []string{
		"dc=example,dc=com",
		"ou=one,dc=example,dc=com",
		"ou=two,dc=example,dc=com",
	} {
		if !strings.Contains(string(referenceData), "dn: "+dn+"\n") {
			t.Fatalf("OpenLDAP -c omitted %q:\n%s", dn, referenceData)
		}
	}
	filter := "(|(dc=EXAMPLE)(ou=ONE))"
	referenceFiltered, err := exec.Command(
		slapcat,
		"-f", configPath,
		"-a", filter,
	).Output()
	if err != nil {
		t.Fatalf("OpenLDAP slapcat -a: %v", err)
	}
	localDatabase := filepath.Join(root, "ldap-go.db")
	seedOpenLDAPAliasDatabase(t, localDatabase)
	localImportOut, localImportErr, localImportCode := runCLIForTest(
		t,
		[]string{"slapadd", "-db", localDatabase, "-n", "1"},
		string(referenceData),
	)
	if localImportCode != 0 || !strings.Contains(localImportOut, "imported 3 entries") ||
		localImportErr != "" {
		t.Fatalf(
			"ldap-go reference import exit=%d stdout=%q stderr=%q",
			localImportCode,
			localImportOut,
			localImportErr,
		)
	}
	localFiltered, localFilterErr, localFilterCode := runCLIForTest(
		t,
		[]string{"slapcat", "-db", localDatabase, "-n", "1", "-a", filter},
		"",
	)
	if localFilterCode != 0 || !strings.Contains(localFilterErr, "exported 2 entries") {
		t.Fatalf(
			"ldap-go slapcat -a exit=%d stdout=%q stderr=%q",
			localFilterCode,
			localFiltered,
			localFilterErr,
		)
	}
	referenceEntries := parseLDAPSearchOutput(t, string(referenceFiltered))
	localEntries := parseLDAPSearchOutput(t, localFiltered)
	referenceDNs := make([]string, len(referenceEntries))
	localDNs := make([]string, len(localEntries))
	for index := range referenceEntries {
		referenceDNs[index] = referenceEntries[index].DN
	}
	for index := range localEntries {
		localDNs[index] = localEntries[index].DN
	}
	slices.Sort(referenceDNs)
	slices.Sort(localDNs)
	if !slices.Equal(localDNs, referenceDNs) {
		t.Fatalf("slapcat -a DNs = %q, want OpenLDAP %q", localDNs, referenceDNs)
	}

	quick := exec.Command(
		slapadd,
		"-f", configPath,
		"-q",
		"-o", "value-check=yes",
		"-u",
		"-l", inputPath,
	)
	quickOutput, quickErr := quick.CombinedOutput()
	if quickErr != nil || !strings.Contains(
		string(quickOutput),
		"value-check incompatible with quick mode; disabled.",
	) {
		t.Fatalf("OpenLDAP slapadd quick error=%v output=%q", quickErr, quickOutput)
	}
	invalidSchema := `dn: cn=quick,dc=example,dc=com
objectClass: organizationalUnit
ou: quick
cn: rejected

`
	invalidSchemaPath := filepath.Join(root, "quick-invalid-schema.ldif")
	if err := os.WriteFile(invalidSchemaPath, []byte(invalidSchema), 0o600); err != nil {
		t.Fatalf("write quick schema LDIF: %v", err)
	}
	referenceQuickSchema := exec.Command(
		slapadd,
		"-f", configPath,
		"-q",
		"-u",
		"-l", invalidSchemaPath,
	)
	referenceQuickSchemaOutput, referenceQuickSchemaErr :=
		referenceQuickSchema.CombinedOutput()
	if referenceQuickSchemaErr == nil || !strings.Contains(
		string(referenceQuickSchemaOutput),
		"not allowed",
	) {
		t.Fatalf(
			"OpenLDAP slapadd -q schema error=%v output=%q",
			referenceQuickSchemaErr,
			referenceQuickSchemaOutput,
		)
	}
	referenceQuickNoSchema := exec.Command(
		slapadd,
		"-f", configPath,
		"-q",
		"-s",
		"-u",
		"-l", invalidSchemaPath,
	)
	referenceQuickNoSchemaOutput, referenceQuickNoSchemaErr :=
		referenceQuickNoSchema.CombinedOutput()
	if referenceQuickNoSchemaErr != nil {
		t.Fatalf(
			"OpenLDAP slapadd -q -s error=%v output=%q",
			referenceQuickNoSchemaErr,
			referenceQuickNoSchemaOutput,
		)
	}

	databasePath := filepath.Join(root, "ldap-go.db")
	configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com

`
	_, _, exitCode := runCLIForTest(
		t,
		[]string{"import", "-db", databasePath, "-replace"},
		configLDIF,
	)
	if exitCode != 0 {
		t.Fatal("seed ldap-go differential database failed")
	}
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "1", "-c"},
		input,
	)
	if exitCode != 1 || !strings.Contains(stdout, "imported 3 entries") ||
		!strings.Contains(stderr, "1 record errors") {
		t.Fatalf("ldap-go slapadd -c exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "1", "-q", "-u"},
		invalidSchema,
	)
	if exitCode != 1 || !strings.Contains(stderr, "not allowed") {
		t.Fatalf("ldap-go slapadd -q exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "1", "-q", "-s", "-u"},
		invalidSchema,
	)
	if exitCode != 0 || !strings.Contains(stdout, "validated 1 entries") {
		t.Fatalf("ldap-go slapadd -q -s exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	resumeInput := `this malformed record must be skipped

dn: cn=resumed,dc=example,dc=com
objectClass: organizationalRole
cn: resumed

`
	resumePath := filepath.Join(root, "resume.ldif")
	if err := os.WriteFile(resumePath, []byte(resumeInput), 0o600); err != nil {
		t.Fatalf("write resume LDIF: %v", err)
	}
	if output, err := exec.Command(
		slapadd, "-f", configPath, "-j", "3", "-l", resumePath,
	).CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP slapadd -j: %v\n%s", err, output)
	}
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "1", "-j", "3"},
		resumeInput,
	)
	if exitCode != 0 || !strings.Contains(stdout, "imported 1 entries") || stderr != "" {
		t.Fatalf("ldap-go slapadd -j exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	referenceResumed, err := exec.Command(
		slapcat, "-f", configPath, "-a", "(cn=resumed)",
	).Output()
	if err != nil {
		t.Fatalf("OpenLDAP slapcat resumed entry: %v", err)
	}
	localResumed, localResumeErr, localResumeCode := runCLIForTest(
		t,
		[]string{"slapcat", "-db", databasePath, "-n", "1", "-a", "(cn=resumed)"},
		"",
	)
	if localResumeCode != 0 || !strings.Contains(localResumeErr, "exported 1 entries") ||
		!strings.Contains(localResumed, "dn: cn=resumed,dc=example,dc=com") ||
		!strings.Contains(string(referenceResumed), "dn: cn=resumed,dc=example,dc=com") {
		t.Fatalf(
			"slapadd -j final entries: local=%q/%q/%d reference=%q",
			localResumed, localResumeErr, localResumeCode, referenceResumed,
		)
	}
	slapacl := filepath.Join(filepath.Dir(slapadd), "slapacl")
	if _, err := os.Stat(slapacl); err != nil {
		t.Fatalf("OpenLDAP slapacl is unavailable: %v", err)
	}
	referenceACL, err := exec.Command(
		slapacl,
		"-f", configPath,
		"-D", "cn=observer,dc=example,dc=com",
		"-b", "cn=resumed,dc=example,dc=com",
		"cn/read", "cn",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP slapacl: %v\n%s", err, referenceACL)
	}
	localACLOut, localACLErr, localACLCode := runCLIForTest(
		t,
		[]string{
			"slapacl", "-db", databasePath,
			"-D", "cn=observer,dc=example,dc=com",
			"-b", "cn=resumed,dc=example,dc=com",
			"cn/read", "cn",
		},
		"",
	)
	for _, expected := range []string{
		"read access to cn: ALLOWED",
		"cn: read(=rscxd)",
	} {
		if localACLCode != 0 || localACLOut != "" ||
			!strings.Contains(localACLErr, expected) ||
			!strings.Contains(string(referenceACL), expected) {
			t.Fatalf(
				"slapacl differential missing %q: local=%q/%q/%d reference=%q",
				expected, localACLOut, localACLErr, localACLCode, referenceACL,
			)
		}
	}
}

func TestUsageListsOpenLDAPOfflineAliases(t *testing.T) {
	t.Parallel()

	stdout, stderr, exitCode := runCLIForTest(t, []string{"help"}, "")
	if exitCode != 0 || stderr != "" {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	for _, command := range []string{"slapacl", "slapadd", "slapcat", "slappasswd", "slapindex"} {
		if !strings.Contains(stdout, command) {
			t.Errorf("help does not list %s: %q", command, stdout)
		}
	}
}

func TestSlapACLChecksAccessAndRedactsPasswords(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "slapacl.db")
	config := `dn: cn=config
objectClass: olcGlobal
cn: config
olcAuthzRegexp: {0}^uid=([^,]+),cn=auth$ uid=$1,dc=example,dc=com

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=admin,dc=example,dc=com
olcAccess: {0}to attrs=cn by dn.exact="uid=alice,dc=example,dc=com" read by * none
olcAccess: {1}to attrs=userPassword by self auth by * none
olcAccess: {2}to * by users read by * none

`
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"import", "-db", databasePath, "-replace"},
		config,
	)
	if exitCode != 0 {
		t.Fatalf("seed slapacl config exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	data := `dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=alice,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example
userPassword: alice-secret

dn: uid=bob,dc=example,dc=com
objectClass: inetOrgPerson
uid: bob
cn: Bob Example
sn: Example
userPassword: bob-secret

`
	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{"slapadd", "-db", databasePath, "-n", "1"},
		data,
	)
	if exitCode != 0 {
		t.Fatalf("seed slapacl data exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slapacl", "-db", databasePath,
			"-U", "alice", "-b", "uid=bob,dc=example,dc=com",
			"2.5.4.3/read:Bob Example", "cn/write",
		},
		"",
	)
	if exitCode != 0 || stdout != "" ||
		!strings.Contains(stderr, `authcDN: "uid=alice,dc=example,dc=com"`) ||
		!strings.Contains(stderr, "read access to cn=Bob Example: ALLOWED") ||
		!strings.Contains(stderr, "write access to cn: DENIED") {
		t.Fatalf("slapacl checks exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runCLIForTest(
		t,
		[]string{
			"slapacl", "-db", databasePath,
			"-D", "uid=alice,dc=example,dc=com",
			"-b", "uid=alice,dc=example,dc=com",
		},
		"",
	)
	if exitCode != 0 || stdout != "" ||
		!strings.Contains(stderr, "userPassword=****:") ||
		strings.Contains(stderr, "alice-secret") {
		t.Fatalf("slapacl default output exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	after, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("slapacl modified the database")
	}
}

func seedOpenLDAPAliasDatabase(t *testing.T, databasePath string) {
	t.Helper()
	configLDIF := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
entryUUID: 11111111-1111-4111-8111-111111111111

`
	stdout, stderr, exitCode := runCLIForTest(
		t,
		[]string{"import", "-db", databasePath, "-replace"},
		configLDIF,
	)
	if exitCode != 0 {
		t.Fatalf("seed database exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func runCLIForTest(t *testing.T, args []string, stdin string) (string, string, int) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run(
		args,
		strings.NewReader(stdin),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	return stdout.String(), stderr.String(), exitCode
}

func TestLoadServerTLSConfigRequiresCertificatePair(t *testing.T) {
	t.Parallel()

	config, err := loadServerTLSConfig("", "")
	if err != nil || config != nil {
		t.Fatalf("loadServerTLSConfig(empty) = %#v, %v", config, err)
	}
	if _, err := loadServerTLSConfig("server.crt", ""); err == nil {
		t.Fatal("certificate without private key was accepted")
	}
	if _, err := loadServerTLSConfig("", "server.key"); err == nil {
		t.Fatal("private key without certificate was accepted")
	}
	if _, err := loadServerTLSConfigWithClientAuth(
		"server.crt",
		"server.key",
		"",
		true,
	); err == nil || !strings.Contains(err.Error(), "-tls-client-ca") {
		t.Fatalf("required TLS client certificate error = %v", err)
	}
}

func TestLoadServerTLCPRequiresDualCertificatePairs(t *testing.T) {
	t.Parallel()

	transport, err := loadServerTLCP("", "", "", "")
	if err != nil || transport != nil {
		t.Fatalf("loadServerTLCP(empty) = %#v, %v", transport, err)
	}
	if _, err := loadServerTLCP(
		"sign.crt",
		"sign.key",
		"",
		"",
	); err == nil {
		t.Fatal("TLCP configuration without encryption certificate was accepted")
	}
	if _, err := loadServerTLCPWithClientAuth(
		"sign.crt",
		"sign.key",
		"enc.crt",
		"enc.key",
		"",
		true,
	); err == nil || !strings.Contains(err.Error(), "-tlcp-client-ca") {
		t.Fatalf("required TLCP client certificate error = %v", err)
	}
}
