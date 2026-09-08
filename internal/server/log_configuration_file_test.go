package server

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPLogFileStartupOnlineRollbackAndDelete(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	root := t.TempDir()
	firstPath := filepath.Join(root, "first.log")
	secondPath := filepath.Join(root, "second.log")
	setStoredOpenLDAPLogging(t, store, map[string][]string{
		"olcLogLevel":      {"ANY"},
		"olcLogFile":       {firstPath},
		"olcLogFileFormat": {"debug"},
		"olcLogFileOnly":   {"FALSE"},
	})
	captured := &capturedMonitorLogState{}
	instance, address, stop := startMonitorLogRoutingServer(
		t, store, slog.New(capturedMonitorLogHandler{state: captured}),
	)
	defer stop()

	instance.config.Logger.Error("startup marker", "sequence", 1)
	assertFileContains(t, firstPath, "startup marker sequence=1")
	assertCapturedMessage(t, captured.snapshot(), "startup marker", true)

	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	captured.reset()
	replace := ldap.NewModifyRequest("cn=config", nil)
	replace.Replace("olcLogFile", []string{secondPath})
	replace.Replace("olcLogFileFormat", []string{"syslog-utc"})
	replace.Replace("olcLogFileOnly", []string{"TRUE"})
	replace.Replace("olcLogFileRotate", []string{"2 1 1"})
	if err := client.Modify(replace); err != nil {
		t.Fatalf("replace logfile configuration: %v", err)
	}
	instance.config.Logger.Error("online marker", "sequence", 2)
	second := readLogFile(t, secondPath)
	if !regexp.MustCompile(`(?m)^[A-Z][a-z]{2} [0-9]{2} [0-9:]{8} .* slapd\[[0-9]+\]: online marker sequence=2(?: .*)?$`).Match(second) {
		t.Fatalf("syslog-utc logfile = %q", second)
	}
	assertCapturedMessage(t, captured.snapshot(), "online marker", false)

	active := instance.runtime.Load()
	invalid := ldap.NewModifyRequest("cn=config", nil)
	rejectedPath := filepath.Join(root, "rejected.log")
	invalid.Replace("olcLogFile", []string{rejectedPath})
	invalid.Replace("olcLogFileFormat", []string{"debug"})
	invalid.Replace("olcLogFileOnly", []string{"FALSE"})
	invalid.Replace("olcLogLevel", []string{"0"})
	invalid.Replace("olcLogFileRotate", []string{"0 0 0"})
	if code := ldapOperationResultCode(client.Modify(invalid)); code != ldap.LDAPResultOther {
		t.Fatalf("invalid rotate result = %d, want %d", code, ldap.LDAPResultOther)
	}
	if instance.runtime.Load() != active {
		t.Fatal("invalid logfile configuration activated a runtime")
	}
	if values := readConfiguredAttribute(t, client, "olcLogFileRotate"); !slices.Equal(values, []string{"2 1 1"}) {
		t.Fatalf("persisted rotate after rollback = %q", values)
	}
	for attribute, expected := range map[string]string{
		"olcLogFile": secondPath, "olcLogFileFormat": "syslog-utc", "olcLogFileOnly": "TRUE", "olcLogLevel": "ANY",
	} {
		if got := readConfiguredAttribute(t, client, attribute); !slices.Equal(got, []string{expected}) {
			t.Fatalf("rollback changed %s to %v", attribute, got)
		}
	}
	if _, err := os.Stat(rejectedPath); !os.IsNotExist(err) {
		t.Fatalf("invalid configuration opened candidate logfile: %v", err)
	}
	instance.config.Logger.Error("rollback marker")
	assertFileContains(t, secondPath, "rollback marker")

	missing := ldap.NewModifyRequest("cn=config", nil)
	missing.Replace("olcLogFile", []string{filepath.Join(root, "missing", "slapd.log")})
	if code := ldapOperationResultCode(client.Modify(missing)); code != ldap.LDAPResultOther {
		t.Fatalf("invalid path result = %d, want %d", code, ldap.LDAPResultOther)
	}
	if instance.runtime.Load() != active {
		t.Fatal("unopenable logfile configuration activated a runtime")
	}

	remove := ldap.NewModifyRequest("cn=config", nil)
	for _, attribute := range []string{
		"olcLogFile", "olcLogFileFormat", "olcLogFileOnly", "olcLogFileRotate",
	} {
		remove.Delete(attribute, nil)
	}
	if err := client.Modify(remove); err != nil {
		t.Fatalf("delete logfile configuration: %v", err)
	}
	captured.reset()
	instance.config.Logger.Error("deleted marker")
	assertCapturedMessage(t, captured.snapshot(), "deleted marker", true)
	if got := readLogFile(t, secondPath); strings.Contains(string(got), "deleted marker") {
		t.Fatalf("deleted logfile received a record: %q", got)
	}
}

func TestOpenLDAPLogFileFormats(t *testing.T) {
	now := time.Date(2026, time.September, 3, 12, 34, 56, 123456789, time.FixedZone("test", 8*60*60))
	tests := []struct {
		name   string
		format openLDAPLogFileFormat
		match  string
	}{
		{"debug", openLDAPLogFileFormatDebug, `^6[0-9a-f]+\.075bcd15 0x0 event value="hello world"\n$`},
		{"syslog-utc", openLDAPLogFileFormatSyslogUTC, `^Sep 03 04:34:56 .* slapd\[[0-9]+\]: event value="hello world"\n$`},
		{"syslog-localtime", openLDAPLogFileFormatSyslogLocaltime, `^[A-Z][a-z]{2} [0-9]{2} [0-9:]{8} .* slapd\[[0-9]+\]: event value="hello world"\n$`},
		{"rfc3339-utc", openLDAPLogFileFormatRFC3339UTC, `^2026-09-03T04:34:56\.123456789Z .* slapd\[[0-9]+\]: event value="hello world"\n$`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "slapd.log")
			file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{
				path: path, format: test.format,
			}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			defer file.close()
			if err := file.write(
				slog.NewRecord(now, slog.LevelInfo, "event", 0),
				appendOpenLDAPLogAttributes(nil, nil, []slog.Attr{slog.String("value", "hello world")}),
				nil,
			); err != nil {
				t.Fatal(err)
			}
			if got := string(readLogFile(t, path)); !regexp.MustCompile(test.match).MatchString(got) {
				t.Fatalf("formatted record = %q, want %s", got, test.match)
			}
		})
	}
}

func TestOpenLDAPLogFileRotationSizeAgeAndRetention(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "slapd.log")
		now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
		file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{
			path:     path,
			rotation: openLDAPLogFileRotation{maximum: 2, bytes: 1 << 20},
		}, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		defer file.close()
		payload := strings.Repeat("x", 600<<10)
		for index := 1; index <= 4; index++ {
			record := slog.NewRecord(now, slog.LevelInfo, fmt.Sprintf("record-%d", index), 0)
			record.AddAttrs(slog.String("payload", payload))
			if err := file.write(record, nil, nil); err != nil {
				t.Fatal(err)
			}
		}
		assertFileContains(t, path, "record-4")
		assertFileContains(t, path+".01", "record-3")
		assertFileContains(t, path+".02", "record-2")
		if _, err := os.Stat(path + ".03"); !os.IsNotExist(err) {
			t.Fatalf("unexpected third retained logfile: %v", err)
		}
	})

	t.Run("age", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "slapd.log")
		var nanoseconds atomic.Int64
		start := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
		nanoseconds.Store(start.UnixNano())
		file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{
			path:     path,
			rotation: openLDAPLogFileRotation{maximum: 1, age: time.Hour},
		}, func() time.Time { return time.Unix(0, nanoseconds.Load()).UTC() })
		if err != nil {
			t.Fatal(err)
		}
		defer file.close()
		if err := file.write(slog.NewRecord(start, slog.LevelInfo, "before", 0), nil, nil); err != nil {
			t.Fatal(err)
		}
		nanoseconds.Store(start.Add(time.Hour).UnixNano())
		if err := file.write(slog.NewRecord(start.Add(time.Hour), slog.LevelInfo, "after", 0), nil, nil); err != nil {
			t.Fatal(err)
		}
		assertFileContains(t, path+".01", "before")
		assertFileContains(t, path, "after")
	})
}

func TestOpenLDAPLogFileConcurrentWritesAndSoftFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slapd.log")
	monitor := newMonitorState()
	monitor.setLogging([]string{"ANY"}, []string{"ANY"})
	if err := monitor.configureLogFile(openLDAPLogFileConfiguration{
		path: path, only: true,
	}, time.Now); err != nil {
		t.Fatal(err)
	}
	captured := &capturedMonitorLogState{}
	logger := slog.New(&monitorLogHandler{
		next:    slog.New(capturedMonitorLogHandler{state: captured}).Handler(),
		monitor: monitor,
	})

	const workers, records = 16, 100
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for record := 0; record < records; record++ {
				logger.Error("concurrent", "worker", worker, "record", record)
			}
		}(worker)
	}
	wait.Wait()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if !strings.Contains(scanner.Text(), "concurrent") {
			t.Fatalf("partial/interleaved logfile line = %q", scanner.Text())
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines != workers*records {
		t.Fatalf("logfile lines = %d, want %d", lines, workers*records)
	}
	if got := captured.snapshot(); len(got) != 0 {
		t.Fatalf("file-only records reached process logger: %#v", got)
	}

	if err := monitor.configuredLogFile().close(); err != nil {
		t.Fatal(err)
	}
	logger.Error("soft failure marker")
	assertCapturedMessage(t, captured.snapshot(), "soft failure marker", true)
}

func TestLoadOpenLDAPLogFileConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		attributes map[string][]string
		want       openLDAPLogFileConfiguration
		invalid    bool
	}{
		{name: "defaults", want: openLDAPLogFileConfiguration{}},
		{
			name: "complete",
			attributes: map[string][]string{
				"olcLogFile": {"/tmp/slapd.log"}, "olcLogFileFormat": {"SYSLOG-LOCALTIME"},
				"olcLogFileOnly": {"TRUE"}, "olcLogFileRotate": {"7 8 9"},
			},
			want: openLDAPLogFileConfiguration{
				path: "/tmp/slapd.log", format: openLDAPLogFileFormatSyslogLocaltime, only: true,
				rotation: openLDAPLogFileRotation{maximum: 7, bytes: 8 << 20, age: 9 * time.Hour},
			},
		},
		{name: "invalid format", attributes: map[string][]string{"olcLogFileFormat": {"json"}}, invalid: true},
		{name: "invalid boolean", attributes: map[string][]string{"olcLogFileOnly": {"yes"}}, invalid: true},
		{name: "missing rotation field", attributes: map[string][]string{"olcLogFileRotate": {"2 1"}}, invalid: true},
		{name: "invalid max", attributes: map[string][]string{"olcLogFileRotate": {"100 1 0"}}, invalid: true},
		{name: "disabled limits", attributes: map[string][]string{"olcLogFileRotate": {"2 0 0"}}, invalid: true},
		{name: "negative limit", attributes: map[string][]string{"olcLogFileRotate": {"2 -1 0"}}, invalid: true},
		{name: "Go binary", attributes: map[string][]string{"olcLogFileRotate": {"0b10 1 0"}}, invalid: true},
		{name: "Go separators", attributes: map[string][]string{"olcLogFileRotate": {"2 1_0 0"}}, invalid: true},
		{name: "Go octal", attributes: map[string][]string{"olcLogFileRotate": {"0o2 1 0"}}, invalid: true},
		{name: "overflow hours", attributes: map[string][]string{"olcLogFileRotate": {"2 1 4294967295"}}, invalid: true},
		{name: "multiple paths", attributes: map[string][]string{"olcLogFile": {"a", "b"}}, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			defer store.Close()
			seedOnlineConfiguration(t, store)
			setStoredOpenLDAPLogging(t, store, test.attributes)
			var got openLDAPLogFileConfiguration
			err := store.View(context.Background(), func(reader storage.Reader) error {
				var err error
				got, err = loadOpenLDAPLogFileConfiguration(reader)
				return err
			})
			if test.invalid {
				if err == nil {
					t.Fatal("invalid logfile configuration was accepted")
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("load configuration = %#v, %v, want %#v", got, err, test.want)
			}
		})
	}
}

func TestOpenLDAPLogFilePathAndCreationMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slapd.log")
	file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{path: path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer file.close()
	information, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if information.Mode().Perm()&0o027 != 0 {
		t.Fatalf("logfile mode = %#o, grants group-write or world access", information.Mode().Perm())
	}
	missing := filepath.Join(t.TempDir(), "missing", "slapd.log")
	if file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{path: missing}, nil); err == nil {
		_ = file.close()
		t.Fatal("logfile in a missing directory was accepted")
	}
}

func TestOpenLDAPReferenceGlobalLogFileConfiguration(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI := startOpenLDAPDynamicConfigReferralServer(t, tools)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	implementationAddress, stop := startServer(t, store, Config{})
	defer stop()

	reference := observeOpenLDAPLogFileConfiguration(
		t,
		referenceURI,
		filepath.Join(t.TempDir(), "openldap.log"),
	)
	implementation := observeOpenLDAPLogFileConfiguration(
		t,
		"ldap://"+implementationAddress,
		filepath.Join(t.TempDir(), "ldap-go.log"),
	)
	if !reflect.DeepEqual(implementation, reference) {
		t.Fatalf(
			"global logfile configuration:\nldap-go:  %#v\nOpenLDAP: %#v",
			implementation,
			reference,
		)
	}
}

type openLDAPLogFileConfigurationOutcome struct {
	FileCode                 uint16
	DebugFormatCode          uint16
	SyslogUTCFormatCode      uint16
	SyslogLocaltimeCode      uint16
	OnlyTrueCode             uint16
	OnlyFalseCode            uint16
	RotateCode               uint16
	ValuesAfterValid         [3][]string
	InvalidFormatCode        uint16
	FormatAfterInvalid       []string
	InvalidOnlyCode          uint16
	OnlyAfterInvalid         []string
	InvalidRotateMaxCode     uint16
	InvalidRotateLimitsCode  uint16
	RotateAfterInvalid       []string
	InvalidPathCode          uint16
	FileConfiguredAfterError bool
	DeleteRotateCode         uint16
	DeleteOnlyCode           uint16
	DeleteFormatCode         uint16
	DeleteFileCode           uint16
	ValuesAfterDelete        [4][]string
}

func observeOpenLDAPLogFileConfiguration(
	t *testing.T,
	uri,
	path string,
) openLDAPLogFileConfigurationOutcome {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetTimeout(5 * time.Second)
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	modify := func(attribute string, values ...string) uint16 {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace(attribute, values)
		return ldapOperationResultCode(client.Modify(request))
	}
	remove := func(attribute string) uint16 {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Delete(attribute, nil)
		return ldapOperationResultCode(client.Modify(request))
	}
	outcome := openLDAPLogFileConfigurationOutcome{}
	outcome.FileCode = modify("olcLogFile", path)
	outcome.DebugFormatCode = modify("olcLogFileFormat", "debug")
	outcome.SyslogUTCFormatCode = modify("olcLogFileFormat", "syslog-utc")
	outcome.SyslogLocaltimeCode = modify("olcLogFileFormat", "syslog-localtime")
	outcome.OnlyTrueCode = modify("olcLogFileOnly", "TRUE")
	outcome.OnlyFalseCode = modify("olcLogFileOnly", "FALSE")
	outcome.RotateCode = modify("olcLogFileRotate", "2 1 1")
	outcome.ValuesAfterValid = [3][]string{
		readConfiguredAttribute(t, client, "olcLogFileFormat"),
		readConfiguredAttribute(t, client, "olcLogFileOnly"),
		readConfiguredAttribute(t, client, "olcLogFileRotate"),
	}
	outcome.InvalidFormatCode = modify("olcLogFileFormat", "json")
	outcome.FormatAfterInvalid = readConfiguredAttribute(t, client, "olcLogFileFormat")
	outcome.InvalidOnlyCode = modify("olcLogFileOnly", "yes")
	outcome.OnlyAfterInvalid = readConfiguredAttribute(t, client, "olcLogFileOnly")
	outcome.InvalidRotateMaxCode = modify("olcLogFileRotate", "0 1 0")
	outcome.InvalidRotateLimitsCode = modify("olcLogFileRotate", "2 0 0")
	outcome.RotateAfterInvalid = readConfiguredAttribute(t, client, "olcLogFileRotate")
	outcome.InvalidPathCode = modify(
		"olcLogFile",
		filepath.Join(filepath.Dir(path), "missing", "slapd.log"),
	)
	outcome.FileConfiguredAfterError = len(readConfiguredAttribute(t, client, "olcLogFile")) == 1
	outcome.DeleteRotateCode = remove("olcLogFileRotate")
	outcome.DeleteOnlyCode = remove("olcLogFileOnly")
	outcome.DeleteFormatCode = remove("olcLogFileFormat")
	outcome.DeleteFileCode = remove("olcLogFile")
	outcome.ValuesAfterDelete = [4][]string{
		readConfiguredAttribute(t, client, "olcLogFile"),
		readConfiguredAttribute(t, client, "olcLogFileFormat"),
		readConfiguredAttribute(t, client, "olcLogFileOnly"),
		readConfiguredAttribute(t, client, "olcLogFileRotate"),
	}
	return outcome
}

func TestOpenLDAPReferenceLogFileRotationNames(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri := startOpenLDAPDynamicConfigReferralServer(t, tools)
	path := filepath.Join(t.TempDir(), "slapd.log")
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetTimeout(5 * time.Second)
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	for attribute, value := range map[string]string{
		"olcLogFile":       path,
		"olcLogFileOnly":   "TRUE",
		"olcLogFileFormat": "debug",
		"olcLogFileRotate": "2 1 0",
		"olcLogLevel":      "STATS",
	} {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace(attribute, []string{value})
		if err := client.Modify(request); err != nil {
			t.Fatalf("configure %s: %v", attribute, err)
		}
	}

	search := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil,
	)
	for attempt := 0; attempt < 10_000; attempt++ {
		if _, err := client.Search(search); err != nil {
			t.Fatalf("generate OpenLDAP log traffic: %v", err)
		}
		if attempt%100 == 0 {
			if _, err := os.Stat(path + ".01"); err == nil {
				break
			}
		}
	}
	if _, err := os.Stat(path + ".01"); err != nil {
		t.Fatalf("OpenLDAP did not create .01 during rotation: %v", err)
	}
	if _, err := os.Stat(path + ".03"); !os.IsNotExist(err) {
		t.Fatalf("OpenLDAP retained a logfile beyond max=2: %v", err)
	}
}

func setStoredOpenLDAPLogging(
	t *testing.T,
	store storage.Store,
	attributes map[string][]string,
) {
	t.Helper()
	if len(attributes) == 0 {
		return
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		for attribute, values := range attributes {
			entry.ReplaceValues(attribute, stringValues(values...))
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
}

func readConfiguredAttribute(t *testing.T, client *ldap.Conn, attribute string) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{attribute}, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read %s = %#v, %v", attribute, result, err)
	}
	return result.Entries[0].GetAttributeValues(attribute)
}

func readLogFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read logfile %s: %v", path, err)
	}
	return value
}

func assertFileContains(t *testing.T, path, marker string) {
	t.Helper()
	if got := string(readLogFile(t, path)); !strings.Contains(got, marker) {
		t.Fatalf("logfile %s = %q, want marker %q", path, got, marker)
	}
}

func assertCapturedMessage(
	t *testing.T,
	records []capturedMonitorLogRecord,
	message string,
	want bool,
) {
	t.Helper()
	for _, record := range records {
		if record.message == message {
			if !want {
				t.Fatalf("unexpected process log %q in %#v", message, records)
			}
			return
		}
	}
	if want {
		t.Fatalf("process log %q not found in %#v", message, records)
	}
}
