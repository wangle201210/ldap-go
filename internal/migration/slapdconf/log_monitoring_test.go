package slapdconf

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogfileAndMonitoringDirectives(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "slapd.log")
	path := configFile(t, fmt.Sprintf(`logfile %q
logfile-format syslog-utc
logfile-only on
logfile-rotate 3 1 24
database mdb
suffix dc=example
directory /unused
monitoring off
`, logPath))
	document, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for attribute, want := range map[string]string{
		"olcLogFile":       logPath,
		"olcLogFileFormat": "syslog-utc",
		"olcLogFileOnly":   "TRUE",
		"olcLogFileRotate": "3 1 24",
	} {
		if got := values(t, document, "cn=config", attribute); len(got) != 1 || got[0] != want {
			t.Fatalf("%s = %q, want %q", attribute, got, want)
		}
	}
	if got := values(t, document, "olcDatabase={1}mdb,cn=config", "olcMonitoring"); len(got) != 1 || got[0] != "FALSE" {
		t.Fatalf("olcMonitoring = %q", got)
	}
}

func TestLogfileAndMonitoringValidationLocations(t *testing.T) {
	for _, test := range []struct {
		name      string
		directive string
		fragment  string
	}{
		{"format", "logfile-format unknown", "olcLogFileFormat"},
		{"only", "logfile-only maybe", "logfile-only"},
		{"rotate arity", "logfile-rotate 3 1", "requires 3"},
		{"rotate values", "logfile-rotate 0 0 0", "olcLogFileRotate"},
		{"monitoring value", "monitoring maybe", "monitoring"},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := "logfile /tmp/slapdconf-test.log\n"
			if strings.HasPrefix(test.directive, "monitoring") {
				prefix = "database mdb\nsuffix dc=example\ndirectory /unused\n"
			}
			path := configFile(t, prefix+test.directive+"\n")
			_, err := ConvertFile(path, ParseOptions{})
			var located *ParseError
			if err == nil || !errors.As(err, &located) || located.Position.Path != path ||
				!strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.fragment)) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestMonitoringRequiresDatabase(t *testing.T) {
	path := configFile(t, "monitoring on\n")
	if _, err := ConvertFile(path, ParseOptions{}); err == nil || !strings.Contains(err.Error(), path+":1:") {
		t.Fatalf("error = %v", err)
	}
}
