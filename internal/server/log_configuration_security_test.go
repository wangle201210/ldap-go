package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenLDAPLogFileRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"symlink", "dangling-symlink", "hardlink", "directory", "nul"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			target, path := filepath.Join(root, "target"), filepath.Join(root, "slapd.log")
			if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, path)
			case "dangling-symlink":
				err = os.Symlink(filepath.Join(root, "absent"), path)
			case "hardlink":
				err = os.Link(target, path)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "nul":
				path += "\x00"
			}
			if err != nil {
				t.Fatal(err)
			}
			file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{path: path}, nil)
			if err == nil {
				_ = file.close()
				t.Fatal("unsafe logfile accepted")
			}
			if string(readLogFile(t, target)) != "untouched" {
				t.Fatal("opening logfile changed link target")
			}
		})
	}
}

func TestOpenLDAPLogFileRotationFailureKeepsWriting(t *testing.T) {
	for _, kind := range []string{"archive-directory", "archive-symlink", "replaced-active", "unrelated-tmp"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "slapd.log")
			configuration := openLDAPLogFileConfiguration{path: path, only: true,
				rotation: openLDAPLogFileRotation{maximum: 2, bytes: 1}}
			file, err := openConfiguredLDAPLogFile(configuration, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer file.close()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			activePath := path
			switch kind {
			case "archive-directory":
				err = os.Mkdir(path+".01", 0o700)
			case "archive-symlink":
				err = os.Symlink(target, path+".01")
			case "replaced-active":
				activePath = path + ".moved"
				if err = os.Rename(path, activePath); err == nil {
					err = os.Symlink(target, path)
				}
			case "unrelated-tmp":
				err = os.WriteFile(path+".tmp", []byte("untouched"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = file.write(slog.NewRecord(time.Now(), slog.LevelError, "survives rotation", 0), nil, nil)
			if kind == "unrelated-tmp" {
				if err != nil {
					t.Fatal(err)
				}
				if string(readLogFile(t, path+".tmp")) != "untouched" {
					t.Fatal("rotation overwrote unrelated .tmp")
				}
			} else if err == nil {
				t.Fatal("unsafe rotation succeeded")
			}
			assertFileContains(t, activePath, "survives rotation")
			if string(readLogFile(t, target)) != "untouched" {
				t.Fatal("rotation wrote to unrelated target")
			}
		})
	}
}

func TestOpenLDAPLogFileStructuredAttributesAndEscaping(t *testing.T) {
	monitor := newMonitorState()
	defer monitor.closeLogFile()
	path := filepath.Join(t.TempDir(), "slapd.log")
	if err := monitor.configureLogFile(openLDAPLogFileConfiguration{path: path, only: true}, nil); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(&monitorLogHandler{monitor: monitor, next: capturedMonitorLogHandler{state: &capturedMonitorLogState{}}})
	logger.With("root", "r").WithGroup("outer").With("bound", "b").WithGroup("inner").WithGroup("").Error(
		"line\nbreak", "value", "x\ny", slog.Group("", "inline", "v"), slog.Group("nested", "key", "value"), "bad\nkey", "safe",
	)
	got := string(readLogFile(t, path))
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("record injected extra lines: %q", got)
	}
	for _, value := range []string{`"line\nbreak"`, `root=r`, `outer.bound=b`, `outer.inner.value="x\ny"`,
		`outer.inner.inline=v`, `outer.inner.nested.key=value`, `"outer.inner.bad\nkey"=safe`} {
		if !strings.Contains(got, value) {
			t.Errorf("missing %s in %q", value, got)
		}
	}
	if strings.Contains(got, "inner.root") || strings.Contains(got, "inner.bound") {
		t.Fatalf("later groups affected previously bound attributes: %q", got)
	}
}

type reentrantLogFileValue struct {
	logger *slog.Logger
}

func (value reentrantLogFileValue) LogValue() slog.Value {
	value.logger.Error("nested LogValuer record")
	return slog.StringValue("resolved")
}

func TestOpenLDAPLogFileLogValuerCanLog(t *testing.T) {
	monitor := newMonitorState()
	path := filepath.Join(t.TempDir(), "slapd.log")
	if err := monitor.configureLogFile(openLDAPLogFileConfiguration{path: path, only: true}, nil); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(&monitorLogHandler{monitor: monitor, next: capturedMonitorLogHandler{state: &capturedMonitorLogState{}}})
	done := make(chan struct{})
	go func() {
		logger.Error("outer record", "value", reentrantLogFileValue{logger: logger})
		close(done)
	}()
	select {
	case <-done:
		monitor.closeLogFile()
	case <-time.After(2 * time.Second):
		t.Fatal("LogValuer deadlocked the logfile")
	}
	assertFileContains(t, path, "nested LogValuer record")
	assertFileContains(t, path, "outer record value=resolved")
}

func TestOpenLDAPLogFileAppendAndExactRotationBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slapd.log")
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{path: path}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer file.close()
	record := slog.NewRecord(now, slog.LevelError, "exact-boundary", 0)
	length := int64(len(file.formatPrefix(now)) + len(formatOpenLDAPLogMessage(record, nil, nil)))
	file.configuration.rotation = openLDAPLogFileRotation{maximum: 1, bytes: file.size + length}
	if err := file.write(record, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".01"); !os.IsNotExist(err) {
		t.Fatalf("rotated at exact size limit: %v", err)
	}
	if !strings.HasPrefix(string(readLogFile(t, path)), "existing\n") {
		t.Fatal("opening existing file truncated its contents")
	}
	if err := file.write(record, nil, nil); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, path+".01", "existing")
	information, err := os.Stat(path + ".01")
	if err != nil || information.Mode().Perm() != 0o600 {
		t.Fatalf("existing logfile permissions changed: %v, %v", information, err)
	}
}
