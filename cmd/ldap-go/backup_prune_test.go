//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const backupPruneTestPrefix = "ldap-go-"

type backupPruneFixture struct {
	directory      string
	activeDatabase string
}

func TestBackupPruneRetentionDryRunAndDeterministicReports(t *testing.T) {
	t.Parallel()

	fixture := newBackupPruneFixture(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	newest := writeBackupPruneFile(t, fixture.directory, now.Add(-time.Hour), "0000000000000003", "new")
	fresh := writeBackupPruneFile(t, fixture.directory, now.Add(-24*time.Hour), "0000000000000002", "fresh")
	oldest := writeBackupPruneFile(t, fixture.directory, now.Add(-72*time.Hour), "0000000000000001", "old")
	if err := os.WriteFile(filepath.Join(fixture.directory, "notes.txt"), []byte("not managed"), 0o600); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	report, err := executeBackupPrune(context.Background(), backupPruneOptions{
		directory:      fixture.directory,
		prefix:         backupPruneTestPrefix,
		activeDatabase: fixture.activeDatabase,
		keepLast:       1,
		maxAge:         48 * time.Hour,
		format:         "text",
		now:            now,
	})
	if err != nil {
		t.Fatalf("executeBackupPrune(): %v", err)
	}
	if report.Mode != "dry-run" || report.Matched != 3 || report.Retained != 2 ||
		report.Planned != 1 || report.Deleted != 0 || report.Ignored != 1 {
		t.Fatalf("report = %#v", report)
	}
	wantFiles := []backupPruneFileReport{
		{Name: newest, CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), Size: 3, Action: "retain", Reason: "keep-last"},
		{Name: fresh, CreatedAt: now.Add(-24 * time.Hour).Format(time.RFC3339Nano), Size: 5, Action: "retain", Reason: "max-age"},
		{Name: oldest, CreatedAt: now.Add(-72 * time.Hour).Format(time.RFC3339Nano), Size: 3, Action: "would-delete", Reason: "expired"},
	}
	if !reflect.DeepEqual(report.Files, wantFiles) {
		t.Fatalf("files = %#v, want %#v", report.Files, wantFiles)
	}
	if _, err := os.Lstat(filepath.Join(fixture.directory, oldest)); err != nil {
		t.Fatalf("dry-run removed old backup: %v", err)
	}

	var textOne, textTwo bytes.Buffer
	if err := writeBackupPruneReport(&textOne, report, "text"); err != nil {
		t.Fatalf("write text report: %v", err)
	}
	if err := writeBackupPruneReport(&textTwo, report, "text"); err != nil {
		t.Fatalf("write second text report: %v", err)
	}
	if textOne.String() != textTwo.String() ||
		!strings.Contains(textOne.String(), "mode=dry-run") ||
		strings.Index(textOne.String(), newest) > strings.Index(textOne.String(), oldest) {
		t.Fatalf("text report is not deterministic: %q", textOne.String())
	}
	var jsonOne, jsonTwo bytes.Buffer
	if err := writeBackupPruneReport(&jsonOne, report, "json"); err != nil {
		t.Fatalf("write JSON report: %v", err)
	}
	if err := writeBackupPruneReport(&jsonTwo, report, "json"); err != nil {
		t.Fatalf("write second JSON report: %v", err)
	}
	if jsonOne.String() != jsonTwo.String() {
		t.Fatalf("JSON reports differ:\n%s\n%s", jsonOne.String(), jsonTwo.String())
	}
	var decoded backupPruneReport
	if err := json.Unmarshal(jsonOne.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON report: %v", err)
	}
	if !reflect.DeepEqual(decoded, report) {
		t.Fatalf("decoded JSON = %#v, want %#v", decoded, report)
	}
}

func TestBackupPruneApplyAndCLI(t *testing.T) {
	t.Parallel()

	fixture := newBackupPruneFixture(t)
	now := time.Now().UTC()
	newest := writeBackupPruneFile(t, fixture.directory, now.Add(-time.Hour), "1000000000000002", "new")
	oldest := writeBackupPruneFile(t, fixture.directory, now.Add(-2*time.Hour), "1000000000000001", "old")
	args := []string{
		"backup-prune",
		"-dir", fixture.directory,
		"-prefix", backupPruneTestPrefix,
		"-active-db", fixture.activeDatabase,
		"-keep-last", "1",
		"-format", "json",
	}
	var stdout, stderr bytes.Buffer
	exitCode := run(args, strings.NewReader(""), &stdout, &stderr, func(string) string { return "" })
	if exitCode != 0 || stderr.Len() != 0 {
		t.Fatalf("dry-run exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	var dryRun backupPruneReport
	if err := json.Unmarshal(stdout.Bytes(), &dryRun); err != nil {
		t.Fatalf("decode dry-run report: %v", err)
	}
	if dryRun.Mode != "dry-run" || dryRun.Planned != 1 || dryRun.Deleted != 0 {
		t.Fatalf("dry-run report = %#v", dryRun)
	}
	if _, err := os.Lstat(filepath.Join(fixture.directory, oldest)); err != nil {
		t.Fatalf("CLI dry-run removed backup: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	args = append(args, "-apply")
	exitCode = run(args, strings.NewReader(""), &stdout, &stderr, func(string) string { return "" })
	if exitCode != 0 || stderr.Len() != 0 {
		t.Fatalf("apply exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	var applied backupPruneReport
	if err := json.Unmarshal(stdout.Bytes(), &applied); err != nil {
		t.Fatalf("decode apply report: %v", err)
	}
	if applied.Mode != "apply" || applied.Planned != 1 || applied.Deleted != 1 ||
		applied.Files[1].Action != "deleted" {
		t.Fatalf("apply report = %#v", applied)
	}
	if _, err := os.Lstat(filepath.Join(fixture.directory, oldest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old backup still exists or unexpected error: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.directory, newest)); err != nil {
		t.Fatalf("new backup was removed: %v", err)
	}
	if _, err := os.Lstat(fixture.activeDatabase); err != nil {
		t.Fatalf("active database was removed: %v", err)
	}
}

func TestBackupPruneRejectsUnsafePrefixedEntriesBeforeDeletion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(*testing.T, backupPruneFixture, string)
		want  string
	}{
		{
			name: "symbolic link",
			setup: func(t *testing.T, fixture backupPruneFixture, name string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(fixture.directory), "outside.db")
				if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(fixture.directory, name)); err != nil {
					t.Fatalf("create symlink: %v", err)
				}
			},
			want: "symbolic link",
		},
		{
			name: "directory",
			setup: func(t *testing.T, fixture backupPruneFixture, name string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(fixture.directory, name), 0o700); err != nil {
					t.Fatalf("create prefixed directory: %v", err)
				}
			},
			want: "not a regular file",
		},
		{
			name: "malformed generated name",
			setup: func(t *testing.T, fixture backupPruneFixture, _ string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(fixture.directory, backupPruneTestPrefix+"manual.db"), []byte("manual"), 0o600); err != nil {
					t.Fatalf("write malformed file: %v", err)
				}
			},
			want: "does not match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBackupPruneFixture(t)
			now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
			old := writeBackupPruneFile(t, fixture.directory, now.Add(-72*time.Hour), "2000000000000001", "old")
			unsafeName := backupPruneFilename(now.Add(-48*time.Hour), "2000000000000002")
			test.setup(t, fixture, unsafeName)
			_, err := executeBackupPrune(context.Background(), backupPruneOptions{
				directory:      fixture.directory,
				prefix:         backupPruneTestPrefix,
				activeDatabase: fixture.activeDatabase,
				keepLast:       1,
				apply:          true,
				format:         "text",
				now:            now,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("executeBackupPrune() error = %v, want %q", err, test.want)
			}
			if _, err := os.Lstat(filepath.Join(fixture.directory, old)); err != nil {
				t.Fatalf("valid backup was deleted before unsafe entry rejection: %v", err)
			}
		})
	}
}

func TestBackupPruneRejectsActiveDatabaseAndHardLink(t *testing.T) {
	t.Parallel()

	fixture := newBackupPruneFixture(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	name := backupPruneFilename(now.Add(-72*time.Hour), "3000000000000001")
	if err := os.Link(fixture.activeDatabase, filepath.Join(fixture.directory, name)); err != nil {
		t.Fatalf("hard-link active database: %v", err)
	}
	_, err := executeBackupPrune(context.Background(), backupPruneOptions{
		directory:      fixture.directory,
		prefix:         backupPruneTestPrefix,
		activeDatabase: fixture.activeDatabase,
		keepLast:       1,
		format:         "text",
		now:            now,
	})
	if err == nil || !strings.Contains(err.Error(), "active database") {
		t.Fatalf("hard-linked active database error = %v", err)
	}
	if contents, err := os.ReadFile(fixture.activeDatabase); err != nil || string(contents) != "active" {
		t.Fatalf("active database changed: contents=%q err=%v", contents, err)
	}

	inside := filepath.Join(fixture.directory, "directory.db")
	if err := os.WriteFile(inside, []byte("active"), 0o600); err != nil {
		t.Fatalf("write database inside backup directory: %v", err)
	}
	_, err = executeBackupPrune(context.Background(), backupPruneOptions{
		directory:      fixture.directory,
		prefix:         backupPruneTestPrefix,
		activeDatabase: inside,
		keepLast:       1,
		format:         "text",
		now:            now,
	})
	if err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("database inside backup directory error = %v", err)
	}
}

func TestBackupPruneRejectsReplacementRacesWithoutFollowingLinks(t *testing.T) {
	t.Parallel()

	t.Run("candidate becomes symlink", func(t *testing.T) {
		fixture := newBackupPruneFixture(t)
		now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		name := writeBackupPruneFile(t, fixture.directory, now.Add(-72*time.Hour), "4000000000000001", "old")
		outside := filepath.Join(filepath.Dir(fixture.directory), "outside.db")
		if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
			t.Fatalf("write outside file: %v", err)
		}
		_, err := executeBackupPrune(context.Background(), backupPruneOptions{
			directory:      fixture.directory,
			prefix:         backupPruneTestPrefix,
			activeDatabase: fixture.activeDatabase,
			keepLast:       0,
			maxAge:         time.Hour,
			apply:          true,
			format:         "text",
			now:            now,
			hooks: backupPruneHooks{beforeApply: func() error {
				if err := os.Remove(filepath.Join(fixture.directory, name)); err != nil {
					return err
				}
				return os.Symlink(outside, filepath.Join(fixture.directory, name))
			}},
		})
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("replacement error = %v", err)
		}
		if contents, err := os.ReadFile(outside); err != nil || string(contents) != "outside" {
			t.Fatalf("outside target changed: contents=%q err=%v", contents, err)
		}
		if info, err := os.Lstat(filepath.Join(fixture.directory, name)); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("replacement symlink was followed or removed: info=%v err=%v", info, err)
		}
	})

	t.Run("active database changes identity", func(t *testing.T) {
		fixture := newBackupPruneFixture(t)
		now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		name := writeBackupPruneFile(t, fixture.directory, now.Add(-72*time.Hour), "4000000000000002", "old")
		_, err := executeBackupPrune(context.Background(), backupPruneOptions{
			directory:      fixture.directory,
			prefix:         backupPruneTestPrefix,
			activeDatabase: fixture.activeDatabase,
			keepLast:       0,
			maxAge:         time.Hour,
			apply:          true,
			format:         "text",
			now:            now,
			hooks: backupPruneHooks{beforeApply: func() error {
				replacement := fixture.activeDatabase + ".replacement"
				if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
					return err
				}
				return os.Rename(replacement, fixture.activeDatabase)
			}},
		})
		if err == nil || !strings.Contains(err.Error(), "active database changed identity") {
			t.Fatalf("active replacement error = %v", err)
		}
		if _, err := os.Lstat(filepath.Join(fixture.directory, name)); err != nil {
			t.Fatalf("backup deleted after active database replacement: %v", err)
		}
	})

	t.Run("candidate changes identity", func(t *testing.T) {
		fixture := newBackupPruneFixture(t)
		now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		name := writeBackupPruneFile(t, fixture.directory, now.Add(-72*time.Hour), "4000000000000003", "old")
		_, err := executeBackupPrune(context.Background(), backupPruneOptions{
			directory:      fixture.directory,
			prefix:         backupPruneTestPrefix,
			activeDatabase: fixture.activeDatabase,
			keepLast:       0,
			maxAge:         time.Hour,
			apply:          true,
			format:         "text",
			now:            now,
			hooks: backupPruneHooks{beforeRemove: func(candidate string) error {
				path := filepath.Join(fixture.directory, candidate)
				if err := os.Remove(path); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("replacement"), 0o600)
			}},
		})
		if err == nil || !strings.Contains(err.Error(), "changed identity") {
			t.Fatalf("candidate replacement error = %v", err)
		}
		contents, readErr := os.ReadFile(filepath.Join(fixture.directory, name))
		if readErr != nil || string(contents) != "replacement" {
			t.Fatalf("replacement candidate changed: contents=%q err=%v", contents, readErr)
		}
	})
}

func TestBackupPruneValidationAndCancellation(t *testing.T) {
	t.Parallel()

	fixture := newBackupPruneFixture(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	valid := backupPruneOptions{
		directory:      fixture.directory,
		prefix:         backupPruneTestPrefix,
		activeDatabase: fixture.activeDatabase,
		keepLast:       1,
		format:         "text",
		now:            now,
	}
	tests := []struct {
		name   string
		mutate func(*backupPruneOptions)
		want   string
	}{
		{name: "relative directory", mutate: func(options *backupPruneOptions) { options.directory = "backups" }, want: "absolute"},
		{name: "relative database", mutate: func(options *backupPruneOptions) { options.activeDatabase = "directory.db" }, want: "absolute"},
		{name: "path prefix", mutate: func(options *backupPruneOptions) { options.prefix = "../ldap-" }, want: "ASCII"},
		{name: "broad prefix", mutate: func(options *backupPruneOptions) { options.prefix = "ldap" }, want: "end"},
		{name: "negative keep", mutate: func(options *backupPruneOptions) { options.keepLast = -1 }, want: "negative"},
		{name: "no policy", mutate: func(options *backupPruneOptions) { options.keepLast = 0 }, want: "retention policy"},
		{name: "bad format", mutate: func(options *backupPruneOptions) { options.format = "yaml" }, want: "text or json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if _, err := executeBackupPrune(context.Background(), options); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	if err := os.Chmod(fixture.directory, 0o755); err != nil {
		t.Fatalf("make backup directory public: %v", err)
	}
	if _, err := executeBackupPrune(context.Background(), valid); err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("public directory error = %v", err)
	}
	if err := os.Chmod(fixture.directory, 0o700); err != nil {
		t.Fatalf("restore private permissions: %v", err)
	}

	alias := filepath.Join(filepath.Dir(fixture.directory), "backup-link")
	if err := os.Symlink(fixture.directory, alias); err != nil {
		t.Fatalf("create directory symlink: %v", err)
	}
	linked := valid
	linked.directory = alias
	if _, err := executeBackupPrune(context.Background(), linked); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("directory symlink error = %v", err)
	}

	unsafeParent := filepath.Join(filepath.Dir(fixture.directory), "unsafe-parent")
	if err := os.Mkdir(unsafeParent, 0o777); err != nil {
		t.Fatalf("create unsafe parent: %v", err)
	}
	if err := os.Chmod(unsafeParent, 0o777); err != nil {
		t.Fatalf("make parent unsafe: %v", err)
	}
	unsafeDirectory := filepath.Join(unsafeParent, "backups")
	if err := os.Mkdir(unsafeDirectory, 0o700); err != nil {
		t.Fatalf("create private directory under unsafe parent: %v", err)
	}
	unsafe := valid
	unsafe.directory = unsafeDirectory
	if _, err := executeBackupPrune(context.Background(), unsafe); err == nil || !strings.Contains(err.Error(), "unsafe replacement") {
		t.Fatalf("unsafe ancestor error = %v", err)
	}

	name := writeBackupPruneFile(t, fixture.directory, now.Add(-72*time.Hour), "5000000000000001", "old")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	apply := valid
	apply.keepLast = 0
	apply.maxAge = time.Hour
	apply.apply = true
	if _, err := executeBackupPrune(canceled, apply); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.directory, name)); err != nil {
		t.Fatalf("canceled prune removed backup: %v", err)
	}
}

func TestParseBackupPruneDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want time.Duration
		ok   bool
	}{
		{raw: "0", ok: true},
		{raw: "30d", want: 30 * 24 * time.Hour, ok: true},
		{raw: "2w", want: 14 * 24 * time.Hour, ok: true},
		{raw: "90m", want: 90 * time.Minute, ok: true},
		{raw: ""},
		{raw: "-1h"},
		{raw: "1.5d"},
		{raw: "0d"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := parseBackupPruneDuration(test.raw)
			if test.ok && (err != nil || got != test.want) {
				t.Fatalf("parseBackupPruneDuration(%q) = %v, %v, want %v", test.raw, got, err, test.want)
			}
			if !test.ok && err == nil {
				t.Fatalf("parseBackupPruneDuration(%q) unexpectedly succeeded with %v", test.raw, got)
			}
		})
	}
}

func newBackupPruneFixture(t *testing.T) backupPruneFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	directory := filepath.Join(root, "backups")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create private backup directory: %v", err)
	}
	databaseDirectory := filepath.Join(root, "database")
	if err := os.Mkdir(databaseDirectory, 0o700); err != nil {
		t.Fatalf("create database directory: %v", err)
	}
	activeDatabase := filepath.Join(databaseDirectory, "directory.db")
	if err := os.WriteFile(activeDatabase, []byte("active"), 0o600); err != nil {
		t.Fatalf("write active database: %v", err)
	}
	return backupPruneFixture{directory: directory, activeDatabase: activeDatabase}
}

func writeBackupPruneFile(
	t *testing.T,
	directory string,
	createdAt time.Time,
	randomHex string,
	contents string,
) string {
	t.Helper()
	name := backupPruneFilename(createdAt, randomHex)
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatalf("write backup %q: %v", name, err)
	}
	return name
}

func backupPruneFilename(createdAt time.Time, randomHex string) string {
	return backupPruneTestPrefix + createdAt.UTC().Format(backupPruneTimestampLayout) + "-" + randomHex + ".db"
}
