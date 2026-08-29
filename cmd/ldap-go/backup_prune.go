package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const backupPruneTimestampLayout = "20060102T150405.000000000Z"

type backupPruneDuration struct {
	duration time.Duration
}

func (value *backupPruneDuration) Set(raw string) error {
	duration, err := parseBackupPruneDuration(raw)
	if err != nil {
		return err
	}
	value.duration = duration
	return nil
}

func (value backupPruneDuration) String() string {
	return value.duration.String()
}

type backupPruneOptions struct {
	directory      string
	prefix         string
	activeDatabase string
	keepLast       int
	maxAge         time.Duration
	apply          bool
	format         string
	now            time.Time
	hooks          backupPruneHooks
}

type backupPruneHooks struct {
	beforeApply  func() error
	beforeRemove func(string) error
}

type backupPruneCandidate struct {
	name      string
	createdAt time.Time
	info      os.FileInfo
}

type backupPruneReport struct {
	Mode      string                  `json:"mode"`
	Directory string                  `json:"directory"`
	Prefix    string                  `json:"prefix"`
	KeepLast  int                     `json:"keep_last"`
	MaxAge    string                  `json:"max_age"`
	Matched   int                     `json:"matched"`
	Retained  int                     `json:"retained"`
	Planned   int                     `json:"planned"`
	Deleted   int                     `json:"deleted"`
	Ignored   int                     `json:"ignored"`
	Files     []backupPruneFileReport `json:"files"`
}

type backupPruneFileReport struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Size      int64  `json:"size"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
}

func runBackupPrune(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("backup-prune", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("dir", "", "absolute private backup directory")
	prefix := flags.String("prefix", "", "explicit generated-backup filename prefix")
	activeDatabase := flags.String("active-db", "", "absolute active database path to protect")
	keepLast := flags.Int("keep-last", 7, "always retain this many newest backups")
	var maxAge backupPruneDuration
	flags.Var(&maxAge, "max-age", "retain backups no older than this duration (for example 30d or 720h)")
	apply := flags.Bool("apply", false, "delete planned files; the default is dry-run")
	format := flags.String("format", "text", "report format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	report, err := executeBackupPrune(ctx, backupPruneOptions{
		directory:      *directory,
		prefix:         *prefix,
		activeDatabase: *activeDatabase,
		keepLast:       *keepLast,
		maxAge:         maxAge.duration,
		apply:          *apply,
		format:         strings.ToLower(strings.TrimSpace(*format)),
		now:            time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return writeBackupPruneReport(stdout, report, strings.ToLower(strings.TrimSpace(*format)))
}

func executeBackupPrune(
	ctx context.Context,
	options backupPruneOptions,
) (report backupPruneReport, runErr error) {
	if ctx == nil {
		return report, errors.New("backup-prune context is required")
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	directory, directoryInfo, activeInfo, err := validateBackupPruneOptions(options)
	if err != nil {
		return report, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return report, fmt.Errorf("open private backup directory: %w", err)
	}
	defer func() {
		runErr = errors.Join(runErr, root.Close())
	}()
	openedDirectoryInfo, err := root.Lstat(".")
	if err != nil {
		return report, fmt.Errorf("verify opened backup directory: %w", err)
	}
	if !os.SameFile(directoryInfo, openedDirectoryInfo) {
		return report, errors.New("backup directory changed identity while it was being opened")
	}

	candidates, ignored, err := scanBackupPruneCandidates(ctx, root, options.prefix, activeInfo)
	if err != nil {
		return report, err
	}
	report, planned := planBackupPrune(options, directory, candidates, ignored)
	if !options.apply || len(planned) == 0 {
		return report, nil
	}
	if options.hooks.beforeApply != nil {
		if err := options.hooks.beforeApply(); err != nil {
			return report, fmt.Errorf("backup-prune pre-apply hook: %w", err)
		}
	}
	for _, candidate := range planned {
		if err := revalidateBackupPruneCandidate(
			root,
			candidate,
			filepath.Clean(options.activeDatabase),
			activeInfo,
		); err != nil {
			return report, err
		}
	}
	for _, candidate := range planned {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if options.hooks.beforeRemove != nil {
			if err := options.hooks.beforeRemove(candidate.name); err != nil {
				return report, fmt.Errorf("backup-prune pre-remove hook for %q: %w", candidate.name, err)
			}
		}
		if err := revalidateBackupPruneCandidate(
			root,
			candidate,
			filepath.Clean(options.activeDatabase),
			activeInfo,
		); err != nil {
			return report, err
		}
		if err := root.Remove(candidate.name); err != nil {
			return report, fmt.Errorf("delete backup %q: %w", candidate.name, err)
		}
		report.Deleted++
		for index := range report.Files {
			if report.Files[index].Name == candidate.name {
				report.Files[index].Action = "deleted"
				break
			}
		}
	}
	return report, nil
}

func validateBackupPruneOptions(
	options backupPruneOptions,
) (string, os.FileInfo, os.FileInfo, error) {
	if options.directory == "" {
		return "", nil, nil, errors.New("-dir is required")
	}
	if !filepath.IsAbs(options.directory) {
		return "", nil, nil, errors.New("-dir must be an absolute path")
	}
	if options.activeDatabase == "" {
		return "", nil, nil, errors.New("-active-db is required")
	}
	if !filepath.IsAbs(options.activeDatabase) {
		return "", nil, nil, errors.New("-active-db must be an absolute path")
	}
	if err := validateBackupPrunePrefix(options.prefix); err != nil {
		return "", nil, nil, err
	}
	if options.keepLast < 0 {
		return "", nil, nil, errors.New("-keep-last must not be negative")
	}
	if options.maxAge < 0 {
		return "", nil, nil, errors.New("-max-age must not be negative")
	}
	if options.keepLast == 0 && options.maxAge == 0 {
		return "", nil, nil, errors.New("at least one retention policy must be enabled")
	}
	if options.format != "text" && options.format != "json" {
		return "", nil, nil, errors.New("-format must be text or json")
	}

	directory := filepath.Clean(options.directory)
	activeDatabase := filepath.Clean(options.activeDatabase)
	if err := rejectBackupPruneSymbolicLinkPath(directory, true); err != nil {
		return "", nil, nil, fmt.Errorf("validate backup directory: %w", err)
	}
	if err := validateBackupPrunePrivateDirectory(directory); err != nil {
		return "", nil, nil, err
	}
	if err := rejectBackupPruneSymbolicLinkPath(activeDatabase, false); err != nil {
		return "", nil, nil, fmt.Errorf("validate active database: %w", err)
	}
	activeInfo, err := os.Lstat(activeDatabase)
	if err != nil {
		return "", nil, nil, fmt.Errorf("stat active database: %w", err)
	}
	if !activeInfo.Mode().IsRegular() {
		return "", nil, nil, errors.New("-active-db must name a regular file")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return "", nil, nil, fmt.Errorf("restat backup directory: %w", err)
	}
	activeParentInfo, err := os.Lstat(filepath.Dir(activeDatabase))
	if err != nil {
		return "", nil, nil, fmt.Errorf("stat active database directory: %w", err)
	}
	if filepath.Clean(filepath.Dir(activeDatabase)) == directory ||
		os.SameFile(directoryInfo, activeParentInfo) {
		return "", nil, nil, errors.New("backup directory must not contain the active database")
	}
	return directory, directoryInfo, activeInfo, nil
}

func validateBackupPrunePrefix(prefix string) error {
	if prefix == "" {
		return errors.New("-prefix is required")
	}
	if len(prefix) < 3 || len(prefix) > 64 {
		return errors.New("-prefix must contain between 3 and 64 ASCII characters")
	}
	if prefix[len(prefix)-1] != '-' && prefix[len(prefix)-1] != '_' {
		return errors.New("-prefix must end in '-' or '_'")
	}
	for index := range len(prefix) {
		character := prefix[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '.' || character == '-' || character == '_' {
			continue
		}
		return errors.New("-prefix may contain only ASCII letters, digits, '.', '-', and '_'")
	}
	if prefix[0] == '.' || prefix[0] == '-' || prefix[0] == '_' {
		return errors.New("-prefix must start with an ASCII letter or digit")
	}
	if strings.ContainsAny(prefix, `/\\`) || filepath.Base(prefix) != prefix {
		return errors.New("-prefix must not contain a path separator")
	}
	return nil
}

func rejectBackupPruneSymbolicLinkPath(path string, finalDirectory bool) error {
	clean := filepath.Clean(path)
	var components []string
	for current := clean; ; current = filepath.Dir(current) {
		components = append(components, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	for left, right := 0, len(components)-1; left < right; left, right = left+1, right-1 {
		components[left], components[right] = components[right], components[left]
	}
	for index, component := range components {
		info, err := os.Lstat(component)
		if err != nil {
			return fmt.Errorf("lstat path component %q: %w", component, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symbolic link", component)
		}
		last := index == len(components)-1
		if !last || finalDirectory {
			if !info.IsDir() {
				return fmt.Errorf("path component %q is not a directory", component)
			}
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("path component %q is not a regular file", component)
		}
	}
	return nil
}

func scanBackupPruneCandidates(
	ctx context.Context,
	root *os.Root,
	prefix string,
	activeInfo os.FileInfo,
) ([]backupPruneCandidate, int, error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, 0, fmt.Errorf("read private backup directory: %w", err)
	}
	candidates := make([]backupPruneCandidate, 0, len(entries))
	ignored := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			ignored++
			continue
		}
		info, err := root.Lstat(name)
		if err != nil {
			return nil, 0, fmt.Errorf("lstat prefixed backup %q: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, 0, fmt.Errorf("prefixed backup %q is a symbolic link", name)
		}
		if !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("prefixed backup %q is not a regular file", name)
		}
		createdAt, err := parseBackupPruneFilename(prefix, name)
		if err != nil {
			return nil, 0, err
		}
		if os.SameFile(info, activeInfo) {
			return nil, 0, fmt.Errorf("prefixed backup %q is the active database or a hard link to it", name)
		}
		candidates = append(candidates, backupPruneCandidate{
			name:      name,
			createdAt: createdAt,
			info:      info,
		})
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].createdAt.Equal(candidates[right].createdAt) {
			return candidates[left].name < candidates[right].name
		}
		return candidates[left].createdAt.After(candidates[right].createdAt)
	})
	return candidates, ignored, nil
}

func parseBackupPruneFilename(prefix, name string) (time.Time, error) {
	const randomHexLength = 16
	const suffix = ".db"
	remainder := strings.TrimPrefix(name, prefix)
	timestampLength := len(backupPruneTimestampLayout)
	wantLength := timestampLength + 1 + randomHexLength + len(suffix)
	if len(remainder) != wantLength || remainder[timestampLength] != '-' ||
		!strings.HasSuffix(remainder, suffix) {
		return time.Time{}, fmt.Errorf(
			"prefixed backup %q does not match the generated backup filename format",
			name,
		)
	}
	timestamp := remainder[:timestampLength]
	createdAt, err := time.Parse(backupPruneTimestampLayout, timestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("prefixed backup %q has an invalid UTC timestamp: %w", name, err)
	}
	randomHex := remainder[timestampLength+1 : timestampLength+1+randomHexLength]
	if strings.ToLower(randomHex) != randomHex {
		return time.Time{}, fmt.Errorf("prefixed backup %q has a non-canonical random suffix", name)
	}
	if _, err := hex.DecodeString(randomHex); err != nil {
		return time.Time{}, fmt.Errorf("prefixed backup %q has an invalid random suffix", name)
	}
	return createdAt.UTC(), nil
}

func planBackupPrune(
	options backupPruneOptions,
	directory string,
	candidates []backupPruneCandidate,
	ignored int,
) (backupPruneReport, []backupPruneCandidate) {
	mode := "dry-run"
	if options.apply {
		mode = "apply"
	}
	maxAge := "disabled"
	if options.maxAge > 0 {
		maxAge = options.maxAge.String()
	}
	report := backupPruneReport{
		Mode:      mode,
		Directory: directory,
		Prefix:    options.prefix,
		KeepLast:  options.keepLast,
		MaxAge:    maxAge,
		Matched:   len(candidates),
		Ignored:   ignored,
		Files:     make([]backupPruneFileReport, 0, len(candidates)),
	}
	cutoff := options.now.UTC().Add(-options.maxAge)
	planned := make([]backupPruneCandidate, 0, len(candidates))
	for index, candidate := range candidates {
		action := "retain"
		reason := "keep-last"
		retain := index < options.keepLast
		if !retain && options.maxAge > 0 && !candidate.createdAt.Before(cutoff) {
			retain = true
			reason = "max-age"
		}
		if retain {
			report.Retained++
		} else {
			action = "would-delete"
			reason = "beyond-keep-last"
			if options.maxAge > 0 {
				reason = "expired"
			}
			report.Planned++
			planned = append(planned, candidate)
		}
		report.Files = append(report.Files, backupPruneFileReport{
			Name:      candidate.name,
			CreatedAt: candidate.createdAt.Format(time.RFC3339Nano),
			Size:      candidate.info.Size(),
			Action:    action,
			Reason:    reason,
		})
	}
	return report, planned
}

func revalidateBackupPruneCandidate(
	root *os.Root,
	candidate backupPruneCandidate,
	activeDatabase string,
	activeInfo os.FileInfo,
) error {
	if err := rejectBackupPruneSymbolicLinkPath(activeDatabase, false); err != nil {
		return fmt.Errorf("revalidate active database path: %w", err)
	}
	currentActiveInfo, err := os.Lstat(activeDatabase)
	if err != nil {
		return fmt.Errorf("revalidate active database: %w", err)
	}
	if currentActiveInfo.Mode()&os.ModeSymlink != 0 || !currentActiveInfo.Mode().IsRegular() {
		return errors.New("active database is no longer a regular non-symbolic-link file")
	}
	if !os.SameFile(activeInfo, currentActiveInfo) {
		return errors.New("active database changed identity after planning")
	}
	info, err := root.Lstat(candidate.name)
	if err != nil {
		return fmt.Errorf("revalidate backup %q: %w", candidate.name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup %q became a symbolic link", candidate.name)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup %q is no longer a regular file", candidate.name)
	}
	if !os.SameFile(candidate.info, info) {
		return fmt.Errorf("backup %q changed identity after planning", candidate.name)
	}
	if os.SameFile(info, currentActiveInfo) {
		return fmt.Errorf("backup %q became the active database or a hard link to it", candidate.name)
	}
	return nil
}

func parseBackupPruneDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errors.New("duration is empty")
	}
	if raw == "0" || raw == "0s" {
		return 0, nil
	}
	unit := time.Duration(0)
	switch raw[len(raw)-1] {
	case 'd':
		unit = 24 * time.Hour
	case 'w':
		unit = 7 * 24 * time.Hour
	}
	if unit != 0 {
		count, err := strconv.ParseUint(raw[:len(raw)-1], 10, 64)
		if err != nil || count == 0 || count > uint64(math.MaxInt64/int64(unit)) {
			return 0, fmt.Errorf("invalid retention duration %q", raw)
		}
		return time.Duration(count) * unit, nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid retention duration %q", raw)
	}
	return duration, nil
}

func writeBackupPruneReport(writer io.Writer, report backupPruneReport, format string) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	if _, err := fmt.Fprintf(
		writer,
		"backup-prune mode=%s directory=%q prefix=%q keep-last=%d max-age=%s matched=%d retained=%d planned=%d deleted=%d ignored=%d\n",
		report.Mode,
		report.Directory,
		report.Prefix,
		report.KeepLast,
		report.MaxAge,
		report.Matched,
		report.Retained,
		report.Planned,
		report.Deleted,
		report.Ignored,
	); err != nil {
		return err
	}
	for _, file := range report.Files {
		if _, err := fmt.Fprintf(
			writer,
			"%s name=%q created-at=%s size=%d reason=%s\n",
			file.Action,
			file.Name,
			file.CreatedAt,
			file.Size,
			file.Reason,
		); err != nil {
			return err
		}
	}
	return nil
}
