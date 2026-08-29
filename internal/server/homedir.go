package server

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultHomedirSkeletonPath = "/etc/skel"
	defaultHomedirMinimumUID   = uint64(100)
	maximumHomedirPathLength   = 1023
)

type homedirDeleteStyle uint8

const (
	homedirDeleteIgnore homedirDeleteStyle = iota
	homedirDeleteDelete
	homedirDeleteArchive
)

type homedirRuntimeConfiguration struct {
	skeletonPath string
	minimumUID   uint64
	regexps      []homedirRegexp
	deleteStyle  homedirDeleteStyle
	archivePath  string
}

type homedirRegexp struct {
	match       string
	replacement string
	compiled    *regexp.Regexp
	root        string
}

type homedirPath struct {
	root     string
	relative string
	absolute string
}

type homedirEntryValues struct {
	path     homedirPath
	uid      uint64
	gid      uint64
	presence bool
	valid    bool
}

func loadHomedirRuntimeConfiguration(
	entry directory.Entry,
) (homedirRuntimeConfiguration, error) {
	if !homedirFilesystemSupported {
		return homedirRuntimeConfiguration{}, fmt.Errorf(
			"%s homedir overlay requires a POSIX filesystem",
			entry.DN,
		)
	}
	configuration := homedirRuntimeConfiguration{
		skeletonPath: defaultHomedirSkeletonPath,
		minimumUID:   defaultHomedirMinimumUID,
		deleteStyle:  homedirDeleteIgnore,
	}

	if value, present, err := singleHomedirString(entry, "olcSkeletonPath"); err != nil {
		return homedirRuntimeConfiguration{}, err
	} else if present {
		path, err := validateHomedirConfiguredPath(value, false)
		if err != nil {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcSkeletonPath: %w",
				entry.DN,
				err,
			)
		}
		configuration.skeletonPath = path
	}

	if values := entry.Values("olcMinimumUidNumber"); len(values) > 0 {
		if len(values) != 1 {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcMinimumUidNumber must be single-valued",
				entry.DN,
			)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(values[0])), 10, 32)
		if err != nil {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcMinimumUidNumber has invalid value %q",
				entry.DN,
				values[0],
			)
		}
		configuration.minimumUID = value
	}

	orderedRegexps, err := orderedHomedirRegexpValues(entry.Values("olcHomedirRegexp"))
	if err != nil {
		return homedirRuntimeConfiguration{}, fmt.Errorf(
			"%s olcHomedirRegexp: %w",
			entry.DN,
			err,
		)
	}
	for _, raw := range orderedRegexps {
		arguments, err := tokenizeOpenLDAPConfig(raw)
		if err != nil {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcHomedirRegexp: %w",
				entry.DN,
				err,
			)
		}
		if len(arguments) != 2 {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcHomedirRegexp requires a match and replacement",
				entry.DN,
			)
		}
		compiled, err := regexp.CompilePOSIX(arguments[0])
		if err != nil {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcHomedirRegexp match %q: %w",
				entry.DN,
				arguments[0],
				err,
			)
		}
		root, err := homedirReplacementRoot(arguments[1])
		if err != nil {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcHomedirRegexp replacement %q: %w",
				entry.DN,
				arguments[1],
				err,
			)
		}
		configuration.regexps = append(configuration.regexps, homedirRegexp{
			match:       arguments[0],
			replacement: arguments[1],
			compiled:    compiled,
			root:        root,
		})
	}

	if value, present, err := singleHomedirString(entry, "olcHomedirDeleteStyle"); err != nil {
		return homedirRuntimeConfiguration{}, err
	} else if present {
		switch {
		case strings.EqualFold(value, "IGNORE"):
			configuration.deleteStyle = homedirDeleteIgnore
		case strings.EqualFold(value, "DELETE"):
			configuration.deleteStyle = homedirDeleteDelete
		case strings.EqualFold(value, "ARCHIVE"):
			configuration.deleteStyle = homedirDeleteArchive
		default:
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcHomedirDeleteStyle has invalid value %q",
				entry.DN,
				value,
			)
		}
	}

	if value, present, err := singleHomedirString(entry, "olcHomedirArchivePath"); err != nil {
		return homedirRuntimeConfiguration{}, err
	} else if present {
		path, err := validateHomedirConfiguredPath(value, true)
		if err != nil {
			return homedirRuntimeConfiguration{}, fmt.Errorf(
				"%s olcHomedirArchivePath: %w",
				entry.DN,
				err,
			)
		}
		configuration.archivePath = path
	}

	return configuration, nil
}

func singleHomedirString(
	entry directory.Entry,
	attribute string,
) (string, bool, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", false, fmt.Errorf(
			"%s %s must be single-valued",
			entry.DN,
			attribute,
		)
	}
	value := strings.TrimSpace(string(values[0]))
	if value == "" {
		return "", false, fmt.Errorf("%s %s cannot be empty", entry.DN, attribute)
	}
	return value, true, nil
}

func orderedHomedirRegexpValues(values [][]byte) ([]string, error) {
	type orderedValue struct {
		order    int
		position int
		value    string
		explicit bool
	}

	ordered := make([]orderedValue, 0, len(values))
	orders := make(map[int]struct{})
	hasExplicit := false
	hasImplicit := false
	for position, raw := range values {
		value := strings.TrimSpace(string(raw))
		order := position
		explicit := false
		if strings.HasPrefix(value, "{") {
			hasExplicit = true
			end := strings.IndexByte(value, '}')
			if end < 2 {
				return nil, errors.New("invalid ordered value prefix")
			}
			parsed, err := strconv.Atoi(value[1:end])
			if err != nil || parsed < 0 {
				return nil, fmt.Errorf("invalid ordered value prefix %q", value[:end+1])
			}
			if _, duplicate := orders[parsed]; duplicate {
				return nil, fmt.Errorf("duplicate ordered value index %d", parsed)
			}
			orders[parsed] = struct{}{}
			order = parsed
			explicit = true
			value = strings.TrimSpace(value[end+1:])
		} else {
			hasImplicit = true
		}
		if value == "" {
			return nil, errors.New("contains an empty value")
		}
		ordered = append(ordered, orderedValue{
			order:    order,
			position: position,
			value:    value,
			explicit: explicit,
		})
	}
	if hasExplicit && hasImplicit {
		return nil, errors.New("cannot mix ordered and unordered values")
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].explicit {
			return ordered[i].position < ordered[j].position
		}
		return ordered[i].order < ordered[j].order
	})
	result := make([]string, len(ordered))
	for index := range ordered {
		result[index] = ordered[index].value
	}
	return result, nil
}

func validateHomedirConfiguredPath(raw string, rejectRoot bool) (string, error) {
	if strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("contains a NUL byte")
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("must be an absolute path")
	}
	if homedirPathHasParentReference(raw) {
		return "", errors.New("must not contain a parent-directory component")
	}
	cleaned := filepath.Clean(raw)
	if rejectRoot && cleaned == string(filepath.Separator) {
		return "", errors.New("must not be the filesystem root")
	}
	return cleaned, nil
}

func homedirReplacementRoot(replacement string) (string, error) {
	if replacement == "" {
		return "", errors.New("cannot be empty")
	}
	var literal strings.Builder
	hasExpansion := false
	for position := 0; position < len(replacement); position++ {
		switch replacement[position] {
		case '\\':
			position++
			if position == len(replacement) {
				return "", errors.New("has a trailing escape")
			}
			if !hasExpansion {
				literal.WriteByte(replacement[position])
			}
		case '$':
			position++
			if position == len(replacement) || replacement[position] < '0' || replacement[position] > '9' {
				return "", errors.New("contains an invalid match expansion")
			}
			hasExpansion = true
		default:
			if !hasExpansion {
				literal.WriteByte(replacement[position])
			}
		}
	}

	prefix := literal.String()
	if prefix == "" || !filepath.IsAbs(prefix) {
		return "", errors.New("must have an absolute literal prefix before expansion")
	}
	if homedirPathHasParentReference(prefix) {
		return "", errors.New("literal prefix must not contain a parent-directory component")
	}
	root := filepath.Clean(prefix)
	if !hasExpansion || !strings.HasSuffix(prefix, string(filepath.Separator)) {
		root = filepath.Dir(root)
	}
	if root == string(filepath.Separator) {
		return "", errors.New("trusted root must be narrower than the filesystem root")
	}
	return root, nil
}

func homedirPathHasParentReference(path string) bool {
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

func (mapping homedirRegexp) expand(value string) (homedirPath, bool) {
	matches := mapping.compiled.FindStringSubmatchIndex(value)
	if matches == nil {
		return homedirPath{}, false
	}

	var result strings.Builder
	for position := 0; position < len(mapping.replacement); position++ {
		switch mapping.replacement[position] {
		case '\\':
			position++
			if position == len(mapping.replacement) {
				return homedirPath{}, false
			}
			result.WriteByte(mapping.replacement[position])
		case '$':
			position++
			if position == len(mapping.replacement) {
				return homedirPath{}, false
			}
			group := int(mapping.replacement[position] - '0')
			matchPosition := group * 2
			if matchPosition+1 >= len(matches) || matches[matchPosition] < 0 {
				return homedirPath{}, false
			}
			result.WriteString(value[matches[matchPosition]:matches[matchPosition+1]])
		default:
			result.WriteByte(mapping.replacement[position])
		}
		if result.Len() > maximumHomedirPathLength {
			return homedirPath{}, false
		}
	}

	expanded := result.String()
	if strings.IndexByte(expanded, 0) >= 0 ||
		!filepath.IsAbs(expanded) ||
		homedirPathHasParentReference(expanded) {
		return homedirPath{}, false
	}
	cleaned := filepath.Clean(expanded)
	relative, err := filepath.Rel(mapping.root, cleaned)
	if err != nil || relative == "." || !homedirRelativePathSafe(relative) {
		return homedirPath{}, false
	}
	return homedirPath{
		root:     mapping.root,
		relative: relative,
		absolute: cleaned,
	}, true
}

func homedirRelativePathSafe(relative string) bool {
	return relative != "" &&
		!filepath.IsAbs(relative) &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
		!homedirPathHasParentReference(relative)
}

func (configuration homedirRuntimeConfiguration) harvest(
	entry *directory.Entry,
) homedirEntryValues {
	if entry == nil {
		return homedirEntryValues{}
	}
	values := homedirEntryValues{}
	homeValues := entry.Values("homeDirectory")
	uidValues := entry.Values("uidNumber")
	gidValues := entry.Values("gidNumber")
	values.presence = len(homeValues) > 0 || len(uidValues) > 0 || len(gidValues) > 0
	if len(homeValues) == 0 {
		return values
	}
	if len(uidValues) > 0 {
		uid, err := strconv.ParseUint(strings.TrimSpace(string(uidValues[0])), 10, 32)
		if err != nil {
			return values
		}
		values.uid = uid
	}
	if len(gidValues) > 0 {
		gid, err := strconv.ParseUint(strings.TrimSpace(string(gidValues[0])), 10, 32)
		if err != nil {
			return values
		}
		values.gid = gid
	}
	for _, mapping := range configuration.regexps {
		if path, matched := mapping.expand(string(homeValues[0])); matched {
			values.path = path
			values.valid = values.uid >= configuration.minimumUID
			return values
		}
	}
	return values
}

func validateHomedirSchema(
	registry *schema.Registry,
	configuration *homedirRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for _, attribute := range []string{"homeDirectory", "uidNumber", "gidNumber"} {
		if _, found := registry.AttributeType(attribute); !found {
			return fmt.Errorf("requires undefined attribute type %q", attribute)
		}
	}
	return nil
}

func (server *Server) applyHomedirTransition(
	configuration homedirRuntimeConfiguration,
	before *directory.Entry,
	after *directory.Entry,
) {
	oldValues := configuration.harvest(before)
	newValues := configuration.harvest(after)

	switch {
	case before == nil && newValues.valid:
		server.runHomedirEffect("provision", newValues.path, func() error {
			return provisionHomedir(
				newValues.path,
				configuration.skeletonPath,
				newValues.uid,
				newValues.gid,
			)
		})
	case after == nil && oldValues.valid:
		server.deprovisionHomedir(configuration, oldValues.path)
	case newValues.valid && !oldValues.valid:
		server.runHomedirEffect("provision", newValues.path, func() error {
			return provisionHomedir(
				newValues.path,
				configuration.skeletonPath,
				newValues.uid,
				newValues.gid,
			)
		})
	case oldValues.valid && !newValues.valid && !newValues.presence:
		server.deprovisionHomedir(configuration, oldValues.path)
	case oldValues.valid && newValues.valid:
		if oldValues.path.absolute != newValues.path.absolute {
			server.runHomedirEffect("rename", oldValues.path, func() error {
				return renameHomedir(oldValues.path, newValues.path)
			})
		}
		if oldValues.uid != newValues.uid || oldValues.gid != newValues.gid {
			server.runHomedirEffect("chown", newValues.path, func() error {
				return chownHomedir(
					newValues.path,
					oldValues.uid,
					newValues.uid,
					oldValues.gid,
					newValues.gid,
				)
			})
		}
	}
}

func (server *Server) deprovisionHomedir(
	configuration homedirRuntimeConfiguration,
	path homedirPath,
) {
	switch configuration.deleteStyle {
	case homedirDeleteIgnore:
		return
	case homedirDeleteDelete:
		server.runHomedirEffect("delete", path, func() error {
			return deleteHomedir(path)
		})
	case homedirDeleteArchive:
		server.runHomedirEffect("archive and delete", path, func() error {
			if configuration.archivePath == "" {
				return errors.New("olcHomedirArchivePath is not configured")
			}
			if err := archiveHomedir(path, configuration.archivePath, time.Now()); err != nil {
				return err
			}
			return deleteHomedir(path)
		})
	}
}

func (server *Server) runHomedirEffect(
	action string,
	path homedirPath,
	effect func() error,
) {
	if err := effect(); err != nil {
		server.config.Logger.Warn(
			"homedir overlay filesystem operation failed",
			"action", action,
			"path", path.absolute,
			"error", err,
		)
	}
}

func provisionHomedir(path homedirPath, skeletonPath string, uid, gid uint64) error {
	cleanedSkeleton := filepath.Clean(skeletonPath)
	resolvedSkeleton, err := filepath.EvalSymlinks(cleanedSkeleton)
	if err != nil {
		return fmt.Errorf("resolve skeleton %q: %w", cleanedSkeleton, err)
	}
	resolvedDestinationRoot, err := filepath.EvalSymlinks(path.root)
	if err != nil {
		return fmt.Errorf("resolve trusted root %q: %w", path.root, err)
	}
	resolvedDestination := filepath.Join(resolvedDestinationRoot, path.relative)
	if resolvedDestination == resolvedSkeleton ||
		strings.HasPrefix(
			resolvedDestination,
			resolvedSkeleton+string(filepath.Separator),
		) {
		return fmt.Errorf(
			"skeleton path %q contains destination %q",
			resolvedSkeleton,
			resolvedDestination,
		)
	}
	destinationRoot, err := openHomedirBoundary(path)
	if err != nil {
		return err
	}
	defer destinationRoot.Close()
	if _, err := destinationRoot.Lstat(path.relative); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	skeletonRoot, err := os.OpenRoot(skeletonPath)
	if err != nil {
		return fmt.Errorf("open skeleton %q: %w", skeletonPath, err)
	}
	defer skeletonRoot.Close()

	return fs.WalkDir(skeletonRoot.FS(), ".", func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		destination := path.relative
		if name != "." {
			destination = filepath.Join(path.relative, filepath.FromSlash(name))
		}
		if _, err := destinationRoot.Lstat(destination); err == nil {
			if item.IsDir() {
				return fs.SkipDir
			}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		switch {
		case item.IsDir():
			if err := destinationRoot.Mkdir(destination, info.Mode().Perm()); err != nil {
				return err
			}
			if err := destinationRoot.Lchown(destination, int(uid), int(gid)); err != nil {
				return err
			}
			return destinationRoot.Chmod(destination, info.Mode().Perm())
		case info.Mode().IsRegular():
			source, err := skeletonRoot.Open(name)
			if err != nil {
				return err
			}
			destinationFile, err := destinationRoot.OpenFile(
				destination,
				os.O_WRONLY|os.O_CREATE|os.O_EXCL,
				info.Mode().Perm(),
			)
			if err != nil {
				return errors.Join(err, source.Close())
			}
			_, copyErr := io.Copy(destinationFile, source)
			sourceCloseErr := source.Close()
			closeErr := destinationFile.Close()
			if copyErr != nil {
				return copyErr
			}
			if sourceCloseErr != nil {
				return sourceCloseErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err := destinationRoot.Lchown(destination, int(uid), int(gid)); err != nil {
				return err
			}
			return destinationRoot.Chmod(destination, info.Mode().Perm())
		case info.Mode()&os.ModeSymlink != 0:
			target, err := skeletonRoot.Readlink(name)
			if err != nil {
				return err
			}
			if err := destinationRoot.Symlink(target, destination); err != nil {
				return err
			}
			return destinationRoot.Lchown(destination, int(uid), int(gid))
		default:
			return nil
		}
	})
}

func openHomedirBoundary(path homedirPath) (*os.Root, error) {
	if !homedirRelativePathSafe(path.relative) ||
		filepath.Clean(filepath.Join(path.root, path.relative)) != path.absolute {
		return nil, errors.New("home path escapes its configured root")
	}
	root, err := os.OpenRoot(path.root)
	if err != nil {
		return nil, fmt.Errorf("open trusted root %q: %w", path.root, err)
	}
	if err := rejectHomedirSymlinkParents(root, path.relative); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func rejectHomedirSymlinkParents(root *os.Root, relative string) error {
	components := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	for index := 1; index < len(components); index++ {
		parent := filepath.Join(components[:index]...)
		info, err := root.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("parent path %q is a symbolic link", parent)
		}
		if !info.IsDir() {
			return fmt.Errorf("parent path %q is not a directory", parent)
		}
	}
	return nil
}

func renameHomedir(source, destination homedirPath) error {
	commonRoot, err := commonHomedirRoot(source.root, destination.root)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(commonRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	sourceRelative, err := filepath.Rel(commonRoot, source.absolute)
	if err != nil || !homedirRelativePathSafe(sourceRelative) {
		return errors.New("source home path escapes its configured root")
	}
	destinationRelative, err := filepath.Rel(commonRoot, destination.absolute)
	if err != nil || !homedirRelativePathSafe(destinationRelative) {
		return errors.New("destination home path escapes its configured root")
	}
	if err := rejectHomedirSymlinkParents(root, sourceRelative); err != nil {
		return err
	}
	if err := rejectHomedirSymlinkParents(root, destinationRelative); err != nil {
		return err
	}
	return root.Rename(sourceRelative, destinationRelative)
}

func commonHomedirRoot(left, right string) (string, error) {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if filepath.VolumeName(left) != filepath.VolumeName(right) {
		return "", errors.New("home paths are on different volumes")
	}
	leftParts := strings.Split(strings.TrimPrefix(left, string(filepath.Separator)), string(filepath.Separator))
	rightParts := strings.Split(strings.TrimPrefix(right, string(filepath.Separator)), string(filepath.Separator))
	length := len(leftParts)
	if len(rightParts) < length {
		length = len(rightParts)
	}
	shared := 0
	for shared < length && leftParts[shared] == rightParts[shared] {
		shared++
	}
	if shared == 0 {
		return "", errors.New("home rename has no bounded common root")
	}
	root := string(filepath.Separator) + filepath.Join(leftParts[:shared]...)
	if root == string(filepath.Separator) {
		return "", errors.New("home rename common root is the filesystem root")
	}
	return root, nil
}

func chownHomedir(path homedirPath, oldUID, newUID, oldGID, newGID uint64) error {
	root, err := openHomedirBoundary(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), filepath.ToSlash(path.relative), func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		currentUID, currentGID, ok := homedirFileOwnership(info)
		if !ok {
			return errors.New("filesystem ownership information is unavailable")
		}
		uid := -1
		gid := -1
		if currentUID == oldUID {
			uid = int(newUID)
		}
		if currentGID == oldGID {
			gid = int(newGID)
		}
		if uid == -1 && gid == -1 {
			return nil
		}
		return root.Lchown(filepath.FromSlash(name), uid, gid)
	})
}

func deleteHomedir(path homedirPath) error {
	root, err := openHomedirBoundary(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(path.relative)
}

func archiveHomedir(path homedirPath, archivePath string, now time.Time) error {
	resolvedSource, err := filepath.EvalSymlinks(path.absolute)
	if err != nil {
		return fmt.Errorf("resolve home path %q: %w", path.absolute, err)
	}
	resolvedArchive, err := filepath.EvalSymlinks(archivePath)
	if err != nil {
		return fmt.Errorf("resolve archive path %q: %w", archivePath, err)
	}
	if resolvedArchive == resolvedSource ||
		strings.HasPrefix(
			resolvedArchive,
			resolvedSource+string(filepath.Separator),
		) {
		return fmt.Errorf(
			"archive path %q is inside source home %q",
			resolvedArchive,
			resolvedSource,
		)
	}

	sourceRoot, err := openHomedirBoundary(path)
	if err != nil {
		return err
	}
	defer sourceRoot.Close()
	archiveRoot, err := os.OpenRoot(archivePath)
	if err != nil {
		return fmt.Errorf("open archive path %q: %w", archivePath, err)
	}
	defer archiveRoot.Close()

	base := filepath.Base(path.absolute)
	var archiveFile *os.File
	var archiveName string
	for counter := 0; ; counter++ {
		archiveName = fmt.Sprintf("%s-%d-%d.tar", base, now.Unix(), counter)
		archiveFile, err = archiveRoot.OpenFile(
			archiveName,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			0o600,
		)
		if !errors.Is(err, os.ErrExist) {
			break
		}
	}
	if err != nil {
		return err
	}

	tarWriter := tar.NewWriter(archiveFile)
	walkErr := fs.WalkDir(sourceRoot.FS(), filepath.ToSlash(path.relative), func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = sourceRoot.Readlink(filepath.FromSlash(name))
			if err != nil {
				return err
			}
		}
		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(path.relative, filepath.FromSlash(name))
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("archive traversal escaped the home directory")
		}
		header.Name = filepath.ToSlash(filepath.Join(base, relative))
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := sourceRoot.Open(filepath.FromSlash(name))
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	closeTarErr := tarWriter.Close()
	closeFileErr := archiveFile.Close()
	if walkErr != nil {
		return fmt.Errorf("archive %q: %w", archiveName, walkErr)
	}
	if closeTarErr != nil {
		return fmt.Errorf("archive %q: %w", archiveName, closeTarErr)
	}
	if closeFileErr != nil {
		return fmt.Errorf("archive %q: %w", archiveName, closeFileErr)
	}
	return nil
}

type homedirEffectStore struct {
	storage.Store
	server *Server
	mu     sync.Mutex
}

func (store *homedirEffectStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	runtime := store.server.runtime.Load()
	coordinator := newSQLBackendTransactionCoordinator(ctx)
	ctx = withSQLBackendTransactionCoordinator(ctx, coordinator)
	defer coordinator.rollback()
	var changes []homedirStorageChange
	err := store.Store.Update(ctx, func(writer storage.Writer) error {
		tracker := newHomedirTrackingWriter(writer, runtime)
		if err := update(tracker); err != nil {
			return err
		}
		changes = tracker.changes()
		return coordinator.commit()
	})
	if err != nil {
		return err
	}
	coordinator.completeUpdate()
	if runtime != nil {
		store.server.applyHomedirStorageChanges(runtime, changes)
	}
	return nil
}

type homedirTrackedEntry struct {
	partition string
	dn        directory.DN
	before    *directory.Entry
	after     *directory.Entry
}

type homedirTrackingWriter struct {
	storage.Writer
	runtime *runtimeState
	tracked map[string]*homedirTrackedEntry
}

func newHomedirTrackingWriter(
	writer storage.Writer,
	runtime *runtimeState,
) *homedirTrackingWriter {
	return &homedirTrackingWriter{
		Writer:  writer,
		runtime: runtime,
		tracked: make(map[string]*homedirTrackedEntry),
	}
}

func (writer *homedirTrackingWriter) AccessContext() any {
	if provider, ok := writer.Writer.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func (writer *homedirTrackingWriter) StorageContext() context.Context {
	if provider, ok := writer.Writer.(interface {
		StorageContext() context.Context
	}); ok {
		return provider.StorageContext()
	}
	return nil
}

func (writer *homedirTrackingWriter) MaintenanceStorageReader() storage.Reader {
	return writer.Writer
}

func (writer *homedirTrackingWriter) MaintenanceStorageWriter() storage.Writer {
	return writer.Writer
}

func (writer *homedirTrackingWriter) ObserveMaintenanceMutation(
	partition string,
	before *directory.Entry,
	after *directory.Entry,
) error {
	identity := after
	if identity == nil {
		identity = before
	}
	if identity == nil {
		return nil
	}
	dn, err := directory.ParseDN(identity.DN)
	if err != nil {
		return err
	}
	normalizedDN, err := homedirNormalizeDN(writer.runtime, partition, dn)
	if err != nil {
		return err
	}
	key := partition + "\x00" + normalizedDN.Key()
	tracked := writer.tracked[key]
	if tracked == nil {
		tracked = &homedirTrackedEntry{partition: partition, dn: normalizedDN}
		if before != nil {
			cloned := before.Clone()
			tracked.before = &cloned
		}
		writer.tracked[key] = tracked
	}
	tracked.after = nil
	if after != nil {
		cloned := after.Clone()
		tracked.after = &cloned
	}
	return nil
}

func (writer *homedirTrackingWriter) Put(entry directory.Entry, replace bool) error {
	return writer.putIn("", entry, replace, false)
}

func (writer *homedirTrackingWriter) PutIn(
	partition string,
	entry directory.Entry,
	replace bool,
) error {
	return writer.putIn(partition, entry, replace, true)
}

func (writer *homedirTrackingWriter) putIn(
	partition string,
	entry directory.Entry,
	replace bool,
	explicitPartition bool,
) error {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	tracked, err := writer.track(partition, dn, explicitPartition)
	if err != nil {
		return err
	}
	if explicitPartition {
		err = writer.Writer.PutIn(partition, entry, replace)
	} else {
		err = writer.Writer.Put(entry, replace)
	}
	if err != nil {
		return err
	}
	after := entry.Clone()
	tracked.after = &after
	return nil
}

func (writer *homedirTrackingWriter) Delete(dn directory.DN) error {
	partition, err := homedirEntryPartition(writer.Writer, writer.runtime, dn)
	if err != nil {
		return err
	}
	tracked, err := writer.track(partition, dn, true)
	if err != nil {
		return err
	}
	if err := homedirWriterForPartition(
		writer.Writer,
		writer.runtime,
		partition,
	).Delete(dn); err != nil {
		return err
	}
	tracked.after = nil
	return nil
}

func (writer *homedirTrackingWriter) DeleteIn(partition string, dn directory.DN) error {
	tracked, err := writer.track(partition, dn, true)
	if err != nil {
		return err
	}
	if err := homedirWriterForPartition(
		writer.Writer,
		writer.runtime,
		partition,
	).Delete(dn); err != nil {
		return err
	}
	tracked.after = nil
	return nil
}

func (writer *homedirTrackingWriter) Clear() error {
	if err := writer.Writer.ForEachPartition(func(partition string, entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		tracked, err := writer.track(partition, dn, true)
		if err != nil {
			return err
		}
		tracked.after = nil
		return nil
	}); err != nil {
		return err
	}
	return writer.Writer.Clear()
}

func (writer *homedirTrackingWriter) track(
	partition string,
	dn directory.DN,
	explicitPartition bool,
) (*homedirTrackedEntry, error) {
	if !explicitPartition {
		resolved, err := homedirEntryPartition(writer.Writer, writer.runtime, dn)
		switch {
		case err == nil:
			partition = resolved
			explicitPartition = true
		case errors.Is(err, storage.ErrEntryNotFound):
		case err != nil:
			return nil, err
		}
	}
	normalizedDN, err := homedirNormalizeDN(writer.runtime, partition, dn)
	if err != nil {
		return nil, err
	}
	key := partition + "\x00" + normalizedDN.Key()
	if tracked := writer.tracked[key]; tracked != nil {
		return tracked, nil
	}
	var beforeEntry directory.Entry
	if explicitPartition {
		beforeEntry, err = homedirReaderForPartition(
			writer.Writer,
			writer.runtime,
			partition,
		).Get(normalizedDN)
	} else {
		beforeEntry, err = writer.Writer.Get(normalizedDN)
	}
	tracked := &homedirTrackedEntry{partition: partition, dn: normalizedDN}
	if err == nil {
		before := beforeEntry.Clone()
		after := beforeEntry.Clone()
		tracked.before = &before
		tracked.after = &after
	} else if !errors.Is(err, storage.ErrEntryNotFound) {
		return nil, err
	}
	writer.tracked[key] = tracked
	return tracked, nil
}

func (writer *homedirTrackingWriter) changes() []homedirStorageChange {
	keys := make([]string, 0, len(writer.tracked))
	for key := range writer.tracked {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	changes := make([]homedirStorageChange, 0, len(keys))
	for _, key := range keys {
		tracked := writer.tracked[key]
		changes = append(changes, homedirStorageChange{
			partition: tracked.partition,
			before:    cloneHomedirEntry(tracked.before),
			after:     cloneHomedirEntry(tracked.after),
		})
	}
	return changes
}

func homedirNormalizeDN(
	runtime *runtimeState,
	partition string,
	dn directory.DN,
) (directory.DN, error) {
	database := runtimeDatabaseForPartition(runtime, partition)
	if database == nil || database.dnNormalizer == nil {
		return dn, nil
	}
	return normalizeRuntimeDatabaseDN(*database, dn)
}

func homedirReaderForPartition(
	reader storage.Reader,
	runtime *runtimeState,
	partition string,
) storage.Reader {
	database := runtimeDatabaseForPartition(runtime, partition)
	if database != nil && database.dnNormalizer != nil &&
		databaseUsesSchemaAwareContentStorage(*database) {
		return storage.ReaderInPartitionWithNormalizer(
			reader,
			partition,
			database.dnNormalizer,
		)
	}
	return storage.ReaderInPartition(reader, partition)
}

func homedirWriterForPartition(
	writer storage.Writer,
	runtime *runtimeState,
	partition string,
) storage.Writer {
	database := runtimeDatabaseForPartition(runtime, partition)
	if database != nil && database.dnNormalizer != nil &&
		databaseUsesSchemaAwareContentStorage(*database) {
		return storage.WriterInPartitionWithNormalizer(
			writer,
			partition,
			database.dnNormalizer,
		)
	}
	return storage.WriterInPartition(writer, partition)
}

func homedirEntryPartition(
	reader storage.Reader,
	runtime *runtimeState,
	dn directory.DN,
) (string, error) {
	partition := ""
	found := false
	err := reader.ForEachPartition(func(candidatePartition string, entry directory.Entry) error {
		candidate, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		database := runtimeDatabaseForPartition(runtime, candidatePartition)
		matches := candidate.Equal(dn)
		if database != nil {
			matches = databaseDNEqual(*database, candidate, dn)
		}
		if !matches {
			return nil
		}
		if found && partition != candidatePartition {
			return storage.ErrEntryAmbiguous
		}
		partition = candidatePartition
		found = true
		return nil
	})
	if err != nil {
		return "", err
	}
	if !found {
		return "", storage.ErrEntryNotFound
	}
	return partition, nil
}

type homedirStorageChange struct {
	partition string
	before    *directory.Entry
	after     *directory.Entry
}

func cloneHomedirEntry(entry *directory.Entry) *directory.Entry {
	if entry == nil {
		return nil
	}
	cloned := entry.Clone()
	return &cloned
}

func (server *Server) applyHomedirStorageChanges(
	runtime *runtimeState,
	changes []homedirStorageChange,
) {
	if runtime == nil || len(changes) == 0 {
		return
	}
	server.homedirMu.Lock()
	defer server.homedirMu.Unlock()

	removed := make(map[string]int)
	added := make(map[string]int)
	consumed := make([]bool, len(changes))
	for index := range changes {
		change := &changes[index]
		switch {
		case change.before != nil && change.after == nil:
			if identity := homedirEntryIdentity(change.partition, *change.before); identity != "" {
				removed[identity] = index
			}
		case change.before == nil && change.after != nil:
			if identity := homedirEntryIdentity(change.partition, *change.after); identity != "" {
				added[identity] = index
			}
		}
	}
	for identity, removedIndex := range removed {
		addedIndex, found := added[identity]
		if !found {
			continue
		}
		before := changes[removedIndex].before
		after := changes[addedIndex].after
		server.applyHomedirChange(runtime, changes[removedIndex].partition, before, after)
		consumed[removedIndex] = true
		consumed[addedIndex] = true
	}
	for index := range changes {
		if consumed[index] {
			continue
		}
		change := changes[index]
		server.applyHomedirChange(runtime, change.partition, change.before, change.after)
	}
}

func homedirEntryIdentity(partition string, entry directory.Entry) string {
	values := entry.Values("entryUUID")
	if len(values) != 1 || len(values[0]) == 0 {
		return ""
	}
	return partition + "\x00" + strings.ToLower(string(values[0]))
}

func (server *Server) applyHomedirChange(
	runtime *runtimeState,
	partition string,
	before *directory.Entry,
	after *directory.Entry,
) {
	entry := after
	if entry == nil {
		entry = before
	}
	if entry == nil {
		return
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil || isConfigurationDN(dn) || isSubschemaDN(dn) {
		return
	}
	for _, configuration := range homedirConfigurationsForEntry(runtime, partition, dn) {
		server.applyHomedirTransition(configuration, before, after)
	}
}

func homedirConfigurationsForEntry(
	runtime *runtimeState,
	partition string,
	dn directory.DN,
) []homedirRuntimeConfiguration {
	var configurations []homedirRuntimeConfiguration
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if database.homedir == nil {
			continue
		}
		if databaseType(database.name) == "frontend" {
			configurations = append(configurations, *database.homedir)
			continue
		}
		if database.partition != partition ||
			isConfigDatabase(*database) ||
			isMonitorDatabase(*database) ||
			isNullDatabase(*database) {
			continue
		}
		for _, suffix := range database.suffixes {
			if databaseDNAtOrBelow(*database, dn, suffix) {
				configurations = append(configurations, *database.homedir)
				break
			}
		}
	}
	return configurations
}
