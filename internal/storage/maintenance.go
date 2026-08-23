package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

const maintenanceTransactionSize = 64 << 20

var ErrRestoreRequiresOffline = errors.New("restore requires an offline database")

// PublicationDurabilityError means the complete database file was atomically
// published, but syncing its parent directory failed. The new file is visible;
// only its survival across an immediate system crash is uncertain.
type PublicationDurabilityError struct {
	Path string
	Err  error
}

func (err *PublicationDurabilityError) Error() string {
	return fmt.Sprintf(
		"database %q was published but directory durability is not confirmed: %v",
		err.Path,
		err.Err,
	)
}

func (err *PublicationDurabilityError) Unwrap() error { return err.Err }

type atomicDatabaseFileSystem interface {
	createTemp(string, string) (*os.File, error)
	chmod(string, os.FileMode) error
	syncFile(*os.File) error
	closeFile(*os.File) error
	rename(string, string) error
	link(string, string) error
	remove(string) error
	syncDirectory(string) error
}

type osFileSystem struct{}

func (osFileSystem) createTemp(directory, pattern string) (*os.File, error) {
	return os.CreateTemp(directory, pattern)
}

func (osFileSystem) chmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }
func (osFileSystem) syncFile(file *os.File) error              { return file.Sync() }
func (osFileSystem) closeFile(file *os.File) error             { return file.Close() }
func (osFileSystem) rename(oldPath, newPath string) error      { return os.Rename(oldPath, newPath) }
func (osFileSystem) link(oldPath, newPath string) error        { return os.Link(oldPath, newPath) }
func (osFileSystem) remove(path string) error                  { return os.Remove(path) }
func (osFileSystem) syncDirectory(path string) error           { return syncDirectory(path) }

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer contextWriter) Write(value []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	written, err := writer.writer.Write(value)
	if err != nil {
		return written, err
	}
	if contextErr := writer.ctx.Err(); contextErr != nil {
		return written, contextErr
	}
	return written, nil
}

type CheckReport struct {
	Entries               int
	Partitions            []string
	Metadata              int
	EqualityIndexConfigs  int
	EqualityIndexPostings int
	FileSize              int64
}

func CheckBolt(ctx context.Context, path string) (CheckReport, error) {
	return CheckBoltWithNormalizer(ctx, path, nil)
}

// CheckBoltWithNormalizer additionally verifies schema-aware physical keys and
// detects legacy/v2 duplicates using the supplied matching rules. CheckBolt
// without a normalizer remains conservative: it validates every key binding,
// but cannot infer whether legacy values used caseExact or caseIgnore rules.
func CheckBoltWithNormalizer(
	ctx context.Context,
	path string,
	normalizer directory.DNAttributeNormalizer,
) (CheckReport, error) {
	if path == "" {
		return CheckReport{}, errors.New("database path is required")
	}
	database, err := openBoltReadOnly(path)
	if err != nil {
		return CheckReport{}, err
	}
	defer database.Close()

	report, err := checkBoltDatabase(ctx, database, normalizer)
	if err != nil {
		return CheckReport{}, fmt.Errorf("check database %q: %w", path, err)
	}
	if info, statErr := os.Stat(path); statErr == nil {
		report.FileSize = info.Size()
	}
	return report, nil
}

func BackupBolt(
	ctx context.Context,
	databasePath,
	backupPath string,
	replace bool,
) (CheckReport, error) {
	pathLock, err := acquireBoltPathLock(databasePath, false)
	if err != nil {
		return CheckReport{}, fmt.Errorf("lock backup source: %w", err)
	}
	defer pathLock.Close()
	database, err := openBoltReadOnly(databasePath)
	if err != nil {
		return CheckReport{}, err
	}
	defer database.Close()
	return backupOpenBolt(ctx, database, backupPath, replace, osFileSystem{})
}

func backupOpenBolt(
	ctx context.Context,
	database *bolt.DB,
	backupPath string,
	replace bool,
	filesystem atomicDatabaseFileSystem,
) (CheckReport, error) {
	return backupOpenBoltWithSnapshotHook(
		ctx,
		database,
		backupPath,
		replace,
		filesystem,
		nil,
	)
}

func backupOpenBoltWithSnapshotHook(
	ctx context.Context,
	database *bolt.DB,
	backupPath string,
	replace bool,
	filesystem atomicDatabaseFileSystem,
	snapshotReady func(),
) (CheckReport, error) {
	if err := ctx.Err(); err != nil {
		return CheckReport{}, err
	}
	if database == nil {
		return CheckReport{}, errors.New("database is not open")
	}
	if err := validateDistinctMaintenancePaths(database.Path(), backupPath); err != nil {
		return CheckReport{}, err
	}
	if err := requireReplacePermission(backupPath, replace); err != nil {
		return CheckReport{}, err
	}
	var report CheckReport
	err := writeAtomicDatabaseFileWithFS(ctx, backupPath, replace, func(file *os.File) error {
		return database.View(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if snapshotReady != nil {
				snapshotReady()
			}
			_, err := tx.WriteTo(contextWriter{ctx: ctx, writer: file})
			if err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		})
	}, func(path string) error {
		var err error
		report, err = CheckBolt(ctx, path)
		return err
	}, filesystem)
	if err != nil {
		return CheckReport{}, fmt.Errorf("write backup: %w", err)
	}
	if info, statErr := os.Stat(backupPath); statErr == nil {
		report.FileSize = info.Size()
	}
	return report, nil
}

func RestoreBolt(
	ctx context.Context,
	backupPath,
	databasePath string,
	replace bool,
) (CheckReport, error) {
	return restoreBoltWithFS(ctx, backupPath, databasePath, replace, osFileSystem{})
}

func restoreBoltWithFS(
	ctx context.Context,
	backupPath,
	databasePath string,
	replace bool,
	filesystem atomicDatabaseFileSystem,
) (CheckReport, error) {
	if err := ctx.Err(); err != nil {
		return CheckReport{}, err
	}
	if err := validateDistinctMaintenancePaths(backupPath, databasePath); err != nil {
		return CheckReport{}, err
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		return CheckReport{}, fmt.Errorf("create database directory: %w", err)
	}
	offlineLock, err := lockOfflineBoltDestination(databasePath)
	if err != nil {
		return CheckReport{}, err
	}
	defer offlineLock.Close()
	if err := requireReplacePermission(databasePath, replace); err != nil {
		return CheckReport{}, err
	}
	_, err = CheckBolt(ctx, backupPath)
	if err != nil {
		return CheckReport{}, fmt.Errorf("backup is invalid: %w", err)
	}

	var verified CheckReport
	err = writeAtomicDatabaseFileWithFS(ctx, databasePath, replace, func(destination *os.File) error {
		source, err := os.Open(backupPath)
		if err != nil {
			return err
		}
		defer source.Close()
		if _, err := copyWithContext(ctx, destination, source); err != nil {
			return err
		}
		return nil
	}, func(path string) error {
		var err error
		verified, err = CheckBolt(ctx, path)
		return err
	}, filesystem)
	if err != nil {
		return CheckReport{}, fmt.Errorf("restore backup: %w", err)
	}
	if info, statErr := os.Stat(databasePath); statErr == nil {
		verified.FileSize = info.Size()
	}
	return verified, nil
}

type restoreDestinationLock struct {
	pathLock *boltPathLock
}

func (lock *restoreDestinationLock) Close() error {
	if lock == nil {
		return nil
	}
	return lock.pathLock.Close()
}

func lockOfflineBoltDestination(path string) (*restoreDestinationLock, error) {
	pathLock, err := acquireBoltPathLock(path, true)
	if errors.Is(err, errBoltPathLockBusy) {
		return nil, fmt.Errorf("%w: %q is open", ErrRestoreRequiresOffline, path)
	}
	if err != nil {
		return nil, fmt.Errorf("lock restore destination %q: %w", path, err)
	}
	lock := &restoreDestinationLock{pathLock: pathLock}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return lock, nil
	} else if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("inspect restore destination: %w", err)
	}
	if info.Size() == 0 {
		return lock, nil
	}
	database, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Millisecond})
	if errors.Is(err, bolt.ErrTimeout) {
		_ = lock.Close()
		return nil, fmt.Errorf("%w: %q is open", ErrRestoreRequiresOffline, path)
	}
	if err != nil {
		// A sidecar-exclusive path with an unreadable bbolt file is offline and
		// is exactly the case a validated backup must be allowed to replace.
		return lock, nil
	}
	if err := database.Close(); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("close restore destination probe %q: %w", path, err)
	}
	return lock, nil
}

func RebuildBolt(ctx context.Context, databasePath string) (CheckReport, error) {
	if databasePath == "" {
		return CheckReport{}, errors.New("database path is required")
	}
	pathLock, err := acquireBoltPathLock(databasePath, true)
	if err != nil {
		return CheckReport{}, fmt.Errorf("lock rebuild database: %w", err)
	}
	defer pathLock.Close()
	source, err := openBoltReadOnly(databasePath)
	if err != nil {
		return CheckReport{}, err
	}
	sourceOpen := true
	defer func() {
		if sourceOpen {
			_ = source.Close()
		}
	}()
	if _, err := checkBoltDatabase(ctx, source, nil); err != nil {
		return CheckReport{}, fmt.Errorf("check source database: %w", err)
	}

	directoryPath := filepath.Dir(databasePath)
	if err := os.MkdirAll(directoryPath, 0o700); err != nil {
		return CheckReport{}, fmt.Errorf("create database directory: %w", err)
	}
	temporary, err := os.CreateTemp(directoryPath, ".ldap-go-rebuild-*")
	if err != nil {
		return CheckReport{}, fmt.Errorf("create rebuild database: %w", err)
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return CheckReport{}, fmt.Errorf("close rebuild placeholder: %w", err)
	}
	defer os.Remove(temporaryPath)
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return CheckReport{}, fmt.Errorf("secure rebuild database: %w", err)
	}

	destination, err := bolt.Open(temporaryPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return CheckReport{}, fmt.Errorf("open rebuild database: %w", err)
	}
	compactErr := bolt.Compact(destination, source, maintenanceTransactionSize)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if compactErr != nil {
		return CheckReport{}, fmt.Errorf("rebuild database: %w", compactErr)
	}
	if syncErr != nil {
		return CheckReport{}, fmt.Errorf("sync rebuilt database: %w", syncErr)
	}
	if closeErr != nil {
		return CheckReport{}, fmt.Errorf("close rebuilt database: %w", closeErr)
	}
	if _, err := CheckBolt(ctx, temporaryPath); err != nil {
		return CheckReport{}, fmt.Errorf("verify rebuilt database: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return CheckReport{}, err
	}
	if err := source.Close(); err != nil {
		return CheckReport{}, fmt.Errorf("close source database: %w", err)
	}
	sourceOpen = false
	if err := os.Rename(temporaryPath, databasePath); err != nil {
		return CheckReport{}, fmt.Errorf("publish rebuilt database: %w", err)
	}
	if err := syncDirectory(directoryPath); err != nil {
		return CheckReport{}, err
	}
	return CheckBolt(ctx, databasePath)
}

func openBoltReadOnly(path string) (*bolt.DB, error) {
	database, err := bolt.Open(path, 0o600, &bolt.Options{
		ReadOnly: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", path, err)
	}
	return database, nil
}

func checkBoltDatabase(
	ctx context.Context,
	database *bolt.DB,
	normalizer directory.DNAttributeNormalizer,
) (CheckReport, error) {
	var report CheckReport
	partitions := make(map[string]struct{})
	err := database.View(func(tx *bolt.Tx) error {
		var physicalErr error
		for checkErr := range tx.Check() {
			if physicalErr == nil && checkErr != nil {
				physicalErr = checkErr
			}
		}
		if physicalErr != nil {
			return physicalErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries := tx.Bucket(entriesBucket)
		metadata := tx.Bucket(metaBucket)
		if entries == nil || metadata == nil {
			return errors.New("required entries or metadata bucket is missing")
		}
		logicalEntries := make(map[string]string)
		if err := entries.ForEach(func(key, value []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if value == nil {
				return fmt.Errorf("entries bucket contains nested bucket %q", key)
			}
			partition, keyDN := splitPartitionedEntryKey(string(key))
			stored, err := decodeStoredEntry(value)
			if err != nil {
				return fmt.Errorf("entry key %q: %w", key, err)
			}
			entry := stored.Entry
			if _, err := directory.ParseDN(entry.DN); err != nil {
				return fmt.Errorf("entry key %q has invalid DN %q: %w", key, entry.DN, err)
			}
			if err := validateStoredEntryIdentity(
				keyDN,
				entry,
				stored.DNIdentity,
				stored.DNSource,
			); err != nil {
				return fmt.Errorf(
					"entry key %q does not match DN %q: %w",
					key,
					entry.DN,
					err,
				)
			}
			logicalIdentity := keyDN
			if normalizer != nil && partition != OpenLDAPConfigPartition {
				normalized, err := directory.ParseDNWithNormalizer(entry.DN, normalizer)
				if err != nil {
					return fmt.Errorf(
						"entry key %q cannot normalize DN %q: %w",
						key,
						entry.DN,
						err,
					)
				}
				logicalIdentity = normalized.Key()
				if isSchemaAwareDNKey(keyDN) && keyDN != logicalIdentity {
					return fmt.Errorf(
						"entry key %q does not match schema-normalized DN %q",
						key,
						entry.DN,
					)
				}
			}
			logicalKey := partitionedEntryKey(partition, logicalIdentity)
			if previous, exists := logicalEntries[logicalKey]; exists {
				return fmt.Errorf(
					"entry keys %q and %q identify the same partition and DN",
					previous,
					key,
				)
			}
			logicalEntries[logicalKey] = string(key)
			partitions[partition] = struct{}{}
			report.Entries++
			return nil
		}); err != nil {
			return err
		}
		namingContexts := make(map[string]string)
		if err := metadata.ForEach(func(key, value []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if value == nil {
				return fmt.Errorf("metadata bucket contains nested bucket %q", key)
			}
			report.Metadata++
			if bytes.Equal(key, contextsKey) {
				var contexts []string
				if err := json.Unmarshal(value, &contexts); err != nil {
					return fmt.Errorf("decode naming contexts: %w", err)
				}
				for _, contextDN := range contexts {
					dn, err := directory.ParseDN(contextDN)
					if err != nil {
						return fmt.Errorf("invalid naming context %q: %w", contextDN, err)
					}
					if previous, exists := namingContexts[dn.Key()]; exists {
						return fmt.Errorf(
							"naming contexts %q and %q are equivalent",
							previous,
							contextDN,
						)
					}
					namingContexts[dn.Key()] = contextDN
				}
				return nil
			}
			if !bytes.HasPrefix(key, metadataPrefix) {
				return fmt.Errorf("unknown metadata key %q", key)
			}
			return nil
		}); err != nil {
			return err
		}
		return checkBoltEqualityIndexes(
			ctx,
			tx,
			normalizer,
			&report,
		)
	})
	if err != nil {
		return CheckReport{}, err
	}
	report.Partitions = make([]string, 0, len(partitions))
	for partition := range partitions {
		report.Partitions = append(report.Partitions, partition)
	}
	sort.Strings(report.Partitions)
	return report, nil
}

func checkBoltEqualityIndexes(
	ctx context.Context,
	tx *bolt.Tx,
	normalizer directory.DNAttributeNormalizer,
	report *CheckReport,
) error {
	configsBucket := tx.Bucket(equalityIndexConfigBucket)
	postingsBucket := tx.Bucket(equalityIndexBucket)
	if configsBucket == nil && postingsBucket == nil {
		return nil
	}
	if configsBucket == nil || postingsBucket == nil {
		return errors.New("equality index config and postings buckets must both exist")
	}
	configs := make(map[string]EqualityIndexConfig)
	if err := configsBucket.ForEach(func(key, value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value == nil {
			return fmt.Errorf("equality index config bucket contains nested bucket %q", key)
		}
		var config EqualityIndexConfig
		if err := json.Unmarshal(value, &config); err != nil {
			return fmt.Errorf("decode equality index config %q: %w", key, err)
		}
		normalized, err := normalizeEqualityIndexConfig(config)
		if err != nil {
			return fmt.Errorf("equality index config %q: %w", key, err)
		}
		configs[string(key)] = normalized
		report.EqualityIndexConfigs++
		return nil
	}); err != nil {
		return err
	}

	actual := make(map[string]struct{})
	if err := postingsBucket.ForEach(func(key, value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value == nil {
			return fmt.Errorf("equality index bucket contains nested bucket %q", key)
		}
		partition, attribute, kind, _, entryKey, err := decodeEqualityIndexPostingKey(key)
		if err != nil {
			return fmt.Errorf("equality index posting %q: %w", key, err)
		}
		config, ok := configs[partition]
		if !ok {
			return fmt.Errorf("equality index posting %q has no partition config", key)
		}
		definition, ok := equalityIndexAttributeDefinition(config, attribute)
		if !ok || !equalityIndexPostingKindConfigured(definition, kind) {
			return fmt.Errorf("equality index posting %q is not enabled by its config", key)
		}
		entryPartition, _ := splitPartitionedEntryKey(entryKey)
		if entryPartition != partition {
			return fmt.Errorf("equality index posting %q crosses partitions", key)
		}
		if tx.Bucket(entriesBucket).Get([]byte(entryKey)) == nil {
			return fmt.Errorf("equality index posting %q references a missing entry", key)
		}
		actual[string(key)] = struct{}{}
		report.EqualityIndexPostings++
		return nil
	}); err != nil {
		return err
	}

	schema, ok := normalizer.(EqualityIndexSchema)
	if !ok {
		return nil
	}
	expected := make(map[string]struct{})
	entries := tx.Bucket(entriesBucket)
	if err := entries.ForEach(func(key, value []byte) error {
		partition, entryKey := splitPartitionedEntryKey(string(key))
		config, configured := configs[partition]
		if !configured {
			return nil
		}
		entry, err := decodeAndValidateEntry(entryKey, value)
		if err != nil {
			return err
		}
		terms, err := equalityIndexEntryTerms(schema, config, entry)
		if err != nil {
			return fmt.Errorf("verify index entry %q: %w", entry.DN, err)
		}
		for _, definition := range config.Attributes {
			for _, term := range equalityIndexTermsForAttribute(definition, terms[definition.Attribute]) {
				expected[string(equalityIndexPostingKey(
					partition,
					definition.Attribute,
					term.kind,
					term.value,
					string(key),
				))] = struct{}{}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for posting := range expected {
		if _, ok := actual[posting]; !ok {
			return fmt.Errorf("equality index is missing posting %x", []byte(posting))
		}
	}
	for posting := range actual {
		if _, ok := expected[posting]; !ok {
			return fmt.Errorf("equality index has stale posting %x", []byte(posting))
		}
	}
	return nil
}

func writeAtomicDatabaseFile(
	ctx context.Context,
	path string,
	replace bool,
	write func(*os.File) error,
	validate func(string) error,
) error {
	return writeAtomicDatabaseFileWithFS(ctx, path, replace, write, validate, osFileSystem{})
}

func writeAtomicDatabaseFileWithFS(
	ctx context.Context,
	path string,
	replace bool,
	write func(*os.File) error,
	validate func(string) error,
	filesystem atomicDatabaseFileSystem,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	directoryPath := filepath.Dir(path)
	if err := os.MkdirAll(directoryPath, 0o700); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}
	temporary, err := filesystem.createTemp(directoryPath, ".ldap-go-database-*")
	if err != nil {
		return fmt.Errorf("create temporary database: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = filesystem.remove(temporaryPath) }()
	if err := filesystem.chmod(temporaryPath, 0o600); err != nil {
		_ = filesystem.closeFile(temporary)
		return fmt.Errorf("secure temporary database: %w", err)
	}
	writeErr := write(temporary)
	if writeErr == nil {
		writeErr = ctx.Err()
	}
	var syncErr error
	if writeErr == nil {
		syncErr = filesystem.syncFile(temporary)
	}
	closeErr := filesystem.closeFile(temporary)
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return fmt.Errorf("sync temporary database: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close temporary database: %w", closeErr)
	}
	if validate != nil {
		if err := validate(temporaryPath); err != nil {
			return fmt.Errorf("validate temporary database: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if replace {
		if err := filesystem.rename(temporaryPath, path); err != nil {
			return fmt.Errorf("publish database: %w", err)
		}
	} else {
		if err := filesystem.link(temporaryPath, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("destination %q already exists; use --replace", path)
			}
			return fmt.Errorf("publish database: %w", err)
		}
		if err := filesystem.remove(temporaryPath); err != nil {
			return fmt.Errorf("remove temporary database link: %w", err)
		}
	}
	if err := filesystem.syncDirectory(directoryPath); err != nil {
		return &PublicationDurabilityError{Path: path, Err: err}
	}
	return nil
}

func copyWithContext(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
) (int64, error) {
	buffer := make([]byte, 128*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

func requireReplacePermission(path string, replace bool) error {
	_, err := os.Lstat(path)
	switch {
	case err == nil && !replace:
		return fmt.Errorf("destination %q already exists; use --replace", path)
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return err
	}
}

func validateDistinctMaintenancePaths(left, right string) error {
	if left == "" || right == "" {
		return errors.New("source and destination paths are required")
	}
	leftPath, err := filepath.Abs(left)
	if err != nil {
		return err
	}
	rightPath, err := filepath.Abs(right)
	if err != nil {
		return err
	}
	if leftPath == rightPath {
		return errors.New("source and destination paths must differ")
	}
	leftInfo, leftErr := os.Stat(leftPath)
	rightInfo, rightErr := os.Stat(rightPath)
	if leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo) {
		return errors.New("source and destination paths identify the same file")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open destination directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync destination directory: %w", err)
	}
	return nil
}
