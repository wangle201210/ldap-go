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

type CheckReport struct {
	Entries    int
	Partitions []string
	Metadata   int
	FileSize   int64
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
	if err := validateDistinctMaintenancePaths(databasePath, backupPath); err != nil {
		return CheckReport{}, err
	}
	if err := requireReplacePermission(backupPath, replace); err != nil {
		return CheckReport{}, err
	}
	database, err := openBoltReadOnly(databasePath)
	if err != nil {
		return CheckReport{}, err
	}
	defer database.Close()

	report, err := checkBoltDatabase(ctx, database, nil)
	if err != nil {
		return CheckReport{}, fmt.Errorf("check source database: %w", err)
	}
	err = writeAtomicDatabaseFile(ctx, backupPath, replace, func(file *os.File) error {
		return database.View(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := tx.WriteTo(file)
			return err
		})
	}, func(path string) error {
		_, err := CheckBolt(ctx, path)
		return err
	})
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
	if err := validateDistinctMaintenancePaths(backupPath, databasePath); err != nil {
		return CheckReport{}, err
	}
	if err := requireReplacePermission(databasePath, replace); err != nil {
		return CheckReport{}, err
	}
	_, err := CheckBolt(ctx, backupPath)
	if err != nil {
		return CheckReport{}, fmt.Errorf("backup is invalid: %w", err)
	}

	err = writeAtomicDatabaseFile(ctx, databasePath, replace, func(destination *os.File) error {
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
		_, err := CheckBolt(ctx, path)
		return err
	})
	if err != nil {
		return CheckReport{}, fmt.Errorf("restore backup: %w", err)
	}
	verified, err := CheckBolt(ctx, databasePath)
	if err != nil {
		return CheckReport{}, fmt.Errorf("verify restored database: %w", err)
	}
	return verified, nil
}

func RebuildBolt(ctx context.Context, databasePath string) (CheckReport, error) {
	if databasePath == "" {
		return CheckReport{}, errors.New("database path is required")
	}
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
		return metadata.ForEach(func(key, value []byte) error {
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
		})
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

func writeAtomicDatabaseFile(
	ctx context.Context,
	path string,
	replace bool,
	write func(*os.File) error,
	validate func(string) error,
) error {
	directoryPath := filepath.Dir(path)
	if err := os.MkdirAll(directoryPath, 0o700); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}
	temporary, err := os.CreateTemp(directoryPath, ".ldap-go-database-*")
	if err != nil {
		return fmt.Errorf("create temporary database: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary database: %w", err)
	}
	writeErr := write(temporary)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
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
		if err := os.Rename(temporaryPath, path); err != nil {
			return fmt.Errorf("publish database: %w", err)
		}
	} else {
		if err := os.Link(temporaryPath, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("destination %q already exists; use --replace", path)
			}
			return fmt.Errorf("publish database: %w", err)
		}
		if err := os.Remove(temporaryPath); err != nil {
			return fmt.Errorf("remove temporary database link: %w", err)
		}
	}
	return syncDirectory(directoryPath)
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
