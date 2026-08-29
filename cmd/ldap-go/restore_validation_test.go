package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
	bolt "go.etcd.io/bbolt"
)

func TestRestoreBoltValidatedPublishesCheckedCandidate(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	databasePath := filepath.Join(directoryPath, "directory.db")
	seedRestoreValidationDatabase(t, backupPath, restoreValidationSeed{state: "backup", index: true})
	seedRestoreValidationDatabase(t, databasePath, restoreValidationSeed{state: "target"})

	report, err := restoreBoltValidated(
		context.Background(),
		backupPath,
		databasePath,
		true,
	)
	if err != nil {
		t.Fatalf("restoreBoltValidated(): %v", err)
	}
	if report.Entries != 4 || report.EqualityIndexConfigs != 1 ||
		report.EqualityIndexPostings == 0 {
		t.Fatalf("restore report = %#v", report)
	}
	if got := restoreValidationState(t, databasePath); got != "backup" {
		t.Fatalf("restored state = %q, want backup", got)
	}
	assertNoRestoreValidationStaging(t, directoryPath)
}

func TestRestoreBoltValidatedRejectsStagingMutationAfterInitialValidation(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	databasePath := filepath.Join(directoryPath, "directory.db")
	seedRestoreValidationDatabase(t, backupPath, restoreValidationSeed{state: "backup"})
	seedRestoreValidationDatabase(t, databasePath, restoreValidationSeed{state: "target"})
	before := restoreValidationFileDigest(t, databasePath)

	_, err := restoreBoltValidatedWithHooks(
		context.Background(),
		backupPath,
		databasePath,
		true,
		restoreValidationHooks{
			afterInitialValidation: func(stagingPath string) (runErr error) {
				store, err := storage.OpenBolt(stagingPath)
				if err != nil {
					return err
				}
				defer func() { runErr = errors.Join(runErr, store.Close()) }()
				return store.Update(context.Background(), func(writer storage.Writer) error {
					return writer.PutIn("orphan-after-validation", directory.Entry{
						DN: "ou=orphan,dc=invalid",
						Attributes: []directory.Attribute{
							{
								Description: "objectClass",
								Values:      restoreValidationValues("organizationalUnit"),
							},
							{
								Description: "ou",
								Values:      restoreValidationValues("orphan"),
							},
						},
					}, false)
				})
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "orphan storage partition") {
		t.Fatalf(
			"restoreBoltValidatedWithHooks() error = %v, want orphan partition refusal",
			err,
		)
	}
	if got := restoreValidationState(t, databasePath); got != "target" {
		t.Fatalf("target state = %q after refusal, want target", got)
	}
	if after := restoreValidationFileDigest(t, databasePath); after != before {
		t.Fatal("failed final semantic validation changed destination bytes")
	}
	assertNoRestoreValidationStaging(t, directoryPath)
}

func TestRestoreBoltValidatedRejectsCandidateBeforePublication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		seed    restoreValidationSeed
		corrupt func(*testing.T, string)
		message string
	}{
		{
			name:    "runtime configuration",
			seed:    restoreValidationSeed{state: "backup", invalidRuntime: true},
			message: "runtime configuration",
		},
		{
			name:    "entry schema",
			seed:    restoreValidationSeed{state: "backup", invalidEntry: true},
			message: "directory schema",
		},
		{
			name:    "orphan storage partition",
			seed:    restoreValidationSeed{state: "backup", orphanPartition: true},
			message: "orphan storage partition",
		},
		{
			name: "metadata",
			seed: restoreValidationSeed{state: "backup"},
			corrupt: func(t *testing.T, path string) {
				mutateRestoreValidationBolt(t, path, func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("metadata")).Put(
						[]byte("unrecognized-raw-key"),
						[]byte("invalid"),
					)
				})
			},
			message: "unknown metadata key",
		},
		{
			name: "missing index posting",
			seed: restoreValidationSeed{state: "backup", index: true},
			corrupt: func(t *testing.T, path string) {
				mutateRestoreValidationBolt(t, path, func(tx *bolt.Tx) error {
					bucket := tx.Bucket([]byte("indexes:eq"))
					key, _ := bucket.Cursor().First()
					if key == nil {
						t.Fatal("indexed fixture has no posting")
					}
					return bucket.Delete(key)
				})
			},
			message: "missing posting",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			directoryPath := t.TempDir()
			backupPath := filepath.Join(directoryPath, "backup.db")
			databasePath := filepath.Join(directoryPath, "directory.db")
			seedRestoreValidationDatabase(t, backupPath, test.seed)
			if test.corrupt != nil {
				test.corrupt(t, backupPath)
			}
			seedRestoreValidationDatabase(
				t,
				databasePath,
				restoreValidationSeed{state: "target"},
			)
			before := restoreValidationFileDigest(t, databasePath)

			_, err := restoreBoltValidated(
				context.Background(),
				backupPath,
				databasePath,
				true,
			)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf(
					"restoreBoltValidated() error = %v, want containing %q",
					err,
					test.message,
				)
			}
			if got := restoreValidationState(t, databasePath); got != "target" {
				t.Fatalf("target state = %q after refusal, want target", got)
			}
			if after := restoreValidationFileDigest(t, databasePath); after != before {
				t.Fatal("failed restore changed destination database bytes")
			}
			assertNoRestoreValidationStaging(t, directoryPath)
		})
	}
}

func TestRestoreBoltValidatedPreservesRestoreContracts(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	databasePath := filepath.Join(directoryPath, "directory.db")
	seedRestoreValidationDatabase(t, backupPath, restoreValidationSeed{state: "backup"})
	seedRestoreValidationDatabase(t, databasePath, restoreValidationSeed{state: "target"})
	before := restoreValidationFileDigest(t, databasePath)

	if _, err := restoreBoltValidated(
		context.Background(), backupPath, databasePath, false,
	); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("restore without replace error = %v", err)
	}
	if after := restoreValidationFileDigest(t, databasePath); after != before {
		t.Fatal("restore without replace changed destination")
	}

	if _, err := restoreBoltValidated(
		context.Background(), backupPath, backupPath, true,
	); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("same source and destination error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := restoreBoltValidated(ctx, backupPath, databasePath, true); err == nil ||
		!strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("canceled restore error = %v", err)
	}
	if after := restoreValidationFileDigest(t, databasePath); after != before {
		t.Fatal("canceled restore changed destination")
	}
	assertNoRestoreValidationStaging(t, directoryPath)
}

func TestRestoreBoltValidatedInvalidCandidateDoesNotCreateDestination(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	databasePath := filepath.Join(directoryPath, "missing", "directory.db")
	seedRestoreValidationDatabase(
		t,
		backupPath,
		restoreValidationSeed{state: "backup", invalidEntry: true},
	)

	if _, err := restoreBoltValidated(
		context.Background(), backupPath, databasePath, false,
	); err == nil || !strings.Contains(err.Error(), "directory schema") {
		t.Fatalf("invalid restore error = %v", err)
	}
	if _, err := os.Lstat(databasePath); !os.IsNotExist(err) {
		t.Fatalf("invalid restore destination stat error = %v, want not exist", err)
	}
	assertNoRestoreValidationStaging(t, filepath.Dir(databasePath))
}

func TestRestoreBoltValidatedAcceptsBootstrapDatabase(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "bootstrap.db")
	databasePath := filepath.Join(directoryPath, "restored.db")
	seedMaintenanceCommandDatabase(t, backupPath, "bootstrap")

	if _, err := restoreBoltValidated(
		context.Background(), backupPath, databasePath, false,
	); err != nil {
		t.Fatalf("restore bootstrap database: %v", err)
	}
	store, err := storage.OpenBoltReadOnly(databasePath)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(restored): %v", err)
	}
	contextDN, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		_ = store.Close()
		t.Fatalf("ParseDN(): %v", err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.GetIn(storage.OpenLDAPBootstrapPartition(contextDN), contextDN)
		return err
	})
	if closeErr := store.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("read restored bootstrap entry: %v", err)
	}
}

type restoreValidationSeed struct {
	state           string
	index           bool
	invalidRuntime  bool
	invalidEntry    bool
	orphanPartition bool
}

func seedRestoreValidationDatabase(
	t *testing.T,
	path string,
	seed restoreValidationSeed,
) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(%q): %v", path, err)
	}
	databaseAttributes := []directory.Attribute{
		{Description: "olcDatabase", Values: restoreValidationValues("{1}mdb")},
		{Description: "olcSuffix", Values: restoreValidationValues("dc=example,dc=com")},
	}
	if seed.index {
		databaseAttributes = append(databaseAttributes, directory.Attribute{
			Description: "olcDbIndex",
			Values:      restoreValidationValues("uid eq,pres"),
		})
	}
	globalAttributes := []directory.Attribute{
		{Description: "objectClass", Values: restoreValidationValues("olcGlobal")},
		{Description: "cn", Values: restoreValidationValues("config")},
	}
	if seed.invalidRuntime {
		globalAttributes = append(globalAttributes, directory.Attribute{
			Description: "olcSaslSecProps",
			Values:      restoreValidationValues("minssf=invalid"),
		})
	}
	personAttributes := []directory.Attribute{
		{
			Description: "objectClass",
			Values: restoreValidationValues(
				"top", "person", "organizationalPerson", "inetOrgPerson",
			),
		},
		{Description: "structuralObjectClass", Values: restoreValidationValues("inetOrgPerson")},
		{Description: "uid", Values: restoreValidationValues("alice")},
		{Description: "cn", Values: restoreValidationValues("Alice")},
	}
	if !seed.invalidEntry {
		personAttributes = append(personAttributes, directory.Attribute{
			Description: "sn",
			Values:      restoreValidationValues("Example"),
		})
	}
	dataPartition := storage.OpenLDAPDatabasePartition("{1}mdb", nil)
	if seed.orphanPartition {
		dataPartition = "orphan-partition"
	}
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []struct {
			partition string
			entry     directory.Entry
		}{
			{
				partition: storage.OpenLDAPConfigPartition,
				entry: directory.Entry{
					DN: "cn=config", Attributes: globalAttributes,
				},
			},
			{
				partition: storage.OpenLDAPConfigPartition,
				entry: directory.Entry{
					DN: "olcDatabase={1}mdb,cn=config", Attributes: databaseAttributes,
				},
			},
			{
				partition: dataPartition,
				entry: directory.Entry{
					DN: "dc=example,dc=com",
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: restoreValidationValues("top", "domain")},
						{Description: "structuralObjectClass", Values: restoreValidationValues("domain")},
						{Description: "dc", Values: restoreValidationValues("example")},
					},
				},
			},
			{
				partition: dataPartition,
				entry: directory.Entry{
					DN: "uid=alice,dc=example,dc=com", Attributes: personAttributes,
				},
			},
		}
		for _, candidate := range entries {
			if err := writer.PutIn(candidate.partition, candidate.entry, false); err != nil {
				return err
			}
		}
		if err := writer.SetNamingContexts([]string{"dc=example,dc=com"}); err != nil {
			return err
		}
		return writer.SetMetadata("restore-validation-state", []byte(seed.state))
	})
	if err == nil && seed.index {
		_, err = server.ReindexOffline(context.Background(), store, "{1}mdb", false)
	}
	if closeErr := store.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("seed restore validation database %q: %v", path, err)
	}
}

func mutateRestoreValidationBolt(
	t *testing.T,
	path string,
	mutate func(*bolt.Tx) error,
) {
	t.Helper()
	database, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("open raw bbolt %q: %v", path, err)
	}
	if err := database.Update(mutate); err != nil {
		_ = database.Close()
		t.Fatalf("mutate raw bbolt %q: %v", path, err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close raw bbolt %q: %v", path, err)
	}
}

func restoreValidationState(t *testing.T, path string) string {
	t.Helper()
	store, err := storage.OpenBoltReadOnly(path)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(%q): %v", path, err)
	}
	var state []byte
	err = store.View(context.Background(), func(reader storage.Reader) error {
		var readErr error
		state, readErr = reader.Metadata("restore-validation-state")
		return readErr
	})
	if closeErr := store.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("read restore state %q: %v", path, err)
	}
	return string(state)
}

func restoreValidationFileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return sha256.Sum256(contents)
}

func assertNoRestoreValidationStaging(t *testing.T, directoryPath string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(
		directoryPath,
		".ldap-go-restore-validation-*",
	))
	if err != nil {
		t.Fatalf("glob restore staging directories: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("restore staging directories remain: %v", matches)
	}
}

func restoreValidationValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}
