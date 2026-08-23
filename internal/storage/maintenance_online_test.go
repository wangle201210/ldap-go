package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var errInjectedPublicationFault = errors.New("injected publication fault")

type faultAtomicFileSystem struct {
	osFileSystem
	operation string
}

type hookedAtomicFileSystem struct {
	osFileSystem
	beforeRename func()
}

func (filesystem hookedAtomicFileSystem) rename(oldPath, newPath string) error {
	if filesystem.beforeRename != nil {
		filesystem.beforeRename()
	}
	return filesystem.osFileSystem.rename(oldPath, newPath)
}

func (filesystem faultAtomicFileSystem) syncFile(file *os.File) error {
	if filesystem.operation == "file-fsync" {
		return errInjectedPublicationFault
	}
	return filesystem.osFileSystem.syncFile(file)
}

func (filesystem faultAtomicFileSystem) rename(oldPath, newPath string) error {
	if filesystem.operation == "rename" {
		return errInjectedPublicationFault
	}
	return filesystem.osFileSystem.rename(oldPath, newPath)
}

func (filesystem faultAtomicFileSystem) syncDirectory(path string) error {
	if filesystem.operation == "directory-fsync" {
		return errInjectedPublicationFault
	}
	return filesystem.osFileSystem.syncDirectory(path)
}

func TestBoltOnlineBackupPinsOneCommittedSnapshot(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	databasePath := filepath.Join(directoryPath, "live.db")
	backupPath := filepath.Join(directoryPath, "backup.db")
	store, err := OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer store.Close()

	const partition = "database-one"
	dn := mustMaintenanceDN(t, "uid=state,dc=example,dc=com")
	putGeneration := func(value string) error {
		return store.Update(context.Background(), func(writer Writer) error {
			if err := writer.PutIn(partition, directory.Entry{
				DN: dn.String(),
				Attributes: []directory.Attribute{
					{Description: "cn", Values: [][]byte{[]byte(value)}},
				},
			}, true); err != nil {
				return err
			}
			return writer.SetMetadata("backup-generation", []byte(value))
		})
	}
	if err := putGeneration("old000"); err != nil {
		t.Fatalf("seed generation: %v", err)
	}

	snapshotReady := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSnapshot) }) }
	defer release()
	backupDone := make(chan error, 1)
	go func() {
		_, backupErr := backupOpenBoltWithSnapshotHook(
			context.Background(),
			store.db,
			backupPath,
			false,
			osFileSystem{},
			func() {
				close(snapshotReady)
				<-releaseSnapshot
			},
		)
		backupDone <- backupErr
	}()

	select {
	case <-snapshotReady:
	case <-time.After(5 * time.Second):
		t.Fatal("online backup did not open its snapshot transaction")
	}
	writeDone := make(chan error, 1)
	writeStarted := make(chan struct{})
	go func() {
		close(writeStarted)
		writeDone <- putGeneration("new000")
	}()
	select {
	case <-writeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent write did not start")
	}
	release()
	if err := <-writeDone; err != nil {
		t.Fatalf("concurrent write: %v", err)
	}
	if err := <-backupDone; err != nil {
		t.Fatalf("online backup: %v", err)
	}

	assertGeneration := func(reader Reader, want string) error {
		entry, err := reader.GetIn(partition, dn)
		if err != nil {
			return err
		}
		if got := string(entry.Attributes[0].Values[0]); got != want {
			t.Fatalf("entry generation = %q, want %q", got, want)
		}
		metadata, err := reader.Metadata("backup-generation")
		if err != nil {
			return err
		}
		if got := string(metadata); got != want {
			t.Fatalf("metadata generation = %q, want %q", got, want)
		}
		return nil
	}
	if err := store.View(context.Background(), func(reader Reader) error {
		return assertGeneration(reader, "new000")
	}); err != nil {
		t.Fatalf("read live database: %v", err)
	}
	backup, err := OpenBoltReadOnly(backupPath)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(backup): %v", err)
	}
	defer backup.Close()
	if err := backup.View(context.Background(), func(reader Reader) error {
		return assertGeneration(reader, "old000")
	}); err != nil {
		t.Fatalf("read backup: %v", err)
	}
}

func TestBoltOnlineBackupCancellationPreservesDestination(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	databasePath := filepath.Join(directoryPath, "live.db")
	destinationPath := filepath.Join(directoryPath, "backup.db")
	seedMaintenanceDatabase(t, databasePath)
	seedMaintenanceDatabase(t, destinationPath)
	wantDestination := readMaintenanceSnapshot(t, destinationPath)
	store, err := OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	_, err = backupOpenBoltWithSnapshotHook(
		ctx,
		store.db,
		destinationPath,
		true,
		osFileSystem{},
		cancel,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("online backup error = %v, want context.Canceled", err)
	}
	assertMaintenanceSnapshot(t, destinationPath, wantDestination)
	assertNoMaintenanceTemporaryFiles(t, directoryPath)
}

func TestAtomicBackupPublicationFaultBoundaries(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{"file-fsync", "rename", "directory-fsync"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			directoryPath := t.TempDir()
			sourcePath := filepath.Join(directoryPath, "source.db")
			destinationPath := filepath.Join(directoryPath, "backup.db")
			seedMaintenanceDatabase(t, sourcePath)
			mutateMaintenanceDatabase(t, sourcePath)
			seedMaintenanceDatabase(t, destinationPath)
			wantOld := readMaintenanceSnapshot(t, destinationPath)
			wantNew := readMaintenanceSnapshot(t, sourcePath)
			store, err := OpenBolt(sourcePath)
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			defer store.Close()

			_, err = backupOpenBolt(
				context.Background(),
				store.db,
				destinationPath,
				true,
				faultAtomicFileSystem{operation: operation},
			)
			assertPublicationFault(t, operation, err)
			if operation == "directory-fsync" {
				assertMaintenanceSnapshot(t, destinationPath, wantNew)
			} else {
				assertMaintenanceSnapshot(t, destinationPath, wantOld)
			}
			assertNoMaintenanceTemporaryFiles(t, directoryPath)
		})
	}
}

func TestAtomicRestorePublicationFaultBoundaries(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{"file-fsync", "rename", "directory-fsync"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			directoryPath := t.TempDir()
			backupPath := filepath.Join(directoryPath, "backup.db")
			destinationPath := filepath.Join(directoryPath, "destination.db")
			seedMaintenanceDatabase(t, backupPath)
			mutateMaintenanceDatabase(t, backupPath)
			seedMaintenanceDatabase(t, destinationPath)
			wantOld := readMaintenanceSnapshot(t, destinationPath)
			wantNew := readMaintenanceSnapshot(t, backupPath)

			_, err := restoreBoltWithFS(
				context.Background(),
				backupPath,
				destinationPath,
				true,
				faultAtomicFileSystem{operation: operation},
			)
			assertPublicationFault(t, operation, err)
			if operation == "directory-fsync" {
				assertMaintenanceSnapshot(t, destinationPath, wantNew)
			} else {
				assertMaintenanceSnapshot(t, destinationPath, wantOld)
			}
			assertNoMaintenanceTemporaryFiles(t, directoryPath)
		})
	}
}

func TestRestoreRequiresOfflineDestination(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	seedMaintenanceDatabase(t, backupPath)
	mutateMaintenanceDatabase(t, backupPath)
	seedMaintenanceDatabase(t, destinationPath)
	store, err := OpenBolt(destinationPath)
	if err != nil {
		t.Fatalf("OpenBolt(destination): %v", err)
	}

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); !errors.Is(err, ErrRestoreRequiresOffline) {
		_ = store.Close()
		t.Fatalf("RestoreBolt() error = %v, want ErrRestoreRequiresOffline", err)
	}
	if err := store.Update(context.Background(), func(writer Writer) error {
		return writer.SetMetadata("still-online", []byte("yes"))
	}); err != nil {
		_ = store.Close()
		t.Fatalf("destination stopped working after refused restore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(destination): %v", err)
	}

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); err != nil {
		t.Fatalf("offline RestoreBolt(): %v", err)
	}
	assertMaintenanceSnapshot(t, destinationPath, readMaintenanceSnapshot(t, backupPath))
}

func TestRestoreRequiresReadOnlyDestinationToClose(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	seedMaintenanceDatabase(t, backupPath)
	mutateMaintenanceDatabase(t, backupPath)
	seedMaintenanceDatabase(t, destinationPath)
	store, err := OpenBoltReadOnly(destinationPath)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(destination): %v", err)
	}

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); !errors.Is(err, ErrRestoreRequiresOffline) {
		_ = store.Close()
		t.Fatalf("RestoreBolt() error = %v, want ErrRestoreRequiresOffline", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(destination): %v", err)
	}
	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); err != nil {
		t.Fatalf("offline RestoreBolt(): %v", err)
	}
}

func TestRestoreWaitsForEveryReadOnlySidecarHolder(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	seedMaintenanceDatabase(t, backupPath)
	seedMaintenanceDatabase(t, destinationPath)
	first, err := OpenBoltReadOnly(destinationPath)
	if err != nil {
		t.Fatalf("first OpenBoltReadOnly(): %v", err)
	}
	second, err := OpenBoltReadOnly(destinationPath)
	if err != nil {
		_ = first.Close()
		t.Fatalf("second OpenBoltReadOnly(): %v", err)
	}
	if err := first.Close(); err != nil {
		_ = second.Close()
		t.Fatalf("Close(first): %v", err)
	}

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); !errors.Is(err, ErrRestoreRequiresOffline) {
		_ = second.Close()
		t.Fatalf("RestoreBolt() error = %v, want second holder to block restore", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); err != nil {
		t.Fatalf("RestoreBolt() after every close: %v", err)
	}
}

func TestRestoreDetectsLegacyOpenWithoutSidecarOwnership(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	seedMaintenanceDatabase(t, backupPath)
	seedMaintenanceDatabase(t, destinationPath)
	database, err := openBoltReadOnly(destinationPath)
	if err != nil {
		t.Fatalf("open legacy read-only destination: %v", err)
	}

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); !errors.Is(err, ErrRestoreRequiresOffline) {
		_ = database.Close()
		t.Fatalf("RestoreBolt() error = %v, want ErrRestoreRequiresOffline", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close legacy destination: %v", err)
	}
	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); err != nil {
		t.Fatalf("RestoreBolt() after legacy close: %v", err)
	}
}

func TestRestoreReplacesCorruptOfflineDestination(t *testing.T) {
	t.Parallel()

	corruptions := map[string]func(*testing.T, string){
		"empty": func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatalf("empty destination: %v", err)
			}
		},
		"truncated": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Truncate(path, 64); err != nil {
				t.Fatalf("truncate destination: %v", err)
			}
		},
		"random-content": func(t *testing.T, path string) {
			t.Helper()
			content := bytes.Repeat([]byte("not-a-bbolt-database"), 512)
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatalf("replace destination with random content: %v", err)
			}
		},
		"damaged-meta-pages": func(t *testing.T, path string) {
			t.Helper()
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("open destination: %v", err)
			}
			_, writeErr := file.WriteAt(make([]byte, 2*os.Getpagesize()), 0)
			syncErr := file.Sync()
			closeErr := file.Close()
			if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
				t.Fatalf("damage destination metadata: %v", err)
			}
		},
	}

	for name, corrupt := range corruptions {
		name, corrupt := name, corrupt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directoryPath := t.TempDir()
			backupPath := filepath.Join(directoryPath, "backup.db")
			destinationPath := filepath.Join(directoryPath, "destination.db")
			seedMaintenanceDatabase(t, backupPath)
			mutateMaintenanceDatabase(t, backupPath)
			want := readMaintenanceSnapshot(t, backupPath)
			seedMaintenanceDatabase(t, destinationPath)
			corrupt(t, destinationPath)

			if _, err := RestoreBolt(
				context.Background(),
				backupPath,
				destinationPath,
				true,
			); err != nil {
				t.Fatalf("RestoreBolt(corrupt offline destination): %v", err)
			}
			assertMaintenanceSnapshot(t, destinationPath, want)
		})
	}
}

func TestRestoreInvalidBackupDoesNotInitializeEmptyDestination(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "invalid.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	if err := os.WriteFile(backupPath, []byte("invalid"), 0o600); err != nil {
		t.Fatalf("write invalid backup: %v", err)
	}
	if err := os.WriteFile(destinationPath, nil, 0o600); err != nil {
		t.Fatalf("write empty destination: %v", err)
	}
	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); err == nil {
		t.Fatal("RestoreBolt() succeeded with invalid backup")
	}
	info, err := os.Stat(destinationPath)
	if err != nil {
		t.Fatalf("Stat(destination): %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("empty destination size = %d after failed restore, want 0", info.Size())
	}
}

func TestRestoreNonexistentDestinationRejectsOpenDuringPublication(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	seedMaintenanceDatabase(t, backupPath)
	publicationReached := make(chan struct{})
	releasePublication := make(chan struct{})
	restoreDone := make(chan error, 1)
	go func() {
		_, err := restoreBoltWithFS(
			context.Background(),
			backupPath,
			destinationPath,
			true,
			hookedAtomicFileSystem{
				beforeRename: func() {
					close(publicationReached)
					<-releasePublication
				},
			},
		)
		restoreDone <- err
	}()

	select {
	case <-publicationReached:
	case <-time.After(5 * time.Second):
		close(releasePublication)
		t.Fatal("restore did not reach publication")
	}
	if _, err := os.Stat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		close(releasePublication)
		t.Fatalf("destination exists before publication: %v", err)
	}
	store, err := OpenBolt(destinationPath)
	if err == nil {
		_ = store.Close()
		close(releasePublication)
		t.Fatal("OpenBolt succeeded while restore held the publication lock")
	}
	if !errors.Is(err, errBoltPathLockBusy) {
		close(releasePublication)
		t.Fatalf("OpenBolt error = %v, want sidecar lock conflict", err)
	}
	close(releasePublication)
	if err := <-restoreDone; err != nil {
		t.Fatalf("restore after rejected OpenBolt: %v", err)
	}
	assertMaintenanceSnapshot(t, destinationPath, readMaintenanceSnapshot(t, backupPath))
}

func TestRestoreDoesNotReplaceOpenBoltWinnerForInitiallyMissingPath(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	seedMaintenanceDatabase(t, backupPath)
	if _, err := os.Stat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination initially exists: %v", err)
	}
	store, err := OpenBolt(destinationPath)
	if err != nil {
		t.Fatalf("OpenBolt(destination): %v", err)
	}
	before, err := os.Stat(destinationPath)
	if err != nil {
		_ = store.Close()
		t.Fatalf("Stat(destination): %v", err)
	}

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); !errors.Is(err, ErrRestoreRequiresOffline) {
		_ = store.Close()
		t.Fatalf("RestoreBolt() error = %v, want ErrRestoreRequiresOffline", err)
	}
	after, err := os.Stat(destinationPath)
	if err != nil {
		_ = store.Close()
		t.Fatalf("Stat(destination after restore refusal): %v", err)
	}
	if !os.SameFile(before, after) {
		_ = store.Close()
		t.Fatal("restore replaced the inode held by OpenBolt")
	}
	if err := store.Update(context.Background(), func(writer Writer) error {
		return writer.SetMetadata("still-online", []byte("yes"))
	}); err != nil {
		_ = store.Close()
		t.Fatalf("online database stopped working: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(destination): %v", err)
	}
}

func TestRestoreSidecarLockWorksAcrossProcessesForCorruptDestination(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	readyPath := filepath.Join(directoryPath, "ready")
	releasePath := filepath.Join(directoryPath, "release")
	seedMaintenanceDatabase(t, backupPath)
	if err := os.WriteFile(destinationPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt destination: %v", err)
	}

	command := exec.Command(os.Args[0], "-test.run=^TestBoltSidecarLockProcessHelper$")
	command.Env = append(os.Environ(),
		"LDAP_GO_BOLT_LOCK_HELPER=1",
		"LDAP_GO_BOLT_LOCK_PATH="+destinationPath,
		"LDAP_GO_BOLT_LOCK_READY="+readyPath,
		"LDAP_GO_BOLT_LOCK_RELEASE="+releasePath,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatalf("start lock helper: %v", err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		_ = os.WriteFile(releasePath, []byte("release"), 0o600)
	}
	defer release()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			release()
			_ = command.Wait()
			t.Fatalf("inspect helper readiness: %v", err)
		}
		if time.Now().After(deadline) {
			release()
			_ = command.Wait()
			t.Fatalf("lock helper did not become ready: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		destinationPath,
		true,
	); !errors.Is(err, ErrRestoreRequiresOffline) {
		release()
		_ = command.Wait()
		t.Fatalf("RestoreBolt() error = %v, want cross-process offline refusal", err)
	}
	content, err := os.ReadFile(destinationPath)
	if err != nil {
		release()
		_ = command.Wait()
		t.Fatalf("read destination: %v", err)
	}
	if string(content) != "corrupt" {
		release()
		_ = command.Wait()
		t.Fatalf("destination changed while sidecar was locked: %q", content)
	}
	release()
	if err := command.Wait(); err != nil {
		t.Fatalf("lock helper failed: %v\n%s", err, output.String())
	}
}

func TestBoltSidecarLockProcessHelper(t *testing.T) {
	if os.Getenv("LDAP_GO_BOLT_LOCK_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	lock, err := acquireBoltPathLock(os.Getenv("LDAP_GO_BOLT_LOCK_PATH"), false)
	if err != nil {
		t.Fatalf("acquire sidecar lock: %v", err)
	}
	defer lock.Close()
	if err := os.WriteFile(os.Getenv("LDAP_GO_BOLT_LOCK_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatalf("publish helper readiness: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("LDAP_GO_BOLT_LOCK_RELEASE")); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect helper release: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for helper release")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRestoreLockCanonicalizesDatabaseSymlink(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	destinationPath := filepath.Join(directoryPath, "destination.db")
	aliasPath := filepath.Join(directoryPath, "destination-alias.db")
	seedMaintenanceDatabase(t, backupPath)
	seedMaintenanceDatabase(t, destinationPath)
	if err := os.Symlink(destinationPath, aliasPath); err != nil {
		t.Skipf("database symlink is unavailable: %v", err)
	}
	store, err := OpenBolt(destinationPath)
	if err != nil {
		t.Fatalf("OpenBolt(destination): %v", err)
	}
	defer store.Close()

	if _, err := RestoreBolt(
		context.Background(),
		backupPath,
		aliasPath,
		true,
	); !errors.Is(err, ErrRestoreRequiresOffline) {
		t.Fatalf("RestoreBolt(symlink) error = %v, want ErrRestoreRequiresOffline", err)
	}
}

func TestBackupRestorePublicationPermissions(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	sourcePath := filepath.Join(directoryPath, "source.db")
	backupDirectory := filepath.Join(directoryPath, "private", "nested")
	backupPath := filepath.Join(backupDirectory, "backup.db")
	restoredPath := filepath.Join(directoryPath, "restored.db")
	seedMaintenanceDatabase(t, sourcePath)
	store, err := OpenBolt(sourcePath)
	if err != nil {
		t.Fatalf("OpenBolt(source): %v", err)
	}
	if _, err := store.Backup(context.Background(), backupPath, false); err != nil {
		_ = store.Close()
		t.Fatalf("online Backup(): %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(source): %v", err)
	}
	assertPrivateDatabaseMode(t, backupPath)
	if info, err := os.Stat(backupDirectory); err != nil {
		t.Fatalf("Stat(backup directory): %v", err)
	} else if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("backup directory mode = %#o, want 0700", got)
	}

	seedMaintenanceDatabase(t, restoredPath)
	if err := os.Chmod(restoredPath, 0o666); err != nil {
		t.Fatalf("Chmod(restored): %v", err)
	}
	if _, err := RestoreBolt(context.Background(), backupPath, restoredPath, true); err != nil {
		t.Fatalf("RestoreBolt(): %v", err)
	}
	assertPrivateDatabaseMode(t, restoredPath)
}

func assertPublicationFault(t *testing.T, operation string, err error) {
	t.Helper()
	if !errors.Is(err, errInjectedPublicationFault) {
		t.Fatalf("%s error = %v, want injected fault", operation, err)
	}
	var durabilityErr *PublicationDurabilityError
	if got := errors.As(err, &durabilityErr); got != (operation == "directory-fsync") {
		t.Fatalf("%s durability error = %t, want %t", operation, got, operation == "directory-fsync")
	}
}

func assertNoMaintenanceTemporaryFiles(t *testing.T, directoryPath string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directoryPath, ".ldap-go-database-*"))
	if err != nil {
		t.Fatalf("Glob(): %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary database files remain: %s", strings.Join(matches, ", "))
	}
}

func mustMaintenanceDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
