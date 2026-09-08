package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type logFileCommitFailureStore struct {
	storage.Store
	failNext atomic.Bool
}

var errLogFileTestCommit = errors.New("injected storage commit failure")

func (store *logFileCommitFailureStore) Update(ctx context.Context, update func(storage.Writer) error) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		if err := update(writer); err != nil {
			return err
		}
		if store.failNext.Swap(false) {
			return errLogFileTestCommit
		}
		return nil
	})
}

func TestOpenLDAPLogFileCommitRollbackAndPreparedActivation(t *testing.T) {
	store := &logFileCommitFailureStore{Store: storage.NewMemory()}
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	root := t.TempDir()
	path := filepath.Join(root, "active.log")
	setStoredOpenLDAPLogging(t, store, map[string][]string{
		"olcLogFile": {path}, "olcLogLevel": {"ANY"}, "olcLogFileOnly": {"TRUE"},
	})
	instance, address, stop := startMonitorLogRoutingServer(t, store, nil)
	defer stop()
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	active := instance.runtime.Load()
	oldFile := instance.monitor.configuredLogFile()
	instance.config.Logger.Error("before rollback")

	for _, samePath := range []bool{false, true} {
		t.Run(fmt.Sprintf("same-path-%t", samePath), func(t *testing.T) {
			nextPath := filepath.Join(root, "candidate.log")
			if samePath {
				nextPath = path
			}
			var candidate *runtimeState
			var prepared *openLDAPLogFile
			err := instance.config.Store.Update(t.Context(), func(writer storage.Writer) error {
				entry, err := writer.GetIn(configurationStoragePartition, configurationSuffix)
				if err != nil {
					return err
				}
				entry.ReplaceValues("olcLogFile", stringValues(nextPath))
				entry.ReplaceValues("olcLogFileFormat", stringValues("syslog-utc"))
				if err := writer.PutIn(configurationStoragePartition, entry, true); err != nil {
					return err
				}
				candidate, err = instance.validateRuntimeConfiguration(writer)
				if err != nil {
					return err
				}
				prepared = candidate.preparedLogFile.file.Load()
				store.failNext.Store(true)
				return nil
			})
			if !errors.Is(err, errLogFileTestCommit) {
				t.Fatalf("transaction failure = %v", err)
			}
			if candidate.preparedLogFile.file.Load() != nil {
				t.Fatal("rollback retained candidate ownership")
			}
			if samePath {
				if prepared != oldFile || prepared.closed || prepared.references != 1 {
					t.Fatal("rollback changed active file ownership")
				}
			} else if !prepared.closed {
				t.Fatal("rollback leaked candidate descriptor")
			}
			if instance.runtime.Load() != active || instance.monitor.configuredLogFile() != oldFile {
				t.Fatal("failed transaction changed active runtime or destination")
			}
			if got := readConfiguredAttribute(t, client, "olcLogFile"); !slices.Equal(got, []string{path}) {
				t.Fatalf("failed transaction persisted %v", got)
			}
			instance.config.Logger.Error("after rollback")
			assertFileContains(t, path, "after rollback")
		})
	}

	// Simulate the pathname disappearing after preparation and before publication.
	// Activation must use the descriptor it validated, without opening the path again.
	nextPath := filepath.Join(root, "prepared.log")
	movedPath := filepath.Join(root, "moved.log")
	var candidate *runtimeState
	if err := instance.config.Store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcLogFile", stringValues(nextPath))
		if err := writer.PutIn(configurationStoragePartition, entry, true); err != nil {
			return err
		}
		candidate, err = instance.validateRuntimeConfiguration(writer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(nextPath, movedPath); err != nil {
		t.Fatal(err)
	}
	instance.activateRuntime(candidate)
	instance.config.Logger.Error("prepared descriptor marker")
	assertFileContains(t, movedPath, "prepared descriptor marker")
	if _, err := os.Stat(nextPath); !os.IsNotExist(err) {
		t.Fatalf("activation reopened the pathname: %v", err)
	}
	if !oldFile.closed {
		t.Fatal("activation leaked previous descriptor")
	}
}

func TestOpenLDAPLogFileConcurrentRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slapd.log")
	file, err := openConfiguredLDAPLogFile(openLDAPLogFileConfiguration{
		path: path, rotation: openLDAPLogFileRotation{maximum: 99, bytes: 1024},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer file.close()
	const workers, records = 8, 40
	var wait sync.WaitGroup
	for worker := range workers {
		wait.Go(func() {
			for index := range records {
				record := slog.NewRecord(time.Now(), slog.LevelError, fmt.Sprintf("rotation-%d-%d end", worker, index), 0)
				if err := file.write(record, nil, nil); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wait.Wait()
	paths, err := filepath.Glob(path + "*")
	if err != nil || len(paths) < 2 {
		t.Fatalf("rotation did not produce archives: %v, %v", paths, err)
	}
	var contents strings.Builder
	for _, path := range paths {
		contents.Write(readLogFile(t, path))
	}
	logs := contents.String()
	if strings.Count(logs, "\n") != workers*records {
		t.Fatal("concurrent rotation lost or split records")
	}
	for worker := range workers {
		for index := range records {
			if marker := fmt.Sprintf("rotation-%d-%d end", worker, index); strings.Count(logs, marker) != 1 {
				t.Fatalf("record %q missing or duplicated", marker)
			}
		}
	}
}

func TestOpenLDAPLogFileRejectsStaleRuntimeAndShutdown(t *testing.T) {
	instance := newRuntimeActivationTestServer()
	defer instance.metaTransports.close()
	instance.monitor = newMonitorState()
	path := filepath.Join(t.TempDir(), "active.log")
	configuration := openLDAPLogFileConfiguration{path: path}
	prepared, err := instance.monitor.prepareLogFile(configuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	current := &runtimeState{revision: 2, logFile: configuration, preparedLogFile: prepared}
	instance.activateRuntime(current)
	file := instance.monitor.configuredLogFile()
	configuration.path = filepath.Join(t.TempDir(), "stale.log")
	stale, err := instance.monitor.prepareLogFile(configuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	staleFile := stale.file.Load()
	instance.activateRuntime(&runtimeState{revision: 1, logFile: configuration, preparedLogFile: stale})
	if !staleFile.closed || instance.monitor.configuredLogFile() != file {
		t.Fatal("stale runtime changed destination or leaked descriptor")
	}
	late, err := instance.monitor.prepareLogFile(configuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	lateFile := late.file.Load()
	instance.monitor.closeLogFile()
	instance.activateRuntime(&runtimeState{revision: 3, logFile: configuration, preparedLogFile: late})
	if !file.closed || !lateFile.closed || instance.monitor.configuredLogFile() != nil {
		t.Fatal("shutdown leaked or reactivated a logfile")
	}
}

func TestOpenLDAPLogFileConcurrentOnlineHandover(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	root := t.TempDir()
	paths := []string{filepath.Join(root, "a.log"), filepath.Join(root, "b.log")}
	setStoredOpenLDAPLogging(t, store, map[string][]string{
		"olcLogFile": {paths[0]}, "olcLogFileOnly": {"TRUE"}, "olcLogLevel": {"ANY"},
	})
	captured := &capturedMonitorLogState{}
	instance, address, stop := startMonitorLogRoutingServer(t, store, slog.New(capturedMonitorLogHandler{state: captured}))
	defer stop()
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	const workers, count = 8, 150
	var wait sync.WaitGroup
	for worker := range workers {
		wait.Go(func() {
			logger := instance.config.Logger.With("worker", worker).WithGroup("event")
			for record := range count {
				logger.Error(fmt.Sprintf("handover-%d-%d", worker, record))
			}
		})
	}
	for index := range 40 {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcLogFile", []string{paths[index%2]})
		request.Replace("olcLogFileFormat", []string{[]string{"debug", "rfc3339-utc"}[index%2]})
		if err := client.Modify(request); err != nil {
			t.Error(err)
			break
		}
	}
	wait.Wait()
	logs := string(readLogFile(t, paths[0])) + string(readLogFile(t, paths[1]))
	for worker := range workers {
		for record := range count {
			marker := fmt.Sprintf("handover-%d-%d ", worker, record)
			if strings.Count(logs, marker) != 1 {
				t.Fatalf("marker %q missing or duplicated during handover", marker)
			}
		}
	}
	for _, record := range captured.snapshot() {
		if strings.HasPrefix(record.message, "handover-") {
			t.Fatalf("handover fell back to process logger: %s", record.message)
		}
	}
}

func TestOpenLDAPLogFileSamePathPreservesRotationState(t *testing.T) {
	monitor := newMonitorState()
	defer monitor.closeLogFile()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	configuration := openLDAPLogFileConfiguration{
		path:     filepath.Join(t.TempDir(), "slapd.log"),
		rotation: openLDAPLogFileRotation{maximum: 2, age: time.Hour},
	}
	if err := monitor.configureLogFile(configuration, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	file := monitor.configuredLogFile()
	if err := file.write(slog.NewRecord(now, slog.LevelInfo, "before", 0), nil, nil); err != nil {
		t.Fatal(err)
	}
	size, created := file.size, file.created
	now = now.Add(time.Hour)
	configuration.format = openLDAPLogFileFormatRFC3339UTC
	if err := monitor.configureLogFile(configuration, nil); err != nil {
		t.Fatal(err)
	}
	if file != monitor.configuredLogFile() || file.created != created || file.size != size {
		t.Fatal("same-path reconfiguration reset file state")
	}
	if err := file.write(slog.NewRecord(now, slog.LevelInfo, "after", 0), nil, nil); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, configuration.path+".01", "before")
	assertFileContains(t, configuration.path, "2026-09-08T01:00:00.000000000Z")
}

func TestOpenLDAPLogFileStartupFailureAndServeCleanup(t *testing.T) {
	store := storage.NewMemory()
	defer store.Close()
	seedOnlineConfiguration(t, store)
	setStoredOpenLDAPLogging(t, store, map[string][]string{
		"olcLogFile": {filepath.Join(t.TempDir(), "missing", "slapd.log")},
	})
	if instance, err := New(Config{Store: store}); err == nil {
		instance.monitor.closeLogFile()
		t.Fatal("startup accepted inaccessible logfile")
	}
	// New partitions cn=config even on failure.
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcLogFile", stringValues(filepath.Join(t.TempDir(), "slapd.log")))
		return writer.PutIn(configurationStoragePartition, entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	instance, _, stop := startMonitorLogRoutingServer(t, store, nil)
	file := instance.monitor.configuredLogFile()
	stop()
	if !file.closed || instance.monitor.configuredLogFile() != nil {
		t.Fatal("Serve did not close the logfile")
	}
}
