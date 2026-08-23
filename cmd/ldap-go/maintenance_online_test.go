package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestBackupCommandHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	databasePath := filepath.Join(directoryPath, "directory.db")
	backupDirectory := filepath.Join(directoryPath, "canceled")
	backupPath := filepath.Join(backupDirectory, "backup.db")
	seedMaintenanceCommandDatabase(t, databasePath, "source")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := runWithContext(
		ctx,
		[]string{"backup", "-db", databasePath, "-out", backupPath},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "context canceled") {
		t.Fatalf(
			"backup exit=%d stdout=%q stderr=%q",
			exitCode,
			stdout.String(),
			stderr.String(),
		)
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("canceled backup destination stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(backupDirectory); !os.IsNotExist(err) {
		t.Fatalf("canceled backup directory stat error = %v, want not exist", err)
	}
}

func TestRestoreCommandRejectsRunningDestination(t *testing.T) {
	t.Parallel()

	directoryPath := t.TempDir()
	backupPath := filepath.Join(directoryPath, "backup.db")
	databasePath := filepath.Join(directoryPath, "directory.db")
	seedMaintenanceCommandDatabase(t, backupPath, "backup")
	seedMaintenanceCommandDatabase(t, databasePath, "live")
	live, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatalf("OpenBolt(live): %v", err)
	}
	defer live.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := runWithContext(
		context.Background(),
		[]string{"restore", "-backup", backupPath, "-db", databasePath, "-replace"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		func(string) string { return "" },
	)
	if exitCode != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), storage.ErrRestoreRequiresOffline.Error()) {
		t.Fatalf(
			"restore exit=%d stdout=%q stderr=%q",
			exitCode,
			stdout.String(),
			stderr.String(),
		)
	}
	if err := live.View(context.Background(), func(reader storage.Reader) error {
		value, err := reader.Metadata("command-state")
		if err != nil {
			return err
		}
		if string(value) != "live" {
			t.Fatalf("live state = %q, want live", value)
		}
		return nil
	}); err != nil {
		t.Fatalf("read live database after refused restore: %v", err)
	}
}

func seedMaintenanceCommandDatabase(t *testing.T, path, state string) {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(%q): %v", path, err)
	}
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "dc", Values: [][]byte{[]byte("example")}},
			},
		}, false); err != nil {
			return err
		}
		return writer.SetMetadata("command-state", []byte(state))
	})
	if err != nil {
		_ = store.Close()
		t.Fatalf("seed %q: %v", path, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(%q): %v", path, err)
	}
}
