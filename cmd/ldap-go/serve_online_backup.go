package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func prepareServeOnlineBackupDirectory(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("-online-backup-dir must be an absolute directory")
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve online backup directory: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("stat online backup directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("-online-backup-dir must name a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf(
			"online backup directory permissions %04o allow group or other writes",
			info.Mode().Perm(),
		)
	}
	probe, err := os.CreateTemp(canonical, ".ldap-go-backup-probe-*")
	if err != nil {
		return "", fmt.Errorf("write online backup directory: %w", err)
	}
	probePath := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(probePath)
	if closeErr != nil || removeErr != nil {
		return "", errors.Join(closeErr, removeErr)
	}
	return canonical, nil
}
