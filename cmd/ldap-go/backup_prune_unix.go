//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validateBackupPrunePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat private backup directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("-dir must name a directory")
	}
	permissions := info.Mode().Perm()
	if permissions&0o700 != 0o700 || permissions&0o077 != 0 {
		return fmt.Errorf(
			"backup directory permissions %04o are not private owner access",
			permissions,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("backup directory owner could not be inspected")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"backup directory owner uid=%d does not match process uid=%d",
			stat.Uid,
			os.Geteuid(),
		)
	}
	for ancestor := filepath.Dir(path); ; ancestor = filepath.Dir(ancestor) {
		ancestorInfo, err := os.Lstat(ancestor)
		if err != nil {
			return fmt.Errorf("stat backup directory ancestor %q: %w", ancestor, err)
		}
		permissions := ancestorInfo.Mode().Perm()
		if permissions&0o022 != 0 && ancestorInfo.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf(
				"backup directory ancestor %q permissions %04o allow unsafe replacement",
				ancestor,
				permissions,
			)
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			break
		}
	}
	return nil
}
