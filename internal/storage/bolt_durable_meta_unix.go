//go:build !windows && !plan9 && !openbsd

package storage

import (
	"os"
	"syscall"
)

func openBoltDurableMetaFile(path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDWR|syscall.O_SYNC, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil
}
