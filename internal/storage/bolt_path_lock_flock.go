//go:build !android && !solaris && (darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd)

package storage

import (
	"errors"
	"os"
	"syscall"
)

func tryPlatformFileLock(file *os.File, exclusive bool) (bool, error) {
	operation := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		operation = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), operation); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func unlockPlatformFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
