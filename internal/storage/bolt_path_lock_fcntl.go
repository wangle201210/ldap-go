//go:build aix || android || solaris

package storage

import (
	"errors"
	"os"
	"syscall"
)

func tryPlatformFileLock(file *os.File, exclusive bool) (bool, error) {
	lockType := int16(syscall.F_RDLCK)
	if exclusive {
		lockType = syscall.F_WRLCK
	}
	lock := syscall.Flock_t{Type: lockType}
	if err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock); err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func unlockPlatformFile(file *os.File) error {
	lock := syscall.Flock_t{Type: syscall.F_UNLCK}
	return syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock)
}
