//go:build unix

package server

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Nonblocking open prevents a concurrently substituted FIFO from hanging config.
const openLDAPLogOpenFlags = unix.O_NOFOLLOW | unix.O_NONBLOCK

func validateOpenLDAPLogHandle(file *os.File, _ os.FileInfo) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("logfile must have exactly one hard link")
	}
	return nil
}
