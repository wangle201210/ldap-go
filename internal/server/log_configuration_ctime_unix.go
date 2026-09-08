//go:build unix

package server

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func openLDAPLogChangeTime(file *os.File, _ os.FileInfo) (time.Time, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return time.Time{}, err
	}
	return time.Unix(stat.Ctim.Sec, 0), nil
}
