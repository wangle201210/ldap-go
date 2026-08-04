//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package server

import (
	"io/fs"
	"os"
	"syscall"
)

const homedirFilesystemSupported = true

func homedirFileOwnership(info fs.FileInfo) (uint64, uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(stat.Uid), uint64(stat.Gid), true
}

func homedirCanChangeOwnership() bool {
	return os.Geteuid() == 0
}
