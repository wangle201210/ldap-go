//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package server

import "io/fs"

const homedirFilesystemSupported = false

func homedirFileOwnership(fs.FileInfo) (uint64, uint64, bool) {
	return 0, 0, false
}

func homedirCanChangeOwnership() bool {
	return false
}
