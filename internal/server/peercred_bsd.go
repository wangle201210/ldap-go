//go:build darwin || freebsd

package server

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func unixPeerCredentials(connection net.Conn) (
	uid,
	gid uint32,
	available bool,
	err error,
) {
	rawProvider, ok := connection.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0, 0, false, fmt.Errorf("LDAPI connection does not expose its socket")
	}
	raw, err := rawProvider.SyscallConn()
	if err != nil {
		return 0, 0, false, fmt.Errorf("access LDAPI socket: %w", err)
	}
	var credentials *unix.Xucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptXucred(
			int(fd),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERCRED,
		)
	}); err != nil {
		return 0, 0, false, fmt.Errorf("inspect LDAPI socket: %w", err)
	}
	if socketErr != nil {
		return 0, 0, false, fmt.Errorf("read LDAPI peer credentials: %w", socketErr)
	}
	if credentials == nil {
		return 0, 0, false, fmt.Errorf("read LDAPI peer credentials: empty result")
	}
	if credentials.Ngroups <= 0 {
		return 0, 0, false, fmt.Errorf("LDAPI peer credentials contain no effective group")
	}
	return credentials.Uid, credentials.Groups[0], true, nil
}
