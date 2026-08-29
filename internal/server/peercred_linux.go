//go:build linux

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
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
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
	return credentials.Uid, credentials.Gid, true, nil
}
