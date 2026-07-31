//go:build linux

package server

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

func setSyncConsumerTCPUserTimeout(
	fileDescriptor uintptr,
	timeout time.Duration,
) error {
	milliseconds := int64(timeout / time.Millisecond)
	if milliseconds > int64(^uint32(0)>>1) {
		return fmt.Errorf("tcp-user-timeout %s exceeds the platform limit", timeout)
	}
	return unix.SetsockoptInt(
		int(fileDescriptor),
		unix.IPPROTO_TCP,
		unix.TCP_USER_TIMEOUT,
		int(milliseconds),
	)
}
