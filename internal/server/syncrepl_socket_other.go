//go:build !linux

package server

import "time"

func setSyncConsumerTCPUserTimeout(
	_ uintptr,
	_ time.Duration,
) error {
	return nil
}
