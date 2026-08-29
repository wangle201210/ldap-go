//go:build windows

package main

import (
	"errors"
	"net"
)

func listenServeSystemd(func(string) string, string) ([]net.Listener, []string, []bool, error) {
	return nil, nil, nil, errors.New("systemd socket activation is not supported on Windows")
}
