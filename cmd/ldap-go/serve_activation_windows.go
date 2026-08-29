//go:build windows

package main

import (
	"errors"
	"net"
)

func listenServeSystemd(func(string) string, string) ([]net.Listener, []string, error) {
	return nil, nil, errors.New("systemd socket activation is not supported on Windows")
}
