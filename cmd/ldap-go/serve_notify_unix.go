//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func notifySystemd(getenv func(string) string, state string) (bool, error) {
	address := getenv("NOTIFY_SOCKET")
	if address == "" {
		return false, nil
	}
	if strings.ContainsAny(state, "\x00\r") || state == "" {
		return true, errors.New("systemd notification state is invalid")
	}
	if strings.HasPrefix(address, "@") {
		address = "\x00" + address[1:]
	} else if !strings.HasPrefix(address, "/") {
		return true, errors.New("NOTIFY_SOCKET must be an absolute or abstract Unix socket")
	}
	remote := &net.UnixAddr{Name: address, Net: "unixgram"}
	connection, err := net.DialUnix("unixgram", nil, remote)
	if err != nil {
		return true, fmt.Errorf("connect to NOTIFY_SOCKET: %w", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(state)); err != nil {
		return true, fmt.Errorf("write systemd notification: %w", err)
	}
	return true, nil
}
