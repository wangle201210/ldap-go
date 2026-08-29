//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type systemdNotifier struct {
	connection *net.UnixConn
}

func openSystemdNotifier(getenv func(string) string) (*systemdNotifier, bool, error) {
	address := getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil, false, nil
	}
	if strings.HasPrefix(address, "@") {
		address = "\x00" + address[1:]
	} else if !strings.HasPrefix(address, "/") {
		return nil, true, errors.New("NOTIFY_SOCKET must be an absolute or abstract Unix socket")
	}
	remote := &net.UnixAddr{Name: address, Net: "unixgram"}
	connection, err := net.DialUnix("unixgram", nil, remote)
	if err != nil {
		return nil, true, fmt.Errorf("connect to NOTIFY_SOCKET: %w", err)
	}
	return &systemdNotifier{connection: connection}, true, nil
}

func (notifier *systemdNotifier) Notify(state string) error {
	if notifier == nil || notifier.connection == nil {
		return nil
	}
	if strings.ContainsAny(state, "\x00\r") || state == "" {
		return errors.New("systemd notification state is invalid")
	}
	if _, err := notifier.connection.Write([]byte(state)); err != nil {
		return fmt.Errorf("write systemd notification: %w", err)
	}
	return nil
}

func (notifier *systemdNotifier) Close() error {
	if notifier == nil || notifier.connection == nil {
		return nil
	}
	return notifier.connection.Close()
}

func notifySystemd(getenv func(string) string, state string) (bool, error) {
	notifier, configured, err := openSystemdNotifier(getenv)
	if err != nil {
		return configured, err
	}
	if !configured {
		return false, nil
	}
	defer notifier.Close()
	return true, notifier.Notify(state)
}
