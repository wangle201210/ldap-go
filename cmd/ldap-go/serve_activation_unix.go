//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const systemdListenFDStart = 3

func listenServeSystemd(
	getenv func(string) string,
	tcpScheme string,
) ([]net.Listener, []string, error) {
	pid, err := parseSystemdActivationInteger(getenv("LISTEN_PID"), "LISTEN_PID")
	if err != nil {
		return nil, nil, err
	}
	if pid != os.Getpid() {
		return nil, nil, fmt.Errorf(
			"LISTEN_PID=%d does not match this process (%d)",
			pid,
			os.Getpid(),
		)
	}
	count, err := parseSystemdActivationInteger(getenv("LISTEN_FDS"), "LISTEN_FDS")
	if err != nil {
		return nil, nil, err
	}
	if count <= 0 || count > 1024 {
		return nil, nil, fmt.Errorf("LISTEN_FDS must be between 1 and 1024")
	}
	names := []string(nil)
	if rawNames := getenv("LISTEN_FDNAMES"); rawNames != "" {
		names = strings.Split(rawNames, ":")
		if len(names) != count {
			return nil, nil, fmt.Errorf(
				"LISTEN_FDNAMES contains %d names for %d descriptors",
				len(names),
				count,
			)
		}
	}

	listeners := make([]net.Listener, 0, count)
	listenerURLs := make([]string, 0, count)
	closeListeners := func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}
	for index := range count {
		name := fmt.Sprintf("systemd-listener-%d", index)
		if len(names) != 0 && names[index] != "" {
			name = names[index]
		}
		file := os.NewFile(uintptr(systemdListenFDStart+index), name)
		if file == nil {
			closeListeners()
			return nil, nil, fmt.Errorf("systemd descriptor %d is invalid", index)
		}
		listener, listenerErr := net.FileListener(file)
		fileErr := file.Close()
		if listenerErr != nil {
			closeListeners()
			return nil, nil, fmt.Errorf(
				"adopt systemd descriptor %d (%s): %w",
				index,
				name,
				listenerErr,
			)
		}
		if fileErr != nil {
			_ = listener.Close()
			closeListeners()
			return nil, nil, fmt.Errorf("close inherited descriptor %d: %w", index, fileErr)
		}
		var listenerURL string
		switch address := listener.Addr(); address.Network() {
		case "tcp", "tcp4", "tcp6":
			listenerURL = tcpScheme + "://" + address.String() + "/"
		case "unix", "unixpacket":
			if tcpScheme != "ldap" {
				_ = listener.Close()
				closeListeners()
				return nil, nil, errors.New(
					"inherited LDAPI sockets cannot share implicit TLS or TLCP mode",
				)
			}
			unixListener, ok := listener.(*net.UnixListener)
			if !ok {
				_ = listener.Close()
				closeListeners()
				return nil, nil, fmt.Errorf("systemd Unix descriptor %d is not a stream listener", index)
			}
			unixListener.SetUnlinkOnClose(false)
			listenerURL = "ldapi://" + url.PathEscape(address.String()) + "/"
		default:
			_ = listener.Close()
			closeListeners()
			return nil, nil, fmt.Errorf(
				"systemd descriptor %d has unsupported network %q",
				index,
				address.Network(),
			)
		}
		listeners = append(listeners, listener)
		listenerURLs = append(listenerURLs, listenerURL)
	}
	return listeners, listenerURLs, nil
}

func parseSystemdActivationInteger(raw, name string) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("%s is required for systemd activation", name)
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative decimal integer", name)
	}
	return value, nil
}
