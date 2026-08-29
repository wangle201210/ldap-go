//go:build windows

package main

import (
	"errors"
	"net"
	"os"
)

func listenServeLDAPI(string, os.FileMode) (net.Listener, string, error) {
	return nil, "", errors.New("LDAPI Unix sockets are not supported on Windows")
}
