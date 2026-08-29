//go:build !windows

package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func listenServeLDAPI(path string, mode os.FileMode) (net.Listener, string, error) {
	if strings.TrimSpace(path) != path || path == "" {
		return nil, "", fmt.Errorf("LDAPI socket path is empty or contains surrounding whitespace")
	}
	if !filepath.IsAbs(path) {
		return nil, "", fmt.Errorf("LDAPI socket path must be absolute: %s", path)
	}
	path = filepath.Clean(path)
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, "", fmt.Errorf("stat LDAPI socket directory: %w", err)
	}
	if !parent.IsDir() {
		return nil, "", fmt.Errorf("LDAPI socket parent is not a directory: %s", filepath.Dir(path))
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, "", fmt.Errorf("LDAPI socket path already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return nil, "", fmt.Errorf("inspect LDAPI socket path: %w", err)
	}
	address, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, "", fmt.Errorf("resolve LDAPI socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, "", fmt.Errorf("listen on LDAPI socket %s: %w", path, err)
	}
	if err := os.Chmod(path, mode.Perm()); err != nil {
		_ = listener.Close()
		return nil, "", fmt.Errorf("set LDAPI socket permissions: %w", err)
	}
	return listener, "ldapi://" + url.PathEscape(path) + "/", nil
}
