//go:build windows

package main

import "errors"

type servePrivilegeConfig struct{}

func resolveServePrivileges(user, group, chroot string) (*servePrivilegeConfig, error) {
	if user != "" || group != "" || chroot != "" {
		return nil, errors.New("-user, -group, and -chroot are not supported on Windows")
	}
	return &servePrivilegeConfig{}, nil
}

func (*servePrivilegeConfig) Close() error { return nil }

func applyServePrivileges(*servePrivilegeConfig) error { return nil }
