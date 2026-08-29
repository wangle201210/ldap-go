//go:build linux || darwin || freebsd

package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

type servePrivilegeConfig struct {
	userSpec  string
	groupSpec string
	chroot    string
	chrootDir *os.File
}

type serveIdentity struct {
	userName string
	uid      int
	gid      int
	groups   []int
	setUID   bool
	setGID   bool
}

func resolveServePrivileges(userSpec, groupSpec, chroot string) (*servePrivilegeConfig, error) {
	configuration := &servePrivilegeConfig{userSpec: userSpec, groupSpec: groupSpec}
	for value, name := range map[string]string{userSpec: "user", groupSpec: "group"} {
		if value != "" && numericIdentity(value) {
			if _, err := parseServeIdentityID(value, name+" ID"); err != nil {
				return nil, err
			}
		}
	}
	if chroot == "" {
		return configuration, nil
	}
	if !filepath.IsAbs(chroot) {
		return nil, errors.New("-chroot must be an absolute directory")
	}
	canonical, err := filepath.EvalSymlinks(filepath.Clean(chroot))
	if err != nil {
		return nil, fmt.Errorf("resolve chroot directory: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return nil, fmt.Errorf("stat chroot directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("-chroot must name a directory")
	}
	directory, err := os.Open(canonical)
	if err != nil {
		return nil, fmt.Errorf("open chroot directory: %w", err)
	}
	configuration.chroot = canonical
	configuration.chrootDir = directory
	return configuration, nil
}

func (configuration *servePrivilegeConfig) Close() error {
	if configuration == nil || configuration.chrootDir == nil {
		return nil
	}
	err := configuration.chrootDir.Close()
	configuration.chrootDir = nil
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func applyServePrivileges(configuration *servePrivilegeConfig) error {
	if configuration == nil {
		return nil
	}
	if configuration.chrootDir != nil {
		if os.Getuid() != 0 {
			return errors.New("-chroot requires root privileges")
		}
		if err := configuration.chrootDir.Chdir(); err != nil {
			return fmt.Errorf("enter chroot directory: %w", err)
		}
		if err := syscall.Chroot("."); err != nil {
			return fmt.Errorf("chroot to %s: %w", configuration.chroot, err)
		}
		if err := os.Chdir("/"); err != nil {
			return fmt.Errorf("change to chroot root: %w", err)
		}
		_ = configuration.Close()
	}
	identity, err := resolveServeIdentity(configuration.userSpec, configuration.groupSpec)
	if err != nil {
		return err
	}
	if identity.setUID && os.Getuid() == 0 {
		if err := syscall.Setgroups(identity.groups); err != nil {
			return fmt.Errorf("set supplementary groups: %w", err)
		}
	}
	if identity.setGID {
		if err := syscall.Setgid(identity.gid); err != nil {
			return fmt.Errorf("set gid %d: %w", identity.gid, err)
		}
	}
	if identity.setUID {
		if err := syscall.Setuid(identity.uid); err != nil {
			return fmt.Errorf("set uid %d: %w", identity.uid, err)
		}
	}
	if identity.setUID && (os.Getuid() != identity.uid || os.Geteuid() != identity.uid) {
		return fmt.Errorf("real/effective uid is %d/%d after switching to %d", os.Getuid(), os.Geteuid(), identity.uid)
	}
	if identity.setGID && (os.Getgid() != identity.gid || os.Getegid() != identity.gid) {
		return fmt.Errorf("real/effective gid is %d/%d after switching to %d", os.Getgid(), os.Getegid(), identity.gid)
	}
	return nil
}

func resolveServeIdentity(userSpec, groupSpec string) (serveIdentity, error) {
	identity := serveIdentity{}
	var account *user.User
	if userSpec != "" {
		var err error
		if numericIdentity(userSpec) {
			account, err = user.LookupId(userSpec)
		} else {
			account, err = user.Lookup(userSpec)
		}
		if err != nil {
			return serveIdentity{}, fmt.Errorf("resolve serve user %q: %w", userSpec, err)
		}
		uid, err := parseServeIdentityID(account.Uid, "user ID")
		if err != nil {
			return serveIdentity{}, err
		}
		gid, err := parseServeIdentityID(account.Gid, "primary group ID")
		if err != nil {
			return serveIdentity{}, err
		}
		identity.userName = account.Username
		identity.uid, identity.gid = uid, gid
		identity.setUID, identity.setGID = true, true
	}
	if groupSpec != "" {
		var group *user.Group
		var err error
		if numericIdentity(groupSpec) {
			group, err = user.LookupGroupId(groupSpec)
		} else {
			group, err = user.LookupGroup(groupSpec)
		}
		if err != nil {
			return serveIdentity{}, fmt.Errorf("resolve serve group %q: %w", groupSpec, err)
		}
		identity.gid, err = parseServeIdentityID(group.Gid, "group ID")
		if err != nil {
			return serveIdentity{}, err
		}
		identity.setGID = true
	}
	if account != nil {
		groupIDs, err := account.GroupIds()
		if err != nil {
			return serveIdentity{}, fmt.Errorf("resolve supplementary groups for %q: %w", account.Username, err)
		}
		seen := map[int]struct{}{identity.gid: {}}
		identity.groups = []int{identity.gid}
		for _, rawGroup := range groupIDs {
			if groupSpec != "" && rawGroup == account.Gid {
				continue
			}
			gid, err := parseServeIdentityID(rawGroup, "supplementary group ID")
			if err != nil {
				return serveIdentity{}, err
			}
			if _, duplicate := seen[gid]; duplicate {
				continue
			}
			seen[gid] = struct{}{}
			identity.groups = append(identity.groups, gid)
		}
	}
	return identity, nil
}

func numericIdentity(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parseServeIdentityID(value, name string) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not an unsigned 32-bit integer", name, value)
	}
	converted := int(parsed)
	if converted < 0 || uint64(converted) != parsed {
		return 0, fmt.Errorf("%s %q is outside the platform integer range", name, value)
	}
	return converted, nil
}
