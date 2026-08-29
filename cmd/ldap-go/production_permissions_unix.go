//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func inspectProductionDatabasePermissions(path string) productionPermissionAssessment {
	info, err := os.Lstat(path)
	if err != nil {
		return productionPermissionAssessment{
			status:  productionCheckUnknown,
			summary: "database file permissions could not be inspected",
		}
	}
	if !info.Mode().IsRegular() {
		return productionPermissionAssessment{
			status:   productionCheckFail,
			summary:  "database path is not a regular file",
			evidence: []string{"database type=" + productionFileType(info.Mode())},
		}
	}
	permissions := info.Mode().Perm()
	if permissions&0o077 != 0 || permissions&0o600 != 0o600 {
		return productionPermissionAssessment{
			status:   productionCheckFail,
			summary:  "database file is not restricted to readable and writable owner access",
			evidence: []string{fmt.Sprintf("database permissions=%04o", permissions)},
		}
	}
	if issue := inspectProductionOwner(info, "database"); issue != nil {
		return *issue
	}
	if issue := inspectProductionPathAncestors(path); issue != nil {
		return *issue
	}
	return productionPermissionAssessment{
		status:   productionCheckPass,
		summary:  "database file and parent directory permissions are production-safe",
		evidence: []string{fmt.Sprintf("database permissions=%04o", permissions)},
	}
}

func inspectProductionBackupDirectoryPermissions(path string) productionPermissionAssessment {
	info, err := os.Lstat(path)
	if err != nil {
		return productionPermissionAssessment{
			status:  productionCheckFail,
			summary: "online backup directory is unavailable",
		}
	}
	if !info.IsDir() {
		return productionPermissionAssessment{
			status:   productionCheckFail,
			summary:  "online backup path is not a directory",
			evidence: []string{"backup type=" + productionFileType(info.Mode())},
		}
	}
	permissions := info.Mode().Perm()
	if permissions&0o077 != 0 || permissions&0o700 != 0o700 {
		return productionPermissionAssessment{
			status:   productionCheckFail,
			summary:  "online backup directory is not restricted to owner access",
			evidence: []string{fmt.Sprintf("backup permissions=%04o", permissions)},
		}
	}
	if issue := inspectProductionOwner(info, "backup"); issue != nil {
		return *issue
	}
	if issue := inspectProductionPathAncestors(path); issue != nil {
		if issue.status == productionCheckFail {
			issue.summary = "online backup directory has an unsafe parent directory"
		}
		return *issue
	}
	return productionPermissionAssessment{
		status:   productionCheckPass,
		summary:  "a private online backup directory is configured",
		evidence: []string{fmt.Sprintf("backup permissions=%04o", permissions)},
	}
}

func inspectProductionPathAncestors(path string) *productionPermissionAssessment {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return &productionPermissionAssessment{
			status: productionCheckUnknown, summary: "path ancestry could not be resolved",
		}
	}
	parent := filepath.Dir(filepath.Clean(absolute))
	direct := true
	for {
		info, err := os.Lstat(parent)
		if err != nil {
			return &productionPermissionAssessment{
				status: productionCheckUnknown, summary: "path ancestry permissions could not be inspected",
			}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			stat, owned := info.Sys().(*syscall.Stat_t)
			if !owned || stat.Uid != 0 {
				return &productionPermissionAssessment{
					status:   productionCheckFail,
					summary:  "path ancestry contains an untrusted symbolic-link component",
					evidence: []string{"ancestor type=" + productionFileType(info.Mode())},
				}
			}
		} else if !info.IsDir() {
			return &productionPermissionAssessment{
				status:   productionCheckFail,
				summary:  "path ancestry contains a non-directory component",
				evidence: []string{"ancestor type=" + productionFileType(info.Mode())},
			}
		}
		if direct && info.Mode()&os.ModeSymlink == 0 {
			if issue := inspectProductionOwner(info, "parent"); issue != nil {
				return issue
			}
		}
		permissions := info.Mode().Perm()
		writableByOthers := permissions&0o022 != 0
		sticky := info.Mode()&os.ModeSticky != 0
		if info.Mode()&os.ModeSymlink == 0 && writableByOthers && !sticky {
			return &productionPermissionAssessment{
				status:   productionCheckFail,
				summary:  "path ancestry is writable by group or other users",
				evidence: []string{fmt.Sprintf("ancestor permissions=%04o", permissions)},
			}
		}
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
		direct = false
	}
}

func inspectProductionOwner(
	info os.FileInfo,
	role string,
) *productionPermissionAssessment {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return &productionPermissionAssessment{
			status: productionCheckUnknown, summary: role + " owner could not be inspected",
		}
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != uid {
		return &productionPermissionAssessment{
			status:   productionCheckFail,
			summary:  role + " is not owned by the service identity",
			evidence: []string{fmt.Sprintf("%s owner uid=%d service uid=%d", role, stat.Uid, uid)},
		}
	}
	return nil
}

func productionFileType(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "symbolic-link"
	case mode.IsDir():
		return "directory"
	case mode.IsRegular():
		return "regular"
	default:
		return "special"
	}
}
