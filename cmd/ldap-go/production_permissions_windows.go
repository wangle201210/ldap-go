//go:build windows

package main

import "os"

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
	return productionPermissionAssessment{
		status:  productionCheckUnknown,
		summary: "database and parent-directory ACLs require Windows-specific verification",
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
	return productionPermissionAssessment{
		status:  productionCheckUnknown,
		summary: "backup-directory and parent-directory ACLs require Windows-specific verification",
	}
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
