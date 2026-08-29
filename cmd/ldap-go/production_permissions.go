package main

type productionPermissionAssessment struct {
	status   productionCheckStatus
	summary  string
	evidence []string
}

func productionDatabasePermissionFinding(path string) productionCheckFinding {
	assessment := inspectProductionDatabasePermissions(path)
	return productionCheckFinding{
		ID:       "storage.permissions",
		Category: "storage",
		Status:   assessment.status,
		Summary:  assessment.summary,
		Evidence: assessment.evidence,
		Remediation: productionPermissionRemediation(
			assessment.status,
			"place the database in a private directory and restrict the regular file to its service account, normally mode 0600",
			"verify the database and parent-directory ACLs allow only the service identity and authorized backup operators",
		),
	}
}

func productionBackupDirectoryPermissionFinding(path string) productionCheckFinding {
	assessment := inspectProductionBackupDirectoryPermissions(path)
	return productionCheckFinding{
		ID:       "backup.recovery",
		Category: "backup",
		Status:   assessment.status,
		Summary:  assessment.summary,
		Evidence: assessment.evidence,
		Remediation: productionPermissionRemediation(
			assessment.status,
			"create a private backup directory in a parent directory that is not writable by group or other users, normally mode 0700",
			"verify the backup-directory and parent-directory ACLs allow only the service identity and authorized backup operators",
		),
	}
}

func productionPermissionRemediation(
	status productionCheckStatus,
	insecure string,
	unknown string,
) string {
	switch status {
	case productionCheckFail:
		return insecure
	case productionCheckUnknown:
		return unknown
	default:
		return ""
	}
}
