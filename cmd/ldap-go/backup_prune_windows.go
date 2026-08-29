//go:build windows

package main

import "errors"

func validateBackupPrunePrivateDirectory(string) error {
	return errors.New(
		"backup-prune is unavailable on Windows because private directory ACLs cannot be verified safely",
	)
}
