package storage

import "github.com/wangle201210/ldap-go/internal/directory"

// validateStorageEntry preserves write preconditions when an indexed mutation
// unwraps contextual writers to call the underlying backend directly.
func validateStorageEntry(writer Writer, partition string, entry directory.Entry) error {
	for depth := 0; depth < 32 && writer != nil; depth++ {
		if validator, ok := writer.(interface {
			ValidateStorageEntry(string, directory.Entry) error
		}); ok {
			if err := validator.ValidateStorageEntry(partition, entry); err != nil {
				return err
			}
		}
		provider, ok := writer.(MaintenanceWriterProvider)
		if !ok {
			break
		}
		writer = provider.MaintenanceStorageWriter()
	}
	return nil
}
