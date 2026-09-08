package migration

import (
	"fmt"

	"github.com/wangle201210/ldap-go/internal/mdbentry"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Check only newly imported entries, after schema and generated operational
// attributes. Lowering a limit must not reject existing oversized entries.
func validateImportedEntrySizes(writer storage.Writer, entries []importedContentEntry, base *schema.Registry) error {
	var registry *schema.Registry
	for _, imported := range entries {
		if imported.target.maxEntrySize == 0 {
			continue
		}
		if registry == nil {
			var err error
			registry, err = importedSchemaRegistry(writer, base)
			if err != nil {
				return err
			}
		}
		entry, err := writer.GetIn(imported.partition, imported.dn)
		if err != nil {
			return err
		}
		if err := mdbentry.Check(entry, registry, imported.target.maxEntrySize); err != nil {
			return fmt.Errorf("import %q: %w", entry.DN, err)
		}
	}
	return nil
}
