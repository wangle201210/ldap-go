package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestAllowedOverlayConfigurationLoading(t *testing.T) {
	for _, parent := range []string{"olcDatabase={-1}frontend,cn=config", "olcDatabase={1}mdb,cn=config"} {
		t.Run(parent, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			addAllowedConfigurationFrontend(t, store)
			addAllowedConfigurationOverlay(t, store, parent, 0)
			databases, err := loadRuntimeDatabases(t.Context(), store)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, database := range databases {
				if database.configDNKey == staticRuntimeDN(parent).Key() {
					found = true
					if !database.allowedOverlay || runtimeDatabaseOverlayCount(database) != 1 {
						t.Fatalf("allowed flag/count missing on %s", parent)
					}
				}
			}
			if !found {
				t.Fatalf("configured database not loaded: %s", parent)
			}
			addAllowedConfigurationOverlay(t, store, parent, 1)
			if _, err := loadRuntimeDatabases(t.Context(), store); err == nil || !strings.Contains(err.Error(), "duplicate allowed overlay") {
				t.Fatalf("duplicate overlay accepted: %v", err)
			}
		})
	}
}

func TestAllowedOverlayConfigurationPerDatabaseScope(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	addAllowedConfigurationFrontend(t, store)
	for _, parent := range []string{"olcDatabase={-1}frontend,cn=config", "olcDatabase={1}mdb,cn=config"} {
		addAllowedConfigurationOverlay(t, store, parent, 0)
	}
	databases, err := loadRuntimeDatabases(t.Context(), store)
	if err != nil {
		t.Fatalf("allowed may be configured on frontend and data databases: %v", err)
	}
	count := 0
	for _, database := range databases {
		if database.allowedOverlay {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("allowed overlay count = %d", count)
	}
	addAllowedConfigurationOverlay(t, store, "olcDatabase={2}mdb,cn=config", 0)
	if _, err := loadRuntimeDatabases(t.Context(), store); err == nil || !strings.Contains(err.Error(), "parent is not a configured database") {
		t.Fatalf("unconfigured parent accepted: %v", err)
	}
}

func addAllowedConfigurationFrontend(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcFrontendConfig")},
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
}

func addAllowedConfigurationOverlay(t *testing.T, store storage.Store, parent string, index int) {
	t.Helper()
	value := fmt.Sprintf("{%d}allowed", index)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcOverlay=" + value + "," + parent,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
				{Description: "olcOverlay", Values: stringValues(value)},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
}
