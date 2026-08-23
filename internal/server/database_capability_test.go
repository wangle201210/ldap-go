package server

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadRuntimeDatabasesRejectsUnsupportedBackendTypes(t *testing.T) {
	tests := []string{
		"perl",
		"unknown-backend",
		"bootstrap",
	}
	for _, backend := range tests {
		t.Run(backend, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			entry := capabilityDatabaseEntry(
				"{1}"+backend,
				"dc="+backend+",dc=test",
			)
			seedCapabilityConfiguration(t, store, entry)

			_, err := loadRuntimeDatabases(context.Background(), store)
			if err == nil {
				t.Fatalf(
					"loadRuntimeDatabases() accepted unsupported backend %q",
					backend,
				)
			}
			for _, want := range []string{entry.DN, backend, "unsupported"} {
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
					t.Fatalf(
						"loadRuntimeDatabases() error = %q, want substring %q",
						err,
						want,
					)
				}
			}
		})
	}
}

func TestSupportedRuntimeDatabaseType(t *testing.T) {
	t.Parallel()

	for backend := range supportedRuntimeDatabaseTypes {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			t.Parallel()
			got, ok := supportedRuntimeDatabaseType(
				" {12}" + strings.ToUpper(backend) + " ",
			)
			if !ok || got != backend {
				t.Fatalf(
					"supportedRuntimeDatabaseType() = (%q, %t), want (%q, true)",
					got,
					ok,
					backend,
				)
			}
		})
	}
}

func TestSupportedRuntimeDatabaseTypeRejectsBootstrap(t *testing.T) {
	t.Parallel()

	if got, ok := supportedRuntimeDatabaseType("{7}BOOTSTRAP"); ok || got != "bootstrap" {
		t.Fatalf(
			"supportedRuntimeDatabaseType(bootstrap) = (%q, %t), want (bootstrap, false)",
			got,
			ok,
		)
	}
}

func TestRuntimeAddsInternalBootstrapDatabase(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.SetNamingContexts([]string{"dc=bootstrap,dc=test"})
	}); err != nil {
		t.Fatalf("SetNamingContexts(): %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	for _, database := range databases {
		if database.name == "bootstrap" {
			return
		}
	}
	t.Fatalf("loadRuntimeDatabases() did not add internal bootstrap database: %#v", databases)
}

func TestNewAcceptsPasswdDatabaseBackend(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	fixture := writePasswdCapabilityFixture(t)
	entry := capabilityDatabaseEntry(
		"{1}passwd",
		"dc=passwd,dc=test",
		directory.Attribute{Description: "olcPasswdFile", Values: stringValues(fixture)},
	)
	seedCapabilityConfiguration(t, store, entry)

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New() rejected passwd database backend: %v", err)
	}
	instance.closeSQLBackends()
}

func TestValidateConfigurationAcceptsDNSSRVDatabaseBackend(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := capabilityDatabaseEntry("{1}dnssrv", "dc=dnssrv,dc=test")
	seedCapabilityConfiguration(t, store, entry)

	_, err := ValidateConfiguration(context.Background(), Config{Store: store})
	if err != nil {
		t.Fatalf("ValidateConfiguration() rejected dnssrv backend: %v", err)
	}
}

func TestOnlineConfigurationRejectsUnsupportedDatabaseBackend(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	entry := capabilityDatabaseEntry("{2}perl", "dc=perl,dc=test")
	request := ldap.NewAddRequest(entry.DN, nil)
	request.Attribute("objectClass", []string{"olcDatabaseConfig"})
	request.Attribute("olcDatabase", []string{"{2}perl"})
	request.Attribute("olcSuffix", []string{"dc=perl,dc=test"})
	err = client.Add(request)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Errorf(
			"online Add error = %v, want LDAP constraintViolation(%d)",
			err,
			ldap.LDAPResultConstraintViolation,
		)
	}

	dn, parseErr := directory.ParseDN(entry.DN)
	if parseErr != nil {
		t.Fatalf("ParseDN(%q): %v", entry.DN, parseErr)
	}
	readErr := store.View(context.Background(), func(reader storage.Reader) error {
		_, getErr := reader.GetIn(configurationStoragePartition, dn)
		return getErr
	})
	switch {
	case readErr == nil:
		t.Error("rejected unsupported database entry was committed to cn=config")
	case !errors.Is(readErr, storage.ErrEntryNotFound):
		t.Fatalf("read rejected database entry: %v", readErr)
	}
}

func TestLoadRuntimeDatabasesAcceptsImplementedBackendTypes(t *testing.T) {
	passwdFixture := writePasswdCapabilityFixture(t)
	tests := []struct {
		name    string
		backend string
		entries []directory.Entry
	}{
		{
			name:    "frontend",
			backend: "frontend",
			entries: []directory.Entry{capabilityDatabaseEntry("{-1}frontend", "")},
		},
		{
			name:    "config",
			backend: "config",
			entries: []directory.Entry{capabilityDatabaseEntry("{0}config", "")},
		},
		{
			name:    "monitor",
			backend: "monitor",
			entries: []directory.Entry{capabilityDatabaseEntry("{1}monitor", "")},
		},
		{
			name:    "mdb",
			backend: "mdb",
			entries: []directory.Entry{capabilityDatabaseEntry("{1}mdb", "dc=mdb,dc=test")},
		},
		{
			name:    "ldif",
			backend: "ldif",
			entries: []directory.Entry{capabilityDatabaseEntry("{1}ldif", "dc=ldif,dc=test")},
		},
		{
			name:    "wt",
			backend: "wt",
			entries: []directory.Entry{capabilityDatabaseEntry("{1}wt", "dc=wt,dc=test")},
		},
		{
			name:    "null",
			backend: "null",
			entries: []directory.Entry{capabilityDatabaseEntry("{1}null", "dc=null,dc=test")},
		},
		{
			name:    "passwd",
			backend: "passwd",
			entries: []directory.Entry{capabilityDatabaseEntry(
				"{1}passwd",
				"dc=passwd,dc=test",
				directory.Attribute{Description: "olcPasswdFile", Values: stringValues(passwdFixture)},
			)},
		},
		{
			name:    "dnssrv",
			backend: "dnssrv",
			entries: []directory.Entry{capabilityDatabaseEntry("{1}dnssrv", "dc=dnssrv,dc=test")},
		},
		{
			name:    "relay",
			backend: "relay",
			entries: []directory.Entry{
				capabilityDatabaseEntry("{1}mdb", "dc=target,dc=test"),
				capabilityDatabaseEntry(
					"{2}relay",
					"dc=relay,dc=test",
					directory.Attribute{
						Description: "olcRelay",
						Values:      stringValues("dc=target,dc=test"),
					},
				),
			},
		},
		{
			name:    "ldap",
			backend: "ldap",
			entries: []directory.Entry{capabilityDatabaseEntry(
				"{1}ldap",
				"dc=ldap,dc=test",
				directory.Attribute{
					Description: "olcDbURI",
					Values:      stringValues("ldap://127.0.0.1:1"),
				},
			)},
		},
		{
			name:    "meta",
			backend: "meta",
			entries: []directory.Entry{capabilityDatabaseEntry("{1}meta", "dc=meta,dc=test")},
		},
		{
			name:    "sock",
			backend: "sock",
			entries: []directory.Entry{capabilityDatabaseEntry(
				"{1}sock",
				"dc=sock,dc=test",
				directory.Attribute{
					Description: "olcDbSocketPath",
					Values:      stringValues("/tmp/ldap-go-capability.sock"),
				},
			)},
		},
		{
			name:    "sql",
			backend: "sql",
			entries: []directory.Entry{capabilityDatabaseEntry(
				"{1}sql",
				"dc=sql,dc=test",
				directory.Attribute{Description: "olcDbName", Values: stringValues("directory")},
				directory.Attribute{Description: "olcDbUser", Values: stringValues("ldap")},
			)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedCapabilityConfiguration(t, store, test.entries...)

			databases, err := loadRuntimeDatabases(context.Background(), store)
			if err != nil {
				t.Fatalf("loadRuntimeDatabases(%s): %v", test.backend, err)
			}
			found := false
			for _, database := range databases {
				if databaseType(database.name) == test.backend {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("implemented backend %q was not loaded: %#v", test.backend, databases)
			}
		})
	}
}

func writePasswdCapabilityFixture(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/passwd"
	if err := os.WriteFile(
		path,
		[]byte("fixture:x:1000:1000:Fixture User:/home/fixture:/bin/sh\n"),
		0o600,
	); err != nil {
		t.Fatalf("write passwd fixture: %v", err)
	}
	return path
}

func capabilityDatabaseEntry(
	name string,
	suffix string,
	attributes ...directory.Attribute,
) directory.Entry {
	entry := directory.Entry{
		DN: "olcDatabase=" + name + ",cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues(name)},
		},
	}
	if suffix != "" {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcSuffix",
			Values:      stringValues(suffix),
		})
	}
	entry.Attributes = append(entry.Attributes, attributes...)
	return entry
}

func seedCapabilityConfiguration(
	t *testing.T,
	store storage.Store,
	entries ...directory.Entry,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.PutIn(configurationStoragePartition, entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed capability configuration: %v", err)
	}
}
