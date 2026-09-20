package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestConfigurationSchemaExpansionPreservesBoltData(t *testing.T) {
	builtin, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	legacy := configurationPersistenceLegacySchema(t, builtin)
	// Change only the core configuration catalog between the two Config.Schema
	// values, so unrelated hidden types cannot cause the migration under test.
	current := legacy.Clone()
	if err := schema.RegisterOpenLDAPConfigurationSchema(current); err != nil {
		t.Fatalf("expand legacy configuration schema: %v", err)
	}
	if legacy.DNIdentityFingerprint() == current.DNIdentityFingerprint() {
		t.Fatal("configuration schema expansion must change the naming fingerprint")
	}
	for _, attribute := range []string{"olcConnMaxPending", "olcConnMaxPendingAuth"} {
		definition, found := current.AttributeType(attribute)
		if !found || definition.Syntax != schema.SyntaxInteger {
			t.Fatalf("expanded %s definition = %#v, found=%v", attribute, definition, found)
		}
		if err := current.ValidateAttributeValue(attribute, []byte("0x10")); err == nil {
			t.Fatalf("%s no longer exercises the configuration/LDAP integer syntax distinction", attribute)
		}
	}

	path := filepath.Join(t.TempDir(), "directory.db")
	open := func() storage.Store {
		t.Helper()
		store, err := storage.OpenBolt(path)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	store := open()
	t.Cleanup(func() { _ = store.Close() })

	// Real configuration imports preserve classic base-zero tokens. Ordinary
	// integer syntax validation must not be applied to these runtime settings.
	if result, err := migration.ImportLDIF(t.Context(), store, strings.NewReader(configurationPersistenceLDIF), migration.ImportOptions{
		Schema: legacy,
	}); err != nil {
		t.Fatalf("import legacy configuration: %v", err)
	} else if result.Entries != 8 {
		t.Fatalf("imported entries = %d, want 8", result.Entries)
	}
	before := configurationPersistenceSnapshot(t, store)
	legacyConfig := Config{Schema: legacy, MaxSearchCandidates: 1}
	instance, address, stop := startConfigurationPersistenceServer(t, store, legacyConfig)
	func() {
		defer stop()
		assertConnectionPendingRuntime(t, instance.runtime.Load(), 16, 64)
		assertConfigurationPersistenceContent(t, store, instance, address)
		assertConfigurationPersistenceSnapshot(t, store, before)
		assertConfigurationPersistenceFingerprint(t, store, legacy)
	}()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = open()
	assertConfigurationPersistenceFingerprint(t, store, legacy)
	expandedConfig := legacyConfig
	expandedConfig.Schema = current
	instance, address, stop = startConfigurationPersistenceServer(t, store, expandedConfig)
	func() {
		defer stop()
		assertConfigurationPersistenceSnapshot(t, store, before)
		assertConfigurationPersistenceFingerprint(t, store, current)
		assertConnectionPendingRuntime(t, instance.runtime.Load(), 16, 64)
		assertConfigurationPersistenceContent(t, store, instance, address)
		client := bindConstraintClient(t, address, "cn=config", "config-secret")
		defer client.Close()
		assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPending", "0x10")
		assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPendingAuth", "0100")

		modify := ldap.NewModifyRequest("cn=config", nil)
		modify.Replace("olcConnMaxPending", []string{"0x20"})
		modify.Replace("olcConnMaxPendingAuth", []string{"+0100"})
		if err := client.Modify(modify); err != nil {
			t.Fatalf("modify accepted classic integer settings after expansion: %v", err)
		}
		assertConnectionPendingRuntime(t, instance.runtime.Load(), 32, 64)
		assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPending", "0x20")
		assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPendingAuth", "+0100")
		updated := configurationPersistenceSnapshot(t, store)
		if len(updated) != len(before) {
			t.Fatalf("configuration reload changed entry count from %d to %d", len(before), len(updated))
		}
		for key, entry := range before {
			if key.dn != "cn=config" && !reflect.DeepEqual(updated[key], entry) {
				t.Fatalf("configuration reload changed unrelated entry %s in %s", key.dn, key.partition)
			}
		}

		for _, attribute := range []string{"olcThreads", "olcThreadQueues", "olcListenerThreads", "olcToolThreads"} {
			definition, found := current.AttributeType(attribute)
			if !found {
				t.Fatalf("expanded schema is missing %s", attribute)
			}
			for _, description := range []string{attribute, definition.OID} {
				active := instance.runtime.Load()
				request := ldap.NewModifyRequest("cn=config", nil)
				request.Replace(description, []string{"32"})
				assertLDAPResultCode(t, client.Modify(request), ldap.LDAPResultConstraintViolation)
				if instance.runtime.Load() != active {
					t.Fatalf("unsupported %s change activated a runtime", description)
				}
				assertConfigurationPersistenceSnapshot(t, store, updated)
			}
		}
		before = updated
	}()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = open()
	assertConfigurationPersistenceFingerprint(t, store, current)
	instance, address, stop = startConfigurationPersistenceServer(t, store, expandedConfig)
	defer stop()
	assertConfigurationPersistenceSnapshot(t, store, before)
	assertConfigurationPersistenceFingerprint(t, store, current)
	assertConnectionPendingRuntime(t, instance.runtime.Load(), 32, 64)
	assertConfigurationPersistenceContent(t, store, instance, address)
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPending", "0x20")
	assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPendingAuth", "+0100")
}

func TestConfigurationSchemaImportPreservesClassicIntegerValues(t *testing.T) {
	current, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if result, err := migration.ImportLDIF(t.Context(), store, strings.NewReader(configurationPersistenceLDIF), migration.ImportOptions{
		Schema: current,
	}); err != nil {
		t.Fatalf("import expanded configuration: %v", err)
	} else if result.Entries != 8 {
		t.Fatalf("imported entries = %d, want 8", result.Entries)
	}
	before := configurationPersistenceSnapshot(t, store)
	instance, address, stop := startConfigurationPersistenceServer(t, store, Config{Schema: current, MaxSearchCandidates: 1})
	defer stop()
	assertConnectionPendingRuntime(t, instance.runtime.Load(), 16, 64)
	assertConfigurationPersistenceContent(t, store, instance, address)
	assertConfigurationPersistenceSnapshot(t, store, before)
	assertConfigurationPersistenceFingerprint(t, store, current)
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPending", "0x10")
	assertConfigurationPersistenceValues(t, client, current, "olcConnMaxPendingAuth", "0100")
}

const configurationPersistenceLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config
olcConnMaxPending: 0x10
olcConnMaxPendingAuth: 0100
olcThreads: 16
olcThreadQueues: 1
olcListenerThreads: 1
olcToolThreads: 1

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret
olcAccess: {0}to * by * none

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=directory-admin,dc=example,dc=com
olcRootPW: directory-secret
olcDbIndex: uid eq
olcAccess: {0}to * by * read

dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: ou=archive,dc=example,dc=com
objectClass: organizationalUnit
ou: archive

dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example
userPassword: secret
jpegPhoto:: AP8Q

`

func startConfigurationPersistenceServer(t *testing.T, store storage.Store, config Config) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.Store = store
	instance, err := New(config)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
	return instance, listener.Addr().String(), stop
}

// Config.Schema is an existing extension point. This deliberately minimal
// registry retains published content definitions and the earlier hidden core
// configuration types, without requiring a historical server binary. Exclude
// the expanded core catalog by OID before restoring its historical subset.
func configurationPersistenceLegacySchema(t *testing.T, current *schema.Registry) *schema.Registry {
	t.Helper()
	legacy := schema.NewRegistry()
	for _, description := range current.AttributeTypeDescriptions() {
		definition, err := schema.ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(definition.OID, "1.3.6.1.4.1.4203.1.12.2.3.0.") ||
			strings.HasPrefix(definition.OID, "1.3.6.1.4.1.4203.1.12.2.3.2.0.") {
			continue
		}
		if err := legacy.RegisterAttributeType(definition); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		"olcBackend", "olcDatabase", "olcOverlay", "olcAccess", "olcLogLevel",
		"olcModuleLoad", "olcModulePath", "olcSaslCBinding", "olcPasswordCryptSaltFormat",
		"olcSyncUseSubentry", "olcAuthzRegexp", "olcSyncrepl",
	} {
		definition, found := current.AttributeType(name)
		if !found {
			t.Fatalf("missing historical configuration naming type %s", name)
		}
		definition.Hidden = true
		if err := legacy.RegisterAttributeType(definition); err != nil {
			t.Fatal(err)
		}
	}
	for _, description := range current.ObjectClassDescriptions() {
		definition, err := schema.ParseObjectClass(description)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(definition.OID, "1.3.6.1.4.1.4203.1.12.2.4.0.") {
			continue
		}
		if err := legacy.RegisterObjectClass(definition); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"olcConfig", "olcModuleList"} {
		definition, found := current.ObjectClass(name)
		if !found {
			t.Fatalf("missing historical configuration class %s", name)
		}
		definition.Hidden = true
		if err := legacy.RegisterObjectClass(definition); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"olcConnMaxPending", "olcConnMaxPendingAuth", "olcThreads", "olcRootDN"} {
		if _, found := legacy.AttributeType(name); found {
			t.Fatalf("legacy schema unexpectedly contains the newly registered %s", name)
		}
	}
	for _, name := range []string{"olcGlobal", "olcDatabaseConfig"} {
		if _, found := legacy.ObjectClass(name); found {
			t.Fatalf("legacy schema unexpectedly contains the newly registered %s", name)
		}
	}
	return legacy
}

type configurationPersistenceEntryKey struct {
	partition string
	dn        string
}

func configurationPersistenceSnapshot(t *testing.T, store storage.Store) map[configurationPersistenceEntryKey]directory.Entry {
	t.Helper()
	entries := make(map[configurationPersistenceEntryKey]directory.Entry)
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		return reader.ForEachPartition(func(partition string, entry directory.Entry) error {
			key := configurationPersistenceEntryKey{partition: partition, dn: entry.DN}
			if _, exists := entries[key]; exists {
				return fmt.Errorf("duplicate stored DN %s", entry.DN)
			}
			entries[key] = entry.Clone()
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func assertConfigurationPersistenceSnapshot(t *testing.T, store storage.Store, want map[configurationPersistenceEntryKey]directory.Entry) {
	t.Helper()
	got := configurationPersistenceSnapshot(t, store)
	if len(got) != len(want) {
		t.Fatalf("stored entries = %d, want %d", len(got), len(want))
	}
	for key, entry := range want {
		if !reflect.DeepEqual(got[key], entry) {
			t.Fatalf("schema migration or reload changed stored entry %s in %s", key.dn, key.partition)
		}
	}
}

func assertConfigurationPersistenceFingerprint(t *testing.T, store storage.Store, registry *schema.Registry) {
	t.Helper()
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		got, err := reader.Metadata(runtimeDNIdentityFingerprintMetadataKey(configuredDatabasePartition("{1}mdb")))
		if err != nil {
			return err
		}
		want := registry.DNIdentityFingerprint()
		if !bytes.Equal(got, want[:]) {
			return fmt.Errorf("stored naming fingerprint = %x, want %x", got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertConfigurationPersistenceValues(t *testing.T, client *ldap.Conn, registry *schema.Registry, name, want string) {
	t.Helper()
	definition, found := registry.AttributeType(name)
	if !found {
		t.Fatalf("missing configuration attribute %s", name)
	}
	for _, description := range []string{name, definition.OID} {
		result, err := client.Search(ldap.NewSearchRequest("cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"("+description+"=*)", []string{description}, nil))
		if err != nil {
			t.Fatalf("read configuration by %s: %v", description, err)
		}
		if len(result.Entries) != 1 || len(result.Entries[0].Attributes) != 1 ||
			!reflect.DeepEqual(result.Entries[0].Attributes[0].Values, []string{want}) {
			t.Fatalf("read configuration by %s did not preserve %q: %#v", description, want, result.Entries)
		}
	}
}

func assertConfigurationPersistenceContent(t *testing.T, store storage.Store, instance *Server, address string) {
	t.Helper()
	const dn = "uid=alice,ou=people,dc=example,dc=com"
	client := bindConstraintClient(t, address, "cn=directory-admin,dc=example,dc=com", "directory-secret")
	defer client.Close()
	assertDNIdentityIndexedSearch(t, client, "alice", dn)
	for _, base := range []string{dn, "0.9.2342.19200300.100.1.1=alice,2.5.4.11=people,0.9.2342.19200300.100.1.25=example,0.9.2342.19200300.100.1.25=com"} {
		result, err := client.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(0.9.2342.19200300.100.1.1=alice)", []string{"cn", "jpegPhoto"}, nil))
		if err != nil {
			t.Fatalf("content OID/name lookup %s: %v", base, err)
		}
		if len(result.Entries) != 1 || result.Entries[0].DN != dn ||
			result.Entries[0].GetAttributeValue("cn") != "Alice Example" ||
			!bytes.Equal(result.Entries[0].GetRawAttributeValue("jpegPhoto"), []byte{0, 0xff, 0x10}) {
			t.Fatalf("content OID/name lookup changed DN or values: %#v", result.Entries)
		}
	}
	runtime := instance.runtime.Load()
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		for _, database := range runtime.databases {
			if database.partition != configuredDatabasePartition("{1}mdb") {
				continue
			}
			for _, attribute := range []string{"uid", "0.9.2342.19200300.100.1.1"} {
				var found []string
				planned, candidates, err := storage.ForEachFilterCandidate(storage.ReaderInPartitionWithNormalizer(reader, database.partition, database.dnNormalizer),
					directory.Filter{Kind: directory.FilterEquality, Attribute: attribute, Assertion: []byte("alice")},
					func(entry directory.Entry) error { found = append(found, entry.DN); return nil })
				if err != nil {
					return err
				}
				if !planned || candidates != 1 || !reflect.DeepEqual(found, []string{dn}) {
					return fmt.Errorf("%s index planned=%v candidates=%d entries=%v", attribute, planned, candidates, found)
				}
			}
			return nil
		}
		return fmt.Errorf("content database was lost during migration")
	}); err != nil {
		t.Fatal(err)
	}
}
