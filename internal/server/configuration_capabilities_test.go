package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRuntimeConfigurationCapabilitiesRejectHighImpactNoOps(t *testing.T) {
	for attribute := range unsupportedRuntimeConfigurationAttributes {
		attribute := attribute
		t.Run(attribute, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			target := "cn=config"
			if strings.HasPrefix(attribute, "olcdb") || attribute == "olcmonitoring" {
				target = "olcDatabase={1}mdb,cn=config"
			}
			setUnsupportedRuntimeConfigurationAttribute(
				t, store, target, attribute, "configured",
			)

			if _, err := ValidateConfiguration(context.Background(), Config{Store: store}); err == nil || !strings.Contains(strings.ToLower(err.Error()), attribute) {
				t.Fatalf("ValidateConfiguration() error = %v", err)
			}
			instance, err := New(Config{Store: store})
			if instance != nil {
				instance.closeSQLBackends()
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), attribute) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestRuntimeConfigurationCapabilitiesOnlineRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	instance, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()

	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	for _, test := range []struct {
		dn, attribute, value string
	}{
		{"cn=config", "olcSaslCBinding", "tls-unique"},
		{"cn=config", "olcLogFile", "/var/log/slapd.log"},
		{"cn=config", "olcThreads", "32"},
		{"olcDatabase={1}mdb,cn=config", "olcDbMaxEntrySize", "1048576"},
		{"olcDatabase={1}mdb,cn=config", "olcDbNoSync", "TRUE"},
		{"olcDatabase={1}mdb,cn=config", "olcMonitoring", "FALSE"},
	} {
		active := instance.runtime.Load()
		request := ldap.NewModifyRequest(test.dn, nil)
		request.Add(test.attribute, []string{test.value})
		assertLDAPResultCode(t, client.Modify(request), ldap.LDAPResultConstraintViolation)
		if instance.runtime.Load() != active {
			t.Fatalf("failed %s update activated a runtime", test.attribute)
		}
		entry := readStoredEntry(t, store, test.dn)
		if values := entry.Values(test.attribute); len(values) != 0 {
			t.Fatalf("persisted %s after rollback = %q", test.attribute, values)
		}
	}
}

func TestRuntimeConfigurationCapabilitiesAllowImplementedAndPortableFields(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	setUnsupportedRuntimeConfigurationAttribute(
		t, store, "cn=config", "olcLogLevel", "ACL SYNC",
	)
	setUnsupportedRuntimeConfigurationAttribute(
		t,
		store,
		"olcDatabase={1}mdb,cn=config",
		"olcDbDirectory",
		"/var/lib/ldap",
	)
	for attribute, value := range portableRuntimeConfigurationDefaults {
		target := "cn=config"
		if strings.HasPrefix(attribute, "olcdb") {
			target = "olcDatabase={1}mdb,cn=config"
		}
		setUnsupportedRuntimeConfigurationAttribute(t, store, target, attribute, value)
	}
	setUnsupportedRuntimeConfigurationAttribute(
		t,
		store,
		"olcDatabase={1}mdb,cn=config",
		"olcDbMaxSize",
		"4294967296",
	)
	setUnsupportedRuntimeConfigurationAttribute(
		t,
		store,
		"olcDatabase={1}mdb,cn=config",
		"olcMonitoring",
		"TRUE",
	)
	setUnsupportedRuntimeConfigurationAttribute(
		t,
		store,
		"olcDatabase={0}config,cn=config",
		"olcMonitoring",
		"FALSE",
	)
	if _, err := ValidateConfiguration(context.Background(), Config{Store: store}); err != nil {
		t.Fatalf("ValidateConfiguration(): %v", err)
	}
}

func startConfigurationCapabilityServer(
	t *testing.T,
	store storage.Store,
) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{Store: store})
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
	return instance, fmt.Sprint(listener.Addr()), stop
}

func setUnsupportedRuntimeConfigurationAttribute(
	t *testing.T,
	store storage.Store,
	rawDN,
	attribute,
	value string,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(rawDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(attribute, stringValues(value))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set %s on %s: %v", attribute, rawDN, err)
	}
}
