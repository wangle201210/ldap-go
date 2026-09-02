package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	rwmOverlayConfigDN = "olcOverlay={0}rwm,olcDatabase={2}relay,cn=config"
	rwmMetaTargetDN    = "olcMetaSub={0}uri,olcDatabase={1}meta,cn=config"
)

func TestRWMUnsupportedRewriteDirectiveRejectedAtStartup(t *testing.T) {
	tests := []struct {
		name        string
		seed        func(*testing.T, storage.Store)
		dn          string
		attribute   string
		valid       string
		unsupported string
		directive   string
	}{
		{
			name:        "rwm overlay",
			seed:        seedRWMRelayConfiguration,
			dn:          rwmOverlayConfigDN,
			attribute:   "olcRwmRewrite",
			valid:       `{0}rwm-suffixmassage "dc=virtual,dc=test" "dc=example,dc=com"`,
			unsupported: `{1}rewriteEngine on`,
			directive:   "rewriteEngine",
		},
		{
			name:        "back-meta target",
			seed:        seedRWMBackMetaConfiguration,
			dn:          rwmMetaTargetDN,
			attribute:   "olcDbRewrite",
			valid:       `{0}suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
			unsupported: `{1}rewriteContext default`,
			directive:   "rewriteContext",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			test.seed(t, store)
			setRWMRewriteValues(t, store, test.dn, test.attribute, test.valid, test.unsupported)

			instance, err := New(Config{Store: store})
			if err == nil {
				instance.closeSQLBackends()
				t.Fatal("New() accepted an unsupported rewrite directive")
			}
			assertUnsupportedRWMRewriteError(t, err, test.dn, test.attribute, test.directive)
		})
	}
}

func TestRWMUnsupportedRewriteDirectiveOnlineModificationRollsBack(t *testing.T) {
	tests := []struct {
		name        string
		seed        func(*testing.T, storage.Store)
		dn          string
		attribute   string
		valid       string
		unsupported string
		directive   string
	}{
		{
			name:        "rwm overlay",
			seed:        seedRWMRelayConfiguration,
			dn:          rwmOverlayConfigDN,
			attribute:   "olcRwmRewrite",
			valid:       `{0}rwm-suffixmassage "dc=virtual,dc=test" "dc=example,dc=com"`,
			unsupported: `{1}rewriteRule "(.*)" "$1" :`,
			directive:   "rewriteRule",
		},
		{
			name:        "back-meta target",
			seed:        seedRWMBackMetaConfiguration,
			dn:          rwmMetaTargetDN,
			attribute:   "olcDbRewrite",
			valid:       `{0}suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
			unsupported: `{1}rewriteMap ldap lookup "ldap://127.0.0.1"`,
			directive:   "rewriteMap",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			test.seed(t, store)
			instance, address, stop := startRWMConfigurationServer(t, store)
			defer stop()

			client := bindConstraintClient(t, address, "cn=config", "config-secret")
			defer client.Close()
			activeRuntime := instance.runtime.Load()
			request := ldap.NewModifyRequest(test.dn, nil)
			request.Replace(test.attribute, []string{test.valid, test.unsupported})
			err := client.Modify(request)
			assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
			assertUnsupportedRWMRewriteError(t, err, test.dn, test.attribute, test.directive)

			if got := instance.runtime.Load(); got != activeRuntime {
				t.Fatal("failed configuration write activated a new runtime snapshot")
			}
			entry := readStoredEntry(t, store, test.dn)
			if got := byteValuesToStrings(entry.Values(test.attribute)); !slices.Equal(got, []string{test.valid}) {
				t.Fatalf("persisted %s after rollback = %q, want %q", test.attribute, got, test.valid)
			}
		})
	}
}

func TestRWMUnsupportedRewriteDirectiveOnlineAddRollsBack(t *testing.T) {
	tests := []struct {
		name      string
		seed      func(*testing.T, storage.Store)
		dn        string
		attribute string
		directive string
		request   func() *ldap.AddRequest
	}{
		{
			name:      "rwm overlay",
			seed:      seedRWMRelayConfiguration,
			dn:        rwmOverlayConfigDN,
			attribute: "olcRwmRewrite",
			directive: "rewriteContext",
			request: func() *ldap.AddRequest {
				request := ldap.NewAddRequest(rwmOverlayConfigDN, nil)
				request.Attribute("objectClass", []string{"olcOverlayConfig", "olcRwmConfig"})
				request.Attribute("olcOverlay", []string{"{0}rwm"})
				request.Attribute("olcRwmRewrite", []string{
					`{0}rwm-suffixmassage "dc=virtual,dc=test" "dc=example,dc=com"`,
					`{1}rewriteContext default`,
				})
				return request
			},
		},
		{
			name:      "back-meta target",
			seed:      seedRWMBackMetaConfiguration,
			dn:        rwmMetaTargetDN,
			attribute: "olcDbRewrite",
			directive: "rewriteRule",
			request: func() *ldap.AddRequest {
				request := ldap.NewAddRequest(rwmMetaTargetDN, nil)
				request.Attribute("objectClass", []string{"olcMetaTargetConfig"})
				request.Attribute("olcMetaSub", []string{"{0}uri"})
				request.Attribute("olcDbURI", []string{"ldap://127.0.0.1:1/dc=meta,dc=test"})
				request.Attribute("olcDbRewrite", []string{
					`{0}suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
					`{1}rewriteRule "(.*)" "$1" :`,
				})
				return request
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			test.seed(t, store)
			deleteRWMConfigurationEntry(t, store, test.dn)
			instance, address, stop := startRWMConfigurationServer(t, store)
			defer stop()

			client := bindConstraintClient(t, address, "cn=config", "config-secret")
			defer client.Close()
			activeRuntime := instance.runtime.Load()
			err := client.Add(test.request())
			assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
			assertUnsupportedRWMRewriteError(t, err, test.dn, test.attribute, test.directive)
			if got := instance.runtime.Load(); got != activeRuntime {
				t.Fatal("failed configuration Add activated a new runtime snapshot")
			}
			assertRWMConfigurationEntryAbsent(t, store, test.dn)
		})
	}
}

func seedRWMRelayConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	seedRelayConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed relay config database: %v", err)
	}
}

func seedRWMBackMetaConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: "olcDatabase={1}meta,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}meta")},
				{Description: "olcSuffix", Values: stringValues("dc=meta,dc=test")},
			},
		},
		{
			DN: rwmMetaTargetDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1:1/dc=meta,dc=test")},
				{Description: "olcDbRewrite", Values: stringValues(
					`{0}suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
				)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=meta,dc=test", "cn=config"})
	}); err != nil {
		t.Fatalf("seed back-meta RWM configuration: %v", err)
	}
}

func setRWMRewriteValues(
	t *testing.T,
	store storage.Store,
	rawDN string,
	attribute string,
	values ...string,
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
		entry.ReplaceValues(attribute, stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set %s on %s: %v", attribute, rawDN, err)
	}
}

func deleteRWMConfigurationEntry(t *testing.T, store storage.Store, rawDN string) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(rawDN)
		if err != nil {
			return err
		}
		return writer.Delete(dn)
	}); err != nil {
		t.Fatalf("delete configuration entry %s: %v", rawDN, err)
	}
}

func assertRWMConfigurationEntryAbsent(t *testing.T, store storage.Store, rawDN string) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("parse configuration DN %s: %v", rawDN, err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("read rolled-back configuration entry %s: %v, want entry not found", rawDN, err)
	}
}

func assertUnsupportedRWMRewriteError(
	t *testing.T,
	err error,
	dn string,
	attribute string,
	directive string,
) {
	t.Helper()
	for _, fragment := range []string{dn, attribute, "unsupported rewrite directive", directive} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not contain %q", err, fragment)
		}
	}
}

func startRWMConfigurationServer(
	t *testing.T,
	store storage.Store,
) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
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
