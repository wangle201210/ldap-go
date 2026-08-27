package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSupportedRuntimeOverlayType(t *testing.T) {
	t.Parallel()

	supported := []string{
		"accesslog",
		"auditlog",
		"autoca",
		"chain",
		"collect",
		"constraint",
		"dds",
		"deref",
		"dyngroup",
		"dynlist",
		"glue",
		"homedir",
		"memberof",
		"nestgroup",
		"otp",
		"pbind",
		"pcache",
		"ppolicy",
		"refint",
		"remoteauth",
		"retcode",
		"rwm",
		"seqmod",
		"sock",
		"sssvlv",
		"syncprov",
		"totp",
		"translucent",
		"unique",
		"valsort",
	}
	for _, overlayType := range supported {
		overlayType := overlayType
		t.Run(overlayType, func(t *testing.T) {
			t.Parallel()
			got, ok := supportedRuntimeOverlayType(" {12}" + strings.ToUpper(overlayType) + " ")
			if !ok {
				t.Fatalf("supportedRuntimeOverlayType() rejected %q", overlayType)
			}
			if got != overlayType {
				t.Fatalf("supportedRuntimeOverlayType() = %q, want %q", got, overlayType)
			}
		})
	}
}

func TestLoadRuntimeDatabasesAcceptsExplicitGlueOverlay(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedCapabilityConfiguration(
		t,
		store,
		capabilityDatabaseEntry("{1}mdb", "dc=example,dc=test"),
		capabilityOverlayEntry("{0}glue"),
	)
	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("load explicit glue overlay: %v", err)
	}
	database := databaseForDN(
		&runtimeState{databases: databases},
		staticRuntimeDN("dc=example,dc=test"),
	)
	if database == nil || !database.explicitGlue {
		t.Fatalf("explicit glue database = %#v", database)
	}
	if !slices.Contains(runtimeDatabaseOverlayNames(*database), "glue") {
		t.Fatalf("Monitor overlay names = %q", runtimeDatabaseOverlayNames(*database))
	}
}

func TestSupportedRuntimeOverlayAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  string
	}{
		{value: "proxycache", want: "pcache"},
		{value: "{2}PROXYCACHE", want: "pcache"},
		{value: "pcache", want: "pcache"},
		{value: "otp", want: "otp"},
		{value: "totp", want: "totp"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			got, ok := supportedRuntimeOverlayType(test.value)
			if !ok || got != test.want {
				t.Fatalf(
					"supportedRuntimeOverlayType(%q) = (%q, %t), want (%q, true)",
					test.value,
					got,
					ok,
					test.want,
				)
			}
		})
	}
}

func TestRequireSupportedRuntimeOverlayTypeRejectsUnknown(t *testing.T) {
	t.Parallel()

	const entryDN = "olcOverlay={0}unknown,olcDatabase={1}mdb,cn=config"
	if _, err := requireSupportedRuntimeOverlayType(entryDN, "{0}UNKNOWN"); err == nil {
		t.Fatal("requireSupportedRuntimeOverlayType() accepted an unknown overlay")
	} else {
		for _, fragment := range []string{entryDN, `unsupported OpenLDAP overlay "unknown"`} {
			if !strings.Contains(err.Error(), fragment) {
				t.Fatalf("error %q does not contain %q", err, fragment)
			}
		}
	}
}

func TestLoadRuntimeDatabasesRejectsUnsupportedOverlay(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	overlay := capabilityOverlayEntry("{0}unknown")
	seedCapabilityConfiguration(
		t,
		store,
		capabilityDatabaseEntry("{1}mdb", "dc=example,dc=test"),
		overlay,
	)

	_, err := loadRuntimeDatabases(context.Background(), store)
	assertUnsupportedOverlayError(t, err, overlay.DN, "unknown")
}

func TestNewRejectsUnsupportedOverlay(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	overlay := capabilityOverlayEntry("{0}unknown")
	seedCapabilityConfiguration(
		t,
		store,
		capabilityDatabaseEntry("{1}mdb", "dc=example,dc=test"),
		overlay,
	)

	instance, err := New(Config{Store: store})
	if err == nil {
		instance.closeSQLBackends()
		t.Fatal("New() accepted an unsupported overlay")
	}
	assertUnsupportedOverlayError(t, err, overlay.DN, "unknown")
}

func TestValidateConfigurationRejectsUnsupportedOverlay(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	overlay := capabilityOverlayEntry("{0}unknown")
	seedCapabilityConfiguration(
		t,
		store,
		capabilityDatabaseEntry("{1}mdb", "dc=example,dc=test"),
		overlay,
	)

	_, err := ValidateConfiguration(context.Background(), Config{Store: store})
	assertUnsupportedOverlayError(t, err, overlay.DN, "unknown")
}

func TestOnlineConfigurationRejectsUnsupportedOverlay(t *testing.T) {
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

	overlay := capabilityOverlayEntry("{0}unknown")
	request := ldap.NewAddRequest(overlay.DN, nil)
	request.Attribute("objectClass", []string{"olcOverlayConfig"})
	request.Attribute("olcOverlay", []string{"{0}unknown"})
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

	dn, parseErr := directory.ParseDN(overlay.DN)
	if parseErr != nil {
		t.Fatalf("ParseDN(%q): %v", overlay.DN, parseErr)
	}
	readErr := store.View(context.Background(), func(reader storage.Reader) error {
		_, getErr := reader.GetIn(configurationStoragePartition, dn)
		return getErr
	})
	switch {
	case readErr == nil:
		t.Error("rejected unsupported overlay entry was committed to cn=config")
	case !errors.Is(readErr, storage.ErrEntryNotFound):
		t.Fatalf("read rejected overlay entry: %v", readErr)
	}
}

func capabilityOverlayEntry(value string) directory.Entry {
	return directory.Entry{
		DN: "olcOverlay=" + value + ",olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues(value)},
		},
	}
}

func assertUnsupportedOverlayError(
	t *testing.T,
	err error,
	entryDN string,
	overlayType string,
) {
	t.Helper()
	if err == nil {
		t.Fatal("runtime configuration accepted an unsupported overlay")
	}
	for _, want := range []string{entryDN, overlayType, "unsupported"} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Fatalf("runtime error = %q, want substring %q", err, want)
		}
	}
}
