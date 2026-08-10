package server

import (
	"context"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadSockBackendRuntimeConfiguration(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}sock,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDbSocketPath", Values: stringValues("/run/example.sock")},
			{
				Description: "olcDbSocketExtensions",
				Values:      stringValues("binddn peername", "SSF", "connid"),
			},
		},
	}
	configuration, err := loadSockBackendRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadSockBackendRuntimeConfiguration(): %v", err)
	}
	wantExtensions := sockExtensionBindDN | sockExtensionPeerName |
		sockExtensionSSF | sockExtensionConnectionID
	if configuration.path != "/run/example.sock" ||
		configuration.extensions != wantExtensions {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestLoadSockBackendRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name       string
		paths      [][]byte
		extensions [][]byte
		want       string
	}{
		{name: "missing path", want: "exactly one value"},
		{name: "multiple paths", paths: stringValues("/one", "/two"), want: "exactly one value"},
		{name: "empty path", paths: stringValues(""), want: "is invalid"},
		{name: "NUL path", paths: [][]byte{[]byte("/tmp/a\x00b")}, want: "is invalid"},
		{name: "empty extension", paths: stringValues("/tmp/sock"), extensions: stringValues(""), want: "is empty"},
		{name: "unknown extension", paths: stringValues("/tmp/sock"), extensions: stringValues("tls"), want: "not one of"},
		{name: "broken order prefix", paths: stringValues("/tmp/sock"), extensions: stringValues("{0binddn"), want: "ordering prefix"},
		{name: "empty order prefix", paths: stringValues("/tmp/sock"), extensions: stringValues("{}binddn"), want: "ordering prefix"},
		{name: "nonnumeric order prefix", paths: stringValues("/tmp/sock"), extensions: stringValues("{x}binddn"), want: "ordering prefix"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{
				DN: "olcDatabase={1}sock,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDbSocketPath", Values: test.paths},
					{Description: "olcDbSocketExtensions", Values: test.extensions},
				},
			}
			_, err := loadSockBackendRuntimeConfiguration(entry)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestLoadRuntimeDatabasesTreatsSockAsDelegatedBackend(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "olcDatabase={1}sock,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}sock")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcDbSocketPath", Values: stringValues("/run/example.sock")},
			{Description: "olcDbSocketExtensions", Values: stringValues("binddn", "connid")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(configurationStoragePartition, entry, false)
	}); err != nil {
		t.Fatalf("seed sock database: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	dn, err := directory.ParseDN("uid=alice,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databaseForDN(&runtimeState{databases: databases}, dn)
	if database == nil || database.sockBackend == nil {
		t.Fatalf("sock database was not selected: %#v", databases)
	}
	if database.partition != "" || database.sockBackend.path != "/run/example.sock" {
		t.Fatalf("sock database runtime = %#v", database)
	}
}

func TestSockBackendRejectsAttachedOverlays(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}sock,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}sock")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcDbSocketPath", Values: stringValues("/run/example.sock")},
			},
		},
		{
			DN: "olcOverlay={0}pcache,olcDatabase={1}sock,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}pcache")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed sock backend with overlay: %v", err)
	}

	_, err := loadRuntimeDatabases(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "local overlays would be bypassed") {
		t.Fatalf("attached-overlay error = %v", err)
	}
}

func TestSockBackendPasswordModifyReturnsGeneratedPassword(t *testing.T) {
	fixture := startOpenLDAPSockFixture(t)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoSockReferenceConfiguration(t, store, fixture.path)
	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(openLDAPSockBindDN, openLDAPSockPassword); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	result, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		openLDAPSockBindDN,
		"",
		"",
	))
	if err != nil {
		t.Fatalf("PasswordModify(): %v", err)
	}
	if len(result.GeneratedPassword) != generatedPasswordLength {
		t.Fatalf(
			"generated password length = %d, want %d",
			len(result.GeneratedPassword),
			generatedPasswordLength,
		)
	}
	if err := client.Unbind(); err != nil {
		t.Fatalf("Unbind(): %v", err)
	}
	requests := fixture.take(t, 3)
	for index, command := range []string{"BIND", "EXTENDED", "UNBIND"} {
		if requests[index].command != command {
			t.Fatalf("request %d command = %q, want %q", index, requests[index].command, command)
		}
	}
}

func TestSockBackendRelaxRequiresManageACL(t *testing.T) {
	for _, test := range []struct {
		name      string
		access    string
		wantCode  uint16
		delegated bool
	}{
		{
			name:     "write is insufficient",
			access:   "{0}to * by * write",
			wantCode: ldap.LDAPResultInsufficientAccessRights,
		},
		{
			name:      "manage delegates",
			access:    "{0}to * by * manage",
			wantCode:  ldap.LDAPResultSuccess,
			delegated: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := startOpenLDAPSockFixture(t)
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedLDAPGoSockReferenceConfiguration(t, store, fixture.path)
			setSockBackendAccessForTest(t, store, test.access)
			address, stop := startServer(t, store, Config{})
			defer stop()

			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatalf("DialURL(): %v", err)
			}
			defer client.Close()
			if err := client.Bind(openLDAPSockBindDN, openLDAPSockPassword); err != nil {
				t.Fatalf("Bind(): %v", err)
			}
			if request := fixture.take(t, 1)[0]; request.command != "BIND" {
				t.Fatalf("setup socket command = %q, want BIND", request.command)
			}

			request := ldap.NewDelRequest(
				openLDAPSockValidationDN,
				[]ldap.Control{relaxLDAPControl()},
			)
			if code := monitorLDAPResultCode(client.Del(request)); code != test.wantCode {
				t.Fatalf("Relax Delete code = %d, want %d", code, test.wantCode)
			}
			if test.delegated {
				if request := fixture.take(t, 1)[0]; request.command != "DELETE" {
					t.Fatalf("socket command = %q, want DELETE", request.command)
				}
				return
			}
			select {
			case request := <-fixture.requests:
				t.Fatalf("Relax request unexpectedly delegated: %s", request.raw)
			case err := <-fixture.failures:
				t.Fatalf("socket fixture failed: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

func TestSockBackendHonorsDontUseCopyDisallow(t *testing.T) {
	fixture := startOpenLDAPSockFixture(t)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoSockReferenceConfiguration(t, store, fixture.path)
	setConfigurationAttributeForTest(
		t,
		store,
		"cn=config",
		"olcDisallows",
		"dontusecopy_non_critical",
	)
	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(openLDAPSockBindDN, openLDAPSockPassword); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	if request := fixture.take(t, 1)[0]; request.command != "BIND" {
		t.Fatalf("setup socket command = %q, want BIND", request.command)
	}

	request := ldap.NewSearchRequest(
		openLDAPSockBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		[]ldap.Control{&ldap.ControlString{
			ControlType: dontUseCopyControlOID,
		}},
	)
	if code := monitorLDAPResultCode(func() error {
		_, err := client.Search(request)
		return err
	}()); code != ldap.LDAPResultProtocolError {
		t.Fatalf("noncritical DontUseCopy code = %d, want protocolError", code)
	}
	select {
	case request := <-fixture.requests:
		t.Fatalf("DontUseCopy request unexpectedly delegated: %s", request.raw)
	case err := <-fixture.failures:
		t.Fatalf("socket fixture failed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func setSockBackendAccessForTest(
	t *testing.T,
	store storage.Store,
	access string,
) {
	t.Helper()
	setConfigurationAttributeForTest(
		t,
		store,
		"olcDatabase={1}sock,cn=config",
		"olcAccess",
		access,
	)
}

func setConfigurationAttributeForTest(
	t *testing.T,
	store storage.Store,
	dnValue,
	description,
	value string,
) {
	t.Helper()
	dn, err := directory.ParseDN(dnValue)
	if err != nil {
		t.Fatalf("ParseDN(%s): %v", dnValue, err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(description, stringValues(value))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set %s on %s: %v", description, dnValue, err)
	}
}
