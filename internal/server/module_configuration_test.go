package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestValidateOpenLDAPModuleConfigurationAcceptsImplementedDeclarations(t *testing.T) {
	loads := []string{
		"{0}back_mdb.la",
		"{1}back_LDAP.so",
		"{2}syncprov.la",
		"{3}proxycache.so",
		"{4}pw-sha2.la",
		`{5}/opt/openldap/pw-radius.so config="/etc/radius.conf"`,
		"{6}pw-totp.la",
		"{7}argon2.la",
		"{8}glue.la",
		"{9}allop.la",
	}
	store := moduleConfigurationStore(t, loads...)

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return validateOpenLDAPModuleConfiguration(reader)
	}); err != nil {
		t.Fatalf("implemented module declarations were rejected: %v", err)
	}
}

func TestValidateOpenLDAPModuleConfigurationAcceptsInertModulePath(t *testing.T) {
	store := moduleConfigurationStore(t)

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return validateOpenLDAPModuleConfiguration(reader)
	}); err != nil {
		t.Fatalf("inert olcModulePath metadata was rejected: %v", err)
	}
}

func TestValidateOpenLDAPModuleConfigurationRejectsNativeExternalModules(t *testing.T) {
	tests := []string{
		"custom-plugin.so",
		"lastbind.la",
		"back_perl.la",
		"/opt/openldap/syncprov.so",
		"/opt/openldap/back_mdb.la",
		"SYNCPROV.la",
	}
	for _, module := range tests {
		t.Run(module, func(t *testing.T) {
			store := moduleConfigurationStore(t, "{0}"+module)
			err := store.View(context.Background(), func(reader storage.Reader) error {
				return validateOpenLDAPModuleConfiguration(reader)
			})
			if err == nil {
				t.Fatalf("native external module %q was accepted", module)
			}
			for _, want := range []string{
				"cn=module{0},cn=config",
				"olcModuleLoad",
				module,
				"unsupported",
				"not loaded",
			} {
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
					t.Fatalf("validation error = %q, want substring %q", err, want)
				}
			}
		})
	}
}

func TestNewRejectsNativeOpenLDAPModuleConfiguration(t *testing.T) {
	store := moduleConfigurationStore(t, "{0}/opt/openldap/custom-plugin.so")

	instance, err := New(Config{Store: store})
	if err == nil {
		instance.closeSQLBackends()
		t.Fatal("New() silently accepted a native OpenLDAP module")
	}
	assertUnsupportedModuleConfigurationError(t, err, "custom-plugin.so")
}

func TestValidateConfigurationRejectsNativeOpenLDAPModule(t *testing.T) {
	store := moduleConfigurationStore(t, "{0}custom-plugin.la")

	_, err := ValidateConfiguration(context.Background(), Config{Store: store})
	if err == nil {
		t.Fatal("ValidateConfiguration() silently accepted a native OpenLDAP module")
	}
	assertUnsupportedModuleConfigurationError(t, err, "custom-plugin.la")
}

func TestNewAndValidateConfigurationAcceptImplementedModuleDeclarations(t *testing.T) {
	loads := []string{"{0}back_mdb.la", "{1}syncprov.la", "{2}pw-pbkdf2.la"}

	validateStore := moduleConfigurationStore(t, loads...)
	if _, err := ValidateConfiguration(
		context.Background(),
		Config{Store: validateStore},
	); err != nil {
		t.Fatalf("ValidateConfiguration() rejected implemented modules: %v", err)
	}

	startStore := moduleConfigurationStore(t, loads...)
	instance, err := New(Config{Store: startStore})
	if err != nil {
		t.Fatalf("New() rejected implemented modules: %v", err)
	}
	instance.closeSQLBackends()
}

func TestOnlineConfigurationRejectsNativeModuleAndRollsBack(t *testing.T) {
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

	const moduleDN = "cn=module{0},cn=config"
	request := ldap.NewAddRequest(moduleDN, nil)
	request.Attribute("objectClass", []string{"olcModuleList"})
	request.Attribute("cn", []string{"module{0}"})
	request.Attribute("olcModuleLoad", []string{"{0}/opt/openldap/custom-plugin.so"})
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

	dn, parseErr := directory.ParseDN(moduleDN)
	if parseErr != nil {
		t.Fatalf("ParseDN(%q): %v", moduleDN, parseErr)
	}
	readErr := store.View(context.Background(), func(reader storage.Reader) error {
		_, getErr := reader.GetIn(configurationStoragePartition, dn)
		return getErr
	})
	switch {
	case readErr == nil:
		t.Error("rejected native module declaration was committed to cn=config")
	case !errors.Is(readErr, storage.ErrEntryNotFound):
		t.Fatalf("read rejected module declaration: %v", readErr)
	}
}

func TestOnlineConfigurationRejectsNativeModuleModifyAndRollsBack(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(configurationStoragePartition, directory.Entry{
			DN: "cn=module{0},cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcModuleList")},
				{Description: "cn", Values: stringValues("module{0}")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed empty module entry: %v", err)
	}

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

	const moduleDN = "cn=module{0},cn=config"
	request := ldap.NewModifyRequest(moduleDN, nil)
	request.Add("olcModuleLoad", []string{"{0}custom-plugin.la"})
	err = client.Modify(request)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Errorf(
			"online Modify error = %v, want LDAP constraintViolation(%d)",
			err,
			ldap.LDAPResultConstraintViolation,
		)
	}

	dn, parseErr := directory.ParseDN(moduleDN)
	if parseErr != nil {
		t.Fatalf("ParseDN(%q): %v", moduleDN, parseErr)
	}
	readErr := store.View(context.Background(), func(reader storage.Reader) error {
		entry, getErr := reader.GetIn(configurationStoragePartition, dn)
		if getErr != nil {
			return getErr
		}
		if entry.HasAttribute("olcModuleLoad") {
			return errors.New("rejected native module modification was committed to cn=config")
		}
		return nil
	})
	if readErr != nil {
		t.Error(readErr)
	}
}

func TestOnlineConfigurationAcceptsImplementedModuleDeclaration(t *testing.T) {
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

	request := ldap.NewAddRequest("cn=module{0},cn=config", nil)
	request.Attribute("objectClass", []string{"olcModuleList"})
	request.Attribute("cn", []string{"module{0}"})
	request.Attribute("olcModuleLoad", []string{"{0}syncprov.la"})
	if err := client.Add(request); err != nil {
		t.Fatalf("online Add implemented module declaration: %v", err)
	}
}

func TestOpenLDAPDynamicModuleSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}

	bconfig := readModuleContractSource(t, sourceRoot, "servers", "slapd", "bconfig.c")
	for _, anchor := range []string{
		"case CFG_MODLOAD:",
		"module_load(c->argv[1]",
		"case CFG_MODPATH:",
		"module_path(c->argv[1])",
	} {
		if !strings.Contains(bconfig, anchor) {
			t.Errorf("OpenLDAP bconfig.c is missing %q", anchor)
		}
	}

	module := readModuleContractSource(t, sourceRoot, "servers", "slapd", "module.c")
	for _, anchor := range []string{
		`strncasecmp( file_name, "back_", 5 )`,
		"backend_info( name ) != NULL",
		"overlay_find( file_name ) != NULL",
		"lt_dlopenext(file)",
		`lt_dlsym(module->lib, "init_module")`,
		"initialize(argc, argv)",
	} {
		if !strings.Contains(module, anchor) {
			t.Errorf("OpenLDAP module.c is missing %q", anchor)
		}
	}
}

func moduleConfigurationStore(t *testing.T, loads ...string) storage.Store {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		attributes := []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcModuleList")},
			{Description: "cn", Values: stringValues("module{0}")},
			{Description: "olcModulePath", Values: stringValues("/opt/openldap/modules")},
		}
		if len(loads) > 0 {
			attributes = append(attributes, directory.Attribute{
				Description: "olcModuleLoad",
				Values:      stringValues(loads...),
			})
		}
		return writer.PutIn(configurationStoragePartition, directory.Entry{
			DN:         "cn=module{0},cn=config",
			Attributes: attributes,
		}, false)
	}); err != nil {
		t.Fatalf("seed module configuration: %v", err)
	}
	return store
}

func assertUnsupportedModuleConfigurationError(t *testing.T, err error, module string) {
	t.Helper()
	for _, want := range []string{"olcModuleLoad", module, "unsupported", "not loaded"} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Fatalf("module configuration error = %q, want substring %q", err, want)
		}
	}
}

func readModuleContractSource(t *testing.T, root string, elements ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{root}, elements...)...)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OpenLDAP source %s: %v", path, err)
	}
	return string(contents)
}
