package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestLDAPClientOpenLDAPRADIUSPasswordBind(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "ldap-radius-shared"
		username     = "external-alice"
		password     = "external-secret"
		nas          = "ldap-radius.example.test"
	)
	requests := make(chan [3]string, 12)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			request := [3]string{
				rfc2865.UserName_GetString(packet),
				rfc2865.UserPassword_GetString(packet),
				rfc2865.NASIdentifier_GetString(packet),
			}
			requests <- request
			if request[0] == username && request[1] == password {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	ldifInput := "dn: dc=example,dc=com\n" +
		"objectClass: domain\n" +
		"dc: example\n\n" +
		"dn: ou=people,dc=example,dc=com\n" +
		"objectClass: organizationalUnit\n" +
		"ou: people\n\n" +
		"dn: " + aliceDN + "\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: alice\n" +
		"cn: Alice Example\n" +
		"sn: Example\n" +
		"userPassword: " + auth.OpenLDAPRADIUSHashScheme + username + "\n\n"
	result, err := migration.ImportLDIF(
		t.Context(),
		store,
		bytes.NewBufferString(ldifInput),
		migration.ImportOptions{},
	)
	if err != nil {
		t.Fatalf("import RADIUS password LDIF: %v", err)
	}
	if result.Entries != 3 {
		t.Fatalf("imported RADIUS LDIF entries = %d, want 3", result.Entries)
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=module{0},cn=config",
			Attributes: []directory.Attribute{
				{Description: "cn", Values: stringValues("module{0}")},
				{
					Description: "olcModuleLoad",
					Values: stringValues(
						`{0}pw-radius.la config="` + radiusConfig + `"`,
					),
				},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed RADIUS password: %v", err)
	}
	seedSASLPlainConfiguration(t, store, "none")
	address, stopLDAP := startServer(t, store, Config{
		RADIUSNASIdentifier: nas,
		RootDN:              "cn=admin,dc=example,dc=com",
		RootPassword:        []byte("admin-secret"),
	})
	defer stopLDAP()

	assertBindPassword(t, address, aliceDN, password, true)
	if got := <-requests; got != [3]string{username, password, nas} {
		t.Fatalf("RADIUS request = %q", got)
	}
	assertBindPassword(t, address, aliceDN, "wrong", false)
	if got := <-requests; got[0] != username || got[1] != "wrong" || got[2] != nas {
		t.Fatalf("wrong-password RADIUS request = %q", got)
	}

	raw, err := dialAndBindSASLPlain(address, "", "alice", password)
	if err != nil {
		t.Fatalf("RADIUS SASL PLAIN Bind: %v", err)
	}
	_ = raw.Close()
	if got := <-requests; got != [3]string{username, password, nas} {
		t.Fatalf("SASL PLAIN RADIUS request = %q", got)
	}
	denied, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial denied password modify client: %v", err)
	}
	if err := denied.Bind(aliceDN, password); err != nil {
		t.Fatalf("bind denied password modify client: %v", err)
	}
	if got := <-requests; got != [3]string{username, password, nas} {
		t.Fatalf("denied-client RADIUS request = %q", got)
	}
	_, err = denied.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		password,
		"must-not-be-stored",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)
	_ = denied.Close()
	select {
	case got := <-requests:
		t.Fatalf("ACL-denied Password Modify contacted RADIUS: %q", got)
	case <-time.After(100 * time.Millisecond):
	}

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial password modify client: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("admin bind before RADIUS Password Modify: %v", err)
	}
	if _, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		aliceDN,
		password,
		"replacement-secret",
	)); err != nil {
		t.Fatalf("RADIUS Password Modify: %v", err)
	}
	if got := <-requests; got != [3]string{username, password, nas} {
		t.Fatalf("old-password RADIUS request = %q", got)
	}
	assertBindPassword(t, address, aliceDN, "replacement-secret", true)
}

func TestOpenLDAPRADIUSOnlineModuleActivation(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-online-shared"
		username     = "radius-online-user"
		password     = "radius-online-password"
	)
	requests := make(chan string, 4)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			requests <- rfc2865.UserName_GetString(packet)
			return radius.CodeAccessAccept
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(aliceDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"userPassword",
			stringValues(auth.OpenLDAPRADIUSHashScheme+username),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed online RADIUS password: %v", err)
	}

	address, stopLDAP := startServer(t, store, Config{RADIUSNASIdentifier: "online-nas"})
	defer stopLDAP()
	assertBindPassword(t, address, aliceDN, password, false)
	select {
	case username := <-requests:
		t.Fatalf("disabled RADIUS module contacted user %q", username)
	default:
	}

	configuration, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial cn=config: %v", err)
	}
	defer configuration.Close()
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind cn=config: %v", err)
	}
	bypass := ldap.NewModifyRequest("cn=config", nil)
	bypass.Add("objectClass", []string{"extensibleObject"})
	bypass.Add("olcModulePath", []string{"/usr/lib/openldap"})
	bypass.Add("olcModuleLoad", []string{
		`{0}pw-radius.la config="` + radiusConfig + `"`,
	})
	assertLDAPResultCode(t, configuration.Modify(bypass), ldap.LDAPResultOther)
	bypassAdd := ldap.NewAddRequest("cn=module-bypass,cn=config", nil)
	bypassAdd.Attribute("objectClass", []string{"olcModuleList"})
	bypassAdd.Attribute("cn", []string{"module-bypass"})
	bypassAdd.Attribute("olcModulePath", []string{"/usr/lib/openldap"})
	bypassAdd.Attribute("olcModuleLoad", []string{
		`{0}pw-radius.la config="` + radiusConfig + `"`,
	})
	assertLDAPResultCode(t, configuration.Add(bypassAdd), ldap.LDAPResultOther)
	module := ldap.NewAddRequest("cn=module{0},cn=config", nil)
	module.Attribute("objectClass", []string{"olcModuleList"})
	module.Attribute("cn", []string{"module{0}"})
	module.Attribute("olcModuleLoad", []string{
		`{0}pw-radius.la config="` + radiusConfig + `"`,
	})
	if err := configuration.Add(module); err != nil {
		t.Fatalf("online Add pw-radius module: %v", err)
	}

	assertBindPassword(t, address, aliceDN, password, true)
	select {
	case got := <-requests:
		if got != username {
			t.Fatalf("online RADIUS username = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("online RADIUS request did not arrive")
	}

	duplicate := ldap.NewAddRequest("cn=module{1},cn=config", nil)
	duplicate.Attribute("objectClass", []string{"olcModuleList"})
	duplicate.Attribute("cn", []string{"module{1}"})
	duplicate.Attribute("olcModuleLoad", []string{
		`{0}pw-radius.la config="` + radiusConfig + `"`,
	})
	assertLDAPResultCode(
		t,
		configuration.Add(duplicate),
		ldap.LDAPResultConstraintViolation,
	)
	duplicateDN, err := directory.ParseDN("cn=module{1},cn=config")
	if err != nil {
		t.Fatalf("parse duplicate module DN: %v", err)
	}
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		_, err := reader.Get(duplicateDN)
		return err
	}); !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("duplicate module rollback error = %v", err)
	}

	removeLoad := ldap.NewModifyRequest("cn=module{0},cn=config", nil)
	removeLoad.Delete("olcModuleLoad", nil)
	assertLDAPResultCode(t, configuration.Modify(removeLoad), ldap.LDAPResultOther)
	replaceLoad := ldap.NewModifyRequest("cn=module{0},cn=config", nil)
	replaceLoad.Replace("olcModuleLoad", []string{"{0}pw-radius.la"})
	assertLDAPResultCode(t, configuration.Modify(replaceLoad), ldap.LDAPResultOther)
	addPath := ldap.NewModifyRequest("cn=module{0},cn=config", nil)
	addPath.Add("olcModulePath", []string{"/usr/lib/openldap"})
	assertLDAPResultCode(t, configuration.Modify(addPath), ldap.LDAPResultOther)
	emptyModule := ldap.NewAddRequest("cn=module{2},cn=config", nil)
	emptyModule.Attribute("objectClass", []string{"1.3.6.1.4.1.4203.1.12.2.4.0.8"})
	emptyModule.Attribute("cn", []string{"module{2}"})
	if err := configuration.Add(emptyModule); err != nil {
		t.Fatalf("online Add empty module list: %v", err)
	}
	addEmptyPath := ldap.NewModifyRequest("cn=module{2},cn=config", nil)
	addEmptyPath.Add("olcModulePath", []string{"/usr/lib/openldap"})
	assertLDAPResultCode(t, configuration.Modify(addEmptyPath), ldap.LDAPResultOther)
	assertLDAPResultCode(
		t,
		configuration.Del(ldap.NewDelRequest("cn=module{0},cn=config", nil)),
		ldap.LDAPResultUnwillingToPerform,
	)
	assertBindPassword(t, address, aliceDN, password, true)
	select {
	case got := <-requests:
		if got != username {
			t.Fatalf("RADIUS username after rejected unload = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("RADIUS module was disabled after rejected unload")
	}
}

func TestOpenLDAPRADIUSBindPreservesPasswordValueShortCircuit(t *testing.T) {
	t.Parallel()

	const sharedSecret = "radius-short-circuit-shared"
	usernames := make(chan string, 4)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			username := rfc2865.UserName_GetString(packet)
			usernames <- username
			if username == "first-radius-user" {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}

	t.Run("local password first", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		if err := store.Update(t.Context(), func(writer storage.Writer) error {
			dn, _ := directory.ParseDN(aliceDN)
			entry, err := writer.Get(dn)
			if err != nil {
				return err
			}
			local := bytes.Clone(entry.Values("userPassword")[0])
			if !auth.VerifyPassword(local, []byte("secret")) {
				return errors.New("seed password does not verify")
			}
			entry.ReplaceValues("userPassword", [][]byte{
				local,
				[]byte(auth.OpenLDAPRADIUSHashScheme + "must-not-receive"),
			})
			return writer.Put(entry, true)
		}); err != nil {
			t.Fatalf("seed local-first passwords: %v", err)
		}
		address, stopLDAP := startServer(t, store, Config{
			RADIUSConfigPath: radiusConfig, RADIUSNASIdentifier: "nas",
		})
		defer stopLDAP()
		assertBindPassword(t, address, aliceDN, "secret", true)
		select {
		case username := <-usernames:
			t.Fatalf("local-first Bind contacted RADIUS user %q", username)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("first external password succeeds", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		if err := store.Update(t.Context(), func(writer storage.Writer) error {
			dn, _ := directory.ParseDN(aliceDN)
			entry, err := writer.Get(dn)
			if err != nil {
				return err
			}
			entry.ReplaceValues("userPassword", stringValues(
				auth.OpenLDAPRADIUSHashScheme+"first-radius-user",
				auth.OpenLDAPRADIUSHashScheme+"must-not-receive",
			))
			return writer.Put(entry, true)
		}); err != nil {
			t.Fatalf("seed external passwords: %v", err)
		}
		address, stopLDAP := startServer(t, store, Config{
			RADIUSConfigPath: radiusConfig, RADIUSNASIdentifier: "nas",
		})
		defer stopLDAP()
		assertBindPassword(t, address, aliceDN, "external-secret", true)
		select {
		case username := <-usernames:
			if username != "first-radius-user" {
				t.Fatalf("first RADIUS username = %q", username)
			}
		case <-time.After(time.Second):
			t.Fatal("first RADIUS request did not arrive")
		}
		select {
		case username := <-usernames:
			t.Fatalf("successful external Bind contacted later user %q", username)
		case <-time.After(100 * time.Millisecond):
		}
	})
}

func TestLoadExternalPasswordRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=module{0},cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcModuleLoad",
				Values: stringValues(
					`{0}/usr/lib/openldap/pw-radius.so config="/path with spaces/radius.conf"`,
				),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed module configuration: %v", err)
	}
	var configuration externalPasswordRuntimeConfiguration
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		var err error
		configuration, err = loadExternalPasswordRuntimeConfiguration(
			reader,
			Config{RADIUSNASIdentifier: "nas"},
		)
		return err
	}); err != nil {
		t.Fatalf("loadExternalPasswordRuntimeConfiguration(): %v", err)
	}
	if !configuration.radiusEnabled ||
		configuration.radiusConfigPath != "/path with spaces/radius.conf" ||
		configuration.radiusNASIdentifier != "nas" {
		t.Fatalf("external password configuration = %#v", configuration)
	}
}

func TestLoadExternalPasswordRuntimeConfigurationUsesFirstConfigArgument(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=module{0},cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcModuleLoad",
				Values: stringValues(
					`{0}pw-radius.la config=/first/radius.conf CONFIG=/ignored/radius.conf`,
				),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed module configuration: %v", err)
	}
	var configuration externalPasswordRuntimeConfiguration
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		var err error
		configuration, err = loadExternalPasswordRuntimeConfiguration(
			reader,
			Config{RADIUSNASIdentifier: "nas"},
		)
		return err
	}); err != nil {
		t.Fatalf("loadExternalPasswordRuntimeConfiguration(): %v", err)
	}
	if configuration.radiusConfigPath != "/first/radius.conf" {
		t.Fatalf("RADIUS config path = %q, want first argument", configuration.radiusConfigPath)
	}
}

func TestLoadExternalPasswordRuntimeConfigurationRejectsUnknownArgument(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=module{0},cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcModuleLoad",
				Values:      stringValues(`{0}pw-radius.la timeout=5`),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed module configuration: %v", err)
	}
	err := store.View(t.Context(), func(reader storage.Reader) error {
		_, err := loadExternalPasswordRuntimeConfiguration(
			reader,
			Config{RADIUSNASIdentifier: "nas"},
		)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "unknown argument") {
		t.Fatalf("unknown pw-radius argument error = %v", err)
	}
}

func TestLoadExternalPasswordRuntimeConfigurationRequiresActivation(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	var disabled, enabled externalPasswordRuntimeConfiguration
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		var err error
		disabled, err = loadExternalPasswordRuntimeConfiguration(
			reader,
			Config{RADIUSNASIdentifier: "nas"},
		)
		if err != nil {
			return err
		}
		enabled, err = loadExternalPasswordRuntimeConfiguration(
			reader,
			Config{
				RADIUSConfigPath:    "/operator/radius.conf",
				RADIUSNASIdentifier: "nas",
			},
		)
		return err
	}); err != nil {
		t.Fatalf("load external password configuration: %v", err)
	}
	if disabled.radiusEnabled || disabled.radiusConfigPath != "" {
		t.Fatalf("unconfigured RADIUS runtime = %#v", disabled)
	}
	if !enabled.radiusEnabled || enabled.radiusConfigPath != "/operator/radius.conf" {
		t.Fatalf("explicit RADIUS runtime = %#v", enabled)
	}
}

func TestOpenLDAPRADIUSBindDoesNotHoldDirectoryWriteTransaction(t *testing.T) {
	t.Parallel()

	const sharedSecret = "radius-delayed-shared"
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseRequest := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseRequest()
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(*radius.Packet) radius.Code {
			started <- struct{}{}
			<-release
			return radius.CodeAccessAccept
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(aliceDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"userPassword",
			stringValues(auth.OpenLDAPRADIUSHashScheme+"delayed-user"),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed delayed RADIUS password: %v", err)
	}
	address, stopLDAP := startServer(t, store, Config{
		RADIUSConfigPath:    radiusConfig,
		RADIUSNASIdentifier: "nas",
	})
	defer stopLDAP()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial ldap-go: %v", err)
	}
	defer client.Close()
	bindDone := make(chan error, 1)
	go func() { bindDone <- client.Bind(aliceDN, "delayed-password") }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("RADIUS request did not start")
	}

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- store.Update(context.Background(), func(writer storage.Writer) error {
			return writer.SetNamingContexts([]string{"dc=example,dc=com"})
		})
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("concurrent directory write: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("RADIUS Bind held the directory write transaction")
	}
	releaseRequest()
	if err := <-bindDone; err != nil {
		t.Fatalf("RADIUS Bind: %v", err)
	}
}

func TestOpenLDAPRADIUSVerificationIsGloballySerialized(t *testing.T) {
	t.Parallel()

	const sharedSecret = "radius-serialized-shared"
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(*radius.Packet) radius.Code {
			started <- struct{}{}
			<-release
			return radius.CodeAccessAccept
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	stores := []storage.Store{storage.NewMemory(), storage.NewMemory()}
	for _, store := range stores {
		store := store
		t.Cleanup(func() { _ = store.Close() })
	}
	servers := make([]*Server, len(stores))
	for index, store := range stores {
		var err error
		servers[index], err = New(Config{Store: store})
		if err != nil {
			t.Fatalf("New(server %d): %v", index, err)
		}
	}
	runtime := &runtimeState{externalPasswords: externalPasswordRuntimeConfiguration{
		radiusEnabled:       true,
		radiusConfigPath:    radiusConfig,
		radiusNASIdentifier: "nas",
	}}
	results := make(chan bool, 2)
	verify := func(server *Server) {
		results <- server.verifyStoredPassword(
			context.Background(),
			runtime,
			[]byte(auth.OpenLDAPRADIUSHashScheme+"serialized-user"),
			[]byte("serialized-password"),
		)
	}
	go verify(servers[0])
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first RADIUS verification did not start")
	}
	go verify(servers[1])
	select {
	case <-started:
		t.Fatal("second RADIUS verification started before the first completed")
	case <-time.After(100 * time.Millisecond):
	}
	releaseAll()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("second RADIUS verification did not start after the first completed")
	}
	for range 2 {
		select {
		case ok := <-results:
			if !ok {
				t.Fatal("serialized RADIUS verification failed")
			}
		case <-time.After(time.Second):
			t.Fatal("serialized RADIUS verification did not finish")
		}
	}
}

func TestOpenLDAPRADIUSPasswordPolicyRejectsBeforeNetwork(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-ppolicy-preflight-shared"
		username     = "radius-ppolicy-preflight-user"
		password     = "radius-ppolicy-preflight-password"
	)
	requests := make(chan struct{}, 2)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(*radius.Packet) radius.Code {
			requests <- struct{}{}
			return radius.CodeAccessAccept
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, []directory.Attribute{{
		Description: "pwdMinAge", Values: stringValues("300"),
	}}, nil)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"userPassword":   stringValues(auth.OpenLDAPRADIUSHashScheme + username),
		"pwdChangedTime": stringValues(formatPasswordPolicyTime(time.Now())),
	})
	address, stopLDAP := startServer(t, store, Config{
		RADIUSConfigPath: radiusConfig, RADIUSNASIdentifier: "preflight-nas",
	})
	defer stopLDAP()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial ldap-go: %v", err)
	}
	defer client.Close()
	if err := client.Bind(aliceDN, password); err != nil {
		t.Fatalf("RADIUS Bind: %v", err)
	}
	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("RADIUS Bind request did not arrive")
	}
	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		password,
		"replacement-password",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
	select {
	case <-requests:
		t.Fatal("pwdMinAge-rejected password change contacted RADIUS")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestOpenLDAPRADIUSPasswordHistoryStateChangeFailsBusy(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-history-state-shared"
		initialUser  = "radius-history-initial"
		matchingUser = "radius-history-matching"
		candidate    = "radius-history-candidate"
	)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseInitial := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseInitial()
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			username := rfc2865.UserName_GetString(packet)
			password := rfc2865.UserPassword_GetString(packet)
			if username == initialUser {
				started <- struct{}{}
				<-release
				return radius.CodeAccessReject
			}
			if username == matchingUser && password == candidate {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, []directory.Attribute{{
		Description: "pwdInHistory", Values: stringValues("1"),
	}}, nil)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"pwdHistory": {buildPasswordHistoryValue(
			time.Now().Add(-time.Minute),
			[]byte(auth.OpenLDAPRADIUSHashScheme+initialUser),
		)},
	})
	instance, address, stopLDAP := startSeqmodServer(t, store, Config{
		RADIUSConfigPath: radiusConfig, RADIUSNASIdentifier: "history-nas",
	})
	defer stopLDAP()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial ldap-go: %v", err)
	}
	defer client.Close()
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("local Bind: %v", err)
	}
	request := ldap.NewPasswordModifyRequest("", "secret", candidate)
	modifyDone := make(chan error, 1)
	go func() {
		_, err := client.PasswordModify(request)
		modifyDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("initial history RADIUS verification did not start")
	}
	alice, _ := directory.ParseDN(aliceDN)
	database := databaseForDN(instance.runtime.Load(), alice)
	if database == nil {
		t.Fatal("RADIUS history test database was not loaded")
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		entry, err := tx.Get(alice)
		if err != nil {
			return err
		}
		entry.ReplaceValues("pwdHistory", [][]byte{buildPasswordHistoryValue(
			time.Now(),
			[]byte(auth.OpenLDAPRADIUSHashScheme+matchingUser),
		)})
		return tx.Put(entry, true)
	}); err != nil {
		t.Fatalf("replace concurrent RADIUS history: %v", err)
	}
	releaseInitial()
	select {
	case err := <-modifyDone:
		assertLDAPResultCode(t, err, ldap.LDAPResultBusy)
	case <-time.After(time.Second):
		t.Fatal("password change did not reject stale RADIUS verification")
	}
	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"secret",
		candidate,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
}

func TestOpenLDAPRADIUSPasswordModifyInTransaction(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-transaction-shared"
		username     = "radius-transaction-user"
		password     = "radius-transaction-password"
	)
	requests := make(chan struct{}, 4)
	blockCommit := atomic.Bool{}
	releaseCommit := make(chan struct{})
	var releaseCommitOnce sync.Once
	allowCommit := func() { releaseCommitOnce.Do(func() { close(releaseCommit) }) }
	defer allowCommit()
	expectRequest := func() {
		select {
		case <-requests:
		case <-time.After(time.Second):
			t.Fatal("RADIUS transaction verification did not arrive")
		}
	}
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			requests <- struct{}{}
			if blockCommit.Load() {
				<-releaseCommit
			}
			if rfc2865.UserName_GetString(packet) == username &&
				rfc2865.UserPassword_GetString(packet) == password {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(aliceDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"userPassword",
			stringValues(auth.OpenLDAPRADIUSHashScheme+username),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed transaction RADIUS password: %v", err)
	}
	address, stopLDAP := startServer(t, store, Config{
		RADIUSConfigPath:    radiusConfig,
		RADIUSNASIdentifier: "transaction-nas",
	})
	defer stopLDAP()
	connection := dialAndBindRawLDAP(t, address, aliceDN, password)
	defer connection.Close()
	expectRequest()
	blockCommit.Store(true)

	identifier := startRawLDAPTransaction(t, connection, 2)
	queued := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawModifyReplaceRequest(aliceDN, "description", "transaction preflight"),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, queued, int64(ldap.LDAPResultSuccess))
	queued = sendRawLDAPOperation(
		t,
		connection,
		4,
		rawExtendedRequest(
			passwordModifyOID,
			rawPasswordModifyRequestValue(
				[]byte(password),
				[]byte("transaction-replacement"),
			),
			true,
		),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, queued, int64(ldap.LDAPResultSuccess))
	select {
	case <-requests:
		t.Fatal("transaction queueing contacted RADIUS before commit")
	case <-time.After(100 * time.Millisecond):
	}
	commitDone := make(chan *ber.Packet, 1)
	go func() {
		commitDone <- endRawLDAPTransaction(t, connection, 5, true, identifier)
	}()
	expectRequest()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- store.Update(context.Background(), func(writer storage.Writer) error {
			return writer.SetNamingContexts([]string{"dc=example,dc=com"})
		})
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("concurrent directory write: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("transaction RADIUS verification held the directory write transaction")
	}
	allowCommit()
	select {
	case committed := <-commitDone:
		assertRawLDAPResult(t, committed, int64(ldap.LDAPResultSuccess))
	case <-time.After(time.Second):
		t.Fatal("transaction commit did not finish after RADIUS response")
	}
	select {
	case <-requests:
		t.Fatal("transaction commit repeated RADIUS verification")
	default:
	}
	assertBindPassword(t, address, aliceDN, "transaction-replacement", true)
	stored := readStoredEntry(t, store, aliceDN)
	if got := string(stored.Values("description")[0]); got != "transaction preflight" {
		t.Fatalf("transactional description = %q", got)
	}
}

func TestOpenLDAPRADIUSPasswordTransactionPreservesFirstFailure(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-transaction-order-shared"
		username     = "radius-transaction-order-user"
		password     = "radius-transaction-order-password"
	)
	requests := make(chan struct{}, 4)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			requests <- struct{}{}
			if rfc2865.UserName_GetString(packet) == username &&
				rfc2865.UserPassword_GetString(packet) == password {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, []directory.Attribute{{
		Description: "pwdMinAge", Values: stringValues("300"),
	}}, nil)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"userPassword":   stringValues(auth.OpenLDAPRADIUSHashScheme + username),
		"pwdChangedTime": stringValues(formatPasswordPolicyTime(time.Now())),
	})
	address, stopLDAP := startServer(t, store, Config{
		RADIUSConfigPath: radiusConfig, RADIUSNASIdentifier: "transaction-order-nas",
	})
	defer stopLDAP()
	connection := dialAndBindRawLDAP(t, address, aliceDN, password)
	defer connection.Close()
	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("RADIUS Bind request did not arrive")
	}

	identifier := startRawLDAPTransaction(t, connection, 2)
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		3,
		rawModifyReplaceRequest(
			"uid=missing,ou=people,dc=example,dc=com",
			"description",
			"missing",
		),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		4,
		rawExtendedRequest(
			passwordModifyOID,
			rawPasswordModifyRequestValue(
				[]byte(password),
				[]byte("transaction-order-replacement"),
			),
			true,
		),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	response := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultNoSuchObject))
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("failed transaction response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil {
		t.Fatalf("DecodeTransactionEndResponseValue(): %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 3 {
		t.Fatalf("transaction end response = %#v, want failed message ID 3", decoded)
	}
	select {
	case <-requests:
		t.Fatal("later ppolicy failure contacted RADIUS")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestOpenLDAPRADIUSPasswordTransactionStopsAfterWrongOldPassword(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-transaction-old-password-shared"
		currentUser  = "radius-transaction-current"
		historyUser  = "radius-transaction-history"
		password     = "radius-transaction-current-password"
	)
	requests := make(chan string, 8)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			username := rfc2865.UserName_GetString(packet)
			requests <- username
			if username == currentUser &&
				rfc2865.UserPassword_GetString(packet) == password {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, []directory.Attribute{{
		Description: "pwdInHistory", Values: stringValues("1"),
	}}, nil)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"userPassword": stringValues(auth.OpenLDAPRADIUSHashScheme + currentUser),
		"pwdHistory": {buildPasswordHistoryValue(
			time.Now().Add(-time.Minute),
			[]byte(auth.OpenLDAPRADIUSHashScheme+historyUser),
		)},
	})
	address, stopLDAP := startServer(t, store, Config{
		RADIUSConfigPath: radiusConfig, RADIUSNASIdentifier: "transaction-old-password-nas",
	})
	defer stopLDAP()
	connection := dialAndBindRawLDAP(t, address, aliceDN, password)
	defer connection.Close()
	select {
	case username := <-requests:
		if username != currentUser {
			t.Fatalf("Bind RADIUS username = %q, want %q", username, currentUser)
		}
	case <-time.After(time.Second):
		t.Fatal("RADIUS Bind request did not arrive")
	}

	identifier := startRawLDAPTransaction(t, connection, 2)
	operations := []struct {
		messageID  int64
		old, newID string
	}{
		{messageID: 3, old: "wrong-old-password", newID: "history-candidate"},
		{messageID: 4, old: password, newID: "later-candidate"},
	}
	for _, operation := range operations {
		assertRawLDAPResult(t, sendRawLDAPOperation(
			t,
			connection,
			operation.messageID,
			rawExtendedRequest(
				passwordModifyOID,
				rawPasswordModifyRequestValue(
					[]byte(operation.old),
					[]byte(operation.newID),
				),
				true,
			),
			rawTransactionSpecificationControl(identifier, true, true),
		), int64(ldapwire.ResultSuccess))
	}
	response := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultUnwillingToPerform))
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("failed transaction response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil {
		t.Fatalf("DecodeTransactionEndResponseValue(): %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 3 {
		t.Fatalf("transaction end response = %#v, want failed message ID 3", decoded)
	}
	select {
	case username := <-requests:
		if username != currentUser {
			t.Fatalf("old-password RADIUS username = %q, want %q", username, currentUser)
		}
	case <-time.After(time.Second):
		t.Fatal("old-password RADIUS request did not arrive")
	}
	select {
	case username := <-requests:
		t.Fatalf("failed old password triggered an extra RADIUS request for %q", username)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestOpenLDAPRADIUSPasswordTransactionUsesEarlierPolicyChange(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-transaction-policy-shared"
		historyUser  = "radius-transaction-policy-history"
		candidate    = "radius-transaction-policy-candidate"
	)
	requests := make(chan struct{}, 2)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			requests <- struct{}{}
			if rfc2865.UserName_GetString(packet) == historyUser &&
				rfc2865.UserPassword_GetString(packet) == candidate {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, nil, nil)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"pwdHistory": {buildPasswordHistoryValue(
			time.Now().Add(-time.Minute),
			[]byte(auth.OpenLDAPRADIUSHashScheme+historyUser),
		)},
	})
	instance, _, stopLDAP := startSeqmodServer(t, store, Config{
		RootDN:              "cn=admin,dc=example,dc=com",
		RootPassword:        []byte("admin-secret"),
		RADIUSConfigPath:    radiusConfig,
		RADIUSNASIdentifier: "transaction-policy-nas",
	})
	defer stopLDAP()
	runtime := instance.runtime.Load()
	transaction := &ldapTransaction{
		runtime: runtime,
		operations: []ldapTransactionOperation{
			{
				boundDN: "cn=admin,dc=example,dc=com",
				message: ldapwire.Message{
					ID: 3,
					Request: ldapwire.ModifyRequest{
						DN: passwordPolicyDN,
						Changes: []ldapwire.Modification{{
							Operation: ldapwire.ModificationReplace,
							Attribute: directory.Attribute{
								Description: "pwdInHistory",
								Values:      stringValues("1"),
							},
						}},
					},
				},
			},
			{
				boundDN: aliceDN,
				message: ldapwire.Message{
					ID: 4,
					Request: ldapwire.ExtendedRequest{
						Name: passwordModifyOID,
						Value: rawPasswordModifyRequestValue(
							[]byte("secret"),
							[]byte(candidate),
						),
						HasValue: true,
					},
				},
			},
		},
	}
	state := &connectionState{
		boundDN: "cn=admin,dc=example,dc=com",
		runtime: runtime,
	}
	result, response := instance.commitLDAPTransaction(t.Context(), state, transaction)
	if result.Code != ldapwire.ResultConstraintViolation {
		t.Fatalf("transaction result = %#v, want constraint violation", result)
	}
	if !response.HasFailedMessageID || response.FailedMessageID != 4 {
		t.Fatalf("transaction response = %#v, want failed message ID 4", response)
	}
	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("ordered policy history did not contact RADIUS")
	}
	select {
	case <-requests:
		t.Fatal("ordered policy history contacted RADIUS more than once")
	default:
	}
	policy := readStoredEntry(t, store, passwordPolicyDN)
	if policy.HasAttribute("pwdInHistory") {
		t.Fatal("failed policy/password transaction committed pwdInHistory")
	}
}

func TestOpenLDAPRADIUSPasswordTransactionUsesExactMultiValueMatch(t *testing.T) {
	t.Parallel()

	const (
		sharedSecret = "radius-transaction-multivalue-shared"
		firstUser    = "radius-transaction-first"
		secondUser   = "radius-transaction-second"
		firstSecret  = "first-password"
		secondSecret = "second-password"
		finalSecret  = "final-password"
	)
	requests := make(chan string, 8)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			username := rfc2865.UserName_GetString(packet)
			password := rfc2865.UserPassword_GetString(packet)
			requests <- username + "\x00" + password
			if username == firstUser && password == firstSecret {
				return radius.CodeAccessAccept
			}
			if username == secondUser && password == secondSecret {
				return radius.CodeAccessAccept
			}
			return radius.CodeAccessReject
		},
	)
	defer stopRADIUS()
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, []directory.Attribute{{
		Description: "pwdSafeModify", Values: stringValues("TRUE"),
	}}, nil)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"userPassword": stringValues(
			auth.OpenLDAPRADIUSHashScheme+firstUser,
			auth.OpenLDAPRADIUSHashScheme+secondUser,
		),
	})
	instance, address, stopLDAP := startSeqmodServer(t, store, Config{
		RADIUSConfigPath:    radiusConfig,
		RADIUSNASIdentifier: "transaction-multivalue-nas",
	})
	defer stopLDAP()
	runtime := instance.runtime.Load()
	transaction := &ldapTransaction{
		runtime: runtime,
		operations: []ldapTransactionOperation{
			{
				boundDN: aliceDN,
				message: ldapwire.Message{
					ID: 3,
					Request: ldapwire.ModifyRequest{
						DN: aliceDN,
						Changes: []ldapwire.Modification{
							{
								Operation: ldapwire.ModificationDelete,
								Attribute: directory.Attribute{
									Description: "userPassword",
									Values:      stringValues(secondSecret),
								},
							},
							{
								Operation: ldapwire.ModificationAdd,
								Attribute: directory.Attribute{
									Description: "userPassword",
									Values:      stringValues("intermediate-password"),
								},
							},
						},
					},
				},
			},
			{
				boundDN: aliceDN,
				message: ldapwire.Message{
					ID: 4,
					Request: ldapwire.ExtendedRequest{
						Name: passwordModifyOID,
						Value: rawPasswordModifyRequestValue(
							[]byte(firstSecret),
							[]byte(finalSecret),
						),
						HasValue: true,
					},
				},
			},
		},
	}
	state := &connectionState{boundDN: aliceDN, runtime: runtime}
	result, response := instance.commitLDAPTransaction(t.Context(), state, transaction)
	if result.Code != ldapwire.ResultSuccess {
		t.Fatalf("transaction result = %#v, want success", result)
	}
	if response.HasFailedMessageID {
		t.Fatalf("transaction response = %#v, want no failed message ID", response)
	}
	wantRequests := []string{
		firstUser + "\x00" + secondSecret,
		secondUser + "\x00" + secondSecret,
		firstUser + "\x00" + firstSecret,
	}
	for _, want := range wantRequests {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("RADIUS request = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("RADIUS request %q did not arrive", want)
		}
	}
	select {
	case got := <-requests:
		t.Fatalf("transaction repeated RADIUS request %q", got)
	default:
	}
	assertBindPassword(t, address, aliceDN, finalSecret, true)
}

func startLDAPRADIUSServer(
	t *testing.T,
	secret []byte,
	response func(*radius.Packet) radius.Code,
) (string, func()) {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen RADIUS: %v", err)
	}
	server := &radius.PacketServer{
		SecretSource: radius.StaticSecretSource(secret),
		Handler: radius.HandlerFunc(func(
			writer radius.ResponseWriter,
			request *radius.Request,
		) {
			if err := writer.Write(request.Response(response(request.Packet))); err != nil {
				t.Errorf("write RADIUS response: %v", err)
			}
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(connection) }()
	return connection.LocalAddr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("shutdown RADIUS server: %v", err)
		}
		if err := <-done; !errors.Is(err, radius.ErrServerShutdown) {
			t.Errorf("RADIUS Serve() error = %v", err)
		}
	}
}
