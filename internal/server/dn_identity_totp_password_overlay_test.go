package server

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityTOTPPasswordBaseDN        = "dc=example,dc=com"
	dnIdentityTOTPPasswordUserDN        = "totpExactName=Alice+totpFoldName=Primary User,ou=people," + dnIdentityTOTPPasswordBaseDN
	dnIdentityTOTPPasswordUserRef       = `totpFoldAlias=\20PRIMARY\20\20USER\20+1.3.6.1.4.1.99999.933.1=Alice,OU=PEOPLE,DC=EXAMPLE,DC=COM`
	dnIdentityTOTPPasswordLowerUserDN   = "totpExactName=alice+totpFoldName=Primary User,ou=people," + dnIdentityTOTPPasswordBaseDN
	dnIdentityTOTPPasswordLowerUserRef  = "totpFoldAlias=primary user+totpExactAlias=alice,OU=PEOPLE,DC=EXAMPLE,DC=COM"
	dnIdentityTOTPPasswordRootDN        = "totpExactName=Admin+totpFoldName=Directory Root," + dnIdentityTOTPPasswordBaseDN
	dnIdentityTOTPPasswordRootRef       = `totpFoldAlias=\20DIRECTORY\20\20ROOT\20+1.3.6.1.4.1.99999.933.1=Admin,DC=EXAMPLE,DC=COM`
	dnIdentityTOTPPasswordLowerRootDN   = "totpExactName=admin+totpFoldName=Directory Root," + dnIdentityTOTPPasswordBaseDN
	dnIdentityTOTPPasswordLowerRootRef  = "totpFoldAlias=directory root+totpExactAlias=admin,DC=EXAMPLE,DC=COM"
	dnIdentityTOTPPasswordPartition     = "dn-identity-totp-password"
	dnIdentityTOTPPasswordConfiguration = "olcOverlay={0}totp,olcDatabase={1}mdb,cn=config"
)

var (
	dnIdentityTOTPPasswordSecret      = []byte("12345678901234567890123456789012")
	dnIdentityTOTPPasswordOtherSecret = []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
)

func TestDNIdentityTOTPPasswordBindStateAndReplay(t *testing.T) {
	placements := []struct {
		name     string
		frontend bool
	}{
		{name: "database"},
		{name: "frontend", frontend: true},
	}
	for _, backend := range dnIdentityTOTPPasswordBackends() {
		backend := backend
		for _, placement := range placements {
			placement := placement
			t.Run(backend.name+"/"+placement.name, func(t *testing.T) {
				store := backend.open(t)
				t.Cleanup(func() { _ = store.Close() })
				registry := dnIdentityTOTPPasswordRegistry(t)
				runtime, database, instance, clock := newDNIdentityTOTPPasswordRuntime(
					t,
					store,
					registry,
					placement.frontend,
				)
				seedDNIdentityTOTPPasswordEntries(t, store, database)

				assertDNIdentityTOTPPasswordCaseExactIsolation(
					t, instance, runtime, store, database,
				)
				assertDNIdentityTOTPPasswordOrdinaryBind(
					t, instance, runtime, store, database,
				)
				assertDNIdentityTOTPPasswordRootBind(
					t, instance, runtime, store, database,
				)
				clock.Add(30)
				assertDNIdentityTOTPPasswordConcurrentReplay(
					t, instance, runtime, clock.Load(),
				)
			})
		}
	}
}

func TestDNIdentityTOTPPasswordConfigurationPlacementAndKey(t *testing.T) {
	entry := totpPasswordOverlayEntry(false)
	entry.DN = "olcOverlay={0}TOTP,olcDatabase={1}MDB,CN=CONFIG"
	configuration, err := loadTOTPPasswordRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadTOTPPasswordRuntimeConfiguration(): %v", err)
	}
	want, err := totpPasswordConfigurationDNKey(dnIdentityTOTPPasswordConfiguration)
	if err != nil {
		t.Fatalf("totpPasswordConfigurationDNKey(): %v", err)
	}
	if configuration.configDNKey != want {
		t.Fatalf("config DN key = %q, want %q", configuration.configDNKey, want)
	}

	disabled := totpPasswordRuntimeConfiguration{disabled: true}
	local := totpPasswordRuntimeConfiguration{configDNKey: "local"}
	global := totpPasswordRuntimeConfiguration{configDNKey: "frontend"}
	runtime := &runtimeState{databases: []runtimeDatabase{
		{name: "{-1}frontend", totpPasswords: []totpPasswordRuntimeConfiguration{disabled, global}},
		{name: "{1}mdb", totpPasswords: []totpPasswordRuntimeConfiguration{disabled, local}},
	}}
	if got := activeTOTPPasswordConfiguration(runtime, &runtime.databases[1]); got == nil || got.configDNKey != "local" {
		t.Fatalf("database placement selected %#v", got)
	}
	runtime.databases[1].totpPasswords = []totpPasswordRuntimeConfiguration{disabled}
	if got := activeTOTPPasswordConfiguration(runtime, &runtime.databases[1]); got == nil || got.configDNKey != "frontend" {
		t.Fatalf("frontend placement selected %#v", got)
	}
}

func assertDNIdentityTOTPPasswordCaseExactIsolation(
	t *testing.T,
	instance *Server,
	runtime *runtimeState,
	store storage.Store,
	database runtimeDatabase,
) {
	t.Helper()
	credential := dnIdentityTOTPPasswordCredential(
		t,
		dnIdentityTOTPPasswordSecret,
		totpPasswordTestUnix,
		otpHMACSHA256OID,
	)
	result, err := instance.authenticatePasswordBind(
		context.Background(),
		runtime,
		dnIdentityTOTPPasswordLowerUserRef,
		credential,
		false,
	)
	if err != nil {
		t.Fatalf("caseExact-mismatched ordinary Bind: %v", err)
	}
	if result.authenticated {
		t.Fatal("caseExact-mismatched ordinary Bind authenticated")
	}
	assertDNIdentityTOTPPasswordTimestamp(
		t, store, database, dnIdentityTOTPPasswordLowerUserDN, false, 0,
	)

	rootResult, err := instance.authenticatePasswordBind(
		context.Background(),
		runtime,
		dnIdentityTOTPPasswordLowerRootRef,
		credential,
		false,
	)
	if err != nil {
		t.Fatalf("caseExact-mismatched root Bind: %v", err)
	}
	if rootResult.authenticated {
		t.Fatal("caseExact-mismatched root Bind authenticated")
	}
	assertDNIdentityTOTPPasswordTimestamp(
		t, store, database, dnIdentityTOTPPasswordLowerRootDN, false, 0,
	)
}

func assertDNIdentityTOTPPasswordOrdinaryBind(
	t *testing.T,
	instance *Server,
	runtime *runtimeState,
	store storage.Store,
	database runtimeDatabase,
) {
	t.Helper()
	credential := dnIdentityTOTPPasswordCredential(
		t,
		dnIdentityTOTPPasswordSecret,
		totpPasswordTestUnix,
		otpHMACSHA256OID,
	)
	result, err := instance.authenticatePasswordBind(
		context.Background(), runtime, dnIdentityTOTPPasswordUserRef, credential, false,
	)
	if err != nil || !result.authenticated {
		t.Fatalf("schema-equivalent ordinary Bind = %#v, error %v", result, err)
	}
	assertDNIdentityTOTPPasswordTimestamp(
		t, store, database, dnIdentityTOTPPasswordUserDN, true, totpPasswordTestUnix,
	)
	replay, err := instance.authenticatePasswordBind(
		context.Background(), runtime, dnIdentityTOTPPasswordUserRef, credential, false,
	)
	if err != nil {
		t.Fatalf("ordinary replay Bind: %v", err)
	}
	if replay.authenticated {
		t.Fatal("ordinary TOTP replay authenticated")
	}
}

func assertDNIdentityTOTPPasswordRootBind(
	t *testing.T,
	instance *Server,
	runtime *runtimeState,
	store storage.Store,
	database runtimeDatabase,
) {
	t.Helper()
	credential := dnIdentityTOTPPasswordCredential(
		t,
		dnIdentityTOTPPasswordSecret,
		totpPasswordTestUnix,
		otpHMACSHA512OID,
	)
	result, err := instance.authenticatePasswordBind(
		context.Background(), runtime, dnIdentityTOTPPasswordRootRef, credential, false,
	)
	if err != nil || !result.authenticated {
		t.Fatalf("schema-equivalent root Bind = %#v, error %v", result, err)
	}
	assertDNIdentityTOTPPasswordTimestamp(
		t, store, database, dnIdentityTOTPPasswordRootDN, true, totpPasswordTestUnix,
	)
	replay, err := instance.authenticatePasswordBind(
		context.Background(), runtime, dnIdentityTOTPPasswordRootRef, credential, false,
	)
	if err != nil {
		t.Fatalf("root replay Bind: %v", err)
	}
	if replay.authenticated {
		t.Fatal("root TOTP replay authenticated")
	}
}

func assertDNIdentityTOTPPasswordConcurrentReplay(
	t *testing.T,
	instance *Server,
	runtime *runtimeState,
	now int64,
) {
	t.Helper()
	credential := dnIdentityTOTPPasswordCredential(
		t,
		dnIdentityTOTPPasswordSecret,
		now,
		otpHMACSHA256OID,
	)
	const clients = 16
	start := make(chan struct{})
	results := make(chan bool, clients)
	errors := make(chan error, clients)
	var ready sync.WaitGroup
	ready.Add(clients)
	for range clients {
		go func() {
			ready.Done()
			<-start
			result, err := instance.authenticatePasswordBind(
				context.Background(),
				runtime,
				dnIdentityTOTPPasswordUserRef,
				credential,
				false,
			)
			results <- result.authenticated
			errors <- err
		}()
	}
	ready.Wait()
	close(start)
	successes := 0
	for range clients {
		if err := <-errors; err != nil {
			t.Fatalf("concurrent TOTP Bind: %v", err)
		}
		if <-results {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successful TOTP Binds = %d, want 1", successes)
	}
}

func newDNIdentityTOTPPasswordRuntime(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
	frontendPlacement bool,
) (*runtimeState, runtimeDatabase, *Server, *atomic.Int64) {
	t.Helper()
	suffix := mustDNIdentityTOTPPasswordDN(t, registry, dnIdentityTOTPPasswordBaseDN)
	rootDN := mustDNIdentityTOTPPasswordDN(t, registry, dnIdentityTOTPPasswordRootDN)
	rootPassword, err := auth.HashPassword(
		dnIdentityTOTPPasswordSecret,
		auth.TOTP512HashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(root TOTP512): %v", err)
	}
	configuration := totpPasswordRuntimeConfiguration{
		configDNKey: dnIdentityTOTPPasswordConfiguration,
	}
	database := runtimeDatabase{
		name:            "{1}mdb",
		partition:       dnIdentityTOTPPasswordPartition,
		suffixes:        []directory.DN{suffix},
		dnNormalizer:    registry,
		rootDN:          &rootDN,
		rootPassword:    rootPassword,
		rootPasswordSet: true,
		lastMod:         false,
		totpPasswords:   []totpPasswordRuntimeConfiguration{configuration},
	}
	frontend := runtimeDatabase{name: "{-1}frontend"}
	if frontendPlacement {
		database.totpPasswords = nil
		frontend.totpPasswords = []totpPasswordRuntimeConfiguration{configuration}
	}
	runtime := &runtimeState{
		schema:    registry,
		access:    acl.DefaultPolicy(),
		databases: []runtimeDatabase{frontend, database},
	}
	var clock atomic.Int64
	clock.Store(totpPasswordTestUnix)
	instance := &Server{
		config: Config{
			Store:  store,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		clock: func() time.Time {
			return time.Unix(clock.Load(), 0).UTC()
		},
	}
	return runtime, database, instance, &clock
}

func seedDNIdentityTOTPPasswordEntries(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
) {
	t.Helper()
	upperPassword, err := auth.HashPassword(
		dnIdentityTOTPPasswordSecret,
		auth.TOTP256HashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(upper TOTP256): %v", err)
	}
	lowerPassword, err := auth.HashPassword(
		dnIdentityTOTPPasswordOtherSecret,
		auth.TOTP256HashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(lower TOTP256): %v", err)
	}
	entries := []directory.Entry{
		dnIdentityTOTPPasswordEntry(dnIdentityTOTPPasswordUserDN, upperPassword),
		dnIdentityTOTPPasswordEntry(dnIdentityTOTPPasswordLowerUserDN, lowerPassword),
		dnIdentityTOTPPasswordEntry(dnIdentityTOTPPasswordRootDN, nil),
		dnIdentityTOTPPasswordEntry(dnIdentityTOTPPasswordLowerRootDN, lowerPassword),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed TOTP password DN identity entries: %v", err)
	}
}

func dnIdentityTOTPPasswordEntry(rawDN string, password []byte) directory.Entry {
	entry := directory.Entry{
		DN: rawDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("person")},
			{Description: "sn", Values: stringValues("TOTP")},
		},
	}
	if password != nil {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "userPassword",
			Values:      [][]byte{password},
		})
	}
	return entry
}

func assertDNIdentityTOTPPasswordTimestamp(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	rawDN string,
	wantPresent bool,
	wantUnix int64,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := readerForDatabase(reader, database).Get(
			mustDNIdentityTOTPPasswordLegacyDN(t, rawDN),
		)
		if err != nil {
			return err
		}
		values := entry.Values("authTimestamp")
		if !wantPresent {
			if len(values) != 0 {
				t.Fatalf("%s authTimestamp = %q, want absent", rawDN, values)
			}
			return nil
		}
		want := formatPasswordPolicyTime(time.Unix(wantUnix, 0))
		if len(values) != 1 || string(values[0]) != want {
			t.Fatalf("%s authTimestamp = %q, want %q", rawDN, values, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("read TOTP password state %s: %v", rawDN, err)
	}
}

func dnIdentityTOTPPasswordCredential(
	t *testing.T,
	secret []byte,
	now int64,
	algorithmOID string,
) []byte {
	t.Helper()
	return []byte(totpPasswordCredential(t, secret, now/30, algorithmOID, ""))
}

func dnIdentityTOTPPasswordRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.933.1 NAME ( 'totpExactName' 'totpExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.933.2 NAME ( 'totpFoldName' 'totpFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func mustDNIdentityTOTPPasswordDN(
	t *testing.T,
	registry *schema.Registry,
	rawDN string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(rawDN)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", rawDN, err)
	}
	return dn
}

func mustDNIdentityTOTPPasswordLegacyDN(t *testing.T, rawDN string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	return dn
}

type dnIdentityTOTPPasswordBackend struct {
	name string
	open func(*testing.T) storage.Store
}

func dnIdentityTOTPPasswordBackends() []dnIdentityTOTPPasswordBackend {
	return []dnIdentityTOTPPasswordBackend{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}
}
