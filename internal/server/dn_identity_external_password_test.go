package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	dnIdentityExternalExactOID = "1.3.6.1.4.1.99999.962.1"
	dnIdentityExternalFoldOID  = "1.3.6.1.4.1.99999.962.2"
	dnIdentityExternalSuffix   = "dc=external,dc=test"
	dnIdentityExternalUpperDN  = "externalExactName=Alice+" +
		"externalFoldName=Primary Team,ou=people," + dnIdentityExternalSuffix
	dnIdentityExternalLowerDN = "externalExactName=alice+" +
		"externalFoldName=Primary Team,ou=people," + dnIdentityExternalSuffix
	dnIdentityExternalEquivalentUpperDN = dnIdentityExternalFoldOID +
		`=\20PRIMARY\20\20TEAM\20+externalExactAlias=Alice,` +
		"OU=PEOPLE,DC=EXTERNAL,DC=TEST"
	dnIdentityExternalEquivalentLowerDN = "externalFoldAlias=primary team+" +
		dnIdentityExternalExactOID + "=alice,OU=PEOPLE,DC=EXTERNAL,DC=TEST"
)

type dnIdentityExternalPasswordRequest struct {
	username string
	password string
}

func TestDNIdentityExternalPassword(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			testDNIdentityExternalPassword(t, backend.open)
		})
	}
}

func testDNIdentityExternalPassword(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	t.Helper()
	const (
		sharedSecret = "dn-identity-radius-shared"
		upperUser    = "dn-identity-radius-upper"
		lowerUser    = "dn-identity-radius-lower"
		upperSecret  = "upper-radius-secret"
		lowerSecret  = "lower-radius-secret"
	)

	requests := make(chan dnIdentityExternalPasswordRequest, 16)
	radiusAddress, stopRADIUS := startLDAPRADIUSServer(
		t,
		[]byte(sharedSecret),
		func(packet *radius.Packet) radius.Code {
			request := dnIdentityExternalPasswordRequest{
				username: rfc2865.UserName_GetString(packet),
				password: rfc2865.UserPassword_GetString(packet),
			}
			requests <- request
			switch request {
			case dnIdentityExternalPasswordRequest{upperUser, upperSecret},
				dnIdentityExternalPasswordRequest{lowerUser, lowerSecret}:
				return radius.CodeAccessAccept
			default:
				return radius.CodeAccessReject
			}
		},
	)
	t.Cleanup(stopRADIUS)
	radiusConfig := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		radiusConfig,
		[]byte("auth "+radiusAddress+" "+sharedSecret+" 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write RADIUS configuration: %v", err)
	}

	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	registry := dnIdentityExternalPasswordRegistry(t)
	database := dnIdentityExternalPasswordDatabase(t, registry)
	runtime := &runtimeState{
		schema:    registry,
		access:    acl.DefaultPolicy(),
		databases: []runtimeDatabase{database},
		externalPasswords: externalPasswordRuntimeConfiguration{
			radiusEnabled:       true,
			radiusConfigPath:    radiusConfig,
			radiusNASIdentifier: "dn-identity-radius-nas",
		},
		passwordHashSchemes: []string{auth.OpenLDAPDefaultHashScheme},
	}
	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	instance := &Server{config: Config{
		Store:  store,
		Clock:  func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, clock: func() time.Time { return now }}
	dnIdentityExternalPasswordSeed(
		t,
		store,
		database,
		[]byte(auth.OpenLDAPRADIUSHashScheme+upperUser),
		[]byte(auth.OpenLDAPRADIUSHashScheme+lowerUser),
	)

	t.Run("caseExact users do not share RADIUS identity or state", func(t *testing.T) {
		result, err := instance.authenticatePasswordBind(
			t.Context(),
			runtime,
			dnIdentityExternalEquivalentLowerDN,
			[]byte(upperSecret),
			false,
		)
		if err != nil || result.authenticated {
			t.Fatalf("caseExact sibling Bind = %#v, %v", result, err)
		}
		assertDNIdentityExternalPasswordRequest(
			t,
			requests,
			dnIdentityExternalPasswordRequest{lowerUser, upperSecret},
		)
		assertDNIdentityExternalPasswordLastSuccess(
			t, store, database, registry, dnIdentityExternalUpperDN, false,
		)
		assertDNIdentityExternalPasswordLastSuccess(
			t, store, database, registry, dnIdentityExternalLowerDN, false,
		)
	})

	t.Run("caseIgnore alias OID and multiAVA authenticate equivalently", func(t *testing.T) {
		result, err := instance.authenticatePasswordBind(
			t.Context(),
			runtime,
			dnIdentityExternalEquivalentUpperDN,
			[]byte(upperSecret),
			false,
		)
		if err != nil || !result.authenticated {
			t.Fatalf("schema-equivalent RADIUS Bind = %#v, %v", result, err)
		}
		assertDNIdentityExternalPasswordRequest(
			t,
			requests,
			dnIdentityExternalPasswordRequest{upperUser, upperSecret},
		)
		assertDNIdentityExternalPasswordLastSuccess(
			t, store, database, registry, dnIdentityExternalUpperDN, true,
		)
		assertDNIdentityExternalPasswordLastSuccess(
			t, store, database, registry, dnIdentityExternalLowerDN, false,
		)
	})

	localPassword, err := auth.HashPassword(
		[]byte("local-secret"),
		auth.OpenLDAPDefaultHashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(local): %v", err)
	}
	wrongLocalPassword, err := auth.HashPassword(
		[]byte("different-local-secret"),
		auth.OpenLDAPDefaultHashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(wrong local): %v", err)
	}

	t.Run("ordinary hash takes priority over later RADIUS values", func(t *testing.T) {
		dnIdentityExternalPasswordReplace(
			t,
			store,
			database,
			registry,
			dnIdentityExternalUpperDN,
			localPassword,
			[]byte(auth.OpenLDAPRADIUSHashScheme+"must-not-be-contacted"),
		)
		result, err := instance.authenticatePasswordBind(
			t.Context(),
			runtime,
			dnIdentityExternalEquivalentUpperDN,
			[]byte("local-secret"),
			false,
		)
		if err != nil || !result.authenticated {
			t.Fatalf("local-first Bind = %#v, %v", result, err)
		}
		assertNoDNIdentityExternalPasswordRequest(t, requests)
	})

	t.Run("ordinary and RADIUS values combine in stored order", func(t *testing.T) {
		dnIdentityExternalPasswordReplace(
			t,
			store,
			database,
			registry,
			dnIdentityExternalUpperDN,
			wrongLocalPassword,
			[]byte(auth.OpenLDAPRADIUSHashScheme+upperUser),
		)
		result, err := instance.authenticatePasswordBind(
			t.Context(),
			runtime,
			dnIdentityExternalEquivalentUpperDN,
			[]byte(upperSecret),
			false,
		)
		if err != nil || !result.authenticated {
			t.Fatalf("local plus RADIUS Bind = %#v, %v", result, err)
		}
		assertDNIdentityExternalPasswordRequest(
			t,
			requests,
			dnIdentityExternalPasswordRequest{upperUser, upperSecret},
		)
	})

	t.Run("password modification preverification uses schema identity", func(t *testing.T) {
		target := mustDNIdentityExternalPasswordLegacyDN(
			t,
			dnIdentityExternalEquivalentUpperDN,
		)
		matches, err := instance.preverifyPasswordModification(
			t.Context(),
			runtime,
			dnIdentityExternalEquivalentUpperDN,
			database,
			target,
			[]ldapwire.Modification{{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "userPassword",
					Values:      [][]byte{[]byte("replacement-secret")},
				},
			}},
			nil,
			passwordPolicyModificationOptions{
				passwordModify: true,
				hasOldPassword: true,
				oldPassword:    []byte(upperSecret),
				newPassword:    []byte("replacement-secret"),
			},
		)
		if err != nil {
			t.Fatalf("preverifyPasswordModification(): %v", err)
		}
		if err := validateExternalPasswordMatches(
			matches,
			[][]byte{[]byte(auth.OpenLDAPRADIUSHashScheme + upperUser)},
			[]byte(upperSecret),
		); err != nil {
			t.Fatalf("validateExternalPasswordMatches(): %v", err)
		}
		assertDNIdentityExternalPasswordRequest(
			t,
			requests,
			dnIdentityExternalPasswordRequest{upperUser, upperSecret},
		)
	})

	t.Run("transaction preflight rejects a different caseExact state", func(t *testing.T) {
		upperTarget := mustDNIdentityExternalPasswordLegacyDN(
			t,
			dnIdentityExternalEquivalentUpperDN,
		)
		collector := &externalPasswordVerificationCollector{
			matches: newExternalPasswordMatches(),
		}
		collectContext := context.WithValue(
			t.Context(),
			collectExternalPasswordVerificationContextKey{},
			collector,
		)
		matches, err := instance.preverifyEntryPasswords(
			collectContext,
			runtime,
			database,
			upperTarget,
			"userPassword",
			[]byte(upperSecret),
		)
		if err != nil {
			t.Fatalf("collect transaction passwords: %v", err)
		}
		upperStored := [][]byte{
			wrongLocalPassword,
			[]byte(auth.OpenLDAPRADIUSHashScheme + upperUser),
		}
		err = validateExternalPasswordMatches(matches, upperStored, []byte(upperSecret))
		assertDNIdentityExternalPasswordBusy(
			t,
			err,
			"external password verification pending",
		)
		if collector.request == nil {
			t.Fatal("transaction preflight did not collect external password work")
		}
		instance.preverifyOrderedPasswords(
			t.Context(),
			runtime,
			collector.request.stored,
			collector.request.supplied,
			matches,
		)
		clearExternalPasswordVerificationSequence(collector.request)
		collector.request = nil
		assertDNIdentityExternalPasswordRequest(
			t,
			requests,
			dnIdentityExternalPasswordRequest{upperUser, upperSecret},
		)

		prepared := externalPasswordMatches{values: matches.values}
		preparedContext := context.WithValue(
			t.Context(),
			preparedExternalPasswordVerificationContextKey{},
			preparedExternalPasswordVerification{matches: prepared},
		)
		lowerTarget := mustDNIdentityExternalPasswordLegacyDN(
			t,
			dnIdentityExternalEquivalentLowerDN,
		)
		prepared, err = instance.preverifyEntryPasswords(
			preparedContext,
			runtime,
			database,
			lowerTarget,
			"userPassword",
			[]byte(upperSecret),
		)
		if err != nil {
			t.Fatalf("load prepared transaction passwords: %v", err)
		}
		err = validateExternalPasswordMatches(
			prepared,
			[][]byte{[]byte(auth.OpenLDAPRADIUSHashScheme + lowerUser)},
			[]byte(upperSecret),
		)
		assertDNIdentityExternalPasswordBusy(
			t,
			err,
			"external password verification state changed; retry the operation",
		)
		assertNoDNIdentityExternalPasswordRequest(t, requests)
	})

	t.Run("remote-write transaction rejection keeps schema routing", func(t *testing.T) {
		transactionDatabase := database
		transactionDatabase.translucent = &translucentRuntimeConfiguration{}
		transactionRuntime := &runtimeState{
			schema:    registry,
			access:    acl.DefaultPolicy(),
			databases: []runtimeDatabase{transactionDatabase},
			externalPasswords: externalPasswordRuntimeConfiguration{
				radiusEnabled: true,
			},
		}
		state := &connectionState{
			boundDN: dnIdentityExternalEquivalentUpperDN,
			transaction: &ldapTransaction{
				runtime: transactionRuntime,
			},
		}
		_, result := instance.transactionOperationDatabase(state, ldapwire.Message{
			ID: 1,
			Request: ldapwire.ModifyRequest{
				DN: dnIdentityExternalEquivalentUpperDN,
				Changes: []ldapwire.Modification{{
					Operation: ldapwire.ModificationReplace,
					Attribute: directory.Attribute{
						Description: "userPassword",
						Values:      [][]byte{[]byte("replacement-secret")},
					},
				}},
			},
		})
		if result == nil || result.Code != ldapwire.ResultUnwillingToPerform ||
			result.DiagnosticMessage !=
				"RADIUS password verification is not supported in translucent LDAP transactions" {
			t.Fatalf("transaction rejection = %#v", result)
		}
	})
}

func TestDNIdentityExternalPasswordConfigurationDNRemainsLegacy(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "CN=MODULE{0},CN=CONFIG",
			Attributes: []directory.Attribute{{
				Description: "olcModuleLoad",
				Values:      stringValues("pw-radius.la config=/legacy/radius.conf"),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed legacy configuration DN: %v", err)
	}
	var configuration externalPasswordRuntimeConfiguration
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		var err error
		configuration, err = loadExternalPasswordRuntimeConfiguration(
			reader,
			Config{RADIUSNASIdentifier: "legacy-config-nas"},
		)
		return err
	}); err != nil {
		t.Fatalf("loadExternalPasswordRuntimeConfiguration(): %v", err)
	}
	if !configuration.radiusEnabled ||
		configuration.radiusConfigPath != "/legacy/radius.conf" {
		t.Fatalf("legacy cn=config module = %#v", configuration)
	}
}

func dnIdentityExternalPasswordRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( " + dnIdentityExternalExactOID +
			" NAME ( 'externalExactName' 'externalExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + dnIdentityExternalFoldOID +
			" NAME ( 'externalFoldName' 'externalFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityExternalPasswordDatabase(
	t *testing.T,
	registry *schema.Registry,
) runtimeDatabase {
	t.Helper()
	suffix, err := registry.NormalizeDN(dnIdentityExternalSuffix)
	if err != nil {
		t.Fatalf("NormalizeDN(suffix): %v", err)
	}
	rootDN, err := registry.NormalizeDN(dnIdentityExternalUpperDN)
	if err != nil {
		t.Fatalf("NormalizeDN(root DN): %v", err)
	}
	return runtimeDatabase{
		name:              "{1}mdb",
		partition:         "dn-identity-external-password",
		suffixes:          []directory.DN{suffix},
		rootDN:            &rootDN,
		dnNormalizer:      registry,
		lastBind:          true,
		lastBindPrecision: 0,
	}
}

func dnIdentityExternalPasswordSeed(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	upperPassword,
	lowerPassword []byte,
) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		for _, entry := range []directory.Entry{
			{
				DN: dnIdentityExternalUpperDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("top", "person")},
					{Description: "cn", Values: stringValues("Upper Alice")},
					{Description: "sn", Values: stringValues("Alice")},
					{Description: "externalExactAlias", Values: stringValues("Alice")},
					{Description: dnIdentityExternalFoldOID, Values: stringValues("Primary Team")},
					{Description: "userPassword", Values: [][]byte{upperPassword}},
				},
			},
			{
				DN: dnIdentityExternalLowerDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("top", "person")},
					{Description: "cn", Values: stringValues("Lower Alice")},
					{Description: "sn", Values: stringValues("alice")},
					{Description: dnIdentityExternalExactOID, Values: stringValues("alice")},
					{Description: "externalFoldAlias", Values: stringValues("Primary Team")},
					{Description: "userPassword", Values: [][]byte{lowerPassword}},
				},
			},
		} {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed external password entries: %v", err)
	}
}

func dnIdentityExternalPasswordReplace(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	registry *schema.Registry,
	rawDN string,
	values ...[]byte,
) {
	t.Helper()
	dn, err := registry.NormalizeDN(rawDN)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", rawDN, err)
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		entry, err := tx.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", cloneByteValues(values))
		return tx.Put(entry, true)
	}); err != nil {
		t.Fatalf("replace external passwords: %v", err)
	}
}

func assertDNIdentityExternalPasswordLastSuccess(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	registry *schema.Registry,
	rawDN string,
	want bool,
) {
	t.Helper()
	dn, err := registry.NormalizeDN(rawDN)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", rawDN, err)
	}
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		entry, err := readerForDatabase(reader, database).Get(dn)
		if err != nil {
			return err
		}
		if got := entry.HasAttribute("pwdLastSuccess"); got != want {
			return fmt.Errorf("pwdLastSuccess present = %t, want %t", got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("check %s state: %v", rawDN, err)
	}
}

func assertDNIdentityExternalPasswordRequest(
	t *testing.T,
	requests <-chan dnIdentityExternalPasswordRequest,
	want dnIdentityExternalPasswordRequest,
) {
	t.Helper()
	select {
	case got := <-requests:
		if got != want {
			t.Fatalf("RADIUS request = %#v, want %#v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("RADIUS request %#v did not arrive", want)
	}
}

func assertNoDNIdentityExternalPasswordRequest(
	t *testing.T,
	requests <-chan dnIdentityExternalPasswordRequest,
) {
	t.Helper()
	select {
	case got := <-requests:
		t.Fatalf("unexpected RADIUS request %#v", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func assertDNIdentityExternalPasswordBusy(
	t *testing.T,
	err error,
	diagnostic string,
) {
	t.Helper()
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultBusy ||
		failure.result.DiagnosticMessage != diagnostic {
		t.Fatalf("external password failure = %#v, %v", failure, err)
	}
}

func mustDNIdentityExternalPasswordLegacyDN(
	t *testing.T,
	raw string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", raw, err)
	}
	return dn
}
