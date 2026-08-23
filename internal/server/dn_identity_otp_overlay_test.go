package server

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityOTPBaseDN         = "dc=example,dc=com"
	dnIdentityOTPUserDN         = "otpExactName=User," + dnIdentityOTPBaseDN
	dnIdentityOTPUserAliasDN    = "otpExactAlias=User,DC=EXAMPLE,DC=COM"
	dnIdentityOTPTokenDN        = "otpExactName=Token+otpFoldName=Primary Token,ou=otp," + dnIdentityOTPBaseDN
	dnIdentityOTPLowerTokenDN   = "otpExactName=token+otpFoldName=Primary Token,ou=otp," + dnIdentityOTPBaseDN
	dnIdentityOTPTokenReference = `otpFoldAlias=\20PRIMARY\20\20TOKEN\20+1.3.6.1.4.1.99999.932.1=Token,OU=OTP,DC=EXAMPLE,DC=COM`
	dnIdentityOTPLowerReference = "otpFoldAlias=primary token+otpExactAlias=token,ou=otp," + dnIdentityOTPBaseDN
	dnIdentityOTPHOTPParamsDN   = "otpFoldName=HOTP Params+uid=primary,ou=otp," + dnIdentityOTPBaseDN
	dnIdentityOTPHOTPParamsRef  = `UID=PRIMARY+1.3.6.1.4.1.99999.932.2=\20hotp\20\20params\20,OU=OTP,DC=EXAMPLE,DC=COM`
	dnIdentityOTPTOTPUserDN     = "otpFoldName=TOTP User,ou=people," + dnIdentityOTPBaseDN
	dnIdentityOTPTOTPUserRef    = `otpFoldAlias=\20totp\20\20user\20,OU=PEOPLE,DC=EXAMPLE,DC=COM`
	dnIdentityOTPTOTPTokenDN    = "otpExactName=TOTP+otpFoldName=Primary Token,ou=otp," + dnIdentityOTPBaseDN
	dnIdentityOTPTOTPTokenRef   = "otpFoldAlias=primary token+otpExactAlias=TOTP,OU=OTP,DC=EXAMPLE,DC=COM"
	dnIdentityOTPTOTPParamsDN   = "otpFoldName=TOTP Params+uid=primary,ou=otp," + dnIdentityOTPBaseDN
	dnIdentityOTPTOTPParamsRef  = `UID=PRIMARY+otpFoldAlias=\20totp\20\20params\20,OU=OTP,DC=EXAMPLE,DC=COM`
	dnIdentityOTPStaticPassword = "static-secret"
)

func TestDNIdentityOTPOverlayBindAndStateUpdate(t *testing.T) {
	for _, backend := range dnIdentityOTPBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })

			registry := dnIdentityOTPRegistry(t)
			database := dnIdentityOTPDatabase(t, registry)
			runtime := &runtimeState{
				schema:    registry,
				databases: []runtimeDatabase{database},
			}
			instance := &Server{config: Config{Store: store}}
			seedDNIdentityOTPEntries(t, store, database)

			userDN := mustDNIdentityOTPLegacyDN(t, dnIdentityOTPUserAliasDN)
			setDNIdentityOTPUserToken(
				t,
				store,
				database,
				dnIdentityOTPUserDN,
				dnIdentityOTPLowerReference,
			)
			credential := []byte(
				dnIdentityOTPStaticPassword +
					openLDAPOTPToken(openLDAPOTPSecret, 4, 6),
			)
			handled, static, result := instance.prepareOTPBind(
				context.Background(), runtime, database, userDN, credential,
			)
			if !handled || result.Code != ldapwire.ResultInvalidCredentials || static != nil {
				t.Fatalf(
					"caseExact-mismatched Bind = handled %t, static %q, result %d",
					handled,
					static,
					result.Code,
				)
			}
			assertDNIdentityOTPState(t, store, database, dnIdentityOTPTokenDN, "oathHOTPCounter", "3")
			assertDNIdentityOTPState(t, store, database, dnIdentityOTPLowerTokenDN, "oathHOTPCounter", "10")

			setDNIdentityOTPUserToken(
				t,
				store,
				database,
				dnIdentityOTPUserDN,
				dnIdentityOTPTokenReference,
			)
			handled, static, result = instance.prepareOTPBind(
				context.Background(), runtime, database, userDN, credential,
			)
			if !handled || result.Code != ldapwire.ResultSuccess ||
				!bytes.Equal(static, []byte(dnIdentityOTPStaticPassword)) {
				t.Fatalf(
					"schema-equivalent HOTP Bind = handled %t, static %q, result %d",
					handled,
					static,
					result.Code,
				)
			}
			assertDNIdentityOTPState(t, store, database, dnIdentityOTPTokenDN, "oathHOTPCounter", "4")
			assertDNIdentityOTPState(t, store, database, dnIdentityOTPLowerTokenDN, "oathHOTPCounter", "10")

			testDNIdentityOTPTOTPBind(t, instance, store, runtime, database)
		})
	}
}

func TestDNIdentityOTPConfigurationKeyUsesConfigIdentity(t *testing.T) {
	entry := otpOverlayEntry(false)
	entry.DN = "olcOverlay={0}OTP,olcDatabase={1}MDB,CN=CONFIG"
	configuration, err := loadOTPRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadOTPRuntimeConfiguration(): %v", err)
	}
	want := mustDNIdentityOTPLegacyDN(t, otpTestOverlayDN).Key()
	if configuration.configDNKey != want {
		t.Fatalf("config DN key = %q, want %q", configuration.configDNKey, want)
	}
}

func testDNIdentityOTPTOTPBind(
	t *testing.T,
	instance *Server,
	store storage.Store,
	runtime *runtimeState,
	database runtimeDatabase,
) {
	t.Helper()
	period := int64(315360000)
	step := time.Now().Unix() / period
	credential := []byte(
		dnIdentityOTPStaticPassword +
			openLDAPOTPToken(openLDAPOTPSecret, uint64(step), 6),
	)
	userDN := mustDNIdentityOTPLegacyDN(t, dnIdentityOTPTOTPUserRef)
	handled, static, result := instance.prepareOTPBind(
		context.Background(), runtime, database, userDN, credential,
	)
	if !handled || result.Code != ldapwire.ResultSuccess ||
		!bytes.Equal(static, []byte(dnIdentityOTPStaticPassword)) {
		t.Fatalf(
			"schema-equivalent TOTP Bind = handled %t, static %q, result %d",
			handled,
			static,
			result.Code,
		)
	}
	assertDNIdentityOTPState(
		t,
		store,
		database,
		dnIdentityOTPTOTPTokenDN,
		"oathTOTPLastTimeStep",
		strconv.FormatInt(step, 10),
	)
	assertDNIdentityOTPState(
		t,
		store,
		database,
		dnIdentityOTPTOTPTokenDN,
		"oathTOTPTimeStepDrift",
		"0",
	)
}

func dnIdentityOTPRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.932.1 NAME ( 'otpExactName' 'otpExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.932.2 NAME ( 'otpFoldName' 'otpFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityOTPDatabase(t *testing.T, registry *schema.Registry) runtimeDatabase {
	t.Helper()
	suffix, err := registry.NormalizeDN(dnIdentityOTPBaseDN)
	if err != nil {
		t.Fatalf("NormalizeDN(suffix): %v", err)
	}
	return runtimeDatabase{
		name:         "{1}mdb",
		partition:    "dn-identity-otp",
		suffixes:     []directory.DN{suffix},
		dnNormalizer: registry,
		lastMod:      false,
		otp:          &otpRuntimeConfiguration{},
	}
}

func seedDNIdentityOTPEntries(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: dnIdentityOTPHOTPParamsDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathHOTPParams")},
				{Description: "oathOTPLength", Values: stringValues("6")},
				{Description: "oathHOTPLookAhead", Values: stringValues("3")},
				{Description: "oathHMACAlgorithm", Values: stringValues(otpHMACSHA1OID)},
			},
		},
		{
			DN: dnIdentityOTPTokenDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathHOTPToken")},
				{Description: "oathHOTPParams", Values: stringValues(dnIdentityOTPHOTPParamsRef)},
				{Description: "oathSecret", Values: stringValues(openLDAPOTPSecret)},
				{Description: "oathHOTPCounter", Values: stringValues("3")},
			},
		},
		{
			DN: dnIdentityOTPLowerTokenDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathHOTPToken")},
				{Description: "oathHOTPParams", Values: stringValues(dnIdentityOTPHOTPParamsRef)},
				{Description: "oathSecret", Values: stringValues("different-secret")},
				{Description: "oathHOTPCounter", Values: stringValues("10")},
			},
		},
		{
			DN: dnIdentityOTPUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson", "oathHOTPUser")},
				{Description: "oathHOTPToken", Values: stringValues(dnIdentityOTPTokenReference)},
			},
		},
		{
			DN: dnIdentityOTPTOTPParamsDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathTOTPParams")},
				{Description: "oathOTPLength", Values: stringValues("6")},
				{Description: "oathTOTPTimeStepPeriod", Values: stringValues("315360000")},
				{Description: "oathTOTPTimeStepWindow", Values: stringValues("0")},
				{Description: "oathHMACAlgorithm", Values: stringValues(otpHMACSHA1OID)},
			},
		},
		{
			DN: dnIdentityOTPTOTPTokenDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathTOTPToken")},
				{Description: "oathTOTPParams", Values: stringValues(dnIdentityOTPTOTPParamsRef)},
				{Description: "oathSecret", Values: stringValues(openLDAPOTPSecret)},
			},
		},
		{
			DN: dnIdentityOTPTOTPUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson", "oathTOTPUser")},
				{Description: "oathTOTPToken", Values: stringValues(dnIdentityOTPTOTPTokenRef)},
			},
		},
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
		t.Fatalf("seed OTP DN identity entries: %v", err)
	}
}

func setDNIdentityOTPUserToken(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	rawUserDN string,
	tokenReference string,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		user, err := tx.Get(mustDNIdentityOTPLegacyDN(t, rawUserDN))
		if err != nil {
			return err
		}
		user.ReplaceValues("oathHOTPToken", stringValues(tokenReference))
		return tx.Put(user, true)
	}); err != nil {
		t.Fatalf("set OTP user token reference: %v", err)
	}
}

func assertDNIdentityOTPState(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	rawDN string,
	attribute string,
	want string,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := readerForDatabase(reader, database).Get(
			mustDNIdentityOTPLegacyDN(t, rawDN),
		)
		if err != nil {
			return err
		}
		values := entry.Values(attribute)
		if len(values) != 1 || string(values[0]) != want {
			t.Fatalf("%s %s = %q, want %q", rawDN, attribute, values, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("read OTP state %s: %v", rawDN, err)
	}
}

func mustDNIdentityOTPLegacyDN(t *testing.T, raw string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", raw, err)
	}
	return dn
}

type dnIdentityOTPBackend struct {
	name string
	open func(*testing.T) storage.Store
}

func dnIdentityOTPBackends() []dnIdentityOTPBackend {
	return []dnIdentityOTPBackend{
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
