package server

import (
	"context"
	"errors"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/scram"
)

func TestDNIdentityRuntimeAuthorizationPaths(t *testing.T) {
	store := newDNIdentityRoutingStore(
		t,
		dnIdentityRoutingConfig(
			dnIdentityRoutingMDB(
				1,
				"exactName=Tenant",
				"exactName=Admin,exactName=Tenant",
				"exact-secret",
			),
			dnIdentityRoutingMDB(
				2,
				"foldName=Remote Tenant",
				"foldName=Directory Admin,foldName=Remote Tenant",
				"fold-secret",
			),
		),
		nil,
	)
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	t.Cleanup(instance.closeSQLBackends)
	runtime := instance.runtime.Load()

	exactRoot := mustDNIdentityAuthorizationDN(
		t,
		"exactName=Admin,exactName=Tenant",
	)
	exactDifferentCase := mustDNIdentityAuthorizationDN(
		t,
		"exactName=admin,exactName=Tenant",
	)
	exactSubject := mustDNIdentityAuthorizationDN(
		t,
		"exactName=User,exactName=Tenant",
	)
	foldEquivalentRoot := mustDNIdentityAuthorizationDN(
		t,
		`foldName=\20DIRECTORY\20\20ADMIN\20,foldName=\20REMOTE\20\20TENANT\20`,
	)
	foldSubject := mustDNIdentityAuthorizationDN(
		t,
		"foldName=User,foldName=Remote Tenant",
	)

	t.Run("SASL root authorization uses schema equality", func(t *testing.T) {
		if !saslRootMayAuthorize(runtime, exactRoot, exactSubject) {
			t.Fatal("configured caseExact root was not authorized")
		}
		if saslRootMayAuthorize(runtime, exactDifferentCase, exactSubject) {
			t.Fatal("caseExact-different root was authorized")
		}
		if !saslRootMayAuthorize(runtime, foldEquivalentRoot, foldSubject) {
			t.Fatal("caseIgnore-equivalent root was not authorized")
		}
	})

	t.Run("SASL self identity uses schema equality", func(t *testing.T) {
		if runtimeDNEqual(runtime, exactRoot, exactDifferentCase) {
			t.Fatal("caseExact-different identities compared equal")
		}
		configuredFoldRoot := mustDNIdentityAuthorizationDN(
			t,
			"foldName=Directory Admin,foldName=Remote Tenant",
		)
		if !runtimeDNEqual(runtime, configuredFoldRoot, foldEquivalentRoot) {
			t.Fatal("caseIgnore-equivalent identities compared different")
		}
	})

	t.Run("SCRAM and DIGEST root credential lookup uses schema equality", func(t *testing.T) {
		exactRuntime := *runtime
		exactRuntime.sasl = runtime.sasl

		scramRule, err := parseSASLAuthzRegexp(
			`{0}^uid=[^,]+,cn=scram-sha-256,cn=auth$ exactName=Admin,exactName=Tenant`,
		)
		if err != nil {
			t.Fatalf("parse SCRAM authz regexp: %v", err)
		}
		exactRuntime.sasl.authzRegexps = []saslAuthzRegexp{scramRule}
		if _, _, err := instance.lookupSASLSCRAMCredentials(
			context.Background(),
			&exactRuntime,
			"SCRAM-SHA-256",
			"root",
			scram.SHA256,
		); err != nil {
			t.Fatalf("lookup configured caseExact SCRAM root: %v", err)
		}
		lowerSCRAMRule, err := parseSASLAuthzRegexp(
			`{0}^uid=[^,]+,cn=scram-sha-256,cn=auth$ exactName=admin,exactName=Tenant`,
		)
		if err != nil {
			t.Fatalf("parse lower-case SCRAM authz regexp: %v", err)
		}
		exactRuntime.sasl.authzRegexps = []saslAuthzRegexp{lowerSCRAMRule}
		if _, _, err := instance.lookupSASLSCRAMCredentials(
			context.Background(),
			&exactRuntime,
			"SCRAM-SHA-256",
			"root",
			scram.SHA256,
		); !errors.Is(err, errSASLSCRAMCredentialsUnavailable) {
			t.Fatalf("caseExact-different SCRAM root error = %v, want unavailable", err)
		}

		digestRule, err := parseSASLAuthzRegexp(
			`{0}^uid=[^,]+,cn=example\.com,cn=digest-md5,cn=auth$ exactName=Admin,exactName=Tenant`,
		)
		if err != nil {
			t.Fatalf("parse DIGEST authz regexp: %v", err)
		}
		exactRuntime.sasl.realm = "example.com"
		exactRuntime.sasl.authzRegexps = []saslAuthzRegexp{digestRule}
		credentials, err := instance.lookupSASLDigestMD5Credentials(
			context.Background(),
			&exactRuntime,
			"root",
		)
		if err != nil {
			t.Fatalf("lookup configured caseExact DIGEST root: %v", err)
		}
		defer credentials.clear()
		if string(credentials.password) != "exact-secret" {
			t.Fatalf("DIGEST root password = %q, want exact-secret", credentials.password)
		}
		lowerDigestRule, err := parseSASLAuthzRegexp(
			`{0}^uid=[^,]+,cn=example\.com,cn=digest-md5,cn=auth$ exactName=admin,exactName=Tenant`,
		)
		if err != nil {
			t.Fatalf("parse lower-case DIGEST authz regexp: %v", err)
		}
		exactRuntime.sasl.authzRegexps = []saslAuthzRegexp{lowerDigestRule}
		if _, err := instance.lookupSASLDigestMD5Credentials(
			context.Background(),
			&exactRuntime,
			"root",
		); !errors.Is(err, errSASLDigestMD5CredentialsUnavailable) {
			t.Fatalf("caseExact-different DIGEST root error = %v, want unavailable", err)
		}
	})

	t.Run("shadow updateDN and referral suffix use schema equality", func(t *testing.T) {
		exactDatabase := *databaseForDN(runtime, exactSubject)
		exactDatabase.shadow = false
		if err := loadRuntimeShadowSettings(directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcUpdateDN", Values: stringValues(exactRoot.String())},
				{Description: "olcUpdateRef", Values: stringValues("ldap://provider.example")},
			},
		}, &exactDatabase); err != nil {
			t.Fatalf("loadRuntimeShadowSettings(): %v", err)
		}
		shadowRuntime := *runtime
		shadowRuntime.databases = []runtimeDatabase{exactDatabase}
		if result := updateOperationPrecondition(
			&shadowRuntime,
			exactRoot.String(),
			exactSubject,
		); result != nil {
			t.Fatalf("configured caseExact updateDN result = %#v, want allowed", result)
		}
		if result := updateOperationPrecondition(
			&shadowRuntime,
			exactDifferentCase.String(),
			exactSubject,
		); result == nil || result.Code != ldapwire.ResultReferral {
			t.Fatalf("caseExact-different updateDN result = %#v, want referral", result)
		}
	})

	t.Run("retcode root bind uses schema equality", func(t *testing.T) {
		exactDatabase := *databaseForDN(runtime, exactRoot)
		request := ldapwire.BindRequest{
			Version: 3,
			Authentication: ldapwire.Authentication{
				Simple: []byte("exact-secret"),
			},
		}
		if !instance.retcodeSuccessfulRootBind(
			context.Background(), runtime, exactDatabase, exactRoot, request,
		) {
			t.Fatal("configured caseExact retcode root bind was not recognized")
		}
		if instance.retcodeSuccessfulRootBind(
			context.Background(), runtime, exactDatabase, exactDifferentCase, request,
		) {
			t.Fatal("caseExact-different retcode root bind was recognized")
		}

		foldDatabase := *databaseForDN(runtime, foldSubject)
		request.Authentication.Simple = []byte("fold-secret")
		if !instance.retcodeSuccessfulRootBind(
			context.Background(), runtime, foldDatabase, foldEquivalentRoot, request,
		) {
			t.Fatal("caseIgnore-equivalent retcode root bind was not recognized")
		}
	})
}

func mustDNIdentityAuthorizationDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
