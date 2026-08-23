package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const (
	saslIdentityExactOID = "1.3.6.1.4.1.99999.926.1"
	saslIdentityFoldOID  = "1.3.6.1.4.1.99999.926.2"
)

func TestDNIdentitySASLIdentityRewrite(t *testing.T) {
	registry, runtime := dnIdentitySASLIdentityRuntime(t)
	instance := &Server{}

	t.Run("direct request identity", func(t *testing.T) {
		mapped, err := instance.saslUserDN(
			context.Background(),
			runtime,
			"PLAIN",
			"Alice Smith",
			"",
		)
		if err != nil {
			t.Fatalf("saslUserDN(): %v", err)
		}
		want := mustDNIdentitySASLIdentityDN(
			t,
			registry,
			"uid=Alice Smith,cn=plain,cn=auth",
		)
		if !mapped.Equal(want) {
			t.Fatalf("direct request DN = %q, want %q", mapped.String(), want.String())
		}
		if !strings.HasPrefix(mapped.Key(), "dn:v2:") {
			t.Fatalf("direct request DN key = %q, want schema-aware identity", mapped.Key())
		}
	})

	t.Run("regexp sees normalized text and maps aliases OIDs and multi AVA", func(t *testing.T) {
		rule, err := parseSASLAuthzRegexp(
			`{0}"^uid=alice smith,cn=plain,cn=auth$" ` +
				`saslExactAlias=Alice+` + saslIdentityFoldOID +
				`=\20SMITH\20,DC=EXAMPLE,DC=COM`,
		)
		if err != nil {
			t.Fatalf("parseSASLAuthzRegexp(): %v", err)
		}
		runtime.sasl.authzRegexps = []saslAuthzRegexp{rule}

		mapped, err := instance.saslUserDN(
			context.Background(),
			runtime,
			"PLAIN",
			"Alice  Smith",
			"",
		)
		if err != nil {
			t.Fatalf("saslUserDN(regexp): %v", err)
		}
		want := mustDNIdentitySASLIdentityDN(
			t,
			registry,
			"saslExactName=Alice+saslFoldName=smith,dc=example,dc=com",
		)
		if !mapped.Equal(want) {
			t.Fatalf(
				"regexp mapped DN = %q (%q), want %q (%q)",
				mapped.String(),
				mapped.NormalizedString(),
				want.String(),
				want.NormalizedString(),
			)
		}

		rule, err = parseSASLAuthzRegexp(
			`{0}^dn:v2:.*$ saslExactName=wrong,dc=example,dc=com`,
		)
		if err != nil {
			t.Fatalf("parse opaque-key regexp: %v", err)
		}
		runtime.sasl.authzRegexps = []saslAuthzRegexp{rule}
		direct, err := instance.saslUserDN(
			context.Background(),
			runtime,
			"PLAIN",
			"Alice Smith",
			"",
		)
		if err != nil {
			t.Fatalf("saslUserDN(opaque-key regexp): %v", err)
		}
		request := mustDNIdentitySASLIdentityDN(
			t,
			registry,
			"uid=Alice Smith,cn=plain,cn=auth",
		)
		if !direct.Equal(request) {
			t.Fatalf("regexp matched opaque key: got %q, want %q", direct.String(), request.String())
		}
	})
}

func TestDNIdentitySASLAuthorizationIDs(t *testing.T) {
	registry, runtime := dnIdentitySASLIdentityRuntime(t)
	instance := &Server{}
	authenticationDN := mustDNIdentitySASLIdentityDN(
		t,
		registry,
		"saslExactName=Alice+saslFoldName=Smith,dc=example,dc=com",
	)
	equivalent := "saslExactAlias=Alice+" + saslIdentityFoldOID +
		`=\20SMITH\20,DC=EXAMPLE,DC=COM`

	t.Run("dn authorization ID", func(t *testing.T) {
		got, err := instance.resolveSASLAuthorizationDN(
			context.Background(),
			runtime,
			"PLAIN",
			"alice",
			authenticationDN,
			"dn:"+equivalent,
		)
		if err != nil || !got.Equal(authenticationDN) {
			t.Fatalf("equivalent dn: authorization ID = %q, %v", got.String(), err)
		}

		caseExactDifferent := strings.Replace(equivalent, "=Alice+", "=alice+", 1)
		_, err = instance.resolveSASLAuthorizationDN(
			context.Background(),
			runtime,
			"PLAIN",
			"alice",
			authenticationDN,
			"dn:"+caseExactDifferent,
		)
		if !errors.Is(err, errSASLAuthorizationDenied) {
			t.Fatalf("caseExact-different dn: error = %v, want denied", err)
		}
	})

	t.Run("u authorization ID regexp rewrite", func(t *testing.T) {
		rule, err := parseSASLAuthzRegexp(
			`{0}^uid=delegate,cn=plain,cn=auth$ ` + equivalent,
		)
		if err != nil {
			t.Fatalf("parseSASLAuthzRegexp(): %v", err)
		}
		runtime.sasl.authzRegexps = []saslAuthzRegexp{rule}
		got, err := instance.resolveSASLAuthorizationDN(
			context.Background(),
			runtime,
			"PLAIN",
			"alice",
			authenticationDN,
			"u:delegate",
		)
		if err != nil || !got.Equal(authenticationDN) {
			t.Fatalf("equivalent u: authorization ID = %q, %v", got.String(), err)
		}
	})
}

func TestDNIdentitySASLIdentityLegacyFallback(t *testing.T) {
	rule, err := parseSASLAuthzRegexp(
		`{0}^uid=alice,cn=plain,cn=auth$ CN=Mapped,DC=Example,DC=COM`,
	)
	if err != nil {
		t.Fatalf("parseSASLAuthzRegexp(): %v", err)
	}
	runtime := &runtimeState{sasl: saslRuntimeConfiguration{
		authzRegexps: []saslAuthzRegexp{rule},
	}}
	mapped, err := (&Server{}).saslUserDN(
		context.Background(),
		runtime,
		"PLAIN",
		"Alice",
		"",
	)
	if err != nil {
		t.Fatalf("legacy saslUserDN(): %v", err)
	}
	want, err := directory.ParseDN("cn=mapped,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(want): %v", err)
	}
	if !mapped.Equal(want) || strings.HasPrefix(mapped.Key(), "dn:v2:") {
		t.Fatalf("legacy mapped DN = %q, key %q", mapped.String(), mapped.Key())
	}
}

func dnIdentitySASLIdentityRuntime(
	t *testing.T,
) (*schema.Registry, *runtimeState) {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( " + saslIdentityExactOID +
			" NAME ( 'saslExactName' 'saslExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + saslIdentityFoldOID +
			" NAME ( 'saslFoldName' 'saslFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	suffix := mustDNIdentitySASLIdentityDN(t, registry, "dc=example,dc=com")
	runtime := &runtimeState{
		schema: registry,
		databases: []runtimeDatabase{{
			name:         "{1}mdb",
			partition:    "dn-identity-sasl-identity",
			suffixes:     []directory.DN{suffix},
			dnNormalizer: registry,
		}},
	}
	return registry, runtime
}

func mustDNIdentitySASLIdentityDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(value)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", value, err)
	}
	return dn
}
