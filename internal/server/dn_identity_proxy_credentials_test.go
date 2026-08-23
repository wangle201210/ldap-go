package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const dnIdentityProxyCredentialPartition = "dn-identity-proxy-credentials"

func TestDNIdentityProxyAuthorizationIDs(t *testing.T) {
	registry, runtime, _ := dnIdentityProxyCredentialRuntime(t, nil)
	instance := &Server{}
	equivalent := `1.3.6.1.4.1.99999.925.2=\20SMITH\20+credentialExactAlias=Alice,DC=EXAMPLE,DC=COM`
	want := mustDNIdentityProxyCredentialDN(
		t,
		registry,
		"credentialExactName=Alice+credentialFoldName=Smith,dc=example,dc=com",
	)

	got, err := instance.proxiedAuthorizationDN(
		context.Background(),
		runtime,
		"PLAIN",
		want.String(),
		[]byte("dn:"+equivalent),
	)
	if err != nil || !got.Equal(want) {
		t.Fatalf("proxiedAuthorizationDN(dn:) = %q, %v; want %q", got.String(), err, want.String())
	}
	if got.NormalizedString() != want.NormalizedString() {
		t.Fatalf(
			"proxiedAuthorizationDN(dn:) normalized = %q, want %q",
			got.NormalizedString(),
			want.NormalizedString(),
		)
	}

	rule, err := parseSASLAuthzRegexp(
		`{0}^uid=alice,cn=plain,cn=auth$ ` + equivalent,
	)
	if err != nil {
		t.Fatalf("parseSASLAuthzRegexp(): %v", err)
	}
	runtime.sasl.authzRegexps = []saslAuthzRegexp{rule}
	got, err = instance.proxiedAuthorizationDN(
		context.Background(),
		runtime,
		"PLAIN",
		want.String(),
		[]byte("u:alice"),
	)
	if err != nil || !got.Equal(want) {
		t.Fatalf("proxiedAuthorizationDN(u:) = %q, %v; want %q", got.String(), err, want.String())
	}

	message := ldapwire.Message{
		Request: ldapwire.ExtendedRequest{Name: whoAmIOID},
		Controls: []ldapwire.Control{{
			OID:      proxyAuthorizationControlOID,
			Critical: true,
			HasValue: true,
			Value:    []byte("dn:" + want.String()),
		}},
	}
	state := &connectionState{runtime: runtime, boundDN: equivalent}
	_, effectiveDN, applied, result := instance.applyProxyAuthorization(
		context.Background(),
		state,
		message,
	)
	if result != nil || !applied || effectiveDN != want.String() {
		t.Fatalf("schema-equivalent proxy authorization = %q, %t, %#v", effectiveDN, applied, result)
	}

	exactDifferent := strings.Replace(equivalent, "=Alice,", "=alice,", 1)
	state.boundDN = exactDifferent
	_, _, applied, result = instance.applyProxyAuthorization(
		context.Background(),
		state,
		message,
	)
	if applied || result == nil || result.Code != ldapwire.ResultProxiedAuthorizationDenied {
		t.Fatalf("caseExact-different proxy authorization = %t, %#v", applied, result)
	}
}

func TestDNIdentityBackendCredentialLookup(t *testing.T) {
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
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			registry, runtime, database := dnIdentityProxyCredentialRuntime(t, store)
			canonical := "credentialExactName=Alice+credentialFoldName=Smith,dc=example,dc=com"
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				tx := storage.WriterInPartitionWithNormalizer(
					writer,
					database.partition,
					registry,
				)
				return tx.Put(directory.Entry{
					DN: canonical,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("person")},
						{Description: "cn", Values: stringValues("Alice")},
						{Description: "sn", Values: stringValues("Smith")},
						{Description: "userPassword", Values: stringValues("secret")},
					},
				}, false)
			}); err != nil {
				t.Fatalf("seed credential entry: %v", err)
			}

			instance := &Server{config: Config{Store: store}}
			equivalent := mustDNIdentityProxyCredentialLegacyDN(
				t,
				`1.3.6.1.4.1.99999.925.2=\20SMITH\20+credentialExactAlias=Alice,DC=EXAMPLE,DC=COM`,
			)
			entry, err := instance.lookupSASLCredentialEntry(
				context.Background(),
				runtime,
				equivalent,
				[]string{"userPassword"},
			)
			values := entry.Values("userPassword")
			if err != nil || len(values) != 1 || string(values[0]) != "secret" {
				t.Fatalf("schema-equivalent credential lookup = %#v, %v", entry, err)
			}
			clearSASLCredentialEntry(&entry)

			exactDifferent := mustDNIdentityProxyCredentialLegacyDN(
				t,
				"credentialFoldAlias=SMITH+credentialExactAlias=alice,dc=example,dc=com",
			)
			_, err = instance.lookupSASLCredentialEntry(
				context.Background(),
				runtime,
				exactDifferent,
				[]string{"userPassword"},
			)
			if !errors.Is(err, errSASLCredentialEntryUnavailable) {
				t.Fatalf("caseExact-different credential lookup error = %v, want unavailable", err)
			}
		})
	}
}

func TestDNIdentityRemoteCredentialEntryValidation(t *testing.T) {
	_, runtime, _ := dnIdentityProxyCredentialRuntime(t, nil)
	want := mustDNIdentityProxyCredentialLegacyDN(
		t,
		"credentialExactName=Alice+credentialFoldName=Smith,dc=example,dc=com",
	)
	attempt := dnIdentityProxyCredentialAttempt(t, directory.Entry{
		DN: `1.3.6.1.4.1.99999.925.2=\20SMITH\20+credentialExactAlias=Alice,DC=EXAMPLE,DC=COM`,
		Attributes: []directory.Attribute{{
			Description: "userPassword",
			Values:      stringValues("secret"),
		}},
	})
	entry, err := saslBackendCredentialEntryFromAttempt(
		runtime,
		want,
		[]string{"userPassword"},
		attempt,
	)
	values := entry.Values("userPassword")
	if err != nil || len(values) != 1 || string(values[0]) != "secret" {
		t.Fatalf("schema-equivalent remote credential entry = %#v, %v", entry, err)
	}
	clearSASLCredentialEntry(&entry)
	clearSASLCredentialAttempt(&attempt)

	attempt = dnIdentityProxyCredentialAttempt(t, directory.Entry{
		DN: "credentialFoldName=SMITH+credentialExactName=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "userPassword",
			Values:      stringValues("secret"),
		}},
	})
	_, err = saslBackendCredentialEntryFromAttempt(
		runtime,
		want,
		[]string{"userPassword"},
		attempt,
	)
	if err == nil || !strings.Contains(err.Error(), "unexpected entry") {
		t.Fatalf("caseExact-different remote credential entry error = %v", err)
	}
	clearSASLCredentialAttempt(&attempt)
}

func dnIdentityProxyCredentialRuntime(
	t *testing.T,
	store storage.Store,
) (*schema.Registry, *runtimeState, runtimeDatabase) {
	t.Helper()
	registry := dnIdentityProxyCredentialRegistry(t)
	database := runtimeDatabase{
		name:         "{1}mdb",
		partition:    dnIdentityProxyCredentialPartition,
		suffixes:     []directory.DN{mustDNIdentityProxyCredentialDN(t, registry, "dc=example,dc=com")},
		dnNormalizer: registry,
	}
	runtime := &runtimeState{
		schema:    registry,
		access:    acl.DefaultPolicy(),
		databases: []runtimeDatabase{database},
	}
	return registry, runtime, database
}

func dnIdentityProxyCredentialRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.925.1 NAME ( 'credentialExactName' 'credentialExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.925.2 NAME ( 'credentialFoldName' 'credentialFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func mustDNIdentityProxyCredentialDN(
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

func mustDNIdentityProxyCredentialLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func dnIdentityProxyCredentialAttempt(
	t *testing.T,
	entry directory.Entry,
) chainAttempt {
	t.Helper()
	packet, err := ber.DecodePacketErr(ldapwire.EncodeSearchResultEntry(1, entry, nil))
	if err != nil {
		t.Fatalf("decode credential SearchResultEntry: %v", err)
	}
	return chainAttempt{
		packets:    []*ber.Packet{packet},
		result:     ldapwire.Result{Code: ldapwire.ResultSuccess},
		hasResult:  true,
		hasEntries: true,
	}
}
