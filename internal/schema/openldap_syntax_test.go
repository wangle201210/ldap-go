package schema

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseAndFormatLDAPSyntax(t *testing.T) {
	t.Parallel()

	ldapSyntax, err := ParseLDAPSyntax(
		"{7}( 1.2.3.4 DESC 'custom syntax' X-OTHER ( 'one' 'two' ) " +
			"X-SUBST '1.3.6.1.4.1.1466.115.121.1.15' )",
	)
	if err != nil {
		t.Fatalf("ParseLDAPSyntax(): %v", err)
	}
	if ldapSyntax.OID != "1.2.3.4" || ldapSyntax.Description != "custom syntax" {
		t.Fatalf("ParseLDAPSyntax() = %#v", ldapSyntax)
	}
	if values := ldapSyntax.Extensions["X-SUBST"]; len(values) != 1 ||
		values[0] != SyntaxDirectoryString {
		t.Fatalf("X-SUBST = %#v", values)
	}

	formatted := FormatLDAPSyntax(ldapSyntax)
	parsedAgain, err := ParseLDAPSyntax(formatted)
	if err != nil {
		t.Fatalf("ParseLDAPSyntax(FormatLDAPSyntax()): %v", err)
	}
	if parsedAgain.OID != ldapSyntax.OID ||
		parsedAgain.Description != ldapSyntax.Description ||
		len(parsedAgain.Extensions["X-OTHER"]) != 2 ||
		parsedAgain.Extensions["X-SUBST"][0] != SyntaxDirectoryString {
		t.Fatalf("round trip = %#v; formatted %q", parsedAgain, formatted)
	}
}

func TestLoadOpenLDAPConfigLDAPSyntaxesInXOrderedOrder(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "cn={1}custom,cn=schema,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcLdapSyntaxes",
				Values: byteValues(
					"{2}( 1.2.3.102 DESC 'certificate alias chain' X-SUBST '1.2.3.101' )",
					"{0}( 1.2.3.100 DESC 'declaration only' X-BINARY-TRANSFER-REQUIRED 'TRUE' )",
					"{1}( 1.2.3.101 DESC 'certificate alias' X-SUBST '"+SyntaxCertificate+"' )",
				),
			},
			{
				Description: "olcAttributeTypes",
				Values: byteValues(
					"{0}( 1.2.3.200 NAME 'declarationOnlyValue' SYNTAX 1.2.3.100 )",
					"{1}( 1.2.3.201 NAME 'certificateAliasValue' SYNTAX 1.2.3.102 )",
				),
			},
		},
	}
	registry, result, err := loadOpenLDAPSyntaxTestEntry(t, entry)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.Syntaxes != 3 || result.AttributeTypes != 2 {
		t.Fatalf("LoadResult = %#v", result)
	}

	declaration, found := registry.LDAPSyntax("1.2.3.100")
	if !found {
		t.Fatal("ordinary LDAP syntax was not registered")
	}
	if declaration.BinaryTransferRequired || declaration.BEREncoded || declaration.HasValidator() {
		t.Fatalf("ordinary LDAP syntax inherited behavior from declaration extensions: %#v", declaration)
	}
	if err := registry.ValidateAttributeValue("declarationOnlyValue", []byte("anything")); err == nil ||
		!strings.Contains(err.Error(), "no validator for syntax 1.2.3.100") {
		t.Fatalf("ordinary syntax value-check error = %v", err)
	}

	alias, found := registry.LDAPSyntax("1.2.3.102")
	if !found || !alias.BinaryTransferRequired || !alias.BEREncoded || !alias.HasValidator() {
		t.Fatalf("chained X-SUBST syntax = %#v, found %t", alias, found)
	}
	attribute, found := registry.AttributeType("certificateAliasValue")
	if !found {
		t.Fatal("certificateAliasValue was not registered")
	}
	if err := registry.validateAttributeDescription("certificateAliasValue", attribute); err == nil ||
		!strings.Contains(err.Error(), "needs ';binary'") {
		t.Fatalf("alias bare AttributeDescription error = %v", err)
	}
	if err := registry.validateAttributeDescription("certificateAliasValue;binary", attribute); err != nil {
		t.Fatalf("alias ;binary AttributeDescription: %v", err)
	}
	if err := registry.ValidateAttributeValue("certificateAliasValue", []byte{0x30, 0x00}); err == nil {
		t.Fatal("X-SUBST alias did not inherit the certificate validator")
	}
}

func TestLoadOpenLDAPConfigLDAPSyntaxesAcceptsBuiltinDeclarations(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "cn=schema,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcLdapSyntaxes",
				Values: byteValues(
					"{0}( "+SyntaxACIItem+" DESC 'ACI Item exported by OpenLDAP' )",
					"{1}( "+SyntaxCertificate+" DESC 'Certificate exported by OpenLDAP' )",
					"{2}( "+SyntaxSupportedAlgorithm+" DESC 'Supported Algorithm exported by OpenLDAP' )",
				),
			},
		},
	}
	registry, result, err := loadOpenLDAPSyntaxTestEntry(t, entry)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.Syntaxes != 3 {
		t.Fatalf("LoadResult = %#v", result)
	}
	for _, oid := range []string{SyntaxACIItem, SyntaxCertificate, SyntaxSupportedAlgorithm} {
		ldapSyntax, found := registry.LDAPSyntax(oid)
		if !found || !ldapSyntax.BinaryTransferRequired || !ldapSyntax.BEREncoded {
			t.Fatalf("LDAPSyntax(%q) = %#v, found %t", oid, ldapSyntax, found)
		}
	}
	if aci, _ := registry.LDAPSyntax(SyntaxACIItem); aci.HasValidator() {
		t.Fatal("an exported ACI Item declaration added a validator")
	}
	if supported, _ := registry.LDAPSyntax(SyntaxSupportedAlgorithm); !supported.HasValidator() {
		t.Fatal("an exported Supported Algorithm declaration removed its validator")
	}
}

func TestLoadOpenLDAPConfigLDAPSyntaxesIsIdempotent(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "cn={1}repeatable,cn=schema,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcLdapSyntaxes",
				Values: byteValues(
					"{0}( 1.2.3.105 DESC 'repeatable alias' X-SUBST '" + SyntaxDirectoryString + "' )",
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.PutIn(storage.OpenLDAPConfigPartition, entry, false)
	}); err != nil {
		t.Fatalf("seed schema entry: %v", err)
	}
	registry := NewRegistry()
	for attempt := 1; attempt <= 2; attempt++ {
		result, err := LoadOpenLDAPConfig(context.Background(), store, registry)
		if err != nil {
			t.Fatalf("LoadOpenLDAPConfig() attempt %d: %v", attempt, err)
		}
		if result.Syntaxes != 1 {
			t.Fatalf("attempt %d LoadResult = %#v", attempt, result)
		}
	}
}

func TestLoadOpenLDAPConfigLDAPSyntaxesRejectsConflictingDuplicates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
	}{
		{
			name: "builtin behavior conflict",
			values: []string{
				"{0}( " + SyntaxCertificate + " X-SUBST '" + SyntaxDirectoryString + "' )",
			},
		},
		{
			name: "dynamic declaration conflict",
			values: []string{
				"{0}( 1.2.3.106 DESC 'first' X-SUBST '" + SyntaxDirectoryString + "' )",
				"{1}( 1.2.3.106 DESC 'different' X-SUBST '" + SyntaxDirectoryString + "' )",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{
				DN: "cn={1}conflict,cn=schema,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcLdapSyntaxes",
						Values:      byteValues(test.values...),
					},
				},
			}
			_, _, err := loadOpenLDAPSyntaxTestEntry(t, entry)
			if err == nil || !strings.Contains(err.Error(), "conflicts with the already registered definition") {
				t.Fatalf("LoadOpenLDAPConfig() error = %v", err)
			}
		})
	}
}

func TestLoadOpenLDAPConfigLDAPSyntaxesRejectsInvalidSubstitutions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{
			name:   "unknown target",
			values: []string{"{0}( 1.2.3.110 X-SUBST '1.2.3.999' )"},
			want:   "is not registered",
		},
		{
			name: "multiple targets",
			values: []string{
				"{0}( 1.2.3.111 X-SUBST ( '" + SyntaxDirectoryString + "' '" + SyntaxOctetString + "' ) )",
			},
			want: "exactly one X-SUBST",
		},
		{
			name: "forward reference after ordering",
			values: []string{
				"{1}( 1.2.3.113 X-SUBST '" + SyntaxDirectoryString + "' )",
				"{0}( 1.2.3.112 X-SUBST '1.2.3.113' )",
			},
			want: "is not registered",
		},
		{
			name: "mixed indexed and unindexed values",
			values: []string{
				"{0}( 1.2.3.114 X-SUBST '" + SyntaxDirectoryString + "' )",
				"( 1.2.3.115 X-SUBST '" + SyntaxDirectoryString + "' )",
			},
			want: "indexed and unindexed values cannot be mixed",
		},
		{
			name:   "unknown descriptor target",
			values: []string{"{0}( 1.2.3.116 X-SUBST 'missingSyntaxMacro' )"},
			want:   "undefined object identifier descriptor",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{
				DN: "cn={1}invalid,cn=schema,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcLdapSyntaxes",
						Values:      byteValues(test.values...),
					},
				},
			}
			_, _, err := loadOpenLDAPSyntaxTestEntry(t, entry)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadOpenLDAPConfig() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadOpenLDAPConfigLDAPSyntaxesUsesConfigDNOrder(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "cn={2}consumer,cn=schema,cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcLdapSyntaxes",
					Values: byteValues(
						"{0}( 1.2.3.121 X-SUBST '1.2.3.120' )",
					),
				},
			},
		},
		{
			DN: "cn={1}provider,cn=schema,cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcLdapSyntaxes",
					Values: byteValues(
						"{0}( 1.2.3.120 X-SUBST '" + SyntaxDirectoryString + "' )",
					),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed schema entries: %v", err)
	}
	registry := NewRegistry()
	result, err := LoadOpenLDAPConfig(context.Background(), store, registry)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.Syntaxes != 2 {
		t.Fatalf("LoadResult = %#v", result)
	}
	consumer, found := registry.LDAPSyntax("1.2.3.121")
	if !found || !consumer.HasValidator() {
		t.Fatalf("consumer syntax = %#v, found %t", consumer, found)
	}
}

func loadOpenLDAPSyntaxTestEntry(
	t *testing.T,
	entry directory.Entry,
) (*Registry, LoadResult, error) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.PutIn(storage.OpenLDAPConfigPartition, entry, false)
	}); err != nil {
		t.Fatalf("seed schema entry: %v", err)
	}
	registry := NewRegistry()
	result, err := LoadOpenLDAPConfig(context.Background(), store, registry)
	return registry, result, err
}
