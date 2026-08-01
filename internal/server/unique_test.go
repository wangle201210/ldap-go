package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseUniqueDomain(t *testing.T) {
	t.Parallel()

	database := uniqueTestDatabase(t)
	domain, err := parseUniqueDomain(
		"{4}ignore serialize strict "+
			"ldap:///ou=people,dc=example,dc=com?uid,mail?one?"+
			"(objectClass=inetOrgPerson) "+
			"ldap:///ou=archive,dc=example,dc=com?description?sub",
		database,
	)
	if err != nil {
		t.Fatalf("parseUniqueDomain(): %v", err)
	}
	if !domain.ignore || !domain.serialize || !domain.strict ||
		len(domain.uris) != 2 {
		t.Fatalf("domain = %#v", domain)
	}
	if domain.uris[0].scope != directory.ScopeSingleLevel ||
		len(domain.uris[0].attributes) != 2 ||
		domain.uris[0].filter == nil ||
		domain.uris[1].scope != directory.ScopeWholeSubtree {
		t.Fatalf("domain URIs = %#v", domain.uris)
	}

	strictIgnore, err := parseUniqueDomain(
		"strict ignore ldap:///??sub",
		database,
	)
	if err != nil {
		t.Fatalf("parse strict-ignore domain: %v", err)
	}
	if !strictIgnore.strict || !strictIgnore.ignore {
		t.Fatalf("strict-ignore domain = %#v", strictIgnore)
	}
}

func TestParseUniqueDomainRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	database := uniqueTestDatabase(t)
	for name, value := range map[string]string{
		"empty":          "",
		"keywords-only":  "ignore serialize strict",
		"base-scope":     "ldap:///ou=people,dc=example,dc=com?uid?base",
		"remote-host":    "ldap://directory.example/??sub",
		"outside-suffix": "ldap:///dc=other,dc=com?uid?sub",
		"bad-order":      "{-1}ldap:///??sub",
		"bad-keyword-order": "strict serialize " +
			"ldap:///??sub",
	} {
		value := value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseUniqueDomain(value, database); err == nil {
				t.Fatalf("parseUniqueDomain(%q) succeeded", value)
			}
		})
	}
}

func TestValidateUniqueSchemaRejectsNoncanonicalFilter(t *testing.T) {
	t.Parallel()

	if _, err := parseUniqueDomain(
		"ldap:///??sub?((uid=test))",
		uniqueTestDatabase(t),
	); err == nil {
		t.Fatal("OpenLDAP-invalid noncanonical filter was accepted")
	}
}

func TestLoadUniqueRuntimeConfigurationLegacy(t *testing.T) {
	t.Parallel()

	database := uniqueTestDatabase(t)
	entry := directory.Entry{
		DN: "olcOverlay={0}unique,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues("{0}unique")},
			{
				Description: "olcUniqueAttribute",
				Values:      stringValues("uid mail", "description"),
			},
			{
				Description: "olcUniqueBase",
				Values:      stringValues("ou=people,dc=example,dc=com"),
			},
			{Description: "olcUniqueStrict", Values: stringValues("TRUE")},
		},
	}
	configuration, err := loadUniqueRuntimeConfiguration(entry, database)
	if err != nil {
		t.Fatalf("loadUniqueRuntimeConfiguration(): %v", err)
	}
	if len(configuration.domains) != 1 ||
		!configuration.domains[0].strict ||
		configuration.domains[0].ignore ||
		len(configuration.domains[0].uris) != 1 {
		t.Fatalf("legacy configuration = %#v", configuration)
	}
	uri := configuration.domains[0].uris[0]
	if uri.base == nil ||
		uri.base.Key() != "ou=people,dc=example,dc=com" ||
		strings.Join(uri.attributes, ",") != "uid,mail,description" {
		t.Fatalf("legacy URI = %#v", uri)
	}
}

func TestLoadUniqueRuntimeConfigurationRejectsMixedAndInvalidLegacy(t *testing.T) {
	t.Parallel()

	database := uniqueTestDatabase(t)
	for name, attributes := range map[string][]directory.Attribute{
		"URI-and-legacy": {
			{Description: "olcUniqueURI", Values: stringValues("ldap:///??sub")},
			{Description: "olcUniqueAttribute", Values: stringValues("uid")},
		},
		"attribute-and-ignore": {
			{Description: "olcUniqueAttribute", Values: stringValues("uid")},
			{Description: "olcUniqueIgnore", Values: stringValues("mail")},
		},
		"multiple-base": {
			{Description: "olcUniqueBase", Values: stringValues(
				"ou=people,dc=example,dc=com",
				"ou=archive,dc=example,dc=com",
			)},
		},
		"bad-strict": {
			{Description: "olcUniqueStrict", Values: stringValues("sometimes")},
		},
		"outside-base": {
			{Description: "olcUniqueBase", Values: stringValues("dc=other,dc=com")},
		},
	} {
		attributes := attributes
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entry := directory.Entry{
				DN:         "olcOverlay=unique,olcDatabase={1}mdb,cn=config",
				Attributes: attributes,
			}
			if _, err := loadUniqueRuntimeConfiguration(entry, database); err == nil {
				t.Fatal("invalid unique configuration was accepted")
			}
		})
	}
}

func TestValidateUniqueSchema(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	configuration := uniqueRuntimeConfiguration{domains: []uniqueDomain{{
		uris: []uniqueURI{{
			attributes: []string{"uid", "mail;lang-en"},
			scope:      directory.ScopeWholeSubtree,
		}},
	}}}
	if err := validateUniqueSchema(registry, &configuration); err != nil {
		t.Fatalf("validateUniqueSchema(): %v", err)
	}

	configuration.domains[0].uris[0].attributes = []string{"undefinedUnique"}
	if err := validateUniqueSchema(registry, &configuration); err == nil {
		t.Fatal("undefined unique attribute was accepted")
	}
}

func TestUniqueAssertions(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	attributes := []directory.Attribute{
		{Description: "uid", Values: stringValues("alice")},
		{Description: "mail", Values: stringValues("alice@example.com")},
		{Description: "description"},
		{Description: "entryUUID", Values: stringValues("ignored")},
	}
	domain := uniqueDomain{strict: true}
	uri := uniqueURI{
		attributes: []string{"uid", "description"},
		scope:      directory.ScopeWholeSubtree,
	}
	assertions := uniqueAssertions(registry, domain, uri, attributes)
	if len(assertions) != 2 ||
		assertions[0].Kind != directory.FilterEquality ||
		assertions[1].Kind != directory.FilterPresent {
		t.Fatalf("selected assertions = %#v", assertions)
	}

	domain.ignore = true
	assertions = uniqueAssertions(registry, domain, uri, attributes)
	if len(assertions) != 1 || assertions[0].Attribute != "mail" {
		t.Fatalf("ignore assertions = %#v", assertions)
	}
}

func TestLoadRuntimeDatabasesLoadsUniqueOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		uniqueOverlayEntry("{0}"),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed unique configuration: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databases[databaseIndexForDN(databases, suffix)]
	if database.unique == nil || len(database.unique.domains) != 1 ||
		len(database.unique.domains[0].uris) != 1 {
		t.Fatalf("unique runtime configuration = %#v", database.unique)
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidUniquePlacement(t *testing.T) {
	t.Parallel()

	for name, entries := range map[string][]directory.Entry{
		"duplicate": {
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				},
			},
			uniqueOverlayEntry("{0}"),
			uniqueOverlayEntry("{1}"),
		},
		"frontend": {
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				}},
			},
			{
				DN: "olcOverlay={0}unique,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcOverlay", Values: stringValues("{0}unique")},
					{Description: "olcUniqueURI", Values: stringValues("ldap:///??sub")},
				},
			},
		},
	} {
		entries := entries
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				for _, entry := range entries {
					if err := writer.Put(entry, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("seed invalid placement: %v", err)
			}
			if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
				t.Fatal("invalid unique placement was accepted")
			}
		})
	}
}

func uniqueOverlayEntry(order string) directory.Entry {
	return directory.Entry{
		DN: "olcOverlay=" + order + "unique,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues(order + "unique")},
			{Description: "olcUniqueURI", Values: stringValues("ldap:///?uid?sub")},
		},
	}
}

func uniqueTestDatabase(t *testing.T) runtimeDatabase {
	t.Helper()
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	return runtimeDatabase{
		name:     "{1}mdb",
		suffixes: []directory.DN{suffix},
	}
}
