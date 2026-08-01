package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadMemberOfRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcMemberOfDN", Values: stringValues("cn=overlay,dc=example,dc=com")},
			{Description: "olcMemberOfDangling", Values: stringValues("error")},
			{Description: "olcMemberOfDanglingError", Values: stringValues("noSuchObject")},
			{Description: "olcMemberOfRefInt", Values: stringValues("TRUE")},
			{Description: "olcMemberOfAddCheck", Values: stringValues("TRUE")},
			{Description: "olcMemberOfGroupOC", Values: stringValues("groupA")},
			{Description: "olcMemberOfMemberAD", Values: stringValues("memberA")},
			{Description: "olcMemberOfMemberOfAD", Values: stringValues("memberOfA")},
		},
	}
	configuration, err := loadMemberOfRuntimeConfiguration(entry, memberOfTestDatabase(t))
	if err != nil {
		t.Fatalf("loadMemberOfRuntimeConfiguration(): %v", err)
	}
	if configuration.modifierDN == nil ||
		configuration.modifierDN.Key() != "cn=overlay,dc=example,dc=com" ||
		configuration.dangling != memberOfDanglingError ||
		configuration.danglingError != ldapwire.ResultNoSuchObject ||
		!configuration.refint || !configuration.addCheck ||
		configuration.groupObjectClass != "groupA" ||
		configuration.memberAttribute != "memberA" ||
		configuration.memberOfAttribute != "memberOfA" {
		t.Fatalf("configuration = %#v", configuration)
	}

	defaults, err := loadMemberOfRuntimeConfiguration(
		directory.Entry{DN: entry.DN},
		memberOfTestDatabase(t),
	)
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	if defaults.dangling != memberOfDanglingIgnore ||
		defaults.danglingError != ldapwire.ResultConstraintViolation ||
		defaults.groupObjectClass != "groupOfNames" ||
		defaults.memberAttribute != "member" ||
		defaults.memberOfAttribute != "memberOf" ||
		defaults.refint || defaults.addCheck || defaults.modifierDN != nil {
		t.Fatalf("defaults = %#v", defaults)
	}
}

func TestLoadMemberOfRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := map[string]directory.Attribute{
		"multiple": {
			Description: "olcMemberOfGroupOC",
			Values:      stringValues("groupOfNames", "groupA"),
		},
		"empty":       {Description: "olcMemberOfMemberAD", Values: stringValues(" ")},
		"DN":          {Description: "olcMemberOfDN", Values: stringValues("not a DN")},
		"dangling":    {Description: "olcMemberOfDangling", Values: stringValues("keep")},
		"result-code": {Description: "olcMemberOfDanglingError", Values: stringValues("missing")},
		"boolean":     {Description: "olcMemberOfRefInt", Values: stringValues("sometimes")},
		"reverse":     {Description: "olcMemberOfReverse", Values: stringValues("TRUE")},
	}
	for name, attribute := range tests {
		attribute := attribute
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entry := directory.Entry{
				DN:         "olcOverlay=memberof,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{attribute},
			}
			if _, err := loadMemberOfRuntimeConfiguration(
				entry,
				memberOfTestDatabase(t),
			); err == nil {
				t.Fatal("invalid memberof configuration was accepted")
			}
		})
	}
}

func TestValidateMemberOfSchema(t *testing.T) {
	t.Parallel()

	registry := memberOfTestRegistry(t)
	configuration := memberOfRuntimeConfiguration{
		groupObjectClass:  "groupOfNames",
		memberAttribute:   "member",
		memberOfAttribute: "memberOf",
	}
	if err := validateMemberOfSchema(
		registry,
		[]memberOfRuntimeConfiguration{configuration},
	); err != nil {
		t.Fatalf("validateMemberOfSchema(valid): %v", err)
	}
	configuration.memberAttribute = "mail"
	if err := validateMemberOfSchema(
		registry,
		[]memberOfRuntimeConfiguration{configuration},
	); err == nil || !strings.Contains(err.Error(), "not DN or nameAndOptionalUID-valued") {
		t.Fatalf("non-DN member attribute error = %v", err)
	}
	configuration.memberAttribute = "undefinedMember"
	if err := validateMemberOfSchema(
		registry,
		[]memberOfRuntimeConfiguration{configuration},
	); err == nil || !strings.Contains(err.Error(), "undefined") {
		t.Fatalf("undefined member attribute error = %v", err)
	}
}

func TestLoadRuntimeDatabasesLoadsMultipleMemberOfAndRefintOverlays(t *testing.T) {
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
		memberOfOverlayEntry("{0}", nil),
		memberOfOverlayEntry("{1}", []directory.Attribute{
			{Description: "olcMemberOfGroupOC", Values: stringValues("groupA")},
			{Description: "olcMemberOfMemberAD", Values: stringValues("memberA")},
			{Description: "olcMemberOfMemberOfAD", Values: stringValues("memberOfA")},
		}),
		refintOverlayEntry("{2}", []string{"member", "manager"}, ""),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed overlays: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	suffix, _ := directory.ParseDN("dc=example,dc=com")
	database := databases[databaseIndexForDN(databases, suffix)]
	if len(database.memberOf) != 2 || len(database.refint) != 1 ||
		len(database.refint[0].attributes) != 2 {
		t.Fatalf(
			"loaded memberof=%#v refint=%#v",
			database.memberOf,
			database.refint,
		)
	}
}

func TestMutateDNReferenceUsesDNEquality(t *testing.T) {
	t.Parallel()

	registry := memberOfTestRegistry(t)
	oldDN, _ := directory.ParseDN("cn=Old Group,ou=groups,dc=example,dc=com")
	newDN, _ := directory.ParseDN("cn=New Group,ou=groups,dc=example,dc=com")
	entry := directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "memberOf",
			Values: stringValues(
				"CN=old group,OU=groups,DC=example,DC=com",
				"cn=Other,ou=groups,dc=example,dc=com",
			),
		}},
	}
	if !mutateDNReference(registry, &entry, "memberOf", &oldDN, &newDN) {
		t.Fatal("DN reference replacement reported no change")
	}
	values := entry.Values("memberOf")
	if len(values) != 2 || !containsDNValue(values, newDN) || containsDNValue(values, oldDN) {
		t.Fatalf("memberOf values = %q", values)
	}
}

func memberOfTestDatabase(t *testing.T) runtimeDatabase {
	t.Helper()
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	return runtimeDatabase{
		name:      "{1}mdb",
		partition: configuredDatabasePartition("{1}mdb"),
		suffixes:  []directory.DN{suffix},
		lastMod:   true,
	}
}

func memberOfTestRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.1.1 NAME 'memberA' EQUALITY distinguishedNameMatch SYNTAX " +
			schema.SyntaxDistinguishedName + " )",
		"( 1.3.6.1.4.1.99999.1.2 NAME 'memberOfA' EQUALITY distinguishedNameMatch SYNTAX " +
			schema.SyntaxDistinguishedName +
			" NO-USER-MODIFICATION USAGE dSAOperation )",
		"( 1.3.6.1.4.1.99999.1.3 NAME 'managerRef' EQUALITY distinguishedNameMatch SYNTAX " +
			schema.SyntaxDistinguishedName + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register attribute %q: %v", definition, err)
		}
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.2.1 NAME 'groupA' SUP top STRUCTURAL MUST ( cn $ memberA ) )",
		"( 1.3.6.1.4.1.99999.2.2 NAME 'refHolder' SUP top AUXILIARY MAY managerRef )",
	} {
		if err := registry.ParseAndRegisterObjectClass(definition); err != nil {
			t.Fatalf("register objectClass %q: %v", definition, err)
		}
	}
	return registry
}

func memberOfOverlayEntry(
	order string,
	extra []directory.Attribute,
) directory.Entry {
	attributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcMemberOfConfig")},
		{Description: "olcOverlay", Values: stringValues(order + "memberof")},
	}
	attributes = append(attributes, extra...)
	return directory.Entry{
		DN:         "olcOverlay=" + order + "memberof,olcDatabase={1}mdb,cn=config",
		Attributes: attributes,
	}
}
