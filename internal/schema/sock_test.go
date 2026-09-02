package schema

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestRegisterOpenLDAPSockSchema(t *testing.T) {
	registry := NewRegistry()
	if err := RegisterOpenLDAPSockSchema(registry); err != nil {
		t.Fatalf("RegisterOpenLDAPSockSchema(): %v", err)
	}

	path, ok := registry.AttributeType("olcDbSocketPath")
	if !ok {
		t.Fatal("olcDbSocketPath is not registered")
	}
	if path.OID != openLDAPSockDatabaseAttributeOID+".1" ||
		!reflect.DeepEqual(path.Names, []string{"olcDbSocketPath"}) ||
		path.Description != "Pathname for Unix domain socket" ||
		path.Equality != "caseExactMatch" ||
		path.Syntax != SyntaxDirectoryString ||
		!path.SingleValue {
		t.Fatalf("olcDbSocketPath = %#v", path)
	}

	extensions, ok := registry.AttributeType("olcDbSocketExtensions")
	if !ok {
		t.Fatal("olcDbSocketExtensions is not registered")
	}
	if extensions.OID != openLDAPSockDatabaseAttributeOID+".2" ||
		!reflect.DeepEqual(extensions.Names, []string{"olcDbSocketExtensions"}) ||
		extensions.Description != "binddn, peername, or ssf" ||
		extensions.Equality != "caseIgnoreMatch" ||
		extensions.Syntax != SyntaxDirectoryString ||
		extensions.SingleValue {
		t.Fatalf("olcDbSocketExtensions = %#v", extensions)
	}
	callbackTimeout, ok := registry.AttributeType(ldapGoSockCallbackTimeoutName)
	if !ok {
		t.Fatalf("%s is not registered", ldapGoSockCallbackTimeoutName)
	}
	if callbackTimeout.OID != ldapGoSockExtensionOID+".1" ||
		callbackTimeout.Syntax != SyntaxDirectoryString ||
		!callbackTimeout.SingleValue ||
		!reflect.DeepEqual(
			callbackTimeout.Extensions["X-ORIGIN"],
			[]string{"ldap-go extension"},
		) {
		t.Fatalf("%s = %#v", ldapGoSockCallbackTimeoutName, callbackTimeout)
	}

	objectClass, ok := registry.ObjectClass("olcDbSocketConfig")
	if !ok {
		t.Fatal("olcDbSocketConfig is not registered")
	}
	if objectClass.OID != openLDAPSockDatabaseObjectOID+".1" ||
		!reflect.DeepEqual(objectClass.Names, []string{"olcDbSocketConfig"}) ||
		objectClass.Description != "Socket backend configuration" ||
		!reflect.DeepEqual(objectClass.Superiors, []string{"olcDatabaseConfig"}) ||
		objectClass.Kind != ObjectClassStructural ||
		!reflect.DeepEqual(objectClass.Must, []string{"olcDbSocketPath"}) ||
		!reflect.DeepEqual(objectClass.May, []string{"olcDbSocketExtensions"}) {
		t.Fatalf("olcDbSocketConfig = %#v", objectClass)
	}

	overlay, ok := registry.ObjectClass("olcOvSocketConfig")
	if !ok {
		t.Fatal("olcOvSocketConfig is not registered")
	}
	if overlay.OID != openLDAPSockDatabaseObjectOID+".2" ||
		!reflect.DeepEqual(overlay.Superiors, []string{"olcOverlayConfig"}) ||
		!reflect.DeepEqual(overlay.Must, []string{"olcDbSocketPath"}) ||
		!reflect.DeepEqual(overlay.May, []string{
			"olcDbSocketExtensions",
			"olcOvSocketOps",
			"olcOvSocketResps",
			"olcOvSocketDNpat",
			ldapGoSockCallbackTimeoutName,
		}) {
		t.Fatalf("olcOvSocketConfig = %#v", overlay)
	}

	for _, description := range openLDAPSockAttributeTypes {
		if _, err := ParseAttributeType(description); err != nil {
			t.Fatalf("parse emitted attribute type %q: %v", description, err)
		}
	}
	for _, description := range ldapGoSockExtensionAttributeTypes {
		if _, err := ParseAttributeType(description); err != nil {
			t.Fatalf("parse ldap-go extension attribute type %q: %v", description, err)
		}
	}
	for _, description := range openLDAPSockObjectClasses {
		if _, err := ParseObjectClass(description); err != nil {
			t.Fatalf("parse emitted object class %q: %v", description, err)
		}
	}
}

func TestRegisterOpenLDAPSockSchemaIsIdempotentAndCompatible(t *testing.T) {
	registry := NewRegistry()
	attribute, err := ParseAttributeType(openLDAPSockAttributeTypes[0])
	if err != nil {
		t.Fatalf("parse attribute: %v", err)
	}
	attribute.Names = append(attribute.Names, "preloadedSocketPath")
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatalf("preload attribute: %v", err)
	}
	objectClass, err := ParseObjectClass(openLDAPSockObjectClasses[0])
	if err != nil {
		t.Fatalf("parse object class: %v", err)
	}
	objectClass.Names = append(objectClass.Names, "preloadedSocketConfig")
	if err := registry.RegisterObjectClass(objectClass); err != nil {
		t.Fatalf("preload object class: %v", err)
	}

	for call := 1; call <= 2; call++ {
		if err := RegisterOpenLDAPSockSchema(registry); err != nil {
			t.Fatalf("RegisterOpenLDAPSockSchema() call %d: %v", call, err)
		}
	}
	if _, ok := registry.AttributeType("preloadedSocketPath"); !ok {
		t.Fatal("compatible attribute alias was discarded")
	}
	if _, ok := registry.ObjectClass("preloadedSocketConfig"); !ok {
		t.Fatal("compatible object class alias was discarded")
	}
}

func TestRegisterOpenLDAPSockSchemaRejectsInvalidRegistration(t *testing.T) {
	t.Run("nil registry", func(t *testing.T) {
		err := RegisterOpenLDAPSockSchema(nil)
		if err == nil || err.Error() != "register OpenLDAP back-sock schema: nil registry" {
			t.Fatalf("RegisterOpenLDAPSockSchema(nil) error = %v", err)
		}
	})

	t.Run("incompatible attribute", func(t *testing.T) {
		registry := NewRegistry()
		attribute, err := ParseAttributeType(openLDAPSockAttributeTypes[0])
		if err != nil {
			t.Fatalf("parse attribute: %v", err)
		}
		attribute.Equality = "caseIgnoreMatch"
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatalf("preload attribute: %v", err)
		}
		err = RegisterOpenLDAPSockSchema(registry)
		if err == nil || !strings.Contains(err.Error(), "incompatible existing definition") {
			t.Fatalf("RegisterOpenLDAPSockSchema() error = %v", err)
		}
	})

	t.Run("identifier conflict", func(t *testing.T) {
		registry := NewRegistry()
		byOID, err := ParseAttributeType(openLDAPSockAttributeTypes[0])
		if err != nil {
			t.Fatalf("parse OID attribute: %v", err)
		}
		byOID.Names = []string{"otherSocketPath"}
		if err := registry.RegisterAttributeType(byOID); err != nil {
			t.Fatalf("register OID attribute: %v", err)
		}
		byName, err := ParseAttributeType(openLDAPSockAttributeTypes[0])
		if err != nil {
			t.Fatalf("parse named attribute: %v", err)
		}
		byName.OID = openLDAPSockDatabaseAttributeOID + ".99"
		if err := registry.RegisterAttributeType(byName); err != nil {
			t.Fatalf("register named attribute: %v", err)
		}
		err = RegisterOpenLDAPSockSchema(registry)
		if err == nil || !strings.Contains(err.Error(), "identifiers conflict") {
			t.Fatalf("RegisterOpenLDAPSockSchema() error = %v", err)
		}
	})
}

func TestValidateOpenLDAPSockExtensions(t *testing.T) {
	valid := [][]string{
		nil,
		{"binddn"},
		{"BINDDN", "PeerName", "sSf", "CONNID"},
		{"binddn peername", "ssf connid"},
		{" binddn\tpeername  ssf\nconnid "},
		{"binddn", "binddn"},
	}
	for _, values := range valid {
		if err := ValidateOpenLDAPSockExtensions(values...); err != nil {
			t.Errorf("ValidateOpenLDAPSockExtensions(%q): %v", values, err)
		}
	}

	invalid := [][]string{
		{""},
		{" \t\n "},
		{"binddn remote-user"},
		{"peername", "tls"},
		{"binddn\u00a0peername"},
		{string([]byte{'s', 's', 'f', 0xff})},
	}
	for _, values := range invalid {
		if err := ValidateOpenLDAPSockExtensions(values...); err == nil {
			t.Errorf("ValidateOpenLDAPSockExtensions(%q) succeeded", values)
		}
	}
}

func TestOpenLDAPSockSchemaValidatesConfigEntry(t *testing.T) {
	registry, err := newSockConfigTestRegistry()
	if err != nil {
		t.Fatalf("newSockConfigTestRegistry(): %v", err)
	}

	entry := directory.Entry{
		DN: "olcDatabase={1}sock,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("olcDatabaseConfig", "olcDbSocketConfig")},
			{Description: "olcDatabase", Values: byteValues("{1}sock")},
			{Description: "olcDbSocketPath", Values: byteValues("/run/example.sock")},
			{Description: "olcDbSocketExtensions", Values: byteValues("binddn", "peername", "ssf", "connid")},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(real cn=config shape): %v", err)
	}
	values := entry.Values("olcDbSocketExtensions")
	textValues := make([]string, len(values))
	for i := range values {
		textValues[i] = string(values[i])
	}
	if err := ValidateOpenLDAPSockExtensions(textValues...); err != nil {
		t.Fatalf("ValidateOpenLDAPSockExtensions(real cn=config shape): %v", err)
	}

	missingPath := entry.Without("olcDbSocketPath")
	assertSockViolation(
		t,
		registry.ValidateEntry(missingPath),
		ViolationMissingRequiredAttribute,
	)

	multiplePaths := entry.Clone()
	multiplePaths.ReplaceValues("olcDbSocketPath", byteValues("/one.sock", "/two.sock"))
	assertSockViolation(t, registry.ValidateEntry(multiplePaths), ViolationSingleValue)

	invalidPath := entry.Clone()
	invalidPath.ReplaceValues("olcDbSocketPath", [][]byte{{0xff}})
	assertSockViolation(t, registry.ValidateEntry(invalidPath), ViolationSyntax)

	emptyExtension := entry.Clone()
	emptyExtension.ReplaceValues("olcDbSocketExtensions", byteValues(""))
	assertSockViolation(t, registry.ValidateEntry(emptyExtension), ViolationSyntax)

	withoutExtensions := entry.Without("olcDbSocketExtensions")
	if err := registry.ValidateEntry(withoutExtensions); err != nil {
		t.Fatalf("ValidateEntry(without optional extensions): %v", err)
	}
}

func newSockConfigTestRegistry() (*Registry, error) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		return nil, err
	}
	if !registry.HasAttributeType("olcDatabase") {
		if err := registry.ParseAndRegisterAttributeType(
			"( 1.3.6.1.4.1.4203.1.12.2.3.2.0.1 NAME 'olcDatabase' " +
				"EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
		); err != nil {
			return nil, err
		}
	}
	if err := registry.ParseAndRegisterObjectClass(
		"( 1.3.6.1.4.1.4203.1.12.2.4.0.4 NAME 'olcDatabaseConfig' " +
			"SUP olcConfig STRUCTURAL MUST olcDatabase )",
	); err != nil {
		return nil, err
	}
	if err := RegisterOpenLDAPSockSchema(registry); err != nil {
		return nil, err
	}
	return registry, nil
}

func assertSockViolation(t *testing.T, err error, want ViolationKind) {
	t.Helper()
	var violation *Violation
	if !errors.As(err, &violation) {
		t.Fatalf("error = %v, want schema violation %d", err, want)
	}
	if violation.Kind != want {
		t.Fatalf("violation kind = %d, want %d: %v", violation.Kind, want, err)
	}
}
