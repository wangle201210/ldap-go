package schema

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRegisterOpenLDAPAllowedSchema(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	wants := []struct{ oid, name, description string }{
		{"1.2.840.113556.1.4.911", "allowedChildClasses", "Child classes allowed for a given object"},
		{"1.2.840.113556.1.4.912", "allowedChildClassesEffective", "Child classes allowed for a given object according to ACLs"},
		{"1.2.840.113556.1.4.913", "allowedAttributes", "Attributes allowed for a given object"},
		{"1.2.840.113556.1.4.914", "allowedAttributesEffective", "Attributes allowed for a given object according to ACLs"},
	}
	for _, want := range wants {
		if registry.HasAttributeType(want.name) || registry.HasAttributeType(want.oid) {
			t.Fatalf("allowed schema is active without explicit registration: %s", want.name)
		}
	}
	before := len(registry.AttributeTypeDescriptions())
	for call := 0; call < 2; call++ {
		if err := RegisterOpenLDAPAllowedSchema(registry); err != nil {
			t.Fatal(err)
		}
		if got := len(registry.AttributeTypeDescriptions()); got != before+4 {
			t.Fatalf("registration %d: attribute count = %d, want %d", call, got, before+4)
		}
	}
	for _, want := range wants {
		for _, key := range []string{want.oid, want.name} {
			got, ok := registry.AttributeType(key)
			attribute := AttributeType{
				OID: want.oid, Names: []string{want.name}, Description: want.description,
				Equality: "objectIdentifierMatch", Syntax: "1.3.6.1.4.1.1466.115.121.1.38",
				NoUserModification: true, Usage: UsageDSAOperation,
			}
			// Parser initializes Extensions even when the source has none.
			attribute.Extensions = got.Extensions
			if !ok || len(got.Extensions) != 0 || !reflect.DeepEqual(got, attribute) {
				t.Fatalf("attribute %s = %#v, found %t", key, got, ok)
			}
		}
	}
}

func TestRegisterOpenLDAPAllowedSchemaImportedDefinitions(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	description := "( 1.2.840.113556.1.4.913 NAME ( 'allowedAttributes' 'allowedAttrsAlias' ) DESC 'Imported metadata' EQUALITY 2.5.13.0 SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 NO-USER-MODIFICATION USAGE dSAOperation X-ORIGIN 'deployment' )"
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.PutIn(storage.OpenLDAPConfigPartition, directory.Entry{
			DN:         "cn={1}allowed,cn=schema,cn=config",
			Attributes: []directory.Attribute{{Description: "olcAttributeTypes", Values: byteValues(description)}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOpenLDAPConfig(t.Context(), store, registry); err != nil {
		t.Fatal(err)
	}
	before, _ := registry.AttributeType("allowedAttributes")
	if err := RegisterOpenLDAPAllowedSchema(registry); err != nil {
		t.Fatal(err)
	}
	after, ok := registry.AttributeType("allowedAttrsAlias")
	if !ok || !reflect.DeepEqual(after, before) {
		t.Fatalf("compatible imported schema was replaced: %#v", after)
	}

	// Dynamic reloads import definitions before checking the active module.
	conflicting := before
	conflicting.NoUserModification = false
	if err := registry.UpsertAttributeType(conflicting); err != nil {
		t.Fatal(err)
	}
	if err := RegisterOpenLDAPAllowedSchema(registry); err == nil {
		t.Fatal("accepted modified active schema")
	}
}

func TestRegisterOpenLDAPAllowedSchemaRejectsConflictsAtomically(t *testing.T) {
	if err := RegisterOpenLDAPAllowedSchema(nil); err == nil {
		t.Fatal("accepted nil registry")
	}
	for _, test := range []struct {
		name   string
		change func(*AttributeType)
	}{
		{"OID", func(a *AttributeType) { a.OID = "1.2.3.4" }},
		{"name", func(a *AttributeType) { a.Names = []string{"unrelated"} }},
		{"hidden", func(a *AttributeType) { a.Hidden = true }},
		{"obsolete", func(a *AttributeType) { a.Obsolete = true }},
		{"superior", func(a *AttributeType) { a.Superior = "objectClass" }},
		{"equality", func(a *AttributeType) { a.Equality = "caseIgnoreMatch" }},
		{"ordering", func(a *AttributeType) { a.Ordering = "caseIgnoreOrderingMatch" }},
		{"substring", func(a *AttributeType) { a.Substring = "caseIgnoreSubstringsMatch" }},
		{"syntax", func(a *AttributeType) { a.Syntax = SyntaxDirectoryString }},
		{"syntax length", func(a *AttributeType) { a.SyntaxLength = 10 }},
		{"single value", func(a *AttributeType) { a.SingleValue = true }},
		{"user modification", func(a *AttributeType) { a.NoUserModification = false }},
		{"usage", func(a *AttributeType) { a.Usage = UsageDirectoryOperation }},
		{"ordered", func(a *AttributeType) { a.Extensions = map[string][]string{"X-ORDERED": {"VALUES"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := NewRegistry()
			conflicting, err := ParseAttributeType(openLDAPAllowedAttributeTypes[3])
			if err != nil {
				t.Fatal(err)
			}
			test.change(&conflicting)
			if err := registry.RegisterAttributeType(conflicting); err != nil {
				t.Fatal(err)
			}
			before := registry.AttributeTypeDescriptions()
			if err := RegisterOpenLDAPAllowedSchema(registry); err == nil || !strings.Contains(err.Error(), "incompatible") {
				t.Fatalf("conflict error = %v", err)
			}
			if got := registry.AttributeTypeDescriptions(); !reflect.DeepEqual(got, before) {
				t.Fatalf("failed registration changed the registry: %q", got)
			}
		})
	}
	t.Run("split identifiers", func(t *testing.T) {
		registry := NewRegistry()
		for _, definition := range []string{
			"( 1.2.840.113556.1.4.914 NAME 'other' SYNTAX " + SyntaxOID + " )",
			"( 1.2.3.4 NAME 'allowedAttributesEffective' SYNTAX " + SyntaxOID + " )",
		} {
			if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
				t.Fatal(err)
			}
		}
		before := registry.AttributeTypeDescriptions()
		if err := RegisterOpenLDAPAllowedSchema(registry); err == nil || !strings.Contains(err.Error(), "identifiers conflict") {
			t.Fatalf("identifier conflict error = %v", err)
		}
		if !reflect.DeepEqual(registry.AttributeTypeDescriptions(), before) {
			t.Fatal("identifier conflict changed registry")
		}
	})
}

func TestObjectClassesSnapshotIncludesHiddenAndIsIsolated(t *testing.T) {
	registry := NewRegistry()
	for index := 3; index > 0; index-- {
		objectClass := ObjectClass{
			OID: fmt.Sprintf("1.2.3.%d", index), Names: []string{fmt.Sprintf("class%d", index), fmt.Sprintf("alias%d", index)},
			Hidden: index == 2, Kind: ObjectClassAuxiliary, Superiors: []string{"top"},
			Must: []string{"cn"}, May: []string{"description"}, Extensions: map[string][]string{"X-ORIGIN": {"test"}},
		}
		if err := registry.RegisterObjectClass(objectClass); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := registry.ObjectClasses()
	if len(snapshot) != 3 || !snapshot[1].Hidden || len(registry.ObjectClassDescriptions()) != 2 {
		t.Fatalf("hidden class or aliases mishandled: %#v", snapshot)
	}
	for index, objectClass := range snapshot {
		if objectClass.OID != fmt.Sprintf("1.2.3.%d", index+1) {
			t.Fatalf("unstable OID order: %#v", snapshot)
		}
	}
	before := registry.ObjectClasses()
	for index := range snapshot {
		snapshot[index].Names[0] = "changed"
		snapshot[index].Superiors[0] = "changed"
		snapshot[index].Must[0] = "changed"
		snapshot[index].May[0] = "changed"
		snapshot[index].Extensions["X-ORIGIN"][0] = "changed"
		snapshot[index].Extensions["X-NEW"] = []string{"changed"}
		snapshot[index].Hidden = !snapshot[index].Hidden
	}
	if got := registry.ObjectClasses(); !reflect.DeepEqual(got, before) {
		t.Fatalf("snapshot mutation changed registry: %#v", got)
	}
	updated := before[0]
	updated.Names = []string{"renamed"}
	updated.Extensions = map[string][]string{"X-ORIGIN": {"updated"}}
	if err := registry.UpsertObjectClass(updated); err != nil {
		t.Fatal(err)
	}
	if before[0].Names[0] != "class1" || before[0].Extensions["X-ORIGIN"][0] != "test" {
		t.Fatal("registry update changed an existing snapshot")
	}
}
