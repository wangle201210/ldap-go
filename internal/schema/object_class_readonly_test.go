package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Preserve the 2645eba description check, without the exact-string fast path.
func originalObjectClassDescriptionSubtype(registry *Registry, candidate, requested string) bool {
	candidateName, candidateOptions := splitAttributeDescription(candidate)
	requestedName, requestedOptions := splitAttributeDescription(requested)
	candidateType, candidateKnown := registry.attributes[schemaKey(candidateName)]
	requestedType, requestedKnown := registry.attributes[schemaKey(requestedName)]
	if !candidateKnown || !requestedKnown {
		return schemaKey(candidateName) == schemaKey(requestedName) &&
			attributeOptionsSubtype(candidateOptions, requestedOptions)
	}
	return registry.attributeTypeSubtype(candidateType, requestedType, make(map[string]bool)) &&
		attributeOptionsSubtype(candidateOptions, requestedOptions)
}

// Preserve the original full scan and value clones, including the old subtype check.
func originalEntryHasObjectClass(registry *Registry, entry directory.Entry, name string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	target, ok := registry.objectClasses[schemaKey(name)]
	if !ok {
		return false
	}
	var values [][]byte
	for _, attribute := range entry.Attributes {
		if originalObjectClassDescriptionSubtype(registry, attribute.Description, "objectClass") {
			for _, value := range attribute.Values {
				values = append(values, bytes.Clone(value))
			}
		}
	}
	for _, value := range values {
		candidate, ok := registry.objectClasses[schemaKey(string(value))]
		if ok && registry.isSubclass(candidate, target, make(map[string]bool)) {
			return true
		}
	}
	return false
}

func objectClassReadOnlyRegistry(t testing.TB) *Registry {
	t.Helper()
	registry := NewRegistry()
	for _, attribute := range []AttributeType{
		{OID: "2.5.4.0", Names: []string{"objectClass", "classAlias", "\u212aClass"}},
		{OID: "1.2.1", Names: []string{"childClass"}, Superior: "classAlias"},
		{OID: "1.2.2", Names: []string{"grandchildClass"}, Superior: "childClass"},
		{OID: "1.2.3", Names: []string{"attrCycleA"}, Superior: "attrCycleB"},
		{OID: "1.2.4", Names: []string{"attrCycleB"}, Superior: "attrCycleA"},
		{OID: "1.2.5", Names: []string{"orphanAttr"}, Superior: "missingAttr"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, class := range []ObjectClass{
		{OID: "1.3.1", Names: []string{"root", "rootAlias", "\u00c9lite"}},
		{OID: "1.3.2", Names: []string{"left"}, Superiors: []string{"rootAlias"}},
		{OID: "1.3.3", Names: []string{"right"}, Superiors: []string{"1.3.1"}},
		{OID: "1.3.4", Names: []string{"leaf", "leafAlias"}, Superiors: []string{"left", "right"}},
		{OID: "1.3.5", Names: []string{"unrelated"}},
		{OID: "1.3.6", Names: []string{"cycleA"}, Superiors: []string{"cycleB"}},
		{OID: "1.3.7", Names: []string{"cycleB"}, Superiors: []string{"cycleA", "root"}},
		{OID: "1.3.8", Names: []string{"orphan"}, Superiors: []string{"missingParent"}},
		{OID: "1.3.9", Names: []string{"partial"}, Superiors: []string{"missingParent", "root"}},
	} {
		if err := registry.RegisterObjectClass(class); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func checkObjectClassReadOnly(t *testing.T, registry *Registry, entry directory.Entry, target string, want bool) {
	t.Helper()
	before := entry
	before.Attributes = slices.Clone(entry.Attributes)
	for i, attribute := range before.Attributes {
		before.Attributes[i].Values = slices.Clone(attribute.Values)
		for j, value := range attribute.Values {
			before.Attributes[i].Values[j] = bytes.Clone(value)
		}
	}
	for name, lookup := range map[string]func(directory.Entry, string) bool{
		"original": func(entry directory.Entry, target string) bool {
			return originalEntryHasObjectClass(registry, entry, target)
		},
		"current": registry.EntryHasObjectClass,
	} {
		if got := lookup(entry, target); got != want {
			t.Errorf("%s(%q) = %v, want %v", name, target, got, want)
		}
		if !reflect.DeepEqual(entry, before) {
			t.Fatalf("%s changed source entry: got %#v, want %#v", name, entry, before)
		}
	}
	registry.mu.RLock()
	if attribute := registry.attributes["objectclass"]; attribute != nil {
		registry.prepareAttributeNames(attribute)
	}
	registry.mu.RUnlock()
	if got := registry.EntryHasObjectClass(entry, target); got != want || !reflect.DeepEqual(entry, before) {
		t.Fatalf("prepared lookup(%q) = %v, want %v with unchanged entry", target, got, want)
	}
}

func TestEntryHasObjectClassReadOnly(t *testing.T) {
	registry := objectClassReadOnlyRegistry(t)
	attr := func(description string, values ...string) directory.Attribute {
		return directory.Attribute{Description: description, Values: byteValues(values...), RawNormalized: true}
	}
	for _, test := range []struct {
		name       string
		attributes []directory.Attribute
		target     string
		want       bool
	}{
		{"empty entry", nil, "root", false},
		{"empty attributes", []directory.Attribute{}, "root", false},
		{"nil values", []directory.Attribute{{Description: "objectClass"}}, "root", false},
		{"empty values", []directory.Attribute{{Description: "objectClass", Values: [][]byte{}}}, "root", false},
		{"nil and empty bytes", []directory.Attribute{{Description: "objectClass", Values: [][]byte{nil, {}}}}, "root", false},
		{"direct", []directory.Attribute{attr("objectClass", "root")}, "root", true},
		{"aliases", []directory.Attribute{attr("classAlias", "leafAlias")}, "rootAlias", true},
		{"OIDs", []directory.Attribute{attr("2.5.4.0", "1.3.4")}, "1.3.1", true},
		{"subtype options", []directory.Attribute{attr("grandchildClass;LANG-en;binary", "leaf")}, "root", true},
		{"subtype OID", []directory.Attribute{attr("1.2.1", "root")}, "root", true},
		{"mixed case", []directory.Attribute{attr("OBJECTCLASS", "LEAF")}, "ROOT", true},
		{"whitespace", []directory.Attribute{attr(" objectClass ; lang-en ", "\tLEAF\n")}, " root ", true},
		{"unicode", []directory.Attribute{attr("\u212aCLASS", "\u00e9LITE")}, "\u00c9LITE", true},
		{"unicode spaces", []directory.Attribute{attr("\u00a0objectClass\u2003", "\u2003root\u00a0")}, "root", true},
		{"unknown description", []directory.Attribute{attr("unknown", "root")}, "root", false},
		{"unknown target", []directory.Attribute{attr("objectClass", "unknown")}, "unknown", false},
		{"empty target", []directory.Attribute{attr("objectClass", "")}, "", false},
		{"unknown values", []directory.Attribute{attr("objectClass", "unknown", "\xff", "")}, "root", false},
		{"later value", []directory.Attribute{attr("objectClass", "unknown", "unrelated", "leaf")}, "root", true},
		{"later attribute", []directory.Attribute{attr("objectClass", "unrelated"), attr("classAlias;lang-en", "leaf")}, "root", true},
		{"early match", []directory.Attribute{attr("objectClass", "root", "cycleA"), attr("objectClass", "unknown")}, "root", true},
		{"multiple misses", []directory.Attribute{attr("objectClass", "orphan"), attr("objectClass;binary", "unrelated")}, "root", false},
		{"diamond", []directory.Attribute{attr("objectClass", "leaf")}, "root", true},
		{"diamond miss", []directory.Attribute{attr("objectClass", "leaf")}, "unrelated", false},
		{"reverse inheritance", []directory.Attribute{attr("objectClass", "root")}, "leaf", false},
		{"cycle exit", []directory.Attribute{attr("objectClass", "cycleA")}, "root", true},
		{"cycle member", []directory.Attribute{attr("objectClass", "cycleA")}, "cycleB", true},
		{"cycle miss", []directory.Attribute{attr("objectClass", "cycleA")}, "unrelated", false},
		{"missing parent", []directory.Attribute{attr("objectClass", "orphan")}, "root", false},
		{"missing parent sibling", []directory.Attribute{attr("objectClass", "partial")}, "root", true},
		{"attribute cycle", []directory.Attribute{attr("attrCycleA", "root")}, "root", false},
		{"attribute orphan", []directory.Attribute{attr("orphanAttr", "root")}, "root", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkObjectClassReadOnly(t, registry, directory.Entry{DN: "cn=source", Attributes: test.attributes}, test.target, test.want)
		})
	}
}

func TestAttributeDescriptionSubtypeExactReadOnlyDifferential(t *testing.T) {
	registry := objectClassReadOnlyRegistry(t)
	descriptions := []string{
		"", " ", "\t\n", ";", ";;", " ; ", "objectClass", "OBJECTCLASS", " objectClass ",
		"2.5.4.0", "classAlias", "\u212aCLASS", "kclass", "\u00a0objectClass\u2003",
		"objectClass;lang-en", "objectClass;LANG-en;binary", " objectClass ; LANG-en ; binary ",
		"objectClass;lang-", "objectClass;lang", "objectClass;", "objectClass;;", "objectClass;lang-en;lang-en",
		"childClass", "grandchildClass;lang-en", "attrCycleA", "attrCycleA;binary", "attrCycleB", "orphanAttr",
		"unknown", "UNKNOWN", "unknown;lang-en", "unknown;lang-", "unknown;", "\xff;\xfe", "\u00c9", "\u00e9",
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	for _, candidate := range descriptions {
		for _, requested := range descriptions {
			want := originalObjectClassDescriptionSubtype(registry, candidate, requested)
			got := registry.attributeDescriptionSubtype(candidate, requested)
			if got != want || (candidate == requested && !got) {
				t.Errorf("subtype(%q, %q) = %v, original %v", candidate, requested, got, want)
			}
		}
	}
}

func TestEntryHasObjectClassReadOnlySchemaMutation(t *testing.T) {
	registry := objectClassReadOnlyRegistry(t)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "lateAttr", Values: byteValues("lateClass")}}}
	check := func(err error, want bool) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		checkObjectClassReadOnly(t, registry, entry, "lateTarget", want)
	}
	check(nil, false)
	check(registry.RegisterObjectClass(ObjectClass{OID: "1.4.1", Names: []string{"lateTarget"}}), false)
	class := ObjectClass{OID: "1.4.2", Names: []string{"lateClass"}, Superiors: []string{"lateTarget"}}
	check(registry.RegisterObjectClass(class), false)
	attribute := AttributeType{OID: "1.4.3", Names: []string{"lateAttr"}, Superior: "objectClass"}
	check(registry.RegisterAttributeType(attribute), true)
	class.Superiors = []string{"unrelated"}
	check(registry.UpsertObjectClass(class), false)
	class.Superiors = []string{"lateTarget"}
	check(registry.UpsertObjectClass(class), true)
	attribute.Superior = ""
	check(registry.UpsertAttributeType(attribute), false)
	attribute.Superior = "objectClass"
	check(registry.UpsertAttributeType(attribute), true)
}

func TestEntryHasObjectClassReadOnlyWithoutAttributeSchema(t *testing.T) {
	registry := NewRegistry()
	if err := registry.RegisterObjectClass(ObjectClass{OID: "1.4.1", Names: []string{"target"}}); err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{Attributes: []directory.Attribute{
		{Description: " OBJECTCLASS;lang-en ", Values: byteValues("target")},
	}}
	checkObjectClassReadOnly(t, registry, entry, "target", true)
}

func TestEntryHasObjectClassReadOnlyDoesNotPrepareOnMiss(t *testing.T) {
	registry := objectClassReadOnlyRegistry(t)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "classAlias", Values: byteValues("leaf")}}}
	for _, target := range []string{"root", "unrelated"} {
		if got, want := registry.EntryHasObjectClass(entry, target), originalEntryHasObjectClass(registry, entry, target); got != want {
			t.Fatalf("cold lookup(%q) = %v, want %v", target, got, want)
		}
		if registry.preparedNames.plans != nil || registry.preparedNames.bytes != 0 {
			t.Fatal("object-class lookup populated the preparation cache")
		}
	}
}

// Retain cloning with the current subtype check to isolate the entry scan change.
func cloningEntryHasObjectClass(registry *Registry, entry directory.Entry, name string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	target, ok := registry.objectClasses[schemaKey(name)]
	if !ok {
		return false
	}
	for _, value := range registry.attributeValues(entry, "objectClass") {
		candidate, ok := registry.objectClasses[schemaKey(string(value))]
		if ok && registry.isSubclass(candidate, target, make(map[string]bool)) {
			return true
		}
	}
	return false
}

func BenchmarkEntryHasObjectClassReadOnly(b *testing.B) {
	registry := objectClassReadOnlyRegistry(b)
	coldRegistry := registry.Clone()
	registry.mu.RLock()
	registry.prepareAttributeNames(registry.attributes["objectclass"])
	registry.mu.RUnlock()
	entry := directory.Entry{Attributes: make([]directory.Attribute, 10)}
	for i := range entry.Attributes {
		entry.Attributes[i] = directory.Attribute{Description: fmt.Sprintf("attr%d", i), Values: byteValues("payload")}
	}
	entry.Attributes[5] = directory.Attribute{Description: "objectClass", Values: byteValues("leaf", "right", "root")}
	for _, target := range []string{"leaf", "root", "unrelated", "unknown"} {
		for name, lookup := range map[string]func(directory.Entry, string) bool{
			"original": func(entry directory.Entry, target string) bool {
				return originalEntryHasObjectClass(registry, entry, target)
			},
			"cloning": func(entry directory.Entry, target string) bool {
				return cloningEntryHasObjectClass(registry, entry, target)
			},
			"current": registry.EntryHasObjectClass,
			"cold":    coldRegistry.EntryHasObjectClass,
		} {
			b.Run(target+"/"+name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					lookup(entry, target)
				}
			})
		}
	}
}
