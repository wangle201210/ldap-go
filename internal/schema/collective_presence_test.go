package schema

import "testing"

func collectivePresenceReference(registry *Registry) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	for _, attribute := range uniqueAttributeTypes(registry.attributes) {
		if attribute.Collective {
			return true
		}
	}
	return false
}

func TestCollectivePresenceTracksSchemaUpdates(t *testing.T) {
	registry := NewRegistry()
	check := func(want bool) {
		t.Helper()
		if got := registry.HasCollectiveAttributeTypes(); got != want || got != collectivePresenceReference(registry) {
			t.Fatalf("collective presence = %v, want %v", got, want)
		}
	}
	check(false)
	attribute := AttributeType{OID: "1.2.3.4", Names: []string{"sample", "sampleAlias"}, Syntax: SyntaxDirectoryString}
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	check(false)
	attribute.Collective = true
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	check(true)
	clone := registry.Clone()
	attribute.Collective = false
	attribute.Names = []string{"renamed"}
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	check(false)
	if !clone.HasCollectiveAttributeTypes() {
		t.Fatal("updating registry changed cloned collective presence")
	}
}

func BenchmarkCollectivePresence(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		match func(*Registry) bool
	}{
		{"reference", collectivePresenceReference},
		{"current", (*Registry).HasCollectiveAttributeTypes},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if !test.match(registry) {
					b.Fatal("builtin collective attributes missing")
				}
			}
		})
	}
}
