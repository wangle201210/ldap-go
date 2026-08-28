package schema

import "testing"

func TestOpenLDAPLastBindConfigSchema(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if _, found := registry.ObjectClass("olcLastBindConfig"); !found {
		t.Fatal("olcLastBindConfig is not registered")
	}
	if err := registry.ValidateAttributeValue(
		"olcLastBindForwardUpdates",
		[]byte("TRUE"),
	); err != nil {
		t.Fatalf("valid olcLastBindForwardUpdates: %v", err)
	}
	if err := registry.ValidateAttributeValue(
		"olcLastBindForwardUpdates",
		[]byte("sometimes"),
	); err == nil {
		t.Fatal("invalid olcLastBindForwardUpdates was accepted")
	}
}
