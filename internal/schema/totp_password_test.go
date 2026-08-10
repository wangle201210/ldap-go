package schema

import "testing"

func TestBuiltinTOTPAuthTimestampSchema(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	attribute, ok := registry.AttributeType("authTimestamp")
	if !ok {
		t.Fatal("authTimestamp is not registered")
	}
	if attribute.OID != "1.3.6.1.4.1.453.16.2.188" ||
		attribute.Equality != "generalizedTimeMatch" ||
		attribute.Ordering != "generalizedTimeOrderingMatch" ||
		attribute.Syntax != SyntaxGeneralizedTime ||
		!attribute.SingleValue || !attribute.NoUserModification ||
		attribute.Usage != UsageDSAOperation {
		t.Fatalf("authTimestamp = %#v", attribute)
	}
	if err := registry.ValidateAttributeValue(
		"authTimestamp",
		[]byte("20260810120000Z"),
	); err != nil {
		t.Fatalf("ValidateAttributeValue(authTimestamp): %v", err)
	}
}
