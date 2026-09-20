package schema

import "testing"

func TestBuiltinObjectClassReferences(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range registry.ObjectClasses() {
		for _, parent := range class.Superiors {
			if _, ok := registry.ObjectClass(parent); !ok {
				t.Errorf("%s missing parent %s", class.Name(), parent)
			}
		}
		for _, names := range [][]string{class.Must, class.May} {
			for _, name := range names {
				if _, ok := registry.AttributeType(name); !ok {
					t.Errorf("%s references missing attribute %s", class.Name(), name)
				}
			}
		}
	}
}

func TestPKIRevocationAttributesRequireBinaryTransfer(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, oid, syntax string }{
		{"authorityRevocationList", "2.5.4.38", SyntaxCertificateList},
		{"certificateRevocationList", "2.5.4.39", SyntaxCertificateList},
		{"crossCertificatePair", "2.5.4.40", SyntaxCertificatePair},
	} {
		attribute, ok := registry.AttributeType(test.oid)
		if !ok || attribute.Name() != test.name || attribute.Syntax != test.syntax || attribute.Equality != "" {
			t.Fatalf("unexpected PKI declaration: %+v", attribute)
		}
		for _, name := range []string{test.name, test.oid} {
			if err := registry.ValidateAttributeDescription(name); err == nil {
				t.Fatalf("accepted nonbinary transfer for %s", name)
			}
			if err := registry.ValidateAttributeDescription(name + ";binary"); err != nil {
				t.Fatal(err)
			}
			if err := registry.ValidateAttributeValue(name, []byte("not a certificate structure")); err == nil {
				t.Fatalf("invalid binary value accepted by %s", name)
			}
		}
	}
}
