package schema

import (
	"errors"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestSchemaDescriptionAssertionsResolveRegisteredIdentifiers(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	attribute, _ := registry.AttributeType("olcSizeLimit")
	class, _ := registry.ObjectClass("olcDatabaseConfig")
	for _, test := range []struct{ attribute, description, name, oid string }{
		{"attributeTypes", FormatAttributeType(attribute), "olcSizeLimit", attribute.OID},
		{"2.5.21.5", FormatAttributeType(attribute), "OLCSIZELIMIT", attribute.OID},
		{"objectClasses", FormatObjectClass(class), "olcDatabaseConfig", class.OID},
		{"2.5.21.6", FormatObjectClass(class), "OLCDATABASECONFIG", class.OID},
	} {
		for _, assertion := range []string{test.name, test.oid} {
			if compared, err := registry.Compare(test.attribute, "", []byte(test.description), []byte(assertion)); err != nil || compared != 0 {
				t.Fatalf("known %s/%s: %d %v", test.attribute, assertion, compared, err)
			}
		}
		for _, assertion := range []struct {
			value   string
			unknown bool
		}{
			{"unknownDefinition", true}, {"bad identifier", false}, {" " + test.name + " ", false}, {"1..2", false},
		} {
			_, err := registry.Compare(test.attribute, "", []byte(test.description), []byte(assertion.value))
			var typed *SchemaDescriptionAssertionError
			if !errors.As(err, &typed) || typed.Unknown != assertion.unknown {
				t.Fatalf("assertion classification: %q %v", assertion.value, err)
			}
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: test.attribute, Values: [][]byte{[]byte(test.description)}}}}
			filter := directory.Filter{Kind: directory.FilterNot, Children: []directory.Filter{{Kind: directory.FilterEquality, Attribute: test.attribute, Assertion: []byte(assertion.value)}}}
			if result, err := filter.EvaluateWith(entry, registry); err != nil || result != directory.FilterUndefinedResult {
				t.Fatalf("NOT undefined became match: %v %v", result, err)
			}
		}
		if compared, err := registry.Compare(test.attribute, "", []byte(test.description), []byte("1.2.3.999")); err != nil || compared == 0 {
			t.Fatal("unknown numeric identifier did not compare false")
		}
	}
}
