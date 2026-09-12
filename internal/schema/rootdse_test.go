package schema

import (
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestRootDSESchemaAndPlacement(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"OpenLDAProotDSE", "LDAProotDSE", "1.3.6.1.4.1.4203.1.4.1"} {
		class, ok := registry.ObjectClass(name)
		if !ok || class.Name() != "OpenLDAProotDSE" || class.Kind != ObjectClassStructural {
			t.Fatalf("Root DSE schema: %+v %v", class, ok)
		}
		entry := directory.Entry{Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte(name)}},
			{Description: "cn", Values: [][]byte{[]byte("root")}},
		}}
		if err := registry.ValidateEntry(entry); err != nil {
			t.Fatal(err)
		}
		entry.DN = "cn=root,dc=example"
		if err := registry.ValidateEntry(entry); err == nil {
			t.Fatal("Root DSE object class accepted in a content entry")
		}
	}
	attributes, _, known := registry.ObjectClassAttributeDescriptions("subschema")
	if !known || !slices.Contains(attributes, "matchingRules") || !slices.Contains(attributes, "matchingRuleUse") {
		t.Fatalf("subschema incomplete: %v", attributes)
	}
}
