package schema

import (
	"strings"
	"testing"
)

func TestBuiltinRetcodeSchemaIsHidden(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, name := range []string{
		"errCode",
		"errOp",
		"errText",
		"errSleepTime",
		"errMatchedDN",
		"errUnsolicitedOID",
		"errUnsolicitedData",
		"errDisconnect",
	} {
		attribute, found := registry.AttributeType(name)
		if !found || !attribute.Hidden {
			t.Fatalf("hidden attribute %s = %#v, %t", name, attribute, found)
		}
	}
	for _, name := range []string{"errAbsObject", "errObject", "errAuxObject"} {
		objectClass, found := registry.ObjectClass(name)
		if !found || !objectClass.Hidden {
			t.Fatalf("hidden object class %s = %#v, %t", name, objectClass, found)
		}
	}
	for _, description := range registry.AttributeTypeDescriptions() {
		if strings.Contains(description, "errCode") {
			t.Fatalf("hidden retcode attribute was published: %s", description)
		}
	}
	for _, description := range registry.ObjectClassDescriptions() {
		if strings.Contains(description, "errObject") {
			t.Fatalf("hidden retcode object class was published: %s", description)
		}
	}
}
