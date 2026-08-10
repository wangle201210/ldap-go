package schema

import (
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestBuiltinOpenLDAPModuleSchema(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}

	moduleLoad, found := registry.AttributeType("olcModuleLoad")
	if !found || moduleLoad.OID != "1.3.6.1.4.1.4203.1.12.2.3.0.30" ||
		moduleLoad.Equality != "caseIgnoreMatch" ||
		moduleLoad.Syntax != SyntaxDirectoryString || moduleLoad.SingleValue ||
		!moduleLoad.Hidden ||
		!reflect.DeepEqual(moduleLoad.Extensions, map[string][]string{
			"X-ORDERED": {"VALUES"},
		}) {
		t.Fatalf("olcModuleLoad = %#v, found %t", moduleLoad, found)
	}

	modulePath, found := registry.AttributeType("olcModulePath")
	if !found || modulePath.OID != "1.3.6.1.4.1.4203.1.12.2.3.0.31" ||
		modulePath.Equality != "caseExactMatch" ||
		modulePath.Syntax != SyntaxDirectoryString || !modulePath.SingleValue ||
		!modulePath.Hidden {
		t.Fatalf("olcModulePath = %#v, found %t", modulePath, found)
	}

	moduleList, found := registry.ObjectClass("olcModuleList")
	if !found || moduleList.OID != "1.3.6.1.4.1.4203.1.12.2.4.0.8" ||
		moduleList.Description != "OpenLDAP dynamic module info" ||
		moduleList.Kind != ObjectClassStructural || !moduleList.Hidden ||
		!reflect.DeepEqual(moduleList.Superiors, []string{"olcConfig"}) ||
		!reflect.DeepEqual(moduleList.May, []string{
			"cn", "olcModulePath", "olcModuleLoad",
		}) {
		t.Fatalf("olcModuleList = %#v, found %t", moduleList, found)
	}

	entry := directory.Entry{
		DN: "cn=module{0},cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("olcModuleList")}},
			{Description: "cn", Values: [][]byte{[]byte("module{0}")}},
			{Description: "olcModulePath", Values: [][]byte{[]byte("/usr/lib/openldap")}},
			{Description: "olcModuleLoad", Values: [][]byte{[]byte("{0}pw-radius.la")}},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(OpenLDAP module list): %v", err)
	}
}
